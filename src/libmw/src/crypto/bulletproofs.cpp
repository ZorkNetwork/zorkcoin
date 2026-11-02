#include <mw/crypto/bulletproofs.h>

#include <caches/cache.h>
#include <context.h>
#include <conversion_util.h>
#include <internal/cache.hpp>
#include <mw/common/lock.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/models/crypto/big_integer.h>
#include <mw/models/crypto/proof_data.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/util/vector_util.h>
#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_commitment.h>
#include <secp256k1_generator.h>
#include <secp256k1_scratch.h>
#include <serialize.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <utility>

// Must fit a single BatchVerify of every rangeproof in a max-weight MWEB body:
// up to (MAX_BLOCK_WEIGHT - BASE_KERNEL_WEIGHT) / BASE_OUTPUT_WEIGHT proofs
// (~11764). Nested secp256k1-zkp frames need ~5.3 KiB/proof; 32 MiB fails near
// ~6250 proofs and breaks TestBlockValidity / CreateNewBlock for legal blocks.
static constexpr size_t SCRATCH_SPACE_SIZE = 64 * 1024 * 1024;
static constexpr size_t PROOF_LEN = 675;
static constexpr size_t NUM_BITS_PROVEN = 64;

static Locked<LRUCache<Commitment, ProofData>> CACHE(std::make_shared<LRUCache<Commitment, ProofData>>(3000));
static Locked<Context> BP_CONTEXT(std::make_shared<Context>());
static std::atomic<uint64_t> g_bulletproofs_batch_verify_count{0};

bool Bulletproofs::BatchVerify(const std::vector<ProofData>& proofs)
{
    g_bulletproofs_batch_verify_count.fetch_add(1, std::memory_order_relaxed);

    std::vector<secp256k1_pedersen_commitment> secpCommitments;
    secpCommitments.reserve(proofs.size());

    std::vector<const uint8_t*> bulletproofPointers;
    bulletproofPointers.reserve(proofs.size());

    std::vector<const uint8_t*> extraData;
    extraData.reserve(proofs.size());

    std::vector<size_t> extraDataLen;
    extraDataLen.reserve(proofs.size());

    for (const auto& proof : proofs)
    {
        auto cache_writer = CACHE.Write();
        if (!cache_writer->Cached(proof.commitment) || proof != cache_writer->Get(proof.commitment)) {
            secpCommitments.push_back(ConversionUtil::ToSecp256k1(proof.commitment));
            bulletproofPointers.emplace_back(proof.pRangeProof->data());

            if (!proof.extraData.empty()) {
                extraData.push_back(proof.extraData.data());
                extraDataLen.push_back(proof.extraData.size());
            } else {
                extraData.push_back(nullptr);
                extraDataLen.push_back(0);
            }
        }
    }

    if (secpCommitments.empty()) {
        return true;
    }

    // array of generator multiplied by value in pedersen commitments (cannot be NULL)
    std::vector<secp256k1_generator> valueGenerators;
    valueGenerators.reserve(secpCommitments.size());
    for (size_t i = 0; i < secpCommitments.size(); i++)
    {
        valueGenerators.push_back(secp256k1_generator_const_h);
    }

    std::vector<secp256k1_pedersen_commitment*> commitmentPointers = VectorUtil::ToPointerVec(secpCommitments);

    secp256k1_scratch* pScratchSpace = secp256k1_scratch_space_create(
        BP_CONTEXT.Read()->Get(),
        SCRATCH_SPACE_SIZE
    );
    const int result = secp256k1_bulletproof_rangeproof_verify_multi(
        BP_CONTEXT.Read()->Get(),
        pScratchSpace,
        BP_CONTEXT.Read()->GetGenerators(),
        bulletproofPointers.data(),
        secpCommitments.size(),
        PROOF_LEN,
        nullptr,
        commitmentPointers.data(),
        1,
        NUM_BITS_PROVEN,
        valueGenerators.data(),
        extraData.data(),
        extraDataLen.data()
    );
    secp256k1_scratch_space_destroy(BP_CONTEXT.Read()->Get(), pScratchSpace);

    if (result == 1) {
        auto cache_writer = CACHE.Write();
        for (const auto& proof : proofs)
        {
            cache_writer->Put(proof.commitment, proof);
        }
    }

    return result == 1;
}

uint64_t Bulletproofs::GetBatchVerifyCount() noexcept
{
    return g_bulletproofs_batch_verify_count.load(std::memory_order_relaxed);
}

void Bulletproofs::ResetBatchVerifyCount() noexcept
{
    g_bulletproofs_batch_verify_count.store(0, std::memory_order_relaxed);
}

static RangeProof::CPtr GenerateProof(
    const uint64_t amount,
    const SecretKey& key,
    const uint8_t* rewind_nonce,
    const uint8_t* private_nonce,
    const BigInt<32>& message,
    const std::vector<uint8_t>& extraData)
{
    auto contextWriter = BP_CONTEXT.Write();
    secp256k1_context* pContext = contextWriter->Randomized();

    std::vector<uint8_t> proofBytes(RangeProof::SIZE, 0);
    size_t proofLen = RangeProof::SIZE;

    secp256k1_scratch* pScratchSpace = secp256k1_scratch_space_create(pContext, SCRATCH_SPACE_SIZE);

    std::vector<const uint8_t*> blindingFactors({ key.data() });
    int result = secp256k1_bulletproof_rangeproof_prove(
        pContext,
        pScratchSpace,
        contextWriter->GetGenerators(),
        &proofBytes[0],
        &proofLen,
        nullptr,
        nullptr,
        nullptr,
        &amount,
        nullptr,
        blindingFactors.data(),
        nullptr,
        1,
        &secp256k1_generator_const_h,
        NUM_BITS_PROVEN,
        rewind_nonce,
        private_nonce,
        extraData.data(),
        extraData.size(),
        message.data()
    );
    secp256k1_scratch_space_destroy(pContext, pScratchSpace);

    if (result != 1) {
        ThrowCrypto_F("secp256k1_bulletproof_rangeproof_prove failed with error: {}", result);
    }

    proofBytes.resize(proofLen);
    return std::make_shared<RangeProof>(std::move(proofBytes));
}

RangeProof::CPtr Bulletproofs::Generate(
    const uint64_t amount,
    const SecretKey& key,
    const SecretKey& privateNonce,
    const SecretKey& rewindNonce,
    const ProofMessage& proofMessage,
    const std::vector<uint8_t>& extraData)
{
    BigInt<32> message;
    std::copy(proofMessage.data(), proofMessage.data() + 20, message.data() + 4);
    for (size_t i = 0; i < 8; i++) {
        message[31 - i] = static_cast<uint8_t>(amount >> (8 * i));
    }

    return GenerateProof(amount, key, rewindNonce.data(), privateNonce.data(), message, extraData);
}

RangeProof::CPtr Bulletproofs::Generate(
    const uint64_t amount,
    const SecretKey& key,
    const SecretKey& nonce,
    const BigInt<32>& message,
    const std::vector<uint8_t>& extraData)
{
    return GenerateProof(amount, key, nonce.data(), nullptr, message, extraData);
}

std::unique_ptr<RewoundProof> Bulletproofs::Rewind(
    const Commitment& commitment,
    const RangeProof& rangeProof,
    const std::vector<uint8_t>& extraData,
    const SecretKey& nonce)
{
    secp256k1_pedersen_commitment secpCommitment = ConversionUtil::ToSecp256k1(commitment);

    std::vector<uint8_t> shared_msg(32, 0);
    size_t shared_msg_len = shared_msg.size();
    SecretKey blindingFactor;
    size_t blind_len = blindingFactor.size();

    int result = secp256k1_bulletproof_rangeproof_rewind(
        BP_CONTEXT.Read()->Get(),
        shared_msg.data(),
        &shared_msg_len,
        blindingFactor.data(),
        &blind_len,
        rangeProof.data(),
        rangeProof.size(),
        0,
        &secpCommitment,
        &secp256k1_generator_const_h,
        nonce.data(),
        nonce.data(),
        extraData.data(),
        extraData.size()
    );

    if (result != 1 || shared_msg_len != 32 || blind_len != 32 ||
        shared_msg[0] != 0 || shared_msg[1] != 0 || shared_msg[2] != 0 || shared_msg[3] != 0) {
        return std::unique_ptr<RewoundProof>(nullptr);
    }

    uint64_t value = 0;
    for (size_t i = 24; i < 32; i++) {
        value = (value << 8) | shared_msg[i];
    }

    return std::make_unique<RewoundProof>(
        value,
        std::make_unique<SecretKey>(std::move(blindingFactor)),
        ProofMessage(BigInt<20>(std::vector<uint8_t>(shared_msg.begin() + 4, shared_msg.begin() + 24)))
    );
}

BigInt<32> Bulletproofs::RewindMessage(
    const Commitment& commitment,
    const RangeProof& rangeProof,
    const std::vector<uint8_t>& extraData,
    const SecretKey& nonce)
{
    secp256k1_pedersen_commitment secpCommitment = ConversionUtil::ToSecp256k1(commitment);

    BigInt<32> message;
    size_t message_len = message.size();
    int result = secp256k1_bulletproof_rangeproof_rewind(
        BP_CONTEXT.Read()->Get(),
        message.data(),
        &message_len,
        nullptr,
        nullptr,
        rangeProof.data(),
        rangeProof.size(),
        0,
        &secpCommitment,
        &secp256k1_generator_const_h,
        nonce.data(),
        nullptr,
        extraData.data(),
        extraData.size()
    );

    if (result != 1 || message_len != message.size()) {
        return BigInt<32>{};
    }

    return message;
}
