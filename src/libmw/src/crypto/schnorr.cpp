#include <mw/crypto/schnorr.h>

#include <caches/cache.h>
#include <context.h>
#include <conversion_util.h>
#include <internal/cache.hpp>
#include <mw/common/lock.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/models/crypto/secret_key.h>
#include <secp256k1.h>
#include <secp256k1_aggsig.h>
#include <secp256k1_schnorrsig_mw.h>
#include <secp256k1_scratch.h>
#include <serialize.h>

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>

static Locked<LRUCache<SignedMessage, bool>> CACHE(std::make_shared<LRUCache<SignedMessage, bool>>(3000));
static Locked<Context> SCHNORR_CONTEXT(std::make_shared<Context>());
static std::atomic<uint64_t> g_schnorr_batch_verify_count{0};

// Keep in sync with bulletproofs.cpp: batch verify of a max-weight MWEB body
// can require a large scratch (64 MiB covers weight-max rangeproof batches).
static constexpr size_t SCRATCH_SPACE_SIZE = 64 * 1024 * 1024;

Signature Schnorr::Sign(
    const uint8_t* secretKey,
    const mw::Hash& message)
{
    secp256k1_schnorrsig_mw signature;
    const int signedResult = secp256k1_schnorrsig_mw_sign(
        SCHNORR_CONTEXT.Write()->Randomized(),
        &signature,
        nullptr,
        message.data(),
        secretKey,
        nullptr,
        nullptr
    );
    if (signedResult != 1) {
        ThrowCrypto("Failed to sign message.");
    }

    return ConversionUtil::ToSignature(signature);
}

SignedMessage Schnorr::SignMessage(
    const SecretKey& secretKey,
    const mw::Hash& message)
{
    PublicKey pubkey = PublicKey::From(secretKey);
    Signature sig = Sign(secretKey.data(), message);

    return SignedMessage(message, pubkey, sig);
}

bool Schnorr::Verify(
    const Signature& signature,
    const PublicKey& sumPubKeys,
    const mw::Hash& message)
{
    SignedMessage signed_message(message, sumPubKeys, signature);
    if (CACHE.Write()->Cached(signed_message)) {
        return true;
    }

    secp256k1_pubkey parsedPubKey = ConversionUtil::ToSecp256k1(sumPubKeys);

    const int verifyResult = secp256k1_aggsig_verify_single(
        SCHNORR_CONTEXT.Read()->Get(),
        signature.data(),
        message.data(),
        nullptr,
        &parsedPubKey,
        &parsedPubKey,
        nullptr,
        false
    );
    if (verifyResult == 1) {
        CACHE.Write()->Put(signed_message, true);
    }

    return verifyResult == 1;
}

bool Schnorr::BatchVerify(const std::vector<SignedMessage>& signatures)
{
    g_schnorr_batch_verify_count.fetch_add(1, std::memory_order_relaxed);

    std::vector<SignedMessage> unverified_messages;
    std::vector<secp256k1_pubkey> parsedPubKeys;
    std::vector<secp256k1_schnorrsig_mw> parsedSignatures;
    std::vector<const uint8_t*> messageData;

    for (const SignedMessage& signed_message : signatures) {
        if (CACHE.Write()->Cached(signed_message)) {
            continue;
        }

        unverified_messages.push_back(signed_message);
        parsedPubKeys.push_back(ConversionUtil::ToSecp256k1(signed_message.GetPublicKey()));
        parsedSignatures.push_back(ConversionUtil::ToSecp256k1(signed_message.GetSignature()));
        messageData.push_back(signed_message.GetMsgHash().data());
    }

    if (unverified_messages.empty()) {
        return true;
    }

    std::vector<const secp256k1_pubkey*> pubKeyPtrs;
    pubKeyPtrs.reserve(parsedPubKeys.size());
    for (const secp256k1_pubkey& pubkey : parsedPubKeys) {
        pubKeyPtrs.push_back(&pubkey);
    }

    std::vector<const secp256k1_schnorrsig_mw*> signaturePtrs;
    signaturePtrs.reserve(parsedSignatures.size());
    for (const secp256k1_schnorrsig_mw& signature : parsedSignatures) {
        signaturePtrs.push_back(&signature);
    }

    secp256k1_scratch* pScratchSpace = secp256k1_scratch_space_create(
        SCHNORR_CONTEXT.Read()->Get(),
        SCRATCH_SPACE_SIZE
    );
    const int verifyResult = secp256k1_schnorrsig_mw_verify_batch(
        SCHNORR_CONTEXT.Read()->Get(),
        pScratchSpace,
        signaturePtrs.data(),
        messageData.data(),
        pubKeyPtrs.data(),
        unverified_messages.size()
    );
    secp256k1_scratch_space_destroy(SCHNORR_CONTEXT.Read()->Get(), pScratchSpace);

    if (verifyResult == 1) {
        for (const SignedMessage& message : unverified_messages) {
            CACHE.Write()->Put(message, true);
        }
    }

    return verifyResult == 1;
}

uint64_t Schnorr::GetBatchVerifyCount() noexcept
{
    return g_schnorr_batch_verify_count.load(std::memory_order_relaxed);
}

void Schnorr::ResetBatchVerifyCount() noexcept
{
    g_schnorr_batch_verify_count.store(0, std::memory_order_relaxed);
}
