
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_BULLETPROOFS_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_BULLETPROOFS_H
#include <mw/models/crypto/big_integer.h>
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/proof_message.h>
#include <mw/models/crypto/range_proof.h>
#include <mw/models/crypto/rewound_proof.h>

#include <cstdint>
#include <memory>
#include <vector>

class SecretKey;
struct ProofData;

class Bulletproofs
{
public:
    static bool BatchVerify(
        const std::vector<ProofData>& rangeProofs
    );

    //! Test observability: number of BatchVerify entries since last ResetBatchVerifyCount.
    static uint64_t GetBatchVerifyCount() noexcept;
    static void ResetBatchVerifyCount() noexcept;

    static RangeProof::CPtr Generate(
        uint64_t amount,
        const SecretKey& key,
        const SecretKey& privateNonce,
        const SecretKey& rewindNonce,
        const ProofMessage& proofMessage,
        const std::vector<uint8_t>& extraData
    );

    //
    // Proves a 64-bit amount and embeds a 32-byte message that RewindMessage recovers with the same nonce.
    // The nonce is used for both the rewindable and the private (blinding) randomness.
    //
    static RangeProof::CPtr Generate(
        uint64_t amount,
        const SecretKey& key,
        const SecretKey& nonce,
        const BigInt<32>& message,
        const std::vector<uint8_t>& extraData
    );

    //
    // Recovers value, blinding factor and 20-byte message from a proof whose 32-byte message is
    // [0x00000000 || message || amount (BE)], as written by the ProofMessage Generate overload.
    // Returns nullptr if the nonce does not match.
    //
    static std::unique_ptr<RewoundProof> Rewind(
        const Commitment& commitment,
        const RangeProof& rangeProof,
        const std::vector<uint8_t>& extraData,
        const SecretKey& nonce
    );

    //
    // Recovers the 32-byte message embedded by Generate. The result is unauthenticated: a wrong
    // nonce yields unrelated bytes, so callers must check it. Returns zero bytes on failure.
    //
    static BigInt<32> RewindMessage(
        const Commitment& commitment,
        const RangeProof& rangeProof,
        const std::vector<uint8_t>& extraData,
        const SecretKey& nonce
    );
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_BULLETPROOFS_H
