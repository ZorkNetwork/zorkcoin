
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_SCHNORR_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_SCHNORR_H
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/signature.h>
#include <mw/models/crypto/signed_message.h>

#include <cstdint>
#include <vector>

class SecretKey;

class Schnorr
{
public:
    //
    // Signs the message hash with the given key.
    // If successful, returns a schnorr signature.
    //
    static Signature Sign(
        const uint8_t* secretKey,
        const mw::Hash& message
    );

    static SignedMessage SignMessage(
        const SecretKey& secretKey,
        const mw::Hash& message
    );

    static bool Verify(
        const Signature& signature,
        const PublicKey& sumPubKeys,
        const mw::Hash& message
    );

    static bool BatchVerify(
        const std::vector<SignedMessage>& signatures
    );

    //! Test observability: number of BatchVerify entries since last ResetBatchVerifyCount.
    static uint64_t GetBatchVerifyCount() noexcept;
    static void ResetBatchVerifyCount() noexcept;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_SCHNORR_H
