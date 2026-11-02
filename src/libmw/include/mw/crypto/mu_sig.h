
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_MU_SIG_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_MU_SIG_H
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/crypto/signature.h>

#include <vector>

class MuSig
{
public:
    static SecretKey GenerateSecureNonce();

    //
    // Builds one party's share of a Schnorr signature.
    // Returns a CompactSignature if successful.
    //
    static CompactSignature CalculatePartial(
        const SecretKey& secretKey,
        const SecretKey& secretNonce,
        const PublicKey& sumPubKeys,
        const PublicKey& sumPubNonces,
        const mw::Hash& message
    );

    //
    // Verifies one party's share of a Schnorr signature.
    // Returns true if valid.
    //
    static bool VerifyPartial(
        const CompactSignature& partialSignature,
        const PublicKey& publicKey,
        const PublicKey& sumPubKeys,
        const PublicKey& sumPubNonces,
        const mw::Hash& message
    );

    //
    // Combines multiple partial signatures to build the final aggregate signature.
    // Returns the raw aggregate signature.
    //
    static Signature Aggregate(
        const std::vector<CompactSignature>& signatures,
        const PublicKey& sumPubNonces
    );
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_MU_SIG_H
