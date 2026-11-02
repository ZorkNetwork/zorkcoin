
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PUBLIC_KEYS_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PUBLIC_KEYS_H
#include <mw/models/crypto/big_integer.h>
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/public_key.h>

#include <vector>

class SecretKey;

class PublicKeys
{
public:
    //
    // Calculates the 33 byte public key from the 32 byte private key using curve secp256k1.
    //
    static PublicKey Calculate(const BigInt<32>& privateKey);

    //
    // Converts curve point from Pedersen Commitment serialization to standard PublicKey serialization.
    //
    static PublicKey Convert(const Commitment& commitment);

    //
    // Returns true if the bytes parse as a valid compressed secp256k1 point.
    //
    static bool IsValid(const PublicKey& publicKey) noexcept;

    //
    // Adds a number of public keys together.
    // Returns the combined public key if successful.
    //
    static PublicKey Add(
        const std::vector<PublicKey>& publicKeys,
        const std::vector<PublicKey>& subtract = {}
    );

    //
    // Multiplies the public key (curve point) by given scalar.
    //
    static PublicKey MultiplyKey(const PublicKey& public_key, const SecretKey& mul);

    //
    // Multiplies the public key (curve point) by the inverse of the given scalar.
    //
    static PublicKey DivideKey(const PublicKey& public_key, const SecretKey& div);
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PUBLIC_KEYS_H
