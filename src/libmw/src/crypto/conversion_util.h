
#ifndef BITCOIN_LIBMW_SRC_CRYPTO_CONVERSION_UTIL_H
#define BITCOIN_LIBMW_SRC_CRYPTO_CONVERSION_UTIL_H
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/signature.h>
#include <secp256k1.h>
#include <secp256k1_commitment.h>
#include <secp256k1_schnorrsig_mw.h>

#include <vector>

class ConversionUtil
{
public:
    static PublicKey ToPublicKey(const Commitment& commitment);
    static PublicKey ToPublicKey(const secp256k1_pubkey& pubkey);
    static Commitment ToCommitment(const secp256k1_pedersen_commitment& commitment);

    static secp256k1_pubkey ToSecp256k1(const PublicKey& publicKey);
    static std::vector<secp256k1_pubkey> ToSecp256k1(const std::vector<PublicKey>& publicKeys);

    static secp256k1_pedersen_commitment ToSecp256k1(const Commitment& commitment);
    static std::vector<secp256k1_pedersen_commitment> ToSecp256k1(const std::vector<Commitment>& commitments);

    static secp256k1_schnorrsig_mw ToSecp256k1(const Signature& signature);
    static std::vector<secp256k1_schnorrsig_mw> ToSecp256k1(const std::vector<const Signature*>& signatures);
    static Signature ToSignature(const secp256k1_schnorrsig_mw& signature);
};
#endif // BITCOIN_LIBMW_SRC_CRYPTO_CONVERSION_UTIL_H
