#include <conversion_util.h>

#include <context.h>
#include <mw/common/lock.h>
#include <mw/exceptions/crypto_exception.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>

static Locked<Context> SECP256K1_CONTEXT(std::make_shared<Context>());

PublicKey ConversionUtil::ToPublicKey(const Commitment& commitment)
{
    secp256k1_pedersen_commitment parsedCommitment = ToSecp256k1(commitment);

    secp256k1_pubkey pubkey;
    const int pubkeyResult = secp256k1_pedersen_commitment_to_pubkey(
        SECP256K1_CONTEXT.Read()->Get(),
        &pubkey,
        &parsedCommitment
    );

    if (pubkeyResult != 1) {
        ThrowCrypto_F("Failed to convert commitment ({}) to pubkey", commitment);
    }

    return ToPublicKey(pubkey);
}

PublicKey ConversionUtil::ToPublicKey(const secp256k1_pubkey& pubkey)
{
    PublicKey result;
    size_t length = result.size();
    const int serializeResult = secp256k1_ec_pubkey_serialize(
        SECP256K1_CONTEXT.Read()->Get(),
        result.data(),
        &length,
        &pubkey,
        SECP256K1_EC_COMPRESSED
    );
    if (serializeResult != 1) {
        ThrowCrypto("Failed to convert to PublicKey");
    }

    return result;
}

secp256k1_pubkey ConversionUtil::ToSecp256k1(const PublicKey& publicKey)
{
    secp256k1_pubkey parsedPubkey;
    const int pubkeyResult = secp256k1_ec_pubkey_parse(
        SECP256K1_CONTEXT.Read()->Get(),
        &parsedPubkey,
        publicKey.data(),
        publicKey.size()
    );
    if (pubkeyResult != 1) {
        ThrowCrypto_F("Failed to parse pubkey: {}", publicKey);
    }

    return parsedPubkey;
}

std::vector<secp256k1_pubkey> ConversionUtil::ToSecp256k1(const std::vector<PublicKey>& publicKeys)
{
    std::vector<secp256k1_pubkey> out;
    out.reserve(publicKeys.size());
    std::transform(
        publicKeys.cbegin(), publicKeys.cend(), std::back_inserter(out),
        [](const PublicKey& publicKey) { return ConversionUtil::ToSecp256k1(publicKey); }
    );

    return out;
}

secp256k1_pedersen_commitment ConversionUtil::ToSecp256k1(const Commitment& commitment)
{
    secp256k1_pedersen_commitment parsedCommitment;
    const int commitmentResult = secp256k1_pedersen_commitment_parse(
        SECP256K1_CONTEXT.Read()->Get(),
        &parsedCommitment,
        commitment.data()
    );
    if (commitmentResult != 1) {
        ThrowCrypto_F("Failed to parse commitment: {}", commitment);
    }

    return parsedCommitment;
}

Commitment ConversionUtil::ToCommitment(const secp256k1_pedersen_commitment& commitment)
{
    Commitment out;
    const int serializedResult = secp256k1_pedersen_commitment_serialize(
        SECP256K1_CONTEXT.Read()->Get(),
        out.data(),
        &commitment
    );
    if (serializedResult != 1) {
        ThrowCrypto("Failed to serialize commitment.");
    }

    return out;
}

std::vector<secp256k1_pedersen_commitment> ConversionUtil::ToSecp256k1(const std::vector<Commitment>& commitments)
{
    std::vector<secp256k1_pedersen_commitment> out;
    out.reserve(commitments.size());
    std::transform(
        commitments.cbegin(), commitments.cend(), std::back_inserter(out),
        [](const Commitment& commit) { return ConversionUtil::ToSecp256k1(commit); }
    );

    return out;
}

secp256k1_schnorrsig_mw ConversionUtil::ToSecp256k1(const Signature& signature)
{
    secp256k1_schnorrsig_mw secpSig;
    const int parseSignatureResult = secp256k1_schnorrsig_mw_parse(
        SECP256K1_CONTEXT.Read()->Get(),
        &secpSig,
        signature.data()
    );
    if (parseSignatureResult != 1) {
        ThrowCrypto_F("Failed to parse signature: {}", signature);
    }

    return secpSig;
}

std::vector<secp256k1_schnorrsig_mw> ConversionUtil::ToSecp256k1(const std::vector<const Signature*>& signatures)
{
    std::vector<secp256k1_schnorrsig_mw> out;
    out.reserve(signatures.size());
    std::transform(
        signatures.cbegin(), signatures.cend(), std::back_inserter(out),
        [](const Signature* pSignature) { return ConversionUtil::ToSecp256k1(*pSignature); }
    );

    return out;
}

Signature ConversionUtil::ToSignature(const secp256k1_schnorrsig_mw& signature)
{
    Signature out;
    const int serializedResult = secp256k1_schnorrsig_mw_serialize(
        SECP256K1_CONTEXT.Read()->Get(),
        out.data(),
        &signature
    );
    if (serializedResult != 1) {
        ThrowCrypto("Failed to serialize signature.");
    }

    return out;
}
