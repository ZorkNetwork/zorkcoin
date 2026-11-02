
#ifndef BITCOIN_LIBMW_SRC_CRYPTO_SECP256K1_ZKP_H
#define BITCOIN_LIBMW_SRC_CRYPTO_SECP256K1_ZKP_H
#include <mw/models/crypto/public_key.h>
#include <secp256k1.h>
#include <secp256k1_aggsig.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_commitment.h>
#include <secp256k1_generator.h>
#include <secp256k1_scratch.h>
#include <secp256k1_schnorrsig_mw.h>
#include <secp256k1_zkp.h>

// Compressed encoding of GENERATOR_J; secp256k1_pubkey::data is host-endian
// ge_storage and must be parsed via secp256k1_ec_pubkey_parse.
static const PublicKey GENERATOR_J_PUB{BigInt<33>{std::array<uint8_t, 33>{
    0x02,
    0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3,
    0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a, 0x2f,
    0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d,
    0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15, 0x5f
}}};
#endif // BITCOIN_LIBMW_SRC_CRYPTO_SECP256K1_ZKP_H
