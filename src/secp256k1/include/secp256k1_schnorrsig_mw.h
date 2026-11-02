#ifndef SECP256K1_SCHNORRSIG_MW_H
#define SECP256K1_SCHNORRSIG_MW_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_scratch.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Parsed Mimblewimble/Litecoin Schnorr signature (64 bytes). */
typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig_mw;

SECP256K1_API int secp256k1_schnorrsig_mw_serialize(
    const secp256k1_context *ctx,
    unsigned char *out64,
    const secp256k1_schnorrsig_mw *sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API int secp256k1_schnorrsig_mw_parse(
    const secp256k1_context *ctx,
    secp256k1_schnorrsig_mw *sig,
    const unsigned char *in64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Mimblewimble Schnorr sign (plain SHA256 challenge, not BIP-340). */
SECP256K1_API int secp256k1_schnorrsig_mw_sign(
    const secp256k1_context *ctx,
    secp256k1_schnorrsig_mw *sig,
    int *nonce_is_negated,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Batch verify MW Schnorr signatures (plain SHA256 challenge). */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_mw_verify_batch(
    const secp256k1_context *ctx,
    secp256k1_scratch *scratch,
    const secp256k1_schnorrsig_mw *const *sig,
    const unsigned char *const *msg32,
    const secp256k1_pubkey *const *pk,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRSIG_MW_H */
