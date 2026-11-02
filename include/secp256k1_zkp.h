#ifndef SECP256K1_ZKP_H
#define SECP256K1_ZKP_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Compute the modular inverse of a secret key (modulo the group order).
 *
 *  Returns: 1 if seckey was a valid secret key, 0 otherwise.
 *  Args:    ctx: pointer to a context object.
 *  In/Out: seckey: pointer to a 32-byte secret key. On success, replaced with its inverse.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_seckey_tweak_inv(
    const secp256k1_context *ctx,
    unsigned char *seckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ZKP_H */
