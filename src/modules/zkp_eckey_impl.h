/***********************************************************************
 * Litecoin/MWEB ZKP extensions to the public API.
 **********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_ECKEY_IMPL_H
#define SECP256K1_MODULE_ZKP_ECKEY_IMPL_H

#include "../../include/secp256k1_zkp.h"
#include "zkp_compat.h"
#include <string.h>

int secp256k1_ec_seckey_tweak_inv(const secp256k1_context* ctx, unsigned char *seckey) {
    secp256k1_scalar sec;
    secp256k1_scalar inv;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow;
    secp256k1_memclear_explicit(seckey, 32);
    if (ret) {
        secp256k1_scalar_inverse(&inv, &sec);
        secp256k1_scalar_get_b32(seckey, &inv);
        secp256k1_scalar_clear(&inv);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

#endif /* SECP256K1_MODULE_ZKP_ECKEY_IMPL_H */
