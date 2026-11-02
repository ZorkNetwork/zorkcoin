/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_AGGSIG_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_AGGSIG_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_aggsig.h"

/*
 * Single-signer: sign_single then verify_single over all (d, k, m) tuples.
 */

static void test_exhaustive_aggsig(const secp256k1_context *ctx, const secp256k1_ge *group) {
    secp256k1_context *sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    int d, k;
    uint64_t iter = 0;
    unsigned char seed[32] = {0x42};

    (void)group;

    for (d = 1; d < EXHAUSTIVE_TEST_ORDER; ++d) {
        for (k = 1; k < EXHAUSTIVE_TEST_ORDER; ++k) {
            unsigned char seckey[32];
            unsigned char secnonce[32];
            unsigned char msg32[32];
            unsigned char sig64[64];
            secp256k1_scalar ds;
            secp256k1_scalar ks;
            secp256k1_pubkey pubkey;

            if (skip_section(&iter)) continue;

            secp256k1_scalar_set_int(&ds, d);
            secp256k1_scalar_get_b32(seckey, &ds);
            secp256k1_scalar_set_int(&ks, k);
            secp256k1_scalar_get_b32(secnonce, &ks);
            secp256k1_scalar_set_int(&ds, d + k);
            secp256k1_scalar_get_b32(msg32, &ds);

            CHECK(secp256k1_ec_pubkey_create(sign_ctx, &pubkey, seckey));
            CHECK(secp256k1_aggsig_sign_single(sign_ctx, sig64, msg32, seckey, secnonce, NULL, NULL, NULL, NULL, seed));
            CHECK(secp256k1_aggsig_verify_single(sign_ctx, sig64, msg32, NULL, &pubkey, NULL, NULL, 0));
        }
    }

    secp256k1_context_destroy(sign_ctx);
    (void)ctx;
}

#endif /* SECP256K1_MODULE_AGGSIG_TESTS_EXHAUSTIVE_H */
