/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_COMMITMENT_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_COMMITMENT_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_commitment.h"
#include "../../../include/secp256k1_generator.h"
#include "../../../include/secp256k1_zkp.h"
#include "../generator/main_impl.h"
#include "main_impl.h"
#include "../zkp/tests_exhaustive_util.h"

/*
 * pedersen_commit: oracle is r*H_r + v*G_v via pedersen_ecmult (independent of API path).
 * ec_seckey_tweak_inv(i): oracle is scalar_inverse(i)*i == 1 (mod n).
 * blind_sum: oracle is signed scalar sum over input blinds.
 */

static void test_exhaustive_commitment(const secp256k1_context *ctx, const secp256k1_ge *group) {
    int v, r, i;
    uint64_t iter = 0;
    (void)group;

    for (v = 0; (uint64_t)v < EXHAUSTIVE_TEST_ORDER; ++v) {
        for (r = 1; r < EXHAUSTIVE_TEST_ORDER; ++r) {
            secp256k1_generator g_v;
            secp256k1_generator h_r;
            secp256k1_ge g_v_ge;
            secp256k1_ge h_r_ge;
            secp256k1_pedersen_commitment commit;
            secp256k1_ge commit_ge;
            secp256k1_ge parsed_ge;
            secp256k1_ge oracle_ge;
            unsigned char key_v[32];
            unsigned char key_r[32];
            unsigned char blind32[32];
            secp256k1_scalar blind_scalar;
            unsigned char ser[33];
            secp256k1_pedersen_commitment parsed;

            if (skip_section(&iter)) continue;

            secp256k1_zkp_exhaustive_scalar_to_key32(key_v, v);
            secp256k1_zkp_exhaustive_scalar_to_key32(key_r, EXHAUSTIVE_TEST_ORDER + r);
            CHECK(secp256k1_generator_generate(ctx, &g_v, key_v));
            CHECK(secp256k1_generator_generate(ctx, &h_r, key_r));
            secp256k1_generator_load(&g_v_ge, &g_v);
            secp256k1_generator_load(&h_r_ge, &h_r);

            secp256k1_scalar_set_int(&blind_scalar, r);
            secp256k1_scalar_get_b32(blind32, &blind_scalar);

            CHECK(secp256k1_pedersen_commit(ctx, &commit, blind32, (uint64_t)v, &g_v, &h_r));
            secp256k1_zkp_exhaustive_oracle_pedersen_commit(&oracle_ge, &blind_scalar, (uint64_t)v, &g_v_ge, &h_r_ge);
            secp256k1_pedersen_commitment_load(&commit_ge, &commit);
            CHECK(secp256k1_ge_eq_var(&commit_ge, &oracle_ge));

            CHECK(secp256k1_pedersen_commitment_serialize(ctx, ser, &commit));
            CHECK(secp256k1_pedersen_commitment_parse(ctx, &parsed, ser));
            secp256k1_pedersen_commitment_load(&parsed_ge, &parsed);
            CHECK(secp256k1_ge_eq_var(&commit_ge, &parsed_ge));
        }
    }

    iter = 0;
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        unsigned char seckey[32];
        unsigned char invkey[32];
        secp256k1_scalar s;
        secp256k1_scalar inv;
        secp256k1_scalar prod;

        if (skip_section(&iter)) continue;

        secp256k1_scalar_set_int(&s, i);
        secp256k1_scalar_get_b32(seckey, &s);
        memcpy(invkey, seckey, 32);
        CHECK(secp256k1_ec_seckey_tweak_inv(ctx, invkey));
        secp256k1_scalar_set_b32(&inv, invkey, NULL);
        secp256k1_scalar_mul(&prod, &s, &inv);
        CHECK(secp256k1_scalar_eq(&prod, &secp256k1_scalar_one));
    }

    iter = 0;
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER - 1; ++i) {
        unsigned char blind0[32];
        unsigned char blind1[32];
        unsigned char blind_out[32];
        const unsigned char *blinds[2];
        secp256k1_scalar s0, s1, acc, out;
        int j;

        if (skip_section(&iter)) continue;

        secp256k1_scalar_set_int(&s0, 1);
        secp256k1_scalar_set_int(&s1, i);
        secp256k1_scalar_get_b32(blind0, &s0);
        secp256k1_scalar_get_b32(blind1, &s1);
        blinds[0] = blind0;
        blinds[1] = blind1;
        CHECK(secp256k1_pedersen_blind_sum(ctx, blind_out, blinds, 2, 1));

        secp256k1_scalar_set_int(&acc, 0);
        for (j = 0; j < 2; ++j) {
            secp256k1_scalar x;
            secp256k1_scalar_set_b32(&x, blinds[j], NULL);
            if ((size_t)j >= 1) {
                secp256k1_scalar_negate(&x, &x);
            }
            secp256k1_scalar_add(&acc, &acc, &x);
        }
        secp256k1_scalar_set_b32(&out, blind_out, NULL);
        CHECK(secp256k1_scalar_eq(&acc, &out));
    }
}

#endif /* SECP256K1_MODULE_COMMITMENT_TESTS_EXHAUSTIVE_H */
