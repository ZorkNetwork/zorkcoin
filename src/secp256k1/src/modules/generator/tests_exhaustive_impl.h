/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_GENERATOR_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_GENERATOR_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_generator.h"
#include "../../eckey_impl.h"
#include "main_impl.h"

/*
 * Exhaustive generator tests check:
 *  - determinism of generator_generate(key)
 *  - parse(serialize(gen)) = gen
 *  - generate_blinded(key, blind) = eckey_pubkey_tweak_add(generate(key), blind)
 */

static const unsigned char invalid_generator_prefixes[][33] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
    {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
    {12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
};

#define NUM_INVALID_GENERATOR_PREFIXES (sizeof(invalid_generator_prefixes) / sizeof(invalid_generator_prefixes[0]))

static void test_exhaustive_generator(const secp256k1_context *ctx) {
    int i, b;
    uint64_t iter = 0;
    unsigned char key32[32];
    unsigned char blind32[32];
    secp256k1_scalar s;
    unsigned j;

    for (j = 0; j < NUM_INVALID_GENERATOR_PREFIXES; ++j) {
        secp256k1_generator gen;
        CHECK(!secp256k1_generator_parse(ctx, &gen, invalid_generator_prefixes[j]));
    }

    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        secp256k1_generator gen1;
        secp256k1_generator gen2;
        unsigned char ser[33];
        secp256k1_generator parsed;

        if (skip_section(&iter)) continue;

        secp256k1_scalar_set_int(&s, i);
        secp256k1_scalar_get_b32(key32, &s);

        CHECK(secp256k1_generator_generate(ctx, &gen1, key32));
        CHECK(secp256k1_generator_generate(ctx, &gen2, key32));
        CHECK(secp256k1_memcmp_var(&gen1, &gen2, sizeof(gen1)) == 0);

        CHECK(secp256k1_generator_serialize(ctx, ser, &gen1));
        CHECK(secp256k1_generator_parse(ctx, &parsed, ser));
        CHECK(secp256k1_memcmp_var(&gen1, &parsed, sizeof(gen1)) == 0);
    }

    iter = 0;
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        secp256k1_generator gen_plain;
        secp256k1_generator gen_zero_blind;
        unsigned char zero_blind[32] = {0};

        if (skip_section(&iter)) continue;

        secp256k1_scalar_set_int(&s, i);
        secp256k1_scalar_get_b32(key32, &s);
        CHECK(secp256k1_generator_generate(ctx, &gen_plain, key32));
        CHECK(secp256k1_generator_generate_blinded(ctx, &gen_zero_blind, key32, zero_blind));
        CHECK(secp256k1_memcmp_var(&gen_plain, &gen_zero_blind, sizeof(gen_plain)) == 0);
    }

    iter = 0;
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        for (b = 1; b < EXHAUSTIVE_TEST_ORDER; ++b) {
            secp256k1_generator gen_base;
            secp256k1_generator gen_blinded;
            secp256k1_ge base_ge;
            secp256k1_ge blinded_ge;
            secp256k1_ge tweak_oracle;
            secp256k1_scalar blind_scalar;

            if (skip_section(&iter)) continue;

            secp256k1_scalar_set_int(&s, i);
            secp256k1_scalar_get_b32(key32, &s);
            secp256k1_scalar_set_int(&blind_scalar, b);
            secp256k1_scalar_get_b32(blind32, &blind_scalar);

            CHECK(secp256k1_generator_generate(ctx, &gen_base, key32));
            CHECK(secp256k1_generator_generate_blinded(ctx, &gen_blinded, key32, blind32));

            secp256k1_generator_load(&base_ge, &gen_base);
            secp256k1_generator_load(&blinded_ge, &gen_blinded);

            tweak_oracle = base_ge;
            CHECK(secp256k1_eckey_pubkey_tweak_add(&tweak_oracle, &blind_scalar));
            CHECK(secp256k1_ge_eq_var(&tweak_oracle, &blinded_ge));
        }
    }
}

#endif /* SECP256K1_MODULE_GENERATOR_TESTS_EXHAUSTIVE_H */
