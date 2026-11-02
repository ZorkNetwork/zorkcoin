/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_BULLETPROOF_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_bulletproofs.h"
#include "../../../include/secp256k1_generator.h"
#include "../../../include/secp256k1_scratch.h"
#include "../generator/main_impl.h"
#include "../zkp/tests_exhaustive_util.h"
#include "main_impl.h"

/*
 * Full bulletproof prove+verify roundtrips do not run on the order-13 exhaustive
 * curve: challenge scalars from SHA256 almost always overflow scalar_set_b32,
 * and the exhaustive chacha20 stub fixes alpha=0 for rangeproofs. Inner-product
 * prove works for n<=2 but verify_impl fails before its trivial fast-path.
 * Full consistency testing remains in tests_impl.h on secp256k1.
 *
 * Exhaustive tests therefore cover generators, proof-length arithmetic,
 * point serialize roundtrips, inner-product prove structure (n<=2), and
 * basic API guards.
 */

static int secp256k1_bulletproof_exhaustive_abgh_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    (void)data;
    (void)pt;
    secp256k1_scalar_set_int(sc, (int)(idx + 1));
    return 1;
}

static void test_exhaustive_bulletproof_innerproduct_proof_length(void) {
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(0) == 32);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(1) == 96);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(2) == 160);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(4) == 225);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(8) == 289);
}

static void test_exhaustive_bulletproof_generators(const secp256k1_context *ctx) {
    secp256k1_bulletproof_generators *gens_a;
    secp256k1_bulletproof_generators *gens_b;
    size_t n;
    size_t i;

    secp256k1_ge blinding_oracle;

    secp256k1_generator_load(&blinding_oracle, &secp256k1_generator_const_h);
    for (n = 2; n <= 8; n *= 2) {
        gens_a = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, n);
        gens_b = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, n);
        CHECK(gens_a != NULL);
        CHECK(gens_b != NULL);
        CHECK(gens_a->n == n);
        for (i = 0; i < n; ++i) {
            CHECK(secp256k1_ge_eq_var(&gens_a->gens[i], &gens_b->gens[i]));
        }
        CHECK(secp256k1_ge_eq_var(&gens_a->blinding_gen[0], &gens_b->blinding_gen[0]));
        CHECK(secp256k1_ge_eq_var(&gens_a->blinding_gen[0], &blinding_oracle));
        secp256k1_bulletproof_generators_destroy(ctx, gens_a);
        secp256k1_bulletproof_generators_destroy(ctx, gens_b);
    }
}

static void test_exhaustive_bulletproof_point_serialize(const secp256k1_context *ctx) {
    int i;
    uint64_t iter = 0;

    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        secp256k1_generator gen;
        secp256k1_ge pt;
        secp256k1_ge recovered;
        unsigned char key32[32];
        unsigned char buf[64];

        if (skip_section(&iter)) continue;

        secp256k1_zkp_exhaustive_scalar_to_key32(key32, i);
        CHECK(secp256k1_generator_generate(ctx, &gen, key32));
        secp256k1_generator_load(&pt, &gen);

        secp256k1_bulletproof_serialize_points(buf, &pt, 1);
        CHECK(secp256k1_bulletproof_deserialize_point(&recovered, buf, 0, 1));
        CHECK(secp256k1_fe_equal_var(&pt.x, &recovered.x));
        CHECK(secp256k1_fe_is_quad_var(&pt.y) == secp256k1_fe_is_quad_var(&recovered.y));
    }
}

static void test_exhaustive_bulletproof_inner_product_prove(const secp256k1_context *ctx, const secp256k1_bulletproof_generators *gens) {
    size_t n;
    unsigned char commit[32] = {0x42};
    secp256k1_scalar one;
    secp256k1_scratch *scratch;
    uint64_t iter = 0;

    secp256k1_scalar_set_int(&one, 1);
    scratch = secp256k1_scratch_create(&ctx->error_callback, 256 * 1024);

    for (n = 0; n <= 2; ++n) {
        unsigned char proof[200];
        size_t plen = sizeof(proof);
        secp256k1_scalar dot;
        secp256k1_scalar expected_dot;
        secp256k1_scalar a[2];
        secp256k1_scalar b[2];
        size_t i;

        if (skip_section(&iter)) continue;

        CHECK(secp256k1_bulletproof_inner_product_prove_impl(ctx, scratch, proof, &plen, gens, &one, n, secp256k1_bulletproof_exhaustive_abgh_callback, NULL, commit));
        CHECK(plen == secp256k1_bulletproof_innerproduct_proof_length(n));

        secp256k1_scalar_set_int(&expected_dot, 0);
        for (i = 0; i < n; ++i) {
            secp256k1_scalar_set_int(&a[i], (int)(2 * i + 1));
            secp256k1_scalar_set_int(&b[i], (int)(2 * i + 2));
            secp256k1_scalar_mul(&a[i], &a[i], &b[i]);
            secp256k1_scalar_add(&expected_dot, &expected_dot, &a[i]);
        }

        secp256k1_scalar_set_b32(&dot, proof, NULL);
        CHECK(secp256k1_scalar_eq(&dot, &expected_dot));

        for (i = 0; i < n; ++i) {
            secp256k1_scalar parsed;
            secp256k1_scalar expected_a;
            secp256k1_scalar expected_b;

            secp256k1_scalar_set_int(&expected_a, (int)(2 * i + 1));
            secp256k1_scalar_set_int(&expected_b, (int)(2 * i + 2));
            secp256k1_scalar_set_b32(&parsed, &proof[32 * (i + 1)], NULL);
            CHECK(secp256k1_scalar_eq(&parsed, &expected_a));
            secp256k1_scalar_set_b32(&parsed, &proof[32 * (i + n + 1)], NULL);
            CHECK(secp256k1_scalar_eq(&parsed, &expected_b));
        }
    }

    secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

static void test_exhaustive_bulletproof_api_guards(const secp256k1_context *ctx) {
    secp256k1_bulletproof_generators *gens;
    secp256k1_scratch *scratch;
    unsigned char proof[64];
    size_t plen = 0;
    secp256k1_pedersen_commitment commit;
    memset(&commit, 0, sizeof(commit));

    gens = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, 4);
    CHECK(gens != NULL);
    scratch = secp256k1_scratch_create(&ctx->error_callback, 256 * 1024);

    CHECK(secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, plen, NULL, &commit, 1, 1, &secp256k1_generator_const_h, NULL, 0) == 0);

    secp256k1_scratch_destroy(&ctx->error_callback, scratch);
    secp256k1_bulletproof_generators_destroy(ctx, gens);
}

static void test_exhaustive_bulletproof(const secp256k1_context *ctx) {
    secp256k1_bulletproof_generators *gens;

    test_exhaustive_bulletproof_innerproduct_proof_length();
    test_exhaustive_bulletproof_generators(ctx);
    test_exhaustive_bulletproof_point_serialize(ctx);
    test_exhaustive_bulletproof_api_guards(ctx);

    gens = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, 4);
    CHECK(gens != NULL);
    test_exhaustive_bulletproof_inner_product_prove(ctx, gens);
    secp256k1_bulletproof_generators_destroy(ctx, gens);
}

#endif /* SECP256K1_MODULE_BULLETPROOF_TESTS_EXHAUSTIVE_H */
