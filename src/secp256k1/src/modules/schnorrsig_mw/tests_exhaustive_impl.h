/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MW_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_SCHNORRSIG_MW_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_schnorrsig_mw.h"
#include "main_impl.h"

/*
 * MW sign: sig[0:32] = R.x; sig[32:64] = (k + e*d) mod n with
 * e = SHA256(R.x || compressed(P) || m) and k adjusted for even-y R.
 *
 * verify_batch checks s*G = R + e*P on the full curve. Exhaustive scalars are
 * reduced mod EXHAUSTIVE_TEST_ORDER while ecmult uses the full curve, so
 * verify_batch cannot be exercised on this curve (scalar_negate(mod 13) != curve
 * inverse). Production verify_batch coverage is in tests_impl.h.
 *
 * Verify exhaustive tests recompute s*G + (-e)*P (aggsig-style x/y check with
 * ge_set_xquad on R.x), not verify_batch.
 */

static const unsigned char invalid_rx_bytes[][32] = {
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ((EXHAUSTIVE_TEST_ORDER + 0UL) >> 24) & 0xFF,
        ((EXHAUSTIVE_TEST_ORDER + 0UL) >> 16) & 0xFF,
        ((EXHAUSTIVE_TEST_ORDER + 0UL) >> 8) & 0xFF,
        (EXHAUSTIVE_TEST_ORDER + 0UL) & 0xFF
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ((EXHAUSTIVE_TEST_ORDER + 1UL) >> 24) & 0xFF,
        ((EXHAUSTIVE_TEST_ORDER + 1UL) >> 16) & 0xFF,
        ((EXHAUSTIVE_TEST_ORDER + 1UL) >> 8) & 0xFF,
        (EXHAUSTIVE_TEST_ORDER + 1UL) & 0xFF
    },
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
    },
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x30
    },
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }
};

#define NUM_INVALID_RX (ARRAY_SIZE(invalid_rx_bytes))

static int secp256k1_schnorrsig_mw_exhaustive_noncefp(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *ndata, unsigned int attempt) {
    secp256k1_scalar s;
    int *idata = ndata;
    (void)msg32;
    (void)key32;
    (void)algo16;
    (void)attempt;
    secp256k1_scalar_set_int(&s, *idata);
    secp256k1_scalar_get_b32(nonce32, &s);
    return 1;
}

static void secp256k1_schnorrsig_mw_exhaustive_challenge(const secp256k1_context *ctx, secp256k1_scalar *e, const unsigned char *r32, const unsigned char *msg32, const secp256k1_pubkey *pk) {
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    secp256k1_sha256 sha;

    CHECK(secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk, SECP256K1_EC_COMPRESSED));
    secp256k1_zkp_sha256_initialize(ctx, &sha);
    secp256k1_zkp_sha256_write(ctx, &sha, r32, 32);
    secp256k1_zkp_sha256_write(ctx, &sha, buf, buflen);
    secp256k1_zkp_sha256_write(ctx, &sha, msg32, 32);
    secp256k1_zkp_sha256_finalize(ctx, &sha, buf);
    secp256k1_scalar_set_b32(e, buf, NULL);
}

static int secp256k1_schnorrsig_mw_exhaustive_verify(const secp256k1_context *ctx, const secp256k1_schnorrsig_mw *sig, const unsigned char *msg32, const secp256k1_pubkey *pk) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_fe rx;
    secp256k1_ge r_ge;
    secp256k1_ge pk_ge;
    secp256k1_gej rj;
    secp256k1_gej pkj;
    int overflow;

    if (!secp256k1_fe_set_b32(&rx, sig->data)) {
        return 0;
    }
    if (!secp256k1_ge_set_xquad(&r_ge, &rx)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, sig->data + 32, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &pk_ge, pk)) {
        return 0;
    }
    secp256k1_schnorrsig_mw_exhaustive_challenge(ctx, &e, sig->data, msg32, pk);
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk_ge);
    secp256k1_ecmult(&rj, &pkj, &e, &s);
    secp256k1_ge_set_gej_var(&r_ge, &rj);
    return secp256k1_fe_equal_var(&rx, &r_ge.x) && secp256k1_gej_has_quad_y_var(&rj);
}

static void test_exhaustive_schnorrsig_mw_sign(const secp256k1_context *ctx, const secp256k1_pubkey *pubkeys, unsigned char (*rx_bytes)[32], const int *parities) {
    int d, k;
    uint64_t iter = 0;

    for (d = 1; d < EXHAUSTIVE_TEST_ORDER; ++d) {
        unsigned char seckey[32];
        secp256k1_scalar d_scalar;
        const secp256k1_pubkey *pk_ptr = &pubkeys[d - 1];

        secp256k1_scalar_set_int(&d_scalar, d);
        secp256k1_scalar_get_b32(seckey, &d_scalar);

        for (k = 1; k < EXHAUSTIVE_TEST_ORDER; ++k) {
            int e_done[EXHAUSTIVE_TEST_ORDER] = {0};
            int e_count_done = 0;
            unsigned char msg32[32];
            secp256k1_schnorrsig_mw sig;
            secp256k1_scalar k_scalar;
            int actual_k = parities[k - 1] ? EXHAUSTIVE_TEST_ORDER - k : k;

            if (skip_section(&iter)) continue;

            secp256k1_scalar_set_int(&k_scalar, actual_k);

            while (e_count_done < EXHAUSTIVE_TEST_ORDER) {
                secp256k1_scalar e;
                secp256k1_scalar expected_s;
                unsigned char expected_s_bytes[32];

                testrand256(msg32);
                secp256k1_schnorrsig_mw_exhaustive_challenge(ctx, &e, rx_bytes[k - 1], msg32, pk_ptr);
                if (!e_done[e]) {
                    secp256k1_scalar_mul(&expected_s, &e, &d_scalar);
                    secp256k1_scalar_add(&expected_s, &expected_s, &k_scalar);
                    secp256k1_scalar_get_b32(expected_s_bytes, &expected_s);

                    CHECK(secp256k1_schnorrsig_mw_sign(ctx, &sig, NULL, msg32, seckey, secp256k1_schnorrsig_mw_exhaustive_noncefp, &k));
                    CHECK(secp256k1_memcmp_var(sig.data, rx_bytes[k - 1], 32) == 0);
                    CHECK(secp256k1_memcmp_var(sig.data + 32, expected_s_bytes, 32) == 0);
                    CHECK(secp256k1_schnorrsig_mw_exhaustive_verify(ctx, &sig, msg32, pk_ptr));

                    e_done[e] = 1;
                    ++e_count_done;
                }
            }
        }
    }
}

static void test_exhaustive_schnorrsig_mw_verify(const secp256k1_context *ctx, const secp256k1_pubkey *pubkeys, unsigned char (*rx_bytes)[32], const int *parities) {
    int d;
    uint64_t iter = 0;

    for (d = 1; d < EXHAUSTIVE_TEST_ORDER; ++d) {
        unsigned k;

        for (k = 1; k <= EXHAUSTIVE_TEST_ORDER / 2 + NUM_INVALID_RX; ++k) {
            unsigned char sig64[64];
            int actual_k = -1;
            int e_done[EXHAUSTIVE_TEST_ORDER] = {0};
            int e_count_done = 0;

            if (skip_section(&iter)) continue;

            if (k <= EXHAUSTIVE_TEST_ORDER / 2) {
                memcpy(sig64, rx_bytes[k - 1], 32);
                actual_k = parities[k - 1] ? EXHAUSTIVE_TEST_ORDER - k : k;
            } else {
                memcpy(sig64, invalid_rx_bytes[k - 1 - EXHAUSTIVE_TEST_ORDER / 2], 32);
            }

            while (e_count_done < EXHAUSTIVE_TEST_ORDER) {
                secp256k1_scalar e;
                unsigned char msg32[32];

                testrand256(msg32);
                secp256k1_schnorrsig_mw_exhaustive_challenge(ctx, &e, sig64, msg32, &pubkeys[d - 1]);
                if (!e_done[e]) {
                    int count_valid = 0;
                    unsigned int s;
                    secp256k1_schnorrsig_mw sig;

                    memcpy(sig.data, sig64, 32);
                    for (s = 0; s <= EXHAUSTIVE_TEST_ORDER + 1; ++s) {
                        int expect_valid;
                        int valid;
                        int s_int = (int)s;

                        if (s <= EXHAUSTIVE_TEST_ORDER) {
                            memset(sig.data + 32, 0, 32);
                            secp256k1_write_be32(sig.data + 60, s);
                            expect_valid = actual_k != -1
                                && s_int != EXHAUSTIVE_TEST_ORDER
                                && (s_int == (actual_k + (int)d * (int)e) % EXHAUSTIVE_TEST_ORDER);
                        } else {
                            testrand256(sig.data + 32);
                            expect_valid = 0;
                        }
                        valid = secp256k1_schnorrsig_mw_exhaustive_verify(ctx, &sig, msg32, &pubkeys[d - 1]);
                        CHECK(valid == expect_valid);
                        count_valid += valid;
                    }
                    CHECK(count_valid == (actual_k != -1));
                    e_done[e] = 1;
                    ++e_count_done;
                }
            }
        }
    }
}

static void test_exhaustive_schnorrsig_mw(const secp256k1_context *ctx) {
    secp256k1_context *sign_ctx;
    secp256k1_pubkey pubkeys[EXHAUSTIVE_TEST_ORDER - 1];
    unsigned char rx_bytes[EXHAUSTIVE_TEST_ORDER - 1][32];
    int parities[EXHAUSTIVE_TEST_ORDER - 1];
    unsigned i;

    (void)ctx;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; ++i) {
        secp256k1_scalar scalar_i;
        secp256k1_ge pt;
        unsigned char seckey[32];

        secp256k1_scalar_set_int(&scalar_i, i);
        secp256k1_scalar_get_b32(seckey, &scalar_i);
        CHECK(secp256k1_ec_pubkey_create(sign_ctx, &pubkeys[i - 1], seckey));
        secp256k1_ecmult_gen_ge(&sign_ctx->ecmult_gen_ctx, &pt, &scalar_i);
        secp256k1_fe_normalize_var(&pt.x);
        secp256k1_fe_get_b32(rx_bytes[i - 1], &pt.x);
        parities[i - 1] = !secp256k1_fe_is_quad_var(&pt.y);
    }

    test_exhaustive_schnorrsig_mw_sign(sign_ctx, pubkeys, rx_bytes, parities);
    test_exhaustive_schnorrsig_mw_verify(sign_ctx, pubkeys, rx_bytes, parities);

    secp256k1_context_destroy(sign_ctx);
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_MW_TESTS_EXHAUSTIVE_H */
