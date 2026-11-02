/**********************************************************************
 * Mimblewimble / Litecoin Schnorr (non-BIP-340 sign + batch verify)
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MW_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MW_MAIN_H

#include "../zkp_compat.h"
#include "../../../include/secp256k1_schnorrsig_mw.h"
#include "../../eckey.h"
#include "../../hash.h"
#include "../../util.h"
#include <string.h>

static void secp256k1_schnorrsig_mw_challenge(const secp256k1_context *ctx, secp256k1_scalar *e, const unsigned char *r32, const unsigned char *msg32, const unsigned char *pubkey32) {
    unsigned char buf[32];
    secp256k1_sha256 sha;

    secp256k1_zkp_sha256_initialize(ctx, &sha);
    secp256k1_zkp_sha256_write(ctx, &sha, r32, 32);
    secp256k1_zkp_sha256_write(ctx, &sha, pubkey32, 32);
    secp256k1_zkp_sha256_write(ctx, &sha, msg32, 32);
    secp256k1_zkp_sha256_finalize(ctx, &sha, buf);
    secp256k1_scalar_set_b32(e, buf, NULL);
}

int secp256k1_schnorrsig_mw_serialize(const secp256k1_context *ctx, unsigned char *out64, const secp256k1_schnorrsig_mw *sig) {
    (void)ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out64 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out64, sig->data, 64);
    return 1;
}

int secp256k1_schnorrsig_mw_parse(const secp256k1_context *ctx, secp256k1_schnorrsig_mw *sig, const unsigned char *in64) {
    (void)ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in64 != NULL);
    memcpy(sig->data, in64, 64);
    return 1;
}

int secp256k1_schnorrsig_mw_sign(const secp256k1_context *ctx, secp256k1_schnorrsig_mw *sig, int *nonce_is_negated, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, void *ndata) {
    secp256k1_scalar x;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej pkj;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[33];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        secp256k1_memclear_explicit(sig, sizeof(*sig));
        return 0;
    }

    secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &pkj, &x);
    secp256k1_ge_set_gej_var(&pk, &pkj);

    if (noncefp == NULL) {
        if (!secp256k1_zkp_nonce_function_default(ctx, buf, msg32, seckey, ndata, 0)) {
            secp256k1_scalar_clear(&x);
            return 0;
        }
    } else if (!noncefp(buf, msg32, seckey, NULL, ndata, 0)) {
        secp256k1_scalar_clear(&x);
        return 0;
    }
    secp256k1_scalar_set_b32(&k, buf, NULL);
    secp256k1_memclear_explicit(buf, sizeof(buf));
    if (secp256k1_scalar_is_zero(&k)) {
        secp256k1_scalar_clear(&x);
        secp256k1_scalar_clear(&k);
        return 0;
    }

    secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej_var(&r, &rj);

    if (nonce_is_negated != NULL) {
        *nonce_is_negated = 0;
    }
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
        if (nonce_is_negated != NULL) {
            *nonce_is_negated = 1;
        }
    }
    secp256k1_fe_normalize_var(&r.x);
    secp256k1_fe_get_b32(&sig->data[0], &r.x);

    secp256k1_zkp_sha256_initialize(ctx, &sha);
    secp256k1_zkp_sha256_write(ctx, &sha, &sig->data[0], 32);
    secp256k1_ge_serialize33(&pk, buf);
    secp256k1_zkp_sha256_write(ctx, &sha, buf, 33);
    secp256k1_zkp_sha256_write(ctx, &sha, msg32, 32);
    secp256k1_zkp_sha256_finalize(ctx, &sha, buf);

    secp256k1_scalar_set_b32(&e, buf, NULL);
    secp256k1_scalar_mul(&e, &e, &x);
    secp256k1_scalar_add(&e, &e, &k);

    secp256k1_scalar_get_b32(&sig->data[32], &e);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&x);

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    unsigned char chacha_seed[32];
    secp256k1_scalar randomizer_cache[2];
    const secp256k1_schnorrsig_mw *const *sig;
    const unsigned char *const *msg32;
    const secp256k1_pubkey *const *pk;
    size_t n_sigs;
} secp256k1_schnorrsig_mw_verify_ecmult_context;

static int secp256k1_schnorrsig_mw_verify_batch_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_schnorrsig_mw_verify_ecmult_context *ecmult_context = (secp256k1_schnorrsig_mw_verify_ecmult_context *)data;
    const secp256k1_context *ctx = ecmult_context->ctx;

    if (idx % 4 == 2) {
        secp256k1_scalar_chacha20(&ecmult_context->randomizer_cache[0], &ecmult_context->randomizer_cache[1], ecmult_context->chacha_seed, idx / 4);
    }

    if (idx % 2 == 0) {
        secp256k1_fe rx;
        *sc = ecmult_context->randomizer_cache[(idx / 2) % 2];
        if (!secp256k1_fe_set_b32(&rx, &ecmult_context->sig[idx / 2]->data[0])) {
            return 0;
        }
        if (!secp256k1_ge_set_xquad(pt, &rx)) {
            return 0;
        }
    } else {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_sha256 sha;

        secp256k1_zkp_sha256_initialize(ctx, &sha);
        secp256k1_zkp_sha256_write(ctx, &sha, &ecmult_context->sig[idx / 2]->data[0], 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, ecmult_context->pk[idx / 2], SECP256K1_EC_COMPRESSED);
        secp256k1_zkp_sha256_write(ctx, &sha, buf, buflen);
        secp256k1_zkp_sha256_write(ctx, &sha, ecmult_context->msg32[idx / 2], 32);
        secp256k1_zkp_sha256_finalize(ctx, &sha, buf);

        secp256k1_scalar_set_b32(sc, buf, NULL);
        secp256k1_scalar_mul(sc, sc, &ecmult_context->randomizer_cache[(idx / 2) % 2]);

        if (!secp256k1_pubkey_load(ctx, pt, ecmult_context->pk[idx / 2])) {
            return 0;
        }
    }
    return 1;
}

static int secp256k1_schnorrsig_mw_verify_batch_init_randomizer(const secp256k1_context *ctx, secp256k1_schnorrsig_mw_verify_ecmult_context *ecmult_context, secp256k1_sha256 *sha, const secp256k1_schnorrsig_mw *const *sig, const unsigned char *const *msg32, const secp256k1_pubkey *const *pk, size_t n_sigs) {
    size_t i;

    if (n_sigs > 0) {
        ARG_CHECK(sig != NULL);
        ARG_CHECK(msg32 != NULL);
        ARG_CHECK(pk != NULL);
    }

    for (i = 0; i < n_sigs; i++) {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_zkp_sha256_write(ctx, sha, sig[i]->data, 64);
        secp256k1_zkp_sha256_write(ctx, sha, msg32[i], 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk[i], SECP256K1_EC_COMPRESSED);
        secp256k1_zkp_sha256_write(ctx, sha, buf, 32);
    }
    ecmult_context->ctx = ctx;
    ecmult_context->sig = sig;
    ecmult_context->msg32 = msg32;
    ecmult_context->pk = pk;
    ecmult_context->n_sigs = n_sigs;

    return 1;
}

static int secp256k1_schnorrsig_mw_verify_batch_sum_s(secp256k1_scalar *s, unsigned char *chacha_seed, const secp256k1_schnorrsig_mw *const *sig, size_t n_sigs) {
    secp256k1_scalar randomizer_cache[2];
    size_t i;

    secp256k1_scalar_set_int(&randomizer_cache[0], 1);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;
        if (i % 2 == 1) {
            secp256k1_scalar_chacha20(&randomizer_cache[0], &randomizer_cache[1], chacha_seed, i / 2);
        }

        secp256k1_scalar_set_b32(&term, &sig[i]->data[32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_mul(&term, &term, &randomizer_cache[i % 2]);
        secp256k1_scalar_add(s, s, &term);
    }
    return 1;
}

int secp256k1_schnorrsig_mw_verify_batch(const secp256k1_context *ctx, secp256k1_scratch *scratch, const secp256k1_schnorrsig_mw *const *sig, const unsigned char *const *msg32, const secp256k1_pubkey *const *pk, size_t n_sigs) {
    secp256k1_schnorrsig_mw_verify_ecmult_context ecmult_context;
    secp256k1_sha256 sha;
    secp256k1_scalar s;
    secp256k1_gej rj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(n_sigs <= SIZE_MAX / 2);
    ARG_CHECK(n_sigs < ((size_t)1 << 31));

    secp256k1_zkp_sha256_initialize(ctx, &sha);
    if (!secp256k1_schnorrsig_mw_verify_batch_init_randomizer(ctx, &ecmult_context, &sha, sig, msg32, pk, n_sigs)) {
        return 0;
    }
    secp256k1_zkp_sha256_finalize(ctx, &sha, ecmult_context.chacha_seed);
    secp256k1_scalar_set_int(&ecmult_context.randomizer_cache[0], 1);

    secp256k1_scalar_set_int(&s, 0);
    if (!secp256k1_schnorrsig_mw_verify_batch_sum_s(&s, ecmult_context.chacha_seed, sig, n_sigs)) {
        return 0;
    }
    secp256k1_scalar_negate(&s, &s);

    return secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &s, secp256k1_schnorrsig_mw_verify_batch_ecmult_callback, (void *)&ecmult_context, 2 * n_sigs)
        && secp256k1_gej_is_infinity(&rj);
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_MW_MAIN_H */
