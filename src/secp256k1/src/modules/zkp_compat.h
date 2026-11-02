/***********************************************************************
 * ZKP compatibility shims for litecoin module code on upstream core.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_COMPAT_H
#define SECP256K1_MODULE_ZKP_COMPAT_H

#include "../group.h"
#include "../field.h"
#include "../eckey.h"
#include "../ecmult.h"
#include "../ecmult_gen.h"
#include "../hash.h"
#include "../scalar.h"
#include "../util.h"
#include "zkp_scalar_chacha20.h"

#if !defined(EXHAUSTIVE_TEST_ORDER) && !defined(SECP256K1_WIDEMUL_INT128) && !defined(SECP256K1_WIDEMUL_INT64)
#error "ZKP modules require wide multiplication support"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
static SECP256K1_INLINE void secp256k1_scalar_set_u64(secp256k1_scalar *r, uint64_t v) {
    secp256k1_scalar_set_int(r, (unsigned int)v);
}
#elif defined(SECP256K1_WIDEMUL_INT128) || defined(SECP256K1_WIDEMUL_INT64)
#if defined(SECP256K1_WIDEMUL_INT128)
static SECP256K1_INLINE void secp256k1_scalar_set_u64(secp256k1_scalar *r, uint64_t v) {
    r->d[0] = v;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
}
#else
static SECP256K1_INLINE void secp256k1_scalar_set_u64(secp256k1_scalar *r, uint64_t v) {
    r->d[0] = (uint32_t)v;
    r->d[1] = (uint32_t)(v >> 32);
    r->d[2] = 0;
    r->d[3] = 0;
    r->d[4] = 0;
    r->d[5] = 0;
    r->d[6] = 0;
    r->d[7] = 0;
}
#endif
#endif

static SECP256K1_INLINE int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    return secp256k1_fe_equal(a, b);
}

static SECP256K1_INLINE void secp256k1_scalar_sqr(secp256k1_scalar *r, const secp256k1_scalar *a) {
    secp256k1_scalar_mul(r, a, a);
}

/* --- field / group litecoin names --- */

/* Alias local name to ease merging with call sites that use ge_serialize33. */
static SECP256K1_INLINE void secp256k1_ge_serialize33(secp256k1_ge *elem, unsigned char *pub33) {
    secp256k1_eckey_pubkey_serialize33(elem, pub33);
}

/* Alias local name to ease merging with call sites that use fe_set_int_unchecked. */
#define secp256k1_fe_set_int_unchecked secp256k1_fe_set_int

static SECP256K1_INLINE int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a) {
    return secp256k1_fe_set_b32_limit(r, a);
}

static SECP256K1_INLINE int secp256k1_fe_is_quad_var(const secp256k1_fe *a) {
    return secp256k1_fe_is_square_var(a);
}

static SECP256K1_INLINE int secp256k1_ge_set_xquad(secp256k1_ge *r, const secp256k1_fe *a) {
    secp256k1_fe x2, x3;
    r->x = *a;
    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x3, a, &x2);
    r->infinity = 0;
    secp256k1_fe_add_int(&x3, 7);
    return secp256k1_fe_sqrt(&r->y, &x3);
}

static SECP256K1_INLINE int secp256k1_gej_has_quad_y_var(const secp256k1_gej *a) {
    secp256k1_fe yz;
    secp256k1_fe_mul(&yz, &a->y, &a->z);
    return secp256k1_fe_is_square_var(&yz);
}

/* --- ecmult: upstream uses static tables (no context object) --- */

static SECP256K1_INLINE int secp256k1_ecmult_context_is_built(const void *unused) {
    (void)unused;
    return 1;
}

/* --- hash helpers (ctx-threaded) --- */

static SECP256K1_INLINE void secp256k1_zkp_sha256_initialize(const secp256k1_context *ctx, secp256k1_sha256 *sha) {
    (void)ctx;
    secp256k1_sha256_initialize(sha);
}

static SECP256K1_INLINE void secp256k1_zkp_sha256_write(const secp256k1_context *ctx, secp256k1_sha256 *sha, const unsigned char *data, size_t len) {
    secp256k1_sha256_write(&ctx->hash_ctx, sha, data, len);
}

static SECP256K1_INLINE void secp256k1_zkp_sha256_finalize(const secp256k1_context *ctx, secp256k1_sha256 *sha, unsigned char *out32) {
    secp256k1_sha256_finalize(&ctx->hash_ctx, sha, out32);
}

static SECP256K1_INLINE void secp256k1_zkp_rfc6979_hmac_sha256_initialize(const secp256k1_context *ctx, secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key32, size_t keylen) {
    secp256k1_rfc6979_hmac_sha256_initialize(&ctx->hash_ctx, rng, key32, keylen);
}

static SECP256K1_INLINE void secp256k1_zkp_rfc6979_hmac_sha256_generate(const secp256k1_context *ctx, secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out32, size_t outlen) {
    secp256k1_rfc6979_hmac_sha256_generate(&ctx->hash_ctx, rng, out32, outlen);
}

#if defined(ENABLE_MODULE_SCHNORRSIG_MW)
static int secp256k1_zkp_nonce_function_default(const secp256k1_context *ctx, unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, void *data, unsigned int counter);
#endif

/* --- scratch checkpoint frame (replaces litecoin scratch_allocate_frame) --- */

static SECP256K1_INLINE size_t secp256k1_zkp_scratch_frame_begin(const secp256k1_context *ctx, secp256k1_scratch *scratch) {
    return secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
}

static SECP256K1_INLINE void secp256k1_zkp_scratch_frame_end(const secp256k1_context *ctx, secp256k1_scratch *scratch, size_t checkpoint) {
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, checkpoint);
}

static SECP256K1_INLINE int secp256k1_zkp_scratch_allocate_frame(const secp256k1_context *ctx, secp256k1_scratch *scratch, size_t n, size_t objects, size_t *checkpoint) {
    if (n == 0 || secp256k1_scratch_max_allocation(&ctx->error_callback, scratch, objects) < n) {
        return 0;
    }
    *checkpoint = secp256k1_zkp_scratch_frame_begin(ctx, scratch);
    return 1;
}

static SECP256K1_INLINE void secp256k1_zkp_scratch_deallocate_frame(const secp256k1_context *ctx, secp256k1_scratch *scratch, size_t checkpoint) {
    secp256k1_zkp_scratch_frame_end(ctx, scratch, checkpoint);
}

static SECP256K1_INLINE void *secp256k1_zkp_scratch_alloc(const secp256k1_context *ctx, secp256k1_scratch *scratch, size_t n) {
    return secp256k1_scratch_alloc(&ctx->error_callback, scratch, n);
}

#endif /* SECP256K1_MODULE_ZKP_COMPAT_H */
