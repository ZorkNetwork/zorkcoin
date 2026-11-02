#ifndef SECP256K1_SCRATCH_H
#define SECP256K1_SCRATCH_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque scratch space for multi-scalar multiplication (ZKP modules). */
typedef struct secp256k1_scratch_space_struct secp256k1_scratch;

/** Create scratch space for reuse across verify/prove calls. */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT secp256k1_scratch *secp256k1_scratch_space_create(
    const secp256k1_context *ctx,
    size_t max_size
) SECP256K1_ARG_NONNULL(1);

/** Destroy scratch space. */
SECP256K1_API void secp256k1_scratch_space_destroy(
    const secp256k1_context *ctx,
    secp256k1_scratch *scratch
) SECP256K1_ARG_NONNULL(1);

/** Maximum number of points supported by scratch for ecmult_multi. */
SECP256K1_API size_t secp256k1_scratch_space_max_ecmult_points(
    const secp256k1_context *ctx,
    const secp256k1_scratch *scratch
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Recommended scratch size for a given number of ecmult_multi points. */
SECP256K1_API size_t secp256k1_scratch_space_recommended_size(
    const secp256k1_context *ctx,
    size_t n_points
) SECP256K1_ARG_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCRATCH_H */
