/***********************************************************************
 * Public scratch space sizing helpers for ZKP modules.
 **********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_SCRATCH_IMPL_H
#define SECP256K1_MODULE_ZKP_SCRATCH_IMPL_H

#include "../../include/secp256k1_scratch.h"
#include "../ecmult_impl.h"

#ifdef __cplusplus
extern "C" {
#endif
SECP256K1_API size_t secp256k1_scratch_space_max_ecmult_points(const secp256k1_context *ctx, const secp256k1_scratch *scratch) {
    VERIFY_CHECK(ctx != NULL);
    VERIFY_CHECK(scratch != NULL);
    return secp256k1_pippenger_max_points(&ctx->error_callback, (secp256k1_scratch *)scratch);
}

SECP256K1_API size_t secp256k1_scratch_space_recommended_size(const secp256k1_context *ctx, size_t n_points) {
    int bucket_window;
    (void)ctx;
    VERIFY_CHECK(ctx != NULL);
    if (n_points == 0) {
        return 0;
    }
    bucket_window = secp256k1_pippenger_bucket_window(n_points);
    return secp256k1_pippenger_scratch_size(n_points, bucket_window);
}
#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_MODULE_ZKP_SCRATCH_IMPL_H */
