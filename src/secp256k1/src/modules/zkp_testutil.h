/***********************************************************************
 * Shared helpers for ZKP module tests.
 **********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_TESTUTIL_H
#define SECP256K1_MODULE_ZKP_TESTUTIL_H

#include "../group.h"
#include "../testrand.h"
#include "../testutil.h"
#include "../util.h"

#define random_scalar_order_test testutil_random_scalar_order_test
#define random_scalar_order testutil_random_scalar_order

/* Litecoin-ported test helpers */
#define secp256k1_rand256 testrand256
#define secp256k1_rand32 testrand32
#define secp256k1_rand_int testrand_int
#define secp256k1_rand_bits testrand_bits

static int64_t secp256k1_rands64(int64_t min, int64_t max) {
    if (max <= min) {
        return min;
    }
    /* Cast before +1 so max==INT64_MAX does not overflow signed arithmetic. */
    return min + (int64_t)(testrand64() % ((uint64_t)(max - min) + 1));
}

static void counting_illegal_callback_fn(const char* str, void* data) {
    int32_t *p = (int32_t*)data;
    (void)str;
    if (p) {
        (*p)++;
    }
}

static void random_field_element_test(secp256k1_fe *fe) {
    do {
        unsigned char b32[32];
        testrand256(b32);
        if (secp256k1_fe_set_b32_limit(fe, b32)) {
            break;
        }
    } while (1);
}

static void random_group_element_test(secp256k1_ge *ge) {
    secp256k1_fe fe;
    do {
        random_field_element_test(&fe);
        if (secp256k1_ge_set_xo_var(ge, &fe, testrand_bits(1))) {
            secp256k1_fe_normalize(&ge->y);
            break;
        }
    } while (1);
}

#endif /* SECP256K1_MODULE_ZKP_TESTUTIL_H */
