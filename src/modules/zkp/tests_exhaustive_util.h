/***********************************************************************
 * Copyright (c) 2026 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_TESTS_EXHAUSTIVE_UTIL_H
#define SECP256K1_MODULE_ZKP_TESTS_EXHAUSTIVE_UTIL_H

#include "../../group.h"
#include "../../scalar.h"
#include "../commitment/pedersen_impl.h"

static void secp256k1_zkp_exhaustive_scalar_to_key32(unsigned char *key32, int v) {
    secp256k1_scalar s;
    secp256k1_scalar_set_int(&s, v);
    secp256k1_scalar_get_b32(key32, &s);
}

static void secp256k1_zkp_exhaustive_oracle_pedersen_commit(secp256k1_ge *out, const secp256k1_scalar *blind, uint64_t value, const secp256k1_ge *value_gen, const secp256k1_ge *blind_gen) {
    secp256k1_gej rj;
    secp256k1_pedersen_ecmult(&rj, blind, value, value_gen, blind_gen);
    secp256k1_ge_set_gej(out, &rj);
}

#endif /* SECP256K1_MODULE_ZKP_TESTS_EXHAUSTIVE_UTIL_H */
