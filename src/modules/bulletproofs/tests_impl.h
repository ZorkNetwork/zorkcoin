/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_TESTS
#define SECP256K1_MODULE_BULLETPROOF_TESTS

#include <string.h>

#include "../../group.h"
#include "../../scalar.h"
#include "../../unit_test.h"
#include "../../testrand.h"
#include "../../util.h"
#include "../zkp_testutil.h"

#include "../../../include/secp256k1_bulletproofs.h"

static void test_bulletproof_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch *scratch = secp256k1_scratch_create(&CTX->error_callback, 1024 * 1024);
    secp256k1_generator value_gen;
    secp256k1_bulletproof_generators *gens;
    secp256k1_pedersen_commitment pcommit[4];
    const secp256k1_pedersen_commitment *pcommit_arr[1];
    unsigned char proof[2000];
    unsigned char malformed_proof[2000];
    const unsigned char *proof_ptr = proof;
    const unsigned char *malformed_proof_ptr = malformed_proof;
    unsigned char blind[32];
    const unsigned char *blind_ptr[4];
    size_t blindlen = sizeof(blind);
    size_t plen = sizeof(proof);
    uint64_t value[4] = { 1234, 4567, 8910, 1112 } ;
    uint64_t min_value[4] = { 1000, 4567, 0, 5000 } ;
    const uint64_t *mv_ptr = min_value;
    unsigned char shared_msg[32];
    unsigned char private_msg[32];
    unsigned char expected_msg[32];
    unsigned char message[32];
    size_t shared_len;
    size_t private_len;
    secp256k1_pubkey t_one, t_two;
    const secp256k1_pedersen_commitment *mp_commits[2];

    int32_t ecount = 0;

    memcpy(blind, "   i am not a blinding factor   ", blindlen);
    memcpy(message, "a 32-byte message for rewinding!", sizeof(message));
    blind_ptr[0] = blind;
    blind_ptr[1] = blind;
    blind_ptr[2] = blind;
    blind_ptr[3] = blind;
    pcommit_arr[0] = pcommit;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    CHECK(secp256k1_generator_generate(both, &value_gen, blind) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[0], blind, value[0], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[1], blind, value[1], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[2], blind, value[2], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[3], blind, value[3], &value_gen, &secp256k1_generator_const_h) != 0);

    /* generators */
    gens = secp256k1_bulletproof_generators_create(none, NULL, 256);
    CHECK(gens == NULL && ecount == 1);
    gens = secp256k1_bulletproof_generators_create(none, &secp256k1_generator_const_h, 256);
    CHECK(gens != NULL && ecount == 1);

    /* rangeproof_prove */
    ecount = 0;
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(none, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
    CHECK(ecount == 0);
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(sign, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
    CHECK(ecount == 0);
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(vrfy, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
    CHECK(ecount == 0);
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
    CHECK(ecount == 0);
    plen = 2000;
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
    CHECK(ecount == 0);
    plen = 2000;
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 4, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0); /* too few gens */
    CHECK(ecount == 1);

    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, min_value, blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1); /* mv = v, ok */
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, &value[1], &min_value[1], blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1); /* mv = 0, ok */
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, &value[2], &min_value[2], blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0); /* mv > v, !ok */
    CHECK(ecount == 1);

    CHECK(secp256k1_bulletproof_rangeproof_prove(both, NULL, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, NULL, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, NULL, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, NULL, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, NULL, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, NULL, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 0, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, NULL, 64, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 0, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 65, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, -1, blind, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, NULL, NULL, NULL, 0, NULL) == 0);
    CHECK(ecount == 13);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, blind, 0, NULL) == 1);
    CHECK(ecount == 13);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, min_value, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, blind, 32, NULL) == 1);
    CHECK(ecount == 13);

    /* Malformed A/S and T1/T2 points must release the verifier's scratch allocations. */
    {
        const size_t malformed_point_indices[2] = {0, 2};
        size_t point_case;
        for (point_case = 0; point_case < 2; point_case++) {
            secp256k1_ge parsed_point;
            const size_t point_index = malformed_point_indices[point_case];
            const size_t point_offset = 64 + 1 + point_index * 32;
            size_t invalid_x;
            size_t repeat;

            memcpy(malformed_proof, proof, plen);
            for (invalid_x = 0; invalid_x < 256; invalid_x++) {
                memset(&malformed_proof[point_offset], 0, 32);
                malformed_proof[point_offset + 31] = (unsigned char)invalid_x;
                if (!secp256k1_bulletproof_deserialize_point(&parsed_point, &malformed_proof[64], point_index, 4)) {
                    break;
                }
            }
            CHECK(invalid_x < 256);

            for (repeat = 0; repeat < 8; repeat++) {
                CHECK(scratch->alloc_size == 0);
                CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, malformed_proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
                CHECK(scratch->alloc_size == 0);
                CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &malformed_proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
                CHECK(scratch->alloc_size == 0);
            }
        }
    }

    /* rangeproof_verify */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_verify(none, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(sign, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(vrfy, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 0);

    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen - 1, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, 0, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 31) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, NULL, 0) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 2, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 4, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 1);

    CHECK(secp256k1_bulletproof_rangeproof_verify(both, NULL, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, NULL, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, NULL, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, NULL, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, NULL, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 0, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 65, &value_gen, blind, 32) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 0, &value_gen, blind, 32) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, NULL, blind, 32) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, NULL, 32) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 0) == 0);
    CHECK(ecount == 10);

    /* verify_multi */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(none, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(sign, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(vrfy, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 0);

    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, NULL, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, NULL, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, NULL, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 0, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, NULL, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, NULL, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, NULL, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, NULL, &blindlen) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, NULL) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, NULL, NULL) == 0);
    CHECK(ecount == 8);

    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 0, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 65, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 63, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 0, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 2, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 4, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 12);

    /* Rewind */
    ecount = 0;
    shared_len = private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 1);
    CHECK(ecount == 0);
    CHECK(shared_len == 32 && private_len == 32);
    /* Without a message the shared payload is the value; the private payload is the blinding factor. */
    memset(expected_msg, 0, 32);
    expected_msg[30] = value[0] >> 8;
    expected_msg[31] = value[0] & 0xFF;
    CHECK(memcmp(shared_msg, expected_msg, 32) == 0);
    CHECK(memcmp(private_msg, blind, 32) == 0);
    /* Either half may be omitted */
    shared_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, NULL, NULL, proof, plen, min_value[0], pcommit, &value_gen, blind, NULL, blind, 32) == 1);
    CHECK(memcmp(shared_msg, expected_msg, 32) == 0);
    private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, NULL, NULL, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, NULL, blind, blind, 32) == 1);
    CHECK(memcmp(private_msg, blind, 32) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, NULL, NULL, NULL, NULL, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, NULL, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, NULL, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, NULL, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, 0, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, min_value[0], NULL, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, min_value[0], pcommit, NULL, blind, blind, blind, 32) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, NULL, NULL, blind, 32) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, NULL, NULL, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, NULL, NULL, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, blind, 32) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, NULL, 32) == 0);
    CHECK(ecount == 10);

    /* A 32-byte message replaces the value in the shared payload */
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, message) == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, NULL, pcommit, 1, 64, &value_gen, NULL, 0) == 1);
    shared_len = private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, 0, pcommit, &value_gen, blind, blind, NULL, 0) == 1);
    CHECK(memcmp(shared_msg, message, 32) == 0);
    CHECK(memcmp(private_msg, blind, 32) == 0);
    /* A message whose nonce is not given is not extracted and reports a length of 0 */
    shared_len = private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, plen, 0, pcommit, &value_gen, NULL, blind, NULL, 0) == 1);
    CHECK(shared_len == 0 && private_len == 32);
    /* A failed rewind extracts nothing */
    shared_len = private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, shared_msg, &shared_len, private_msg, &private_len, proof, 0, 0, pcommit, &value_gen, blind, blind, NULL, 0) == 0);
    CHECK(shared_len == 0 && private_len == 0);
    CHECK(ecount == 10);
    /* A message needs exactly one commitment */
    plen = 2000;
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, message) == 0);
    CHECK(ecount == 10);
    /* ...including in the first step of a multi-party proof */
    mp_commits[0] = &pcommit[0];
    mp_commits[1] = &pcommit[1];
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, NULL, NULL, NULL, &t_one, &t_two, value, NULL, blind_ptr, mp_commits, 2, &value_gen, 64, blind, blind, NULL, 0, message) == 0);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, NULL, NULL, NULL, &t_one, &t_two, value, NULL, blind_ptr, mp_commits, 2, &value_gen, 64, blind, blind, NULL, 0, NULL) == 1);
    CHECK(ecount == 10);

    /* Not covered yet. These are not a priority at this time: the MWEB caller cannot reach any of them,
     * since it always proves a single commitment with a hash-derived 32-byte message below the group order
     * and a blinding factor from secp256k1_blind_switch, authenticates the full proof bytes with the output
     * signature, and only rewinds the shared message into a 32-byte buffer.
     * - A message >= the group order round-trips through SHARED_MSG_OVERFLOW.
     * - A first blinding factor >= the group order round-trips through PRIVATE_MSG_OVERFLOW.
     * - An all-zero blinding factor is accepted by prove.
     * - Changing the flag bits in proof[64] still verifies, while rewind fails or recovers the wrong message.
     * - A multi-party proof whose summed tau_x is zero is rejected in the final step.
     * - A shared_msg_len or private_msg_len below 32 truncates the extracted message.
     */

    secp256k1_bulletproof_generators_destroy(none, gens);
    secp256k1_bulletproof_generators_destroy(none, NULL);
    secp256k1_scratch_destroy(&CTX->error_callback, scratch);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

#define MAX_WIDTH (1ul << 20)
typedef struct {
    const secp256k1_scalar *a;
    const secp256k1_scalar *b;
    const secp256k1_ge *g;
    const secp256k1_ge *h;
    size_t n;
} test_bulletproof_ecmult_context;

static int test_bulletproof_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    test_bulletproof_ecmult_context *ecctx = (test_bulletproof_ecmult_context *) data;
    if (idx < ecctx->n) {
        *sc = ecctx->a[idx];
        *pt = ecctx->g[idx];
    } else {
        VERIFY_CHECK(idx < 2*ecctx->n);
        *sc = ecctx->b[idx - ecctx->n];
        *pt = ecctx->h[idx - ecctx->n];
    }
    return 1;
}

typedef struct {
    secp256k1_scalar offs;
    secp256k1_scalar ext_sc;
    secp256k1_scalar skew_sc;
    secp256k1_ge ext_pt;
    secp256k1_ge p;
    size_t n;
    int parity;
} test_bulletproof_offset_context;

static int test_bulletproof_offset_vfy_callback(secp256k1_scalar *sc, secp256k1_ge *pt, secp256k1_scalar *randomizer, size_t idx, void *data) {
    test_bulletproof_offset_context *ecctx = (test_bulletproof_offset_context *) data;
    secp256k1_scalar_set_int(&ecctx->offs, 1);
    if (idx < 2 * ecctx->n) {
        secp256k1_scalar idxsc;
        secp256k1_scalar_set_int(&idxsc, idx);
        secp256k1_scalar_mul(sc, &ecctx->skew_sc, &idxsc);
    } else {
        if (ecctx->parity) {
            *sc = ecctx->ext_sc;
            *pt = ecctx->ext_pt;
        } else {
            secp256k1_scalar_set_int(sc, 1);
            *pt = ecctx->p;
        }
    }
    secp256k1_scalar_mul(sc, sc, randomizer);
    ecctx->parity = !ecctx->parity;
    return 1;
}

typedef struct {
    const secp256k1_scalar *a_arr;
    const secp256k1_scalar *b_arr;
} secp256k1_bulletproof_ip_test_abgh_data;


static int secp256k1_bulletproof_ip_test_abgh_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_ip_test_abgh_data *cbctx = (secp256k1_bulletproof_ip_test_abgh_data *) data;
    const int is_g = idx % 2 == 0;

    (void) pt;
    if (is_g) {
        *sc = cbctx->a_arr[idx / 2];
    } else {
        *sc = cbctx->b_arr[idx / 2];
    }
    return 1;
}

void test_bulletproof_inner_product(size_t n, const secp256k1_bulletproof_generators *gens) {
    const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0,0,0,0,0,0,0,0);
    secp256k1_gej pj;
    secp256k1_gej tmpj, tmpj2;
    secp256k1_scalar *a_arr = (secp256k1_scalar *)checked_malloc(&CTX->error_callback, n * sizeof(*a_arr));
    secp256k1_scalar *b_arr = (secp256k1_scalar *)checked_malloc(&CTX->error_callback, n * sizeof(*b_arr));
    unsigned char commit[32];
    secp256k1_scalar one;
    size_t j;
    test_bulletproof_offset_context offs_ctx;
    secp256k1_bulletproof_ip_test_abgh_data abgh_data;
    secp256k1_bulletproof_innerproduct_context innp_ctx;
    unsigned char proof[2000];
    size_t plen = sizeof(proof);
    secp256k1_scratch *scratch = secp256k1_scratch_create(&CTX->error_callback, 100000 + 256 * (2 * n + 2));

    memcpy(commit, "hash of P, c, etc. all that jazz", sizeof(commit));
    for (j = 0; j < n; j++) {
        random_scalar_order(&a_arr[j]);
        random_scalar_order(&b_arr[j]);
    }

    abgh_data.a_arr = a_arr;
    abgh_data.b_arr = b_arr;

    random_group_element_test(&offs_ctx.ext_pt);
    random_scalar_order(&offs_ctx.ext_sc);
    secp256k1_scalar_set_int(&offs_ctx.skew_sc, 0);
    offs_ctx.n = n;

    secp256k1_scalar_set_int(&one, 1);
    CHECK(secp256k1_bulletproof_inner_product_prove_impl(CTX, scratch, proof, &plen, gens, &one, n, secp256k1_bulletproof_ip_test_abgh_callback, (void *) &abgh_data, commit) == 1);

    innp_ctx.proof = proof;
    memcpy(innp_ctx.commit, commit, sizeof(commit));
    secp256k1_scalar_set_int(&innp_ctx.yinv, 1);
    innp_ctx.n_extra_rangeproof_points = 1;
    innp_ctx.rangeproof_cb = test_bulletproof_offset_vfy_callback;
    innp_ctx.rangeproof_cb_data = (void *) &offs_ctx;

    /* Manually do the multiexp to obtain the point P which commits to the inner product.
     * The prover never computes this because it is implicit in the range/circuit proofs. */
    {
        test_bulletproof_ecmult_context ecmult_data;
        ecmult_data.n = n;
        ecmult_data.a = a_arr;
        ecmult_data.b = b_arr;
        ecmult_data.g = gens->gens;
        ecmult_data.h = gens->gens + gens->n/2;
        CHECK(secp256k1_ecmult_multi_var(&CTX->error_callback, scratch, &pj, &zero, test_bulletproof_ecmult_callback, (void*) &ecmult_data, 2 * n));
        secp256k1_ge_set_gej(&offs_ctx.p, &pj);
    }

    /* Check proof with no offsets or other baubles */
    offs_ctx.parity = 0;
    secp256k1_scalar_set_int(&innp_ctx.p_offs, 0);
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* skew P by a random amount and instruct the verifier to offset it */
    random_scalar_order(&innp_ctx.p_offs);
    secp256k1_gej_set_ge(&tmpj2, &gens->blinding_gen[0]);
    secp256k1_ecmult( &tmpj, &tmpj2, &innp_ctx.p_offs, &zero);
    secp256k1_gej_add_var(&pj, &pj, &tmpj, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &pj);

    /* wrong p_offs should fail */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 0);

    secp256k1_scalar_negate(&innp_ctx.p_offs, &innp_ctx.p_offs);

    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);
    /* check that verification did not trash anything */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);
    /* check that adding a no-op rangeproof skew function doesn't break anything */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Offset P by some random point and then try to undo this in the verification */
    secp256k1_gej_set_ge(&tmpj2, &offs_ctx.ext_pt);
    secp256k1_ecmult( &tmpj, &tmpj2, &offs_ctx.ext_sc, &zero);
    secp256k1_gej_neg(&tmpj, &tmpj);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &offs_ctx.p, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &tmpj);
    offs_ctx.parity = 0;
    innp_ctx.n_extra_rangeproof_points = 2;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Offset each basis by some random point and try to undo this in the verification */
    secp256k1_gej_set_infinity(&tmpj2);
    for (j = 0; j < n; j++) {
        size_t k;
        /* Offset by k-times the kth G basis and (k+n)-times the kth H basis */
        for (k = 0; k < j; k++) {
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j], NULL);
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j + gens->n/2], NULL);
        }
        for (k = 0; k < n; k++) {
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j + gens->n/2], NULL);
        }
    }
    random_scalar_order(&offs_ctx.skew_sc);
    secp256k1_ecmult( &tmpj, &tmpj2, &offs_ctx.skew_sc, &zero);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &offs_ctx.p, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &tmpj);
    secp256k1_scalar_negate(&offs_ctx.skew_sc, &offs_ctx.skew_sc);

    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Try to validate the same proof twice */
{
    test_bulletproof_offset_context offs_ctxs[2];
    secp256k1_bulletproof_innerproduct_context innp_ctxs[2];
    offs_ctx.parity = 1;  /* set parity to 1 so the common point will be returned first, as required by the multi-proof verifier */
    memcpy(&innp_ctxs[0], &innp_ctx, sizeof(innp_ctx));
    memcpy(&innp_ctxs[1], &innp_ctx, sizeof(innp_ctx));
    memcpy(&offs_ctxs[0], &offs_ctx, sizeof(offs_ctx));
    memcpy(&offs_ctxs[1], &offs_ctx, sizeof(offs_ctx));
    innp_ctxs[0].rangeproof_cb_data = (void *)&offs_ctxs[0];
    innp_ctxs[1].rangeproof_cb_data = (void *)&offs_ctxs[1];
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, innp_ctxs, 2, plen, 1) == 1);
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(CTX, scratch, gens, n, innp_ctxs, 2, plen, 0) == 1);
}

    free(a_arr);
    free(b_arr);
    secp256k1_scratch_destroy(&CTX->error_callback, scratch);
}

void test_bulletproof_rangeproof(size_t nbits, size_t expected_size, const secp256k1_bulletproof_generators *gens) {
    secp256k1_scalar blind;
    secp256k1_scalar blind_recovered;
    unsigned char proof[1024];
    unsigned char proof2[1024];
    unsigned char proof3[1024];
    const unsigned char *proof_ptr[3];
    size_t plen = sizeof(proof);
    uint64_t v = 123456;
    uint64_t v_recovered;
    secp256k1_gej commitj;
    secp256k1_ge commitp;
    secp256k1_ge commitp2;
    secp256k1_pedersen_commitment pcommit;
    const secp256k1_ge *commitp_ptr[3];
    secp256k1_ge value_gen[3];
    unsigned char nonce[32];
    unsigned char shared_msg[32];
    unsigned char private_msg[32];
    size_t shared_len;
    size_t private_len;
    size_t i;
    secp256k1_scratch *scratch = secp256k1_scratch_create(&CTX->error_callback, 10000000);

    memcpy(nonce, "my kingdom for some randomness!!", sizeof(nonce));

    /* Shifting a uint64_t by 64 is undefined; for nbits==64 every value fits. */
    if (nbits < 64 && (v >> nbits) > 0) {
        v = 0;
    }

    proof_ptr[0] = proof;
    proof_ptr[1] = proof2;
    proof_ptr[2] = proof3;

    secp256k1_generator_load(&value_gen[0], &secp256k1_generator_const_g);
    secp256k1_generator_load(&value_gen[1], &secp256k1_generator_const_g);
    secp256k1_generator_load(&value_gen[2], &secp256k1_generator_const_h);
    random_scalar_order(&blind);

    secp256k1_pedersen_ecmult(&commitj, &blind, v, &value_gen[0], &gens->blinding_gen[0]);
    secp256k1_ge_set_gej(&commitp, &commitj);
    secp256k1_pedersen_ecmult(&commitj, &blind, v, &value_gen[2], &gens->blinding_gen[0]);
    secp256k1_ge_set_gej(&commitp2, &commitj);
    commitp_ptr[0] = commitp_ptr[1] = &commitp;
    commitp_ptr[2] = &commitp2;
    secp256k1_pedersen_commitment_save(&pcommit, &commitp);

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(CTX, scratch, proof, &plen, NULL, NULL, nbits, &v, NULL, &blind, &commitp, 1, &value_gen[0], gens, nonce, nonce, NULL, 0, 0, NULL) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 1;
    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(CTX, scratch, proof2, &plen, NULL, NULL, nbits, &v, NULL, &blind, &commitp, 1, &value_gen[1], gens, nonce, nonce, NULL, 0, 0, NULL) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 2;
    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(CTX, scratch, proof3, &plen, NULL, NULL, nbits, &v, NULL, &blind, &commitp2, 1, &value_gen[2], gens, nonce, nonce, NULL, 0, 0, NULL) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 3;
    /* Verify once */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(CTX, scratch, proof_ptr, 1, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);
    /* Verify twice at once to test batch validation */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(CTX, scratch, proof_ptr, 2, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);
    /* Verify thrice at once where one has a different asset type */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(CTX, scratch, proof_ptr, 3, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);

    /* Rewind */
    shared_len = private_len = 32;
    CHECK(secp256k1_bulletproof_rangeproof_rewind_impl(CTX, shared_msg, &shared_len, private_msg, &private_len, proof, plen, 0, &pcommit, &secp256k1_generator_const_g, nonce, nonce, NULL, 0) == 1);
    v_recovered = 0;
    for (i = 24; i < 32; i++) {
        v_recovered = (v_recovered << 8) | shared_msg[i];
    }
    CHECK(v_recovered == v);
    secp256k1_scalar_set_b32(&blind_recovered, private_msg, NULL);
    CHECK(secp256k1_scalar_eq(&blind_recovered, &blind) == 1);

    /* Rewinding is unauthenticated: a wrong nonce yields unrelated bytes */
    nonce[0] ^= 111;
    CHECK(secp256k1_bulletproof_rangeproof_rewind_impl(CTX, shared_msg, &shared_len, private_msg, &private_len, proof, plen, 0, &pcommit, &secp256k1_generator_const_g, nonce, nonce, NULL, 0) == 1);
    secp256k1_scalar_set_b32(&blind_recovered, private_msg, NULL);
    CHECK(secp256k1_scalar_eq(&blind_recovered, &blind) == 0);

    secp256k1_scratch_destroy(&CTX->error_callback, scratch);
}

void test_bulletproof_rangeproof_aggregate(size_t nbits, size_t n_commits, size_t expected_size, const secp256k1_bulletproof_generators *gens) {
    unsigned char proof[1024];
    const unsigned char *proof_ptr = proof;
    size_t plen = sizeof(proof);
    secp256k1_scalar *blind = (secp256k1_scalar *)checked_malloc(&CTX->error_callback, n_commits * sizeof(*blind));
    uint64_t *v = (uint64_t *)checked_malloc(&CTX->error_callback, n_commits * sizeof(*v));
    secp256k1_ge *commitp = (secp256k1_ge *)checked_malloc(&CTX->error_callback, n_commits * sizeof(*commitp));
    const secp256k1_ge *constptr = commitp;
    secp256k1_ge value_gen;
    unsigned char commit[32] = {0};
    unsigned char nonce[32];
    size_t i;
    secp256k1_scratch *scratch = secp256k1_scratch_create(&CTX->error_callback, 10000000);

    memcpy(nonce, "mary, mary quite contrary how do", sizeof(nonce));

    secp256k1_generator_load(&value_gen, &secp256k1_generator_const_g);
    for (i = 0; i < n_commits; i++) {
        secp256k1_scalar vs;
        secp256k1_gej commitj;

        v[i] = 223 * i; /* dice-roll random # */
        if (nbits < 64 && (v[i] >> nbits) > 0) {
            v[i] = 0;
        }
        secp256k1_scalar_set_u64(&vs, v[i]);
        random_scalar_order(&blind[i]);
        secp256k1_pedersen_ecmult(&commitj, &blind[i], v[i], &value_gen, &gens->blinding_gen[0]);
        secp256k1_ge_set_gej(&commitp[i], &commitj);

        secp256k1_bulletproof_update_commit(CTX, commit, &commitp[i], &value_gen);
    }

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(CTX, scratch, proof, &plen, NULL, NULL, nbits, v, NULL, blind, commitp, n_commits, &value_gen, gens, nonce, nonce, NULL, 0, 0, NULL) == 1);
    CHECK(plen == expected_size);
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(CTX, scratch, &proof_ptr, 1, plen, nbits, NULL, &constptr, n_commits, &value_gen, gens, NULL, 0) == 1);

    secp256k1_scratch_destroy(&CTX->error_callback, scratch);
    free(commitp);
    free(v);
    free(blind);
}

void test_multi_party_bulletproof(size_t n_parties, secp256k1_scratch* scratch, const secp256k1_bulletproof_generators *gens) {
    size_t j;
    secp256k1_scalar tmp_s;
    unsigned char tmp_c[32];
    unsigned char common_nonce[32];
    unsigned char nonces[10][32];
    unsigned char blinds[10][32];
    const unsigned char* blind_ptr[1];
    secp256k1_pedersen_commitment partial_commits_buf[10];
    secp256k1_pedersen_commitment *partial_commits[10];
    uint64_t value[1] = {11223344};
    secp256k1_pedersen_commitment commit[1];
    const secp256k1_pedersen_commitment *commit_ptr[1];
    secp256k1_pubkey t_1s_buf[10];
    secp256k1_pubkey t_2s_buf[10];
    secp256k1_pubkey *t_1s[10];
    secp256k1_pubkey *t_2s[10];
    secp256k1_pubkey t_1_sum;
    secp256k1_pubkey t_2_sum;
    unsigned char tau_x_sum[32];
    unsigned char proof[675];
    size_t plen = 675;

    if (n_parties < 2 || n_parties > 10) {
        return;
    }

    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(common_nonce, &tmp_s);

    for (j=0;j<n_parties;j++) {
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(nonces[j], &tmp_s);
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(blinds[j], &tmp_s);

        partial_commits[j] = &partial_commits_buf[j];

        if (j == 0) {
            CHECK(secp256k1_pedersen_commit(CTX, partial_commits[j], blinds[j], value[0], &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        }
        else {
            CHECK(secp256k1_pedersen_commit(CTX, partial_commits[j], blinds[j], 0, &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        }
    }
    CHECK(secp256k1_pedersen_commit_sum(CTX, commit, (const secp256k1_pedersen_commitment * const *) partial_commits, n_parties, NULL, 0) == 1);
    commit_ptr[0] = commit;

    for (j=0;j<n_parties;j++) {
        t_1s[j] = &t_1s_buf[j];
        t_2s[j] = &t_2s_buf[j];
        blind_ptr[0] = blinds[j];
        CHECK(secp256k1_bulletproof_rangeproof_prove(CTX, scratch, gens, NULL, NULL, NULL, t_1s[j], t_2s[j], value, NULL, blind_ptr, commit_ptr, 1, &secp256k1_generator_const_h, 64, common_nonce, nonces[j], NULL, 0, NULL) == 1);
    }
    CHECK(secp256k1_ec_pubkey_combine(CTX, &t_1_sum, (const secp256k1_pubkey * const *) t_1s, n_parties) == 1);
    CHECK(secp256k1_ec_pubkey_combine(CTX, &t_2_sum, (const secp256k1_pubkey * const *) t_2s, n_parties) == 1);
    for (j=0;j<n_parties;j++) {
        blind_ptr[0] = blinds[j];
        CHECK(secp256k1_bulletproof_rangeproof_prove(CTX, scratch, gens, NULL, NULL, tmp_c, &t_1_sum, &t_2_sum, value, NULL, blind_ptr, commit_ptr, 1, &secp256k1_generator_const_h, 64, common_nonce, nonces[j], NULL, 0, NULL) == 1);
        if (j == 0) {
            memcpy(tau_x_sum, tmp_c, sizeof(tmp_c));
        } else {
            CHECK(secp256k1_ec_seckey_tweak_add(CTX, tau_x_sum, tmp_c) == 1);
        }
    }
    blind_ptr[0] = blinds[0];
    CHECK(secp256k1_bulletproof_rangeproof_prove(CTX, scratch, gens, proof, &plen, tau_x_sum, &t_1_sum, &t_2_sum, value, NULL, blind_ptr, commit_ptr, 1, &secp256k1_generator_const_h, 64, common_nonce, nonces[0], NULL, 0, NULL) == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify(CTX, scratch, gens, proof, plen, NULL, commit, 1, 64, &secp256k1_generator_const_h, NULL, 0) == 1);
}

static secp256k1_bulletproof_generators *bulletproof_test_gens_create(void) {
    return secp256k1_bulletproof_generators_create(CTX, &secp256k1_generator_const_h, 32768);
}

static void test_bulletproof_innerproduct_proof_length(void) {
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(0) == 32);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(1) == 96);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(2) == 160);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(4) == 225);
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(8) == 289);
}

static void test_zkp_scalar_chacha20_vectors(void) {
    static const unsigned char seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char expected_idx0_r1[32] = {
        0x39, 0xfd, 0x2b, 0x7d, 0xd9, 0xc5, 0x19, 0x6a,
        0x8d, 0xbd, 0x03, 0x77, 0xb8, 0xdc, 0x4a, 0x49,
        0x8a, 0x35, 0xd8, 0x6f, 0xbc, 0xde, 0x6a, 0xcc,
        0xb2, 0xcc, 0x7d, 0x4c, 0xd8, 0xea, 0x24, 0x92
    };
    static const unsigned char expected_idx0_r2[32] = {
        0x2b, 0x23, 0xcc, 0xe7, 0xa2, 0x60, 0x23, 0xab,
        0x3f, 0x0e, 0xef, 0x69, 0x3a, 0xc8, 0x7f, 0x64,
        0x25, 0x82, 0x35, 0xea, 0xb1, 0xf7, 0xa3, 0x2d,
        0xc2, 0x27, 0x62, 0xa0, 0x48, 0x5b, 0x41, 0x0c
    };
    static const unsigned char expected_idx64_r1[32] = {
        0x29, 0xe6, 0x51, 0x4f, 0x5a, 0xe1, 0x5a, 0xa4,
        0x6b, 0x86, 0x56, 0xc5, 0x03, 0x90, 0xf5, 0x5e,
        0xd9, 0xc6, 0xe6, 0xdd, 0x66, 0x73, 0x02, 0x68,
        0x3e, 0x4f, 0x2e, 0xe6, 0x45, 0x56, 0xf9, 0x2f
    };
    static const unsigned char expected_idx64_r2[32] = {
        0x23, 0xf3, 0xa0, 0x2f, 0x36, 0xf9, 0x47, 0xb2,
        0xba, 0x91, 0x39, 0x9c, 0x92, 0x38, 0x50, 0x06,
        0x3d, 0x93, 0x4c, 0xe4, 0x84, 0xb1, 0xe2, 0x41,
        0xcf, 0x1c, 0xc5, 0x4e, 0x7d, 0x5b, 0x27, 0x6c
    };
    secp256k1_scalar r1, r2;
    unsigned char out1[32], out2[32];

    secp256k1_scalar_chacha20(&r1, &r2, seed, 0);
    secp256k1_scalar_get_b32(out1, &r1);
    secp256k1_scalar_get_b32(out2, &r2);
    CHECK(secp256k1_memcmp_var(out1, expected_idx0_r1, 32) == 0);
    CHECK(secp256k1_memcmp_var(out2, expected_idx0_r2, 32) == 0);

    secp256k1_scalar_chacha20(&r1, &r2, seed, 0x0102030405060708ULL);
    secp256k1_scalar_get_b32(out1, &r1);
    secp256k1_scalar_get_b32(out2, &r2);
    CHECK(secp256k1_memcmp_var(out1, expected_idx64_r1, 32) == 0);
    CHECK(secp256k1_memcmp_var(out2, expected_idx64_r2, 32) == 0);
}

static void test_bulletproof_inner_product_n(size_t n) {
    secp256k1_bulletproof_generators *gens = bulletproof_test_gens_create();
    test_bulletproof_inner_product(n, gens);
    secp256k1_bulletproof_generators_destroy(CTX, gens);
}

static void test_bulletproof_inner_product_0(void) { test_bulletproof_inner_product_n(0); }
static void test_bulletproof_inner_product_1(void) { test_bulletproof_inner_product_n(1); }
static void test_bulletproof_inner_product_2(void) { test_bulletproof_inner_product_n(2); }
static void test_bulletproof_inner_product_4(void) { test_bulletproof_inner_product_n(4); }
static void test_bulletproof_inner_product_8(void) { test_bulletproof_inner_product_n(8); }
static void test_bulletproof_inner_product_32_internal(void) { test_bulletproof_inner_product_n(32); }
static void test_bulletproof_inner_product_64_internal(void) { test_bulletproof_inner_product_n(64); }
static void test_bulletproof_inner_product_1024(void) { test_bulletproof_inner_product_n(1024); }

REPEAT_TEST(test_bulletproof_inner_product_32)
REPEAT_TEST(test_bulletproof_inner_product_64)

static void test_bulletproof_rangeproof_nbits(size_t nbits, size_t expected_size) {
    secp256k1_bulletproof_generators *gens = bulletproof_test_gens_create();
    test_bulletproof_rangeproof(nbits, expected_size, gens);
    secp256k1_bulletproof_generators_destroy(CTX, gens);
}

static void test_bulletproof_rangeproof_1(void) { test_bulletproof_rangeproof_nbits(1, 289); }
static void test_bulletproof_rangeproof_2(void) { test_bulletproof_rangeproof_nbits(2, 353); }
static void test_bulletproof_rangeproof_16(void) { test_bulletproof_rangeproof_nbits(16, 546); }
static void test_bulletproof_rangeproof_32(void) { test_bulletproof_rangeproof_nbits(32, 610); }
static void test_bulletproof_rangeproof_64(void) { test_bulletproof_rangeproof_nbits(64, 675); }

static void test_bulletproof_rangeproof_aggregate_case(size_t nbits, size_t n_commits, size_t expected_size) {
    secp256k1_bulletproof_generators *gens = bulletproof_test_gens_create();
    test_bulletproof_rangeproof_aggregate(nbits, n_commits, expected_size, gens);
    secp256k1_bulletproof_generators_destroy(CTX, gens);
}

static void test_bulletproof_rangeproof_aggregate_64_1(void) { test_bulletproof_rangeproof_aggregate_case(64, 1, 675); }
static void test_bulletproof_rangeproof_aggregate_8_2(void) { test_bulletproof_rangeproof_aggregate_case(8, 2, 546); }
static void test_bulletproof_rangeproof_aggregate_8_4(void) { test_bulletproof_rangeproof_aggregate_case(8, 4, 610); }

static void test_multi_party_bulletproof_n(size_t n_parties) {
    secp256k1_scratch *scratch = secp256k1_scratch_create(&CTX->error_callback, 256*(1<<20));
    secp256k1_bulletproof_generators *gens = secp256k1_bulletproof_generators_create(CTX, &secp256k1_generator_const_g, 256);
    test_multi_party_bulletproof(n_parties, scratch, gens);
    secp256k1_bulletproof_generators_destroy(CTX, gens);
    secp256k1_scratch_destroy(&CTX->error_callback, scratch);
}

static void test_multi_party_bulletproof_2(void) { test_multi_party_bulletproof_n(2); }
static void test_multi_party_bulletproof_3(void) { test_multi_party_bulletproof_n(3); }
static void test_multi_party_bulletproof_4(void) { test_multi_party_bulletproof_n(4); }
static void test_multi_party_bulletproof_5(void) { test_multi_party_bulletproof_n(5); }
static void test_multi_party_bulletproof_6(void) { test_multi_party_bulletproof_n(6); }
static void test_multi_party_bulletproof_7(void) { test_multi_party_bulletproof_n(7); }
static void test_multi_party_bulletproof_8(void) { test_multi_party_bulletproof_n(8); }
static void test_multi_party_bulletproof_9(void) { test_multi_party_bulletproof_n(9); }
static void test_multi_party_bulletproof_10(void) { test_multi_party_bulletproof_n(10); }

static const struct tf_test_entry tests_bulletproof[] = {
    CASE1(test_bulletproof_api),
    CASE1(test_zkp_scalar_chacha20_vectors),
    CASE1(test_bulletproof_innerproduct_proof_length),
    CASE1(test_bulletproof_inner_product_0),
    CASE1(test_bulletproof_inner_product_1),
    CASE1(test_bulletproof_inner_product_2),
    CASE1(test_bulletproof_inner_product_4),
    CASE1(test_bulletproof_inner_product_8),
    CASE1(test_bulletproof_inner_product_32),
    CASE1(test_bulletproof_inner_product_64),
    CASE1(test_bulletproof_inner_product_1024),
    CASE1(test_bulletproof_rangeproof_1),
    CASE1(test_bulletproof_rangeproof_2),
    CASE1(test_bulletproof_rangeproof_16),
    CASE1(test_bulletproof_rangeproof_32),
    CASE1(test_bulletproof_rangeproof_64),
    CASE1(test_bulletproof_rangeproof_aggregate_64_1),
    CASE1(test_bulletproof_rangeproof_aggregate_8_2),
    CASE1(test_bulletproof_rangeproof_aggregate_8_4),
    CASE1(test_multi_party_bulletproof_2),
    CASE1(test_multi_party_bulletproof_3),
    CASE1(test_multi_party_bulletproof_4),
    CASE1(test_multi_party_bulletproof_5),
    CASE1(test_multi_party_bulletproof_6),
    CASE1(test_multi_party_bulletproof_7),
    CASE1(test_multi_party_bulletproof_8),
    CASE1(test_multi_party_bulletproof_9),
    CASE1(test_multi_party_bulletproof_10),
};
#undef MAX_WIDTH

#endif
