// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_header.h>
#include <auxpow/kaspa_pow.h>

#include <cstring>

#include <boost/test/unit_test.hpp>

using namespace auxpow;

BOOST_AUTO_TEST_SUITE(kaspa_pow_tests)

BOOST_AUTO_TEST_CASE(golden_header_peer_pow)
{
    KaspaHeader h;
    h.version = 2;
    h.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    h.hash_merkle_root = KaspaHashFromU64(2);
    h.accepted_id_merkle_root = KaspaHashFromU64(3);
    h.utxo_commitment = KaspaHashFromU64(4);
    h.timestamp = 1700000000000ull;
    h.bits = 0x1e0ffff0;
    h.nonce = 42;
    h.daa_score = 100;
    h.blue_score = 50;
    std::memset(h.blue_work, 0, sizeof(h.blue_work));
    h.pruning_point = KaspaHashFromU64(5);

    BOOST_CHECK(KaspaPeerPoW(h) == KaspaHashFromHex("f884a18b54fe55bcf0699003aa12a45eedd8fb813c02725edbbf15a9cc19c76e"));
}

BOOST_AUTO_TEST_SUITE_END()
