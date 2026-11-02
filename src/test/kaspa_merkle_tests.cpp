// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_merkle.h>
#include <auxpow/kaspa_tx.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <cstring>

using namespace auxpow;

BOOST_AUTO_TEST_SUITE(kaspa_merkle_tests)

BOOST_AUTO_TEST_CASE(golden_merkle_roots)
{
    KaspaTransaction coinbase;
    coinbase.version = 1;
    KaspaTxOutput out;
    out.value = 1000;
    out.script_version = 0;
    out.script.assign(32, 0);
    coinbase.outputs.push_back(out);
    std::memcpy(coinbase.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    coinbase.payload = ParseHex("0100000000000000f4010000000000000000200000000000000000000000000000000000000000000000000000000000000000fabe6d6d00000000000011110000000000000000000000000000000000000000000000000100000000000000");

    const uint256 leaf = KaspaTransactionHash(coinbase);
    BOOST_CHECK(KaspaCalcMerkleRoot({leaf}) == KaspaHashFromHex("85a2bc47826ae53354783eb2d16d013a8432da8a32f3350d42e38c42767b3877"));

    KaspaTransaction tx2;
    tx2.version = 0;
    const uint256 leaf2 = KaspaTransactionHash(tx2);
    BOOST_CHECK(leaf2 == KaspaHashFromHex("c9e29784564c269ce2faaffd3487cb4684383018ace11133de082dce4bb88b0b"));
    const uint256 root2 = KaspaCalcMerkleRoot({leaf, leaf2});
    BOOST_CHECK(root2 == KaspaHashFromHex("29bad7e6df870b3924055095dc73c84dea97c336afdc43509875a2e7f215f6c6"));

    KaspaTransaction tx3;
    tx3.version = 0;
    KaspaTxOutput o3;
    o3.value = 1;
    o3.script_version = 0;
    o3.script = {1};
    tx3.outputs.push_back(o3);
    const uint256 leaf3 = KaspaTransactionHash(tx3);
    BOOST_CHECK(leaf3 == KaspaHashFromHex("0da0dd3a051b62a5c7460dd0517c7120b11698d3cbd3de7314374857f1873e92"));
    const uint256 root3 = KaspaCalcMerkleRoot({leaf, leaf2, leaf3});
    BOOST_CHECK(root3 == KaspaHashFromHex("821a868d3cee000841efb2b5aae1ffd66a422c17e78b3098820926e54dcb4bba"));
}

BOOST_AUTO_TEST_CASE(branch_at_index_zero)
{
    const uint256 a = KaspaHashFromU64(1);
    const uint256 b = KaspaHashFromU64(2);
    const uint256 root = KaspaMerkleHash(a, b);
    BOOST_CHECK(CheckKaspaTxMerkleBranch(a, {b}, 0, root));
    BOOST_CHECK(!CheckKaspaTxMerkleBranch(a, {b}, 1, root));
}

BOOST_AUTO_TEST_SUITE_END()
