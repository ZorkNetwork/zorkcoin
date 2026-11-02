// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_header.h>

#include <cstring>

#include <boost/test/unit_test.hpp>

using namespace auxpow;

static KaspaHeader MakeGoldenHeader()
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
    return h;
}

BOOST_AUTO_TEST_SUITE(kaspa_header_tests)

BOOST_AUTO_TEST_CASE(golden_header_hashes)
{
    const KaspaHeader h = MakeGoldenHeader();
    BOOST_CHECK(KaspaPrePowHash(h) == KaspaHashFromHex("3a43e4da7749ef6071df024308306846a1c5d7acfbeb9c6df76363e3f940df0b"));
    BOOST_CHECK(KaspaHeaderHash(h) == KaspaHashFromHex("dc4426bec5c022cee4f05c1983b2aa56b3d91138d3419cfab2654f1a0078c1e8"));
}

BOOST_AUTO_TEST_CASE(header_round_trip)
{
    const KaspaHeader h = MakeGoldenHeader();
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeKaspaHeader(h, wire));
    KaspaHeader out;
    size_t consumed = 0;
    BOOST_REQUIRE(DeserializeKaspaHeader(wire, out, consumed));
    BOOST_CHECK_EQUAL(consumed, wire.size());
    BOOST_CHECK_EQUAL(out.version, h.version);
    BOOST_CHECK_EQUAL(out.timestamp, h.timestamp);
    BOOST_CHECK_EQUAL(out.bits, h.bits);
    BOOST_CHECK_EQUAL(out.nonce, h.nonce);
    BOOST_CHECK(KaspaHeaderHash(out) == KaspaHeaderHash(h));
}

BOOST_AUTO_TEST_CASE(compact_bits_basic)
{
    uint256 target;
    BOOST_REQUIRE(DecodeKaspaCompactBits(0x1e0ffff0, target));
    BOOST_CHECK(!target.IsNull());
    uint256 zero;
    BOOST_CHECK(!DecodeKaspaCompactBits(0x1e8ffff0, zero));
}

BOOST_AUTO_TEST_SUITE_END()
