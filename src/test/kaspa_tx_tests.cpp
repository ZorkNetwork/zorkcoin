// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_tx.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <cstring>

using namespace auxpow;

static KaspaTransaction MakeGoldenCoinbase()
{
    KaspaTransaction tx;
    tx.version = 1;
    KaspaTxOutput out;
    out.value = 1000;
    out.script_version = 0;
    out.script.assign(32, 0);
    out.covenant.present = false;
    tx.outputs.push_back(out);
    tx.lock_time = 0;
    std::memcpy(tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    tx.gas = 0;
    tx.payload = ParseHex("0100000000000000f4010000000000000000200000000000000000000000000000000000000000000000000000000000000000fabe6d6d00000000000011110000000000000000000000000000000000000000000000000100000000000000");
    tx.storage_mass = 0;
    return tx;
}

BOOST_AUTO_TEST_SUITE(kaspa_tx_tests)

BOOST_AUTO_TEST_CASE(golden_coinbase_hash)
{
    const KaspaTransaction tx = MakeGoldenCoinbase();
    BOOST_CHECK(IsKaspaCoinbaseShape(tx));
    BOOST_CHECK(KaspaTransactionHash(tx) == KaspaHashFromHex("85a2bc47826ae53354783eb2d16d013a8432da8a32f3350d42e38c42767b3877"));
}

BOOST_AUTO_TEST_CASE(coinbase_round_trip)
{
    const KaspaTransaction tx = MakeGoldenCoinbase();
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeKaspaTransaction(tx, wire));
    KaspaTransaction out;
    size_t consumed = 0;
    BOOST_REQUIRE(DeserializeKaspaTransaction(wire, out, consumed));
    BOOST_CHECK_EQUAL(consumed, wire.size());
    BOOST_CHECK(KaspaTransactionHash(out) == KaspaTransactionHash(tx));
}

BOOST_AUTO_TEST_CASE(parse_payload_extra_data)
{
    const KaspaTransaction tx = MakeGoldenCoinbase();
    uint64_t blue_score = 0, subsidy = 0;
    uint16_t spk_ver = 0;
    std::vector<unsigned char> spk, extra;
    BOOST_REQUIRE(ParseKaspaCoinbasePayload(tx.payload, blue_score, subsidy, spk_ver, spk, extra));
    BOOST_CHECK_EQUAL(blue_score, 1);
    BOOST_CHECK_EQUAL(subsidy, 500);
    BOOST_CHECK_EQUAL(spk_ver, 0);
    BOOST_CHECK_EQUAL(spk.size(), 32u);
    BOOST_CHECK_EQUAL(extra[0], 0xfa);
    BOOST_CHECK_EQUAL(extra[1], 0xbe);
    BOOST_CHECK_EQUAL(extra[2], 'm');
    BOOST_CHECK_EQUAL(extra[3], 'm');
}

BOOST_AUTO_TEST_SUITE_END()
