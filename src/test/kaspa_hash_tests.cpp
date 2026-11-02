// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_pow.h>

#include <boost/test/unit_test.hpp>

using namespace auxpow;

BOOST_AUTO_TEST_SUITE(kaspa_hash_tests)

BOOST_AUTO_TEST_CASE(blue_work_encoding_matches_kaspa)
{
    auto h = BlockHashHasher();
    h.WriteBlueWorkU64(123456);
    BOOST_CHECK(h.Finalize() == KaspaHashFromHex("5ec9f4461d33f3040a7be72d0f24e5243c08c777a326cc9a213cef1f1df48d53"));

    auto h2 = BlockHashHasher();
    unsigned char len_le[8] = {3, 0, 0, 0, 0, 0, 0, 0};
    unsigned char body[3] = {0x01, 0xe2, 0x40};
    h2.Write(len_le).Write(body);
    BOOST_CHECK(h2.Finalize() == KaspaHashFromHex("5ec9f4461d33f3040a7be72d0f24e5243c08c777a326cc9a213cef1f1df48d53"));
}

BOOST_AUTO_TEST_CASE(from_u64_word)
{
    const uint256 h = KaspaHashFromU64(1);
    BOOST_CHECK_EQUAL(h.begin()[24], 1);
    BOOST_CHECK_EQUAL(h.begin()[0], 0);
    BOOST_CHECK(h.begin()[25] == 0);
}

BOOST_AUTO_TEST_CASE(powhash_and_heavyhash_only)
{
    const uint256 val = KaspaHashFromHex("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
    const uint256 pow = KaspaPowHashOnly(val, 5435345234ull, 432432432ull);
    BOOST_CHECK(pow == KaspaHashFromHex("2fb72b63dd0dd0d82b00cd9f83d4eca0710b7eb8c05966888f39ebc578978abf"));
    BOOST_CHECK(KaspaHeavyHashOnly(val) == KaspaHashFromHex("ad4ded01225705fea9aa043dd0a4e22ca28068bb41d5c6e06d35ca507d5656c7"));
}

BOOST_AUTO_TEST_SUITE_END()
