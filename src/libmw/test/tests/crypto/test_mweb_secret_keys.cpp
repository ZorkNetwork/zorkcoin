// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/blinds.h>
#include <mw/crypto/keys.h>
#include <mw/crypto/secret_keys.h>
#include <mw/exceptions/crypto_exception.h>

#include <test_framework/test_mweb.h>


BOOST_FIXTURE_TEST_SUITE(TestMWEBSecretKeys, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(SecretKeyFromHashValidation)
{
    std::vector<uint8_t> zero(32, 0);
    BOOST_REQUIRE(!SecretKey(zero).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(zero)).IsValid());

    std::vector<uint8_t> one(32, 0);
    one.back() = 1;
    BOOST_REQUIRE(SecretKey(one).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(one)) == SecretKey(one));

    std::vector<uint8_t> order{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    BOOST_REQUIRE(!SecretKey(order).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(order)).IsValid());

    order.back()--;
    BOOST_REQUIRE(SecretKey(order).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(order)) == SecretKey(order));
}

BOOST_AUTO_TEST_SUITE_END()
