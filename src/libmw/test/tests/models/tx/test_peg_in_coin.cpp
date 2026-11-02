// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/tx/peg_in_coin.h>
#include <mw/models/crypto/secret_key.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestPegInCoin, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(TxPegInCoin)
{
    CAmount amount = 123;
    mw::Hash kernel_id = SecretKey::Random().GetBigInt();
    PegInCoin pegInCoin(amount, kernel_id);

    //
    // Serialization
    //
    {
        PegInCoin pegInCoin2 = PegInCoin::Deserialize(pegInCoin.Serialized());
        BOOST_REQUIRE(pegInCoin == pegInCoin2);
    }

    //
    // Getters
    //
    {
        BOOST_REQUIRE(pegInCoin.GetAmount() == amount);
        BOOST_REQUIRE(pegInCoin.GetKernelID() == kernel_id);
    }
}

BOOST_AUTO_TEST_SUITE_END()
