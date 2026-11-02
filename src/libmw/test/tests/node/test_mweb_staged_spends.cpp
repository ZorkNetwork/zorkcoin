// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/params.h>
#include <mw/crypto/blinds.h>
#include <mw/node/block_builder.h>
#include <mw/node/coins_view.h>
#include <mw/node/block_validator.h>

#include <test_framework/miner.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestMWEBStagedSpends, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(BlockBuilderAllowsSpendOfStagedOutput)
{
    auto db_view = CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);

    auto block_builder = std::make_shared<mw::BlockBuilder>(150, cached_view);

    test::Tx pegin_tx = test::Tx::CreatePegIn(1000);
    BOOST_CHECK(block_builder->AddTransaction(
        pegin_tx.GetTransaction(),
        { pegin_tx.GetPegInCoin() }
    ));

    test::Tx spend_tx = test::TxBuilder()
        .AddInput(pegin_tx.GetOutputs().front())
        .AddOutput(900)
        .AddPegoutKernel(100, 0)
        .Build();
    BOOST_CHECK(block_builder->AddTransaction(spend_tx.GetTransaction(), {}));
}

BOOST_AUTO_TEST_SUITE_END()
