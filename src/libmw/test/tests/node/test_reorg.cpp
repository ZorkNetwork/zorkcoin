// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/coins_view.h>
#include <mw/node/block_validator.h>
#include <mw/crypto/secret_keys.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/key_derivation.h>

#include <test_framework/miner.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

BOOST_FIXTURE_TEST_SUITE(TestReorg, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(ReorgChain)
{
    auto pDatabase = GetDB();

    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, pDatabase);
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);

    test::Miner miner(GetDataDir());

    ///////////////////////
    // Mine Block 1
    ///////////////////////
    test::Tx block1_tx1 = test::Tx::CreatePegIn(1000);
    auto block1 = miner.MineBlock(160, { block1_tx1 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block1.GetBlock(), { block1_tx1.GetPegInCoin() }, {}));
    pCachedView->ApplyBlock(block1.GetBlock());

    const auto& block1_tx1_output1 = block1_tx1.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetUTXO(block1_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block1_tx1_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Mine Block 2
    ///////////////////////
    SecretKey subaddr_scan_key = SecretKey::Random();
    SecretKey subaddr_spend_key = SecretKey::Random();
    StealthAddress receiver_addr(PublicKey::From(subaddr_scan_key), PublicKey::From(subaddr_spend_key));
    SecretKey sender_key = SecretKey::Random();

    test::Tx block2_tx1 = test::TxBuilder()
        .AddPeginKernel(500)
        .AddOutput(500, sender_key, receiver_addr)
        .Build();
    const auto& block2_tx1_output1 = block2_tx1.GetOutputs()[0];

    SecretKey shared_secret = mw::DeriveSharedSecret(sender_key, receiver_addr, block2_tx1_output1.GetAmount());
    SecretKey output_spend_key = mw::DeriveOutputSpendKey(subaddr_spend_key, shared_secret);

    test::Tx block2_tx2 = test::TxBuilder()
        .AddInput(
            block2_tx1_output1.GetAmount(),
            output_spend_key,
            block2_tx1_output1.GetBlind(),
            block2_tx1_output1.GetOutputID()
        )
        .AddOutput(block2_tx1_output1.GetAmount(), SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    auto block2 = miner.MineBlock(161, { block2_tx1, block2_tx2 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block2.GetBlock(), { block2_tx1.GetPegInCoin() }, {}));
    mw::BlockUndo::CPtr undoBlock2 = pCachedView->ApplyBlock(block2.GetBlock());

    const auto& block2_tx2_output1 = block2_tx2.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetUTXO(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pDBView->GetUTXO(block2_tx2_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block2_tx2_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Disconnect Block 2
    ///////////////////////
    pCachedView->UndoBlock(undoBlock2);
    BOOST_CHECK(pCachedView->GetUTXO(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block2_tx2_output1.GetOutputID()) == nullptr);
    miner.Rewind(1);

    ///////////////////////
    // Mine Block 3
    ///////////////////////
    test::Tx block3_tx1 = test::Tx::CreatePegIn(1500);
    auto block3 = miner.MineBlock(161, { block3_tx1 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block3.GetBlock(), {block3_tx1.GetPegInCoin()}, {}));
    pCachedView->ApplyBlock(block3.GetBlock());

    const auto& block3_tx1_output1 = block3_tx1.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetUTXO(block3_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block3_tx1_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Flush View
    ///////////////////////
    auto batch = pDatabase->CreateBatch();
    pCachedView->Flush(batch);
    batch->Commit();

    BOOST_CHECK(pDBView->GetUTXO(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pDBView->GetUTXO(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pDBView->GetUTXO(block3_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(block3_tx1_output1.GetOutputID()) != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
