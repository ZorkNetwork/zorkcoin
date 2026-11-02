// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key.h>
#include <mw/consensus/aggregation.h>
#include <primitives/transaction.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/mweb_mempool_setup.h>
#include <test_framework/models/tx.h>
#include <test_framework/tx_builder.h>
#include <txmempool.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

//! An MWEB-only parent and child whose kernel IDs sort in the requested order.
std::pair<test::Tx, test::Tx> MakeChain(const test::TxOutput& coin, bool child_kernel_first)
{
    while (true) {
        test::Tx parent{MWEBPackageSetup::Spend(coin)};
        test::Tx child{MWEBPackageSetup::Spend(parent.GetOutputs().front())};
        const bool child_first{child.GetKernels().front().GetKernelID() < parent.GetKernels().front().GetKernelID()};
        if (child_first == child_kernel_first) return {parent, child};
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_reorg_mempool_tests, MWEBPackageSetup)

// Disconnecting a mined MWEB parent restores its cached transaction and relinks an unconfirmed child.
BOOST_AUTO_TEST_CASE(reorg_restores_parent_and_relinks_child)
{
    const test::Tx parent_mweb{Spend(m_mweb_coins[0])};
    const auto parent = MakeMWEBOnly(parent_mweb);
    Accept(parent, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    CheckCached(parent);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    Accept(child, MWEB_FEE);
    CheckGraph(child, {child}, {child});

    InvalidateTip();
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// A disconnected block's MWEB parent and child both return, whichever kernel sorts first.
BOOST_AUTO_TEST_CASE(reorg_restores_mined_parent_child_package)
{
    const auto [first_parent_mweb, first_child_mweb] = MakeChain(m_mweb_coins[0], /*child_kernel_first=*/true);
    const auto [second_parent_mweb, second_child_mweb] = MakeChain(m_mweb_coins[1], /*child_kernel_first=*/false);
    const auto first_parent = MakeMWEBOnly(first_parent_mweb);
    const auto first_child = MakeMWEBOnly(first_child_mweb);
    const auto second_parent = MakeMWEBOnly(second_parent_mweb);
    const auto second_child = MakeMWEBOnly(second_child_mweb);
    for (const auto& tx : {first_parent, first_child, second_parent, second_child}) Accept(tx, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    for (const auto& tx : {first_parent, first_child, second_parent, second_child}) CheckCached(tx);

    InvalidateTip();
    CheckPool({first_parent, first_child, second_parent, second_child});
    CheckGraph(first_parent, {first_parent}, {first_parent, first_child});
    CheckGraph(first_child, {first_parent, first_child}, {first_child});
    CheckGraph(second_parent, {second_parent}, {second_parent, second_child});
    CheckGraph(second_child, {second_parent, second_child}, {second_child});
}

// Restoring a mined hybrid precedes both its L1 change spender and its MWEB child.
BOOST_AUTO_TEST_CASE(reorg_restores_hybrid_with_both_kinds_of_children)
{
    const test::Tx parent_mweb{Pegin()};
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto l1_child = MakeL1Child({parent}, L1_FEE);
    const auto mweb_child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    Accept(parent, L1_FEE);
    Accept(l1_child, L1_FEE);
    Accept(mweb_child, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    CheckCached(parent);
    CheckCached(mweb_child);

    InvalidateTip();
    CheckPool({parent, l1_child, mweb_child});
    CheckGraph(parent, {parent}, {parent, l1_child, mweb_child});
    CheckGraph(l1_child, {parent, l1_child}, {l1_child});
    CheckGraph(mweb_child, {parent, mweb_child}, {mweb_child});
}

// A mined diamond is restored once per transaction, though its root is cached under two kernels.
BOOST_AUTO_TEST_CASE(reorg_restores_diamond_with_multikernel_parent)
{
    const test::TxOutput& coin{m_mweb_coins[0]};
    const CAmount amount{static_cast<CAmount>(coin.GetAmount())};
    const CAmount half{(amount - MWEB_FEE) / 2};
    const test::Tx root_mweb{test::TxBuilder{}
                                 .AddInput(coin)
                                 .AddOutput(half)
                                 .AddOutput(amount - MWEB_FEE - half)
                                 .AddPlainKernel(MWEB_FEE / 2)
                                 .AddPlainKernel(MWEB_FEE / 2)
                                 .Build()};
    const test::Tx left_mweb{Spend(root_mweb.GetOutputs()[0])};
    const test::Tx right_mweb{Spend(root_mweb.GetOutputs()[1])};
    const auto root = MakeMWEBOnly(root_mweb);
    const auto left = MakeMWEBOnly(left_mweb);
    const auto right = MakeMWEBOnly(right_mweb);
    const auto join = MakeMWEBOnly(Spend({left_mweb.GetOutputs().front(), right_mweb.GetOutputs().front()}));
    for (const auto& tx : {root, left, right, join}) Accept(tx, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    for (const auto& tx : {root, left, right, join}) CheckCached(tx);

    InvalidateTip();
    CheckPool({root, left, right, join});
    CheckGraph(root, {root}, {root, left, right, join});
    CheckGraph(left, {root, left}, {left, join});
    CheckGraph(right, {root, right}, {right, join});
    CheckGraph(join, {root, left, right, join}, {join});
}

// A child spending two outputs of one aggregate does not restore the aggregate twice.
BOOST_AUTO_TEST_CASE(reorg_restores_aggregate_with_multiple_outputs_spent_by_child)
{
    const test::Tx first{Spend(m_mweb_coins[0])};
    const test::Tx second{Spend(m_mweb_coins[1])};
    const test::Tx aggregate_mweb{Aggregation::Aggregate({first.GetTransaction(), second.GetTransaction()}), {}};
    const auto aggregate = MakeMWEBOnly(aggregate_mweb);
    const auto child = MakeMWEBOnly(Spend({first.GetOutputs().front(), second.GetOutputs().front()}));
    Accept(aggregate, 2 * MWEB_FEE);
    Accept(child, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    CheckCached(aggregate);
    CheckCached(child);

    InvalidateTip();
    CheckPool({aggregate, child});
    CheckGraph(aggregate, {aggregate}, {aggregate, child});
    CheckGraph(child, {aggregate, child}, {child});
}

// Disconnecting several blocks restores every MWEB ancestor and relinks the descendants.
BOOST_AUTO_TEST_CASE(reorg_restores_dependencies_across_disconnected_blocks)
{
    const test::Tx parent_mweb{Spend(m_mweb_coins[0])};
    const auto parent = MakeMWEBOnly(parent_mweb);
    Accept(parent, MWEB_FEE);
    MineMWEBEraBlock();
    CBlockIndex* const parent_block{Tip()};
    const test::Tx child_mweb{Spend(parent_mweb.GetOutputs().front())};
    const auto child = MakeMWEBOnly(child_mweb);
    const auto grandchild = MakeMWEBOnly(Spend(child_mweb.GetOutputs().front()));
    Accept(child, MWEB_FEE);
    Accept(grandchild, MWEB_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    for (const auto& tx : {parent, child, grandchild}) CheckCached(tx);

    InvalidateBlock(parent_block);
    CheckPool({parent, child, grandchild});
    CheckGraph(parent, {parent}, {parent, child, grandchild});
    CheckGraph(child, {parent, child}, {child, grandchild});
    CheckGraph(grandchild, {parent, child, grandchild}, {grandchild});
}

// A disconnected hybrid returns with its MWEB data, not as the stripped transaction stored in the block.
BOOST_AUTO_TEST_CASE(reorg_restores_full_hybrid_transaction)
{
    const auto pegin = MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE);
    Accept(pegin, L1_FEE);
    MineMWEBEraBlock();
    CheckPool({});
    CheckCached(pegin);

    InvalidateTip();
    CheckPool({pegin});
    LOCK(Pool().cs);
    const CTransactionRef restored{Pool().get(pegin->GetHash())};
    BOOST_REQUIRE(restored);
    BOOST_CHECK(restored->HasMWEBTx());
    BOOST_CHECK(restored->mweb_tx.GetKernelIDs() == pegin->mweb_tx.GetKernelIDs());
}

// Rolling back the tip removes a child whose kernel is now height-locked, and its descendant,
// while restoring the parent.
BOOST_AUTO_TEST_CASE(reorg_removes_newly_nonfinal_mweb_descendants)
{
    const test::Tx parent_mweb{Spend(m_mweb_coins[0])};
    const auto parent = MakeMWEBOnly(parent_mweb);
    Accept(parent, MWEB_FEE);
    MineMWEBEraBlock();
    const int32_t next_height{Tip()->nHeight + 1};
    const test::TxOutput& parent_output{parent_mweb.GetOutputs().front()};
    const test::Tx child_mweb{test::TxBuilder{}
                                  .AddInput(parent_output)
                                  .AddOutput(static_cast<CAmount>(parent_output.GetAmount()) - MWEB_FEE)
                                  .AddPlainKernel(MWEB_FEE, /*add_stealth_excess=*/false, /*lock_height=*/next_height)
                                  .Build()};
    const auto child = MakeMWEBOnly(child_mweb);
    const auto grandchild = MakeMWEBOnly(Spend(child_mweb.GetOutputs().front()));
    Accept(child, MWEB_FEE);
    Accept(grandchild, MWEB_FEE);

    InvalidateTip();
    CheckPool({parent}, {child, grandchild});
    CheckGraph(parent, {parent}, {parent});
}

// Without the cached original, a disconnected MWEB transaction cannot return, and its
// unconfirmed descendants are removed.
BOOST_AUTO_TEST_CASE(reorg_cache_miss_removes_orphaned_mweb_descendants)
{
    const test::Tx parent_mweb{Spend(m_mweb_coins[0])};
    const auto parent = MakeMWEBOnly(parent_mweb);
    Accept(parent, MWEB_FEE);
    MineMWEBEraBlock();
    const test::Tx child_mweb{Spend(parent_mweb.GetOutputs().front())};
    const auto child = MakeMWEBOnly(child_mweb);
    const auto grandchild = MakeMWEBOnly(Spend(child_mweb.GetOutputs().front()));
    Accept(child, MWEB_FEE);
    Accept(grandchild, MWEB_FEE);
    BOOST_REQUIRE(HaveConfirmedMWEBCoin(parent_mweb.GetOutputs().front().GetOutputID()));
    WITH_LOCK(Pool().cs, Pool().ClearMWEBKernelCacheForTesting());

    InvalidateTip();
    CheckPool({}, {parent, child, grandchild});
    BOOST_CHECK(HaveConfirmedMWEBCoin(m_mweb_coins[0].GetOutputID()));
    BOOST_CHECK(!HaveConfirmedMWEBCoin(parent_mweb.GetOutputs().front().GetOutputID()));
}

namespace {

//! Peg out `amount` from a confirmed MWEB coin to ChangeScript and mine it.
//! Returns the HogEx peg-out outpoint (vout 1) and the peg-out block height.
std::pair<COutPoint, int> MinePegout(MWEBPackageSetup& setup, const test::TxOutput& coin, CAmount amount)
{
    const CAmount change{static_cast<CAmount>(coin.GetAmount()) - MWEB_FEE - amount};
    BOOST_REQUIRE_GT(change, 0);
    const test::Tx pegout_mweb{test::TxBuilder{}
                                   .AddInput(coin)
                                   .AddOutput(change)
                                   .AddPegoutKernel({{amount, setup.ChangeScript()}}, MWEB_FEE)
                                   .Build()};
    const auto pegout_tx{setup.MakeMWEBOnly(pegout_mweb)};
    setup.Accept(pegout_tx, MWEB_FEE);
    setup.MineMWEBEraBlock();
    setup.CheckPool({});

    CBlock block;
    COutPoint outpoint;
    int height{0};
    {
        LOCK(::cs_main);
        CBlockIndex* tip{setup.Tip()};
        BOOST_REQUIRE(Assert(setup.m_node.chainman)->m_blockman.ReadBlock(block, *tip));
        height = tip->nHeight;
        BOOST_REQUIRE(!block.vtx.empty());
        const CTransactionRef& hogex{block.vtx.back()};
        BOOST_REQUIRE(hogex->IsHogEx());
        BOOST_REQUIRE_GE(hogex->vout.size(), 2U);
        outpoint = COutPoint{hogex->GetHash(), 1};
        const Coin& pegout_coin{Assert(setup.m_node.chainman)->ActiveChainstate().CoinsTip().AccessCoin(outpoint)};
        BOOST_REQUIRE(!pegout_coin.IsSpent());
        BOOST_REQUIRE(pegout_coin.IsPegout());
        BOOST_REQUIRE_EQUAL(pegout_coin.out.nValue, amount);
    }
    return {outpoint, height};
}

CTransactionRef SpendPegout(MWEBPackageSetup& setup, const COutPoint& outpoint, CAmount value, CAmount fee)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(outpoint);
    mtx.vout.emplace_back(value - fee, setup.ChangeScript());
    FillableSigningProvider keystore;
    keystore.AddKey(setup.coinbaseKey);
    std::map<COutPoint, Coin> coins;
    {
        LOCK(::cs_main);
        coins.emplace(outpoint, Assert(setup.m_node.chainman)->ActiveChainstate().CoinsTip().AccessCoin(outpoint));
    }
    std::map<int, bilingual_str> errors;
    BOOST_REQUIRE(SignTransaction(mtx, &keystore, coins, {.sighash_type = SIGHASH_ALL}, errors));
    return MakeTransactionRef(mtx);
}

} // namespace

// Peg-out outputs are immature until PEGOUT_MATURITY; the mempool accepts them exactly at the boundary.
BOOST_AUTO_TEST_CASE(pegout_maturity_boundary)
{
    constexpr CAmount pegout_amount{COIN};
    const auto [outpoint, pegout_height] = MinePegout(*this, m_mweb_coins[0], pegout_amount);

    const auto premature{SpendPegout(*this, outpoint, pegout_amount, L1_FEE)};
    Reject(premature, TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-pegout");
    CheckPool({}, {premature});

    for (int i{0}; i < PEGOUT_MATURITY - 2; ++i) MineMWEBEraBlock();
    BOOST_REQUIRE_EQUAL(Tip()->nHeight, pegout_height + PEGOUT_MATURITY - 2);
    Reject(SpendPegout(*this, outpoint, pegout_amount, L1_FEE), TxValidationResult::TX_PREMATURE_SPEND,
           "bad-txns-premature-spend-of-pegout");

    MineMWEBEraBlock();
    BOOST_REQUIRE_EQUAL(Tip()->nHeight, pegout_height + PEGOUT_MATURITY - 1);
    const auto mature{SpendPegout(*this, outpoint, pegout_amount, L1_FEE)};
    Accept(mature, L1_FEE);
    CheckPool({mature});
    {
        LOCK2(::cs_main, Pool().cs);
        const CTxMemPoolEntry* entry{Pool().GetEntry(mature->GetHash())};
        BOOST_REQUIRE(entry);
        // This target keeps the Bitcoin coinbase-only entry flag. Reorg
        // validation scans confirmed inputs for Coin::IsPegout separately.
        BOOST_CHECK(!entry->GetSpendsCoinbase());
        const Coin& coin{Assert(m_node.chainman)->ActiveChainstate().CoinsTip().AccessCoin(outpoint)};
        BOOST_CHECK(coin.IsPegout());
        BOOST_CHECK(!coin.IsCoinBase());
    }
}

// Re-immaturity evicts the canonical peg-out spender and child, while an independent spend survives.
BOOST_AUTO_TEST_CASE(reorg_removes_newly_immature_pegout_spend)
{
    constexpr CAmount pegout_amount{COIN};
    const auto [outpoint, pegout_height] = MinePegout(*this, m_mweb_coins[1], pegout_amount);
    for (int i{0}; i < PEGOUT_MATURITY - 1; ++i) MineMWEBEraBlock();
    BOOST_REQUIRE_EQUAL(Tip()->nHeight, pegout_height + PEGOUT_MATURITY - 1);

    const auto spend{SpendPegout(*this, outpoint, pegout_amount, L1_FEE)};
    Accept(spend, L1_FEE);
    CMutableTransaction child_mtx;
    const COutPoint child_input{spend->GetHash(), 0};
    child_mtx.vin.emplace_back(child_input);
    child_mtx.vout.emplace_back(spend->vout[0].nValue - L1_FEE, ChangeScript());
    Sign(child_mtx, {spend});
    const auto child{MakeTransactionRef(child_mtx)};
    Accept(child, L1_FEE);
    const auto independent{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    Accept(independent, MWEB_FEE);
    CheckPool({spend, child, independent});
    CheckGraph(spend, {spend}, {spend, child});
    CheckGraph(child, {spend, child}, {child});
    {
        LOCK(Pool().cs);
        BOOST_CHECK_EQUAL(Pool().mapNextTx.size(), 2U);
        BOOST_REQUIRE(Pool().GetConflictTx(outpoint));
        BOOST_CHECK(Pool().GetConflictTx(outpoint)->GetHash() == spend->GetHash());
        BOOST_REQUIRE(Pool().GetConflictTx(child_input));
        BOOST_CHECK(Pool().GetConflictTx(child_input)->GetHash() == child->GetHash());
    }

    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Tip()->nHeight, pegout_height + PEGOUT_MATURITY - 2);
    CheckPool({independent}, {spend, child});
    CheckGraph(independent, {independent}, {independent});
    {
        LOCK(Pool().cs);
        BOOST_CHECK(Pool().mapNextTx.empty());
        BOOST_CHECK(!Pool().GetConflictTx(outpoint));
        BOOST_CHECK(!Pool().GetConflictTx(child_input));
    }
    Reject(SpendPegout(*this, outpoint, pegout_amount, L1_FEE), TxValidationResult::TX_PREMATURE_SPEND,
           "bad-txns-premature-spend-of-pegout");
}

BOOST_AUTO_TEST_SUITE_END()
