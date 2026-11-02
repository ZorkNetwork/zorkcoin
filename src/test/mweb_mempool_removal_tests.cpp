// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <mw/consensus/aggregation.h>
#include <mw/crypto/blinds.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <test/util/time.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/time.h>
#include <test/util/setup_common.h>
#include <test_framework/tx_builder.h>
#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mweb_mempool_removal_tests, TestingSetup)

static CTransactionRef WrapMWEBTx(const mw::Transaction::CPtr& tx)
{
    CMutableTransaction mutable_tx;
    mutable_tx.mweb_tx = mw::MutableTx::From(*tx);
    return MakeTransactionRef(std::move(mutable_tx));
}

static CBlock BuildMWEBBlock(const mw::Transaction::CPtr& tx)
{
    const auto header = std::make_shared<mw::Header>(
        1,
        mw::Hash{},
        mw::Hash{},
        mw::Hash{},
        tx->GetKernelOffset(),
        tx->GetStealthOffset(),
        tx->GetOutputs().size(),
        tx->GetKernels().size());
    CBlock block;
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header, tx->GetBody())};
    return block;
}

static std::pair<mw::Transaction::CPtr, SecretKey> BuildMWEBPegout(const test::TxOutput& input)
{
    const SecretKey input_key = SecretKey::Random();
    const Input mweb_input = Input::Create(input.GetOutputID(), input.GetCommitment(), input_key, input.GetSpendKey());
    const BlindingFactor kernel_excess = BlindingFactor::Random();
    const Kernel kernel = Kernel::Create(
        kernel_excess,
        std::nullopt,
        CAmount{0},
        std::nullopt,
        {PegOutCoin{static_cast<CAmount>(input.GetAmount()), CScript{} << OP_TRUE}},
        std::nullopt);
    mw::Transaction::CPtr tx = mw::Transaction::Create(
        Blinds().Sub(input.GetBlind()).Sub(kernel_excess).Total(),
        Blinds().Add(input_key).Sub(input.GetSpendKey()).Total(),
        {mweb_input},
        {},
        {kernel});
    tx->Validate();
    return {std::move(tx), input_key};
}

static mw::Transaction::CPtr CutThrough(
    const test::Tx& parent,
    const SecretKey& parent_sender,
    const mw::Transaction::CPtr& child,
    const SecretKey& child_input_key)
{
    const test::TxOutput& parent_output = parent.GetOutputs().front();
    const mw::Transaction::CPtr aggregate = Aggregation::Aggregate({parent.GetTransaction(), child});
    const BlindingFactor stealth_offset = Blinds(aggregate->GetStealthOffset())
        .Add(parent_output.GetSpendKey())
        .Sub(parent_sender)
        .Sub(child_input_key)
        .Total();
    mw::Transaction::CPtr cut_through = mw::Transaction::Create(
        aggregate->GetKernelOffset(),
        stealth_offset,
        parent.GetTransaction()->GetInputs(),
        {},
        aggregate->GetKernels());
    cut_through->Validate();
    return cut_through;
}

/** The mempool removal sequence ConnectTip runs for a block with an MWEB body. */
static void RemoveForMWEBBlock(CTxMemPool& pool, const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    pool.removeMWEBConflictsForBlock(block.vtx, block.mweb_block);
    pool.removeForBlock(block.vtx);
    pool.removeForMWEBKernels(block.mweb_block.GetKernelIDs());
}

static bool AnyKernelCached(const CTxMemPool& pool, const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    const auto kernel_ids{tx->mweb_tx.GetKernelIDs()};
    return std::ranges::any_of(kernel_ids, [&](const mw::Hash& kernel_id) EXCLUSIVE_LOCKS_REQUIRED(pool.cs) { return pool.HasCachedMWEBTxByKernel(kernel_id); });
}

static bool AllKernelsCached(const CTxMemPool& pool, const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    const auto kernel_ids{tx->mweb_tx.GetKernelIDs()};
    return std::ranges::all_of(kernel_ids, [&](const mw::Hash& kernel_id) EXCLUSIVE_LOCKS_REQUIRED(pool.cs) { return pool.HasCachedMWEBTxByKernel(kernel_id); });
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockConflict)
{
    const test::Tx funding = test::Tx::CreatePegIn(10'000);
    const test::Tx conflicting_spend = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000)
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx conflicting_child = test::Tx::CreatePegOut(conflicting_spend.GetOutputs().front());
    const test::Tx block_spend = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(8'000)
        .AddPlainKernel(2'000)
        .Build();
    const test::Tx unrelated = test::Tx::CreatePegIn(5'000);

    const CTransactionRef conflicting_tx = WrapMWEBTx(conflicting_spend.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(conflicting_child.GetTransaction());
    const CTransactionRef unrelated_tx = WrapMWEBTx(unrelated.GetTransaction());
    const CBlock block = BuildMWEBBlock(block_spend.GetTransaction());

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(conflicting_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    TryAddToMempool(pool, entry.FromTx(unrelated_tx));

    BOOST_REQUIRE(pool.exists(conflicting_tx->GetHash()));
    BOOST_REQUIRE(pool.exists(child_tx->GetHash()));
    BOOST_REQUIRE(pool.exists(unrelated_tx->GetHash()));

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(conflicting_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(pool.exists(unrelated_tx->GetHash()));
    BOOST_CHECK(!AnyKernelCached(pool, conflicting_tx));
    BOOST_CHECK(!AnyKernelCached(pool, child_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockAggregatedConflict)
{
    const test::Tx shared_funding = test::Tx::CreatePegIn(10'000);
    const test::Tx shared_spend = test::TxBuilder()
        .AddInput(shared_funding.GetOutputs().front())
        .AddOutput(9'000)
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx shared_child = test::Tx::CreatePegOut(shared_spend.GetOutputs().front());
    const test::Tx conflicting_funding = test::Tx::CreatePegIn(20'000);
    const test::Tx conflicting_spend = test::TxBuilder()
        .AddInput(conflicting_funding.GetOutputs().front())
        .AddOutput(19'000)
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx conflicting_child = test::Tx::CreatePegOut(conflicting_spend.GetOutputs().front());
    const test::Tx block_spend = test::TxBuilder()
        .AddInput(conflicting_funding.GetOutputs().front())
        .AddOutput(18'000)
        .AddPlainKernel(2'000)
        .Build();
    const test::Tx unrelated = test::Tx::CreatePegIn(5'000);

    const mw::Transaction::CPtr mempool_aggregate = Aggregation::Aggregate({shared_spend.GetTransaction(), conflicting_spend.GetTransaction()});
    const CTransactionRef aggregate_tx = WrapMWEBTx(mempool_aggregate);
    const CTransactionRef shared_child_tx = WrapMWEBTx(shared_child.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(conflicting_child.GetTransaction());
    const CTransactionRef unrelated_tx = WrapMWEBTx(unrelated.GetTransaction());

    const mw::Transaction::CPtr block_aggregate = Aggregation::Aggregate({
        shared_spend.GetTransaction(),
        shared_child.GetTransaction(),
        block_spend.GetTransaction()});
    const CBlock block = BuildMWEBBlock(block_aggregate);

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(aggregate_tx));
    TryAddToMempool(pool, entry.FromTx(shared_child_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    TryAddToMempool(pool, entry.FromTx(unrelated_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 4U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(aggregate_tx->GetHash()));
    BOOST_CHECK(!pool.exists(shared_child_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(pool.exists(unrelated_tx->GetHash()));
    BOOST_CHECK(!AnyKernelCached(pool, aggregate_tx));
    BOOST_CHECK(AllKernelsCached(pool, shared_child_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockSameKernelAlternative)
{
    const test::Tx funding = test::Tx::CreatePegIn(10'000);
    const SecretKey sender_key = SecretKey::Random();
    const test::Tx mempool_spend = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000, sender_key, SecretKey::Random(), SecretKey::Random())
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx alternate_output = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000, sender_key, SecretKey::Random(), SecretKey::Random())
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx mempool_child = test::Tx::CreatePegOut(mempool_spend.GetOutputs().front());
    const test::Tx unrelated = test::Tx::CreatePegIn(5'000);

    const BlindingFactor block_offset = Pedersen::AddBlindingFactors(
        {mempool_spend.GetKernelOffset(), alternate_output.GetOutputs().front().GetBlind()},
        {mempool_spend.GetOutputs().front().GetBlind()});
    const mw::Transaction::CPtr block_variant = mw::Transaction::Create(
        block_offset,
        mempool_spend.GetStealthOffset(),
        mempool_spend.GetTransaction()->GetInputs(),
        {alternate_output.GetOutputs().front().GetOutput()},
        mempool_spend.GetKernels());
    block_variant->Validate();
    BOOST_REQUIRE(block_variant->GetKernels().front().GetKernelID() == mempool_spend.GetKernels().front().GetKernelID());
    BOOST_REQUIRE(block_variant->GetOutputs().front().GetOutputID() != mempool_spend.GetOutputs().front().GetOutputID());

    const CTransactionRef mempool_tx = WrapMWEBTx(mempool_spend.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(mempool_child.GetTransaction());
    const CTransactionRef unrelated_tx = WrapMWEBTx(unrelated.GetTransaction());
    const CBlock block = BuildMWEBBlock(block_variant);

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(mempool_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    TryAddToMempool(pool, entry.FromTx(unrelated_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 3U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(mempool_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(pool.exists(unrelated_tx->GetHash()));
    BOOST_CHECK(AllKernelsCached(pool, mempool_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockMixedTransactionIdentity)
{
    const test::Tx pegin = test::Tx::CreatePegIn(9'000);
    CMutableTransaction mempool_mixed;
    mempool_mixed.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    mempool_mixed.vout.emplace_back(1'000, CScript{} << OP_TRUE);
    mempool_mixed.mweb_tx = mw::MutableTx::From(*pegin.GetTransaction());
    const CTransactionRef mempool_tx = MakeTransactionRef(mempool_mixed);

    CMutableTransaction child;
    child.vin.emplace_back(COutPoint{mempool_tx->GetHash(), 0});
    child.vout.emplace_back(1'000, CScript{} << OP_TRUE);
    const CTransactionRef child_tx = MakeTransactionRef(std::move(child));

    CMutableTransaction block_mixed = mempool_mixed;
    block_mixed.vin.front().prevout = COutPoint{Txid::FromUint256(uint256{2}), 0};
    block_mixed.mweb_tx.SetNull();
    const CTransactionRef block_tx = MakeTransactionRef(std::move(block_mixed));
    BOOST_REQUIRE(block_tx->GetHash() != mempool_tx->GetHash());

    CBlock block = BuildMWEBBlock(pegin.GetTransaction());
    block.vtx.push_back(block_tx);

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(mempool_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(mempool_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(!AnyKernelCached(pool, mempool_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockPreservesValidChild)
{
    const test::Tx funding = test::Tx::CreatePegIn(10'000);
    const test::Tx parent = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000)
        .AddPlainKernel(1'000)
        .Build();
    const test::Tx child = test::Tx::CreatePegOut(parent.GetOutputs().front());
    const CTransactionRef parent_tx = WrapMWEBTx(parent.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(child.GetTransaction());
    const CBlock block = BuildMWEBBlock(parent.GetTransaction());

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(parent_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(parent_tx->GetHash()));
    BOOST_CHECK(pool.exists(child_tx->GetHash()));
    BOOST_CHECK(AllKernelsCached(pool, parent_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockSupportsCutThrough)
{
    const test::Tx funding = test::Tx::CreatePegIn(10'000);
    const SecretKey parent_sender = SecretKey::Random();
    const test::Tx parent = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000, parent_sender, SecretKey::Random(), SecretKey::Random())
        .AddPlainKernel(1'000)
        .Build();
    const auto child = BuildMWEBPegout(parent.GetOutputs().front());
    const mw::Transaction::CPtr cut_through = CutThrough(parent, parent_sender, child.first, child.second);

    const CTransactionRef parent_tx = WrapMWEBTx(parent.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(child.first);
    const CBlock block = BuildMWEBBlock(cut_through);

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(parent_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(parent_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(AllKernelsCached(pool, parent_tx));
    BOOST_CHECK(AllKernelsCached(pool, child_tx));
}

BOOST_AUTO_TEST_CASE(MWEBRemoveForBlockCutThroughAlternativeChild)
{
    const test::Tx funding = test::Tx::CreatePegIn(10'000);
    const SecretKey parent_sender = SecretKey::Random();
    const test::Tx parent = test::TxBuilder()
        .AddInput(funding.GetOutputs().front())
        .AddOutput(9'000, parent_sender, SecretKey::Random(), SecretKey::Random())
        .AddPlainKernel(1'000)
        .Build();
    const auto mempool_child = BuildMWEBPegout(parent.GetOutputs().front());
    const auto block_child = BuildMWEBPegout(parent.GetOutputs().front());
    const mw::Transaction::CPtr cut_through = CutThrough(parent, parent_sender, block_child.first, block_child.second);

    const CTransactionRef parent_tx = WrapMWEBTx(parent.GetTransaction());
    const CTransactionRef child_tx = WrapMWEBTx(mempool_child.first);
    const CBlock block = BuildMWEBBlock(cut_through);

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    TryAddToMempool(pool, entry.FromTx(parent_tx));
    TryAddToMempool(pool, entry.FromTx(child_tx));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);

    RemoveForMWEBBlock(pool, block);

    BOOST_CHECK(!pool.exists(parent_tx->GetHash()));
    BOOST_CHECK(!pool.exists(child_tx->GetHash()));
    BOOST_CHECK(AllKernelsCached(pool, parent_tx));
    BOOST_CHECK(!AnyKernelCached(pool, child_tx));
}

BOOST_AUTO_TEST_SUITE_END()
