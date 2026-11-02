// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <mweb/mweb_mempool_markets.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <sync.h>
#include <test/util/mweb_mempool_setup.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test_framework/models/tx.h>
#include <test_framework/tx_builder.h>
#include <txgraph.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>
#include <vector>

namespace {

struct MarketSetup : public MWEBPackageSetup {
    //! L1-only transaction spending a fresh mature coinbase.
    CTransactionRef MakeL1(CAmount fee)
    {
        const CTransactionRef coinbase = NextCoinbase();
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint{coinbase->GetHash(), 0});
        mtx.vout.emplace_back(coinbase->vout[0].nValue - fee, ChangeScript());
        Sign(mtx, {coinbase});
        return MakeTransactionRef(mtx);
    }

    MWEBMempoolMarkets& Markets() EXCLUSIVE_LOCKS_REQUIRED(Pool().cs) { return *Pool().m_mweb_markets; }

    const CTxMemPoolEntry& Entry(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(Pool().cs)
    {
        return *Assert(Pool().GetEntry(tx->GetHash()));
    }

    //! Txids of the worst chunk in market's eviction graph.
    std::set<Txid> WorstChunk(MempoolMarket market) EXCLUSIVE_LOCKS_REQUIRED(Pool().cs)
    {
        std::set<Txid> ret;
        for (const TxGraph::Ref* ref : Markets().Graph(market).GetWorstMainChunk().first) {
            ret.insert(MWEBMempoolMarkets::Entry(*ref).GetTx().GetHash());
        }
        return ret;
    }

    //! tx's ref in market's eviction graph.
    const TxGraph::Ref& FindRef(const CTransactionRef& tx, MempoolMarket market) EXCLUSIVE_LOCKS_REQUIRED(Pool().cs)
    {
        const TxGraph::Ref* ref{Markets().Find(Entry(tx), market)};
        BOOST_REQUIRE(ref);
        return *ref;
    }

    //! Txids of tx's ancestors (including tx) in market's eviction graph.
    std::set<Txid> Ancestors(const CTransactionRef& tx, MempoolMarket market) EXCLUSIVE_LOCKS_REQUIRED(Pool().cs)
    {
        std::set<Txid> ret;
        for (const TxGraph::Ref* ref : Markets().Graph(market).GetAncestors(FindRef(tx, market), TxGraph::Level::MAIN)) {
            ret.insert(MWEBMempoolMarkets::Entry(*ref).GetTx().GetHash());
        }
        return ret;
    }

    static std::set<Txid> Txids(const std::vector<CTransactionRef>& txs)
    {
        std::set<Txid> ret;
        for (const auto& tx : txs) ret.insert(tx->GetHash());
        return ret;
    }

    //! Real assembly, with exact membership in both transaction representations.
    std::unique_ptr<node::CBlockTemplate> CheckTemplate(CFeeRate minimum, const std::vector<CTransactionRef>& expected)
    {
        node::BlockCreateOptions options;
        options.test_block_validity = true;
        options.coinbase_output_script = CScript() << OP_TRUE;
        options.block_min_fee_rate = minimum;
        std::unique_ptr<node::CBlockTemplate> tmpl;
        {
            LOCK(::cs_main);
            tmpl = node::BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &Pool(), options}.CreateNewBlock();
        }
        BOOST_REQUIRE(tmpl);
        std::set<Txid> expected_l1, actual_l1;
        std::set<mw::Hash> expected_kernels;
        CAmount expected_fees{0}, expected_mweb_fees{0};
        {
            LOCK(Pool().cs);
            for (const auto& tx : expected) {
                if (!tx->IsMWEBOnly()) expected_l1.insert(tx->GetHash());
                const auto kernels{tx->mweb_tx.GetKernelIDs()};
                expected_kernels.insert(kernels.begin(), kernels.end());
                expected_fees += Entry(tx).GetFee();
                BOOST_REQUIRE(tx->mweb_tx.GetFee().has_value());
                expected_mweb_fees += *tx->mweb_tx.GetFee();
            }
        }
        for (const auto& tx : tmpl->block.vtx) {
            if (!tx->IsCoinBase() && !tx->IsHogEx()) actual_l1.insert(tx->GetHash());
        }
        BOOST_CHECK(actual_l1 == expected_l1);
        BOOST_CHECK(tmpl->block.mweb_block.GetKernelIDs() == expected_kernels);
        BOOST_REQUIRE(tmpl->block.mweb_block.GetTotalFee().has_value());
        BOOST_CHECK_EQUAL(*tmpl->block.mweb_block.GetTotalFee(), expected_mweb_fees);
        // Prioritisation changes selection, never the actual fees in the template.
        CAmount actual_fees{0};
        for (const CAmount fee : tmpl->vTxFees) actual_fees += fee;
        BOOST_CHECK_EQUAL(actual_fees, expected_fees);
        return tmpl;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(mweb_mempool_market_tests)

// L1-only transactions join only the L1 graph, MWEB-only transactions only the MWEB
// graph, and hybrids both; each entry's memory is split between the markets.
BOOST_FIXTURE_TEST_CASE(membership_and_usage, MarketSetup)
{
    const auto l1{MakeL1(L1_FEE)};
    const auto hybrid{MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE)};
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    Accept(l1, L1_FEE);
    Accept(hybrid, L1_FEE);
    Accept(mweb, MWEB_FEE);
    CheckPool({l1, hybrid, mweb});

    {
        LOCK(Pool().cs);
        using M = MempoolMarket;
        BOOST_CHECK(MWEBMempoolMarkets::InMarket(Entry(l1), M::L1) && !MWEBMempoolMarkets::InMarket(Entry(l1), M::MWEB));
        BOOST_CHECK(MWEBMempoolMarkets::InMarket(Entry(hybrid), M::L1) && MWEBMempoolMarkets::InMarket(Entry(hybrid), M::MWEB));
        BOOST_CHECK(!MWEBMempoolMarkets::InMarket(Entry(mweb), M::L1) && MWEBMempoolMarkets::InMarket(Entry(mweb), M::MWEB));
        BOOST_CHECK_EQUAL(Markets().Graph(M::L1).GetTransactionCount(TxGraph::Level::MAIN), 2U);
        BOOST_CHECK_EQUAL(Markets().Graph(M::MWEB).GetTransactionCount(TxGraph::Level::MAIN), 2U);

        BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetEntryUsage(Entry(l1), M::MWEB), 0U);
        BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetEntryUsage(Entry(mweb), M::L1), 0U);
        BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetEntryUsage(Entry(hybrid), M::MWEB), ::GetSerializeSize(hybrid->mweb_tx));
        const size_t entry_overhead{MWEBMempoolMarkets::GetEntryUsage(Entry(l1), M::L1) - Entry(l1).DynamicMemoryUsage()};
        for (const auto& tx : {l1, hybrid, mweb}) {
            BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetEntryUsage(Entry(tx), M::L1) + MWEBMempoolMarkets::GetEntryUsage(Entry(tx), M::MWEB),
                              Entry(tx).DynamicMemoryUsage() + entry_overhead);
        }

        for (M market : {M::L1, M::MWEB}) {
            size_t parts{0};
            for (const auto& tx : {l1, hybrid, mweb}) parts += MWEBMempoolMarkets::GetEntryUsage(Entry(tx), market);
            BOOST_CHECK_EQUAL(Markets().GetUsage(market), parts + Markets().Graph(market).GetMainMemoryUsage());
        }

        // The hybrid's L1 rank excludes the base MWEB fee; its MWEB rank is its whole fee.
        const uint64_t weight{hybrid->mweb_tx.GetMWEBWeight()};
        BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetFeerate(Entry(hybrid), M::L1).fee, L1_FEE - CFeeRate::GetMWEBFee(weight));
        BOOST_CHECK(MWEBMempoolMarkets::GetFeerate(Entry(hybrid), M::MWEB) == FeePerWeight(L1_FEE, weight));
    }

    MineMWEBEraBlock();
    CheckPool({});
    LOCK(Pool().cs);
    for (MempoolMarket market : {MempoolMarket::L1, MempoolMarket::MWEB}) {
        BOOST_CHECK_EQUAL(Markets().Graph(market).GetTransactionCount(TxGraph::Level::MAIN), 0U);
        BOOST_CHECK_EQUAL(Markets().GetUsage(market), Markets().Graph(market).GetMainMemoryUsage());
    }
}

// With only L1 transactions, the L1 graph evicts exactly as the main graph does.
BOOST_FIXTURE_TEST_CASE(l1_only_eviction_order_matches_main, TestingSetup)
{
    CTxMemPool& pool{*Assert(m_node.mempool)};
    LOCK2(::cs_main, pool.cs);
    std::vector<COutPoint> unspent;
    for (int i{0}; i < 120; ++i) {
        CMutableTransaction mtx;
        const size_t parents{unspent.empty() ? 0 : m_rng.randrange<size_t>(std::min<size_t>(unspent.size(), 3) + 1)};
        for (size_t p{0}; p < parents; ++p) {
            const size_t index{m_rng.randrange(unspent.size())};
            mtx.vin.emplace_back(unspent[index]);
            unspent.erase(unspent.begin() + index);
        }
        if (mtx.vin.empty()) mtx.vin.emplace_back(COutPoint{Txid::FromUint256(m_rng.rand256()), 0});
        const size_t outputs{1 + m_rng.randrange<size_t>(3)};
        for (size_t o{0}; o < outputs; ++o) {
            mtx.vout.emplace_back(COIN, CScript() << std::vector<unsigned char>(1 + m_rng.randrange<size_t>(200), 0x51));
        }
        const CAmount fee{m_rng.randrange<CAmount>(4) == 0 ? 1000 : m_rng.randrange<CAmount>(50'000)};
        const unsigned int sigops{m_rng.randrange<unsigned int>(4) == 0 ? m_rng.randrange<unsigned int>(400) : 0U};
        const CTransactionRef tx{MakeTransactionRef(mtx)};
        TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(fee).SigOpsCost(sigops).FromTx(tx));
        if (pool.exists(tx->GetHash())) {
            for (uint32_t o{0}; o < tx->vout.size(); ++o) unspent.emplace_back(tx->GetHash(), o);
        }
    }
    BOOST_REQUIRE_GT(pool.size(), 60U);

    MWEBMempoolMarkets& markets{*pool.m_mweb_markets};
    while (pool.size() > 0) {
        markets.SanityCheck(*pool.m_txgraph, pool.size());
        const auto [main_chunk, main_feerate] = pool.m_txgraph->GetWorstMainChunk();
        const auto [l1_chunk, l1_feerate] = markets.Graph(MempoolMarket::L1).GetWorstMainChunk();
        BOOST_CHECK(main_feerate == l1_feerate);
        std::set<const CTxMemPoolEntry*> main_entries, l1_entries;
        for (const TxGraph::Ref* ref : main_chunk) main_entries.insert(static_cast<const CTxMemPoolEntry*>(ref));
        for (const TxGraph::Ref* ref : l1_chunk) l1_entries.insert(&MWEBMempoolMarkets::Entry(*ref));
        BOOST_REQUIRE(main_entries == l1_entries);
        BOOST_CHECK_EQUAL(markets.Graph(MempoolMarket::MWEB).GetTransactionCount(TxGraph::Level::MAIN), 0U);
        pool.TrimToSize(pool.DynamicMemoryUsage() - 1);
    }
    markets.SanityCheck(*pool.m_txgraph, pool.size());
}

// A paying MWEB child lifts its base-fee parent above a lone transaction in the MWEB graph.
BOOST_FIXTURE_TEST_CASE(mweb_cpfp_chunks_parent_with_child, MarketSetup)
{
    const uint64_t weight{MakeMWEBOnly(Spend(m_mweb_coins[0]))->mweb_tx.GetMWEBWeight()};
    const CAmount base{CFeeRate::GetMWEBFee(weight)};
    const test::Tx parent_mweb{Spend(m_mweb_coins[0], base + 200)};
    const auto parent{MakeMWEBOnly(parent_mweb)};
    const auto lone{MakeMWEBOnly(Spend(m_mweb_coins[1], base + 2'000))};
    const auto child{MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front(), 10 * base))};
    Accept(parent, base + 200);
    Accept(lone, base + 2'000);
    WITH_LOCK(Pool().cs, BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({parent})));

    Accept(child, 10 * base);
    CheckPool({parent, lone, child});
    LOCK(Pool().cs);
    BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({lone}));
    TxGraph& graph{Markets().Graph(MempoolMarket::MWEB)};
    BOOST_CHECK(graph.GetMainChunkFeerate(FindRef(parent, MempoolMarket::MWEB)) == graph.GetMainChunkFeerate(FindRef(child, MempoolMarket::MWEB)));
}

// Between MWEB transactions of equal feerate, the newest is evicted first, whatever the txids.
BOOST_FIXTURE_TEST_CASE(mweb_ties_evict_newest, MarketSetup)
{
    const auto older{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    CTransactionRef newer;
    for (int attempt{0}; attempt < 64 && !newer; ++attempt) {
        const auto candidate{MakeMWEBOnly(Spend(m_mweb_coins[1]))};
        if (candidate->GetHash() < older->GetHash()) newer = candidate;
    }
    BOOST_REQUIRE(newer);
    BOOST_REQUIRE_EQUAL(newer->mweb_tx.GetMWEBWeight(), older->mweb_tx.GetMWEBWeight());
    Accept(older, MWEB_FEE);
    Accept(newer, MWEB_FEE);
    CheckPool({older, newer});

    LOCK(Pool().cs);
    BOOST_REQUIRE_LT(Entry(older).GetSequence(), Entry(newer).GetSequence());
    BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({newer}));
}

// An L1 graph dependency runs through an MWEB-only transaction between two hybrids.
BOOST_FIXTURE_TEST_CASE(l1_graph_links_through_mweb_only_transaction, MarketSetup)
{
    const test::Tx root_mweb{Pegin()};
    const auto root{MakeHybrid(root_mweb, FUNDING_AMOUNT, L1_FEE)};
    const test::Tx middle_mweb{Spend(root_mweb.GetOutputs().front())};
    const auto middle{MakeMWEBOnly(middle_mweb)};
    const test::TxOutput& middle_out{middle_mweb.GetOutputs().front()};
    const CAmount pegin{COIN};
    const test::Tx leaf_mweb{test::TxBuilder{}
                                 .AddInput(middle_out)
                                 .AddOutput(static_cast<CAmount>(middle_out.GetAmount()) + pegin)
                                 .AddPeginKernel(pegin)
                                 .Build()};
    const auto leaf{MakeHybrid(leaf_mweb, pegin, L1_FEE)};
    Accept(root, L1_FEE);
    Accept(middle, MWEB_FEE);
    Accept(leaf, L1_FEE);
    CheckPool({root, middle, leaf});

    LOCK(Pool().cs);
    BOOST_CHECK(Ancestors(leaf, MempoolMarket::L1) == Txids({root, leaf}));
    BOOST_CHECK(Ancestors(leaf, MempoolMarket::MWEB) == Txids({root, middle, leaf}));
}

// After a reorg restores a mined hybrid, both eviction graphs link it to its unconfirmed children.
BOOST_FIXTURE_TEST_CASE(reorg_relinks_markets, MarketSetup)
{
    const test::Tx parent_mweb{Pegin()};
    const auto parent{MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE)};
    Accept(parent, L1_FEE);
    MineMWEBEraBlock();
    const auto l1_child{MakeL1Child({parent}, L1_FEE)};
    const auto mweb_child{MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()))};
    Accept(l1_child, L1_FEE);
    Accept(mweb_child, MWEB_FEE);
    CheckPool({l1_child, mweb_child});

    InvalidateTip();
    CheckPool({parent, l1_child, mweb_child});
    LOCK(Pool().cs);
    BOOST_CHECK(Ancestors(l1_child, MempoolMarket::L1) == Txids({parent, l1_child}));
    BOOST_CHECK(Ancestors(mweb_child, MempoolMarket::MWEB) == Txids({parent, mweb_child}));
}

// prioritisetransaction moves an entry's rank in every market it is in.
BOOST_FIXTURE_TEST_CASE(prioritise_updates_markets, MarketSetup)
{
    const auto hybrid{MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE)};
    const auto low{MakeMWEBOnly(Spend(m_mweb_coins[0], MWEB_FEE))};
    const auto high{MakeMWEBOnly(Spend(m_mweb_coins[1], 2 * MWEB_FEE))};
    Accept(hybrid, L1_FEE);
    Accept(low, MWEB_FEE);
    Accept(high, 2 * MWEB_FEE);
    WITH_LOCK(Pool().cs, BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({low})));

    Pool().PrioritiseTransaction(low->GetHash(), 5 * MWEB_FEE);
    Pool().PrioritiseTransaction(hybrid->GetHash(), 7 * L1_FEE);
    CheckPool({hybrid, low, high});
    LOCK(Pool().cs);
    BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({high}));
    const uint64_t weight{hybrid->mweb_tx.GetMWEBWeight()};
    BOOST_CHECK_EQUAL(Markets().Graph(MempoolMarket::L1).GetIndividualFeerate(FindRef(hybrid, MempoolMarket::L1)).fee,
                      8 * L1_FEE - CFeeRate::GetMWEBFee(weight));
    BOOST_CHECK_EQUAL(Markets().Graph(MempoolMarket::MWEB).GetIndividualFeerate(FindRef(hybrid, MempoolMarket::MWEB)).fee, 8 * L1_FEE);
}

// L1 pressure evicts the L1 transaction and keeps a base-fee MWEB-only transaction.
BOOST_FIXTURE_TEST_CASE(l1_pressure_keeps_mweb_only, MarketSetup)
{
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    const auto l1{MakeL1(L1_FEE)};
    Accept(mweb, MWEB_FEE);
    Accept(l1, L1_FEE);
    CheckPool({mweb, l1});

    LOCK(Pool().cs);
    // Default 80% MWEB share: with one of each, L1 is further over its cap.
    BOOST_REQUIRE(Markets().GetWorstChunk(Pool().DynamicMemoryUsage() - 1, /*mweb_share_pct=*/80).market ==
                  MempoolMarket::L1);
    while (Pool().exists(l1->GetHash())) {
        Pool().TrimToSize(Pool().DynamicMemoryUsage() - 1);
    }
    BOOST_CHECK(Pool().exists(mweb->GetHash()));
}

// Shares of 0 and 100 select the non-empty opposing market first when both have txs.
BOOST_FIXTURE_TEST_CASE(share_zero_and_hundred, MarketSetup)
{
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    const auto l1{MakeL1(L1_FEE)};
    Accept(mweb, MWEB_FEE);
    Accept(l1, L1_FEE);

    LOCK(Pool().cs);
    BOOST_CHECK(Markets().GetWorstChunk(/*mempool_limit=*/1'000'000, /*mweb_share_pct=*/0).market == MempoolMarket::MWEB);
    BOOST_CHECK(Markets().GetWorstChunk(/*mempool_limit=*/1'000'000, /*mweb_share_pct=*/100).market == MempoolMarket::L1);
}

// Evicting MWEB-only data raises mwebminfee without bumping the L1 rolling minimum.
BOOST_FIXTURE_TEST_CASE(mweb_trim_bumps_only_mweb_min_fee, MarketSetup)
{
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    Accept(mweb, MWEB_FEE);

    LOCK(Pool().cs);
    const CFeeRate l1_before{Pool().GetMinFee()};
    BOOST_CHECK_EQUAL(l1_before.GetFeePerK(), 0);
    Pool().TrimToSize(0);
    BOOST_CHECK_EQUAL(Pool().size(), 0U);
    BOOST_CHECK(Pool().GetMWEBMinFee() > CFeeRate{0});
    BOOST_CHECK(Pool().GetMinFee() == l1_before);
}

// CheckFeeRate rejects a base-fee MWEB package once mwebminfee has been raised by trim.
BOOST_FIXTURE_TEST_CASE(admission_requires_mweb_min_fee, MarketSetup)
{
    const auto first{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    Accept(first, MWEB_FEE);
    WITH_LOCK(Pool().cs, Pool().TrimToSize(0));
    BOOST_REQUIRE(Pool().GetMWEBMinFee() > CFeeRate{0});

    const auto second{MakeMWEBOnly(Spend(m_mweb_coins[1]))};
    const auto result{Submit(second)};
    BOOST_CHECK(result.m_result_type != MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "mempool min fee not met");
    CheckPool({}, {second});
}

// Each rolling fee decays independently, whichever getter runs first.
BOOST_FIXTURE_TEST_CASE(mweb_min_fee_decays_after_get_min_fee, MarketSetup)
{
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    const auto l1{MakeL1(L1_FEE)};
    Accept(mweb, MWEB_FEE);
    Accept(l1, L1_FEE);

    LOCK(Pool().cs);
    Pool().TrimToSize(0);
    BOOST_REQUIRE(Pool().GetMWEBMinFee() > CFeeRate{0});
    BOOST_REQUIRE(Pool().GetMinFee() > CFeeRate{0});

    for (const bool l1_first : {true, false}) {
        const CFeeRate l1_before{Pool().GetMinFee()};
        const CFeeRate mweb_before{Pool().GetMWEBMinFee()};
        BOOST_REQUIRE(l1_before > CFeeRate{0});
        BOOST_REQUIRE(mweb_before > CFeeRate{0});
        Pool().removeForBlock({}); // allow decay and reset both clocks
        SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{60});
        CFeeRate l1_after, mweb_after;
        if (l1_first) {
            l1_after = Pool().GetMinFee();
            mweb_after = Pool().GetMWEBMinFee();
        } else {
            mweb_after = Pool().GetMWEBMinFee();
            l1_after = Pool().GetMinFee();
        }
        BOOST_CHECK(l1_after < l1_before);
        BOOST_CHECK(mweb_after < mweb_before);
    }
}

// Exact MWEB base charge / charge-1 / surplus selection against the dual-market floor.
BOOST_FIXTURE_TEST_CASE(mweb_fee_floor_charge_minus_one_and_surplus, MarketSetup)
{
    const uint64_t weight{MakeMWEBOnly(Spend(m_mweb_coins[0]))->mweb_tx.GetMWEBWeight()};
    const CAmount base{CFeeRate::GetMWEBFee(weight)};
    BOOST_REQUIRE_GT(base, 0);

    const auto below{MakeMWEBOnly(Spend(m_mweb_coins[0], base - 1))};
    Reject(below, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    CheckPool({}, {below});

    const auto at_floor{MakeMWEBOnly(Spend(m_mweb_coins[0], base))};
    const auto surplus{MakeMWEBOnly(Spend(m_mweb_coins[1], base + 5'000))};
    Accept(at_floor, base);
    Accept(surplus, base + 5'000);
    CheckPool({at_floor, surplus});
    LOCK(Pool().cs);
    BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({at_floor}));
}

// A zero-canonical-vsize singleton at the exact relay floor is selected into CreateNewBlock.
BOOST_FIXTURE_TEST_CASE(assembler_includes_zero_vsize_transaction_at_fee_floor, MarketSetup)
{
    const auto probe{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*probe), 0);
    const CAmount floor_fee{WITH_LOCK(Pool().cs, return Pool().m_opts.min_relay_feerate.GetTotalFee(0, probe->mweb_tx.GetMWEBWeight()))};
    BOOST_REQUIRE_GT(floor_fee, 0);
    const auto at_floor{MakeMWEBOnly(Spend(m_mweb_coins[0], floor_fee))};
    Accept(at_floor, floor_fee);
    CheckPool({at_floor});

    node::BlockCreateOptions options;
    options.test_block_validity = false;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<node::CBlockTemplate> tmpl;
    {
        LOCK(::cs_main);
        tmpl = node::BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), &Pool(), options}.CreateNewBlock();
    }
    BOOST_REQUIRE(tmpl);
    BOOST_REQUIRE(!tmpl->block.mweb_block.IsNull());
    BOOST_REQUIRE(tmpl->block.mweb_block.GetTotalFee().has_value());
    BOOST_CHECK_EQUAL(*tmpl->block.mweb_block.GetTotalFee(), floor_fee);
    const auto expected_ids{at_floor->mweb_tx.GetOutputIDs()};
    BOOST_REQUIRE_EQUAL(expected_ids.size(), 1U);
    bool found{false};
    for (const auto& output : tmpl->block.mweb_block.m_block->GetOutputs()) {
        found |= output.GetOutputID() == *expected_ids.begin();
    }
    BOOST_CHECK(found);
}

// The chunk pays the sum of both bodies' charges. Once its shared ancestor is
// included, each remaining child must pay its own charge without that subsidy.
BOOST_FIXTURE_TEST_CASE(assembler_includes_zero_vsize_package_at_fee_floor, MarketSetup)
{
    // One kernel costs 2 WU and each output 18 WU; inputs cost no MWEB weight.
    constexpr CAmount parent_charge{100 * 38}, child_charge{100 * 20};
    constexpr CAmount package_charge{parent_charge + child_charge};
    constexpr CAmount parent_fee{1}, child_fee{package_charge - parent_fee};
    const test::Tx parent_mweb{Spend({m_mweb_coins[0]}, parent_fee, /*num_outputs=*/2)};
    const auto parent{MakeMWEBOnly(parent_mweb)};
    const auto child{MakeMWEBOnly(Spend(parent_mweb.GetOutputs()[0], child_fee))};
    const auto sibling{MakeMWEBOnly(Spend(parent_mweb.GetOutputs()[1], child_charge))};
    const auto lone{MakeMWEBOnly(Spend(m_mweb_coins[1], child_charge + 1'000))};
    BOOST_REQUIRE_EQUAL(parent->mweb_tx.GetMWEBWeight(), 38U);
    for (const auto& tx : {child, sibling, lone}) BOOST_REQUIRE_EQUAL(tx->mweb_tx.GetMWEBWeight(), 20U);
    for (const auto& tx : {parent, child, sibling, lone}) BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*tx), 0);
    Reject(parent, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    const auto result{SubmitPackage({parent, child})};
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_CHECK_EQUAL(result.m_tx_results.at(parent->GetWitnessHash()).m_base_fees.value(), parent_fee);
    BOOST_CHECK_EQUAL(result.m_tx_results.at(child->GetWitnessHash()).m_base_fees.value(), child_fee);
    Accept(sibling, child_charge);
    Accept(lone, child_charge + 1'000);
    CheckPool({parent, child, sibling, lone});
    CheckGraph(child, {parent, child}, {child});
    CheckGraph(sibling, {parent, sibling}, {sibling});

    // Mining-only deltas preserve real admission at the exact package floor.
    // The canonical fee floor is deliberately nonzero despite zero L1 vsize.
    const CFeeRate minimum{20'000};
    Pool().PrioritiseTransaction(sibling->GetHash(), -1);
    Pool().PrioritiseTransaction(child->GetHash(), -1);
    WITH_LOCK(Pool().cs, BOOST_CHECK_EQUAL(Entry(parent).GetModifiedFee() + Entry(child).GetModifiedFee(), package_charge - 1));
    CheckTemplate(minimum, {lone}); // summed charge - 1
    Pool().PrioritiseTransaction(child->GetHash(), 1);
    WITH_LOCK(Pool().cs, BOOST_CHECK_EQUAL(Entry(parent).GetModifiedFee() + Entry(child).GetModifiedFee(), package_charge));
    CheckTemplate(minimum, {parent, child, lone}); // exact summed charge
    Pool().PrioritiseTransaction(child->GetHash(), 1);
    WITH_LOCK(Pool().cs, BOOST_CHECK_EQUAL(Entry(parent).GetModifiedFee() + Entry(child).GetModifiedFee(), package_charge + 1));
    CheckTemplate(minimum, {parent, child, lone}); // summed charge + 1
    Pool().PrioritiseTransaction(child->GetHash(), -1);

    // Keep the same package total but make the parent a better standalone chunk.
    // Neither the paying child nor its sibling may reuse the included parent.
    Pool().PrioritiseTransaction(parent->GetHash(), 3 * child_fee);
    Pool().PrioritiseTransaction(child->GetHash(), -3 * child_fee);
    {
        LOCK(Pool().cs);
        BOOST_CHECK_EQUAL(Entry(parent).GetModifiedFee() + Entry(child).GetModifiedFee(), package_charge);
        BOOST_CHECK_LT(Entry(child).GetModifiedFee(), child_charge);
        BOOST_CHECK_EQUAL(Entry(sibling).GetModifiedFee(), child_charge - 1);
    }
    CheckTemplate(minimum, {parent, lone});
    CheckPool({parent, child, sibling, lone});
}

// Two siblings pay their respective ancestors before the joining child becomes
// eligible on its own; including the second parent preserves the first removal.
BOOST_FIXTURE_TEST_CASE(assembler_reselects_child_after_both_ancestors_are_paid, MarketSetup)
{
    constexpr CAmount parent_fee{1}, child_fee{2'500};
    const test::Tx first_mweb{Spend({m_mweb_coins[0]}, parent_fee, /*num_outputs=*/2)};
    const test::Tx second_mweb{Spend({m_mweb_coins[1]}, parent_fee, /*num_outputs=*/2)};
    const auto first{MakeMWEBOnly(first_mweb)};
    const auto second{MakeMWEBOnly(second_mweb)};
    const auto first_sibling{MakeMWEBOnly(Spend(first_mweb.GetOutputs()[1], 20'000))};
    const auto second_sibling{MakeMWEBOnly(Spend(second_mweb.GetOutputs()[1], 10'000))};
    for (const Package& package : {Package{first, first_sibling}, Package{second, second_sibling}}) {
        const auto result{SubmitPackage(package)};
        BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    }
    const auto child{MakeMWEBOnly(Spend({first_mweb.GetOutputs()[0], second_mweb.GetOutputs()[0]}, child_fee))};
    const auto lone{MakeMWEBOnly(Spend(m_mweb_coins[2], 3'000))};
    Accept(child, child_fee);
    Accept(lone, 3'000);
    CheckPool({first, first_sibling, second, second_sibling, child, lone});
    CheckGraph(child, {first, second, child}, {child});
    for (const auto& tx : {first, second}) BOOST_REQUIRE_EQUAL(tx->mweb_tx.GetMWEBWeight(), 38U);
    for (const auto& tx : {first_sibling, second_sibling, child, lone}) BOOST_REQUIRE_EQUAL(tx->mweb_tx.GetMWEBWeight(), 20U);
    // The child covers its own 2,000-sat charge but cannot pay either 3,800-sat parent.
    BOOST_REQUIRE_GE(child_fee, 100 * 20);
    BOOST_REQUIRE_LT(child_fee + parent_fee, 100 * (20 + 38));
    const CFeeRate minimum{20'000};
    Pool().PrioritiseTransaction(second_sibling->GetHash(), -8'000);
    CheckTemplate(minimum, {first, first_sibling, lone});
    Pool().PrioritiseTransaction(second_sibling->GetHash(), 8'000);
    const auto tmpl{CheckTemplate(minimum, {first, first_sibling, second, second_sibling, child, lone})};
    // Native chunks, with strictly different rates, expose the child's remaining
    // fee/weight after both ancestors have already been included. Weight 58
    // becomes 15 graph vbytes; the standalone 20-WU child becomes 5.
    const std::vector<FeePerVSize> expected_chunks{{20'001, 15}, {10'001, 15}, {3'000, 5}, {child_fee, 5}};
    BOOST_REQUIRE_EQUAL(tmpl->m_package_feerates.size(), expected_chunks.size());
    for (size_t i{0}; i < expected_chunks.size(); ++i) {
        BOOST_CHECK(tmpl->m_package_feerates[i] == expected_chunks[i]);
    }
    CheckPool({first, first_sibling, second, second_sibling, child, lone});
}

// Independent transactions of each class straddle a nonzero canonical mining
// floor; the MWEB base charge remains due even when that canonical floor is zero.
BOOST_FIXTURE_TEST_CASE(assembler_dual_fee_floor_matrix, MarketSetup)
{
    constexpr CAmount sats_per_vbyte{20};
    std::vector<CTransactionRef> all, selected_nonzero, selected_zero;
    for (int boundary{-1}; boundary <= 1; ++boundary) {
        const auto l1{MakeL1(L1_FEE)};
        const auto hybrid{MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE)};
        const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[boundary + 1]))};
        for (const auto& tx : {l1, hybrid, mweb}) {
            const CAmount actual_fee{tx->IsMWEBOnly() ? MWEB_FEE : L1_FEE};
            Accept(tx, actual_fee);
            const auto vsize{GetVirtualTransactionSize(*tx)};
            const CAmount charge{100 * static_cast<CAmount>(tx->mweb_tx.GetMWEBWeight()) + sats_per_vbyte * vsize};
            BOOST_REQUIRE_GT(charge, 0);
            WITH_LOCK(Pool().cs, BOOST_REQUIRE_EQUAL(Entry(tx).GetTxSize(), vsize));
            Pool().PrioritiseTransaction(tx->GetHash(), charge + boundary - actual_fee);
            WITH_LOCK(Pool().cs, BOOST_CHECK_EQUAL(Entry(tx).GetModifiedFee(), charge + boundary));
            all.push_back(tx);
            if (boundary >= 0) selected_nonzero.push_back(tx);
            if (!tx->IsMWEBOnly() || boundary >= 0) selected_zero.push_back(tx);
        }
    }
    const auto zero_l1{MakeL1(L1_FEE)};
    Accept(zero_l1, L1_FEE);
    Pool().PrioritiseTransaction(zero_l1->GetHash(), -L1_FEE);
    WITH_LOCK(Pool().cs, BOOST_REQUIRE_EQUAL(Entry(zero_l1).GetModifiedFee(), 0));
    all.push_back(zero_l1);
    selected_zero.push_back(zero_l1);
    CheckPool(all);
    CheckTemplate(CFeeRate{sats_per_vbyte * 1'000}, selected_nonzero);
    CheckTemplate(CFeeRate{0}, selected_zero);
    CheckPool(all);
}

// The L1 rank must saturate when subtracting a hybrid's MWEB base charge from
// CAmount::min; native chunk selection must still include unrelated paying txs.
BOOST_FIXTURE_TEST_CASE(minimum_amount_prioritisation_saturates_hybrid_rank, MarketSetup)
{
    const test::Tx parent_mweb{Pegin()};
    const auto parent{MakeHybrid(parent_mweb, FUNDING_AMOUNT, /*l1_fee=*/0)};
    const auto child{MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()))};
    const auto result{SubmitPackage({parent, child})};
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    const auto l1{MakeL1(L1_FEE)};
    const auto mweb{MakeMWEBOnly(Spend(m_mweb_coins[0]))};
    Accept(l1, L1_FEE);
    Accept(mweb, MWEB_FEE);
    constexpr CAmount minimum{std::numeric_limits<CAmount>::min()};
    Pool().PrioritiseTransaction(parent->GetHash(), minimum);
    CheckPool({parent, child, l1, mweb});
    {
        LOCK(Pool().cs);
        BOOST_REQUIRE_GT(Entry(parent).GetMWEBWeight(), 0U);
        BOOST_CHECK_EQUAL(Entry(parent).GetFee(), 0);
        BOOST_CHECK_EQUAL(Entry(parent).GetModifiedFee(), minimum);
        for (const auto market : {MempoolMarket::L1, MempoolMarket::MWEB}) {
            BOOST_CHECK_EQUAL(MWEBMempoolMarkets::GetFeerate(Entry(parent), market).fee, minimum);
            BOOST_CHECK_EQUAL(Markets().Graph(market).GetIndividualFeerate(FindRef(parent, market)).fee, minimum);
        }
        Markets().SanityCheck(*Pool().m_txgraph, Pool().size());
        BOOST_CHECK_EQUAL(Pool().GetTotalFee(), L1_FEE + 2 * MWEB_FEE);
    }
    CheckTemplate(CFeeRate{0}, {l1, mweb});
    CheckPool({parent, child, l1, mweb});

    // Exercise the other transaction classes at the same integer boundary.
    // Their real positive fees remain part of the modified fee after the delta.
    Pool().PrioritiseTransaction(l1->GetHash(), minimum);
    Pool().PrioritiseTransaction(mweb->GetHash(), minimum);
    {
        LOCK(Pool().cs);
        BOOST_CHECK_EQUAL(Entry(l1).GetModifiedFee(), minimum + L1_FEE);
        BOOST_CHECK_EQUAL(Entry(mweb).GetModifiedFee(), minimum + MWEB_FEE);
        BOOST_CHECK_EQUAL(Markets().Graph(MempoolMarket::L1).GetIndividualFeerate(FindRef(l1, MempoolMarket::L1)).fee,
                          minimum + L1_FEE);
        BOOST_CHECK_EQUAL(Markets().Graph(MempoolMarket::MWEB).GetIndividualFeerate(FindRef(mweb, MempoolMarket::MWEB)).fee,
                          minimum + MWEB_FEE);
        for (const auto market : {MempoolMarket::L1, MempoolMarket::MWEB}) {
            BOOST_CHECK_EQUAL(Markets().Graph(market).GetIndividualFeerate(FindRef(parent, market)).fee, minimum);
        }
        Markets().SanityCheck(*Pool().m_txgraph, Pool().size());
        BOOST_CHECK_EQUAL(Pool().GetTotalFee(), L1_FEE + 2 * MWEB_FEE);
    }
    CheckTemplate(CFeeRate{0}, {});

    // Restore in representable steps before CheckPool builds its cumulative fee
    // diagram: the sum of several integer-minimum deltas is outside CAmount.
    for (const auto& tx : {parent, l1, mweb}) {
        Pool().PrioritiseTransaction(tx->GetHash(), std::numeric_limits<CAmount>::max());
        Pool().PrioritiseTransaction(tx->GetHash(), 1);
    }
    CheckPool({parent, child, l1, mweb});
}

// Extreme negative prioritisation demotes an entry without corrupting market graphs or totals.
BOOST_FIXTURE_TEST_CASE(extreme_negative_prioritisation_demotes_mweb_entry, MarketSetup)
{
    const auto low{MakeMWEBOnly(Spend(m_mweb_coins[0], MWEB_FEE))};
    const auto high{MakeMWEBOnly(Spend(m_mweb_coins[1], 3 * MWEB_FEE))};
    Accept(low, MWEB_FEE);
    Accept(high, 3 * MWEB_FEE);
    WITH_LOCK(Pool().cs, BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({low})));

    Pool().PrioritiseTransaction(high->GetHash(), -100 * MWEB_FEE);
    CheckPool({low, high});
    LOCK(Pool().cs);
    BOOST_CHECK(WorstChunk(MempoolMarket::MWEB) == Txids({high}));
    Markets().SanityCheck(*Pool().m_txgraph, Pool().size());
    BOOST_CHECK_EQUAL(Pool().GetTotalFee(), 4 * MWEB_FEE);
}

// After the shared ancestor is mined, an underpaying newly-independent child is rejected on its own floor.
BOOST_FIXTURE_TEST_CASE(underpaying_child_rejected_after_ancestor_mined, MarketSetup)
{
    const uint64_t weight{MakeMWEBOnly(Spend(m_mweb_coins[0]))->mweb_tx.GetMWEBWeight()};
    const CAmount base{CFeeRate::GetMWEBFee(weight)};
    const test::Tx parent_mweb{Spend(m_mweb_coins[0], base)};
    const auto parent{MakeMWEBOnly(parent_mweb)};
    Accept(parent, base);
    MineMWEBEraBlock();
    BOOST_REQUIRE(!Pool().exists(parent->GetHash()));

    const auto underpaying{MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front(), base - 1))};
    Reject(underpaying, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    const auto paying{MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front(), base))};
    Accept(paying, base);
    CheckPool({paying});
}

BOOST_AUTO_TEST_SUITE_END()
