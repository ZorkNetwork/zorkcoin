// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_historical_cache.h>
#include <node/mweb_leafdb_sync.h>

#include <chain.h>
#include <mw/db/leaf_db.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>
#include <mweb/mweb_node.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <test_framework/miner.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

#include <memory>
#include <vector>

using node::CopySpentLeafPayloads;
using node::GetFreezePathStatsForTest;
using node::GetMWEBHistoricalViewCache;
using node::LeafCreateHeight;
using node::NeedsSparseMaterialize;
using node::PruneSpentLeafPayloads;
using node::ResetFreezePathStatsForTest;

BOOST_FIXTURE_TEST_SUITE(mweb_leafdb_sync_tests, MWEBTestingSetup)

namespace {

void FlushView(const mw::CoinsViewCache::Ptr& cache, const mw::DBWrapper::Ptr& db)
{
    auto batch = db->CreateBatch();
    cache->Flush(batch);
    batch->Commit();
}

} // namespace

BOOST_AUTO_TEST_CASE(needs_sparse_materialize_detects_missing_spent_payloads)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCached = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin = test::Tx::CreatePegIn(5'000'000);
    pCached->ApplyBlock(miner.MineBlock(1, {pegin}).GetBlock(), false);
    test::Tx pegout = test::Tx::CreatePegOut(pegin.GetOutputs().front(), /*fee=*/1'000);
    pCached->ApplyBlock(miner.MineBlock(2, {pegout}).GetBlock(), false);
    FlushView(pCached, GetDB());

    BOOST_CHECK(!NeedsSparseMaterialize(*pDBView));

    auto dense = mw::CoinsViewMemory::Materialize(*pDBView);
    BOOST_REQUIRE(dense);
    BOOST_CHECK(!NeedsSparseMaterialize(*dense));

    auto sparse = mw::CoinsViewMemory::MaterializeAssumeUTXOSnapshot(*pDBView);
    BOOST_REQUIRE(sparse);
    BOOST_CHECK(NeedsSparseMaterialize(*sparse));
}

BOOST_AUTO_TEST_CASE(copy_spent_leaf_payloads_from_dense_source)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCached = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin = test::Tx::CreatePegIn(5'000'000);
    pCached->ApplyBlock(miner.MineBlock(1, {pegin}).GetBlock(), false);
    test::Tx pegout = test::Tx::CreatePegOut(pegin.GetOutputs().front(), /*fee=*/1'000);
    pCached->ApplyBlock(miner.MineBlock(2, {pegout}).GetBlock(), false);
    FlushView(pCached, GetDB());

    auto dense_source = mw::CoinsViewMemory::Materialize(*pDBView);
    BOOST_REQUIRE(dense_source);

    const auto leafset = pDBView->GetLeafSet();
    BOOST_REQUIRE(leafset);
    std::vector<mmr::LeafIndex> spent;
    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < leafset->GetNextLeafIdx(); ++idx) {
        if (!leafset->Contains(idx)) {
            spent.push_back(idx);
        }
    }
    BOOST_REQUIRE(!spent.empty());
    {
        auto batch = pDBView->GetDatabase()->CreateBatch();
        LeafDB ldb('O', pDBView->GetDatabase().get(), batch.get());
        ldb.Remove(spent);
        batch->Commit();
    }
    BOOST_CHECK(NeedsSparseMaterialize(*pDBView));

    CChain empty_chain;
    auto stats = CopySpentLeafPayloads(*dense_source, *pDBView, empty_chain, /*min_create_height=*/std::nullopt);
    BOOST_CHECK_GT(stats.copied, 0);
    BOOST_CHECK(!NeedsSparseMaterialize(*pDBView));

    {
        auto batch = pDBView->GetDatabase()->CreateBatch();
        LeafDB ldb('O', pDBView->GetDatabase().get(), batch.get());
        ldb.Remove(spent);
        batch->Commit();
    }
    auto filtered = CopySpentLeafPayloads(*dense_source, *pDBView, empty_chain, /*min_create_height=*/1);
    BOOST_CHECK_EQUAL(filtered.copied, 0);
    BOOST_CHECK_GT(filtered.skipped_below_min_height, 0);
}

BOOST_AUTO_TEST_CASE(prune_spent_leaf_payloads_respects_create_height)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCached = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin = test::Tx::CreatePegIn(5'000'000);
    pCached->ApplyBlock(miner.MineBlock(1, {pegin}).GetBlock(), false);
    test::Tx pegout = test::Tx::CreatePegOut(pegin.GetOutputs().front(), /*fee=*/1'000);
    pCached->ApplyBlock(miner.MineBlock(2, {pegout}).GetBlock(), false);
    FlushView(pCached, GetDB());

    std::vector<std::unique_ptr<CBlockIndex>> indexes;
    indexes.emplace_back(std::make_unique<CBlockIndex>());
    indexes.back()->nHeight = 0;
    indexes.emplace_back(std::make_unique<CBlockIndex>());
    indexes[1]->nHeight = 1;
    indexes[1]->pprev = indexes[0].get();
    indexes[1]->mweb_header = std::make_shared<mw::Header>(
        /*height=*/1, mw::Hash{}, mw::Hash{}, mw::Hash{}, BlindingFactor{}, BlindingFactor{},
        /*outputMMRSize=*/1, /*kernelMMRSize=*/0);
    indexes.emplace_back(std::make_unique<CBlockIndex>());
    indexes[2]->nHeight = 2;
    indexes[2]->pprev = indexes[1].get();
    indexes[2]->mweb_header = pDBView->GetBestHeader();

    CChain chain;
    chain.SetTip(*indexes[2]);

    BOOST_REQUIRE(LeafCreateHeight(chain, /*leaf_index=*/0).has_value());
    BOOST_CHECK(!NeedsSparseMaterialize(*pDBView));

    auto stats = PruneSpentLeafPayloads(*pDBView, chain, /*min_retain_height=*/2);
    BOOST_CHECK_GT(stats.removed, 0);
    BOOST_CHECK(NeedsSparseMaterialize(*pDBView));
}

BOOST_AUTO_TEST_CASE(freeze_sparse_parent_uses_sparse_direct_not_dense_fail)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCached = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin = test::Tx::CreatePegIn(5'000'000);
    pCached->ApplyBlock(miner.MineBlock(1, {pegin}).GetBlock(), false);
    test::Tx pegout = test::Tx::CreatePegOut(pegin.GetOutputs().front(), /*fee=*/1'000);
    pCached->ApplyBlock(miner.MineBlock(2, {pegout}).GetBlock(), false);
    FlushView(pCached, GetDB());

    auto sparse = mw::CoinsViewMemory::MaterializeAssumeUTXOSnapshot(*pDBView);
    BOOST_REQUIRE(sparse);
    BOOST_REQUIRE(NeedsSparseMaterialize(*sparse));

    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    const uint256 parent_hash = uint256::ONE;
    const uint256 child_hash = *Assert(uint256::FromHex(
        "0000000000000000000000000000000000000000000000000000000000000002"));

    auto snap = std::make_shared<MWEBHistoricalSnapshot>();
    snap->block_hash = parent_hash;
    snap->height = 2;
    snap->view = sparse;
    cache.Store(snap);

    test::Tx pegin2 = test::Tx::CreatePegIn(1'000'000);
    auto b3 = miner.MineBlock(3, {pegin2}).GetBlock();

    CBlockIndex parent;
    parent.phashBlock = &parent_hash;
    parent.nHeight = 2;
    parent.mweb_header = sparse->GetBestHeader();

    CBlockIndex child;
    child.phashBlock = &child_hash;
    child.nHeight = 3;
    child.pprev = &parent;
    child.mweb_header = b3->GetHeader();

    CBlock cblock;
    cblock.mweb_block = MWEB::Block(b3);

    ResetFreezePathStatsForTest();
    {
        LOCK(cs_main);
        parent.nStatus |= BLOCK_HAVE_MWEB;
        child.nStatus |= BLOCK_HAVE_MWEB;
        cache.Publish(&child, cblock);
    }
    const auto st = GetFreezePathStatsForTest();
    BOOST_CHECK_EQUAL(st.dense_attempts, 0);
    BOOST_CHECK_GE(st.sparse_direct, 1);
    BOOST_CHECK_EQUAL(st.dense_fallback_to_sparse, 0);
}

BOOST_AUTO_TEST_SUITE_END()
