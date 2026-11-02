// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_historical_cache.h>
#include <node/mweb_p2p_messages.h>
#include <node/mweb_serve.h>
#include <node/mweb_serve_coordinator.h>
#include <node/mweb_serve_scheduling.h>
#include <node/mweb_serve_step_budget.h>
#include <node/mweb_serve_types.h>
#include <mw/models/tx/utxo.h>
#include <mw/node/coins_view_materialize.h>

#include <chainparams.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <merkleblock.h>
#include <mweb/mweb_node.h>
#include <net.h>
#include <netaddress.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <streams.h>
#include <sync.h>
#include <test/util/common.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <node/miner.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/models/block/header.h>

#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

#include <atomic>
#include <algorithm>
#include <deque>
#include <condition_variable>
#include <future>
#include <memory>
#include <optional>
#include <thread>

using node::GetMWEBHistoricalViewCache;
using node::GetMWEBServeCoordinator;
using node::MWEBServeDenyReason;
using node::MWEBServeEngine;
using node::MWEBServeHost;
using node::MWEBServePeerState;
using node::MWEBServePolicy;
using node::MWEBWorkBudget;

namespace {

struct TestEngineContext {
    std::atomic<size_t> global_jobs{0};
    Mutex replay_mutex;
};

struct TestServePeer {
    std::deque<MWEBServeJob> jobs;
    double credits{DEFAULT_MWEB_SERVE_BURST};
    NodeClock::time_point credit_ts{NodeClock::now()};
    int credit_denies{0};
    NodeClock::time_point deny_window_start{NodeClock::now()};
    MWEBServePeerState state;

    TestServePeer() : state{jobs, credits, credit_ts, credit_denies, deny_window_start} {}
};

MWEBHistoricalSnapshotPtr MakeTestSnapshot(const uint256& hash, int height)
{
    auto snap = std::make_shared<MWEBHistoricalSnapshot>();
    snap->block_hash = hash;
    snap->height = height;
    const auto header = std::make_shared<mw::Header>();
    const auto leafset = std::make_shared<MemLeafSet>(mw::DynamicBitSet{});
    const auto pmmr = std::make_shared<MemMMR>();
    snap->view = mw::CoinsViewMemory::Create(header, leafset, pmmr, {});
    return snap;
}

//! Two-leaf view whose leaf payloads are pruned, as in an AssumeUTXO-loaded chainstate.
mw::ICoinsView::Ptr MakePrunedPayloadView(const mw::DynamicBitSet& unspent)
{
    const auto pmmr = std::make_shared<MemMMR>();
    pmmr->PrepareClone(/*num_leaves=*/2, /*num_nodes=*/3);
    for (int i = 0; i < 3; ++i) pmmr->AppendHash(mw::Hash{});
    return mw::CoinsViewMemory::Create(std::make_shared<mw::Header>(), std::make_shared<MemLeafSet>(unspent), pmmr, {});
}

uint256 TestHash(const char* hex)
{
    return *Assert(uint256::FromHex(hex));
}

std::unique_ptr<CNode> MakeTestNode(NodeId id = 1, NetPermissionFlags permissions = NetPermissionFlags::None)
{
    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0x7f000001;
    const CAddress addr{CAddress(CService(CNetAddr(ipv4Addr), Params().GetDefaultPort()), NODE_NETWORK)};
    CNodeOptions opts;
    opts.permission_flags = permissions;
    return std::make_unique<CNode>(id,
                                   /*sock=*/nullptr,
                                   addr,
                                   /*nKeyedNetGroupIn=*/0,
                                   /*nLocalHostNonceIn=*/0,
                                   CAddress(),
                                   /*pszDest=*/"",
                                   ConnectionType::INBOUND,
                                   /*inbound_onion=*/false,
                                   /*network_key=*/0,
                                   std::move(opts));
}

void ExhaustUploadBudget(ConnmanTestMsg& connman, uint64_t limit = 10'000)
{
    connman.SetOutboundTargetForTest(limit, limit);
}

void SetUploadBytesLeft(ConnmanTestMsg& connman, uint64_t bytes_left)
{
    connman.SetOutboundTargetForTest(10'000, 10'000 - bytes_left);
}

MWEBServeEngine MakeTestEngine(ChainstateManager& chainman,
                               ConnmanTestMsg& connman,
                               TestEngineContext& ctx,
                               MWEBServePolicy policy = {},
                               int credit_deny_disconnect = DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT)
{
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeHost host{
        chainman,
        connman,
        policy,
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        credit_deny_disconnect,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    return MWEBServeEngine{std::move(host)};
}

MWEBServeJob MakeHeaderJob(const uint256& hash)
{
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::HEADER;
    job.block_hash = hash;
    return job;
}

constexpr uint32_t MWEB_VB_START_TIME = 1601450001;
constexpr int FIRST_MWEB_HEIGHT = 432;

void MineMwebEraBlock(node::NodeContext& node, const CScript& coinbase_script)
{
    std::shared_ptr<CBlock> block = PrepareBlock(node, {.coinbase_output_script = coinbase_script});
    {
        LOCK(::cs_main);
        const uint32_t mtp = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast();
        block->nTime = std::max({mtp + 1, MWEB_VB_START_TIME});
    }
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    node::RegenerateCommitments(*block, *Assert(node.chainman));
    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }
    ProcessBlock(node, block);
}

void SubmitPeginToMempool(TestChain100Setup& setup, node::NodeContext& node, CAmount pegin_amount = COIN, size_t coinbase_idx = 0)
{
    test::Tx mweb_pegin = test::Tx::CreatePegIn(pegin_amount);
    const auto pegin_coin = mweb_pegin.GetPegInCoin();
    const CScript pegin_script = GetScriptForPegin(pegin_coin.GetKernelID());

    const CTransactionRef& coinbase = setup.m_coinbase_txns.at(coinbase_idx);
    const CAmount fee{10'000};
    const CAmount change = coinbase->vout[0].nValue - pegin_amount - fee;

    const CScript change_script = CScript() << ToByteVector(setup.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction mtx = setup.CreateValidTransaction(
        {coinbase},
        {COutPoint{coinbase->GetHash(), 0}},
        1,
        {setup.coinbaseKey},
        {CTxOut{pegin_amount, pegin_script}, CTxOut{change, change_script}},
        std::nullopt,
        std::nullopt).first;
    mtx.mweb_tx = mw::MutableTx::From(*mweb_pegin.GetTransaction());

    LOCK2(::cs_main, Assert(node.mempool)->cs);
    const MempoolAcceptResult result = Assert(node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        throw std::runtime_error(strprintf("SubmitPeginToMempool failed: %s", result.m_state.ToString()));
    }
}

void MineToMwebChain(TestChain100Setup& setup, node::NodeContext& node, int post_activation_blocks = 4)
{
    const CScript coinbase_script{CScript() << OP_TRUE};
    SetMockTime(std::chrono::seconds{MWEB_VB_START_TIME});

    int height{WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight())};
    while (height < FIRST_MWEB_HEIGHT - 1) {
        MineMwebEraBlock(node, coinbase_script);
        height = WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight());
    }

    SubmitPeginToMempool(setup, node);
    for (int i = 0; i < post_activation_blocks; ++i) {
        MineMwebEraBlock(node, coinbase_script);
    }
}

} // namespace

struct MWEBServeRegtestSetup : public TestChain100Setup {
    MWEBServeRegtestSetup()
        : TestChain100Setup(ChainType::REGTEST, {.extra_args = {"-vbparams=mweb:1601450001:9999999999"}}) {}
};

BOOST_FIXTURE_TEST_SUITE(mweb_serve_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(u01_ring_evict_held_ptr)
{
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();
    std::vector<MWEBHistoricalSnapshotPtr> held;
    for (int i = 0; i < MAX_MWEB_LEAFSET_DEPTH + 3; ++i) {
        const uint256 hash{TestHash(strprintf("%064x", i).c_str())};
        auto snap = MakeTestSnapshot(hash, i);
        held.push_back(snap);
        cache.Store(std::move(snap));
    }
    BOOST_CHECK_EQUAL(cache.GetStats().entries, MAX_MWEB_LEAFSET_DEPTH);
    BOOST_CHECK(held.front()->view != nullptr);
}

BOOST_AUTO_TEST_CASE(u02_lookup_stats)
{
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();
    cache.ResetStats();
    const uint256 hash{TestHash("01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    BOOST_CHECK(!cache.Lookup(hash));
    cache.Store(MakeTestSnapshot(hash, 1));
    BOOST_CHECK(cache.Lookup(hash));
    const auto stats = cache.GetStats();
    BOOST_CHECK_EQUAL(stats.hits, 1);
    BOOST_CHECK_EQUAL(stats.misses, 1);
}

BOOST_AUTO_TEST_CASE(u06_store_overwrite)
{
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();
    const uint256 hash{TestHash("02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")};
    cache.Store(MakeTestSnapshot(hash, 1));
    auto snap2 = MakeTestSnapshot(hash, 2);
    const auto view2 = snap2->view;
    cache.Store(std::move(snap2));
    const auto got = cache.Lookup(hash);
    BOOST_REQUIRE(got);
    BOOST_CHECK_EQUAL(got->height, 2);
    BOOST_CHECK(got->view == view2);
}

BOOST_AUTO_TEST_CASE(u08_coordinator_attach)
{
    auto& coord = GetMWEBServeCoordinator();
    const uint256 hash{TestHash("03cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")};
    auto a = coord.AttachOrCreate(hash);
    auto b = coord.AttachOrCreate(hash);
    BOOST_CHECK(a == b);
    BOOST_CHECK(coord.HasActive(hash));
}

BOOST_AUTO_TEST_CASE(u09_coordinator_cancel)
{
    auto& coord = GetMWEBServeCoordinator();
    const uint256 hash{TestHash("04dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")};
    auto job = coord.AttachOrCreate(hash);
    LOCK(cs_main);
    coord.CancelNotOnActiveChain(*Assert(m_node.chainman));
    BOOST_CHECK(job->cancelled);
    BOOST_CHECK(job->failed);
}

// PruneCompleted must drop finished coordinator entries so the map cannot grow
// without bound across completed/cancelled/failed jobs.
BOOST_AUTO_TEST_CASE(coordinator_prune_completed_bounds_map)
{
    auto& coord = GetMWEBServeCoordinator();
    // Drain any leftovers from earlier cases in this suite.
    coord.PruneCompleted();
    const size_t baseline{coord.ActiveCount()};

    std::vector<std::shared_ptr<node::MWEBServeCoordinatorJob>> kept;
    for (int i = 0; i < 32; ++i) {
        const uint256 hash{TestHash(strprintf("f3%062x", i).c_str())};
        auto job = coord.AttachOrCreate(hash);
        if (i % 3 == 0) {
            job->snapshot = MakeTestSnapshot(hash, i);
        } else if (i % 3 == 1) {
            job->failed = true;
        } else {
            job->cancelled = true;
        }
        kept.push_back(job);
    }
    BOOST_CHECK_EQUAL(coord.ActiveCount(), baseline + 32);

    coord.PruneCompleted();
    BOOST_CHECK_EQUAL(coord.ActiveCount(), baseline);

    // In-progress jobs (no snapshot/fail/cancel) must survive prune.
    const uint256 live_hash{TestHash("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};
    auto live = coord.AttachOrCreate(live_hash);
    BOOST_REQUIRE(live);
    BOOST_CHECK(coord.HasActive(live_hash));
    const size_t with_live{coord.ActiveCount()};
    coord.PruneCompleted();
    BOOST_CHECK_EQUAL(coord.ActiveCount(), with_live);
    BOOST_CHECK(coord.HasActive(live_hash));

    live->failed = true;
    coord.PruneCompleted();
    BOOST_CHECK(!coord.HasActive(live_hash));
    BOOST_CHECK_EQUAL(coord.ActiveCount(), baseline);
}

BOOST_AUTO_TEST_CASE(u10_materialize_chunk_budget)
{
    const auto header = std::make_shared<mw::Header>();
    const auto leafset = std::make_shared<MemLeafSet>(mw::DynamicBitSet{});
    const auto pmmr = std::make_shared<MemMMR>();
    auto source = mw::CoinsViewMemory::Create(header, leafset, pmmr, {});
    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, false);
    mw::MaterializeBudget tiny_budget{1, 8};
    mw::CoinsViewMemory::Ptr out;
    size_t steps{0};
    while (!mw::MaterializeStep(progress, tiny_budget, out) && steps < 10000) {
        ++steps;
    }
    BOOST_CHECK(steps >= 1);
    BOOST_CHECK(out != nullptr);
}

BOOST_AUTO_TEST_CASE(u11_work_budget_replay)
{
    MWEBWorkBudget budget{1024, 8};
    BOOST_CHECK(budget.ConsumeReplayBlock());
    BOOST_CHECK(!budget.ConsumeReplayBlock());
}

BOOST_AUTO_TEST_CASE(u14_credit_costs)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    MWEBServeJob utxos;
    utxos.type = MWEBServeJob::Type::UTXOS;
    utxos.num_requested = 100;
    BOOST_CHECK_EQUAL(engine.CreditCost(utxos), 100.0);

    MWEBServeJob leafset;
    leafset.type = MWEBServeJob::Type::LEAFSET;
    // Hit-path / explicit hints: floor 100, then bytes/1024.
    BOOST_CHECK_EQUAL(engine.CreditCost(leafset, 0), 100.0);
    BOOST_CHECK_EQUAL(engine.CreditCost(leafset, 2048), 100.0);
    BOOST_CHECK_EQUAL(engine.CreditCost(leafset, 204800), 200.0);
    // Miss-path header estimate (num_txos+7)/8 must scale above the floor for large sets.
    const size_t miss_hint_small{(1000 + 7) / 8};
    const size_t miss_hint_large{(2'000'000 + 7) / 8};
    BOOST_CHECK_EQUAL(engine.CreditCost(leafset, miss_hint_small), 100.0);
    BOOST_CHECK(engine.CreditCost(leafset, miss_hint_large) > 100.0);
    BOOST_CHECK(engine.CreditCost(leafset, miss_hint_large) >
                engine.CreditCost(leafset, miss_hint_small));

    MWEBServeJob header;
    header.type = MWEBServeJob::Type::HEADER;
    BOOST_CHECK_EQUAL(engine.CreditCost(header), MWEB_SERVE_HEADER_CREDIT_COST);
    BOOST_CHECK_EQUAL(engine.CreditCost(header, 50'000),
                      std::max(MWEB_SERVE_HEADER_CREDIT_COST, 50'000.0 / 1024.0));
    BOOST_CHECK(engine.CreditCost(header, 2'000'000) > engine.CreditCost(header, 50'000));
}

BOOST_AUTO_TEST_CASE(u15_global_job_cap)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    ctx.global_jobs = MAX_MWEB_SERVE_JOBS_GLOBAL;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const uint256 hash{TestHash("15aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    BOOST_CHECK(!engine.TryEnqueue(*node, peer.state, MakeHeaderJob(hash), 1.0));
}

BOOST_AUTO_TEST_CASE(u16_per_peer_job_cap)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    for (size_t i = 0; i < MAX_MWEB_SERVE_JOBS_PER_PEER; ++i) {
        const uint256 hash{TestHash(strprintf("16%062x", i).c_str())};
        BOOST_CHECK(engine.TryEnqueue(*node, peer.state, MakeHeaderJob(hash), 1.0));
    }
    const uint256 overflow{TestHash("16bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")};
    BOOST_CHECK(!engine.TryEnqueue(*node, peer.state, MakeHeaderJob(overflow), 1.0));
}

BOOST_AUTO_TEST_CASE(u15_global_cap_tracks_enqueued_jobs_and_drain)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    std::vector<std::unique_ptr<TestServePeer>> peers;
    std::vector<std::unique_ptr<CNode>> nodes;
    for (size_t jobs = 0; jobs < MAX_MWEB_SERVE_JOBS_GLOBAL;) {
        peers.push_back(std::make_unique<TestServePeer>());
        nodes.push_back(MakeTestNode(peers.size()));
        for (size_t j = 0; j < MAX_MWEB_SERVE_JOBS_PER_PEER && jobs < MAX_MWEB_SERVE_JOBS_GLOBAL; ++j, ++jobs) {
            const auto hash = TestHash(strprintf("%064x", jobs + 1).c_str());
            BOOST_REQUIRE(engine.TryEnqueue(*nodes.back(), peers.back()->state, MakeHeaderJob(hash), 1.0));
        }
    }
    BOOST_REQUIRE_EQUAL(ctx.global_jobs.load(), MAX_MWEB_SERVE_JOBS_GLOBAL);
    TestServePeer overflow;
    auto extra_node = MakeTestNode(peers.size() + 1);
    const auto extra_hash = TestHash(strprintf("%064x", MAX_MWEB_SERVE_JOBS_GLOBAL + 1).c_str());
    BOOST_CHECK(!engine.TryEnqueue(*extra_node, overflow.state, MakeHeaderJob(extra_hash), 1.0));
    BOOST_CHECK(overflow.jobs.empty());
    const size_t released = peers.front()->jobs.size();
    engine.ClearJobs(peers.front()->state);
    BOOST_CHECK_EQUAL(ctx.global_jobs.load(), MAX_MWEB_SERVE_JOBS_GLOBAL - released);
    BOOST_REQUIRE(engine.TryEnqueue(*extra_node, overflow.state, MakeHeaderJob(extra_hash), 1.0));
    for (auto& peer : peers) engine.ClearJobs(peer->state);
    engine.ClearJobs(overflow.state);
    BOOST_CHECK_EQUAL(ctx.global_jobs.load(), 0u);
}

BOOST_AUTO_TEST_CASE(u15_u16_job_cap_constants)
{
    BOOST_CHECK(MAX_MWEB_SERVE_JOBS_PER_PEER > 0);
    BOOST_CHECK(MAX_MWEB_SERVE_JOBS_GLOBAL >= MAX_MWEB_SERVE_JOBS_PER_PEER);
    BOOST_CHECK(DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT >= 10);
}

BOOST_AUTO_TEST_CASE(u23_can_serve_policy_off)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    MWEBServePolicy off_policy;
    off_policy.mweb_serve = MwebServeMode::OFF;
    auto engine_off = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, off_policy);
    BOOST_CHECK(!engine_off.CanServeLightClient());
}

BOOST_AUTO_TEST_CASE(u23_can_serve_matrix)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;

    MWEBServePolicy blocksonly_policy;
    blocksonly_policy.ignore_incoming_txs = true;
    blocksonly_policy.mweb_serve_in_blocksonly = false;
    auto blocksonly_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, blocksonly_policy);
    BOOST_CHECK(!blocksonly_engine.CanServeLightClient());

    MWEBServePolicy blocksonly_override;
    blocksonly_override.ignore_incoming_txs = true;
    blocksonly_override.mweb_serve_in_blocksonly = true;
    auto override_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, blocksonly_override);
    BOOST_CHECK(override_engine.CanServeLightClient());

    ExhaustUploadBudget(connman);
    MWEBServePolicy auto_policy;
    auto_policy.mweb_serve = MwebServeMode::AUTO;
    auto auto_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, auto_policy);
    BOOST_CHECK(!auto_engine.CanServeLightClient());

    MWEBServePolicy force_policy;
    force_policy.mweb_serve = MwebServeMode::FORCE;
    auto force_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, force_policy);
    BOOST_CHECK(force_engine.CanServeLightClient());
    BOOST_CHECK(force_engine.CanServeLightClientReason() == MWEBServeDenyReason::None);
    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u12_credit_deny_disconnect_threshold)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, {}, /*credit_deny_disconnect=*/10);
    auto node = MakeTestNode();
    TestServePeer peer;
    peer.credits = 0.0;
    const uint256 hash{TestHash("12aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    for (int i = 0; i < 9; ++i) {
        BOOST_CHECK(!engine.TryEnqueue(*node, peer.state, MakeHeaderJob(hash), 100.0));
        BOOST_CHECK(!node->fDisconnect);
    }
    BOOST_CHECK(!engine.TryEnqueue(*node, peer.state, MakeHeaderJob(hash), 100.0));
    BOOST_CHECK(node->fDisconnect);
}

BOOST_AUTO_TEST_CASE(u13_credit_deny_no_deduction)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    peer.credits = 5.0;
    const uint256 hash{TestHash("13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    BOOST_CHECK(!engine.TryEnqueue(*node, peer.state, MakeHeaderJob(hash), 100.0));
    BOOST_CHECK(peer.credits >= 5.0);
    BOOST_CHECK(peer.credits < 5.1);
}

BOOST_AUTO_TEST_CASE(u18_eof_start_index_disconnect)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const uint256 hash{TestHash("18aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = hash;
    job.start_index = 99;
    job.num_requested = 1;
    job.snapshot = MakeTestSnapshot(hash, 1);
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(node->fDisconnect);
}

BOOST_AUTO_TEST_CASE(utxos_start_index_range_checked)
{
    for (const uint64_t start_index : {uint64_t{MAX_SIZE}, uint64_t{MAX_SIZE} + 1}) {
        DataStream stream;
        stream << uint256::ONE;
        WriteCompactSize(stream, start_index);
        stream << uint16_t{1} << uint8_t{0};
        GetMWEBUTXOsMsg msg;
        if (start_index > MAX_SIZE) {
            BOOST_CHECK_EXCEPTION(stream >> msg, std::ios_base::failure, HasReason("ReadCompactSize(): size too large"));
            continue;
        }
        stream >> msg;
        BOOST_CHECK_EQUAL(msg.start_index, start_index);
    }
}

BOOST_AUTO_TEST_CASE(u19_leafset_upload_exhaustion_disconnect)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    ExhaustUploadBudget(connman);
    auto node = MakeTestNode();
    TestServePeer peer;
    const uint256 hash{TestHash("19aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::LEAFSET;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = hash;
    job.snapshot = MakeTestSnapshot(hash, 1);
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(node->fDisconnect);
    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u20_utxo_upload_exhaustion_disconnect)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    ExhaustUploadBudget(connman);
    auto node = MakeTestNode();
    TestServePeer peer;
    const uint256 hash{TestHash("20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = hash;
    job.start_index = 0;
    job.num_requested = 1;
    job.snapshot = MakeTestSnapshot(hash, 1);
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(node->fDisconnect);
    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u21_inject_bad_cache_no_ban)
{
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const uint256 hash{TestHash("21aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = hash;
    job.start_index = 0;
    job.num_requested = 1;
    job.snapshot = MakeTestSnapshot(hash, 1);
    peer.jobs.push_back(std::move(job));
    g_mweb_serve_inject_bad_cache = true;
    engine.ProcessOneStep(*node, peer.state);
    g_mweb_serve_inject_bad_cache = false;
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK(peer.jobs.empty());
}

BOOST_AUTO_TEST_CASE(u08_coordinator_multi_attach)
{
    auto& coord = GetMWEBServeCoordinator();
    const uint256 hash{TestHash("08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
    std::vector<std::shared_ptr<node::MWEBServeCoordinatorJob>> jobs;
    jobs.reserve(4);
    for (int i = 0; i < 4; ++i) {
        jobs.push_back(coord.AttachOrCreate(hash));
    }
    for (size_t i = 1; i < jobs.size(); ++i) {
        BOOST_CHECK(jobs[i] == jobs[0]);
    }
}

BOOST_AUTO_TEST_CASE(u11_assumeutxo_materialize_chunk_budget)
{
    const auto header = std::make_shared<mw::Header>();
    const auto leafset = std::make_shared<MemLeafSet>(mw::DynamicBitSet{});
    const auto pmmr = std::make_shared<MemMMR>();
    auto source = mw::CoinsViewMemory::Create(header, leafset, pmmr, {});
    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, true);
    mw::MaterializeBudget tiny_budget{1, 8};
    mw::CoinsViewMemory::Ptr out;
    size_t steps{0};
    while (!mw::MaterializeStep(progress, tiny_budget, out) && steps < 10000) {
        ++steps;
    }
    BOOST_CHECK(steps >= 1);
    BOOST_CHECK(out != nullptr);
}

BOOST_AUTO_TEST_CASE(materialize_falls_back_to_sparse_for_pruned_spent_leaves)
{
    const auto source{MakePrunedPayloadView(mw::DynamicBitSet{2})};
    mw::CoinsViewMemory::Ptr out;

    mw::MaterializeProgress dense;
    mw::MaterializeProgressBegin(dense, *source, /*assumeutxo_snapshot=*/false);
    BOOST_CHECK_THROW([&] { while (!mw::MaterializeStep(dense, mw::MaterializeBudget{}, out)) {} }(), std::exception);

    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, /*assumeutxo_snapshot=*/false);
    for (int steps = 0; steps < 100 && !mw::MaterializeStepWithSparseFallback(progress, mw::MaterializeBudget{}, out); ++steps) {}
    BOOST_REQUIRE(out);
    BOOST_CHECK(progress.assumeutxo_snapshot);
    BOOST_CHECK_EQUAL(out->GetOutputPMMR()->GetNumLeaves(), 2U);
}

BOOST_AUTO_TEST_CASE(materialize_budget_counts_skipped_spent_leaves)
{
    const auto source{MakePrunedPayloadView(mw::DynamicBitSet{2})};
    mw::CoinsViewMemory::Ptr out;
    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, /*assumeutxo_snapshot=*/true);
    for (int steps = 0; steps < 100 && progress.phase != mw::MaterializeProgress::Phase::PMMR_LEAVES; ++steps) {
        BOOST_REQUIRE(!mw::MaterializeStep(progress, mw::MaterializeBudget{}, out));
    }
    BOOST_REQUIRE(progress.phase == mw::MaterializeProgress::Phase::PMMR_LEAVES);

    // Skipping a spent leaf is work done under the caller's lock, so it uses the step's budget.
    const mw::MaterializeBudget one_leaf{/*max_leaf_ops=*/1, /*max_bytes=*/1 << 20};
    BOOST_REQUIRE(!mw::MaterializeStep(progress, one_leaf, out));
    BOOST_CHECK(progress.phase == mw::MaterializeProgress::Phase::PMMR_LEAVES);
    BOOST_CHECK_EQUAL(progress.cursor, 1U);
}

BOOST_AUTO_TEST_CASE(materialize_sparse_fallback_fails_on_missing_unspent_leaf)
{
    mw::DynamicBitSet unspent{2};
    unspent.set(0);
    const auto source{MakePrunedPayloadView(unspent)};
    mw::CoinsViewMemory::Ptr out;
    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, /*assumeutxo_snapshot=*/false);
    BOOST_CHECK_THROW([&] {
        for (int steps = 0; steps < 100 && !mw::MaterializeStepWithSparseFallback(progress, mw::MaterializeBudget{}, out); ++steps) {}
    }(), std::exception);
    BOOST_CHECK(!out);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_serve_tests_chain, MWEBServeRegtestSetup)

BOOST_AUTO_TEST_CASE(u24_replay_mutex)
{
    MineToMwebChain(*this, m_node, 4);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();
    auto& chainman = *Assert(m_node.chainman);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(chainman, connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    CBlockIndex* tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
    const uint256 historical = tip->pprev->pprev->GetBlockHash();
    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, historical});
    BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1u);
    {
        // Contend from a different thread: recursively try-locking a nonrecursive
        // mutex on the test thread does not exercise engine replay protection.
        std::promise<void> locked;
        std::condition_variable_any wake;
        std::mutex wait_mutex;
        std::jthread holder{[&](std::stop_token stop) {
            LOCK(ctx.replay_mutex);
            locked.set_value();
            std::unique_lock wait_lock{wait_mutex};
            wake.wait(wait_lock, stop, [] { return false; });
        }};
        locked.get_future().wait();
        for (int i = 0; i < 3; ++i) {
            engine.ProcessOneStep(*node, peer.state);
            BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1u);
            const auto& coord = peer.jobs.front().coordinator;
            BOOST_REQUIRE(coord);
            BOOST_CHECK(coord->phase == MWEBServeJob::Phase::REPLAY_BACK);
            BOOST_CHECK(coord->replay_tip == tip);
            BOOST_CHECK(!cache.Lookup(historical));
        }
    }
    for (int i = 0; i < 500 && !peer.jobs.empty(); ++i) engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK(cache.Lookup(historical));
}

// download@ may bypass only UploadLimited — never ServeOff/BlocksOnly merely because
// the outbound target happens to also be exhausted. Requires non-IBD (TryEnqueue
// short-circuits all deny paths during IBD).
BOOST_AUTO_TEST_CASE(download_bypass_only_on_upload_limit)
{
    MineToMwebChain(*this, m_node, 1);
    BOOST_REQUIRE(!Assert(m_node.chainman)->IsInitialBlockDownload());

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    ExhaustUploadBudget(connman);
    auto download_node = MakeTestNode(/*id=*/1, NetPermissionFlags::Download);
    TestServePeer peer;
    const uint256 hash{TestHash("d1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};

    // Upload-limit only + Download → allow.
    MWEBServePolicy auto_policy;
    auto_policy.mweb_serve = MwebServeMode::AUTO;
    auto auto_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, auto_policy);
    BOOST_CHECK(auto_engine.CanServeLightClientReason() == MWEBServeDenyReason::UploadLimited);
    BOOST_CHECK(auto_engine.TryEnqueue(*download_node, peer.state, MakeHeaderJob(hash), 1.0));
    BOOST_CHECK_EQUAL(peer.state.m_mweb_serve_jobs.size(), 1U);
    auto_engine.ClearJobs(peer.state);

    // ServeOff + upload exhausted + Download → still refuse.
    MWEBServePolicy off_policy;
    off_policy.mweb_serve = MwebServeMode::OFF;
    auto off_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, off_policy);
    BOOST_CHECK(off_engine.CanServeLightClientReason() == MWEBServeDenyReason::ServeOff);
    BOOST_CHECK(!off_engine.TryEnqueue(*download_node, peer.state, MakeHeaderJob(hash), 1.0));
    BOOST_CHECK(peer.state.m_mweb_serve_jobs.empty());

    // BlocksOnly + upload exhausted + Download → refuse.
    MWEBServePolicy blocksonly_policy;
    blocksonly_policy.ignore_incoming_txs = true;
    blocksonly_policy.mweb_serve_in_blocksonly = false;
    auto blocksonly_engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx, blocksonly_policy);
    BOOST_CHECK(blocksonly_engine.CanServeLightClientReason() == MWEBServeDenyReason::BlocksOnly);
    BOOST_CHECK(!blocksonly_engine.TryEnqueue(*download_node, peer.state, MakeHeaderJob(hash), 1.0));
    BOOST_CHECK(peer.state.m_mweb_serve_jobs.empty());

    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u03_publish_incremental_from_parent)
{
    MineToMwebChain(*this, m_node, 1);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    CBlockIndex* pindex_parent{nullptr};
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        pindex_parent = chainman.ActiveChain().Tip();
        auto parent_snap = std::make_shared<MWEBHistoricalSnapshot>();
        parent_snap->block_hash = pindex_parent->GetBlockHash();
        parent_snap->height = pindex_parent->nHeight;
        parent_snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        cache.Store(std::move(parent_snap));
    }

    CBlockIndex* pindex_child{nullptr};
    CBlock child_block;
    {
        const CScript coinbase_script{CScript() << OP_TRUE};
        MineMwebEraBlock(m_node, coinbase_script);
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        pindex_child = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(chainman.m_blockman.ReadBlock(child_block, *pindex_child));
        cache.Publish(pindex_child, child_block);
    }
    const auto got = cache.Lookup(pindex_child->GetBlockHash());
    BOOST_REQUIRE(got);
    BOOST_CHECK_EQUAL(got->height, pindex_child->nHeight);
    BOOST_CHECK(got->view != nullptr);
}

BOOST_AUTO_TEST_CASE(u04_publish_without_parent_no_insert)
{
    MineToMwebChain(*this, m_node, 2);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    CBlockIndex* pindex{nullptr};
    CBlock block;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        pindex = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block, *pindex));
        cache.Publish(pindex, block);
    }
    BOOST_CHECK(!cache.Lookup(pindex->GetBlockHash()));
}

// LIP-0006: the merkle block, the HogEx and the MWEB header, with no presence byte.
BOOST_AUTO_TEST_CASE(mwebheader_wire_layout)
{
    MineToMwebChain(*this, m_node, 2);
    CBlock block;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block, *chainman.ActiveChain().Tip()));
    }
    const CTransactionRef hogex{block.GetHogEx()};
    BOOST_REQUIRE(hogex && block.mweb_block.GetMWEBHeader());

    DataStream expected;
    expected << CMerkleBlock{block, std::set<Txid>{hogex->GetHash()}} << TX_WITH_WITNESS(hogex) << *block.mweb_block.GetMWEBHeader();
    DataStream written;
    written << CMerkleBlockWithMWEB{block};
    BOOST_CHECK_EQUAL(HexStr(written), HexStr(expected));

    CMerkleBlockWithMWEB read;
    written >> read;
    BOOST_CHECK(written.empty());
    DataStream rewritten;
    rewritten << read;
    BOOST_CHECK_EQUAL(HexStr(rewritten), HexStr(expected));
}

BOOST_AUTO_TEST_CASE(u05_prune_to_active_chain)
{
    MineToMwebChain(*this, m_node, 4);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    MWEBHistoricalSnapshotPtr held;
    uint256 stale_hash;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        stale_hash = tip->GetBlockHash();
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = stale_hash;
        snap->height = tip->nHeight;
        snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        held = snap;
        cache.Store(std::move(snap));
        BOOST_REQUIRE(cache.Lookup(stale_hash));
    }

    {
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
        BlockValidationState state;
        // InvalidateBlock asserts cs_main is not held (it takes/releases it internally).
        BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, tip));
    }
    {
        const CScript coinbase_script{CScript() << OP_TRUE};
        MineMwebEraBlock(m_node, coinbase_script);
        LOCK(::cs_main);
        cache.PruneToActiveChain(*Assert(m_node.chainman));
        BOOST_CHECK(!cache.Lookup(stale_hash));
        BOOST_CHECK(held->view != nullptr);
    }
}

BOOST_AUTO_TEST_CASE(u07_verify_roots_failure_no_insert)
{
    MineToMwebChain(*this, m_node, 1);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    CBlockIndex* pindex_parent{nullptr};
    MWEBHistoricalSnapshotPtr parent_frozen;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        pindex_parent = chainman.ActiveChain().Tip();
        auto parent_snap = std::make_shared<MWEBHistoricalSnapshot>();
        parent_snap->block_hash = pindex_parent->GetBlockHash();
        parent_snap->height = pindex_parent->nHeight;
        parent_snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        cache.Store(parent_snap);
        parent_frozen = cache.Lookup(pindex_parent->GetBlockHash());
        BOOST_REQUIRE(parent_frozen);
    }

    CBlockIndex* pindex_child{nullptr};
    CBlock child_block;
    {
        const CScript coinbase_script{CScript() << OP_TRUE};
        MineMwebEraBlock(m_node, coinbase_script);
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        pindex_child = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(chainman.m_blockman.ReadBlock(child_block, *pindex_child));
    }

    // ConnectTip may window-warm the new tip into the cache (frozen tip seed).
    // Clear and re-seed the frozen parent so this case isolates Publish()'s verify-fail path.
    cache.ClearForTest();
    cache.Store(parent_frozen);

    mw::Header::CPtr saved_header;
    {
        LOCK(::cs_main);
        const auto& good = pindex_child->mweb_header;
        BOOST_REQUIRE(good);
        saved_header = good;
        const std::vector<uint8_t> bad_bytes(32, 0xff);
        auto bad = std::make_shared<mw::Header>(
            good->GetHeight(),
            mw::Hash(bad_bytes),
            good->GetKernelRoot(),
            good->GetLeafsetRoot(),
            good->GetKernelOffset(),
            good->GetStealthOffset(),
            good->GetNumTXOs(),
            good->GetNumKernels());
        pindex_child->mweb_header = bad;
        cache.Publish(pindex_child, child_block);
        pindex_child->mweb_header = saved_header;
    }
    BOOST_CHECK(!cache.Lookup(pindex_child->GetBlockHash()));
}

BOOST_AUTO_TEST_CASE(u17_empty_segment_no_ban)
{
    // Defensive BuildAndSend path: a job already in BUILD_SEND with num_requested==0
    // must not ban the peer (empty assemble). Enqueue-time rejection of zero is u19
    // (zero-request enqueue guard); this case does not go through EnqueueUTXOs.
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [&](CNode&, MWEBUTXOsMsg) { sent = true; },
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    MWEBHistoricalSnapshotPtr snap;
    uint256 tip_hash;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        auto mutable_snap = std::make_shared<MWEBHistoricalSnapshot>();
        mutable_snap->block_hash = tip_hash;
        mutable_snap->height = tip->nHeight;
        mutable_snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        snap = mutable_snap;
    }

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = tip_hash;
    job.start_index = 0;
    job.num_requested = 0;
    job.snapshot = std::move(snap);
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK(!sent);
}

BOOST_AUTO_TEST_CASE(u19_zero_num_requested_rejected)
{
    // num_requested==0 must not enqueue (zero credit cost / queue bypass).
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};
    const size_t global_before{ctx.global_jobs.load()};

    GetMWEBUTXOsMsg msg;
    {
        LOCK(::cs_main);
        msg.block_hash = Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash();
    }
    msg.start_index = 0;
    msg.num_requested = 0;
    msg.output_format = NetUTXO::HASH_ONLY;

    engine.EnqueueUTXOs(*node, peer.state, msg);

    BOOST_CHECK(node->fDisconnect);
    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK_EQUAL(ctx.global_jobs.load(), global_before);
    BOOST_CHECK_EQUAL(peer.credits, credits_before);
}

BOOST_AUTO_TEST_CASE(u20_start_index_at_num_txos_rejected)
{
    // start_index == GetNumTXOs() is impossible; reject at enqueue.
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};
    const size_t global_before{ctx.global_jobs.load()};

    GetMWEBUTXOsMsg msg;
    uint64_t num_txos{0};
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip->mweb_header);
        num_txos = tip->mweb_header->GetNumTXOs();
        msg.block_hash = tip->GetBlockHash();
    }
    BOOST_REQUIRE(num_txos >= 1);
    msg.start_index = num_txos;
    msg.num_requested = 1;
    msg.output_format = NetUTXO::HASH_ONLY;

    engine.EnqueueUTXOs(*node, peer.state, msg);

    BOOST_CHECK(node->fDisconnect);
    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!GetMWEBServeCoordinator().HasActive(msg.block_hash));
    BOOST_CHECK_EQUAL(ctx.global_jobs.load(), global_before);
    BOOST_CHECK_EQUAL(peer.credits, credits_before);
}

BOOST_AUTO_TEST_CASE(u21_start_index_far_past_rejected)
{
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;

    GetMWEBUTXOsMsg msg;
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip->mweb_header);
        msg.block_hash = tip->GetBlockHash();
        msg.start_index = tip->mweb_header->GetNumTXOs() + 1'000'000;
    }
    msg.num_requested = 1;
    msg.output_format = NetUTXO::HASH_ONLY;

    engine.EnqueueUTXOs(*node, peer.state, msg);

    BOOST_CHECK(node->fDisconnect);
    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!GetMWEBServeCoordinator().HasActive(msg.block_hash));
}

BOOST_AUTO_TEST_CASE(u25_start_index_last_mmr_slot_enqueued)
{
    // start_index == GetNumTXOs()-1 is within the cheap bound and may enqueue
    // (exact unspent EOF still handled later in BuildAndSend / u18).
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;

    GetMWEBUTXOsMsg msg;
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip->mweb_header);
        BOOST_REQUIRE(tip->mweb_header->GetNumTXOs() >= 1);
        msg.block_hash = tip->GetBlockHash();
        msg.start_index = tip->mweb_header->GetNumTXOs() - 1;
    }
    msg.num_requested = 1;
    msg.output_format = NetUTXO::HASH_ONLY;

    engine.EnqueueUTXOs(*node, peer.state, msg);

    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_EQUAL(peer.jobs.front().start_index, msg.start_index);
}

BOOST_AUTO_TEST_CASE(u26_leafset_miss_charges_header_estimate)
{
    // Cache miss must charge max(100, (GetNumTXOs()+7)/8/1024), not a zero hint.
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    uint256 tip_hash;
    size_t miss_hint{0};
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip->mweb_header);
        tip_hash = tip->GetBlockHash();
        miss_hint = (tip->mweb_header->GetNumTXOs() + 7) / 8;
    }
    BOOST_CHECK(!cache.Lookup(tip_hash));

    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::LEAFSET;
    const double expected{engine.CreditCost(cost_job, miss_hint) + MWEB_SERVE_MATERIALIZE_SURCHARGE};

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip_hash});

    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
    BOOST_CHECK(expected >= 100.0 + MWEB_SERVE_MATERIALIZE_SURCHARGE);
}

BOOST_AUTO_TEST_CASE(u28_leafset_hit_uses_header_hint)
{
    // Cache-hit admission pricing uses GetNumTXOs bit-pack hint, not ToDynamicBitSet.
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    uint256 tip_hash;
    size_t hint_bytes{0};
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        BOOST_REQUIRE(tip->mweb_header);
        hint_bytes = (tip->mweb_header->GetNumTXOs() + 7) / 8;
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = tip_hash;
        snap->height = tip->nHeight;
        snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        cache.Store(std::move(snap));
    }

    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::LEAFSET;
    const double expected{engine.CreditCost(cost_job, hint_bytes)};

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip_hash});

    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
}

BOOST_AUTO_TEST_CASE(u29_header_credit_scales_with_size)
{
    // EnqueueHeader charges max(floor, size_proxy/1024), not a flat 10.
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    uint256 tip_hash;
    size_t expected_hint{4096};
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        expected_hint += static_cast<size_t>(tip->nTx) * 300;
        if (tip->mweb_header) {
            expected_hint += tip->mweb_header->GetNumTXOs() * 64;
        }
    }
    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::HEADER;
    const double expected{engine.CreditCost(cost_job, expected_hint)};
    BOOST_CHECK(expected >= MWEB_SERVE_HEADER_CREDIT_COST);

    engine.EnqueueHeader(*node, peer.state, CInv{MSG_MWEB_HEADER, tip_hash});

    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
}

BOOST_AUTO_TEST_CASE(enqueue_credit_hints_above_pricing_floors)
{
    MineToMwebChain(*this, m_node, 3);
    auto& chainman = *Assert(m_node.chainman);
    auto& cache = GetMWEBHistoricalViewCache();
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(chainman, connman, ctx);
    auto node = MakeTestNode();
    for (int mode = 0; mode < 3; ++mode) {
        cache.ClearForTest();
        CBlockIndex* tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        const auto original = tip->mweb_header;
        // This bounded admission-only fixture supplies a large header hint.
        // Never replay/serve it as a real million-output chainstate.
        struct RestoreHeader {
            CBlockIndex* index;
            mw::Header::CPtr header;
            ~RestoreHeader() { LOCK(::cs_main); index->mweb_header = header; }
        } restore{tip, original};
        const uint64_t num_outputs = mode == 2 ? 2'000 : 1'000'000;
        {
            LOCK(::cs_main);
            tip->mweb_header = std::make_shared<mw::Header>(
                original->GetHeight(), original->GetOutputRoot(), original->GetKernelRoot(),
                original->GetLeafsetRoot(), original->GetKernelOffset(), original->GetStealthOffset(),
                num_outputs, original->GetNumKernels());
            if (mode == 1) {
                auto snap = std::make_shared<MWEBHistoricalSnapshot>();
                snap->block_hash = tip->GetBlockHash();
                snap->height = tip->nHeight;
                snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
                cache.Store(std::move(snap));
            }
        }
        TestServePeer peer;
        const double before = peer.credits;
        double expected;
        if (mode == 2) {
            expected = (4096.0 + tip->nTx * 300.0 + num_outputs * 64.0) / 1024.0;
            BOOST_REQUIRE_GT(expected, MWEB_SERVE_HEADER_CREDIT_COST);
            engine.EnqueueHeader(*node, peer.state, CInv{MSG_MWEB_HEADER, tip->GetBlockHash()});
        } else {
            expected = ((num_outputs + 7) / 8) / 1024.0;
            BOOST_REQUIRE_GT(expected, 100.0);
            if (mode == 0) expected += MWEB_SERVE_MATERIALIZE_SURCHARGE;
            engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip->GetBlockHash()});
        }
        BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1u);
        BOOST_CHECK_CLOSE(peer.credits, before - expected, 1e-6);
        engine.ClearJobs(peer.state);
    }
    cache.ClearForTest();
}

BOOST_AUTO_TEST_CASE(u46_header_pruned_node_depth_limit)
{
    // Headers have no leafset depth limit. A pruned node applies its block-serving
    // limit: ordinary peers asking below it are disconnected, NoBan peers are served.
    MineToMwebChain(*this, m_node, 4);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
        /*network_limited_serve_depth=*/1,
    };
    const ServiceFlags services_before{connman.GetLocalServices()};
    connman.AddLocalServices(ServiceFlags(NODE_MWEB | NODE_NETWORK_LIMITED));
    connman.RemoveLocalServices(NODE_NETWORK);
    MWEBServeEngine engine{std::move(host)};

    uint256 within_hash;
    uint256 below_hash;
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        within_hash = tip->pprev->GetBlockHash();
        below_hash = tip->pprev->pprev->GetBlockHash();
    }

    auto within_node = MakeTestNode(1);
    TestServePeer within_peer;
    engine.EnqueueHeader(*within_node, within_peer.state, CInv{MSG_MWEB_HEADER, within_hash});
    BOOST_CHECK(!within_node->fDisconnect);
    BOOST_CHECK_EQUAL(within_peer.jobs.size(), 1U);

    auto below_node = MakeTestNode(2);
    TestServePeer below_peer;
    engine.EnqueueHeader(*below_node, below_peer.state, CInv{MSG_MWEB_HEADER, below_hash});
    BOOST_CHECK(below_node->fDisconnect);
    BOOST_CHECK(below_peer.jobs.empty());

    auto noban_node = MakeTestNode(3, NetPermissionFlags::NoBan);
    TestServePeer noban_peer;
    engine.EnqueueHeader(*noban_node, noban_peer.state, CInv{MSG_MWEB_HEADER, below_hash});
    BOOST_CHECK(!noban_node->fDisconnect);
    BOOST_CHECK_EQUAL(noban_peer.jobs.size(), 1U);

    // A node that isn't pruned serves the same header to an ordinary peer.
    connman.RemoveLocalServices(ServiceFlags(NODE_NETWORK_LIMITED & ~services_before));
    connman.AddLocalServices(ServiceFlags(NODE_NETWORK | services_before));
    auto full_node_peer = MakeTestNode(4);
    TestServePeer full_peer;
    engine.EnqueueHeader(*full_node_peer, full_peer.state, CInv{MSG_MWEB_HEADER, below_hash});
    BOOST_CHECK(!full_node_peer->fDisconnect);
    BOOST_CHECK_EQUAL(full_peer.jobs.size(), 1U);
    connman.RemoveLocalServices(ServiceFlags(NODE_NETWORK & ~services_before));
}

BOOST_AUTO_TEST_CASE(u30_header_outbound_budget_deny)
{
    MineToMwebChain(*this, m_node, 3);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [](CNode&, MWEBUTXOsMsg) {},
        [&](CNode&, CMerkleBlockWithMWEB) { sent = true; },
    };
    connman.AddLocalServices(NODE_MWEB);
    ExhaustUploadBudget(connman);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    uint256 tip_hash;
    {
        LOCK(::cs_main);
        tip_hash = Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash();
    }
    MWEBServeJob job;
    job.type = MWEBServeJob::Type::HEADER;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = tip_hash;
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(node->fDisconnect);
    BOOST_CHECK(!sent);
    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u31_header_read_failure_fail_closed)
{
    // Missing/unknown hash: no send, no ban (internal fail-closed).
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [](CNode&, MWEBUTXOsMsg) {},
        [&](CNode&, CMerkleBlockWithMWEB) { sent = true; },
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::HEADER;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = TestHash("31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK(!sent);
    BOOST_CHECK(peer.jobs.empty());
}

BOOST_AUTO_TEST_CASE(u22_partial_utxo_page_under_budget)
{
    MineToMwebChain(*this, m_node, 3);
    for (size_t i = 1; i <= 3; ++i) SubmitPeginToMempool(*this, m_node, COIN, i);
    MineMwebEraBlock(m_node, CScript() << OP_TRUE);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    uint16_t sent_count{0};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [](CNode&, MWEBLeafsetMsg) {},
        [&](CNode&, MWEBUTXOsMsg msg) { sent_count = static_cast<uint16_t>(msg.utxos.size()); },
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    MWEBHistoricalSnapshotPtr snap;
    uint256 tip_hash;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        auto mutable_snap = std::make_shared<MWEBHistoricalSnapshot>();
        mutable_snap->block_hash = tip_hash;
        mutable_snap->height = tip->nHeight;
        mutable_snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        snap = mutable_snap;
    }

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.phase = MWEBServeJob::Phase::BUILD_SEND;
    job.block_hash = tip_hash;
    job.start_index = 0;
    job.num_requested = 100;
    job.snapshot = snap;
    peer.jobs.push_back(job);
    engine.ProcessOneStep(*node, peer.state);
    BOOST_REQUIRE_EQUAL(sent_count, 4u); // natural exhaustion with no upload limit
    sent_count = 0;
    SetUploadBytesLeft(connman, 512); // at 256 estimated bytes per output, two fit
    peer.jobs.push_back(std::move(job));
    engine.ProcessOneStep(*node, peer.state);
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK_EQUAL(sent_count, 2u);
    connman.ResetMaxOutboundCycle();
}

BOOST_AUTO_TEST_CASE(u32_replay_undo_path_produces_valid_snapshot)
{
    // Historical leafset via MWEB undo path verifies against target header roots.
    MineToMwebChain(*this, m_node, 5);
    for (size_t i = 1; i <= 3; ++i) {
        SubmitPeginToMempool(*this, m_node, COIN, i);
        MineMwebEraBlock(m_node, CScript() << OP_TRUE);
    }
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    std::optional<MWEBLeafsetMsg> sent_msg;
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [&](CNode&, MWEBLeafsetMsg msg) {
            sent = true;
            sent_msg = std::move(msg);
        },
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    uint256 hist_hash;
    mw::Header::CPtr hist_header;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->pprev && tip->pprev->pprev);
        CBlockIndex* hist = tip->pprev->pprev; // tip-2 → at least one undo step
        BOOST_REQUIRE(hist->mweb_header);
        hist_hash = hist->GetBlockHash();
        hist_header = hist->mweb_header;
        // The undone blocks really add coins; empty successors alone leave
        // these roots unchanged and cannot establish coin-undo sensitivity.
        BOOST_REQUIRE(tip->mweb_header->GetOutputRoot() != hist_header->GetOutputRoot());
        BOOST_REQUIRE(tip->mweb_header->GetLeafsetRoot() != hist_header->GetLeafsetRoot());
    }
    BOOST_CHECK(!cache.Lookup(hist_hash));

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, hist_hash});
    BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1U);

    bool finalized_in_steps{false};
    for (int i = 0; i < 500 && !peer.jobs.empty(); ++i) {
        engine.ProcessOneStep(*node, peer.state);
        if (!peer.jobs.empty() && peer.jobs.front().coordinator &&
            peer.jobs.front().coordinator->materialize_purpose == node::MWEBServeCoordinatorJob::MaterializePurpose::FINALIZE) {
            finalized_in_steps = true;
        }
    }

    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!node->fDisconnect);
    BOOST_REQUIRE(sent);
    BOOST_REQUIRE(sent_msg);
    BOOST_CHECK(sent_msg->block_hash == hist_hash);
    // The replayed view is a live overlay, which a peer request may only copy in budgeted steps.
    BOOST_CHECK(finalized_in_steps);

    const auto snap = cache.Lookup(hist_hash);
    BOOST_REQUIRE(snap);
    BOOST_REQUIRE(snap->view);
    BOOST_CHECK(MWEB::Node::VerifyChainstateRoots(*hist_header, *snap->view));
}

BOOST_AUTO_TEST_CASE(replay_copy_fails_closed_when_tip_moves)
{
    MineToMwebChain(*this, m_node, 5);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [&](CNode&, MWEBLeafsetMsg) { sent = true; },
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    const uint256 hist_hash{WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip()->pprev->pprev->GetBlockHash())};
    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, hist_hash});
    BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1U);

    const auto copying = [&] {
        return !peer.jobs.empty() && peer.jobs.front().coordinator &&
               peer.jobs.front().coordinator->materialize_purpose == node::MWEBServeCoordinatorJob::MaterializePurpose::FINALIZE;
    };
    for (int i = 0; i < 500 && !peer.jobs.empty() && !copying(); ++i) {
        engine.ProcessOneStep(*node, peer.state);
    }
    BOOST_REQUIRE(copying());

    // The copy reads through to the tip, so a new block must end it instead of mixing two states.
    MineMwebEraBlock(m_node, CScript() << OP_TRUE);
    for (int i = 0; i < 500 && !peer.jobs.empty(); ++i) {
        engine.ProcessOneStep(*node, peer.state);
    }

    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!sent);
    BOOST_CHECK(!node->fDisconnect);
    BOOST_CHECK(!cache.Lookup(hist_hash));
}

BOOST_AUTO_TEST_CASE(u33_replay_fails_closed_on_missing_undo_and_bad_fallback)
{
    // Undo miss + unreadable block → coordinator fails; no leafset send.
    MineToMwebChain(*this, m_node, 4);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        DEFAULT_MWEB_SERVE_MATERIAL_BUDGET,
        DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [&](CNode&, MWEBLeafsetMsg) { sent = true; },
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    uint256 hist_hash;
    CBlockIndex* tip_index{nullptr};
    uint32_t saved_status{0};
    {
        LOCK(::cs_main);
        tip_index = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip_index && tip_index->pprev);
        hist_hash = tip_index->pprev->GetBlockHash();
        saved_status = tip_index->nStatus;
        tip_index->nStatus &= ~(BLOCK_HAVE_UNDO | BLOCK_HAVE_DATA);
    }

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, hist_hash});
    BOOST_REQUIRE_EQUAL(peer.jobs.size(), 1U);

    for (int i = 0; i < 100 && !peer.jobs.empty(); ++i) {
        engine.ProcessOneStep(*node, peer.state);
    }

    {
        LOCK(::cs_main);
        tip_index->nStatus = saved_status;
    }

    BOOST_CHECK(peer.jobs.empty());
    BOOST_CHECK(!sent);
    BOOST_CHECK(!cache.Lookup(hist_hash));
    BOOST_CHECK(!node->fDisconnect);
}

BOOST_AUTO_TEST_CASE(u34_leafset_miss_materialize_surcharge)
{
    // Leafset cache miss charges CreditCost(hint) + MATERIALIZE_SURCHARGE.
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    uint256 tip_hash;
    size_t miss_hint{0};
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        miss_hint = (tip->mweb_header->GetNumTXOs() + 7) / 8;
    }
    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::LEAFSET;
    const double base{engine.CreditCost(cost_job, miss_hint)};
    const double expected{base + MWEB_SERVE_MATERIALIZE_SURCHARGE};

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip_hash});
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
    BOOST_CHECK(expected > base);
}

BOOST_AUTO_TEST_CASE(u35_leafset_hit_no_surcharge)
{
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    uint256 tip_hash;
    size_t hint_bytes{0};
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        BOOST_REQUIRE(tip->mweb_header);
        hint_bytes = (tip->mweb_header->GetNumTXOs() + 7) / 8;
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = tip_hash;
        snap->height = tip->nHeight;
        snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        cache.Store(std::move(snap));
    }
    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::LEAFSET;
    const double expected{engine.CreditCost(cost_job, hint_bytes)};

    engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip_hash});
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
}

BOOST_AUTO_TEST_CASE(u36_utxos_miss_adds_surcharge)
{
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;
    const double credits_before{peer.credits};

    GetMWEBUTXOsMsg msg;
    {
        LOCK(::cs_main);
        msg.block_hash = Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash();
    }
    msg.start_index = 0;
    msg.num_requested = 1;
    msg.output_format = NetUTXO::HASH_ONLY;

    MWEBServeJob cost_job;
    cost_job.type = MWEBServeJob::Type::UTXOS;
    cost_job.num_requested = 1;
    const double expected{engine.CreditCost(cost_job) + MWEB_SERVE_MATERIALIZE_SURCHARGE};

    engine.EnqueueUTXOs(*node, peer.state, msg);
    BOOST_CHECK_EQUAL(peer.jobs.size(), 1U);
    BOOST_CHECK_CLOSE(peer.credits, credits_before - expected, 1e-6);
}

BOOST_AUTO_TEST_CASE(u37_materialize_leafset_bytes_single_copy)
{
    // Count the actual capture; buffer lifetime alone cannot detect a second copy.
    MineToMwebChain(*this, m_node, 2);
    mw::ICoinsView::Ptr source;
    {
        LOCK(::cs_main);
        source = Assert(m_node.chainman)->ActiveChainstate().CoinsTip().GetMWEBCacheView();
    }
    BOOST_REQUIRE(source);
    BOOST_REQUIRE(source->GetLeafSet());

    std::atomic<uint64_t> bitset_calls{0};
    struct ResetCounter {
        ~ResetCounter() { mw::g_leafset_todynamicbitset_calls = nullptr; }
    } reset_counter;
    mw::g_leafset_todynamicbitset_calls = &bitset_calls;
    mw::MaterializeProgress progress;
    mw::MaterializeProgressBegin(progress, *source, /*assumeutxo_snapshot=*/false);
    mw::CoinsViewMemory::Ptr out;
    mw::MaterializeBudget tiny{/*max_leaf_ops=*/1, /*max_bytes=*/1};

    BOOST_REQUIRE(!mw::MaterializeStep(progress, tiny, out));
    BOOST_CHECK(progress.phase == mw::MaterializeProgress::Phase::LEAFSET_BYTES);
    BOOST_REQUIRE(!progress.leafset_src_bytes.empty());
    BOOST_CHECK_EQUAL(progress.leafset_src_bytes.size(), progress.leafset_total_bytes);
    const size_t src_bytes{progress.leafset_src_bytes.size()};

    // Drain LEAFSET_BYTES under tiny budget; src buffer must remain until complete.
    int guard{0};
    while (progress.phase == mw::MaterializeProgress::Phase::LEAFSET_BYTES && guard++ < 100000) {
        BOOST_CHECK_EQUAL(progress.leafset_src_bytes.size(), src_bytes);
        BOOST_REQUIRE(!mw::MaterializeStep(progress, tiny, out));
    }
    BOOST_CHECK(progress.phase != mw::MaterializeProgress::Phase::LEAFSET_BYTES);
    BOOST_CHECK(progress.leafset_src_bytes.empty());
    BOOST_REQUIRE(progress.built_leafset);
    BOOST_CHECK_EQUAL(bitset_calls.load(), 1U);
}

BOOST_AUTO_TEST_CASE(u38_warm_fills_depth_window)
{
    // Budgeted window warm fills MWEB heights in [tip−depth, tip] within the ring.
    MineToMwebChain(*this, m_node, 8);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    mw::ICoinsView::Ptr tip_view;
    uint256 tip_hash;
    int tip_height{0};
    int min_height{0};
    std::vector<uint256> expected_hashes;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->mweb_header);
        tip_hash = tip->GetBlockHash();
        tip_height = tip->nHeight;
        tip_view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        min_height = std::max(0, tip_height - MAX_MWEB_LEAFSET_DEPTH + 1);
        for (CBlockIndex* p = tip; p && p->nHeight >= min_height; p = p->pprev) {
            if ((p->nStatus & BLOCK_HAVE_MWEB) && p->mweb_header) {
                expected_hashes.push_back(p->GetBlockHash());
            }
        }
        BOOST_REQUIRE(tip_view);
        BOOST_REQUIRE(cache.MaybeScheduleWindowWarm(chainman, *tip, tip_view));
        // Tip seed is frozen into the ring at schedule; never retained as live cache.
        const auto tip_snap = cache.Lookup(tip_hash);
        BOOST_REQUIRE(tip_snap);
        BOOST_REQUIRE(tip_snap->view);
        BOOST_CHECK(!tip_snap->view->IsCache());
        BOOST_REQUIRE(std::dynamic_pointer_cast<mw::CoinsViewMemory>(tip_snap->view));
    }
    BOOST_REQUIRE(!expected_hashes.empty());

    for (int i = 0; i < 5000 && cache.HasPendingWindowWarm(); ++i) {
        cache.ProcessOneWindowWarmStep(*Assert(m_node.chainman));
    }
    BOOST_CHECK(!cache.HasPendingWindowWarm());

    for (const auto& hash : expected_hashes) {
        BOOST_CHECK_MESSAGE(cache.Lookup(hash), "warm miss for " + hash.ToString());
    }
    BOOST_CHECK(cache.GetStats().entries <= static_cast<size_t>(MAX_MWEB_LEAFSET_DEPTH));
    BOOST_CHECK(cache.GetStats().entries >= expected_hashes.size());
}

// Race fix: tip advance while undo warm runs must not crash; scheduled tip
// remains owned CoinsViewMemory (never a live tip overlay as async Materialize source).
BOOST_AUTO_TEST_CASE(window_warm_safe_across_concurrent_tip_advance)
{
    MineToMwebChain(*this, m_node, 6);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    uint256 scheduled_tip_hash;
    mw::Hash leafset_root_at_schedule;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->mweb_header);
        scheduled_tip_hash = tip->GetBlockHash();
        auto tip_view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(tip_view);
        BOOST_REQUIRE(tip_view->IsCache());
        BOOST_REQUIRE(cache.MaybeScheduleWindowWarm(chainman, *tip, tip_view));
        const auto tip_snap = cache.Lookup(scheduled_tip_hash);
        BOOST_REQUIRE(tip_snap);
        BOOST_REQUIRE(std::dynamic_pointer_cast<mw::CoinsViewMemory>(tip_snap->view));
        BOOST_CHECK(!tip_snap->view->IsCache());
        leafset_root_at_schedule = tip_snap->view->GetLeafSet()->Root();
    }
    BOOST_REQUIRE(cache.HasPendingWindowWarm());

    // Mutate live tip while warm undo steps run (the former race window).
    for (int step = 0; step < 64 && cache.HasPendingWindowWarm(); ++step) {
        cache.ProcessOneWindowWarmStep(*Assert(m_node.chainman));
        if (step == 2 || step == 10) {
            SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/3 + step);
            const CScript coinbase_script{CScript() << OP_TRUE};
            MineMwebEraBlock(m_node, coinbase_script);
        }
    }
    while (cache.HasPendingWindowWarm()) {
        cache.ProcessOneWindowWarmStep(*Assert(m_node.chainman));
    }

    const auto after = cache.Lookup(scheduled_tip_hash);
    BOOST_REQUIRE(after);
    BOOST_REQUIRE(std::dynamic_pointer_cast<mw::CoinsViewMemory>(after->view));
    BOOST_CHECK(after->view->GetLeafSet()->Root() == leafset_root_at_schedule);
    {
        LOCK(::cs_main);
        const CBlockIndex* hist = Assert(m_node.chainman)->m_blockman.LookupBlockIndex(scheduled_tip_hash);
        BOOST_REQUIRE(hist && hist->mweb_header);
        BOOST_CHECK(MWEB::Node::VerifyChainstateRoots(*hist->mweb_header, *after->view));
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip);
        BOOST_CHECK(tip->GetBlockHash() != scheduled_tip_hash);
    }
}

// Historical snapshots must not read through to a mutating live tip leafset.
BOOST_AUTO_TEST_CASE(historical_snapshot_immutable_across_tip_advance)
{
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    uint256 hist_hash;
    mw::Hash leafset_root_at_store;
    mw::DynamicBitSet leafset_bits_at_store;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->mweb_header);
        hist_hash = tip->GetBlockHash();

        // Store a live tip overlay (the pre-fix footgun). Store() must freeze it.
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = hist_hash;
        snap->height = tip->nHeight;
        snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(snap->view);
        BOOST_REQUIRE(snap->view->IsCache());
        cache.Store(snap);

        const auto stored = cache.Lookup(hist_hash);
        BOOST_REQUIRE(stored);
        BOOST_REQUIRE(stored->view);
        BOOST_CHECK(!stored->view->IsCache());
        BOOST_REQUIRE(std::dynamic_pointer_cast<mw::CoinsViewMemory>(stored->view));
        BOOST_CHECK(MWEB::Node::VerifyChainstateRoots(*tip->mweb_header, *stored->view));
        leafset_root_at_store = stored->view->GetLeafSet()->Root();
        leafset_bits_at_store = stored->view->GetLeafSet()->ToDynamicBitSet();
    }

    // Advance tip with another pegin so the live leafset / DB mutates.
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/3);
    const CScript coinbase_script{CScript() << OP_TRUE};
    MineMwebEraBlock(m_node, coinbase_script);

    const auto after = cache.Lookup(hist_hash);
    BOOST_REQUIRE(after);
    BOOST_REQUIRE(after->view);
    BOOST_CHECK(!after->view->IsCache());
    BOOST_CHECK(after->view->GetLeafSet()->Root() == leafset_root_at_store);
    BOOST_CHECK(after->view->GetLeafSet()->ToDynamicBitSet().bytes() == leafset_bits_at_store.bytes());

    {
        LOCK(::cs_main);
        const CBlockIndex* hist = Assert(m_node.chainman)->m_blockman.LookupBlockIndex(hist_hash);
        BOOST_REQUIRE(hist && hist->mweb_header);
        BOOST_CHECK(MWEB::Node::VerifyChainstateRoots(*hist->mweb_header, *after->view));
        // Live tip roots must differ once the new block added MWEB state.
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->mweb_header);
        BOOST_CHECK(tip->GetBlockHash() != hist_hash);
        const auto tip_mweb = Assert(m_node.chainman)->ActiveChainstate().CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(tip_mweb);
        BOOST_CHECK(tip_mweb->GetLeafSet()->Root() != leafset_root_at_store);
    }
}

// Queue-full leafset GETDATA spam must not call ToDynamicBitSet for pricing.
BOOST_AUTO_TEST_CASE(leafset_admit_skips_todynamicbitset_on_queue_full)
{
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    auto engine = MakeTestEngine(*Assert(m_node.chainman), connman, ctx);
    auto node = MakeTestNode();
    TestServePeer peer;

    uint256 tip_hash;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        tip_hash = tip->GetBlockHash();
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = tip_hash;
        snap->height = tip->nHeight;
        snap->view = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        cache.Store(std::move(snap));
    }
    BOOST_REQUIRE(cache.Lookup(tip_hash));

    for (size_t i = 0; i < MAX_MWEB_SERVE_JOBS_PER_PEER; ++i) {
        BOOST_REQUIRE(engine.TryEnqueue(*node, peer.state, MakeHeaderJob(TestHash(strprintf("f4%062x", i).c_str())), 1.0));
    }
    BOOST_REQUIRE_EQUAL(peer.jobs.size(), MAX_MWEB_SERVE_JOBS_PER_PEER);

    std::atomic<uint64_t> bitset_calls{0};
    mw::g_leafset_todynamicbitset_calls = &bitset_calls;
    const double credits_before{peer.credits};
    for (int i = 0; i < 200; ++i) {
        engine.EnqueueLeafset(*node, peer.state, CInv{MSG_MWEB_LEAFSET, tip_hash});
    }
    mw::g_leafset_todynamicbitset_calls = nullptr;

    BOOST_CHECK_EQUAL(bitset_calls.load(), 0U);
    BOOST_CHECK_EQUAL(peer.jobs.size(), MAX_MWEB_SERVE_JOBS_PER_PEER);
    BOOST_CHECK_EQUAL(peer.credits, credits_before);
}

// BUILD_SEND + pending finalize-materialize must not busy-loop.
// Reproduces the wedge: job.phase stays BUILD_SEND while coordinator has
// materialize_active / MATERIALIZE_CHUNK, so ProcessCoordinatorStep was skipped.
BOOST_AUTO_TEST_CASE(build_send_materialize_does_not_wedge)
{
    MineToMwebChain(*this, m_node, 3);
    auto& cache = GetMWEBHistoricalViewCache();
    cache.ClearForTest();

    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    TestEngineContext ctx;
    bool sent{false};
    MWEBServeHost host{
        *Assert(m_node.chainman),
        connman,
        {},
        ctx.global_jobs,
        ctx.replay_mutex,
        /*material_byte_budget=*/1024,
        /*material_leaf_ops=*/8,
        DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {},
        [&](CNode&, MWEBLeafsetMsg) { sent = true; },
        [](CNode&, MWEBUTXOsMsg) {},
        [](CNode&, CMerkleBlockWithMWEB) {},
    };
    connman.AddLocalServices(NODE_MWEB);
    MWEBServeEngine engine{std::move(host)};
    auto node = MakeTestNode();
    TestServePeer peer;

    uint256 tip_hash;
    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        CBlockIndex* tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(tip && tip->mweb_header);
        tip_hash = tip->GetBlockHash();

        auto coord = GetMWEBServeCoordinator().AttachOrCreate(tip_hash);
        coord->target_index = tip;
        coord->replay_tip = tip;
        coord->pindex_fork = tip;
        coord->source_tip = tip;
        auto tip_mweb = chainman.ActiveChainstate().CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(tip_mweb);
        coord->mweb_replay_view = std::make_shared<mw::CoinsViewCache>(tip_mweb);
        mw::MaterializeProgressBegin(coord->materialize_progress, *coord->mweb_replay_view, false);
        coord->materialize_active = true;
        coord->materialize_purpose = node::MWEBServeCoordinatorJob::MaterializePurpose::FINALIZE;
        coord->phase = MWEBServeJob::Phase::MATERIALIZE_CHUNK;

        MWEBServeJob job;
        job.type = MWEBServeJob::Type::LEAFSET;
        job.block_hash = tip_hash;
        job.phase = MWEBServeJob::Phase::BUILD_SEND;
        job.coordinator = coord;
        peer.jobs.push_back(std::move(job));
        ctx.global_jobs = 1;
    }

    // First step must leave the wedged BUILD_SEND idle (adopt MATERIALIZE_CHUNK
    // and/or finish the job). Without the fix, phase stays BUILD_SEND forever.
    BOOST_REQUIRE(!peer.jobs.empty());
    BOOST_CHECK_EQUAL(static_cast<int>(peer.jobs.front().phase),
                      static_cast<int>(MWEBServeJob::Phase::BUILD_SEND));
    engine.ProcessOneStep(*node, peer.state);
    if (!peer.jobs.empty()) {
        BOOST_CHECK(peer.jobs.front().phase != MWEBServeJob::Phase::BUILD_SEND ||
                    peer.jobs.front().snapshot != nullptr);
    }

    for (int i = 0; i < 500 && !peer.jobs.empty(); ++i) {
        engine.ProcessOneStep(*node, peer.state);
    }

    BOOST_CHECK_MESSAGE(peer.jobs.empty(),
                        "BUILD_SEND wedge: job still queued after materialize steps");
    BOOST_CHECK(sent);
    BOOST_CHECK(cache.Lookup(tip_hash));
}

BOOST_AUTO_TEST_CASE(u39_rotate_serve_peer_empty)
{
    const std::vector<NodeId> pending;
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, node::NO_BACKGROUND_SERVE_PEER),
                      node::NO_BACKGROUND_SERVE_PEER);
}

BOOST_AUTO_TEST_CASE(u40_rotate_serve_peer_single)
{
    const std::vector<NodeId> pending{5};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 5), 5);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, node::NO_BACKGROUND_SERVE_PEER), 5);
}

BOOST_AUTO_TEST_CASE(u41_rotate_serve_peer_advance)
{
    const std::vector<NodeId> pending{1, 3, 5};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 1), 3);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 3), 5);
}

BOOST_AUTO_TEST_CASE(u42_rotate_serve_peer_wrap)
{
    const std::vector<NodeId> pending{1, 3, 5};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 5), 1);
}

BOOST_AUTO_TEST_CASE(u43_rotate_serve_peer_stale_last)
{
    const std::vector<NodeId> pending{3, 7};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 99), 3);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, node::NO_BACKGROUND_SERVE_PEER), 3);
}

BOOST_AUTO_TEST_CASE(u44_rotate_serve_peer_sparse)
{
    const std::vector<NodeId> pending{2, 8};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 2), 8);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 8), 2);
}

BOOST_AUTO_TEST_CASE(u45_rotate_serve_peer_zero_id)
{
    const std::vector<NodeId> pending{0, 2};
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, node::NO_BACKGROUND_SERVE_PEER), 0);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 0), 2);
    BOOST_CHECK_EQUAL(node::SelectNextRotatingServePeer(pending, 2), 0);
}

BOOST_AUTO_TEST_SUITE_END()
