// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_historical_cache.h>
#include <node/mweb_serve_coordinator.h>
#include <node/mweb_serve_step_budget.h>
#include <node/mweb_serve_types.h>
#include <node/mweb_serve.h>
#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>
#include <mw/mmr/mmr.h>
#include <mw/models/block/header.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <uint256.h>
#include <validation.h>

#include <deque>
#include <limits>

namespace {
TestingSetup* g_setup;

void initialize_mweb_serve()
{
    FakeNodeClock init_clock{};
    static const auto testing_setup = MakeNoLogFileContext<TestingSetup>();
    g_setup = testing_setup.get();
}

} // namespace

FUZZ_TARGET(mweb_serve, .init = initialize_mweb_serve)
{
    FakeNodeClock node_clock{std::chrono::seconds{1610000000}};
    FakeSteadyClock clock;
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    node::GetMWEBHistoricalViewCache().ClearForTest();

    const uint256 hash{ConsumeUInt256(provider)};
    auto& coord = node::GetMWEBServeCoordinator();
    auto job = coord.AttachOrCreate(hash);

    node::MWEBWorkBudget budget{
        provider.ConsumeIntegralInRange<size_t>(1, 65536),
        provider.ConsumeIntegralInRange<size_t>(1, 128),
    };
    (void)budget.ConsumeReplayBlock();

    mw::MaterializeProgress progress;
    if (provider.ConsumeBool()) {
        const auto header = std::make_shared<mw::Header>();
        const auto leafset = std::make_shared<MemLeafSet>(mw::DynamicBitSet{});
        const auto pmmr = std::make_shared<MemMMR>();
        auto source = mw::CoinsViewMemory::Create(header, leafset, pmmr, {});
        mw::MaterializeProgressBegin(progress, *source, provider.ConsumeBool());
        mw::CoinsViewMemory::Ptr out;
        LIMITED_WHILE(provider.ConsumeBool(), 32) {
            (void)mw::MaterializeStep(progress, budget.MaterializeBudget(), out);
        }
    }

    MWEBServeJob serve_job;
    serve_job.type = static_cast<MWEBServeJob::Type>(
        provider.ConsumeIntegralInRange<uint8_t>(0, 2));
    serve_job.block_hash = hash;
    serve_job.start_index = provider.ConsumeIntegral<uint64_t>();
    // Explicitly exercise num_requested==0 (zero-request enqueue) and huge start_index (UTXO EOF).
    serve_job.num_requested = provider.ConsumeBool() ? 0 : provider.ConsumeIntegral<uint16_t>();
    if (provider.ConsumeBool()) {
        serve_job.start_index = std::numeric_limits<uint64_t>::max();
    }
    serve_job.coordinator = job;

    // Exercise the public enqueue guard and the real queue/step/EOF machinery.
    // The empty cached view is deliberate: no chain replay or unbounded output
    // construction is needed to reach EOF for arbitrary (including huge) indexes.
    auto& connman = static_cast<ConnmanTestMsg&>(*g_setup->m_node.connman);
    connman.AddLocalServices(NODE_MWEB);
    auto peer_node = ConsumeNodeAsUniquePtr(provider, clock);
    peer_node->fPauseSend = false;
    node::PeerMWEBState peer;
    auto state = node::MakeMWEBServePeerState(peer);
    std::atomic<size_t> queued{0};
    Mutex replay_mutex;
    node::MWEBServePolicy policy;
    policy.mweb_serve = MwebServeMode::FORCE;
    node::MWEBServeEngine engine{node::MWEBServeHost{
        *g_setup->m_node.chainman, connman, policy, queued, replay_mutex,
        4096, 16, DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT,
        [](CNode&, const std::string&) {}, [](CNode&, MWEBLeafsetMsg) {},
        [](CNode&, MWEBUTXOsMsg) {}, [](CNode&, CMerkleBlockWithMWEB) {},
    }};
    GetMWEBUTXOsMsg request;
    request.block_hash = hash;
    request.start_index = serve_job.start_index;
    request.num_requested = 0;
    request.output_format = NetUTXO::HASH_ONLY;
    const double credits_before = state.m_mweb_serve_credits;
    engine.EnqueueUTXOs(*peer_node, state, request);
    assert(state.m_mweb_serve_jobs.empty());
    assert(queued == 0);
    assert(state.m_mweb_serve_credits == credits_before);

    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = hash;
    snapshot->view = mw::CoinsViewMemory::Create(std::make_shared<mw::Header>(),
        std::make_shared<MemLeafSet>(mw::DynamicBitSet{}), std::make_shared<MemMMR>(), {});
    serve_job.type = MWEBServeJob::Type::UTXOS;
    serve_job.phase = MWEBServeJob::Phase::BUILD_SEND;
    serve_job.snapshot = std::move(snapshot);
    serve_job.num_requested = provider.ConsumeIntegralInRange<uint16_t>(1, 16);
    peer_node->fDisconnect = false;
    assert(engine.TryEnqueue(*peer_node, state, std::move(serve_job), 0));
    assert(queued == 1);
    assert(engine.ProcessOneStep(*peer_node, state));
    assert(state.m_mweb_serve_jobs.empty());
    assert(queued == 0);
    engine.ClearJobs(state);

    if (provider.ConsumeBool()) {
        auto snap = std::make_shared<MWEBHistoricalSnapshot>();
        snap->block_hash = hash;
        const auto header = std::make_shared<mw::Header>();
        const auto leafset = std::make_shared<MemLeafSet>(mw::DynamicBitSet{});
        const auto pmmr = std::make_shared<MemMMR>();
        snap->view = mw::CoinsViewMemory::Create(header, leafset, pmmr, {});
        node::GetMWEBHistoricalViewCache().Store(std::move(snap));
    }

    coord.PruneCompleted();
}
