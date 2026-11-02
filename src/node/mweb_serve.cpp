// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_serve.h>

#include <chain.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <logging.h>
#include <merkleblock.h>
#include <mweb/mweb_node.h>
#include <mw/mmr/segment.h>
#include <mw/models/tx/utxo.h>
#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>
#include <net.h>
#include <net_permissions.h>
#include <node/mweb_historical_cache.h>
#include <node/mweb_serve_coordinator.h>
#include <node/mweb_serve_step_budget.h>
#include <primitives/block.h>
#include <protocol.h>
#include <serialize.h>
#include <undo.h>
#include <validation.h>

#include <chrono>

namespace node {

namespace {

bool ReplayViewValid(const ChainstateManager& chainman, const CBlockIndex& pindex, const CCoinsViewCache& view)
{
    if (!pindex.mweb_header) return false;
    const auto mweb_cache{view.GetMWEBCacheView()};
    if (!mweb_cache) return false;
    return MWEB::Node::VerifyChainstateRoots(*pindex.mweb_header, *mweb_cache);
}

/** Publishes only frozen views; a live CoinsViewCache/LeafSetCache overlay returns null so the
 *  caller copies it in budgeted steps, as a full copy here would stall the message handler. */
MWEBHistoricalSnapshotPtr MakeSnapshotFromView(const CBlockIndex& pindex, mw::ICoinsView::Ptr view)
{
    if (!view || !pindex.mweb_header) return nullptr;
    if (!std::dynamic_pointer_cast<mw::CoinsViewMemory>(view)) return nullptr;
    if (!MWEB::Node::VerifyChainstateRoots(*pindex.mweb_header, *view)) {
        return nullptr;
    }
    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = pindex.GetBlockHash();
    snapshot->height = pindex.nHeight;
    snapshot->view = std::move(view);
    return snapshot;
}

void BeginFinalizeMaterialize(MWEBServeCoordinatorJob& coord)
{
    mw::ICoinsView::Ptr source;
    if (coord.temp_view) {
        source = coord.temp_view->GetMWEBCacheView();
    } else if (coord.mweb_replay_view) {
        source = coord.mweb_replay_view;
    }
    if (!source || !coord.target_index) {
        coord.failed = true;
        return;
    }
    mw::MaterializeProgressBegin(coord.materialize_progress, *source, /*assumeutxo_snapshot=*/false);
    coord.materialize_active = true;
    coord.materialize_purpose = MWEBServeCoordinatorJob::MaterializePurpose::FINALIZE;
    coord.phase = MWEBServeJob::Phase::MATERIALIZE_CHUNK;
}

bool MaterializeChunkStep(mw::ICoinsView& source, mw::MaterializeProgress& progress,
                          mw::ICoinsView::Ptr& out_view, const MWEBWorkBudget& budget, int height, int peer_id)
{
    const auto step_start{std::chrono::steady_clock::now()};
    mw::CoinsViewMemory::Ptr frozen;
    const bool done{mw::MaterializeStepWithSparseFallback(progress, budget.MaterializeBudget(), frozen)};
    const auto step_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - step_start).count()};
    if (done && frozen) {
        out_view = std::move(frozen);
        LogDebug(BCLog::NET, "MWEB serve materialize chunk: height=%d peer=%d phase=complete ns=%d\n",
                 height, peer_id, static_cast<int>(step_ns));
        return true;
    }
    LogDebug(BCLog::NET, "MWEB serve materialize chunk: height=%d peer=%d phase=%d ns=%d\n",
             height, peer_id, static_cast<int>(progress.phase), static_cast<int>(step_ns));
    return false;
}

/** Lazily allocate a full coins cache only when DisconnectBlock fallback is required. */
void EnsureCoordinatorTempView(Chainstate& chainstate, MWEBServeCoordinatorJob& coord)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (coord.temp_view) return;
    // The MWEB layer is wrapped automatically at construction (InitCoinsDB invariant).
    coord.temp_view = std::make_unique<CCoinsViewCache>(&chainstate.CoinsTip());
}

void StoreSnapshotIfValid(MWEBServeCoordinatorJob& coord)
{
    if (!coord.snapshot || !coord.snapshot->view) return;
    GetMWEBHistoricalViewCache().Store(coord.snapshot);
    // Once the historical ring owns the snapshot, drop completed coordinator
    // entries (including this one) so the map does not retain them forever.
    GetMWEBServeCoordinator().PruneCompleted();
}

/** Pop the front serve job and prune finished coordinator map entries. */
void FinishServeJob(MWEBServePeerState& peer, std::atomic<size_t>& global_jobs)
{
    assert(!peer.m_mweb_serve_jobs.empty());
    peer.m_mweb_serve_jobs.pop_front();
    --global_jobs;
    GetMWEBServeCoordinator().PruneCompleted();
}

/** Freeze replay view at target height (matches legacy FinalizeMWEBReplaySnapshot). */
void FinalizeFromReplayView(MWEBServeCoordinatorJob& coord)
{
    if (!coord.target_index || !coord.mweb_replay_view) {
        coord.failed = true;
        return;
    }
    coord.snapshot = MakeSnapshotFromView(*coord.target_index, coord.mweb_replay_view);
    if (!coord.snapshot) {
        BeginFinalizeMaterialize(coord);
        return;
    }
    coord.mweb_replay_view.reset();
    coord.temp_view.reset();
    coord.materialize_active = false;
    coord.materialize_purpose = MWEBServeCoordinatorJob::MaterializePurpose::NONE;
    coord.phase = MWEBServeJob::Phase::BUILD_SEND;
    StoreSnapshotIfValid(coord);
}

void FinalizeFromTempView(MWEBServeCoordinatorJob& coord)
{
    if (!coord.target_index || !coord.temp_view) {
        coord.failed = true;
        return;
    }
    auto mweb = coord.temp_view->GetMWEBCacheView();
    if (!mweb) {
        coord.failed = true;
        return;
    }
    coord.snapshot = MakeSnapshotFromView(*coord.target_index, mweb);
    if (!coord.snapshot) {
        BeginFinalizeMaterialize(coord);
        return;
    }
    coord.mweb_replay_view.reset();
    coord.temp_view.reset();
    coord.materialize_active = false;
    coord.materialize_purpose = MWEBServeCoordinatorJob::MaterializePurpose::NONE;
    coord.phase = MWEBServeJob::Phase::BUILD_SEND;
    StoreSnapshotIfValid(coord);
}

/** Fail closed if target / replay tip / fork left the active chain, or if the tip the
 *  replay views read through to moved, since those views then no longer hold one state. */
bool ReplayChainMembershipOk(const ChainstateManager& chainman, const MWEBServeCoordinatorJob& coord)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (!coord.target_index || !coord.replay_tip || !coord.pindex_fork) return false;
    const CChain& active{chainman.ActiveChain()};
    return active.Tip() == coord.source_tip &&
           active.Contains(*coord.target_index) &&
           active.Contains(*coord.replay_tip) &&
           active.Contains(*coord.pindex_fork);
}

void PopulateForwardBlocks(MWEBServeCoordinatorJob& coord)
{
    coord.forward_blocks.clear();
    for (CBlockIndex* it = coord.target_index;
         it && it->nHeight != coord.replay_tip->nHeight;
         it = it->pprev) {
        coord.forward_blocks.push_back(it);
    }
    coord.forward_pos = 0;
}

void HandleReplayReachedFork(MWEBServeCoordinatorJob& coord)
{
    if (coord.replay_tip->GetBlockHash() == coord.target_index->GetBlockHash()) {
        if (coord.mweb_replay_view) {
            FinalizeFromReplayView(coord);
        } else {
            FinalizeFromTempView(coord);
        }
    } else {
        PopulateForwardBlocks(coord);
        coord.phase = MWEBServeJob::Phase::REPLAY_FORWARD;
    }
}

} // namespace

MWEBServeEngine::MWEBServeEngine(MWEBServeHost host) : m_host(std::move(host)) {}

MWEBServeDenyReason MWEBServeEngine::CanServeLightClientReason() const
{
    if (!(m_host.connman.GetLocalServices() & NODE_MWEB)) return MWEBServeDenyReason::NoNodeMweb;
    if (m_host.policy.ignore_incoming_txs && !m_host.policy.mweb_serve_in_blocksonly) {
        return MWEBServeDenyReason::BlocksOnly;
    }
    if (m_host.policy.mweb_serve == MwebServeMode::OFF) return MWEBServeDenyReason::ServeOff;
    if (m_host.policy.mweb_serve != MwebServeMode::FORCE && m_host.connman.OutboundTargetReached(false)) {
        return MWEBServeDenyReason::UploadLimited;
    }
    return MWEBServeDenyReason::None;
}

void MWEBServeEngine::UpdateCredits(MWEBServePeerState& peer) const
{
    const auto current_time{NodeClock::now()};
    const auto time_diff{current_time - peer.m_mweb_serve_credit_timestamp};
    const double increment{std::chrono::duration<double>(time_diff).count() * MWEB_SERVE_CREDIT_REFILL_PER_SECOND};
    peer.m_mweb_serve_credits = std::min(peer.m_mweb_serve_credits + increment, m_host.policy.mweb_serve_burst);
    peer.m_mweb_serve_credit_timestamp = current_time;
}

bool MWEBServeEngine::HandleCreditDenial(CNode& node, MWEBServePeerState& peer)
{
    const auto now{NodeClock::now()};
    const auto window{std::chrono::seconds(MWEB_SERVE_CREDIT_DENY_WINDOW_SEC)};
    if (now - peer.m_mweb_credit_deny_window_start > window) {
        peer.m_mweb_credit_deny_window_start = now;
        peer.m_mweb_credit_denies_rolling = 0;
    }
    ++peer.m_mweb_credit_denies_rolling;
    if (!node.HasPermission(NetPermissionFlags::NoBan)) {
        if (peer.m_mweb_credit_denies_rolling == 1) {
            LogDebug(BCLog::NET, "MWEB serve rate limit exceeded (peer=%d, first denial in window)\n",
                     node.GetId());
        }
        if (peer.m_mweb_credit_denies_rolling >= m_host.credit_deny_disconnect) {
            node.fDisconnect = true;
        }
    }
    return true;
}

double MWEBServeEngine::CreditCost(const MWEBServeJob& job, size_t leafset_bytes_hint) const
{
    switch (job.type) {
    case MWEBServeJob::Type::UTXOS:
        return static_cast<double>(job.num_requested);
    case MWEBServeJob::Type::LEAFSET:
        return std::max(100.0, static_cast<double>(leafset_bytes_hint) / 1024.0);
    case MWEBServeJob::Type::HEADER:
        // leafset_bytes_hint reused as serialized-block size proxy (EnqueueHeader).
        return std::max(MWEB_SERVE_HEADER_CREDIT_COST, static_cast<double>(leafset_bytes_hint) / 1024.0);
    }
    return 0.0;
}

void MWEBServeEngine::ClearJobs(MWEBServePeerState& peer)
{
    const size_t count{peer.m_mweb_serve_jobs.size()};
    peer.m_mweb_serve_jobs.clear();
    if (count > 0) {
        m_host.global_jobs -= count;
        GetMWEBServeCoordinator().PruneCompleted();
    }
}

bool MWEBServeEngine::ValidateServeBlock(CNode& node, const uint256& block_hash,
                                         bool header_request,
                                         const CBlockIndex** pindex_out)
{
    const bool disconnect_on_policy_violation{!header_request};
    LOCK(cs_main);
    if (m_host.chainman.IsInitialBlockDownload()) {
        LogDebug(BCLog::NET, "Ignoring MWEB serve request from peer=%d because node is in initial block download\n", node.GetId());
        return false;
    }

    const CBlockIndex* pindex = m_host.chainman.m_blockman.LookupBlockIndex(block_hash);
    if (!pindex || !m_host.chainman.ActiveChain().Contains(*pindex)) {
        LogDebug(BCLog::NET, "Ignoring MWEB serve request from peer=%d because requested block hash is not in active chain\n", node.GetId());
        return false;
    }

    const CBlockIndex* tip = m_host.chainman.ActiveChain().Tip();
    const int depth{tip->nHeight - pindex->nHeight};
    if (header_request) {
        // A header is read from the stored block, so it needs no MWEB state replay and
        // has no leafset depth limit. Pruned nodes apply the block-serving limit instead.
        const ServiceFlags local_services{m_host.connman.GetLocalServices()};
        if (!node.HasPermission(NetPermissionFlags::NoBan) &&
            (local_services & NODE_NETWORK_LIMITED) && !(local_services & NODE_NETWORK) &&
            depth > m_host.network_limited_serve_depth) {
            LogDebug(BCLog::NET, "Ignore MWEB header request below NODE_NETWORK_LIMITED threshold, %s", node.DisconnectMsg());
            node.fDisconnect = true;
            return false;
        }
    } else if (depth > MAX_MWEB_LEAFSET_DEPTH) {
        LogDebug(BCLog::NET, "Ignore MWEB serve request below MAX_MWEB_LEAFSET_DEPTH threshold from peer=%d\n", node.GetId());
        if (disconnect_on_policy_violation && !node.HasPermission(NetPermissionFlags::NoBan)) {
            node.fDisconnect = true;
        }
        return false;
    }

    if (!(pindex->nStatus & BLOCK_HAVE_DATA) || !(pindex->nStatus & BLOCK_HAVE_MWEB)) {
        LogDebug(BCLog::NET, "Ignoring MWEB serve request from peer=%d because block is either pruned or lacking mweb data\n", node.GetId());
        if (disconnect_on_policy_violation && !node.HasPermission(NetPermissionFlags::NoBan)) {
            node.fDisconnect = true;
        }
        return false;
    }

    if (!DeploymentActiveAt(*pindex, m_host.chainman, Consensus::DEPLOYMENT_MWEB)) {
        LogDebug(BCLog::NET, "Ignoring MWEB serve request from peer=%d for pre-MWEB block\n", node.GetId());
        if (disconnect_on_policy_violation && !node.HasPermission(NetPermissionFlags::NoBan)) {
            node.fDisconnect = true;
        }
        return false;
    }

    *pindex_out = pindex;
    return true;
}

bool MWEBServeEngine::TryEnqueue(CNode& node, MWEBServePeerState& peer, MWEBServeJob job, double credit_cost)
{
    const MWEBServeDenyReason deny{CanServeLightClientReason()};
    if (deny != MWEBServeDenyReason::None) {
        bool ibd{false};
        {
            LOCK(cs_main);
            ibd = m_host.chainman.IsInitialBlockDownload();
        }
        if (ibd) {
            return false;
        }
        // download@ may bypass only outbound-upload-target exhaustion — never
        // -mwebserve=off / blocksonly / missing NODE_MWEB merely because the
        // upload target happens to also be reached.
        if (deny == MWEBServeDenyReason::UploadLimited) {
            if (!node.HasPermission(NetPermissionFlags::Download)) {
                if (!node.HasPermission(NetPermissionFlags::NoBan)) {
                    LogDebug(BCLog::NET, "MWEB serve request with bandwidth limit reached, %s", node.DisconnectMsg());
                    node.fDisconnect = true;
                }
                return false;
            }
        } else {
            return false;
        }
    }

    if (peer.m_mweb_serve_jobs.size() >= MAX_MWEB_SERVE_JOBS_PER_PEER) {
        LogDebug(BCLog::NET, "MWEB serve queue full for peer=%d, dropping request\n", node.GetId());
        return false;
    }
    if (m_host.global_jobs.load() >= MAX_MWEB_SERVE_JOBS_GLOBAL) {
        LogDebug(BCLog::NET, "Global MWEB serve queue full, dropping request from peer=%d\n", node.GetId());
        return false;
    }

    UpdateCredits(peer);
    if (peer.m_mweb_serve_credits < credit_cost) {
        LogDebug(BCLog::NET, "MWEB serve credit deny: peer=%d cost=%f credits=%f\n",
                 node.GetId(), credit_cost, peer.m_mweb_serve_credits);
        HandleCreditDenial(node, peer);
        return false;
    }
    peer.m_mweb_serve_credits -= credit_cost;

    job.coordinator = GetMWEBServeCoordinator().AttachOrCreate(job.block_hash);
    peer.m_mweb_serve_jobs.push_back(std::move(job));
    ++m_host.global_jobs;
    return true;
}

bool MWEBServeEngine::BuildAndSend(CNode& node, MWEBServeJob& job)
{
    if (node.fPauseSend) return false;

    if (job.type == MWEBServeJob::Type::HEADER) {
        // Snapshot index/pos under cs_main; ReadBlock does its own brief lock for GetBlockPos
        // when called with CBlockIndex — call FlatFilePos overload outside the long hold so
        // disk I/O is not under cs_main (header size-proxy credit pricing).
        FlatFilePos block_pos;
        uint256 expected_hash;
        {
            LOCK(cs_main);
            const CBlockIndex* pindex = m_host.chainman.m_blockman.LookupBlockIndex(job.block_hash);
            if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA)) {
                return true;
            }
            block_pos = pindex->GetBlockPos();
            expected_hash = pindex->GetBlockHash();
        }
        CBlock block;
        if (!m_host.chainman.m_blockman.ReadBlock(block, block_pos, expected_hash)) {
            LogDebug(BCLog::NET, "MWEB header serve read failed for %s peer=%d (no ban)\n",
                     job.block_hash.ToString(), node.GetId());
            return true;
        }
        if (block.GetHogEx() == nullptr || block.mweb_block.IsNull()) {
            return true;
        }
        CMerkleBlockWithMWEB merkle{block};
        const uint64_t est_bytes{GetSerializeSize(merkle)};
        if (m_host.connman.GetMaxOutboundTarget() > 0) {
            const uint64_t bytes_left{m_host.connman.GetOutboundTargetBytesLeft()};
            if ((bytes_left == 0 || est_bytes > bytes_left) &&
                m_host.policy.mweb_serve != MwebServeMode::FORCE &&
                !node.HasPermission(NetPermissionFlags::Download)) {
                LogDebug(BCLog::NET, "MWEB header serve with bandwidth limit reached, %s", node.DisconnectMsg());
                if (!node.HasPermission(NetPermissionFlags::NoBan)) {
                    node.fDisconnect = true;
                }
                return true;
            }
        }
        m_host.send_header(node, std::move(merkle));
        return true;
    }

    if (!job.snapshot || !job.snapshot->view) return true;

    // Defense in depth: if this hash is an on-chain MWEB block, refuse to
    // send when the cached view no longer matches its header roots.
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = m_host.chainman.m_blockman.LookupBlockIndex(job.block_hash);
        if (pindex && pindex->mweb_header &&
            !MWEB::Node::VerifyChainstateRoots(*pindex->mweb_header, *job.snapshot->view)) {
            LogDebug(BCLog::NET, "MWEB serve snapshot roots mismatch peer=%d hash=%s\n",
                     node.GetId(), job.block_hash.ToString());
            return true;
        }
    }

    auto& mweb_view = *job.snapshot->view;

    if (job.type == MWEBServeJob::Type::LEAFSET) {
        const auto leafset_bits{mweb_view.GetLeafSet()->ToDynamicBitSet()};
        if (m_host.connman.GetMaxOutboundTarget() > 0) {
            const uint64_t bytes_left{m_host.connman.GetOutboundTargetBytesLeft()};
            const uint64_t est_bytes{leafset_bits.bytes().size()};
            if ((bytes_left == 0 || est_bytes > bytes_left) &&
                m_host.policy.mweb_serve != MwebServeMode::FORCE &&
                !node.HasPermission(NetPermissionFlags::Download)) {
                LogDebug(BCLog::NET, "MWEB leafset serve with bandwidth limit reached, %s", node.DisconnectMsg());
                if (!node.HasPermission(NetPermissionFlags::NoBan)) {
                    node.fDisconnect = true;
                }
                return true;
            }
        }
        m_host.send_leafset(node, MWEBLeafsetMsg(job.block_hash, leafset_bits));
        return true;
    }

    uint16_t num_requested{job.num_requested};
    if (m_host.connman.GetMaxOutboundTarget() > 0) {
        const uint64_t bytes_left{m_host.connman.GetOutboundTargetBytesLeft()};
        if (bytes_left == 0 &&
            m_host.policy.mweb_serve != MwebServeMode::FORCE &&
            !node.HasPermission(NetPermissionFlags::Download)) {
            LogDebug(BCLog::NET, "MWEB UTXO serve with bandwidth limit reached, %s", node.DisconnectMsg());
            if (!node.HasPermission(NetPermissionFlags::NoBan)) {
                node.fDisconnect = true;
            }
            return true;
        }
        if (bytes_left > 0 && num_requested > 0) {
            const uint16_t max_by_budget{static_cast<uint16_t>(std::min<uint64_t>(num_requested, bytes_left / 256))};
            if (max_by_budget == 0) {
                LogDebug(BCLog::NET, "MWEB UTXO serve with insufficient bandwidth budget, %s", node.DisconnectMsg());
                if (!node.HasPermission(NetPermissionFlags::NoBan)) {
                    node.fDisconnect = true;
                }
                return true;
            }
            num_requested = std::max<uint16_t>(1, max_by_budget);
        }
    }

    const auto& leafset{*mweb_view.GetLeafSet()};
    const mmr::LeafIndex first_leaf{mmr::LeafIndex::At(job.start_index)};
    if (first_leaf >= leafset.GetNextLeafIdx() || !leafset.Contains(first_leaf)) {
        LogDebug(BCLog::NET, "getmwebutxos start_index %llu is not an unspent leaf, peer=%d\n",
                 job.start_index, node.GetId());
        if (!node.HasPermission(NetPermissionFlags::NoBan)) {
            node.fDisconnect = true;
        }
        return true;
    }

    mmr::Segment segment = mmr::SegmentFactory::Assemble(
        *mweb_view.GetOutputPMMR(),
        leafset,
        first_leaf,
        num_requested);
    if (segment.leaves.empty()) {
        LogDebug(BCLog::NET,
                 "Could not build segment requested by getmwebutxos from peer=%d (start=%llu num=%u) — internal error (no ban)\n",
                 node.GetId(), job.start_index, num_requested);
        return true;
    }

    std::vector<NetUTXO> utxos;
    utxos.reserve(segment.leaves.size());
    for (const mmr::Leaf& leaf : segment.leaves) {
        UTXO::CPtr utxo = mweb_view.GetUTXO(leaf.vec());
        if (!utxo) {
            LogDebug(BCLog::NET, "Could not build segment requested by getmwebutxos from peer=%d — internal error (no ban)\n", node.GetId());
            return true;
        }
        utxos.emplace_back(job.output_format, utxo);
    }

    std::vector<mw::Hash> proof_hashes = segment.hashes;
    if (segment.lower_peak) {
        proof_hashes.push_back(*segment.lower_peak);
    }

    MWEBUTXOsMsg utxos_msg;
    utxos_msg.block_hash = job.block_hash;
    utxos_msg.start_index = job.start_index;
    utxos_msg.output_format = job.output_format;
    utxos_msg.utxos = std::move(utxos);
    utxos_msg.proof_hashes = std::move(proof_hashes);
    m_host.send_utxos(node, std::move(utxos_msg));
    return true;
}

bool MWEBServeEngine::ProcessCoordinatorStep(CNode& node, MWEBServePeerState& peer,
                                             MWEBServeJob& job, MWEBServeCoordinatorJob& coord,
                                             MWEBWorkBudget& budget)
{
    if (coord.cancelled || coord.failed) {
        return false;
    }
    if (coord.snapshot) {
        job.snapshot = coord.snapshot;
        job.phase = MWEBServeJob::Phase::BUILD_SEND;
        return true;
    }

    auto& chainstate{m_host.chainman.ActiveChainstate()};
    const int height{coord.target_index ? coord.target_index->nHeight : -1};

    if (coord.phase == MWEBServeJob::Phase::MATERIALIZE_CHUNK || coord.materialize_active) {
        mw::ICoinsView::Ptr source{coord.mweb_replay_view};
        if (!source && coord.temp_view) {
            if (auto mweb = coord.temp_view->GetMWEBCacheView()) {
                source = mweb;
            }
        }
        if (!source) {
            coord.failed = true;
            return false;
        }
        if (!coord.materialize_active) {
            mw::MaterializeProgressBegin(coord.materialize_progress, *source, /*assumeutxo_snapshot=*/false);
            coord.materialize_active = true;
        }
        mw::ICoinsView::Ptr frozen;
        bool done{false};
        {
            LOCK(cs_main);
            if (!ReplayChainMembershipOk(m_host.chainman, coord)) {
                coord.failed = true;
                return false;
            }
            try {
                done = MaterializeChunkStep(*source, coord.materialize_progress, frozen, budget, height, node.GetId());
            } catch (const std::exception& e) {
                LogDebug(BCLog::NET, "MWEB serve materialize failed: height=%d peer=%d: %s\n", height, node.GetId(), e.what());
                coord.failed = true;
                return false;
            }
        }
        if (done && frozen) {
            if (coord.materialize_purpose == MWEBServeCoordinatorJob::MaterializePurpose::FINALIZE) {
                coord.snapshot = MakeSnapshotFromView(*coord.target_index, frozen);
                coord.mweb_replay_view.reset();
                coord.temp_view.reset();
                coord.materialize_active = false;
                coord.materialize_purpose = MWEBServeCoordinatorJob::MaterializePurpose::NONE;
                coord.phase = MWEBServeJob::Phase::BUILD_SEND;
                StoreSnapshotIfValid(coord);
                job.snapshot = coord.snapshot;
            } else {
                coord.mweb_replay_view = std::move(frozen);
                coord.materialize_active = false;
                coord.materialize_purpose = MWEBServeCoordinatorJob::MaterializePurpose::NONE;
                if (coord.target_index &&
                    coord.replay_tip->GetBlockHash() == coord.target_index->GetBlockHash()) {
                    auto snap = std::make_shared<MWEBHistoricalSnapshot>();
                    snap->block_hash = coord.target_index->GetBlockHash();
                    snap->height = coord.target_index->nHeight;
                    snap->view = std::move(coord.mweb_replay_view);
                    coord.snapshot = std::move(snap);
                    coord.mweb_replay_view.reset();
                    coord.temp_view.reset();
                    coord.phase = MWEBServeJob::Phase::BUILD_SEND;
                    StoreSnapshotIfValid(coord);
                } else {
                    coord.phase = MWEBServeJob::Phase::REPLAY_BACK;
                }
            }
        }
        return true;
    }

    if (coord.phase == MWEBServeJob::Phase::REPLAY_BACK ||
        coord.phase == MWEBServeJob::Phase::REPLAY_FORWARD) {
        if (!budget.ConsumeReplayBlock()) {
            return true;
        }

        // Brief cs_main for chain membership; preferred MWEB ReadBlockUndo +
        // UndoBlock (and ReadBlock disk I/O) run outside a long hold. DisconnectBlock /
        // ConnectBlock still require cs_main and are locked only around the call.
        {
            LOCK(cs_main);
            if (!ReplayChainMembershipOk(m_host.chainman, coord)) {
                coord.failed = true;
                return false;
            }
        }

        if (coord.phase == MWEBServeJob::Phase::REPLAY_BACK) {
            if (coord.replay_tip->GetBlockHash() == coord.pindex_fork->GetBlockHash()) {
                HandleReplayReachedFork(coord);
                return true;
            }

            CBlockIndex* const disconnect_index{coord.replay_tip};
            if (!disconnect_index->pprev) {
                coord.failed = true;
                return false;
            }

            if (coord.mweb_replay_view) {
                CBlockUndo block_undo;
                if (chainstate.m_blockman.ReadBlockUndo(block_undo, *disconnect_index)) {
                    {
                        LOCK(cs_main);
                        if (!ReplayChainMembershipOk(m_host.chainman, coord) ||
                            coord.replay_tip != disconnect_index) {
                            coord.failed = true;
                            return false;
                        }
                        if (block_undo.mwundo) {
                            try {
                                auto replay_cache = std::make_shared<mw::CoinsViewCache>(coord.mweb_replay_view);
                                replay_cache->UndoBlock(block_undo.mwundo);
                                coord.mweb_replay_view = replay_cache;
                            } catch (const std::exception&) {
                                coord.failed = true;
                                return false;
                            }
                        }
                    }
                    coord.replay_tip = disconnect_index->pprev;
                    LogDebug(BCLog::NET, "MWEB serve replay step: back height=%d target=%s peer=%d\n",
                             coord.replay_tip->nHeight, job.block_hash.ToString(), node.GetId());
                    if (coord.replay_tip->GetBlockHash() == coord.target_index->GetBlockHash()) {
                        FinalizeFromReplayView(coord);
                    }
                    return true;
                }
                LogDebug(BCLog::NET, "MWEB serve replay undo unavailable, falling back to DisconnectBlock peer=%d height=%d\n",
                         node.GetId(), disconnect_index->nHeight);
            }

            CBlock block;
            if (!chainstate.m_blockman.ReadBlock(block, *disconnect_index)) {
                coord.failed = true;
                return false;
            }
            {
                LOCK(cs_main);
                if (!ReplayChainMembershipOk(m_host.chainman, coord) ||
                    coord.replay_tip != disconnect_index) {
                    coord.failed = true;
                    return false;
                }
                EnsureCoordinatorTempView(chainstate, coord);
                const DisconnectResult disconnect_result{
                    chainstate.DisconnectBlock(block, disconnect_index, *coord.temp_view)};
                if (disconnect_result != DISCONNECT_OK && disconnect_result != DISCONNECT_UNCLEAN) {
                    coord.failed = true;
                    return false;
                }
                coord.replay_tip = disconnect_index->pprev;
                LogDebug(BCLog::NET, "MWEB serve replay step: back height=%d target=%s peer=%d\n",
                         coord.replay_tip->nHeight, job.block_hash.ToString(), node.GetId());
                if (coord.replay_tip->GetBlockHash() == coord.pindex_fork->GetBlockHash()) {
                    HandleReplayReachedFork(coord);
                }
            }
            return true;
        }

        if (coord.forward_pos >= coord.forward_blocks.size()) {
            LOCK(cs_main);
            if (!coord.temp_view || !ReplayChainMembershipOk(m_host.chainman, coord) ||
                !ReplayViewValid(m_host.chainman, *coord.target_index, *coord.temp_view)) {
                coord.failed = true;
                return false;
            }
            FinalizeFromTempView(coord);
            return true;
        }

        CBlockIndex* pindexConnect = coord.forward_blocks[coord.forward_blocks.size() - 1 - coord.forward_pos];
        CBlock block;
        if (!chainstate.m_blockman.ReadBlock(block, *pindexConnect)) {
            coord.failed = true;
            return false;
        }
        {
            LOCK(cs_main);
            if (!ReplayChainMembershipOk(m_host.chainman, coord) ||
                !m_host.chainman.ActiveChain().Contains(*pindexConnect)) {
                coord.failed = true;
                return false;
            }
            EnsureCoordinatorTempView(chainstate, coord);
            BlockValidationState state;
            if (!chainstate.ConnectBlock(block, state, pindexConnect, *coord.temp_view, /*fJustCheck=*/true)) {
                coord.failed = true;
                return false;
            }
            ++coord.forward_pos;
            LogDebug(BCLog::NET, "MWEB serve replay step: forward height=%d target=%s peer=%d\n",
                     pindexConnect->nHeight, job.block_hash.ToString(), node.GetId());
            if (coord.forward_pos >= coord.forward_blocks.size()) {
                if (!ReplayViewValid(m_host.chainman, *coord.target_index, *coord.temp_view)) {
                    coord.failed = true;
                    return false;
                }
                FinalizeFromTempView(coord);
                job.snapshot = coord.snapshot;
            }
        }
        return true;
    }

    if (coord.phase == MWEBServeJob::Phase::BUILD_SEND) {
        if (!coord.snapshot) {
            BeginFinalizeMaterialize(coord);
            if (coord.failed) {
                return false;
            }
            // Materialize started — keep the job alive so ProcessOneStep can
            // adopt MATERIALIZE_CHUNK and drive ProcessCoordinatorStep.
            if (!coord.snapshot) {
                return true;
            }
        }
        job.snapshot = coord.snapshot;
        return true;
    }

    return true;
}

bool MWEBServeEngine::ProcessOneStep(CNode& node, MWEBServePeerState& peer)
{
    if (peer.m_mweb_serve_jobs.empty()) return false;

    MWEBServeJob& job{peer.m_mweb_serve_jobs.front()};
    MWEBWorkBudget budget{m_host.material_byte_budget, m_host.material_leaf_ops};

    // BUILD_SEND must not idle while the coordinator is materializing (or
    // otherwise still working). Previously ProcessCoordinatorStep was skipped
    // whenever job.phase==BUILD_SEND, so BeginFinalizeMaterialize left
    // materialize_active with job.phase stuck on BUILD_SEND → permanent busy loop.
    if (job.phase == MWEBServeJob::Phase::BUILD_SEND && !job.snapshot && job.coordinator &&
        job.type != MWEBServeJob::Type::HEADER) {
        if (job.coordinator->materialize_active ||
            job.coordinator->phase == MWEBServeJob::Phase::MATERIALIZE_CHUNK ||
            (job.coordinator->phase != MWEBServeJob::Phase::BUILD_SEND &&
             job.coordinator->phase != MWEBServeJob::Phase::INIT)) {
            job.phase = job.coordinator->phase;
        }
    }

    if (job.phase == MWEBServeJob::Phase::INIT) {
        job.snapshot = GetMWEBHistoricalViewCache().Lookup(job.block_hash);
        if (job.snapshot) {
            LogDebug(BCLog::NET, "MWEB serve cache hit: height=%d peer=%d hash=%s\n",
                     job.snapshot->height, node.GetId(), job.block_hash.ToString());
            job.phase = MWEBServeJob::Phase::BUILD_SEND;
        } else {
            LogDebug(BCLog::NET, "MWEB serve cache miss: peer=%d hash=%s\n",
                     node.GetId(), job.block_hash.ToString());
            const CBlockIndex* pindex{nullptr};
            if (!ValidateServeBlock(node, job.block_hash, job.type == MWEBServeJob::Type::HEADER, &pindex)) {
                FinishServeJob(peer, m_host.global_jobs);
                return true;
            }
            if (job.type == MWEBServeJob::Type::HEADER) {
                job.phase = MWEBServeJob::Phase::BUILD_SEND;
            } else if (!job.coordinator) {
                job.coordinator = GetMWEBServeCoordinator().AttachOrCreate(job.block_hash);
            }
            if (job.type != MWEBServeJob::Type::HEADER) {
            MWEBServeCoordinatorJob& coord{*job.coordinator};
            if (coord.snapshot) {
                job.snapshot = coord.snapshot;
                job.phase = MWEBServeJob::Phase::BUILD_SEND;
            } else if (coord.cancelled || coord.failed) {
                FinishServeJob(peer, m_host.global_jobs);
                return true;
            } else if (coord.target_index) {
                job.phase = coord.phase;
            } else {
                LOCK(cs_main);
                pindex = m_host.chainman.m_blockman.LookupBlockIndex(job.block_hash);
                if (!pindex || !m_host.chainman.ActiveChain().Contains(*pindex)) {
                    FinishServeJob(peer, m_host.global_jobs);
                    return true;
                }
                coord.target_index = const_cast<CBlockIndex*>(pindex);
                auto& chainstate{m_host.chainman.ActiveChainstate()};
                if (const auto tip_mweb{chainstate.CoinsTip().GetMWEBCacheView()}) {
                    coord.mweb_replay_view = std::make_shared<mw::CoinsViewCache>(tip_mweb);
                }
                coord.replay_tip = m_host.chainman.ActiveChain().Tip();
                coord.source_tip = coord.replay_tip;
                coord.pindex_fork = m_host.chainman.ActiveChain().FindFork(*coord.target_index);
                coord.forward_blocks.clear();
                coord.forward_pos = 0;
                const bool target_is_tip{
                    coord.replay_tip->GetBlockHash() == coord.target_index->GetBlockHash()};
                if (target_is_tip) {
                    coord.phase = MWEBServeJob::Phase::BUILD_SEND;
                } else if (coord.replay_tip->GetBlockHash() == coord.pindex_fork->GetBlockHash()) {
                    for (CBlockIndex* it = coord.target_index;
                         it && it->nHeight != coord.replay_tip->nHeight;
                         it = it->pprev) {
                        coord.forward_blocks.push_back(it);
                    }
                    coord.phase = MWEBServeJob::Phase::REPLAY_FORWARD;
                } else {
                    coord.phase = MWEBServeJob::Phase::REPLAY_BACK;
                }
                job.phase = coord.phase;
            }
            }
        }
    }

    if (job.coordinator && job.phase != MWEBServeJob::Phase::BUILD_SEND && job.phase != MWEBServeJob::Phase::INIT) {
        std::unique_lock<Mutex> replay_lock{m_host.replay_mutex, std::try_to_lock};
        if (!replay_lock.owns_lock()) {
            return true;
        }
        if (!ProcessCoordinatorStep(node, peer, job, *job.coordinator, budget)) {
            LogDebug(BCLog::NET, "MWEB serve coordinator done: peer=%d hash=%s failed=%d cancelled=%d\n",
                     node.GetId(), job.block_hash.ToString(),
                     job.coordinator->failed, job.coordinator->cancelled);
            FinishServeJob(peer, m_host.global_jobs);
            return true;
        }
        job.phase = job.coordinator->snapshot ? MWEBServeJob::Phase::BUILD_SEND : job.coordinator->phase;
        job.snapshot = job.coordinator->snapshot;
    }

    if (job.phase == MWEBServeJob::Phase::BUILD_SEND) {
        if (!job.snapshot && job.type != MWEBServeJob::Type::HEADER && job.coordinator && job.coordinator->target_index) {
            MWEBServeCoordinatorJob& coord{*job.coordinator};
            LOCK(cs_main);
            if (!ReplayChainMembershipOk(m_host.chainman, coord)) {
                coord.failed = true;
            } else if (coord.temp_view &&
                       coord.replay_tip->GetBlockHash() == coord.target_index->GetBlockHash() &&
                       ReplayViewValid(m_host.chainman, *coord.target_index, *coord.temp_view)) {
                FinalizeFromTempView(coord);
            } else if (coord.mweb_replay_view) {
                FinalizeFromReplayView(coord);
            } else if (coord.temp_view && ReplayViewValid(m_host.chainman, *coord.target_index, *coord.temp_view)) {
                BeginFinalizeMaterialize(coord);
            }
            job.snapshot = coord.snapshot;
        }
        if (!job.snapshot && job.type != MWEBServeJob::Type::HEADER) {
            if (job.coordinator &&
                (job.coordinator->materialize_active ||
                 job.coordinator->phase == MWEBServeJob::Phase::MATERIALIZE_CHUNK)) {
                // Adopt coordinator phase so the next step drives materialize
                // (same-step sync at the top of ProcessOneStep also covers this).
                job.phase = job.coordinator->phase;
                return true;
            }
            FinishServeJob(peer, m_host.global_jobs);
            return true;
        }
        if (g_mweb_serve_inject_bad_cache && job.start_index == 0 &&
            job.type == MWEBServeJob::Type::UTXOS) {
            LogDebug(BCLog::NET,
                     "MWEB serve internal error: injected fault peer=%d hash=%s (no ban)\n",
                     node.GetId(), job.block_hash.ToString());
            FinishServeJob(peer, m_host.global_jobs);
            return true;
        }
        if (BuildAndSend(node, job)) {
            FinishServeJob(peer, m_host.global_jobs);
        }
        return true;
    }

    return true;
}

void MWEBServeEngine::EnqueueLeafset(CNode& pfrom, MWEBServePeerState& peer, const CInv& inv)
{
    const CBlockIndex* pindex{nullptr};
    if (!ValidateServeBlock(pfrom, inv.hash, /*header_request=*/false, &pindex)) {
        return;
    }

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::LEAFSET;
    job.block_hash = inv.hash;
    // Never ToDynamicBitSet before TryEnqueue — cache-hit GETDATA spam on a full
    // queue used to build the full bitset for free. Price hit and miss from the same
    // header GetNumTXOs bit-pack hint (may overcharge vs unspent bitset; intentional).
    size_t leafset_bytes{0};
    if (pindex->mweb_header) {
        leafset_bytes = (pindex->mweb_header->GetNumTXOs() + 7) / 8;
    }
    const bool cache_hit{static_cast<bool>(GetMWEBHistoricalViewCache().Lookup(inv.hash))};
    double cost{CreditCost(job, leafset_bytes)};
    if (!cache_hit) {
        // Miss induces replay/materialize — charge explicit surcharge.
        cost += MWEB_SERVE_MATERIALIZE_SURCHARGE;
    }
    TryEnqueue(pfrom, peer, std::move(job), cost);
}

void MWEBServeEngine::EnqueueUTXOs(CNode& pfrom, MWEBServePeerState& peer, const GetMWEBUTXOsMsg& get_utxos)
{
    // Reject zero before ValidateServeBlock/TryEnqueue: cost would be 0 credits
    // yet the job still occupies queue slots and can drive historical replay (zero-request enqueue guard).
    // Litecoin rewinds before disconnecting on num_requested==0; rejecting first is an intentional divergence.
    if (get_utxos.num_requested == 0) {
        LogDebug(BCLog::NET, "getmwebutxos num_requested 0, disconnect peer=%d\n", pfrom.GetId());
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan)) {
            pfrom.fDisconnect = true;
        }
        return;
    }
    if (get_utxos.num_requested > MAX_REQUESTED_MWEB_UTXOS) {
        LogDebug(BCLog::NET, "getmwebutxos num_requested %u > %u, disconnect peer=%d\n",
                 get_utxos.num_requested, MAX_REQUESTED_MWEB_UTXOS, pfrom.GetId());
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan)) {
            pfrom.fDisconnect = true;
        }
        return;
    }

    static const std::set<uint8_t> supported_formats{
        NetUTXO::HASH_ONLY,
        NetUTXO::FULL_UTXO,
        NetUTXO::COMPACT_UTXO,
    };
    if (!supported_formats.contains(get_utxos.output_format)) {
        LogDebug(BCLog::NET, "getmwebutxos output_format %u not supported, disconnect peer=%d\n",
                 get_utxos.output_format, pfrom.GetId());
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan)) {
            pfrom.fDisconnect = true;
        }
        return;
    }

    const CBlockIndex* pindex{nullptr};
    if (!ValidateServeBlock(pfrom, get_utxos.block_hash, /*header_request=*/false, &pindex)) {
        return;
    }

    // start_index is an output MMR leaf index, so it must be below GetNumTXOs(); whether the
    // leaf is unspent is checked in BuildAndSend. Litecoin fails only after rewind; the early
    // reject is an intentional peer-policy divergence.
    if (pindex->mweb_header &&
        get_utxos.start_index >= pindex->mweb_header->GetNumTXOs()) {
        LogDebug(BCLog::NET,
                 "getmwebutxos start_index %llu >= num_txos %llu, disconnect peer=%d\n",
                 get_utxos.start_index, pindex->mweb_header->GetNumTXOs(), pfrom.GetId());
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan)) {
            pfrom.fDisconnect = true;
        }
        return;
    }

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::UTXOS;
    job.block_hash = get_utxos.block_hash;
    job.start_index = get_utxos.start_index;
    job.num_requested = get_utxos.num_requested;
    job.output_format = get_utxos.output_format;
    double cost{CreditCost(job)};
    if (!GetMWEBHistoricalViewCache().Lookup(job.block_hash)) {
        // Miss induces replay/materialize — charge explicit surcharge.
        cost += MWEB_SERVE_MATERIALIZE_SURCHARGE;
    }
    TryEnqueue(pfrom, peer, std::move(job), cost);
}

void MWEBServeEngine::EnqueueHeader(CNode& pfrom, MWEBServePeerState& peer, const CInv& inv)
{
    const CBlockIndex* pindex{nullptr};
    // Pre-MWEB header requests are ignored without disconnect (see mweb_p2p.py).
    if (!ValidateServeBlock(pfrom, inv.hash, /*header_request=*/true, &pindex)) {
        return;
    }

    // Conservative serialized-size proxy for credit pricing. CBlockIndex
    // does not store nSize; prefer overcharge via nTx + MWEB output count.
    size_t block_bytes_hint{4096};
    block_bytes_hint += static_cast<size_t>(pindex->nTx) * 300;
    if (pindex->mweb_header) {
        block_bytes_hint += pindex->mweb_header->GetNumTXOs() * 64;
    }

    MWEBServeJob job;
    job.type = MWEBServeJob::Type::HEADER;
    job.block_hash = inv.hash;
    const double credit_cost{CreditCost(job, block_bytes_hint)};
    TryEnqueue(pfrom, peer, std::move(job), credit_cost);
}

} // namespace node
