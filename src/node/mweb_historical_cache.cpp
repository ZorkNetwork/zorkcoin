// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_historical_cache.h>

#include <algorithm>
#include <atomic>
#include <chain.h>
#include <chrono>
#include <logging.h>
#include <mweb/mweb_node.h>
#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>
#include <node/mweb_leafdb_sync.h>
#include <primitives/block.h>
#include <undo.h>
#include <validation.h>

namespace node {

namespace {

MWEBHistoricalViewCache g_mweb_historical_cache;

} // namespace

std::atomic<uint64_t> g_freeze_dense_attempts{0};
std::atomic<uint64_t> g_freeze_sparse_direct{0};
std::atomic<uint64_t> g_freeze_dense_fallback_to_sparse{0};

namespace {

bool VerifySnapshotRoots(const CBlockIndex& pindex, const mw::ICoinsView& view)
{
    mw::Header::CPtr header{pindex.mweb_header};
    if (!header) {
        return false;
    }
    return MWEB::Node::VerifyChainstateRoots(*header, view);
}

bool VerifySnapshotRoots(const mw::Header::CPtr& header, const mw::ICoinsView& view)
{
    if (!header) {
        return false;
    }
    return MWEB::Node::VerifyChainstateRoots(*header, view);
}

/** Historical cache entries must be parent-free CoinsViewMemory.
 *
 * When spent leaf payloads are missing (AssumeUTXO / LeafDB GC), use sparse
 * materialize directly — do not attempt dense Materialize first (avoids
 * throw/retry on every tip Publish). Dense Materialize when all payloads exist.
 * Throw/catch remains last-resort safety only.
 *
 * ScheduleAssumeUTXOWarm still calls MaterializeAssumeUTXOSnapshot directly. */
mw::ICoinsView::Ptr FreezeHistoricalView(mw::ICoinsView::Ptr view)
{
    if (!view) return nullptr;
    if (std::dynamic_pointer_cast<mw::CoinsViewMemory>(view)) {
        return view;
    }
    if (NeedsSparseMaterialize(*view)) {
        ++g_freeze_sparse_direct;
        try {
            return mw::CoinsViewMemory::MaterializeAssumeUTXOSnapshot(*view);
        } catch (const std::exception& e) {
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: sparse MaterializeAssumeUTXOSnapshot failed: %s\n",
                     e.what());
            return nullptr;
        }
    }
    ++g_freeze_dense_attempts;
    try {
        return mw::CoinsViewMemory::Materialize(*view);
    } catch (const std::exception& e) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: Materialize failed (%s); trying AssumeUTXO clone\n",
                 e.what());
        ++g_freeze_dense_fallback_to_sparse;
    }
    try {
        return mw::CoinsViewMemory::MaterializeAssumeUTXOSnapshot(*view);
    } catch (const std::exception& e) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: MaterializeAssumeUTXOSnapshot failed: %s\n", e.what());
    }
    return nullptr;
}

} // namespace

void ResetFreezePathStatsForTest()
{
    g_freeze_dense_attempts.store(0);
    g_freeze_sparse_direct.store(0);
    g_freeze_dense_fallback_to_sparse.store(0);
}

FreezePathStats GetFreezePathStatsForTest()
{
    return {
        g_freeze_dense_attempts.load(),
        g_freeze_sparse_direct.load(),
        g_freeze_dense_fallback_to_sparse.load(),
    };
}

MWEBHistoricalViewCache& GetMWEBHistoricalViewCache()
{
    return g_mweb_historical_cache;
}

MWEBHistoricalSnapshotPtr MWEBHistoricalViewCache::FindLocked(const uint256& hash) const
{
    for (const auto& entry : m_ring) {
        if (entry && entry->block_hash == hash) return entry;
    }
    return nullptr;
}

void MWEBHistoricalViewCache::InsertLocked(MWEBHistoricalSnapshotPtr snapshot)
{
    assert(snapshot && snapshot->view);
    if (auto existing = FindLocked(snapshot->block_hash)) {
        for (auto& entry : m_ring) {
            if (entry && entry->block_hash == snapshot->block_hash) {
                entry = std::move(snapshot);
                return;
            }
        }
    }
    m_ring.push_back(std::move(snapshot));
    while (m_ring.size() > static_cast<size_t>(MAX_MWEB_LEAFSET_DEPTH)) {
        m_ring.pop_front();
    }
    m_stats.entries = m_ring.size();
}

void MWEBHistoricalViewCache::Publish(const CBlockIndex* pindex, const CBlock& block)
{
    AssertLockHeld(cs_main);
    if (!pindex || !(pindex->nStatus & BLOCK_HAVE_MWEB) || block.mweb_block.IsNull()) {
        return;
    }
    const CBlockIndex* pprev = pindex->pprev;
    if (!pprev) return;

    MWEBHistoricalSnapshotPtr parent;
    {
        LOCK(m_mutex);
        parent = FindLocked(pprev->GetBlockHash());
    }
    // No parent: leave empty. Miss-path jobs fill the cache (I3 — no megastep bootstrap).
    if (!parent || !parent->view) return;

    const auto publish_start{std::chrono::steady_clock::now()};

    auto child = std::make_shared<mw::CoinsViewCache>(parent->view);
    try {
        child->ApplyBlock(block.mweb_block.m_block, /*allow_historical_metadata_mismatch=*/false);
    } catch (const std::exception& e) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: ApplyBlock failed for %s: %s\n",
                 pindex->GetBlockHash().ToString(), e.what());
        return;
    }

    if (!VerifySnapshotRoots(*pindex, *child)) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: Publish MMR mismatch for %s\n",
                 pindex->GetBlockHash().ToString());
        return;
    }

    // Freeze before insert — CoinsViewCache over parent must not stay in the ring.
    auto frozen = FreezeHistoricalView(std::move(child));
    if (!frozen || !VerifySnapshotRoots(*pindex, *frozen)) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: Publish freeze/roots failed for %s\n",
                 pindex->GetBlockHash().ToString());
        return;
    }

    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = pindex->GetBlockHash();
    snapshot->height = pindex->nHeight;
    snapshot->view = std::move(frozen);

    const auto publish_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - publish_start).count()};
    const size_t leafset_bytes{snapshot->view->GetLeafSet()->ToDynamicBitSet().bytes().size()};
    LogDebug(BCLog::NET, "MWEB cache publish: height=%d ns=%d leafset_bytes=%d\n",
             pindex->nHeight, static_cast<int>(publish_ns), static_cast<int>(leafset_bytes));

    LOCK(m_mutex);
    InsertLocked(std::move(snapshot));
}

void MWEBHistoricalViewCache::PruneToActiveChain(const ChainstateManager& chainman)
{
    AssertLockHeld(cs_main);
    LOCK(m_mutex);
    std::erase_if(m_ring, [&](const MWEBHistoricalSnapshotPtr& entry) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (!entry) return true;
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(entry->block_hash);
        return !pindex || !chainman.ActiveChain().Contains(*pindex);
    });
    m_stats.entries = m_ring.size();
}

MWEBHistoricalSnapshotPtr MWEBHistoricalViewCache::Lookup(const uint256& block_hash)
{
    LOCK(m_mutex);
    if (auto entry = FindLocked(block_hash)) {
        ++m_stats.hits;
        return entry;
    }
    ++m_stats.misses;
    return nullptr;
}

void MWEBHistoricalViewCache::Store(MWEBHistoricalSnapshotPtr snapshot)
{
    if (!snapshot || !snapshot->view) return;
    auto frozen = FreezeHistoricalView(snapshot->view);
    if (!frozen) return;
    auto frozen_snap = std::make_shared<MWEBHistoricalSnapshot>();
    frozen_snap->block_hash = snapshot->block_hash;
    frozen_snap->height = snapshot->height;
    frozen_snap->view = std::move(frozen);
    LOCK(m_mutex);
    InsertLocked(std::move(frozen_snap));
}

bool MWEBHistoricalViewCache::ScheduleAssumeUTXOWarm(const CBlockIndex& pindex, const mw::ICoinsView::Ptr& source)
{
    AssertLockHeld(cs_main);
    if (!pindex.mweb_header || !source) return false;

    // Async MaterializeStep must not alias a Flush-mutable CoinsDB/tip overlay.
    // Snapshot bases may have pruned PMMR; use the AssumeUTXO clone path only here.
    mw::ICoinsView::Ptr owned{source};
    if (!std::dynamic_pointer_cast<mw::CoinsViewMemory>(source)) {
        try {
            owned = mw::CoinsViewMemory::MaterializeAssumeUTXOSnapshot(*source);
        } catch (const std::exception& e) {
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: AssumeUTXO warm freeze failed at height %d: %s\n",
                     pindex.nHeight, e.what());
            return false;
        }
    }

    LOCK(m_mutex);
    if (m_assumeutxo_warm) return true;

    auto pending = std::make_unique<AssumeUTXOWarmPending>();
    pending->block_hash = pindex.GetBlockHash();
    pending->height = pindex.nHeight;
    pending->header = pindex.mweb_header;
    pending->source = std::move(owned);
    m_assumeutxo_warm = std::move(pending);
    LogDebug(BCLog::NET, "MWEBHistoricalViewCache: scheduled AssumeUTXO warm at height %d\n",
             pindex.nHeight);
    return true;
}

bool MWEBHistoricalViewCache::HasPendingAssumeUTXOWarm() const
{
    LOCK(m_mutex);
    return m_assumeutxo_warm != nullptr;
}

bool MWEBHistoricalViewCache::ProcessOneAssumeUTXOWarmStep()
{
    const auto step_start{std::chrono::steady_clock::now()};

    std::unique_ptr<AssumeUTXOWarmPending> work;
    {
        LOCK(m_mutex);
        if (!m_assumeutxo_warm) return false;
        work = std::move(m_assumeutxo_warm);
    }

    mw::CoinsViewMemory::Ptr frozen;
    bool done{false};
    try {
        if (!work->started) {
            mw::MaterializeProgressBegin(work->progress, *work->source, /*assumeutxo_snapshot=*/true);
            work->started = true;
        }
        done = mw::MaterializeStep(work->progress, mw::MaterializeBudget{}, frozen);
    } catch (const std::exception& e) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: AssumeUTXO warm failed for %s: %s\n",
                 work->block_hash.ToString(), e.what());
        return false;
    }

    const auto step_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - step_start).count()};
    LogDebug(BCLog::NET, "MWEB cache assumeutxo warm step: height=%d phase=%d ns=%d\n",
             work->height, static_cast<int>(work->progress.phase), static_cast<int>(step_ns));

    if (!done) {
        LOCK(m_mutex);
        // Restore only if nothing newer was scheduled while we stepped.
        if (!m_assumeutxo_warm) {
            m_assumeutxo_warm = std::move(work);
        }
        return true;
    }

    if (!frozen || !VerifySnapshotRoots(work->header, *frozen)) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: AssumeUTXO warm MMR mismatch for %s\n",
                 work->block_hash.ToString());
        return false;
    }

    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = work->block_hash;
    snapshot->height = work->height;
    snapshot->view = std::move(frozen);

    LOCK(m_mutex);
    InsertLocked(std::move(snapshot));

    LogDebug(BCLog::NET, "MWEBHistoricalViewCache: warmed AssumeUTXO snapshot at height %d\n",
             work->height);
    return false;
}

MWEBHistoricalViewCache::Stats MWEBHistoricalViewCache::GetStats() const
{
    LOCK(m_mutex);
    Stats stats = m_stats;
    stats.entries = m_ring.size();
    return stats;
}

void MWEBHistoricalViewCache::ResetStats()
{
    LOCK(m_mutex);
    m_stats.hits = 0;
    m_stats.misses = 0;
}

void MWEBHistoricalViewCache::ClearForTest()
{
    LOCK(m_mutex);
    m_ring.clear();
    m_assumeutxo_warm.reset();
    m_window_warm.reset();
    m_stats.entries = 0;
}

bool MWEBHistoricalViewCache::WindowCompleteLocked(const CBlockIndex& tip, int min_height) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_mutex);
    for (const CBlockIndex* pindex = &tip; pindex && pindex->nHeight >= min_height; pindex = pindex->pprev) {
        if (!(pindex->nStatus & BLOCK_HAVE_MWEB) || !pindex->mweb_header) {
            continue;
        }
        if (!FindLocked(pindex->GetBlockHash())) {
            return false;
        }
    }
    return true;
}

bool MWEBHistoricalViewCache::MaybeScheduleWindowWarm(ChainstateManager& chainman, const CBlockIndex& tip,
                                                      const mw::ICoinsView::Ptr& tip_mweb_view)
{
    AssertLockHeld(cs_main);
    if (!tip.mweb_header || !tip_mweb_view) return false;

    const int min_height{std::max(0, tip.nHeight - MAX_MWEB_LEAFSET_DEPTH + 1)};
    const uint256 tip_hash{tip.GetBlockHash()};

    {
        LOCK(m_mutex);
        if (WindowCompleteLocked(tip, min_height)) {
            return false;
        }
        if (m_window_warm) {
            const CBlockIndex* pending_tip{
                chainman.m_blockman.LookupBlockIndex(m_window_warm->tip_hash)};
            if (pending_tip && chainman.ActiveChain().Contains(*pending_tip)) {
                // Pending tip still on active chain — leave undo job alone (I3).
                return true;
            }
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: dropping window warm after reorg of tip %s\n",
                     m_window_warm->tip_hash.ToString());
            m_window_warm.reset();
        }
        if (FindLocked(tip_hash)) {
            auto pending = std::make_unique<WindowWarmPending>();
            pending->tip_hash = tip_hash;
            pending->tip_height = tip.nHeight;
            pending->min_height = min_height;
            pending->next_undo_height = tip.nHeight;
            m_window_warm = std::move(pending);
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: scheduled window warm undo-only tip_height=%d min_height=%d\n",
                     tip.nHeight, min_height);
            return true;
        }
    }

    // Cold tip seed: one-shot freeze under cs_main into owned CoinsViewMemory.
    // Not a full-window bootstrap — undoes remain budgeted on msghand (I3).
    auto frozen = FreezeHistoricalView(tip_mweb_view);
    if (!frozen || !VerifySnapshotRoots(tip, *frozen)) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window tip freeze/roots failed for %s\n",
                 tip_hash.ToString());
        return false;
    }

    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = tip_hash;
    snapshot->height = tip.nHeight;
    snapshot->view = std::move(frozen);

    LOCK(m_mutex);
    if (WindowCompleteLocked(tip, min_height)) {
        return false;
    }
    if (m_window_warm) {
        const CBlockIndex* pending_tip{
            chainman.m_blockman.LookupBlockIndex(m_window_warm->tip_hash)};
        if (pending_tip && chainman.ActiveChain().Contains(*pending_tip)) {
            return true;
        }
        m_window_warm.reset();
    }
    InsertLocked(std::move(snapshot));
    auto pending = std::make_unique<WindowWarmPending>();
    pending->tip_hash = tip_hash;
    pending->tip_height = tip.nHeight;
    pending->min_height = min_height;
    pending->next_undo_height = tip.nHeight;
    m_window_warm = std::move(pending);
    LogDebug(BCLog::NET, "MWEBHistoricalViewCache: scheduled window warm tip_height=%d min_height=%d (frozen tip seed)\n",
             tip.nHeight, min_height);
    return true;
}

bool MWEBHistoricalViewCache::HasPendingWindowWarm() const
{
    LOCK(m_mutex);
    return m_window_warm != nullptr;
}

bool MWEBHistoricalViewCache::ProcessOneWindowWarmStep(ChainstateManager& chainman)
{
    const auto step_start{std::chrono::steady_clock::now()};

    std::unique_ptr<WindowWarmPending> work;
    {
        LOCK(m_mutex);
        if (!m_window_warm) return false;
        work = std::move(m_window_warm);
    }

    auto restore_or_drop = [&](std::unique_ptr<WindowWarmPending> pending, bool more) {
        if (!more) {
            return false;
        }
        LOCK(m_mutex);
        if (!m_window_warm) {
            m_window_warm = std::move(pending);
        }
        return true;
    };

    // Tip seed is always frozen into the ring at schedule time. Background
    // work is undo-fill only from frozen snaps — never async-reads a live tip overlay.

    // One undo step: produce snapshot for (next_undo_height - 1) from cached next_undo_height.
    if (work->next_undo_height <= work->min_height) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm complete tip_height=%d\n",
                 work->tip_height);
        return false;
    }

    const int from_height{work->next_undo_height};
    uint256 from_hash;
    uint256 parent_hash;
    int parent_height{-1};
    bool skip_only{false};
    bool abort{false};
    MWEBHistoricalSnapshotPtr from_snap;
    {
        LOCK(cs_main);
        CBlockIndex* from_index = chainman.ActiveChain()[from_height];
        if (!from_index) {
            abort = true;
        } else {
            const CBlockIndex* tip = chainman.m_blockman.LookupBlockIndex(work->tip_hash);
            if (!tip || !chainman.ActiveChain().Contains(*tip) || tip->nHeight != work->tip_height) {
                LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm aborted (tip moved/reorg)\n");
                abort = true;
            } else {
                CBlockIndex* parent_index = from_index->pprev;
                if (!parent_index || parent_index->nHeight < work->min_height) {
                    abort = true;
                } else {
                    from_hash = from_index->GetBlockHash();
                    parent_hash = parent_index->GetBlockHash();
                    parent_height = parent_index->nHeight;
                    if (!(parent_index->nStatus & BLOCK_HAVE_MWEB) || !parent_index->mweb_header) {
                        // Past the MWEB window — stop undoing.
                        parent_height = work->min_height;
                        skip_only = true;
                    } else {
                        LOCK(m_mutex);
                        from_snap = FindLocked(from_hash);
                        if (FindLocked(parent_hash)) {
                            skip_only = true;
                        }
                    }
                }
            }
        }
    }
    if (abort) {
        return false;
    }
    if (skip_only) {
        work->next_undo_height = parent_height;
        const bool more{work->next_undo_height > work->min_height};
        return restore_or_drop(std::move(work), more);
    }

    if (!from_snap || !from_snap->view) {
        // Tip should be ready; if mid-window gap, abort and let miss-path fill.
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm missing source snap at height=%d\n",
                 from_height);
        return false;
    }

    const CBlockIndex* from_index_unlocked{nullptr};
    {
        LOCK(cs_main);
        from_index_unlocked = chainman.m_blockman.LookupBlockIndex(from_hash);
        if (!from_index_unlocked || !chainman.ActiveChain().Contains(*from_index_unlocked)) {
            return false;
        }
    }

    CBlockUndo block_undo;
    if (!chainman.m_blockman.ReadBlockUndo(block_undo, *from_index_unlocked)) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm ReadBlockUndo failed height=%d\n",
                 from_height);
        return false;
    }

    mw::ICoinsView::Ptr parent_view;
    try {
        auto replay_cache = std::make_shared<mw::CoinsViewCache>(from_snap->view);
        if (block_undo.mwundo) {
            replay_cache->UndoBlock(block_undo.mwundo);
        }
        parent_view = FreezeHistoricalView(std::move(replay_cache));
        if (!parent_view) {
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm freeze failed height=%d\n",
                     parent_height);
            return false;
        }
    } catch (const std::exception& e) {
        LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm UndoBlock failed height=%d: %s\n",
                 from_height, e.what());
        return false;
    }

    {
        LOCK(cs_main);
        const CBlockIndex* parent_index = chainman.m_blockman.LookupBlockIndex(parent_hash);
        if (!parent_index || !chainman.ActiveChain().Contains(*parent_index) ||
            !VerifySnapshotRoots(*parent_index, *parent_view)) {
            LogDebug(BCLog::NET, "MWEBHistoricalViewCache: window warm parent roots/membership failed height=%d\n",
                     parent_height);
            return false;
        }
    }

    auto snapshot = std::make_shared<MWEBHistoricalSnapshot>();
    snapshot->block_hash = parent_hash;
    snapshot->height = parent_height;
    snapshot->view = std::move(parent_view);
    {
        LOCK(m_mutex);
        InsertLocked(std::move(snapshot));
    }

    const auto step_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - step_start).count()};
    LogDebug(BCLog::NET, "MWEB cache window warm undo step: from=%d to=%d ns=%d\n",
             from_height, parent_height, static_cast<int>(step_ns));

    work->next_undo_height = parent_height;
    const bool more{work->next_undo_height > work->min_height};
    return restore_or_drop(std::move(work), more);
}

} // namespace node
