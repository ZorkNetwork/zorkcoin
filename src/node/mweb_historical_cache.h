// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_HISTORICAL_CACHE_H
#define BITCOIN_NODE_MWEB_HISTORICAL_CACHE_H

#include <node/mweb_serve_types.h>
#include <kernel/cs_main.h>
#include <sync.h>

#include <mw/models/tx/utxo.h>
#include <mw/mmr/leaf_index.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/node/coins_view_materialize.h>

#include <deque>
#include <memory>
#include <optional>
#include <unordered_map>
#include <uint256.h>

class CBlock;
class CBlockIndex;
class Chainstate;
class ChainstateManager;

namespace node {

/**
 * Ring buffer of refcounted immutable MWEB snapshots (tip … tip−MAX_MWEB_LEAFSET_DEPTH).
 *
 * Invariants (see doc/MWEB_P2P_RATE_LIMIT_PLAN_V2.md):
 * - Lookup returns shared_ptr; eviction cannot destroy in-flight snapshots (I1).
 * - Every ring entry's view is a CoinsViewMemory (frozen historical views): never a CoinsViewCache /
 *   LeafSetCache over the live tip — tip connect would otherwise mutate served
 *   leafset/UTXO data for historical hashes.
 * - Publish from parent is O(block) ApplyBlock then freeze (I4 + frozen historical views).
 * - Empty/sparse cache is filled by miss-path jobs and by budgeted window warm via
 *   ProcessBackgroundWork — never a synchronous full bootstrap on connect (I3).
 */
class MWEBHistoricalViewCache
{
public:
    /** Publish snapshot for a newly connected MWEB block (incremental from parent only). */
    void Publish(const CBlockIndex* pindex, const CBlock& block)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_mutex);

    /** Remove cache slots not on the active chain. In-flight shared_ptrs remain valid. */
    void PruneToActiveChain(const ChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_mutex);

    /** Look up a snapshot by block hash. Caller must not hold cs_main. */
    MWEBHistoricalSnapshotPtr Lookup(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Store a snapshot produced by miss-path replay / warm.
     * Non-CoinsViewMemory views are deep-copied (frozen historical views); live tip overlays must
     * never enter the ring.
     */
    void Store(MWEBHistoricalSnapshotPtr snapshot) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Queue stepped AssumeUTXO warm (I13). Caller holds cs_main. Source is frozen to an
     * owned CoinsViewMemory at schedule (frozen historical views) so ProcessOneAssumeUTXOWarmStep never
     * reads a Flush-mutable DB/tip overlay; budgeted MaterializeStep runs later.
     */
    bool ScheduleAssumeUTXOWarm(const CBlockIndex& pindex, const mw::ICoinsView::Ptr& source)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_mutex);

    /** One bounded warm step; returns true if more steps remain. Must not hold cs_main. */
    bool ProcessOneAssumeUTXOWarmStep() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool HasPendingAssumeUTXOWarm() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Queue budgeted undo-fill of [tip − depth, tip] (budgeted window warm / I3).
     * Caller must not schedule during IBD. Tip seed is frozen under cs_main into the
     * ring when cold; background steps are undo-only from frozen snaps. Never
     * retains a live tip CoinsViewCache for async MaterializeStep.
     */
    bool MaybeScheduleWindowWarm(ChainstateManager& chainman, const CBlockIndex& tip,
                                 const mw::ICoinsView::Ptr& tip_mweb_view)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_mutex);

    /**
     * One bounded window-warm undo step. Returns true if more work remains.
     * Must not hold cs_main. Brief cs_main only for chain membership / undo reads.
     */
    bool ProcessOneWindowWarmStep(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool HasPendingWindowWarm() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Clear all ring slots (tests only). In-flight shared_ptrs remain valid. */
    void ClearForTest() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct Stats {
        uint64_t hits{0};
        uint64_t misses{0};
        size_t entries{0};
    };
    Stats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void ResetStats() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct AssumeUTXOWarmPending {
        uint256 block_hash;
        int height{0};
        mw::Header::CPtr header;
        mw::ICoinsView::Ptr source;
        mw::MaterializeProgress progress;
        bool started{false};
    };

    struct WindowWarmPending {
        uint256 tip_hash;
        int tip_height{0};
        int min_height{0};
        /** Height of the next snapshot to produce by undoing from tip_height downward. */
        int next_undo_height{-1};
    };

    mutable Mutex m_mutex;
    std::deque<MWEBHistoricalSnapshotPtr> m_ring GUARDED_BY(m_mutex);
    mutable Stats m_stats GUARDED_BY(m_mutex);
    std::unique_ptr<AssumeUTXOWarmPending> m_assumeutxo_warm GUARDED_BY(m_mutex);
    std::unique_ptr<WindowWarmPending> m_window_warm GUARDED_BY(m_mutex);

    void InsertLocked(MWEBHistoricalSnapshotPtr snapshot) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    MWEBHistoricalSnapshotPtr FindLocked(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool WindowCompleteLocked(const CBlockIndex& tip, int min_height) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex, ::cs_main);
};

MWEBHistoricalViewCache& GetMWEBHistoricalViewCache();

/** Test instrumentation for FreezeHistoricalView path selection (no RPC). */
struct FreezePathStats {
    uint64_t dense_attempts{0};
    uint64_t sparse_direct{0};
    uint64_t dense_fallback_to_sparse{0};
};
void ResetFreezePathStatsForTest();
FreezePathStats GetFreezePathStatsForTest();

} // namespace node

#endif // BITCOIN_NODE_MWEB_HISTORICAL_CACHE_H
