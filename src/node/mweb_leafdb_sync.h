// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_LEAFDB_SYNC_H
#define BITCOIN_NODE_MWEB_LEAFDB_SYNC_H

#include <cstdint>
#include <optional>

#include <kernel/cs_main.h>
#include <mw/node/coins_view.h>
#include <threadsafety.h>

class CChain;
class ChainstateManager;

namespace node {

struct MWEBLeafDBSyncStats {
    uint64_t examined{0};
    uint64_t copied{0};
    uint64_t skipped_unspent{0};
    uint64_t skipped_already_present{0};
    uint64_t skipped_below_min_height{0};
    uint64_t skipped_missing_source{0};
    uint64_t removed{0};
};

/** First chain height whose MWEB header reports num_txos > leaf_index, or nullopt. */
std::optional<int> LeafCreateHeight(const CChain& chain, uint64_t leaf_index);

/**
 * True if any spent leaf index (in leafset range) lacks a PMMR leaf payload.
 * Used to choose sparse materialize without attempting dense Materialize first.
 */
bool NeedsSparseMaterialize(const mw::ICoinsView& view);

/**
 * Copy spent leaf payloads from background_view's LeafDB/PMMR into active_view's LeafDB.
 * Only spent indices missing on active are considered. If min_create_height is set, skip
 * leaves created below that height (prune-horizon filter).
 */
MWEBLeafDBSyncStats CopySpentLeafPayloads(
    const mw::ICoinsView& background_view,
    mw::ICoinsView& active_view,
    const CChain& chain,
    std::optional<int> min_create_height);

/**
 * Delete spent leaf payloads whose create height is strictly below min_retain_height.
 * Unspent leaves are never removed.
 */
MWEBLeafDBSyncStats PruneSpentLeafPayloads(
    mw::ICoinsView& active_view,
    const CChain& chain,
    int min_retain_height);

/** Convenience: prune-aware backfill after AssumeUTXO background validation succeeds. */
MWEBLeafDBSyncStats BackfillSpentLeafPayloadsAfterSnapshotValidation(
    ChainstateManager& chainman,
    const mw::ICoinsView& background_view,
    mw::ICoinsView& active_view) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/** Convenience: GC spent LeafDB after L1 prune advances the retained-block floor. */
MWEBLeafDBSyncStats PruneSpentLeafPayloadsToBlockFloor(
    ChainstateManager& chainman,
    mw::ICoinsView& active_view) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

} // namespace node

#endif // BITCOIN_NODE_MWEB_LEAFDB_SYNC_H
