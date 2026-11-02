// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_MATERIALIZE_H
#define BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_MATERIALIZE_H

#include <mw/node/coins_view.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

MW_NAMESPACE

/** Per-turn materialize budget (I11). */
struct MaterializeBudget {
    size_t max_leaf_ops{64};
    size_t max_bytes{65536};
};

/** Stepped materialize state; resumes across ProcessMessages turns. */
struct MaterializeProgress {
    enum class Phase {
        INIT,
        LEAFSET_BYTES,
        PMMR_HASHES, // AssumeUTXO: copy node hashes (CloneStructure)
        PMMR_LEAVES,
        UTXO_LEAVES,
        DONE,
    };

    Phase phase{Phase::INIT};
    bool assumeutxo_snapshot{false};
    mw::Header::CPtr header;
    mw::ICoinsView::CPtr source;

    uint64_t cursor{0};
    std::vector<uint8_t> leafset_bytes;
    /** Full leafset serialization captured once in INIT; LEAFSET_BYTES streams from this. */
    std::vector<uint8_t> leafset_src_bytes;
    uint64_t leafset_total_bytes{0};
    uint64_t leafset_bit_count{0};
    uint64_t pmmr_total_leaves{0};
    uint64_t pmmr_total_nodes{0};
    uint64_t utxo_next_leaf{0};

    ILeafSet::Ptr built_leafset;
    IMMR::Ptr built_pmmr;
    std::unordered_map<mw::Hash, UTXO::CPtr> built_utxos;
    std::vector<mw::Hash> partial_hashes;
};

void MaterializeProgressBegin(MaterializeProgress& progress, const ICoinsView& source, bool assumeutxo_snapshot);

/** One budgeted step. Returns true when `out` is ready. */
bool MaterializeStep(MaterializeProgress& progress, const MaterializeBudget& budget, CoinsViewMemory::Ptr& out);

/** MaterializeStep that restarts a failed dense copy of the same source as a sparse
 *  (AssumeUTXO) copy, for sources whose spent leaf payloads are pruned. Throws if the
 *  sparse copy fails too. */
bool MaterializeStepWithSparseFallback(MaterializeProgress& progress, const MaterializeBudget& budget, CoinsViewMemory::Ptr& out);

END_NAMESPACE

#endif // BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_MATERIALIZE_H
