// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_leafdb_sync.h>

#include <chain.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <validation.h>

#include <mw/db/leaf_db.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>

#include <vector>

namespace node {
namespace {

constexpr char OUTPUT_PMMR_DB_PREFIX = 'O';

bool LeafPayloadPresent(const mw::ICoinsView& view, const mmr::LeafIndex& idx)
{
    const auto pmmr = view.GetOutputPMMR();
    if (!pmmr) return false;
    return pmmr->HasLeafPayload(idx);
}

} // namespace

std::optional<int> LeafCreateHeight(const CChain& chain, uint64_t leaf_index)
{
    // Binary search for the lowest height whose MWEB header has num_txos > leaf_index.
    int lo = 0;
    int hi = chain.Height();
    if (hi < 0) return std::nullopt;

    std::optional<int> found;
    while (lo <= hi) {
        const int mid = lo + (hi - lo) / 2;
        const CBlockIndex* pindex = chain[mid];
        if (!pindex || !pindex->mweb_header) {
            lo = mid + 1;
            continue;
        }
        if (pindex->mweb_header->GetNumTXOs() > leaf_index) {
            found = mid;
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return found;
}

bool NeedsSparseMaterialize(const mw::ICoinsView& view)
{
    const auto leafset = view.GetLeafSet();
    const auto pmmr = view.GetOutputPMMR();
    if (!leafset || !pmmr) return true;

    const mmr::LeafIndex end = leafset->GetNextLeafIdx();
    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < end; ++idx) {
        if (leafset->Contains(idx)) continue;
        if (!pmmr->HasLeafPayload(idx)) {
            return true;
        }
    }
    return false;
}

MWEBLeafDBSyncStats CopySpentLeafPayloads(
    const mw::ICoinsView& background_view,
    mw::ICoinsView& active_view,
    const CChain& chain,
    std::optional<int> min_create_height)
{
    MWEBLeafDBSyncStats stats;
    const auto bg_leafset = background_view.GetLeafSet();
    const auto bg_pmmr = background_view.GetOutputPMMR();
    const auto& active_db = active_view.GetDatabase();
    if (!bg_leafset || !bg_pmmr || !active_db) {
        return stats;
    }

    // Prefer the active leafset (snapshot tip state) so we only backfill spent slots.
    const auto active_leafset = active_view.GetLeafSet() ? active_view.GetLeafSet() : bg_leafset;
    const mmr::LeafIndex end = active_leafset->GetNextLeafIdx();

    std::vector<mmr::Leaf> to_add;
    to_add.reserve(64);

    auto flush_batch = [&]() {
        if (to_add.empty()) return;
        auto batch = active_db->CreateBatch();
        LeafDB dst(OUTPUT_PMMR_DB_PREFIX, active_db.get(), batch.get());
        dst.Add(to_add);
        batch->Commit();
        to_add.clear();
    };

    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < end; ++idx) {
        ++stats.examined;
        if (active_leafset->Contains(idx)) {
            ++stats.skipped_unspent;
            continue;
        }
        if (LeafPayloadPresent(active_view, idx)) {
            ++stats.skipped_already_present;
            continue;
        }
        if (min_create_height) {
            const auto create_h = LeafCreateHeight(chain, idx.Get());
            if (!create_h || *create_h < *min_create_height) {
                ++stats.skipped_below_min_height;
                continue;
            }
        }
        if (!bg_pmmr->HasLeafPayload(idx)) {
            ++stats.skipped_missing_source;
            continue;
        }
        try {
            to_add.push_back(bg_pmmr->GetLeaf(idx));
            ++stats.copied;
        } catch (const std::exception&) {
            ++stats.skipped_missing_source;
            continue;
        }
        if (to_add.size() >= 256) {
            flush_batch();
        }
    }
    flush_batch();
    return stats;
}

MWEBLeafDBSyncStats PruneSpentLeafPayloads(
    mw::ICoinsView& active_view,
    const CChain& chain,
    int min_retain_height)
{
    MWEBLeafDBSyncStats stats;
    const auto leafset = active_view.GetLeafSet();
    const auto pmmr = active_view.GetOutputPMMR();
    const auto& active_db = active_view.GetDatabase();
    if (!leafset || !pmmr || !active_db) {
        return stats;
    }

    const mmr::LeafIndex end = leafset->GetNextLeafIdx();
    std::vector<mmr::LeafIndex> to_remove;
    to_remove.reserve(64);

    auto flush_batch = [&]() {
        if (to_remove.empty()) return;
        auto batch = active_db->CreateBatch();
        LeafDB dst(OUTPUT_PMMR_DB_PREFIX, active_db.get(), batch.get());
        dst.Remove(to_remove);
        batch->Commit();
        stats.removed += to_remove.size();
        to_remove.clear();
    };

    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < end; ++idx) {
        ++stats.examined;
        if (leafset->Contains(idx)) {
            ++stats.skipped_unspent;
            continue;
        }
        if (!pmmr->HasLeafPayload(idx)) {
            continue;
        }
        const auto create_h = LeafCreateHeight(chain, idx.Get());
        if (!create_h || *create_h >= min_retain_height) {
            continue;
        }
        to_remove.push_back(idx);
        if (to_remove.size() >= 256) {
            flush_batch();
        }
    }
    flush_batch();
    return stats;
}

MWEBLeafDBSyncStats BackfillSpentLeafPayloadsAfterSnapshotValidation(
    ChainstateManager& chainman,
    const mw::ICoinsView& background_view,
    mw::ICoinsView& active_view)
{
    AssertLockHeld(::cs_main);
    std::optional<int> min_create_height;
    if (chainman.m_blockman.IsPruneMode()) {
        const CChain& chain = chainman.ActiveChain();
        if (chain.Tip()) {
            // Retain payloads for leaves created at/after the first block that still has data.
            const CBlockIndex& first_have{
                chainman.m_blockman.GetFirstBlock(*chain.Tip(), BLOCK_HAVE_DATA)};
            min_create_height = first_have.nHeight;
        }
    }
    const auto stats = CopySpentLeafPayloads(
        background_view, active_view, chainman.ActiveChain(), min_create_height);
    LogInfo("[snapshot] MWEB spent LeafDB backfill: examined=%u copied=%u skipped_unspent=%u "
            "skipped_present=%u skipped_below_height=%u skipped_missing_src=%u min_create_height=%s\n",
            stats.examined, stats.copied, stats.skipped_unspent, stats.skipped_already_present,
            stats.skipped_below_min_height, stats.skipped_missing_source,
            min_create_height ? strprintf("%d", *min_create_height) : "none");
    return stats;
}

MWEBLeafDBSyncStats PruneSpentLeafPayloadsToBlockFloor(
    ChainstateManager& chainman,
    mw::ICoinsView& active_view)
{
    AssertLockHeld(::cs_main);
    if (!chainman.m_blockman.IsPruneMode()) {
        return {};
    }
    const CChain& chain = chainman.ActiveChain();
    if (!chain.Tip()) {
        return {};
    }
    const CBlockIndex& first_have{
        chainman.m_blockman.GetFirstBlock(*chain.Tip(), BLOCK_HAVE_DATA)};
    const auto stats = PruneSpentLeafPayloads(active_view, chain, first_have.nHeight);
    if (stats.removed > 0) {
        LogInfo("[prune] MWEB spent LeafDB GC: removed=%u examined=%u min_retain_height=%d\n",
                stats.removed, stats.examined, first_have.nHeight);
    }
    return stats;
}

} // namespace node
