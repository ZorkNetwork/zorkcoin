// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SERVE_COORDINATOR_H
#define BITCOIN_NODE_MWEB_SERVE_COORDINATOR_H

#include <node/mweb_serve_types.h>

#include <coins.h>
#include <kernel/cs_main.h>
#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/hasher.h>

#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

class CBlockIndex;
class ChainstateManager;

namespace node {

/** Shared in-flight miss/warm state for one block hash (I14). */
struct MWEBServeCoordinatorJob {
    uint256 block_hash;
    CBlockIndex* target_index{nullptr};

    MWEBServeJob::Phase phase{MWEBServeJob::Phase::INIT};
    std::unique_ptr<CCoinsViewCache> temp_view;
    mw::ICoinsView::Ptr mweb_replay_view;
    mw::MaterializeProgress materialize_progress;
    bool materialize_active{false};
    enum class MaterializePurpose { NONE, TIP_ISOLATE, FINALIZE };
    MaterializePurpose materialize_purpose{MaterializePurpose::NONE};

    CBlockIndex* replay_tip{nullptr};
    const CBlockIndex* pindex_fork{nullptr};
    //! Chain tip that temp_view and mweb_replay_view read through to.
    const CBlockIndex* source_tip{nullptr};
    std::vector<CBlockIndex*> forward_blocks;
    size_t forward_pos{0};

    MWEBHistoricalSnapshotPtr snapshot;
    bool failed{false};
    bool cancelled{false};
};

class MWEBServeCoordinator
{
public:
    std::shared_ptr<MWEBServeCoordinatorJob> AttachOrCreate(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void CancelNotOnActiveChain(const ChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_mutex);

    void PruneCompleted() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t ActiveCount() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Test-only: count active coordinators for block hash. */
    bool HasActive(const uint256& block_hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    const SaltedUint256Hasher m_hasher;
    mutable Mutex m_mutex;
    std::unordered_map<uint256, std::shared_ptr<MWEBServeCoordinatorJob>, SaltedUint256Hasher> m_jobs GUARDED_BY(m_mutex);
};

MWEBServeCoordinator& GetMWEBServeCoordinator();

} // namespace node

#endif // BITCOIN_NODE_MWEB_SERVE_COORDINATOR_H
