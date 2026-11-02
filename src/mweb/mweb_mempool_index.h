// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_MEMPOOL_INDEX_H
#define BITCOIN_MWEB_MWEB_MEMPOOL_INDEX_H

//! MWEB mempool sidecar: output→creator, spent→spender, and kernel FIFO cache.
//! Owned by CTxMemPool; Core mutation paths call Add/Remove as one-liners.
//! Callers: CTxMemPool::{addNewTransaction,removeUnchecked,GetChildren,GetParents,
//! UpdateTransactionsFromBlock,check,HasNoInputsOf,GetMWEBConflictTx,removeConflicts,removeRecursive,removeMWEBConflictsForBlock,
//! DynamicMemoryUsage,ChangeSet::ProcessDependencies}, CCoinsViewMemPool::GetMWEBCoin,
//! validation DisconnectTip (recent-by-kernel), rpc/mempool depends.

#include <caches/cache.h>
#include <kernel/mempool_removal_reason.h>
#include <logging.h>
#include <memusage.h>
#include <mw/models/crypto/hash.h>
#include <primitives/transaction.h>

#include <map>
#include <optional>
#include <utility>

/** Default size of the recent-by-kernel FIFO used for reorg replay. */
static constexpr unsigned int DEFAULT_MEMPOOL_MWEB_CACHE_SIZE = 1000;

/**
 * Dual MWEB mempool maps + kernel FIFO, parameterized on the mempool entry iterator
 * type so this TU does not depend on CTxMemPool's multi_index definition.
 */
template <typename TxIter>
class MWEBMempoolIndex
{
public:
    /** Index spends and outputs created by this mempool entry. */
    void Add(TxIter it, const CTransaction& tx)
    {
        for (const mw::Hash& spent_id : tx.mweb_tx.GetSpentIDs()) {
            m_next.insert(std::make_pair(spent_id, it));
        }
        for (const mw::Hash& output_id : tx.mweb_tx.GetOutputIDs()) {
            m_outputs.insert(std::make_pair(output_id, &tx));
        }
    }

    /**
     * Drop indexes for ptx. When reason is BLOCK or REORG, cache the full tx by
     * each kernel id for DisconnectTip replay (behavior preserved from this tree).
     */
    void Remove(const CTransactionRef& ptx, MemPoolRemovalReason reason)
    {
        for (const mw::Hash& output_id : ptx->mweb_tx.GetOutputIDs()) {
            m_outputs.erase(output_id);
        }
        for (const mw::Hash& spent_id : ptx->mweb_tx.GetSpentIDs()) {
            m_next.erase(spent_id);
        }
        if (reason == MemPoolRemovalReason::BLOCK || reason == MemPoolRemovalReason::REORG) {
            for (const mw::Hash& kernel_id : ptx->mweb_tx.GetKernelIDs()) {
                m_recent_by_kernel.Put(kernel_id, ptx);
                LogDebug(BCLog::MEMPOOL, "Cached MWEB tx %s for kernel %s (reason=%s)\n",
                         ptx->GetHash().ToString(), kernel_id.ToHex(), RemovalReasonToString(reason));
            }
        }
    }

    const CTransaction* GetConflictTx(const mw::Hash& output_id) const
    {
        const auto it = m_next.find(output_id);
        return it == m_next.end() ? nullptr : &(it->second->GetTx());
    }

    std::optional<TxIter> FindSpender(const mw::Hash& output_id) const
    {
        const auto it = m_next.find(output_id);
        if (it == m_next.end()) return std::nullopt;
        return it->second;
    }

    const CTransaction* FindCreatingTx(const mw::Hash& output_id) const
    {
        const auto it = m_outputs.find(output_id);
        return it == m_outputs.end() ? nullptr : it->second;
    }

    bool HasCreatingTx(const mw::Hash& output_id) const { return m_outputs.contains(output_id); }
    bool IsSpentInMempool(const mw::Hash& output_id) const { return m_next.contains(output_id); }

    bool RecentKernelCached(const mw::Hash& kernel_id) const { return m_recent_by_kernel.Cached(kernel_id); }
    CTransactionRef GetRecentByKernel(const mw::Hash& kernel_id) { return m_recent_by_kernel.Get(kernel_id); }
    void ClearRecentByKernelForTesting() { m_recent_by_kernel.Clear(); }

    size_t DynamicMemoryUsage() const
    {
        return memusage::DynamicUsage(m_outputs) + memusage::DynamicUsage(m_next);
    }

private:
    std::map<mw::Hash, const CTransaction*> m_outputs;
    std::map<mw::Hash, TxIter> m_next;
    FIFOCache<mw::Hash, CTransactionRef> m_recent_by_kernel{DEFAULT_MEMPOOL_MWEB_CACHE_SIZE};
};

#endif // BITCOIN_MWEB_MWEB_MEMPOOL_INDEX_H
