// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_MEMPOOL_MARKETS_H
#define BITCOIN_MWEB_MWEB_MEMPOOL_MARKETS_H

//! MWEB mempool markets: one eviction-only TxGraph per market (L1 and MWEB)
//! beside CTxMemPool's main TxGraph, plus each market's memory usage.
//! Owned by CTxMemPool; its mutation paths call Add/Remove/Link/SetFee as
//! one-liners. The main TxGraph (mining, replacement, cluster limits) is not
//! affected. The side graphs are linearized lazily, when eviction asks for them.

#include <txgraph.h>
#include <util/feefrac.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

class CTxMemPoolEntry;

enum class MempoolMarket {
    L1,   //!< L1-only transactions and hybrids, ranked by L1 fee per sigop-adjusted L1 weight.
    MWEB, //!< MWEB-only transactions and hybrids, ranked by fee per MWEB weight.
};

class MWEBMempoolMarkets
{
public:
    /** Side-graph ref, castable from the TxGraph::Ref* the side graphs return. */
    struct MarketRef : public TxGraph::Ref {
        const CTxMemPoolEntry* entry{nullptr};
    };

    /** The side graphs use the main graph's cluster limits; their clusters are
     *  subsets of main clusters with no larger weights, so they are never oversized. */
    MWEBMempoolMarkets(unsigned max_cluster_count, uint64_t max_cluster_size, uint64_t acceptable_cost);

    /** Whether entry joins market's eviction graph. Hybrids join both. */
    static bool InMarket(const CTxMemPoolEntry& entry, MempoolMarket market);
    /** The eviction feerate entry has in market's graph. */
    static FeePerWeight GetFeerate(const CTxMemPoolEntry& entry, MempoolMarket market);
    /** The part of entry's memory (including its mapTx node) that counts toward market. */
    static size_t GetEntryUsage(const CTxMemPoolEntry& entry, MempoolMarket market);
    /** The mempool entry a side-graph ref belongs to. */
    static const CTxMemPoolEntry& Entry(const TxGraph::Ref& ref) { return *static_cast<const MarketRef&>(ref).entry; }

    /** Add entries already committed to main. Dependencies come from each entry's
     *  in-market main-graph ancestors, which must be in the markets or among entries.
     *  main must not be oversized. */
    void Add(TxGraph& main, std::span<const CTxMemPoolEntry* const> entries);
    void Remove(const CTxMemPoolEntry& entry);
    /** Follow a dependency of child on parent that main gained after both were
     *  added (reorg). An endpoint outside a market is bridged through its in-market
     *  main-graph ancestors (parent) or descendants (child). main must not be oversized. */
    void Link(TxGraph& main, const CTxMemPoolEntry& parent, const CTxMemPoolEntry& child);
    /** Follow a modified-fee change of entry. */
    void SetFee(const CTxMemPoolEntry& entry);

    TxGraph& Graph(MempoolMarket market) const { return market == MempoolMarket::L1 ? *m_l1_graph : *m_mweb_graph; }
    /** entry's ref in market's graph, or nullptr if it is not in that market. */
    const MarketRef* Find(const CTxMemPoolEntry& entry, MempoolMarket market) const;
    /** Memory counted toward market: its entry parts plus its graph. */
    size_t GetUsage(MempoolMarket market) const;
    /** Memory of the side graphs and the ref map, for CTxMemPool::DynamicMemoryUsage. */
    size_t DynamicMemoryUsage() const;

    /** Cap for the MWEB market given the mempool size limit and share percentage. */
    static size_t MWEBCap(size_t mempool_limit, unsigned mweb_share_pct)
    {
        return mempool_limit * std::min(mweb_share_pct, 100u) / 100;
    }

    /**
     * Worst eviction chunk among the markets: pick the market with the larger
     * usage-to-cap ratio (MWEB cap = limit*share, L1 cap = limit - mweb_cap).
     * A market with no transactions is never chosen. Both empty → empty refs.
     */
    struct WorstChunkResult {
        MempoolMarket market{MempoolMarket::L1};
        std::vector<TxGraph::Ref*> refs;
        FeePerWeight feerate{};
    };
    WorstChunkResult GetWorstChunk(size_t mempool_limit, unsigned mweb_share_pct) const;

    void SanityCheck(TxGraph& main, size_t mempool_size) const;

private:
    struct Slot {
        MarketRef l1;
        MarketRef mweb;
        size_t l1_usage{0};
        size_t mweb_usage{0};
        MarketRef& Get(MempoolMarket market) { return market == MempoolMarket::L1 ? l1 : mweb; }
        const MarketRef& Get(MempoolMarket market) const { return market == MempoolMarket::L1 ? l1 : mweb; }
    };

    void LinkAncestors(TxGraph& main, const CTxMemPoolEntry& entry);

    std::unique_ptr<TxGraph> m_l1_graph;
    std::unique_ptr<TxGraph> m_mweb_graph;
    //! Declared after the graphs: destroying a MarketRef removes it from its graph.
    std::unordered_map<const CTxMemPoolEntry*, Slot> m_slots;
    size_t m_l1_entry_usage{0};
    size_t m_mweb_entry_usage{0};
};

#endif // BITCOIN_MWEB_MWEB_MEMPOOL_MARKETS_H
