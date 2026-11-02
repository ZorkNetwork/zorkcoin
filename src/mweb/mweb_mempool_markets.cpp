// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_mempool_markets.h>

#include <kernel/mempool_entry.h>
#include <memusage.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <util/check.h>
#include <util/overflow.h>

#include <algorithm>
#include <cassert>
#include <compare>
#include <limits>
#include <set>
#include <vector>

namespace {
constexpr MempoolMarket MARKETS[]{MempoolMarket::L1, MempoolMarket::MWEB};

int32_t ClampWeight(int64_t weight)
{
    return static_cast<int32_t>(std::clamp<int64_t>(weight, 1, std::numeric_limits<int32_t>::max()));
}

const CTxMemPoolEntry& EntryOf(const TxGraph::Ref& ref)
{
    return MWEBMempoolMarkets::Entry(ref);
}
} // namespace

MWEBMempoolMarkets::MWEBMempoolMarkets(unsigned max_cluster_count, uint64_t max_cluster_size, uint64_t acceptable_cost)
{
    m_l1_graph = MakeTxGraph(
        max_cluster_count, max_cluster_size, acceptable_cost,
        [](const TxGraph::Ref& a, const TxGraph::Ref& b) noexcept {
            return EntryOf(a).GetTx().GetHash() <=> EntryOf(b).GetTx().GetHash();
        });
    m_mweb_graph = MakeTxGraph(
        max_cluster_count, max_cluster_size, acceptable_cost,
        [](const TxGraph::Ref& a, const TxGraph::Ref& b) noexcept {
            const CTxMemPoolEntry& entry_a{EntryOf(a)};
            const CTxMemPoolEntry& entry_b{EntryOf(b)};
            // A lower sequence is better, so the newest transaction is evicted first.
            if (auto cmp = entry_a.GetSequence() <=> entry_b.GetSequence(); cmp != 0) return cmp;
            return entry_a.GetTx().GetHash() <=> entry_b.GetTx().GetHash();
        });
}

bool MWEBMempoolMarkets::InMarket(const CTxMemPoolEntry& entry, MempoolMarket market)
{
    const CTransaction& tx{entry.GetTx()};
    return market == MempoolMarket::L1 ? !tx.IsMWEBOnly() : tx.HasMWEBTx();
}

FeePerWeight MWEBMempoolMarkets::GetFeerate(const CTxMemPoolEntry& entry, MempoolMarket market)
{
    if (market == MempoolMarket::MWEB) {
        return FeePerWeight(entry.GetModifiedFee(), ClampWeight(entry.GetMWEBWeight()));
    }
    // The base MWEB fee is not L1 fee, so a hybrid's MWEB part does not raise its L1 rank.
    const CAmount mweb_fee{CFeeRate::GetMWEBFee(entry.GetMWEBWeight())};
    const int64_t weight{GetSigOpsAdjustedWeight(entry.GetTxWeight(), entry.GetSigOpCost(), ::nBytesPerSigOp)};
    return FeePerWeight(SaturatingAdd(entry.GetModifiedFee(), -mweb_fee), ClampWeight(weight));
}

size_t MWEBMempoolMarkets::GetEntryUsage(const CTxMemPoolEntry& entry, MempoolMarket market)
{
    // Matches the per-entry mapTx estimate in CTxMemPool::DynamicMemoryUsage.
    const size_t total{entry.DynamicMemoryUsage() + memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*))};
    const CTransaction& tx{entry.GetTx()};
    size_t mweb{0};
    if (!InMarket(entry, MempoolMarket::L1)) {
        mweb = total;
    } else if (tx.HasMWEBTx()) {
        mweb = std::min<size_t>(::GetSerializeSize(tx.mweb_tx), total);
    }
    return market == MempoolMarket::MWEB ? mweb : total - mweb;
}

void MWEBMempoolMarkets::Add(TxGraph& main, std::span<const CTxMemPoolEntry* const> entries)
{
    for (const CTxMemPoolEntry* entry : entries) {
        auto [it, inserted] = m_slots.try_emplace(entry);
        if (!Assume(inserted)) continue;
        Slot& slot{it->second};
        slot.l1_usage = GetEntryUsage(*entry, MempoolMarket::L1);
        slot.mweb_usage = GetEntryUsage(*entry, MempoolMarket::MWEB);
        m_l1_entry_usage += slot.l1_usage;
        m_mweb_entry_usage += slot.mweb_usage;
        for (MempoolMarket market : MARKETS) {
            if (!InMarket(*entry, market)) continue;
            MarketRef& ref{slot.Get(market)};
            ref.entry = entry;
            Graph(market).AddTransaction(ref, GetFeerate(*entry, market));
        }
    }
    for (const CTxMemPoolEntry* entry : entries) {
        LinkAncestors(main, *entry);
    }
}

void MWEBMempoolMarkets::LinkAncestors(TxGraph& main, const CTxMemPoolEntry& entry)
{
    auto it{m_slots.find(&entry)};
    if (!Assume(it != m_slots.end())) return;
    const Slot& slot{it->second};
    for (const TxGraph::Ref* ref : main.GetAncestors(entry, TxGraph::Level::MAIN)) {
        const auto* ancestor{static_cast<const CTxMemPoolEntry*>(ref)};
        if (ancestor == &entry) continue;
        auto anc_it{m_slots.find(ancestor)};
        if (!Assume(anc_it != m_slots.end())) continue;
        for (MempoolMarket market : MARKETS) {
            if (slot.Get(market).entry && anc_it->second.Get(market).entry) {
                Graph(market).AddDependency(/*parent=*/anc_it->second.Get(market), /*child=*/slot.Get(market));
            }
        }
    }
}

void MWEBMempoolMarkets::Remove(const CTxMemPoolEntry& entry)
{
    auto it{m_slots.find(&entry)};
    if (!Assume(it != m_slots.end())) return;
    m_l1_entry_usage -= it->second.l1_usage;
    m_mweb_entry_usage -= it->second.mweb_usage;
    m_slots.erase(it);
}

void MWEBMempoolMarkets::Link(TxGraph& main, const CTxMemPoolEntry& parent, const CTxMemPoolEntry& child)
{
    for (MempoolMarket market : MARKETS) {
        std::vector<const MarketRef*> parents;
        if (const MarketRef* ref{Find(parent, market)}) {
            parents.push_back(ref);
        } else {
            for (const TxGraph::Ref* anc : main.GetAncestors(parent, TxGraph::Level::MAIN)) {
                if (const MarketRef* ref{Find(static_cast<const CTxMemPoolEntry&>(*anc), market)}) parents.push_back(ref);
            }
        }
        if (parents.empty()) continue;
        std::vector<const MarketRef*> children;
        if (const MarketRef* ref{Find(child, market)}) {
            children.push_back(ref);
        } else {
            for (const TxGraph::Ref* desc : main.GetDescendants(child, TxGraph::Level::MAIN)) {
                if (const MarketRef* ref{Find(static_cast<const CTxMemPoolEntry&>(*desc), market)}) children.push_back(ref);
            }
        }
        for (const MarketRef* p : parents) {
            for (const MarketRef* c : children) Graph(market).AddDependency(/*parent=*/*p, /*child=*/*c);
        }
    }
}

void MWEBMempoolMarkets::SetFee(const CTxMemPoolEntry& entry)
{
    auto it{m_slots.find(&entry)};
    if (!Assume(it != m_slots.end())) return;
    for (MempoolMarket market : MARKETS) {
        if (const MarketRef& ref{it->second.Get(market)}; ref.entry) {
            Graph(market).SetTransactionFee(ref, GetFeerate(entry, market).fee);
        }
    }
}

const MWEBMempoolMarkets::MarketRef* MWEBMempoolMarkets::Find(const CTxMemPoolEntry& entry, MempoolMarket market) const
{
    auto it{m_slots.find(&entry)};
    if (it == m_slots.end()) return nullptr;
    const MarketRef& ref{it->second.Get(market)};
    return ref.entry ? &ref : nullptr;
}

size_t MWEBMempoolMarkets::GetUsage(MempoolMarket market) const
{
    const size_t entries{market == MempoolMarket::L1 ? m_l1_entry_usage : m_mweb_entry_usage};
    return entries + Graph(market).GetMainMemoryUsage();
}

size_t MWEBMempoolMarkets::DynamicMemoryUsage() const
{
    return m_l1_graph->GetMainMemoryUsage() + m_mweb_graph->GetMainMemoryUsage() + memusage::DynamicUsage(m_slots);
}

MWEBMempoolMarkets::WorstChunkResult MWEBMempoolMarkets::GetWorstChunk(size_t mempool_limit, unsigned mweb_share_pct) const
{
    WorstChunkResult result;
    const size_t mweb_cap{MWEBCap(mempool_limit, mweb_share_pct)};
    const size_t l1_cap{mempool_limit - mweb_cap};
    const size_t mweb_usage{GetUsage(MempoolMarket::MWEB)};
    const size_t l1_usage{GetUsage(MempoolMarket::L1)};
    const auto ratio = [](size_t usage, size_t cap) -> double {
        if (usage == 0) return 0.0;
        if (cap == 0) return 1e300;
        return static_cast<double>(usage) / static_cast<double>(cap);
    };
    const bool l1_nonempty{Graph(MempoolMarket::L1).GetTransactionCount(TxGraph::Level::MAIN) > 0};
    const bool mweb_nonempty{Graph(MempoolMarket::MWEB).GetTransactionCount(TxGraph::Level::MAIN) > 0};
    if (!l1_nonempty && !mweb_nonempty) return result;

    const bool trim_mweb{
        mweb_nonempty && (!l1_nonempty || ratio(mweb_usage, mweb_cap) >= ratio(l1_usage, l1_cap))};
    result.market = trim_mweb ? MempoolMarket::MWEB : MempoolMarket::L1;
    auto [refs, feerate] = Graph(result.market).GetWorstMainChunk();
    result.refs = std::move(refs);
    result.feerate = feerate;
    return result;
}

void MWEBMempoolMarkets::SanityCheck(TxGraph& main, size_t mempool_size) const
{
    assert(m_slots.size() == mempool_size);
    size_t l1_usage{0};
    size_t mweb_usage{0};
    for (MempoolMarket market : MARKETS) {
        TxGraph& graph{Graph(market)};
        assert(!graph.HaveStaging());
        assert(!graph.IsOversized(TxGraph::Level::MAIN));
        graph.SanityCheck();

        TxGraph::GraphIndex members{0};
        for (const auto& [entry, slot] : m_slots) {
            if (market == MempoolMarket::L1) {
                assert(main.Exists(*entry, TxGraph::Level::MAIN));
                assert(slot.l1_usage == GetEntryUsage(*entry, MempoolMarket::L1));
                assert(slot.mweb_usage == GetEntryUsage(*entry, MempoolMarket::MWEB));
                l1_usage += slot.l1_usage;
                mweb_usage += slot.mweb_usage;
            }
            const MarketRef& ref{slot.Get(market)};
            assert(InMarket(*entry, market) == (ref.entry != nullptr));
            if (!ref.entry) continue;
            ++members;
            assert(ref.entry == entry);
            assert(graph.Exists(ref, TxGraph::Level::MAIN));
            assert(graph.GetIndividualFeerate(ref) == GetFeerate(*entry, market));

            // The side-graph ancestors are exactly the in-market main-graph ancestors.
            std::set<const CTxMemPoolEntry*> expected;
            for (const TxGraph::Ref* anc : main.GetAncestors(*entry, TxGraph::Level::MAIN)) {
                const auto* anc_entry{static_cast<const CTxMemPoolEntry*>(anc)};
                if (InMarket(*anc_entry, market)) expected.insert(anc_entry);
            }
            std::set<const CTxMemPoolEntry*> actual;
            for (const TxGraph::Ref* anc : graph.GetAncestors(ref, TxGraph::Level::MAIN)) {
                actual.insert(&Entry(*anc));
            }
            assert(expected == actual);
        }
        assert(graph.GetTransactionCount(TxGraph::Level::MAIN) == members);
    }
    assert(l1_usage == m_l1_entry_usage);
    assert(mweb_usage == m_mweb_entry_usage);
}
