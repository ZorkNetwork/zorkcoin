
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MMR_MMR_UTIL_H
#define BITCOIN_LIBMW_INCLUDE_MW_MMR_MMR_UTIL_H
#include <mw/common/dynamic_bit_set.h>
#include <mw/mmr/index.h>
#include <mw/mmr/leaf_index.h>
#include <optional>

class IMMR;

class MMRUtil
{
public:
    static mw::Hash CalcParentHash(const mmr::Index& index, const mw::Hash& left_hash, const mw::Hash& right_hash);
    static std::vector<mmr::Index> CalcPeakIndices(uint64_t num_nodes);
    static std::optional<mw::Hash> CalcBaggedPeak(const IMMR& mmr, const mmr::Index& peak_idx);

    static mw::DynamicBitSet BuildCompactBitSet(uint64_t num_leaves, const mw::DynamicBitSet& unspent_leaf_indices);
    static mw::DynamicBitSet DiffCompactBitSet(const mw::DynamicBitSet& prev_compact, const mw::DynamicBitSet& new_compact);

    /// <summary>
    /// An MMR can be rebuilt from the leaves and a small set of carefully chosen parent hashes.
    /// This calculates the positions of those parent hashes.
    /// </summary>
    /// <param name="unspent_leaf_indices">The unspent leaf indices.</param>
    /// <returns>The pruned parent positions.</returns>
    static mw::DynamicBitSet CalcPrunedParents(const mw::DynamicBitSet& unspent_leaf_indices);
};

/// <summary>
/// Iterates through MMR index positions at a single height, starting from left to right.
/// </summary>
struct SiblingIter
{
public:
    SiblingIter(uint64_t height, const mmr::Index& last_node);

    bool Next();

    const mmr::Index& Get() const noexcept { return m_next; }
    uint64_t GetPosition() const noexcept { return m_next.GetPosition(); }

private:
    uint64_t m_height;
    mmr::Index m_lastNode;
    uint64_t m_baseInc;

    uint64_t m_siblingNum{0};
    mmr::Index m_next;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MMR_MMR_UTIL_H
