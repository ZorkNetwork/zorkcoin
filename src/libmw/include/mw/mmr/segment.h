
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MMR_SEGMENT_H
#define BITCOIN_LIBMW_INCLUDE_MW_MMR_SEGMENT_H
#include <mw/common/macros.h>
#include <mw/models/crypto/hash.h>
#include <mw/mmr/leaf.h>
#include <optional>
#include <set>

// Forward Declarations
class IMMR;
class ILeafSet;

MMR_NAMESPACE

/// <summary>
/// Represents a collection of contiguous, unpruned leaves,
/// and all hashes necessary to prove membership in the PMMR.
/// </summary>
struct Segment
{
    // The requested unspent leaves, in ascending order
    std::vector<mmr::Leaf> leaves;

    // The MMR node hashes needed to verify the integrity of the MMR & the provided leaves
    std::vector<mw::Hash> hashes;

    // The "bagged" hash of the next lower peak (if there is one),
    // which is necessary to compute the PMMR root
    std::optional<mw::Hash> lower_peak;
};

/// <summary>
/// Builds Segments for a provided MMR and segment.
/// </summary>
class SegmentFactory
{
public:
    static Segment Assemble(
        const IMMR& mmr,
        const ILeafSet& leafset,
        const LeafIndex& first_leaf_idx,
        uint16_t num_leaves
    );

    /// <summary>
    /// Recompute the PMMR root from a segment and the leafset used to assemble it.
    /// Returns nullopt if the segment is incomplete or inconsistent with the leafset.
    /// </summary>
    static std::optional<mw::Hash> CalcRoot(const Segment& segment, const ILeafSet& leafset);

    /// <summary>
    /// True when CalcRoot equals expected_root.
    /// </summary>
    static bool VerifyAgainstRoot(
        const Segment& segment,
        const ILeafSet& leafset,
        const mw::Hash& expected_root);

private:
    static std::set<Index> CalcHashIndices(
        const ILeafSet& leafset,
        const std::vector<Index>& peak_indices,
        const LeafIndex& first_leaf_idx,
        const LeafIndex& last_leaf_idx
    );
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MMR_SEGMENT_H
