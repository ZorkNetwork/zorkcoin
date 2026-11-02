#include <mw/mmr/segment.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/mmr/mmr_util.h>

#include <algorithm>
#include <functional>
#include <unordered_map>

using namespace mmr;

Segment SegmentFactory::Assemble(const IMMR& mmr, const ILeafSet& leafset, const LeafIndex& first_leaf_idx, const uint16_t num_leaves)
{
    if (!leafset.Contains(first_leaf_idx)) {
        return {};
    }

    Segment segment;
    segment.leaves.reserve(num_leaves);

    mmr::LeafIndex leaf_idx = first_leaf_idx;
    mmr::LeafIndex last_leaf_idx = first_leaf_idx;
    while (segment.leaves.size() < num_leaves && leaf_idx < leafset.GetNextLeafIdx()) {
        if (leafset.Contains(leaf_idx)) {
            last_leaf_idx = leaf_idx;
            segment.leaves.push_back(mmr.GetLeaf(leaf_idx));
        }

        ++leaf_idx;
    }

    std::vector<Index> peak_indices = MMRUtil::CalcPeakIndices(leafset.GetNumNodes());
    assert(!peak_indices.empty());

    // Populate hashes
    std::set<Index> hash_indices = CalcHashIndices(leafset, peak_indices, first_leaf_idx, last_leaf_idx);
    segment.hashes.reserve(hash_indices.size());
    for (const Index& idx : hash_indices) {
        segment.hashes.push_back(mmr.GetHash(idx));
    }

    // Determine the lowest peak that can be calculated using the hashes we've already provided
    auto peak_iter = std::find_if(
        peak_indices.begin(), peak_indices.end(),
        [&last_leaf_idx](const Index& peak_idx) { return peak_idx >= last_leaf_idx.GetNodeIndex(); });
    assert(peak_iter != peak_indices.end());

    // Bag the next lower peak (if there is one), so the root can still be calculated
    if (++peak_iter != peak_indices.end()) {
        segment.lower_peak = MMRUtil::CalcBaggedPeak(mmr, *peak_iter);
    }

    return segment;
}


std::set<Index> SegmentFactory::CalcHashIndices(
    const ILeafSet& leafset,
    const std::vector<Index>& peak_indices,
    const mmr::LeafIndex& first_leaf_idx,
    const mmr::LeafIndex& last_leaf_idx)
{
    std::set<Index> proof_indices;

    // 1. Add peaks of mountains to the left of first index
    std::optional<Index> prev_peak;
    for (const Index& peak_idx : peak_indices) {
        if (peak_idx < first_leaf_idx.GetNodeIndex()) {
            proof_indices.insert(peak_idx);
            prev_peak = peak_idx;
        } else {
            break;
        }
    }

    // 2. Add indices needed to reach left edge of mountain
    uint64_t adjustment = prev_peak ? prev_peak->GetPosition() + 1 : 0;
    auto on_mountain_left_edge = [adjustment](const Index& idx) -> bool {
        return (idx.GetPosition() + 2 - adjustment) == (uint64_t(2) << idx.GetHeight());
    };

    Index idx = first_leaf_idx.GetNodeIndex();
    while (!on_mountain_left_edge(idx)) {
        Index sibling_idx = idx.GetSibling();
        if (sibling_idx < idx) {
            proof_indices.insert(sibling_idx);
            idx = Index(idx.GetPosition() + 1, idx.GetHeight() + 1);
        } else {
            idx = Index(sibling_idx.GetPosition() + 1, sibling_idx.GetHeight() + 1);
        }
    }

    // 3. Add all pruned parents after first leaf and before last leaf
    mw::DynamicBitSet pruned_parents = MMRUtil::CalcPrunedParents(leafset.ToDynamicBitSet());
    for (uint64_t pos = first_leaf_idx.GetPosition(); pos < last_leaf_idx.GetPosition(); pos++) {
        if (pruned_parents.test(pos)) {
            proof_indices.insert(Index::At(pos));
        }
    }

    // 4. Add indices needed to reach right edge of mountain containing the last leaf
    auto peak_iter = std::find_if(
        peak_indices.begin(), peak_indices.end(),
        [&last_leaf_idx](const Index& peak_idx) { return peak_idx >= last_leaf_idx.GetNodeIndex(); });
    assert(peak_iter != peak_indices.end());

    Index peak = *peak_iter;
    auto on_mountain_right_edge = [peak](const Index& idx) -> bool {
        return idx.GetPosition() >= peak.GetPosition() - peak.GetHeight();
    };

    idx = last_leaf_idx.GetNodeIndex();
    while (!on_mountain_right_edge(idx)) {
        Index sibling_idx = idx.GetSibling();
        if (sibling_idx > idx) {
            proof_indices.insert(sibling_idx);
            idx = Index(sibling_idx.GetPosition() + 1, idx.GetHeight() + 1);
        } else {
            idx = Index(idx.GetPosition() + 1, idx.GetHeight() + 1);
        }
    }

    return proof_indices;
}

std::optional<mw::Hash> SegmentFactory::CalcRoot(const Segment& segment, const ILeafSet& leafset)
{
    if (segment.leaves.empty()) {
        return std::nullopt;
    }

    const LeafIndex first_leaf_idx = segment.leaves.front().GetLeafIndex();
    const LeafIndex last_leaf_idx = segment.leaves.back().GetLeafIndex();
    if (first_leaf_idx > last_leaf_idx || last_leaf_idx >= leafset.GetNextLeafIdx()) {
        return std::nullopt;
    }

    const std::vector<Index> peak_indices = MMRUtil::CalcPeakIndices(leafset.GetNumNodes());
    if (peak_indices.empty()) {
        return std::nullopt;
    }

    const std::set<Index> hash_indices = CalcHashIndices(leafset, peak_indices, first_leaf_idx, last_leaf_idx);
    if (hash_indices.size() != segment.hashes.size()) {
        return std::nullopt;
    }

    std::unordered_map<uint64_t, mw::Hash> nodes;
    nodes.reserve(hash_indices.size() + segment.leaves.size());
    {
        size_t i = 0;
        for (const Index& idx : hash_indices) {
            nodes.emplace(idx.GetPosition(), segment.hashes[i++]);
        }
    }
    for (const Leaf& leaf : segment.leaves) {
        nodes[leaf.GetNodeIndex().GetPosition()] = leaf.GetHash();
    }

    std::function<std::optional<mw::Hash>(Index)> get_hash = [&](Index idx) -> std::optional<mw::Hash> {
        const auto it = nodes.find(idx.GetPosition());
        if (it != nodes.end()) {
            return it->second;
        }
        if (idx.IsLeaf()) {
            return std::nullopt;
        }
        const auto left = get_hash(idx.GetLeftChild());
        const auto right = get_hash(idx.GetRightChild());
        if (!left || !right) {
            return std::nullopt;
        }
        const mw::Hash parent = MMRUtil::CalcParentHash(idx, *left, *right);
        nodes[idx.GetPosition()] = parent;
        return parent;
    };

    auto peak_iter = std::find_if(
        peak_indices.begin(), peak_indices.end(),
        [&last_leaf_idx](const Index& peak_idx) { return peak_idx >= last_leaf_idx.GetNodeIndex(); });
    if (peak_iter == peak_indices.end()) {
        return std::nullopt;
    }

    // Peaks from the left edge through the mountain that contains the segment.
    std::vector<mw::Hash> peaks_to_bag;
    for (auto it = peak_indices.begin(); it != peak_indices.end(); ++it) {
        if (*it < first_leaf_idx.GetNodeIndex() || it == peak_iter) {
            const auto peak_hash = get_hash(*it);
            if (!peak_hash) {
                return std::nullopt;
            }
            peaks_to_bag.push_back(*peak_hash);
            if (it == peak_iter) {
                break;
            }
        } else if (*it > *peak_iter) {
            break;
        }
    }

    const Index next_node = leafset.GetNextLeafIdx().GetNodeIndex();
    mw::Hash root;
    if (segment.lower_peak) {
        root = *segment.lower_peak;
        for (auto it = peaks_to_bag.rbegin(); it != peaks_to_bag.rend(); ++it) {
            root = MMRUtil::CalcParentHash(next_node, *it, root);
        }
    } else {
        for (auto it = peaks_to_bag.rbegin(); it != peaks_to_bag.rend(); ++it) {
            if (root.IsZero()) {
                root = *it;
            } else {
                root = MMRUtil::CalcParentHash(next_node, *it, root);
            }
        }
        if (root.IsZero()) {
            return std::nullopt;
        }
    }

    return root;
}

bool SegmentFactory::VerifyAgainstRoot(
    const Segment& segment,
    const ILeafSet& leafset,
    const mw::Hash& expected_root)
{
    const std::optional<mw::Hash> root = CalcRoot(segment, leafset);
    return root && *root == expected_root;
}
