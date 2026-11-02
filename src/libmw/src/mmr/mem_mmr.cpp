#include <mw/mmr/mmr.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr_util.h>
#include <mw/exceptions/not_found_exception.h>
#include <cassert>

using namespace mmr;

void MemMMR::PrepareClone(uint64_t num_leaves, uint64_t num_nodes)
{
    m_hashes.clear();
    m_hashes.reserve(num_nodes);
    m_leaves.assign(num_leaves, Leaf{});
}

void MemMMR::AppendHash(const mw::Hash& hash)
{
    m_hashes.push_back(hash);
}

void MemMMR::SetLeafAt(const LeafIndex& idx, const Leaf& leaf)
{
    assert(idx.Get() < m_leaves.size());
    m_leaves[idx.Get()] = leaf;
}

MemMMR::Ptr MemMMR::CloneStructure(const IMMR& source, const ILeafSet& leafset)
{
    auto result = std::make_shared<MemMMR>();
    const uint64_t num_leaves = source.GetNumLeaves();
    const uint64_t num_nodes = source.GetNumNodes();
    result->PrepareClone(num_leaves, num_nodes);
    for (uint64_t pos = 0; pos < num_nodes; ++pos) {
        result->AppendHash(source.GetHash(Index::At(pos)));
    }
    for (LeafIndex idx = LeafIndex::At(0); idx < leafset.GetNextLeafIdx(); ++idx) {
        if (!leafset.Contains(idx)) {
            continue;
        }
        result->SetLeafAt(idx, source.GetLeaf(idx));
    }
    return result;
}

LeafIndex MemMMR::AddLeaf(const Leaf& leaf)
{
    m_leaves.push_back(leaf);
    m_hashes.push_back(leaf.GetHash());

    auto nextIdx = leaf.GetNodeIndex().GetNext();
    while (!nextIdx.IsLeaf()) {
        mw::Hash leftHash = GetHash(nextIdx.GetLeftChild());
        m_hashes.push_back(MMRUtil::CalcParentHash(nextIdx, leftHash, m_hashes.back()));
        nextIdx = nextIdx.GetNext();
    }

    return leaf.GetLeafIndex();
}

Leaf MemMMR::GetLeaf(const LeafIndex& leafIdx) const
{
    assert(leafIdx.Get() < m_leaves.size());
    const Leaf& leaf = m_leaves[leafIdx.Get()];
    // Sparse clones (PrepareClone / AssumeUTXO) leave spent slots default-empty.
    // Surface that as not-found so callers can fall back instead of AddLeaf-aborting.
    if (leaf.vec().empty()) {
        ThrowNotFound_F("MemMMR leaf {} has no payload", leafIdx.Get());
    }
    return leaf;
}

bool MemMMR::HasLeafPayload(const LeafIndex& leafIdx) const
{
    if (leafIdx.Get() >= m_leaves.size()) {
        return false;
    }
    return !m_leaves[leafIdx.Get()].vec().empty();
}

mw::Hash MemMMR::GetHash(const Index& idx) const
{
    assert(idx.GetPosition() < m_hashes.size());
    return m_hashes[idx.GetPosition()];
}

LeafIndex MemMMR::GetNextLeafIdx() const noexcept
{
    return LeafIndex::At(GetNumLeaves());
}

uint64_t MemMMR::GetNumLeaves() const noexcept
{
    return m_leaves.size();
}

void MemMMR::Rewind(const uint64_t numLeaves)
{
    assert(numLeaves <= m_leaves.size());
    m_leaves.resize(numLeaves);
    m_hashes.resize(GetNumNodes());
}
