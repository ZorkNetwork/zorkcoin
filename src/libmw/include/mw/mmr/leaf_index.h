
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_INDEX_H
#define BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_INDEX_H
#include <mw/common/macros.h>
#include <mw/common/traits.h>
#include <mw/mmr/index.h>
#include <mw/util/bit_util.h>

MMR_NAMESPACE

class LeafIndex : public Traits::ISerializable
{
public:
    LeafIndex() noexcept
        : m_leafIndex(0), m_nodeIndex(0, 0) { }
    LeafIndex(const uint64_t leafIndex, const uint64_t position)
        : m_leafIndex(leafIndex), m_nodeIndex(position, 0) { }
    virtual ~LeafIndex() = default;

    static LeafIndex At(const uint64_t leafIndex) noexcept
    {
        return LeafIndex(leafIndex, (2 * leafIndex) - BitUtil::CountBitsSet(leafIndex));
    }

    bool operator<(const LeafIndex& rhs) const noexcept { return m_leafIndex < rhs.m_leafIndex; }
    bool operator>(const LeafIndex& rhs) const noexcept { return m_leafIndex > rhs.m_leafIndex; }
    bool operator==(const LeafIndex& rhs) const noexcept { return m_leafIndex == rhs.m_leafIndex; }
    bool operator!=(const LeafIndex& rhs) const noexcept { return m_leafIndex != rhs.m_leafIndex; }
    bool operator<=(const LeafIndex& rhs) const noexcept { return m_leafIndex <= rhs.m_leafIndex; }
    bool operator>=(const LeafIndex& rhs) const noexcept { return m_leafIndex >= rhs.m_leafIndex; }

    LeafIndex& operator++()
    {
        *this = this->Next();
        return *this;
    }

    uint64_t Get() const noexcept { return m_leafIndex; }
    const Index& GetNodeIndex() const noexcept { return m_nodeIndex; }
    uint64_t GetPosition() const noexcept { return m_nodeIndex.GetPosition(); }
    LeafIndex Next() const noexcept { return LeafIndex::At(m_leafIndex + 1); }

    IMPL_SERIALIZED(LeafIndex);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << m_leafIndex;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint64_t leaf_idx;
        s >> leaf_idx;
        *this = LeafIndex::At(leaf_idx);
    }

private:
    uint64_t m_leafIndex;
    Index m_nodeIndex;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_INDEX_H
