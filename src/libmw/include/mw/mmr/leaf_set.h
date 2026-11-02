
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_SET_H
#define BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_SET_H
#include <mw/common/macros.h>
#include <mw/common/dynamic_bit_set.h>
#include <mw/file/file.h>
#include <mw/file/mem_map.h>
#include <mw/models/crypto/hash.h>
#include <mw/mmr/leaf_index.h>
#include <atomic>
#include <unordered_map>

namespace mw {
/** Optional test hook: when non-null, ILeafSet::ToDynamicBitSet increments it. */
inline std::atomic<uint64_t>* g_leafset_todynamicbitset_calls{nullptr};
} // namespace mw

class ILeafSet
{
public:
    using Ptr = std::shared_ptr<ILeafSet>;

    virtual ~ILeafSet() = default;

    virtual uint8_t GetByte(uint64_t byteIdx) const = 0;
    virtual void SetByte(uint64_t byteIdx, uint8_t value) = 0;

    void Add(const mmr::LeafIndex& idx);
    void Remove(const mmr::LeafIndex& idx);
    bool Contains(const mmr::LeafIndex& idx) const noexcept;
    mw::Hash Root() const;
    void Rewind(uint64_t numLeaves, const std::vector<mmr::LeafIndex>& leavesToAdd);
    const mmr::LeafIndex& GetNextLeafIdx() const noexcept { return m_nextLeafIdx; }
    uint64_t GetNumNodes() const noexcept { return GetNextLeafIdx().GetPosition(); }
    mw::DynamicBitSet ToDynamicBitSet() const;

    virtual void ApplyUpdates(
        uint32_t file_index,
        const mmr::LeafIndex& nextLeafIdx,
        const std::unordered_map<uint64_t, uint8_t>& modifiedBytes
    ) = 0;

protected:
    uint8_t BitToByte(uint8_t bit) const;

    ILeafSet(const mmr::LeafIndex& nextLeafIdx)
        : m_nextLeafIdx(nextLeafIdx) { }

    mmr::LeafIndex m_nextLeafIdx;
};

class LeafSet : public ILeafSet
{
public:
    using Ptr = std::shared_ptr<LeafSet>;

    static LeafSet::Ptr Open(const FilePath& leafset_dir, uint32_t file_index);
    static FilePath GetPath(const FilePath& leafset_dir, uint32_t file_index);

    uint8_t GetByte(uint64_t byteIdx) const final;
    void SetByte(uint64_t byteIdx, uint8_t value) final;

    void ApplyUpdates(
        uint32_t file_index,
        const mmr::LeafIndex& nextLeafIdx,
        const std::unordered_map<uint64_t, uint8_t>& modifiedBytes
    ) final;
    void Flush(uint32_t file_index);
    void Cleanup(uint32_t current_file_index) const;

private:
    LeafSet(FilePath dir, MemMap&& mmap, const mmr::LeafIndex& nextLeafIdx)
        : ILeafSet(nextLeafIdx), m_dir(std::move(dir)), m_mmap(std::move(mmap)) {}

    FilePath m_dir;
    MemMap m_mmap;
    std::unordered_map<uint64_t, uint8_t> m_modifiedBytes;
};

//! Memory-only leafset for immutable historical snapshots (no file I/O).
class MemLeafSet : public ILeafSet
{
public:
    using Ptr = std::shared_ptr<MemLeafSet>;

    explicit MemLeafSet(const mw::DynamicBitSet& bits);

    uint8_t GetByte(uint64_t byteIdx) const final;
    void SetByte(uint64_t byteIdx, uint8_t value) final;

    void ApplyUpdates(
        uint32_t file_index,
        const mmr::LeafIndex& nextLeafIdx,
        const std::unordered_map<uint64_t, uint8_t>& modifiedBytes
    ) final;

private:
    std::vector<uint8_t> m_bytes;
};

class LeafSetCache : public ILeafSet
{
public:
    using Ptr = std::shared_ptr<LeafSetCache>;
    using UPtr = std::unique_ptr<LeafSetCache>;

    LeafSetCache(const ILeafSet::Ptr& pBacked)
        : ILeafSet(pBacked->GetNextLeafIdx()), m_pBacked(pBacked) { }

    uint8_t GetByte(uint64_t byteIdx) const final;
    void SetByte(uint64_t byteIdx, uint8_t value) final;

    void ApplyUpdates(
        uint32_t file_index,
        const mmr::LeafIndex& nextLeafIdx,
        const std::unordered_map<uint64_t, uint8_t>& modifiedBytes
    ) final;
    void Flush(uint32_t file_index);

private:
    ILeafSet::Ptr m_pBacked;
    std::unordered_map<uint64_t, uint8_t> m_modifiedBytes;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MMR_LEAF_SET_H
