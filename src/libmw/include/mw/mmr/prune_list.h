
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MMR_PRUNE_LIST_H
#define BITCOIN_LIBMW_INCLUDE_MW_MMR_PRUNE_LIST_H
#include <mw/file/file_path.h>
#include <mw/mmr/index.h>
#include <mw/mmr/leaf_index.h>
#include <mw/common/dynamic_bit_set.h>
#include <memory>

class PruneList
{
public:
    using Ptr = std::shared_ptr<PruneList>;
    using CPtr = std::shared_ptr<const PruneList>;

    static PruneList::Ptr Open(const FilePath& parent_dir, uint32_t file_index);
    static FilePath GetPath(const FilePath& dir, uint32_t file_index);

    uint64_t GetShift(const mmr::Index& index) const noexcept;
    uint64_t GetShift(const mmr::LeafIndex& index) const noexcept;
    uint64_t GetTotalShift() const noexcept { return m_totalShift; }

    void Commit(uint32_t file_index, const mw::DynamicBitSet& compacted);

private:
    PruneList(const FilePath& dir, mw::DynamicBitSet&& compacted, uint64_t total_shift)
        : m_dir(dir), m_compacted(std::move(compacted)), m_totalShift(total_shift) { }

    FilePath m_dir;
    mw::DynamicBitSet m_compacted;
    uint64_t m_totalShift;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MMR_PRUNE_LIST_H
