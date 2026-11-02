#include <mw/mmr/prune_list.h>
#include <mw/file/file.h>

using namespace mmr;

PruneList::Ptr PruneList::Open(const FilePath& parent_dir, const uint32_t file_index)
{
    File file = GetPath(parent_dir, file_index);

    mw::DynamicBitSet bitset;
    if (file.Exists()) {
        bitset = mw::DynamicBitSet::From(file.ReadBytes());
    } else if (file_index != 0) {
        ThrowFile_F("Missing MWEB prune list {}", file);
    }

    uint64_t total_shift = bitset.count();
    return std::shared_ptr<PruneList>(new PruneList(parent_dir, std::move(bitset), total_shift));
}

FilePath PruneList::GetPath(const FilePath& dir, const uint32_t file_index)
{
    return dir.GetChild(StringUtil::Format("prun{:0>6}.dat", file_index));
}

uint64_t PruneList::GetShift(const Index& index) const noexcept
{
    assert(!m_compacted.test(index.GetPosition()));

    // NOTE: rank() uses an inefficient algorithm.
    // A shift cache with an efficient "nearest-neighbor" searching algorithm would be better.
    return m_compacted.rank(index.GetPosition());
}

uint64_t PruneList::GetShift(const LeafIndex& index) const noexcept
{
    return GetShift(index.GetNodeIndex());
}

void PruneList::Commit(const uint32_t file_index, const mw::DynamicBitSet& compacted)
{
    File file(GetPath(m_dir, file_index));
    // This generation is a replacement, including when the new mask is empty.
    // Other File::Write callers intentionally append.
    file.Write(0, compacted.bytes(), /*truncate=*/true);
    file.Commit();

    m_compacted = compacted;
    m_totalShift = compacted.count();
}
