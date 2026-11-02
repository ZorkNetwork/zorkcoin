
#ifndef BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_H
#define BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_H
#include <mw/common/traits.h>
#include <mw/file/file_path.h>
#include <unordered_map>

class File : public Traits::IPrintable
{
public:
    File(FilePath path) : m_path(std::move(path)) { }
    virtual ~File() = default;

    // Creates an empty file if it doesn't already exist
    void Create();

    const FilePath& GetPath() const noexcept { return m_path; }
    size_t GetSize() const;
    bool Exists() const;

    std::vector<uint8_t> ReadBytes() const;
    std::vector<uint8_t> ReadBytes(size_t startIndex, size_t numBytes) const;

    void Write(const std::vector<uint8_t>& bytes);
    void Write(size_t startIndex, const std::vector<uint8_t>& bytes, bool truncate);
    void WriteBytes(const std::unordered_map<uint64_t, uint8_t>& bytes);
    void Truncate(uint64_t size);
    void Commit() const;

    void CopyTo(const FilePath& new_path) const;

    //
    // Traits
    //
    std::string Format() const final { return m_path.Format(); }

private:
    FilePath m_path;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_H
