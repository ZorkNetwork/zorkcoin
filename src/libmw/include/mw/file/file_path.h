#ifndef BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_PATH_H
#define BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_PATH_H

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/traits.h>
#include <mw/exceptions/file_exception.h>
#include <util/fs.h>

#include <fstream>
#include <string>
#include <system_error>
#include <vector>

class FilePath : public Traits::IPrintable
{
    friend class File;
public:
    //
    // Constructors
    //
    FilePath(const FilePath& other) = default;
    FilePath(FilePath&& other) = default;
    FilePath(const char* path) : m_path(path) {}
    FilePath(const std::string& u8str) : m_path(fs::u8path(u8str)) {}
    FilePath(const fs::path& path) : m_path(path) {}

    //
    // Destructor
    //
    virtual ~FilePath() = default;

    //
    // Operators
    //
    FilePath& operator=(const FilePath& other) = default;
    FilePath& operator=(FilePath&& other) noexcept = default;
    bool operator==(const FilePath& rhs) const noexcept { return m_path == rhs.m_path; }

    FilePath GetChild(const char* filename) const { return FilePath{m_path / filename}; }
    FilePath GetChild(const std::string& filename) const { return FilePath{m_path / fs::u8path(filename)}; }

    FilePath GetParent() const
    {
        if (!m_path.has_parent_path()) {
            ThrowFile_F("Can't find parent path for {}", *this);
        }

        return FilePath{fs::path{m_path.parent_path()}};
    }

    bool Exists() const
    {
        std::error_code ec;
        const fs::file_status status = fs::status(m_path, ec);
        if (status.type() == fs::file_type::not_found || ec == std::errc::no_such_file_or_directory) {
            return false;
        }
        if (ec) {
            ThrowFile_F("Error ({}) while checking if {} exists", ec.message(), *this);
        }

        return fs::exists(status);
    }

    bool Exists_Safe() const noexcept
    {
        std::error_code ec;
        const fs::file_status status = fs::status(m_path, ec);
        if (status.type() == fs::file_type::not_found || ec == std::errc::no_such_file_or_directory) {
            return false;
        }
        return !ec && fs::exists(status);
    }

    bool IsDirectory() const
    {
        std::error_code ec;
        const bool isDirectory = fs::is_directory(m_path, ec);
        if (ec) {
            ThrowFile_F("Error ({}) while checking if {} is a directory", ec.message(), *this);
        }

        return isDirectory;
    }

    bool IsDirectory_Safe() const noexcept
    {
        std::error_code ec;
        return fs::is_directory(m_path, ec);
    }

    FilePath CreateDir() const
    {
        std::error_code ec;
        fs::create_directories(m_path, ec);
        if (ec && (!Exists_Safe() || !IsDirectory_Safe())) {
            ThrowFile_F("Error ({}) while trying to create directory {}", ec.message(), *this);
        }

        return *this;
    }

    // Removes a file, or a directory and the entries directly inside it.
    // Not recursive, and never follows symlinks.
    void Remove() const
    {
        std::error_code ec;
        if (fs::is_directory(fs::symlink_status(m_path, ec))) {
            std::vector<fs::path> entries;
            for (auto it = fs::directory_iterator(m_path, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
                entries.emplace_back(it->path());
            }
            for (const fs::path& entry : entries) {
                if (ec) break;
                fs::remove(entry, ec);
            }
        }
        if (!ec) {
            fs::remove(m_path, ec);
        }
        if (ec && Exists_Safe()) {
            ThrowFile_F("Error ({}) while trying to remove {}", ec.message(), *this);
        }
    }

    std::string ToString() const { return m_path.utf8string(); }

    //
    // Traits
    //
    std::string Format() const final { return m_path.utf8string(); }

private:
    fs::path m_path;
};

#endif // BITCOIN_LIBMW_INCLUDE_MW_FILE_FILE_PATH_H
