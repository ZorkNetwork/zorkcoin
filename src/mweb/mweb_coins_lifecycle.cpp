// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_coins_lifecycle.h>

#include <coins.h>
#include <logging.h>
#include <mw/file/file_path.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/mmr/prune_list.h>
#include <mweb/mweb_db.h>
#include <txdb.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace MWEB;

namespace {

constexpr std::string_view INDEX_ZERO_SUFFIX{"000000.dat"};

/** Name prefix of a GetPath() result for file index 0, e.g. "leaf" for "leaf000000.dat". */
std::string StorageFilePrefix(const FilePath& index_zero_path)
{
    const std::string name{index_zero_path.ToString()};
    assert(name.ends_with(INDEX_ZERO_SUFFIX));
    return name.substr(0, name.size() - INDEX_ZERO_SUFFIX.size());
}

/** Matches PMMR::GetPath, LeafSet::GetPath and PruneList::GetPath: <prefix><index, >= 6 digits>.dat */
bool IsStorageFileName(std::string_view name)
{
    // The PMMR prefix char is formatted as its integer value, so 'O' yields "79".
    static const std::array<std::string, 3> prefixes{
        StorageFilePrefix(PMMR::GetPath(FilePath{fs::path{}}, 'O', 0)),
        StorageFilePrefix(LeafSet::GetPath(FilePath{fs::path{}}, 0)),
        StorageFilePrefix(PruneList::GetPath(FilePath{fs::path{}}, 0)),
    };
    constexpr std::string_view suffix{".dat"};
    for (const std::string_view prefix : prefixes) {
        if (name.size() < prefix.size() + 6 + suffix.size() || !name.starts_with(prefix) || !name.ends_with(suffix)) continue;
        const std::string_view index{name.substr(prefix.size(), name.size() - prefix.size() - suffix.size())};
        if (std::ranges::all_of(index, IsDigit)) return true;
    }
    return false;
}

} // namespace

void CoinsLifecycle::AttachView(CCoinsViewDB& coins_db, const FilePath& storage_path, const mw::Header::CPtr& header)
{
    coins_db.SetMWEBView(mw::CoinsViewDB::Open(
        storage_path,
        header,
        std::make_shared<MWEB::DBWrapper>(coins_db.GetDB())));
}

void CoinsLifecycle::RewrapAfterDbResize(
    CCoinsViewDB& coins_db,
    const FilePath& storage_path,
    const mw::Header::CPtr& header,
    CCoinsViewCache* tip_cache,
    CCoinsViewCache* connect_block_cache)
{
    coins_db.SetMWEBView(mw::CoinsViewDB::Open(
        storage_path,
        header,
        std::make_shared<MWEB::DBWrapper>(coins_db.GetDB())));
    if (tip_cache) {
        tip_cache->RefreshMWEBCache();
    }
    if (connect_block_cache) {
        connect_block_cache->RefreshMWEBCache();
    }
}

void CoinsLifecycle::ReleasePlaceholderForSnapshotLoad(
    CCoinsViewDB& coins_db,
    CCoinsViewCache* tip_cache,
    CCoinsViewCache* connect_block_cache)
{
    coins_db.SetMWEBView(nullptr);
    if (tip_cache) {
        tip_cache->RefreshMWEBCache();
    }
    if (connect_block_cache) {
        connect_block_cache->RefreshMWEBCache();
    }
}

bool CoinsLifecycle::RemoveStorageFiles(const fs::path& storage_path)
{
    std::error_code ec;
    std::vector<fs::path> files;
    for (auto it = fs::directory_iterator(storage_path, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
        std::error_code type_ec;
        if (it->is_regular_file(type_ec) && IsStorageFileName(fs::PathToString(it->path().filename()))) {
            files.emplace_back(it->path());
        }
    }
    if (ec && ec != std::errc::no_such_file_or_directory) {
        LogError("Failed to list MWEB files in %s: %s", fs::PathToString(storage_path), ec.message());
        return false;
    }

    bool removed_all{true};
    for (const fs::path& file : files) {
        if (!fs::remove(file, ec) && ec) {
            LogError("Failed to remove MWEB file %s: %s", fs::PathToString(file), ec.message());
            removed_all = false;
        }
    }
    return removed_all;
}

void CoinsLifecycle::AttachVerifiedAfterSnapshotLoad(
    CCoinsViewDB& coins_db,
    const FilePath& storage_path,
    const mw::Header::CPtr& header,
    CCoinsViewCache* tip_cache,
    CCoinsViewCache* connect_block_cache)
{
    coins_db.SetMWEBView(mw::CoinsViewDB::Open(
        storage_path,
        header,
        std::make_shared<MWEB::DBWrapper>(coins_db.GetDB())));
    if (tip_cache) {
        tip_cache->RefreshMWEBCache();
    }
    if (connect_block_cache) {
        connect_block_cache->RefreshMWEBCache();
    }
}
