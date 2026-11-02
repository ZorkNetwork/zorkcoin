// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_rollback_clone.h>

#include <dbwrapper.h>
#include <logging.h>
#include <mweb/mweb_coins_lifecycle.h>
#include <mweb/mweb_db.h>
#include <mw/db/mmr_info_db.h>
#include <mw/file/file.h>
#include <mw/file/file_path.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/mmr/prune_list.h>
#include <tinyformat.h>
#include <txdb.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace node {
namespace {

void CopyMWEBKeys(CDBWrapper& src_db, CDBWrapper& dst_db, const std::function<void()>& interruption_point)
{
    std::unique_ptr<CDBIterator> it(src_db.NewIterator());
    it->SeekToFirst();
    CDBBatch batch(dst_db);
    unsigned count{0};
    while (it->Valid()) {
        std::string key;
        if (it->GetKey(key) && !key.empty() && (key.front() == 'U' || key.front() == 'O' || key.front() == 'M')) {
            std::vector<uint8_t> value;
            if (!src_db.Read(key, value)) {
                throw std::runtime_error(strprintf("Failed to read MWEB key %s while cloning chainstate", key));
            }
            batch.Write(key, value);
            if (interruption_point && (++count % 5000 == 0)) {
                interruption_point();
            }
        }
        it->Next();
    }
    dst_db.WriteBatch(batch);
}

void CopyFileIfExists(const FilePath& src, const FilePath& dst)
{
    File src_file(src);
    if (!src_file.Exists()) {
        return;
    }
    dst.GetParent().CreateDir();
    src_file.CopyTo(dst);
}

} // namespace

bool CloneMWEBChainstateForRollback(
    CCoinsViewDB& src,
    const FilePath& src_dir,
    CCoinsViewDB& dst,
    const FilePath& dst_dir,
    const std::function<void()>& interruption_point)
{
    if (!src.GetMWEBView()) {
        return false;
    }
    CDBWrapper* src_db = src.GetDB();
    CDBWrapper* dst_db = dst.GetDB();
    if (!src_db || !dst_db) {
        throw std::runtime_error("Cannot clone MWEB chainstate without persistent coins databases");
    }

    CopyMWEBKeys(*src_db, *dst_db, interruption_point);

    MWEB::DBWrapper src_wrap(src_db);
    MWEB::DBWrapper dst_wrap(dst_db);
    const auto src_mmr = MMRInfoDB(&src_wrap, nullptr).GetLatest();
    const auto dst_mmr = MMRInfoDB(&dst_wrap, nullptr).GetLatest();
    if (src_mmr && !dst_mmr) {
        throw std::runtime_error("Cloned MWEB chainstate is missing MMRInfo keys");
    }

    dst_dir.CreateDir();
    MMRInfoDB mmr_db(&src_wrap, nullptr);
    const auto mmr_info = mmr_db.GetLatest();
    const uint32_t file_index = mmr_info ? mmr_info->index : 0;
    const uint32_t compact_index = mmr_info ? mmr_info->compact_index : 0;
    CopyFileIfExists(PMMR::GetPath(src_dir, 'O', file_index), PMMR::GetPath(dst_dir, 'O', file_index));
    CopyFileIfExists(LeafSet::GetPath(src_dir, file_index), LeafSet::GetPath(dst_dir, file_index));
    CopyFileIfExists(PruneList::GetPath(src_dir, compact_index), PruneList::GetPath(dst_dir, compact_index));
    if (src.GetMWEBView() && src.GetMWEBView()->GetBestHeader() &&
        !File(PMMR::GetPath(src_dir, 'O', file_index)).Exists()) {
        throw std::runtime_error(strprintf(
            "MWEB PMMR file missing while cloning: %s (index=%u)",
            PMMR::GetPath(src_dir, 'O', file_index).ToString(), file_index));
    }

    const mw::Header::CPtr header = src.GetMWEBView()->GetBestHeader();
    MWEB::CoinsLifecycle::AttachView(dst, dst_dir, header);
    LogInfo("Cloned MWEB chainstate for dumptxoutset rollback (PMMR file_index=%u compact_index=%u).",
            file_index, compact_index);
    return true;
}

} // namespace node
