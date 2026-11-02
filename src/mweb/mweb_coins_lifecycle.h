// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_COINS_LIFECYCLE_H
#define BITCOIN_MWEB_MWEB_COINS_LIFECYCLE_H

//! MWEB coins-view attach / sanctioned rewrap helpers.
//! Called from Chainstate::InitCoinsDB, ResizeCoinsCaches, and AssumeUTXO snapshot load.

#include <mw/models/block/header.h>
#include <mw/node/coins_view.h>
#include <util/fs.h>

#include <memory>

class CCoinsViewCache;
class CCoinsViewDB;
class FilePath;

namespace MWEB {

class CoinsLifecycle
{
public:
    /** Attach mw::CoinsViewDB once at InitCoinsDB (deployment-enabled chains only). */
    static void AttachView(CCoinsViewDB& coins_db, const FilePath& storage_path, const mw::Header::CPtr& header);

    /**
     * Sanctioned rewrap after CoinsDB().ResizeCache: reopen MWEB view and RefreshMWEBCache
     * on tip / connect-block cache layers. No-op if no MWEB view was attached.
     */
    static void RewrapAfterDbResize(
        CCoinsViewDB& coins_db,
        const FilePath& storage_path,
        const mw::Header::CPtr& header,
        CCoinsViewCache* tip_cache,
        CCoinsViewCache* connect_block_cache);

    /**
     * Sanctioned snapshot-load release: drop placeholder view and refresh nested caches
     * so leafset/PMMR files can be rewritten at the same path.
     */
    static void ReleasePlaceholderForSnapshotLoad(
        CCoinsViewDB& coins_db,
        CCoinsViewCache* tip_cache,
        CCoinsViewCache* connect_block_cache);

    /** Re-attach verified view after LoadMWEBSnapshotSection and refresh caches. */
    static void AttachVerifiedAfterSnapshotLoad(
        CCoinsViewDB& coins_db,
        const FilePath& storage_path,
        const mw::Header::CPtr& header,
        CCoinsViewCache* tip_cache,
        CCoinsViewCache* connect_block_cache);

    /**
     * Remove the PMMR, leafset and prune-list files (named by PMMR::GetPath, LeafSet::GetPath
     * and PruneList::GetPath) from the top level of a chainstate directory, so DestroyDB can
     * remove the then-empty directory.
     * Not recursive; other files are left alone. Returns false if any file could not be removed.
     */
    static bool RemoveStorageFiles(const fs::path& storage_path);
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_COINS_LIFECYCLE_H
