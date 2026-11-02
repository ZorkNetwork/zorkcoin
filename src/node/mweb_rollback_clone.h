// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_ROLLBACK_CLONE_H
#define BITCOIN_NODE_MWEB_ROLLBACK_CLONE_H

#include <functional>

class CCoinsViewDB;
class FilePath;

namespace node {

/**
 * Copy live MWEB LevelDB keys (CoinDB/LeafDB/MMRInfo) and current PMMR files
 * into a private temp coins DB, then AttachView so DisconnectBlock can undo
 * extension-block state without touching the live chainstate.
 *
 * @return true if an MWEB view was cloned and attached; false if src has no MWEB layer.
 */
bool CloneMWEBChainstateForRollback(
    CCoinsViewDB& src,
    const FilePath& src_dir,
    CCoinsViewDB& dst,
    const FilePath& dst_dir,
    const std::function<void()>& interruption_point);

} // namespace node

#endif // BITCOIN_NODE_MWEB_ROLLBACK_CLONE_H
