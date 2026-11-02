// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SNAPSHOT_BASE_BLOCK_H
#define BITCOIN_NODE_MWEB_SNAPSHOT_BASE_BLOCK_H

#include <uint256.h>
#include <util/result.h>
#include <util/time.h>

namespace node {
struct NodeContext;

//! How long loadtxoutset waits for the MWEB snapshot-base block body after
//! requesting it from a peer. The RPC remains interruptible during the wait.
static constexpr auto SNAPSHOT_BASE_BLOCK_FETCH_TIMEOUT{10min};

/**
 * Ensure the snapshot-base block body is on disk when MWEB AssumeUTXO needs it.
 *
 * Bitcoin Core loadtxoutset only requires the base header. ADGL also reads the
 * single base block body to bind the MWEB snapshot to the extension header.
 * If that body is missing, request it out of order from a NODE_MWEB peer and
 * wait until BLOCK_HAVE_DATA. Does not download parent blocks 1…N−1.
 */
[[nodiscard]] util::Result<void> EnsureSnapshotBaseBlock(NodeContext& node, const uint256& base_blockhash);
} // namespace node

#endif // BITCOIN_NODE_MWEB_SNAPSHOT_BASE_BLOCK_H
