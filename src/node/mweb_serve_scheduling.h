// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SERVE_SCHEDULING_H
#define BITCOIN_NODE_MWEB_SERVE_SCHEDULING_H

#include <net.h>
#include <span.h>

#include <algorithm>

namespace node {

/** Sentinel: no peer selected / no prior background serve step. NodeIds are non-negative. */
static constexpr NodeId NO_BACKGROUND_SERVE_PEER = -1;

/** Select the next peer for background MWEB serve rotation.
 *
 * @param pending     Ascending NodeIds with non-empty serve job queues.
 * @param last_served Previous peer served, or NO_BACKGROUND_SERVE_PEER.
 * @return Next peer in round-robin order, or NO_BACKGROUND_SERVE_PEER if pending is empty.
 */
inline NodeId SelectNextRotatingServePeer(std::span<const NodeId> pending, NodeId last_served)
{
    if (pending.empty()) return NO_BACKGROUND_SERVE_PEER;
    if (last_served == NO_BACKGROUND_SERVE_PEER ||
        !std::binary_search(pending.begin(), pending.end(), last_served)) {
        return pending.front();
    }
    const auto after{std::upper_bound(pending.begin(), pending.end(), last_served)};
    if (after != pending.end()) return *after;
    return pending.front();
}

} // namespace node

#endif // BITCOIN_NODE_MWEB_SERVE_SCHEDULING_H
