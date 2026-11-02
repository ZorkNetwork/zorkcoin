// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_PEER_STATE_H
#define BITCOIN_NODE_MWEB_PEER_STATE_H

//! Per-peer MWEB sidecar owned by Peer (net_processing).
//! The have_mweb capability flag is independent of serve queue state.
//! Serve engine views this via MWEBServePeerState aliases in mweb_serve.h.

#include <node/mweb_serve_types.h>
#include <util/time.h>

#include <atomic>
#include <chrono>
#include <deque>

namespace node {

struct PeerMWEBState {
    /** Whether this peer can give us MWEB data (VERSION / NODE_MWEB). */
    std::atomic<bool> m_have_mweb{false};

    /** LIP-0006 serve jobs and connection-local credits/refusal counters (msgproc mutex).
     * InitializeNode gives every new connection a fresh bucket and counter;
     * neither is remembered by address or transferred from a prior connection.
     * See doc/mweb/light-clients.md, Connection resource allowance.
     */
    std::deque<MWEBServeJob> m_serve_jobs;
    double m_serve_credits{DEFAULT_MWEB_SERVE_BURST};
    NodeClock::time_point m_serve_credit_timestamp{NodeClock::now()};
    int m_credit_denies_rolling{0};
    NodeClock::time_point m_credit_deny_window_start{NodeClock::now()};
};

} // namespace node

#endif // BITCOIN_NODE_MWEB_PEER_STATE_H
