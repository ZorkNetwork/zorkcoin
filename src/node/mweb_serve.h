// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SERVE_H
#define BITCOIN_NODE_MWEB_SERVE_H

#include <merkleblock.h>
#include <node/mweb_p2p_messages.h>
#include <node/mweb_peer_state.h>
#include <node/mweb_serve_coordinator.h>
#include <node/mweb_serve_step_budget.h>
#include <node/mweb_serve_types.h>
#include <node/mweb_historical_cache.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <limits>
#include <string>

class CBlockIndex;
class CConnman;
class ChainstateManager;
class CInv;
class CNode;

namespace node {

/** Serve policy copied from PeerManager::Options at engine construction. */
struct MWEBServePolicy {
    MwebServeMode mweb_serve{DEFAULT_MWEB_SERVE_MODE};
    bool mweb_serve_in_blocksonly{DEFAULT_MWEB_SERVE_IN_BLOCKSONLY};
    bool ignore_incoming_txs{false};
    double mweb_serve_burst{DEFAULT_MWEB_SERVE_BURST};
};

/** Per-peer MWEB serve queue state (aliases PeerMWEBState serve fields). */
struct MWEBServePeerState {
    std::deque<MWEBServeJob>& m_mweb_serve_jobs;
    double& m_mweb_serve_credits;
    NodeClock::time_point& m_mweb_serve_credit_timestamp;
    int& m_mweb_credit_denies_rolling;
    NodeClock::time_point& m_mweb_credit_deny_window_start;
};

inline MWEBServePeerState MakeMWEBServePeerState(PeerMWEBState& mweb)
{
    return {
        mweb.m_serve_jobs,
        mweb.m_serve_credits,
        mweb.m_serve_credit_timestamp,
        mweb.m_credit_denies_rolling,
        mweb.m_credit_deny_window_start,
    };
}

struct MWEBServeHost {
    ChainstateManager& chainman;
    CConnman& connman;
    MWEBServePolicy policy;
    std::atomic<size_t>& global_jobs;
    Mutex& replay_mutex;
    size_t material_byte_budget{DEFAULT_MWEB_SERVE_MATERIAL_BUDGET};
    size_t material_leaf_ops{DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS};
    int credit_deny_disconnect{DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT};
    std::function<void(CNode&, const std::string&)> misbehaving;
    std::function<void(CNode&, MWEBLeafsetMsg)> send_leafset;
    std::function<void(CNode&, MWEBUTXOsMsg)> send_utxos;
    std::function<void(CNode&, CMerkleBlockWithMWEB)> send_header;
    //! A pruned (NODE_NETWORK_LIMITED) node disconnects peers requesting a header deeper than this.
    int network_limited_serve_depth{std::numeric_limits<int>::max()};
};

//! Why light-client MWEB serve is refused (or OK). download@ may bypass only UploadLimited.
enum class MWEBServeDenyReason {
    None,           //!< Serving is allowed.
    NoNodeMweb,     //!< Local services lack NODE_MWEB.
    BlocksOnly,     //!< blocksonly without mweb_serve_in_blocksonly.
    ServeOff,       //!< -mwebserve=off.
    UploadLimited,  //!< Outbound upload target reached (FORCE exempt).
};

class MWEBServeEngine
{
public:
    explicit MWEBServeEngine(MWEBServeHost host);

    MWEBServeDenyReason CanServeLightClientReason() const;
    bool CanServeLightClient() const { return CanServeLightClientReason() == MWEBServeDenyReason::None; }
    void UpdateCredits(MWEBServePeerState& peer) const;
    double CreditCost(const MWEBServeJob& job, size_t leafset_bytes_hint = 0) const;

    //! Header requests skip the leafset depth limit and are ignored without a
    //! disconnect, as Litecoin does, except below the pruned-node limit.
    bool ValidateServeBlock(CNode& node, const uint256& block_hash, bool header_request,
                            const CBlockIndex** pindex_out);

    bool TryEnqueue(CNode& node, MWEBServePeerState& peer, MWEBServeJob job, double credit_cost);
    void ClearJobs(MWEBServePeerState& peer);

    bool ProcessOneStep(CNode& node, MWEBServePeerState& peer);

    void EnqueueLeafset(CNode& pfrom, MWEBServePeerState& peer, const CInv& inv);
    void EnqueueUTXOs(CNode& pfrom, MWEBServePeerState& peer, const GetMWEBUTXOsMsg& get_utxos);
    void EnqueueHeader(CNode& pfrom, MWEBServePeerState& peer, const CInv& inv);

    bool BuildAndSend(CNode& node, MWEBServeJob& job);

private:
    bool HandleCreditDenial(CNode& node, MWEBServePeerState& peer);
    bool ProcessCoordinatorStep(CNode& node, MWEBServePeerState& peer, MWEBServeJob& job,
                                MWEBServeCoordinatorJob& coord, MWEBWorkBudget& budget);

    MWEBServeHost m_host;
};

} // namespace node

#endif // BITCOIN_NODE_MWEB_SERVE_H
