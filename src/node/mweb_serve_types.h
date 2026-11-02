// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SERVE_TYPES_H
#define BITCOIN_NODE_MWEB_SERVE_TYPES_H

#include <mw/node/coins_view.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

class CBlockIndex;

namespace node {
struct MWEBServeCoordinatorJob;
}

/** MWEB light-client serve operator policy. */
enum class MwebServeMode {
    OFF,
    AUTO,
    FORCE,
};

static constexpr MwebServeMode DEFAULT_MWEB_SERVE_MODE{MwebServeMode::AUTO};
static constexpr bool DEFAULT_MWEB_SERVE_IN_BLOCKSONLY{false};
static constexpr double DEFAULT_MWEB_SERVE_BURST{50000.0};
static constexpr size_t DEFAULT_MWEB_SERVE_MATERIAL_BUDGET{65536};
static constexpr size_t DEFAULT_MWEB_SERVE_MATERIAL_LEAF_OPS{64};
static constexpr int DEFAULT_MWEB_SERVE_CREDIT_DENY_DISCONNECT{10};
static constexpr int MWEB_SERVE_CREDIT_DENY_WINDOW_SEC{60};
/** Floor credit cost for mwebheader; actual cost is max(floor, size_hint/1024). */
static constexpr double MWEB_SERVE_HEADER_CREDIT_COST{100.0};
/**
 * Extra credits on historical-cache miss for leafset/UTXO jobs (materialize surcharge).
 * Composes with size-based credit pricing; tip/cache hits do not pay this.
 */
static constexpr double MWEB_SERVE_MATERIALIZE_SURCHARGE{500.0};

/** MWEB: Maximum depth of blocks we're willing to serve MWEB leafsets for. */
static constexpr int MAX_MWEB_LEAFSET_DEPTH = 10;
/** MWEB: Maximum number of UTXOs that can be requested in a getmwebutxos message. */
static constexpr uint16_t MAX_REQUESTED_MWEB_UTXOS = 4096;

static constexpr size_t MAX_MWEB_SERVE_JOBS_PER_PEER = 8;
static constexpr size_t MAX_MWEB_SERVE_JOBS_GLOBAL = 64;

/** MWEB serve credit refill: burst / 10 minutes. */
static constexpr double MWEB_SERVE_CREDIT_REFILL_PER_SECOND = DEFAULT_MWEB_SERVE_BURST / 600.0;

/**
 * Immutable MWEB view at a historical block height.
 * Held by shared_ptr so ring eviction cannot destroy in-flight serve jobs (I1).
 * `view` must be a CoinsViewMemory (parent-free); overlays over the live tip are
 * forbidden (frozen historical views).
 */
struct MWEBHistoricalSnapshot {
    uint256 block_hash;
    int height{0};
    //! Owned immutable MWEB view (CoinsViewMemory).
    mw::ICoinsView::Ptr view;
};

using MWEBHistoricalSnapshotPtr = std::shared_ptr<const MWEBHistoricalSnapshot>;

struct MWEBServeJob {
    enum class Type {
        UTXOS,
        LEAFSET,
        HEADER,
    };

    enum class Phase {
        INIT,
        MATERIALIZE_CHUNK,
        REPLAY_BACK,
        REPLAY_FORWARD,
        BUILD_SEND,
        DONE,
    };

    Type type;
    Phase phase{Phase::INIT};

    uint256 block_hash;

    // UTXOS-only:
    uint64_t start_index{0};
    uint16_t num_requested{0};
    uint8_t output_format{0};

    // Hit path: refcounted snapshot (I1).
    MWEBHistoricalSnapshotPtr snapshot;

    //! Shared miss/warm coordinator (I14). Miss-path replay/materialize state
    //! lives only on MWEBServeCoordinatorJob via this handle.
    std::shared_ptr<node::MWEBServeCoordinatorJob> coordinator;
};

/** DEBUG_TEST: force one internal serve fault (I9/E1) — peer must not be banned. */
inline std::atomic<bool> g_mweb_serve_inject_bad_cache{false};

#endif // BITCOIN_NODE_MWEB_SERVE_TYPES_H
