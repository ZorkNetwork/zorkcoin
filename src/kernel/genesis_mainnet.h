// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_GENESIS_MAINNET_H
#define BITCOIN_KERNEL_GENESIS_MAINNET_H

#include <consensus/amount.h>

#include <cstdint>

/**
 * Mainnet genesis pins. Locked fields stay here; T0 only refreshes the
 * Litecoin OP_RETURN plus the three ground values (nonce / hash / merkle).
 *
 * T0 (2026-11-21 21:25:29.728 UTC):
 *   python3 contrib/genesis/grind_mainnet.py --write-pins \
 *       --util ./build/bin/zorkcoin-util
 */
static constexpr uint64_t MAINNET_GENESIS_NTIME = 1795296329728ULL; // 0x1A200000000
static constexpr uint32_t MAINNET_GENESIS_NBITS = 0x1e0ffff0;
static constexpr int32_t MAINNET_GENESIS_NVERSION = 0x20000000;
static constexpr CAmount MAINNET_GENESIS_REWARD = static_cast<CAmount>(1LL << 32);
inline constexpr const char MAINNET_GENESIS_MINER_COMMENT[] = "zork.network";

inline constexpr const char MAINNET_GENESIS_LTC_OPRETURN[] = "The News International 31/Oct/2026 SpaceX Falcon 9 reaches 700th launch with Starlink satellites in historic feat";

static constexpr uint64_t MAINNET_GENESIS_NONCE = 1140114ULL;
inline constexpr const char MAINNET_GENESIS_HASH[] = "e97b7d9b9283162744596c3a46e7e167dcbec6b8df0e2b4ef2786c7c633d1ca8";
inline constexpr const char MAINNET_GENESIS_MERKLE[] = "d89b34bc8c1eded12084fd12964041f5a2111de307b4ab701a9b4ebd580fac24";

/** Mainnet block-1 launch lock pins (see doc/btc-launch-lock.md). */
static constexpr uint32_t BTC_LAUNCH_NBITS_FLOOR = 0x1702353d;
static constexpr uint32_t BTC_LAUNCH_MIN_UNIX = 1795296330; // 2026-11-21 21:25:30 UTC

#endif // BITCOIN_KERNEL_GENESIS_MAINNET_H
