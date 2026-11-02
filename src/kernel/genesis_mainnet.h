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
 * T0 (2026-09-14 12:59:09.696 UTC):
 *   python3 contrib/genesis/grind_mainnet.py --fetch-ltc --write-pins \
 *       --util ./build/bin/zorkcoin-util
 *
 * The Litecoin citation below is an engineering placeholder, not the launch tip.
 */
static constexpr uint64_t MAINNET_GENESIS_NTIME = 1789390749696ULL; // 0x1A0A0000000
static constexpr uint32_t MAINNET_GENESIS_NBITS = 0x1e0ffff0;
static constexpr int32_t MAINNET_GENESIS_NVERSION = 0x20000000;
static constexpr CAmount MAINNET_GENESIS_REWARD = static_cast<CAmount>(1LL << 32);
inline constexpr const char MAINNET_GENESIS_MINER_COMMENT[] = "zork.network";

inline constexpr const char MAINNET_GENESIS_LTC_OPRETURN[] = "LTC BLK:3158477 -> 2e0962ab5028e67b83d6d7f240e2330b4ca58f6a7e28ceda3f371837a03f0d58";

static constexpr uint64_t MAINNET_GENESIS_NONCE = 1634777ULL;
inline constexpr const char MAINNET_GENESIS_HASH[] = "34c6a520b5d21dbbc1a135b0373c2e2aa00992e24db00488ab88d26f8a95c52c";
inline constexpr const char MAINNET_GENESIS_MERKLE[] = "b72f0b81e63bb83b40816ac4e3cf92bdfed7d51c80dbc04d3e66043fc62ea6c1";

/** Mainnet block-1 launch lock pins (see doc/btc-launch-lock.md). */
static constexpr uint32_t BTC_LAUNCH_NBITS_FLOOR = 0x1702353d;
static constexpr uint32_t BTC_LAUNCH_MIN_UNIX = 1789390750; // 2026-09-14 12:59:10 UTC

#endif // BITCOIN_KERNEL_GENESIS_MAINNET_H
