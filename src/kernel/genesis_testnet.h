// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_GENESIS_TESTNET_H
#define BITCOIN_KERNEL_GENESIS_TESTNET_H

#include <consensus/amount.h>

#include <cstdint>

/**
 * Testnet genesis pins (2026-11-01 21:24:36.480 UTC):
 *   python3 contrib/genesis/grind_testnet.py testnet --util ./build/bin/zorkcoin-util
 */
static constexpr uint64_t TESTNET_GENESIS_NTIME = 1793568276480ULL; // 0x1A199000000
static constexpr uint32_t TESTNET_GENESIS_NBITS = 0x1d15198e;
static constexpr int32_t TESTNET_GENESIS_NVERSION = 0x20000000;
static constexpr CAmount TESTNET_GENESIS_REWARD = static_cast<CAmount>(1LL << 32);
inline constexpr const char TESTNET_GENESIS_MINER_COMMENT[] = "ad astra per aspera";

inline constexpr const char TESTNET_GENESIS_LTC_OPRETURN[] = "Space.com 31/Oct/2026 SpaceX celebrates Halloween with early-morning Falcon 9 launch from California";

static constexpr uint64_t TESTNET_GENESIS_NONCE = 707913759ULL;
inline constexpr const char TESTNET_GENESIS_HASH[] = "0f4a929550487a96cb7f0a5dcfe8b9eca20726810d3e12f6c2591fd73be38007";
inline constexpr const char TESTNET_GENESIS_MERKLE[] = "037598f1d4801ccb0f839bde41437ae1e2c81e18a89b5dcb2324756d4a4b74d1";

/**
 * Testnet block-1 Bitcoin launch lock pins (see doc/btc-launch-lock.md).
 *
 * Trigger: 2026-11-01 21:24:37 UTC — first whole Bitcoin second strictly after
 * TESTNET_GENESIS_NTIME (1793568276.480 s).
 * Difficulty floor matches mainnet (BTC #962490 compact target).
 */
static constexpr uint32_t BTC_LAUNCH_TESTNET_NBITS_FLOOR = 0x1702353d;
static constexpr uint32_t BTC_LAUNCH_TESTNET_MIN_UNIX = 1793568277; // 2026-11-01 21:24:37 UTC

#endif // BITCOIN_KERNEL_GENESIS_TESTNET_H
