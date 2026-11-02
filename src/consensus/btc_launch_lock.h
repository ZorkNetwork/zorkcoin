// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BTC_LAUNCH_LOCK_H
#define BITCOIN_CONSENSUS_BTC_LAUNCH_LOCK_H

#include <consensus/params.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <span.h>

#include <cstdint>
#include <optional>
#include <vector>

/** Opaque Bitcoin header size (version..nonce). Not a Zork 88-byte header. */
static constexpr size_t BTC_LAUNCH_HEADER_SIZE = 80;

/** Second push in the OP_RETURN: distinguishes this from other 0-value outputs. */
static constexpr uint8_t BTC_LAUNCH_TAG = 42;

/** Build the coinbase OP_RETURN script: OP_RETURN PUSH "btc" PUSH 42 PUSH <80-byte header>. */
CScript BuildBtcLaunchLockScript(std::span<const unsigned char> header80);

/**
 * If script is a canonical launch-lock OP_RETURN, copy the 80-byte header
 * and return true. Does not check timestamp, nBits, or SHA256d.
 */
bool ParseBtcLaunchLockScript(const CScript& script, std::vector<unsigned char>& header80);

/**
 * Validate SHA256d(header) against header nBits, require decoded
 * header_target <= decoded floor_target, and header unix time >= min_unix_time.
 * Does not check Bitcoin-chain membership.
 */
bool CheckBtcLaunchLockHeader(std::span<const unsigned char> header80, uint32_t min_unix_time,
                              uint32_t nbits_floor, BlockValidationState& state);

/**
 * Mainnet height-1 coinbase must contain exactly one 0-value launch-lock
 * output. Other OP_RETURN outputs (e.g. the witness commitment) are ignored.
 */
bool CheckBtcLaunchLock(const CTransaction& coinbase, const Consensus::BtcLaunchLock& lock,
                        BlockValidationState& state);

/** Index of the unique launch-lock output, or nullopt if none / several. */
std::optional<size_t> GetBtcLaunchLockOutputIndex(const CTransaction& coinbase);

#endif // BITCOIN_CONSENSUS_BTC_LAUNCH_LOCK_H
