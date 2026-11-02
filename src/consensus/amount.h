// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

/** The amount of satoshis in one Zork. */
inline constexpr CAmount COIN{100'000'000};

/** No amount larger than this (in satoshi) is valid.
 *
 * Theoretical max issuance with base subsidy `1<<32` and halvings every `1<<20`
 * blocks is `2 * (1<<32) * (1<<20) = 1<<53` satoshis. This constant is a
 * consensus-critical sanity check (not merely documentation of supply).
 */
inline constexpr CAmount MAX_MONEY{(CAmount{1} << 32) * 2 * (CAmount{1} << 20)}; // 2^53
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H
