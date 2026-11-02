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
 * Maximum coin supply is 90,071,992.53692420 Zorkcoins (0x001FFFFF_FFF00004).
 * This constant is a consensus-critical sanity check.
 */
inline constexpr CAmount MAX_MONEY{9'007'199'253'692'420LL}; // 0x001FFFFF_FFF00004
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H
