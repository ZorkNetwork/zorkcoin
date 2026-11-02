// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstddef>
#include <cstdint>

#include <mw/consensus/params.h> // MWEB

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE{4'000'000};
/**
 * BIP324 short-id `block` application-payload max:
 *   (2^24 - 1) - 1 = 16,777,214
 * (3-byte length field caps contents at 2^24-1; short-id encoding uses 1 type byte).
 */
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE_BIP324 = 16'777'214;
/**
 * Maximum wire-serialized block size (witness + MWEB extension). Consensus.
 * Capped at the BIP324 maximum payload size (16,777,214 bytes).
 */
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB =
    MAX_BLOCK_SERIALIZED_SIZE_BIP324; // 16'777'214

/**
 * Serialized-size budget for CreateNewBlock / GBT / MWEB miner packing.
 * Default equals BIP324. Compile-time overrides (mutually exclusive):
 *   -DMINE_MAX_MWEB_SIZE  -> MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB
 *   -DMINE_TEST_MWEB_SIZE -> MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB + 512
 */
#if defined(MINE_TEST_MWEB_SIZE)
#  if defined(MINE_MAX_MWEB_SIZE)
#    error "Define only one of MINE_MAX_MWEB_SIZE, MINE_TEST_MWEB_SIZE"
#  endif
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE_MINE =
    MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB + 512;
#elif defined(MINE_MAX_MWEB_SIZE)
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE_MINE =
    MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB;
#else
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE_MINE =
    MAX_BLOCK_SERIALIZED_SIZE_BIP324;
#endif

/** True if a serialized block body cannot be carried as a BIP324 short-id `block` payload. */
inline constexpr bool ExceedsBip324BlockPayload(size_t serialized_size)
{
    return serialized_size > MAX_BLOCK_SERIALIZED_SIZE_BIP324;
}

/** The maximum allowed weight for a block, see BIP 141 (network rule) */
inline constexpr unsigned int MAX_BLOCK_WEIGHT{4'000'000};
/** The maximum allowed number of signature check operations in a block (network rule) */
inline constexpr int64_t MAX_BLOCK_SIGOPS_COST{80'000};
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
inline constexpr int COINBASE_MATURITY = 119;
/** MWEB: Pegout transaction outputs can only be spent after this number of new blocks (network rule) */
inline constexpr int PEGOUT_MATURITY = 9;

inline constexpr int WITNESS_SCALE_FACTOR = 4;

inline constexpr size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
inline constexpr size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
inline constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
inline constexpr int64_t MAX_TIMEWARP = 600 * 1000;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
