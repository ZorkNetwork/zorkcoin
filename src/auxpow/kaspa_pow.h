// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_KASPA_POW_H
#define BITCOIN_AUXPOW_KASPA_POW_H

#include <auxpow/kaspa_header.h>
#include <uint256.h>

namespace auxpow {

/** Kaspa peer PoW hash matching rusty-kaspa State::calculate_pow. */
uint256 KaspaPeerPoW(const KaspaHeader& header);

/** cSHAKE256("ProofOfWorkHash") over pre || timestamp || 32 zero || nonce (no matrix). */
uint256 KaspaPowHashOnly(const uint256& pre_pow_hash, uint64_t timestamp, uint64_t nonce);

/** cSHAKE256("HeavyHash") of a single 32-byte input (no matrix). */
uint256 KaspaHeavyHashOnly(const uint256& input);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_KASPA_POW_H
