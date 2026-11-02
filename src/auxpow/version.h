// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_VERSION_H
#define BITCOIN_AUXPOW_VERSION_H

#include <cstdint>

namespace auxpow {

/** Dogecoin-style AuxPoW flag: nVersion bit 8. */
static constexpr int32_t VERSION_AUXPOW_BIT = 0x100;

/**
 * An AuxPoW block's nNonce is fixed to MakeAuxPowNonce(chain_id): ASCII
 * "AuxPoW" in the upper 48 bits and the network chain ID in the low 16 bits,
 * so the little-endian wire bytes read e.g. "ZKAuxPoW" on mainnet.
 */
static constexpr uint64_t AUXPOW_NONCE_MARKER = uint64_t{0x576F50787541} << 16;
static constexpr uint64_t AUXPOW_NONCE_CHAIN_ID_MASK = 0xffff;

inline bool IsAuxPow(int32_t nVersion)
{
    return (nVersion & VERSION_AUXPOW_BIT) != 0;
}

inline int32_t MakeAuxPowVersion(int32_t base_version)
{
    return base_version | VERSION_AUXPOW_BIT;
}

inline uint64_t MakeAuxPowNonce(uint16_t chain_id)
{
    return AUXPOW_NONCE_MARKER | chain_id;
}

inline bool HasAuxPowNonceMarker(uint64_t nNonce)
{
    return (nNonce & ~AUXPOW_NONCE_CHAIN_ID_MASK) == AUXPOW_NONCE_MARKER;
}

inline uint16_t GetAuxPowNonceChainId(uint64_t nNonce)
{
    return static_cast<uint16_t>(nNonce & AUXPOW_NONCE_CHAIN_ID_MASK);
}

} // namespace auxpow

#endif // BITCOIN_AUXPOW_VERSION_H
