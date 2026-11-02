// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_CHAINWORK_H
#define BITCOIN_AUXPOW_CHAINWORK_H

#include <arith_uint256.h>
#include <cstdint>

namespace auxpow {

/** Size-discounted AuxPoW chain work: floor(W * REF / (REF + S)), at least 1 if W >= 1.
 *  Multiplication is overflow-safe. chainwork_ref should be params.auxpow.nChainWorkRef. */
arith_uint256 GetAuxPowBlockProof(uint32_t nBits, uint32_t auxpow_size, uint32_t chainwork_ref = 8192);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_CHAINWORK_H
