// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_CHECK_H
#define BITCOIN_AUXPOW_CHECK_H

#include <auxpow/auxpow.h>
#include <consensus/params.h>
#include <primitives/block.h>

#include <string>

namespace auxpow {

/**
 * Full AuxPoW consensus check for a Zorkcoin block with AuxPoW bit set.
 * Assumes the caller has already verified the AuxPoW bit matches presence of CAuxPow.
 */
bool CheckAuxPow(const CBlockHeader& hdr, const CAuxPow& aux, const Consensus::Params& params, std::string* err = nullptr);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_CHECK_H
