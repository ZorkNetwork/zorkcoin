// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/chainwork.h>
#include <auxpow/auxpow.h>

#include <arith_uint256.h>

namespace auxpow {

arith_uint256 GetAuxPowBlockProof(uint32_t nBits, uint32_t auxpow_size, uint32_t chainwork_ref)
{
    arith_uint256 bnTarget;
    bool fNegative = false;
    bool fOverflow = false;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0) {
        return 0;
    }
    const arith_uint256 W = (~bnTarget / (bnTarget + 1)) + 1;
    if (W == 0) return 0;
    if (chainwork_ref == 0) return 0;
    const arith_uint256 ref(chainwork_ref);
    const arith_uint256 denom = ref + auxpow_size;
    // (W * ref) / denom without overflowing 256 bits: (W/denom)*ref + (W%denom)*ref/denom
    const arith_uint256 q = W / denom;
    const arith_uint256 r = W - q * denom;
    arith_uint256 w_aux = q * ref;
    w_aux += r * ref / denom;
    if (w_aux == 0) w_aux = 1;
    return w_aux;
}

} // namespace auxpow
