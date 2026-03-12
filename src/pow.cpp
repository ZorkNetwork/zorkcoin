// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>

// Consensus-critical: uses integer arithmetic only (no floating point). Results must be
// deterministic and identical regardless of implementation or language.
unsigned int GravityAsert(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    // ASERT algorithm constants
    const int32_t nAnchorHeight = 0; // Genesis block is the anchor for Zorkcoin
    arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    // Check if we're at the genesis block
    if (pindexLast == NULL || pindexLast->nHeight < nAnchorHeight) {
        return bnPowLimit.GetCompact();
    }

    // Find the anchor block (genesis block at height 0)
    const CBlockIndex* pindexAnchor = pindexLast;
    while (pindexAnchor && pindexAnchor->nHeight > nAnchorHeight) {
        pindexAnchor = pindexAnchor->pprev;
    }

    if (pindexAnchor == NULL || pindexAnchor->nHeight != nAnchorHeight) {
        // This shouldn't happen if the blockchain is valid
        return bnPowLimit.GetCompact();
    }

    // Calculate time and height differences
    // Per ASERT spec: time_delta and height_delta use the CURRENT block (the one we're adding),
    // not the previous block. next_target is computed for the block after pindexLast.
    // Zorkcoin uses millisecond timestamps throughout.
    int64_t nTimeRef = pindexAnchor->pprev
        ? pindexAnchor->pprev->GetBlockTime()
        : pindexAnchor->GetBlockTime();
    int64_t nTimeCurr = pblock->GetBlockTime();
    int64_t nTimeDiff = nTimeCurr - nTimeRef;
    int64_t nHeightDiff = (pindexLast->nHeight + 1) - pindexAnchor->nHeight;

    // Get the anchor block target
    arith_uint256 bnAnchorTarget;
    bnAnchorTarget.SetCompact(pindexAnchor->nBits);

    // Calculate the exponent
    // Use params.nASERTHalfLife
    // The exponent represents how many half-lives have passed
    int64_t nExpected = params.nPowTargetSpacing * (nHeightDiff + 1);
    int64_t exponent = ((nTimeDiff - nExpected) * 65536) / params.nASERTHalfLife;

    // Decompose exponent into integer and fractional parts
    int64_t shifts = exponent >> 16;
    uint16_t frac = (uint16_t)exponent;

    // Calculate the factor for the fractional part
    uint64_t factor = 65536ULL + ((195766423245049ULL * frac + 971821376ULL * frac * frac +
                                   5127ULL * frac * frac * frac + (1ULL << 47)) >> 48);

    // Calculate next target
    arith_uint256 bnNext = bnAnchorTarget;
    arith_uint256 bnFactor(factor);
    bnNext *= bnFactor;

    // Apply the integer shifts (divide by 65536 from the factor, then apply 2^shifts)
    shifts -= 16;

    if (shifts < 0) {
        // Right-shifting a 256-bit value by >= 256 bits is undefined in C++; clamp to min target
        if (-shifts >= 256) {
            bnNext = arith_uint256(1);
        } else {
            bnNext >>= -shifts;
        }
    } else if (shifts > 0) {
        // Shifting left by >= 256 bits zeros out a 256-bit value; treat as overflow
        if (shifts >= 256) {
            bnNext = bnPowLimit;
        } else {
            // Detect overflow when left-shifting (per BCH reference implementation)
            arith_uint256 bnNextShifted = bnNext << static_cast<int>(shifts);
            if ((bnNextShifted >> static_cast<int>(shifts)) != bnNext) {
                bnNext = bnPowLimit;
            } else {
                bnNext = bnNextShifted;
            }
        }
    }

    // Ensure the result is within bounds
    if (bnNext > bnPowLimit) {
        bnNext = bnPowLimit;
    }
    // Ensure minimum target (maximum difficulty) - prevent target from becoming too small
    // Set a minimum target of 1 to prevent zero or near-zero targets
    if (bnNext == arith_uint256() || bnNext < arith_uint256(1)) {
        bnNext = arith_uint256(1);
    }

    // Extra shift when mantissa would have bit 23 (0x00800000) set - matches GetCompact's
    // renormalization threshold; ensures target encodes correctly (theory under test)
    int nSize = (bnNext.bits() + 7) / 8;
    if (nSize > 3) {
        arith_uint256 bnMantissa = bnNext >> (8 * (nSize - 3));
        uint32_t nRawMantissa = static_cast<uint32_t>(bnMantissa.GetLow64());
        if ((nRawMantissa & 0x00800000) != 0 && bnNext > arith_uint256(1)) {
            bnNext >>= 1;
            if (bnNext < arith_uint256(1)) bnNext = arith_uint256(1);
        }
    }

    unsigned int nResult = bnNext.GetCompact();
    return nResult;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Handle min-difficulty blocks for testnet
    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* target spacing
        // then allow mining of a min-difficulty block.
        // Zorkcoin uses millisecond timestamps. Heuristic: nTargetSpacing > 30000
        // indicates ms (Zorkcoin uses 150000), and nTimeLast > 1e12 indicates ms.
        int64_t nTargetSpacing = params.nPowTargetSpacing;
        if (nTargetSpacing > 30000) {
            nTargetSpacing = nTargetSpacing / 1000;
        }
        int64_t nTimeLast = pindexLast->GetBlockTime();
        int64_t nTimeBlock = pblock->GetBlockTime();
        if (nTimeLast > 1000000000000LL) {
            nTimeLast = nTimeLast / 1000;
            nTimeBlock = nTimeBlock / 1000;
        }
        if (nTimeBlock > nTimeLast + nTargetSpacing * 2)
            return nProofOfWorkLimit;
    }

    //return CalculateNextWorkRequired(pindexLast, pblock, params);
    // Use ASERT for all blocks (activates from genesis)
    return GravityAsert(pindexLast, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
//unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    return 0x0; // @todo GravityAsert(pindexLast, pblock, params);
/*
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;
    
    // MILLISECOND_TIMESTAMPS:  modifications for correct scaling for NextWork
    // ASERT changes should change all this later
    nActualTimespan = nActualTimespan/1000;
    int64_t nPowTargetSec = params.nPowTargetTimespan/1000;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= nPowTargetSec;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
     */
    // Return current difficulty as fallback
    //return pindexLast->nBits;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
