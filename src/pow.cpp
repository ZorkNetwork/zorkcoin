// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

unsigned int GravityAsert(const CBlockIndex* pindexLast, const CBlockHeader* /*pblock*/, const Consensus::Params& params)
{
    // Integer-only aserti3-2d from a permanent genesis anchor.
    // next_target = anchor_target * 2^((time_delta - T*(height_delta+1)) / half_life)
    // time_delta uses the parent tip timestamp, not the candidate header.
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    const unsigned int nPowLimitCompact = bnPowLimit.GetCompact();

    if (pindexLast == nullptr) {
        return nPowLimitCompact;
    }

    const int nAnchorHeight = 0;
    const CBlockIndex* pindexAnchor = pindexLast->GetAncestor(nAnchorHeight);
    if (pindexAnchor == nullptr || pindexAnchor->nHeight != nAnchorHeight) {
        return nPowLimitCompact;
    }

    const int64_t nTimeRef = pindexAnchor->GetBlockTime();
    const int64_t nTimeCurr = pindexLast->GetBlockTime();
    const int64_t nTimeDiff = nTimeCurr - nTimeRef;
    const int64_t nHeightDiff = pindexLast->nHeight - nAnchorHeight;

    arith_uint256 bnAnchorTarget;
    bnAnchorTarget.SetCompact(pindexAnchor->nBits);

    const int64_t nExpected = params.nPowTargetSpacing * (nHeightDiff + 1);
    const int64_t exponent = ((nTimeDiff - nExpected) * 65536) / params.nASERTHalfLife;

    int64_t shifts = exponent >> 16;
    const uint16_t frac = static_cast<uint16_t>(exponent);

    const uint64_t factor = 65536ULL + ((195766423245049ULL * frac + 971821376ULL * frac * frac +
                                         5127ULL * frac * frac * frac + (1ULL << 47)) >> 48);

    arith_uint256 bnNext = bnAnchorTarget;
    bnNext *= arith_uint256{factor};

    shifts -= 16;

    if (shifts < 0) {
        if (-shifts >= 256) {
            bnNext = arith_uint256{1};
        } else {
            bnNext >>= -shifts;
        }
    } else if (shifts > 0) {
        if (shifts >= 256) {
            bnNext = bnPowLimit;
        } else {
            const arith_uint256 bnNextShifted = bnNext << static_cast<int>(shifts);
            if ((bnNextShifted >> static_cast<int>(shifts)) != bnNext) {
                bnNext = bnPowLimit;
            } else {
                bnNext = bnNextShifted;
            }
        }
    }

    if (bnNext > bnPowLimit) {
        bnNext = bnPowLimit;
    }
    if (bnNext == arith_uint256() || bnNext < arith_uint256{1}) {
        bnNext = arith_uint256{1};
    }

    return bnNext.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (params.fPowAllowMinDifficultyBlocks) {
        // Millisecond consensus times: a gap of more than 2*spacing permits min-diff.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
            return nProofOfWorkLimit;
        }
    }

    return GravityAsert(pindexLast, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }
    // SMA retarget is unused: ASERT is the only retarget. Keep a defined result
    // for any leftover call sites.
    return pindexLast->nBits;
}

bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    // ASERT retargets every block; the SMA 4x window does not apply.
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
