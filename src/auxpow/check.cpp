// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/check.h>

#include <auxpow/kaspa_merkle.h>
#include <auxpow/kaspa_pow.h>
#include <auxpow/kaspa_tx.h>
#include <auxpow/version.h>
#include <arith_uint256.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <cstring>

namespace auxpow {
namespace {

bool CheckTargetLE(const uint256& hash, const uint256& target)
{
    return UintToArith256(hash) <= UintToArith256(target);
}

uint256 DivideTargetFloor(const uint256& target, uint32_t divisor)
{
    if (divisor == 0) return uint256::ZERO;
    return ArithToUint256(UintToArith256(target) / divisor);
}

} // namespace

bool CheckAuxPow(const CBlockHeader& hdr, const CAuxPow& aux, const Consensus::Params& params, std::string* err)
{
    if (!params.auxpow.fGenesisActive) {
        if (err) *err = "auxpow not active";
        return false;
    }
    if (!IsAuxPow(hdr.nVersion)) {
        if (err) *err = "auxpow bit not set";
        return false;
    }
    if (!HasAuxPowNonceMarker(hdr.nNonce)) {
        if (err) *err = "auxpow nonce marker mismatch";
        return false;
    }
    if (GetAuxPowNonceChainId(hdr.nNonce) != params.auxpow.nChainId) {
        if (err) *err = "auxpow chain id mismatch";
        return false;
    }
    if (aux.version != 1) {
        if (err) *err = "auxpow version must be 1";
        return false;
    }
    if (!CheckAuxPowSizeLimits(aux, params.auxpow, err)) {
        return false;
    }
    if (aux.peer_header.version != 2) {
        if (err) *err = "peer header version must be 2";
        return false;
    }
    if (!aux.peer_header.IsRleCanonical(err)) {
        return false;
    }
    if (!IsKaspaCoinbaseShape(aux.coinbase_tx, err)) {
        return false;
    }

    uint256 T_K;
    if (!DecodeKaspaCompactBits(aux.peer_header.bits, T_K, err)) {
        return false;
    }
    uint256 T_Z;
    {
        arith_uint256 bn;
        bool fNeg = false, fOver = false;
        bn.SetCompact(hdr.nBits, &fNeg, &fOver);
        if (fNeg || fOver || bn == 0) {
            if (err) *err = "invalid zork nBits";
            return false;
        }
        T_Z = ArithToUint256(bn);
    }

    const uint256 T_floor = DivideTargetFloor(T_Z, params.auxpow.nFloorMultiplier);
    const uint256 T_kd = DivideTargetFloor(T_K, params.auxpow.nKaspaMultiplier);
    if (T_floor.IsNull() || T_kd.IsNull()) {
        if (err) *err = "derived auxpow target is zero";
        return false;
    }

    const uint256 h = KaspaPeerPoW(aux.peer_header);
    if (!CheckTargetLE(h, T_K)) {
        if (err) *err = "peer pow exceeds T_K";
        return false;
    }
    if (!CheckTargetLE(h, T_kd)) {
        if (err) *err = "peer pow exceeds T_K/3000";
        return false;
    }
    if (!CheckTargetLE(h, T_floor)) {
        if (err) *err = "peer pow exceeds T_Z/4";
        return false;
    }

    const uint256 leaf = KaspaTransactionHash(aux.coinbase_tx);
    if (!CheckKaspaTxMerkleBranch(leaf, aux.vMerkleBranch, /*index=*/0, aux.peer_header.hash_merkle_root, err)) {
        return false;
    }

    const uint256 hash_aux_block = hdr.GetHash();
    const uint256 aux_root = ComputeAuxChainRoot(hash_aux_block, aux.vChainMerkleBranch, static_cast<uint32_t>(aux.nChainIndex));

    uint64_t blue_score = 0, subsidy = 0;
    uint16_t spk_ver = 0;
    std::vector<unsigned char> spk, extra;
    if (!ParseKaspaCoinbasePayload(aux.coinbase_tx.payload, blue_score, subsidy, spk_ver, spk, extra, err)) {
        return false;
    }

    uint256 root_rev;
    uint32_t merkle_size = 0, merkle_nonce = 0;
    if (!FindMergedMiningRecord(extra, root_rev, merkle_size, merkle_nonce, err)) {
        return false;
    }

    uint256 root_expected = aux_root;
    std::reverse(root_expected.begin(), root_expected.end());
    if (root_rev != root_expected) {
        if (err) *err = "merged-mining root mismatch";
        return false;
    }

    if (aux.vChainMerkleBranch.size() > 31) {
        if (err) *err = "chain merkle height too large";
        return false;
    }
    const uint32_t expect_size = 1u << aux.vChainMerkleBranch.size();
    if (merkle_size != expect_size) {
        if (err) *err = "merkle_size mismatch";
        return false;
    }
    if (aux.nChainIndex != GetExpectedIndex(merkle_nonce, params.auxpow.nChainId, static_cast<unsigned>(aux.vChainMerkleBranch.size()))) {
        if (err) *err = "nChainIndex mismatch";
        return false;
    }

    return true;
}

} // namespace auxpow
