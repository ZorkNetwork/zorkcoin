// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_AUXPOW_H
#define BITCOIN_TEST_UTIL_AUXPOW_H

#include <auxpow/auxpow.h>
#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_header.h>
#include <auxpow/kaspa_pow.h>
#include <auxpow/kaspa_tx.h>
#include <auxpow/version.h>
#include <arith_uint256.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace auxpow::test {

/** Largest target Kaspa compact bits can encode (0xffff << 240). */
static constexpr uint32_t EASIEST_KASPA_BITS{0x2100ffff};

inline void WriteLE32Vec(std::vector<unsigned char>& v, uint32_t x)
{
    v.push_back(x & 0xff);
    v.push_back((x >> 8) & 0xff);
    v.push_back((x >> 16) & 0xff);
    v.push_back((x >> 24) & 0xff);
}

inline KaspaTransaction MakeCoinbaseWithMM(const uint256& aux_root_internal, uint32_t merkle_size, uint32_t merkle_nonce)
{
    KaspaTransaction tx;
    tx.version = 1;
    KaspaTxOutput out;
    out.value = 50;
    out.script_version = 0;
    out.script = {0x00};
    tx.outputs.push_back(out);
    std::memcpy(tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);

    std::vector<unsigned char> payload(19, 0);
    payload.insert(payload.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + 4);
    uint256 rev = aux_root_internal;
    std::reverse(rev.begin(), rev.end());
    payload.insert(payload.end(), rev.begin(), rev.end());
    WriteLE32Vec(payload, merkle_size);
    WriteLE32Vec(payload, merkle_nonce);
    tx.payload = std::move(payload);
    return tx;
}

inline void InitLeanPeerHeader(KaspaHeader& h, uint32_t bits)
{
    h.version = 2;
    h.parents_by_level = {KaspaParentRun{1, {KaspaHashFromU64(1)}}};
    h.accepted_id_merkle_root = KaspaHashFromU64(3);
    h.utxo_commitment = KaspaHashFromU64(4);
    h.timestamp = 1'700'000'000'000ull;
    h.bits = bits;
    h.nonce = 0;
    h.daa_score = 1;
    h.blue_score = 1;
    std::memset(h.blue_work, 0, sizeof(h.blue_work));
    h.pruning_point = KaspaHashFromU64(5);
}

/** Extra distinct level-0 parents to grow the serialized peer header. */
inline void InflatePeerParents(KaspaHeader& h, size_t extra_parents)
{
    auto& run = h.parents_by_level.at(0);
    for (size_t i = 0; i < extra_parents; ++i) {
        run.parents.push_back(KaspaHashFromU64(100 + i));
    }
}

inline CAuxPow MakeStructuralAuxPow(const CBlockHeader& hdr, uint32_t kaspa_bits, size_t extra_parents = 0)
{
    CAuxPow aux;
    aux.version = 1;
    aux.nChainIndex = 0;
    aux.coinbase_tx = MakeCoinbaseWithMM(hdr.GetHash(), /*merkle_size=*/1, /*merkle_nonce=*/0);
    InitLeanPeerHeader(aux.peer_header, kaspa_bits);
    InflatePeerParents(aux.peer_header, extra_parents);
    aux.peer_header.hash_merkle_root = KaspaTransactionHash(aux.coinbase_tx);
    return aux;
}

/** 2-leaf aux-chain: dummy sibling, merkle_size=2, nChainIndex from GetExpectedIndex. */
inline CAuxPow MakeTwoLeafAuxPow(const CBlockHeader& hdr, uint32_t kaspa_bits, int32_t chain_id, uint32_t merkle_nonce = 0, size_t extra_parents = 0)
{
    const uint256 sibling = KaspaHashFromU64(99);
    const int index = GetExpectedIndex(merkle_nonce, chain_id, /*h=*/1);
    const uint256 aux_root = ComputeAuxChainRoot(hdr.GetHash(), {sibling}, static_cast<uint32_t>(index));
    CAuxPow aux;
    aux.version = 1;
    aux.nChainIndex = index;
    aux.vChainMerkleBranch = {sibling};
    aux.coinbase_tx = MakeCoinbaseWithMM(aux_root, /*merkle_size=*/2, merkle_nonce);
    InitLeanPeerHeader(aux.peer_header, kaspa_bits);
    InflatePeerParents(aux.peer_header, extra_parents);
    aux.peer_header.hash_merkle_root = KaspaTransactionHash(aux.coinbase_tx);
    return aux;
}

template <typename Pred>
inline bool GrindPeerNonce(KaspaHeader& hdr, Pred pred, uint64_t max_nonce = 16'000'000)
{
    for (uint64_t nonce = 0; nonce < max_nonce; ++nonce) {
        hdr.nonce = nonce;
        if (pred(KaspaPeerPoW(hdr))) return true;
    }
    return false;
}

inline bool GrindPeerToMeetBoth(KaspaHeader& hdr, const uint256& T_kd, const uint256& T_floor, uint64_t max_nonce = 16'000'000)
{
    const arith_uint256 kd = UintToArith256(T_kd);
    const arith_uint256 floor = UintToArith256(T_floor);
    const arith_uint256 limit = kd < floor ? kd : floor;
    return GrindPeerNonce(hdr, [&](const uint256& h) { return UintToArith256(h) <= limit; }, max_nonce);
}

struct DualTargets {
    uint256 T_K;
    uint256 T_kd;
    uint256 T_Z;
    uint256 T_floor;
};

inline DualTargets ComputeDualTargets(uint32_t zork_bits, uint32_t kaspa_bits, uint32_t floor_mult, uint32_t kaspa_mult)
{
    DualTargets t;
    arith_uint256 bn;
    bool neg = false, over = false;
    bn.SetCompact(zork_bits, &neg, &over);
    t.T_Z = ArithToUint256(bn);
    t.T_floor = ArithToUint256(bn / floor_mult);
    DecodeKaspaCompactBits(kaspa_bits, t.T_K);
    t.T_kd = ArithToUint256(UintToArith256(t.T_K) / kaspa_mult);
    return t;
}

struct WorkFlags {
    bool le_TK{false};
    bool le_TK3000{false};
    bool le_TZ{false};
    bool le_TZ4{false};
};

inline WorkFlags ClassifyPow(const uint256& h, const DualTargets& t)
{
    const arith_uint256 H = UintToArith256(h);
    WorkFlags f;
    f.le_TK = H <= UintToArith256(t.T_K);
    f.le_TK3000 = H <= UintToArith256(t.T_kd);
    f.le_TZ = H <= UintToArith256(t.T_Z);
    f.le_TZ4 = H <= UintToArith256(t.T_floor);
    return f;
}

inline bool FlagsEq(const WorkFlags& a, const WorkFlags& b)
{
    return a.le_TK == b.le_TK && a.le_TK3000 == b.le_TK3000 && a.le_TZ == b.le_TZ && a.le_TZ4 == b.le_TZ4;
}

} // namespace auxpow::test

#endif // BITCOIN_TEST_UTIL_AUXPOW_H
