// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>

#include <crypto/common.h>
#include <hash.h>
#include <streams.h>

#include <algorithm>
#include <cstring>

namespace auxpow {

bool CheckAuxPowSizeLimits(const CAuxPow& aux, const Consensus::Params::AuxPow& lim, std::string* err)
{
    std::vector<unsigned char> header_bytes;
    std::vector<unsigned char> tx_bytes;
    if (!SerializeKaspaHeader(aux.peer_header, header_bytes)) {
        if (err) *err = "peer_header serialize failed";
        return false;
    }
    if (!SerializeKaspaTransaction(aux.coinbase_tx, tx_bytes)) {
        if (err) *err = "coinbase serialize failed";
        return false;
    }
    if (header_bytes.size() > lim.nMaxPeerHeaderSize) {
        if (err) *err = "peer_header too large";
        return false;
    }
    if (tx_bytes.size() > lim.nMaxCoinbaseTxSize) {
        if (err) *err = "coinbase_tx too large";
        return false;
    }
    if (aux.vMerkleBranch.size() > lim.nMaxTxMerkleBranchHashes) {
        if (err) *err = "tx merkle branch too long";
        return false;
    }
    if (aux.vChainMerkleBranch.size() > lim.nMaxChainMerkleBranchHashes) {
        if (err) *err = "chain merkle branch too long";
        return false;
    }
    if (aux.vChainMerkleBranch.size() > 30) {
        if (err) *err = "chain merkle branch exceeds Dogecoin limit";
        return false;
    }
    const size_t total = GetSerializeSizeAuxPow(aux);
    if (total > lim.nMaxSerializedSize) {
        if (err) *err = "auxpow header extension exceeds max serialized size";
        return false;
    }
    return true;
}

size_t GetSerializeSizeAuxPow(const CAuxPow& aux)
{
    DataStream ss{};
    ss << aux;
    return ss.size();
}

bool AuxPowEqual(const CAuxPow& a, const CAuxPow& b)
{
    DataStream sa{};
    DataStream sb{};
    sa << a;
    sb << b;
    return sa.size() == sb.size() && std::equal(sa.begin(), sa.end(), sb.begin());
}

int GetExpectedIndex(uint32_t nNonce, int32_t nChainId, unsigned h)
{
    if (h > 31) {
        return 0;
    }
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += static_cast<uint32_t>(nChainId);
    rand = rand * 1103515245 + 12345;
    return static_cast<int>(rand % (1u << h));
}

uint256 AuxChainMerkleHash(const uint256& left, const uint256& right)
{
    return (HashWriter{} << left << right).GetHash();
}

uint256 ComputeAuxChainRoot(const uint256& leaf, const std::vector<uint256>& branch, uint32_t index)
{
    uint256 h = leaf;
    for (const auto& sibling : branch) {
        if ((index & 1u) == 0) {
            h = AuxChainMerkleHash(h, sibling);
        } else {
            h = AuxChainMerkleHash(sibling, h);
        }
        index >>= 1;
    }
    return h;
}

bool FindMergedMiningRecord(const std::vector<unsigned char>& extra_data,
                            uint256& root_reversed,
                            uint32_t& merkle_size,
                            uint32_t& merkle_nonce,
                            std::string* err)
{
    size_t found = 0;
    size_t pos = 0;
    for (size_t i = 0; i + 4 <= extra_data.size(); ++i) {
        if (std::memcmp(extra_data.data() + i, PCH_MERGED_MINING_HEADER, 4) == 0) {
            ++found;
            pos = i;
        }
    }
    if (found != 1) {
        if (err) *err = found == 0 ? "merged-mining magic missing" : "merged-mining magic not unique";
        return false;
    }
    if (pos + 44 > extra_data.size()) {
        if (err) *err = "merged-mining record truncated";
        return false;
    }
    const unsigned char* p = extra_data.data() + pos + 4;
    std::memcpy(root_reversed.begin(), p, 32);
    merkle_size = ReadLE32(p + 32);
    merkle_nonce = ReadLE32(p + 36);
    return true;
}

} // namespace auxpow
