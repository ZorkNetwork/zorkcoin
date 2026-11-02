// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_AUXPOW_H
#define BITCOIN_AUXPOW_AUXPOW_H

#include <auxpow/kaspa_header.h>
#include <auxpow/kaspa_tx.h>
#include <consensus/params.h>
#include <serialize.h>
#include <span>
#include <uint256.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace auxpow {

struct CAuxPow;
size_t GetSerializeSizeAuxPow(const CAuxPow& aux);

/** Consensus size caps, matching Consensus::Params::AuxPow defaults. Enforced during unserialize. */
static constexpr uint32_t MAX_AUXPOW_SERIALIZED_SIZE = 1280;
static constexpr uint32_t MAX_AUXPOW_PEER_HEADER_SIZE = 720;
static constexpr uint32_t MAX_AUXPOW_COINBASE_TX_SIZE = 400;
static constexpr uint32_t MAX_AUXPOW_TX_MERKLE_BRANCH_HASHES = 8;
static constexpr uint32_t MAX_AUXPOW_CHAIN_MERKLE_BRANCH_HASHES = 5;
static constexpr uint32_t AUXPOW_CHAINWORK_REF = 8192;

struct CAuxPow {
    uint32_t version{1};
    KaspaHeader peer_header;
    KaspaTransaction coinbase_tx;
    std::vector<uint256> vMerkleBranch;
    std::vector<uint256> vChainMerkleBranch;
    int32_t nChainIndex{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        std::vector<unsigned char> header_bytes;
        std::vector<unsigned char> tx_bytes;
        if (!SerializeKaspaHeader(peer_header, header_bytes)) {
            throw std::ios_base::failure("serialize auxpow peer_header");
        }
        if (!SerializeKaspaTransaction(coinbase_tx, tx_bytes)) {
            throw std::ios_base::failure("serialize auxpow coinbase_tx");
        }
        ::Serialize(s, header_bytes);
        ::Serialize(s, tx_bytes);
        ::Serialize(s, vMerkleBranch);
        ::Serialize(s, vChainMerkleBranch);
        ::Serialize(s, nChainIndex);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        std::vector<unsigned char> header_bytes;
        std::vector<unsigned char> tx_bytes;
        // Cap CompactSizes before allocating (DoS).
        ::Unserialize(s, Using<LimitedVectorFormatter<MAX_AUXPOW_PEER_HEADER_SIZE>>(header_bytes));
        ::Unserialize(s, Using<LimitedVectorFormatter<MAX_AUXPOW_COINBASE_TX_SIZE>>(tx_bytes));
        size_t consumed = 0;
        if (!DeserializeKaspaHeader(header_bytes, peer_header, consumed) || consumed != header_bytes.size()) {
            throw std::ios_base::failure("bad auxpow peer_header");
        }
        consumed = 0;
        if (!DeserializeKaspaTransaction(tx_bytes, coinbase_tx, consumed) || consumed != tx_bytes.size()) {
            throw std::ios_base::failure("bad auxpow coinbase_tx");
        }
        ::Unserialize(s, Using<LimitedVectorFormatter<MAX_AUXPOW_TX_MERKLE_BRANCH_HASHES>>(vMerkleBranch));
        ::Unserialize(s, Using<LimitedVectorFormatter<MAX_AUXPOW_CHAIN_MERKLE_BRANCH_HASHES>>(vChainMerkleBranch));
        ::Unserialize(s, nChainIndex);
        if (GetSerializeSizeAuxPow(*this) > MAX_AUXPOW_SERIALIZED_SIZE) {
            throw std::ios_base::failure("auxpow header extension exceeds max serialized size");
        }
    }
};

bool CheckAuxPowSizeLimits(const CAuxPow& aux, const Consensus::Params::AuxPow& lim, std::string* err = nullptr);
/** Serialized equality: a later proof for the same 88-byte hash must match the first-seen extension. */
bool AuxPowEqual(const CAuxPow& a, const CAuxPow& b);

static constexpr unsigned char PCH_MERGED_MINING_HEADER[4] = {0xfa, 0xbe, 0x6d, 0x6d};

int GetExpectedIndex(uint32_t nNonce, int32_t nChainId, unsigned h);
uint256 AuxChainMerkleHash(const uint256& left, const uint256& right);
uint256 ComputeAuxChainRoot(const uint256& leaf, const std::vector<uint256>& branch, uint32_t index);

bool FindMergedMiningRecord(const std::vector<unsigned char>& extra_data,
                            uint256& root_reversed,
                            uint32_t& merkle_size,
                            uint32_t& merkle_nonce,
                            std::string* err = nullptr);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_AUXPOW_H
