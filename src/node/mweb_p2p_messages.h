// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_P2P_MESSAGES_H
#define BITCOIN_NODE_MWEB_P2P_MESSAGES_H

#include <mw/common/dynamic_bit_set.h>
#include <mw/models/tx/utxo.h>
#include <serialize.h>
#include <uint256.h>

#include <vector>

class NetUTXO;

struct MWEBLeafsetMsg
{
    MWEBLeafsetMsg() = default;
    MWEBLeafsetMsg(uint256 block_hash_in, mw::DynamicBitSet leafset_in)
        : block_hash(std::move(block_hash_in)), leafset(std::move(leafset_in)) { }

    SERIALIZE_METHODS(MWEBLeafsetMsg, obj) { READWRITE(obj.block_hash, obj.leafset); }

    uint256 block_hash;
    mw::DynamicBitSet leafset;
};

struct GetMWEBUTXOsMsg
{
    GetMWEBUTXOsMsg() = default;

    SERIALIZE_METHODS(GetMWEBUTXOsMsg, obj)
    {
        READWRITE(obj.block_hash, COMPACTSIZE(obj.start_index), obj.num_requested, obj.output_format);
    }

    uint256 block_hash;
    uint64_t start_index{0};
    uint16_t num_requested{0};
    uint8_t output_format{0};
};

struct MWEBUTXOsMsg
{
    MWEBUTXOsMsg() = default;

    SERIALIZE_METHODS(MWEBUTXOsMsg, obj)
    {
        READWRITE(obj.block_hash, COMPACTSIZE(obj.start_index), obj.output_format, obj.utxos, obj.proof_hashes);
    }

    uint256 block_hash;
    uint64_t start_index{0};
    uint8_t output_format{0};
    std::vector<NetUTXO> utxos;
    std::vector<mw::Hash> proof_hashes;
};

#endif // BITCOIN_NODE_MWEB_P2P_MESSAGES_H
