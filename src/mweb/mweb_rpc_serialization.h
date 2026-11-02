// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_RPC_SERIALIZATION_H
#define BITCOIN_MWEB_MWEB_RPC_SERIALIZATION_H

#include <common/args.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <cstddef>
#include <vector>

namespace MWEB {

//! -rpcserialversion, as in Litecoin Core: 1 leaves MWEB data out of raw transaction
//! and block output (RPC, REST and ZMQ), 2 includes it. Bitcoin Core removed 0.
inline constexpr int DEFAULT_RPC_SERIALIZE_VERSION{2};

inline bool RPCSerializeWithMWEB()
{
    return gArgs.GetIntArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) >= 2;
}

//! Raw block bytes from disk, re-serialized without MWEB data when -rpcserialversion=1.
inline std::vector<std::byte> RPCRawBlock(std::vector<std::byte> block_data)
{
    if (RPCSerializeWithMWEB()) return block_data;
    CBlock block;
    SpanReader{block_data} >> TX_WITH_WITNESS(block);
    DataStream stream;
    stream << TX_NO_MWEB(block);
    return {stream.begin(), stream.end()};
}

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_RPC_SERIALIZATION_H
