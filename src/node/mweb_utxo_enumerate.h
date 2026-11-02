// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_UTXO_ENUMERATE_H
#define BITCOIN_NODE_MWEB_UTXO_ENUMERATE_H

#include <mw/mmr/leaf_index.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/utxo.h>
#include <uint256.h>
#include <util/result.h>

#include <cstdint>
#include <functional>

namespace mw {
class ICoinsView;
}

namespace node {

struct MWEBUnspentEntry {
    mw::Hash output_id;
    int32_t block_height;
    mmr::LeafIndex leaf_index;
    std::vector<uint8_t> leaf_data;
    const Output& output;
};

/**
 * Iterate unspent MWEB outputs via leafset + output PMMR (hot chainstate path).
 * Requires a view with non-null leafset and output PMMR (e.g. GetMWEBCacheView()).
 * Callback returning false aborts; returns count examined or error.
 */
util::Result<uint64_t> ForEachUnspentMWEBUTXO(
    const mw::ICoinsView& view,
    const std::function<bool(MWEBUnspentEntry&&)>& fn,
    const std::function<void()>& interruption_point = {});

} // namespace node

#endif // BITCOIN_NODE_MWEB_UTXO_ENUMERATE_H
