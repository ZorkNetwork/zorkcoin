// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_COIN_H
#define BITCOIN_NODE_COIN_H

#include <mw/models/crypto/hash.h>
#include <mw/models/tx/output.h>

#include <map>
#include <optional>

class COutPoint;
class Coin;

namespace node {
struct NodeContext;

/**
 * Look up unspent output information. Returns coins in the mempool and in the
 * current chain UTXO set. Iterates through all the keys in the map and
 * populates the values.
 *
 * @param[in] node The node context to use for lookup
 * @param[in,out] coins map to fill
 */
void FindCoins(const node::NodeContext& node, std::map<COutPoint, Coin>& coins);

/**
 * Look up unspent MWEB outputs by output ID, in the mempool and in the current
 * chain MWEB UTXO set. Outputs that are unknown or spent are set to nullopt.
 */
void FindCoins(const node::NodeContext& node, std::map<mw::Hash, std::optional<Output>>& coins);
} // namespace node

#endif // BITCOIN_NODE_COIN_H
