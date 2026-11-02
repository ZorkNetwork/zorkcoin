// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coin.h>

#include <node/context.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void FindCoins(const NodeContext& node, std::map<COutPoint, Coin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    for (auto& [outpoint, coin] : coins) {
        if (auto c{mempool_view.GetCoin(outpoint)}) {
            coin = std::move(*c);
        } else {
            coin.Clear(); // Either the coin is not in the CCoinsViewCache or is spent
        }
    }
}

void FindCoins(const NodeContext& node, std::map<mw::Hash, std::optional<Output>>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    const CCoinsView& view{mempool_view};
    for (auto& [output_id, coin] : coins) {
        Output output;
        if (view.GetMWEBCoin(output_id, output)) {
            coin = std::move(output);
        } else {
            coin.reset();
        }
    }
}
} // namespace node
