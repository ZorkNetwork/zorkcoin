// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_chain_scan.h>

#include <chain.h>
#include <deploymentstatus.h>
#include <kernel/cs_main.h>
#include <node/coinsview_scan_reserver.h>
#include <node/context.h>
#include <node/mweb_utxo_enumerate.h>
#include <sync.h>
#include <validation.h>

namespace node {

MWEBUTXOScanResult ScanMWEBUTXOsAtTip(
    node::NodeContext& node,
    const std::function<bool(int32_t height, const Output& output)>& callback,
    const std::function<void()>& interruption_point)
{
    MWEBUTXOScanResult result;
    ChainstateManager* chainman = node.chainman.get();
    if (!chainman) {
        result.error = "No chain manager";
        return result;
    }

    CoinsViewScanReserver reserver;
    if (!reserver.reserve()) {
        result.error = "UTXO set scan already in progress";
        return result;
    }

    LOCK(::cs_main);
    Chainstate& active_chainstate = chainman->ActiveChainstate();
    const CBlockIndex* tip = active_chainstate.m_chain.Tip();
    if (!tip) {
        result.error = "No active chain tip";
        return result;
    }

    if (!DeploymentActiveAt(*tip, *chainman, Consensus::DEPLOYMENT_MWEB)) {
        result.error = "MWEB is not active at chain tip";
        return result;
    }

    active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);

    CCoinsViewCache& coins_tip = active_chainstate.CoinsTip();
    const auto mweb_view = coins_tip.GetMWEBCacheView();
    if (!mweb_view) {
        result.error = "MWEB chainstate view unavailable at tip";
        return result;
    }

    auto examined = ForEachUnspentMWEBUTXO(
        *mweb_view,
        [&](MWEBUnspentEntry&& entry) {
            return callback(entry.block_height, entry.output);
        },
        interruption_point);

    if (!examined) {
        result.error = util::ErrorString(examined).original;
        return result;
    }

    result.success = true;
    result.examined = *examined;
    return result;
}

} // namespace node
