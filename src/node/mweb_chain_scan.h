// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_CHAIN_SCAN_H
#define BITCOIN_NODE_MWEB_CHAIN_SCAN_H

#include <mw/models/tx/output.h>

#include <cstdint>
#include <functional>
#include <string>

namespace node {

struct NodeContext;

struct MWEBUTXOScanResult {
    bool success{false};
    std::string error;
    uint64_t examined{0};
};

/** Scan active chainstate MWEB UTXOs at tip; holds cs_main and CoinsViewScanReserver. */
MWEBUTXOScanResult ScanMWEBUTXOsAtTip(
    node::NodeContext& node,
    const std::function<bool(int32_t height, const Output& output)>& callback,
    const std::function<void()>& interruption_point = {});

} // namespace node

#endif // BITCOIN_NODE_MWEB_CHAIN_SCAN_H
