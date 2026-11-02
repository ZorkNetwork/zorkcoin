// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coinsview_scan_reserver.h>

namespace node {

std::atomic<bool> g_coinsview_scan_in_progress{false};

} // namespace node
