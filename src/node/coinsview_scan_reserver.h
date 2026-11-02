// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_COINSVIEW_SCAN_RESERVER_H
#define BITCOIN_NODE_COINSVIEW_SCAN_RESERVER_H

#include <atomic>
#include <util/check.h>

namespace node {

/** Shared guard: only one chainstate UTXO scan (L1 scantxoutset or MWEB) at a time. */
extern std::atomic<bool> g_coinsview_scan_in_progress;

/** RAII object to prevent concurrent scans of the UTXO set. */
class CoinsViewScanReserver
{
    bool m_could_reserve{false};

public:
    CoinsViewScanReserver() = default;

    bool reserve()
    {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_coinsview_scan_in_progress.exchange(true)) {
            return false;
        }
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver()
    {
        if (m_could_reserve) {
            g_coinsview_scan_in_progress = false;
        }
    }
};

} // namespace node

#endif // BITCOIN_NODE_COINSVIEW_SCAN_RESERVER_H
