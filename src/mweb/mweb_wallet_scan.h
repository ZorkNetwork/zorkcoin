// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_WALLET_SCAN_H
#define BITCOIN_MWEB_MWEB_WALLET_SCAN_H

#include <cstdint>

namespace MWEB {

struct UTXOScanStats {
    uint64_t examined{0};
    uint64_t matched{0};
    uint64_t persisted{0};
    uint64_t indices_persisted{0};
    bool aborted{false};
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_WALLET_SCAN_H
