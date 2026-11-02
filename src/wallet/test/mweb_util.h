// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_MWEB_UTIL_H
#define BITCOIN_WALLET_TEST_MWEB_UTIL_H

#include <consensus/amount.h>
#include <mw/models/crypto/hash.h>

#include <map>

struct MWEBRegtest100Setup;

namespace wallet {
class CWallet;

//! Pegs `amount` of the wallet's L1 coins into MWEB at 10 sat/vB, mines the peg-in and returns
//! the wallet's confirmed MWEB coins. The wallet must be receiving the chain's notifications.
std::map<mw::Hash, CAmount> PegInAndMine(MWEBRegtest100Setup& setup, CWallet& wallet, CAmount amount);
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_MWEB_UTIL_H
