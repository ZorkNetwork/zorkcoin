// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_QT_TEST_MWEB_WALLET_TESTS_H
#define BITCOIN_QT_TEST_MWEB_WALLET_TESTS_H
#include <memory>
namespace interfaces { class Node; }
namespace wallet { class CWallet; }
void TestGUIMWEBReceive(interfaces::Node& node, const std::shared_ptr<wallet::CWallet>& wallet);
#endif
