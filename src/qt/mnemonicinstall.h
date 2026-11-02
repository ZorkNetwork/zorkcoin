// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MNEMONICINSTALL_H
#define BITCOIN_QT_MNEMONICINSTALL_H

#include <support/allocators/secure.h>

#include <QString>

namespace interfaces {
class Node;
class Wallet;
} // namespace interfaces

/** Install BIP39 mnemonic as unused HD master and create active descriptors (incl. MWEB).
 *  When restoring, finish with the wallet RPC historical rescan. A failed or aborted
 *  scan leaves the installed keys available for a later retry. */
bool InstallMnemonicHdKey(interfaces::Node& node, const QString& wallet_name,
                          const SecureString& passphrase, const SecureString& mnemonic,
                          QString& error_message, bool restore = false);

/** Install a BIP39 mnemonic into a newly created blank wallet. If the wallet was
 *  created encrypted, encryption_passphrase unlocks it for the install and the
 *  wallet is locked again afterwards. */
bool InstallMnemonicIntoNewWallet(interfaces::Node& node, interfaces::Wallet& wallet,
                                  const SecureString& encryption_passphrase,
                                  const SecureString& mnemonic, const SecureString& passphrase,
                                  QString& error_message, bool restore = false);

#endif // BITCOIN_QT_MNEMONICINSTALL_H
