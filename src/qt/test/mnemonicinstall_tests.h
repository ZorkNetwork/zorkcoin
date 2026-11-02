// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_MNEMONICINSTALL_TESTS_H
#define BITCOIN_QT_TEST_MNEMONICINSTALL_TESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class MnemonicInstallTests : public QObject
{
public:
    explicit MnemonicInstallTests(interfaces::Node& node) : m_node(node) {}
    interfaces::Node& m_node;

    Q_OBJECT

private Q_SLOTS:
    void rejectDifferentMnemonicAfterInstall();
    void resumeAfterMasterAdded();
    void rejectPassphraseMismatch();
    void installIntoEncryptedWallet();
    void installIntoEncryptedWalletWrongPassphrase();
    void createWalletActivityCancelCreatesNothing();
    void createWalletActivityImportsPhrase();
    void restoreScanCancellationAndRetry();
    void createWalletDefaultOptionStates();
    void createWalletDisablePrivateKeysExcludesKeyedOptions();
    void createWalletEncryptExcludesDisablePrivateKeys();
    void createWalletBlankAndMnemonicAreExclusive();
    void createWalletExternalSignerLocksOptions();
    void createWalletMnemonicBlocksExternalSignerDefault();
};

#endif // BITCOIN_QT_TEST_MNEMONICINSTALL_TESTS_H
