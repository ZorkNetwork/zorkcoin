// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_MWEBTESTS_H
#define BITCOIN_QT_TEST_MWEBTESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class MWEBTests : public QObject
{
public:
    explicit MWEBTests(interfaces::Node& node) : m_node(node) {}
    interfaces::Node& m_node;

    Q_OBJECT

private Q_SLOTS:
    void mwebUriTests();
    void reassignMWEBAmountsTests();
    void availableBalanceTests();
    void partialReceiveIdentityTests();
    void partialReceiveStatusTests();
    void pegOutSendTests();
    void createUnsignedTests();
};

#endif // BITCOIN_QT_TEST_MWEBTESTS_H
