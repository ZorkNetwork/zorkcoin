// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_MNEMONICPHRASEVIEW_TESTS_H
#define BITCOIN_QT_TEST_MNEMONICPHRASEVIEW_TESTS_H

#include <QObject>
#include <QTest>

class MnemonicPhraseViewTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void gridVisibilityForWordCounts();
    void copyPhraseFormat();
    void wipeClearsCells();
    void wipeClearsClipboard();
    void enterChecksumGatesValidity();
    void enterIgnoresDialogLanguage();
};

#endif // BITCOIN_QT_TEST_MNEMONICPHRASEVIEW_TESTS_H
