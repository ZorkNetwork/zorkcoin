// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/mnemonicphraseview_tests.h>

#include <wallet/mnemonic.h>
#include <qt/mnemonicphraseview.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>

#include <QApplication>
#include <QClipboard>
#include <QRegularExpression>
#include <QStringList>

#include <string>
#include <vector>

namespace {
QStringList MakeWords(int count)
{
    QStringList words;
    words.reserve(count);
    for (int i = 0; i < count; ++i) {
        words << QStringLiteral("w%1").arg(i);
    }
    return words;
}

QStringList EnglishVector12()
{
    return QStringLiteral("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .split(QLatin1Char(' '));
}
} // namespace

void MnemonicPhraseViewTests::gridVisibilityForWordCounts()
{
    MnemonicPhraseView view;
    view.setMode(MnemonicPhraseView::Mode::Reveal);

    const struct {
        int words;
        int visible_groups;
    } cases[] = {
        {12, 4},
        {15, 5},
        {18, 6},
        {21, 7},
        {24, 8},
    };

    for (const auto& c : cases) {
        view.setWordCount(c.words);
        QCOMPARE(view.wordCount(), c.words);
        for (int g = 0; g < MnemonicPhraseView::GROUPS; ++g) {
            QCOMPARE(view.isGroupVisible(g), g < c.visible_groups);
        }
    }
}

void MnemonicPhraseViewTests::copyPhraseFormat()
{
    MnemonicPhraseView view;
    view.setMode(MnemonicPhraseView::Mode::Reveal);
    view.setWordCount(12);
    view.setWords(MakeWords(12));

    // 4 groups on 2 rows: spaces within group, tab between groups, newline between rows.
    QCOMPARE(view.copyPhrase(), QStringLiteral("w0 w1 w2\tw3 w4 w5\nw6 w7 w8\tw9 w10 w11"));

    view.setWordCount(15);
    view.setWords(MakeWords(15));
    QCOMPARE(view.copyPhrase(), QStringLiteral("w0 w1 w2\tw3 w4 w5\nw6 w7 w8\tw9 w10 w11\nw12 w13 w14"));

    view.setWordCount(24);
    view.setWords(MakeWords(24));
    QCOMPARE(view.copyPhrase(),
             QStringLiteral("w0 w1 w2\tw3 w4 w5\nw6 w7 w8\tw9 w10 w11\nw12 w13 w14\tw15 w16 w17\nw18 w19 w20\tw21 w22 w23"));
}

void MnemonicPhraseViewTests::wipeClearsCells()
{
    MnemonicPhraseView view;
    view.setMode(MnemonicPhraseView::Mode::Enter);
    view.setWordCount(12);
    view.setWords(MakeWords(12));
    view.setPassphrase(QStringLiteral("secret-pass"));

    QCOMPARE(view.words().size(), 12);
    QVERIFY(!view.words().front().isEmpty());
    QCOMPARE(view.passphrase(), QStringLiteral("secret-pass"));

    view.wipe();

    for (const QString& w : view.words()) {
        QVERIFY(w.isEmpty());
    }
    QVERIFY(view.passphrase().isEmpty());
    QVERIFY(!view.isWrittenDownChecked());
}

void MnemonicPhraseViewTests::wipeClearsClipboard()
{
    MnemonicPhraseView view;
    view.setMode(MnemonicPhraseView::Mode::Reveal);
    view.setWordCount(12);
    view.setWords(MakeWords(12));

    const QString phrase = view.copyPhrase();
    QClipboard* clipboard = QApplication::clipboard();
    QVERIFY(clipboard);
    clipboard->setText(phrase, QClipboard::Clipboard);
    clipboard->setText(phrase, QClipboard::Selection);
    QCOMPARE(clipboard->text(QClipboard::Clipboard), phrase);

    view.wipe();

    QVERIFY(clipboard->text(QClipboard::Clipboard).isEmpty());
    QVERIFY(clipboard->text(QClipboard::Selection).isEmpty());
}

void MnemonicPhraseViewTests::enterChecksumGatesValidity()
{
    MnemonicPhraseView view;
    view.setMode(MnemonicPhraseView::Mode::Enter);
    view.setWordCount(12);

    // Valid English words but invalid BIP39 checksum.
    QStringList bad_checksum = EnglishVector12();
    bad_checksum[11] = QStringLiteral("abandon");
    view.setWords(bad_checksum);
    QVERIFY(view.allWordsValid());
    QVERIFY(!view.phraseChecksumValid());

    view.setWords(EnglishVector12());
    QVERIFY(view.allWordsValid());
    QVERIFY(view.phraseChecksumValid());
}

void MnemonicPhraseViewTests::enterIgnoresDialogLanguage()
{
    MnemonicPhraseView view;
    // Simulate Dialog 1 language = English, then Import Enter mode with a French phrase.
    view.setLanguage(mnemonic::WLL_ENGLISH);
    view.setMode(MnemonicPhraseView::Mode::Enter);
    view.setWordCount(12);

    // Prefer Encode→Decode round-trip so accents match the codec wordlist exactly.
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy(16, 0x11);
    SecureString words;
    std::string sError;
    QVERIFY(0 == mnemonic::Encode(mnemonic::WLL_FRENCH, entropy, words, sError));
    const QStringList french = QString::fromUtf8(words.c_str()).split(QRegularExpression(QStringLiteral("[\\s\\x{3000}]+")), Qt::SkipEmptyParts);
    memory_cleanse(words.data(), words.size());
    QCOMPARE(french.size(), 12);

    view.setWords(french);
    QVERIFY(view.allWordsValid());
    QVERIFY(view.phraseChecksumValid());
}
