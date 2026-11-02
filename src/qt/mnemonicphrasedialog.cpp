// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicphrasedialog.h>

#include <key.h>
#include <qt/guiutil.h>
#include <support/cleanse.h>
#include <wallet/mnemonic.h>

#include <QByteArray>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

#include <algorithm>
#include <string>
#include <vector>

namespace {
SecureString ToSecureString(const QString& text)
{
    QByteArray utf8 = text.toUtf8();
    SecureString out(utf8.constData(), utf8.size());
    memory_cleanse(utf8.data(), utf8.size());
    return out;
}

void SecureClear(SecureString& str)
{
    memory_cleanse(str.data(), str.size());
    str.clear();
}
} // namespace

MnemonicPhraseDialog::MnemonicPhraseDialog(int word_count, int language, bool create_mode, QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags),
      m_word_count(word_count),
      m_language(language),
      m_create_mode(create_mode)
{
    setWindowTitle(create_mode ? tr("Write down your seed phrase") : tr("Enter your seed phrase"));

    auto* layout = new QVBoxLayout(this);
    m_view = new MnemonicPhraseView(this);
    m_view->setLanguage(m_language);
    m_view->setWordCount(m_word_count);
    m_view->setMode(create_mode ? MnemonicPhraseView::Mode::Reveal : MnemonicPhraseView::Mode::Enter);
    layout->addWidget(m_view);

    m_buttons = new QDialogButtonBox(this);
    m_back = m_buttons->addButton(tr("Back"), QDialogButtonBox::ActionRole);
    m_primary = m_buttons->addButton(create_mode ? tr("Continue") : tr("Restore"), QDialogButtonBox::AcceptRole);
    m_buttons->addButton(QDialogButtonBox::Cancel);
    layout->addWidget(m_buttons);

    connect(m_back, &QPushButton::clicked, this, &MnemonicPhraseDialog::onBack);
    connect(m_primary, &QPushButton::clicked, this, &MnemonicPhraseDialog::onContinue);
    connect(m_buttons, &QDialogButtonBox::rejected, this, [this] {
        secureWipe();
        reject();
    });
    connect(m_view, &MnemonicPhraseView::writtenDownChanged, this, &MnemonicPhraseDialog::updatePrimaryButton);
    connect(m_view, &MnemonicPhraseView::validityChanged, this, &MnemonicPhraseDialog::updatePrimaryButton);

    if (m_create_mode) {
        if (!generatePhrase()) {
            QMessageBox::critical(this, tr("Mnemonic generation failed"), tr("Could not generate a seed phrase."));
        }
    }

    updatePrimaryButton();
    GUIUtil::handleCloseWindowShortcut(this);
}

MnemonicPhraseDialog::~MnemonicPhraseDialog()
{
    // wipe() emits validity/writtenDown signals connected to this dialog. Block
    // them first so Debug Qt does not assert on slots during destruction.
    if (m_view) {
        m_view->blockSignals(true);
    }
    secureWipe();
    SecureClear(m_phrase);
    SecureClear(m_passphrase);
}

void MnemonicPhraseDialog::takeMnemonic(SecureString& phrase, SecureString& passphrase)
{
    phrase.swap(m_phrase);
    passphrase.swap(m_passphrase);
    SecureClear(m_phrase);
    SecureClear(m_passphrase);
}

bool MnemonicPhraseDialog::generatePhrase()
{
    const size_t n_entropy = mnemonic::EntropyBytesForWordCount(m_word_count);
    if (n_entropy == 0) return false;

    CKey seed_key = GenerateRandomKey();
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy(n_entropy);
    std::transform(seed_key.begin(), seed_key.begin() + n_entropy, entropy.begin(),
                   [](std::byte b) { return static_cast<uint8_t>(b); });

    SecureString words;
    std::string sError;
    if (0 != mnemonic::Encode(m_language, entropy, words, sError)) {
        memory_cleanse(words.data(), words.size());
        return false;
    }

    QStringList list = QString::fromUtf8(words.c_str()).split(QLatin1Char(' '), Qt::SkipEmptyParts);
    // Japanese uses ideographic space in some lists; Encode returns space-separated for UI via Decode/Encode path.
    // Split also on ideographic space if present.
    if (list.size() != m_word_count) {
        list = QString::fromUtf8(words.c_str()).split(QRegularExpression(QStringLiteral("[\\s\\x{3000}]+")), Qt::SkipEmptyParts);
    }
    m_view->setWords(list);
    memory_cleanse(words.data(), words.size());
    return list.size() == m_word_count;
}

bool MnemonicPhraseDialog::collectMnemonic()
{
    QStringList word_list = m_view->words();
    if (m_create_mode) {
        // Reveal path already has exact words; ensure they are non-empty.
        for (const QString& w : word_list) {
            if (w.isEmpty()) return false;
        }
    } else {
        // Canonicalize Interpreted words before validation.
        for (int i = 0; i < word_list.size(); ++i) {
            QString canonical;
            const auto status = m_view->validateWord(word_list.at(i), &canonical);
            if (status == MnemonicPhraseView::WordStatus::Unknown) {
                return false;
            }
            if (status == MnemonicPhraseView::WordStatus::Interpreted && !canonical.isEmpty()) {
                word_list[i] = canonical;
            }
        }
        m_view->setWords(word_list);
    }

    SecureString phrase = ToSecureString(word_list.join(QLatin1Char(' ')));
    int n_language = -1;
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
    std::string sError;
    if (0 != mnemonic::Decode(n_language, phrase, entropy, sError)) {
        SecureClear(phrase);
        QMessageBox::critical(this, tr("Invalid seed phrase"), QString::fromStdString(sError));
        return false;
    }

    SecureClear(m_phrase);
    SecureClear(m_passphrase);
    m_phrase.swap(phrase);
    m_passphrase = ToSecureString(m_view->passphrase());
    return true;
}

void MnemonicPhraseDialog::updatePrimaryButton()
{
    bool enable = m_view->allWordsValid();
    if (m_create_mode) {
        enable = enable && m_view->isWrittenDownChecked();
    } else {
        // §9.5: Restore only when words are valid and Decode checksum passes.
        enable = enable && m_view->phraseChecksumValid();
    }
    m_primary->setEnabled(enable);
}

void MnemonicPhraseDialog::onBack()
{
    m_navigated_back = true;
    secureWipe();
    done(Back);
}

void MnemonicPhraseDialog::onContinue()
{
    if (!collectMnemonic()) {
        return;
    }
    secureWipe();
    accept();
}

void MnemonicPhraseDialog::secureWipe()
{
    if (m_view) {
        m_view->wipe();
    }
}
