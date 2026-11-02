// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MNEMONICPHRASEDIALOG_H
#define BITCOIN_QT_MNEMONICPHRASEDIALOG_H

#include <qt/mnemonicphraseview.h>
#include <support/allocators/secure.h>

#include <QDialog>

class QDialogButtonBox;
class QPushButton;

/** Dialog 2 of the BIP39 wizard: reveal a generated phrase or enter one to import.
 *  Nothing is written to a wallet; the confirmed phrase is handed back to the caller. */
class MnemonicPhraseDialog : public QDialog
{
    Q_OBJECT

public:
    enum ResultCode {
        Accepted = QDialog::Accepted,
        Rejected = QDialog::Rejected,
        Back = 2,
    };

    MnemonicPhraseDialog(int word_count, int language, bool create_mode, QWidget* parent = nullptr);
    ~MnemonicPhraseDialog() override;

    bool navigatedBack() const { return m_navigated_back; }

    /** Move the confirmed phrase and BIP39 passphrase out of the dialog (valid after Accepted). */
    void takeMnemonic(SecureString& phrase, SecureString& passphrase);

private Q_SLOTS:
    void onBack();
    void onContinue();
    void updatePrimaryButton();

private:
    bool generatePhrase();
    bool collectMnemonic();
    void secureWipe();

    int m_word_count{24};
    int m_language{1};
    bool m_create_mode{true};
    bool m_navigated_back{false};
    SecureString m_phrase;
    SecureString m_passphrase;

    MnemonicPhraseView* m_view{nullptr};
    QPushButton* m_back{nullptr};
    QPushButton* m_primary{nullptr};
    QDialogButtonBox* m_buttons{nullptr};
};

#endif // BITCOIN_QT_MNEMONICPHRASEDIALOG_H
