// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MNEMONICSETUPDIALOG_H
#define BITCOIN_QT_MNEMONICSETUPDIALOG_H

#include <QDialog>

class QComboBox;
class QDialogButtonBox;
class QRadioButton;

/** Dialog 1 of the BIP39 create-wallet wizard: word count, language, create vs import. */
class MnemonicSetupDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MnemonicSetupDialog(QWidget* parent = nullptr);

    int wordCount() const;
    QString languageTag() const;
    int language() const;
    bool isCreateMode() const;

    static QString DefaultLanguageTag();

private:
    QComboBox* m_word_count{nullptr};
    QComboBox* m_language{nullptr};
    QRadioButton* m_create{nullptr};
    QRadioButton* m_import{nullptr};
    QDialogButtonBox* m_buttons{nullptr};
};

#endif // BITCOIN_QT_MNEMONICSETUPDIALOG_H
