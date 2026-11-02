// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MNEMONICPHRASEVIEW_H
#define BITCOIN_QT_MNEMONICPHRASEVIEW_H

#include <QString>
#include <QStringList>
#include <QWidget>

#include <array>

class QCheckBox;
class QGridLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QVBoxLayout;

/** Shared BIP39 phrase grid used by create/import dialogs. */
class MnemonicPhraseView : public QWidget
{
    Q_OBJECT

public:
    enum class Mode {
        Reveal,
        Enter,
    };

    enum class WordStatus {
        Exact,
        Interpreted,
        Unknown,
    };

    static constexpr int MAX_WORDS = 24;
    static constexpr int GROUPS = 8;
    static constexpr int WORDS_PER_GROUP = 3;

    explicit MnemonicPhraseView(QWidget* parent = nullptr);
    ~MnemonicPhraseView() override;

    void setMode(Mode mode);
    Mode mode() const { return m_mode; }

    void setWordCount(int word_count);
    int wordCount() const { return m_word_count; }

    void setLanguage(int language);
    int language() const { return m_language; }

    void setWords(const QStringList& words);
    QStringList words() const;

    QString passphrase() const;
    void setPassphrase(const QString& passphrase);

    void wipe();
    QString copyPhrase() const;

    bool isGroupVisible(int group_index) const;
    bool isWrittenDownChecked() const;

    WordStatus validateWord(const QString& input, QString* canonical = nullptr) const;
    bool allWordsValid() const;
    /** Enter mode: true when the current phrase Decode()s with a valid checksum (language auto-detect). */
    bool phraseChecksumValid() const;

Q_SIGNALS:
    void writtenDownChanged(bool checked);
    void validityChanged(bool valid);

private Q_SLOTS:
    void onCellEdited();
    void onCellFocusOut();
    void onWrittenDownToggled(bool checked);
    void onCopyPhraseClicked();

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void rebuildWordListCache();
    void updateGroupVisibility();
    void updateHeader();
    void applyCellStyle(int index, WordStatus status);
    void handlePaste(int start_index, const QString& text);
    int levenshtein(const QString& a, const QString& b) const;

    Mode m_mode{Mode::Reveal};
    int m_word_count{24};
    int m_language{1}; // mnemonic::WLL_ENGLISH

    QLabel* m_header{nullptr};
    QGridLayout* m_grid{nullptr};
    std::array<QWidget*, GROUPS> m_groups{};
    std::array<QLineEdit*, MAX_WORDS> m_cells{};
    QLineEdit* m_passphrase{nullptr};
    QCheckBox* m_written_down{nullptr};
    QPushButton* m_copy_phrase{nullptr};

    QStringList m_wordlist;
};

#endif // BITCOIN_QT_MNEMONICPHRASEVIEW_H
