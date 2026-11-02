// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicphraseview.h>

#include <wallet/mnemonic.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QEvent>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

#include <algorithm>
#include <vector>

namespace {
constexpr QChar IDEOGRAPHIC_SPACE{0x3000};
} // namespace

MnemonicPhraseView::MnemonicPhraseView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);

    m_header = new QLabel(this);
    m_header->setWordWrap(true);
    layout->addWidget(m_header);

    m_grid = new QGridLayout();
    m_grid->setHorizontalSpacing(12);
    m_grid->setVerticalSpacing(8);

    for (int group = 0; group < GROUPS; ++group) {
        auto* group_widget = new QWidget(this);
        auto* group_layout = new QHBoxLayout(group_widget);
        group_layout->setContentsMargins(0, 0, 0, 0);
        group_layout->setSpacing(4);
        m_groups[group] = group_widget;

        for (int i = 0; i < WORDS_PER_GROUP; ++i) {
            const int index = group * WORDS_PER_GROUP + i;
            auto* cell = new QLineEdit(group_widget);
            cell->setObjectName(QStringLiteral("mnemonic_cell_%1").arg(index));
            cell->installEventFilter(this);
            connect(cell, &QLineEdit::textEdited, this, &MnemonicPhraseView::onCellEdited);
            connect(cell, &QLineEdit::editingFinished, this, &MnemonicPhraseView::onCellFocusOut);
            m_cells[index] = cell;
            group_layout->addWidget(cell);
        }

        const int row = group / 2;
        const int col = group % 2;
        m_grid->addWidget(group_widget, row, col);
    }
    layout->addLayout(m_grid);

    m_copy_phrase = new QPushButton(tr("Copy seed phrase"), this);
    m_copy_phrase->setObjectName(QStringLiteral("mnemonic_copy_phrase"));
    m_copy_phrase->setToolTip(tr("Copy all words to the clipboard so you can paste them elsewhere."));
    connect(m_copy_phrase, &QPushButton::clicked, this, &MnemonicPhraseView::onCopyPhraseClicked);
    layout->addWidget(m_copy_phrase);

    auto* pass_row = new QHBoxLayout();
    auto* pass_label = new QLabel(tr("BIP39 passphrase (optional):"), this);
    m_passphrase = new QLineEdit(this);
    m_passphrase->setObjectName(QStringLiteral("mnemonic_passphrase"));
    m_passphrase->setEchoMode(QLineEdit::Password);
    pass_row->addWidget(pass_label);
    pass_row->addWidget(m_passphrase);
    layout->addLayout(pass_row);

    m_written_down = new QCheckBox(tr("I have written down my seed phrase"), this);
    m_written_down->setObjectName(QStringLiteral("mnemonic_written_down"));
    connect(m_written_down, &QCheckBox::toggled, this, &MnemonicPhraseView::onWrittenDownToggled);
    layout->addWidget(m_written_down);

    setLanguage(mnemonic::WLL_ENGLISH);
    setWordCount(24);
    setMode(Mode::Reveal);
}

MnemonicPhraseView::~MnemonicPhraseView()
{
    wipe();
}

void MnemonicPhraseView::setMode(Mode mode)
{
    m_mode = mode;
    const bool reveal = (mode == Mode::Reveal);
    for (auto* cell : m_cells) {
        cell->setReadOnly(reveal);
        if (reveal) {
            cell->setFocusPolicy(Qt::ClickFocus);
        } else {
            cell->setFocusPolicy(Qt::StrongFocus);
        }
    }
    m_written_down->setVisible(reveal);
    m_copy_phrase->setVisible(reveal);
    // Enter mode validates against every BIP39 list (Import ignores Dialog 1 language).
    // Reveal keeps the Create language wordlist for display sizing only.
    rebuildWordListCache();
    updateHeader();
    Q_EMIT validityChanged(allWordsValid());
    Q_EMIT writtenDownChanged(isWrittenDownChecked());
}

void MnemonicPhraseView::setWordCount(int word_count)
{
    if (mnemonic::EntropyBytesForWordCount(word_count) == 0) {
        word_count = 24;
    }
    m_word_count = word_count;
    updateGroupVisibility();
    Q_EMIT validityChanged(allWordsValid());
}

void MnemonicPhraseView::setLanguage(int language)
{
    if (!mnemonic::HaveLanguage(language)) {
        language = mnemonic::WLL_ENGLISH;
    }
    m_language = language;
    rebuildWordListCache();
    // Size cells for longest word in the active list.
    int max_len = 8;
    for (const QString& word : m_wordlist) {
        max_len = std::max(max_len, static_cast<int>(word.size()));
    }
    const QString sample(max_len, QLatin1Char('W'));
    for (auto* cell : m_cells) {
        cell->setMinimumWidth(cell->fontMetrics().horizontalAdvance(sample) + 12);
    }
    if (m_mode == Mode::Enter) {
        onCellEdited();
    }
}

void MnemonicPhraseView::rebuildWordListCache()
{
    m_wordlist.clear();
    auto append_language = [this](int language) {
        for (int i = 0; i < 2048; ++i) {
            SecureString sWord;
            std::string sError;
            if (0 != mnemonic::GetWord(language, i, sWord, sError)) {
                break;
            }
            m_wordlist.push_back(QString::fromUtf8(sWord.c_str()));
            memory_cleanse(sWord.data(), sWord.size());
        }
    };

    if (m_mode == Mode::Enter) {
        // Import: ignore Dialog 1 language; accept words from any enabled list.
        m_wordlist.reserve(2048 * (mnemonic::WLL_MAX - 1));
        for (int lang = mnemonic::WLL_ENGLISH; lang < mnemonic::WLL_MAX; ++lang) {
            if (!mnemonic::HaveLanguage(lang)) continue;
            append_language(lang);
        }
    } else {
        m_wordlist.reserve(2048);
        append_language(m_language);
    }
}

void MnemonicPhraseView::updateGroupVisibility()
{
    const int active_groups = (m_word_count + WORDS_PER_GROUP - 1) / WORDS_PER_GROUP;
    for (int group = 0; group < GROUPS; ++group) {
        m_groups[group]->setVisible(group < active_groups);
    }
}

void MnemonicPhraseView::updateHeader()
{
    if (m_mode == Mode::Reveal) {
        m_header->setText(tr("Write these words down now. This application will not show or store your seed phrase again. "
                             "Exporting keys or descriptors later is a separate backup."));
    } else {
        m_header->setText(tr("Enter your BIP39 seed phrase. Words are validated against the BIP39 word lists; "
                             "near matches are corrected when you leave a field."));
    }
}

void MnemonicPhraseView::setWords(const QStringList& words)
{
    for (int i = 0; i < MAX_WORDS; ++i) {
        if (i < words.size()) {
            m_cells[i]->setText(words.at(i));
        } else {
            m_cells[i]->clear();
        }
        applyCellStyle(i, WordStatus::Exact);
    }
    Q_EMIT validityChanged(allWordsValid());
}

QStringList MnemonicPhraseView::words() const
{
    QStringList out;
    out.reserve(m_word_count);
    for (int i = 0; i < m_word_count; ++i) {
        out.push_back(m_cells[i]->text().trimmed());
    }
    return out;
}

QString MnemonicPhraseView::passphrase() const
{
    return m_passphrase->text();
}

void MnemonicPhraseView::setPassphrase(const QString& passphrase)
{
    m_passphrase->setText(passphrase);
}

void MnemonicPhraseView::wipe()
{
    for (auto* cell : m_cells) {
        QString text = cell->text();
        cell->clear();
        if (!text.isEmpty()) {
            memory_cleanse(text.data(), text.size() * sizeof(QChar));
        }
    }
    QString pass = m_passphrase->text();
    m_passphrase->clear();
    if (!pass.isEmpty()) {
        memory_cleanse(pass.data(), pass.size() * sizeof(QChar));
    }
    m_written_down->setChecked(false);
    // Always clear system clipboards on wipe (accept/cancel/back/destructor).
    // Safer than comparing contents to the phrase; seed must not linger after Copy.
    if (QClipboard* clipboard = QApplication::clipboard()) {
        clipboard->clear(QClipboard::Clipboard);
        clipboard->clear(QClipboard::Selection);
    }
    Q_EMIT validityChanged(false);
    Q_EMIT writtenDownChanged(false);
}

QString MnemonicPhraseView::copyPhrase() const
{
    QString out;
    const int active_groups = (m_word_count + WORDS_PER_GROUP - 1) / WORDS_PER_GROUP;
    for (int group = 0; group < active_groups; ++group) {
        if (group > 0) {
            if (group % 2 == 0) {
                out += QLatin1Char('\n');
            } else {
                out += QLatin1Char('\t');
            }
        }
        for (int i = 0; i < WORDS_PER_GROUP; ++i) {
            const int index = group * WORDS_PER_GROUP + i;
            if (index >= m_word_count) break;
            if (i > 0) out += QLatin1Char(' ');
            out += m_cells[index]->text().trimmed();
        }
    }
    return out;
}

bool MnemonicPhraseView::isGroupVisible(int group_index) const
{
    if (group_index < 0 || group_index >= GROUPS) return false;
    return !m_groups[group_index]->isHidden();
}

bool MnemonicPhraseView::isWrittenDownChecked() const
{
    return m_written_down->isVisible() && m_written_down->isChecked();
}

int MnemonicPhraseView::levenshtein(const QString& a, const QString& b) const
{
    const int n = a.size();
    const int m = b.size();
    if (n == 0) return m;
    if (m == 0) return n;
    std::vector<int> prev(m + 1), cur(m + 1);
    for (int j = 0; j <= m; ++j) prev[j] = j;
    for (int i = 1; i <= n; ++i) {
        cur[0] = i;
        for (int j = 1; j <= m; ++j) {
            const int cost = (a.at(i - 1) == b.at(j - 1)) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        prev.swap(cur);
    }
    return prev[m];
}

MnemonicPhraseView::WordStatus MnemonicPhraseView::validateWord(const QString& input, QString* canonical) const
{
    const QString trimmed = input.trimmed();
    if (trimmed.isEmpty()) {
        if (canonical) canonical->clear();
        return WordStatus::Unknown;
    }

    QStringList exact;
    QStringList prefix;
    QStringList fuzzy;
    for (const QString& word : m_wordlist) {
        if (word.compare(trimmed, Qt::CaseInsensitive) == 0) {
            exact.push_back(word);
        } else if (word.startsWith(trimmed, Qt::CaseInsensitive)) {
            prefix.push_back(word);
        } else if (levenshtein(trimmed.toLower(), word.toLower()) <= 1) {
            fuzzy.push_back(word);
        }
    }

    // Enter mode may contain the same spelling from multiple language lists.
    if (!exact.isEmpty()) {
        if (canonical) *canonical = exact.front();
        return (exact.front() == trimmed) ? WordStatus::Exact : WordStatus::Interpreted;
    }

    auto unique_canonical = [](const QStringList& candidates) -> QString {
        if (candidates.isEmpty()) return {};
        const QString first = candidates.front();
        for (const QString& c : candidates) {
            if (c.compare(first, Qt::CaseInsensitive) != 0) return {};
        }
        return first;
    };

    if (const QString canon = unique_canonical(prefix); !canon.isEmpty()) {
        if (canonical) *canonical = canon;
        return WordStatus::Interpreted;
    }
    if (const QString canon = unique_canonical(fuzzy); !canon.isEmpty()) {
        if (canonical) *canonical = canon;
        return WordStatus::Interpreted;
    }
    if (canonical) canonical->clear();
    return WordStatus::Unknown;
}

bool MnemonicPhraseView::allWordsValid() const
{
    if (m_mode == Mode::Reveal) {
        for (int i = 0; i < m_word_count; ++i) {
            if (m_cells[i]->text().trimmed().isEmpty()) return false;
        }
        return true;
    }
    for (int i = 0; i < m_word_count; ++i) {
        if (validateWord(m_cells[i]->text()) == WordStatus::Unknown) {
            return false;
        }
    }
    return true;
}

bool MnemonicPhraseView::phraseChecksumValid() const
{
    if (!allWordsValid()) return false;
    const QString phrase = words().join(QLatin1Char(' '));
    SecureString mnemonic_words{phrase.toStdString()};
    int n_language = -1;
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
    std::string sError;
    const int rc = mnemonic::Decode(n_language, mnemonic_words, entropy, sError);
    memory_cleanse(mnemonic_words.data(), mnemonic_words.size());
    return rc == 0;
}

void MnemonicPhraseView::applyCellStyle(int index, WordStatus status)
{
    QString color;
    switch (status) {
    case WordStatus::Exact:
        color = QStringLiteral("");
        break;
    case WordStatus::Interpreted:
        color = QStringLiteral("background-color: #fff3cd;");
        break;
    case WordStatus::Unknown:
        color = QStringLiteral("background-color: #f8d7da;");
        break;
    }
    m_cells[index]->setStyleSheet(color);
}

void MnemonicPhraseView::onCellEdited()
{
    if (m_mode != Mode::Enter) {
        Q_EMIT validityChanged(allWordsValid());
        return;
    }
    for (int i = 0; i < m_word_count; ++i) {
        applyCellStyle(i, validateWord(m_cells[i]->text()));
    }
    Q_EMIT validityChanged(allWordsValid());
}

void MnemonicPhraseView::onCellFocusOut()
{
    if (m_mode != Mode::Enter) return;
    auto* cell = qobject_cast<QLineEdit*>(sender());
    if (!cell) return;
    QString canonical;
    const WordStatus status = validateWord(cell->text(), &canonical);
    if (status == WordStatus::Interpreted && !canonical.isEmpty()) {
        cell->setText(canonical);
    }
    onCellEdited();
}

void MnemonicPhraseView::onWrittenDownToggled(bool checked)
{
    Q_EMIT writtenDownChanged(checked);
}

void MnemonicPhraseView::onCopyPhraseClicked()
{
    if (QClipboard* clipboard = QApplication::clipboard()) {
        clipboard->setText(copyPhrase());
    }
}

void MnemonicPhraseView::handlePaste(int start_index, const QString& text)
{
    QString normalized = text;
    normalized.replace(IDEOGRAPHIC_SPACE, QLatin1Char(' '));
    normalized.replace(QLatin1Char('\r'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\n'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\t'), QLatin1Char(' '));
    const QStringList parts = normalized.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    if (parts.size() <= 1) {
        // Single word paste into current cell — default handling.
        return;
    }
    for (int i = 0; i < parts.size() && (start_index + i) < m_word_count; ++i) {
        m_cells[start_index + i]->setText(parts.at(i));
    }
    onCellEdited();
}

bool MnemonicPhraseView::eventFilter(QObject* obj, QEvent* event)
{
    auto* cell = qobject_cast<QLineEdit*>(obj);
    if (!cell) {
        return QWidget::eventFilter(obj, event);
    }

    if (event->type() == QEvent::KeyPress) {
        auto* key = static_cast<QKeyEvent*>(event);
        if (m_mode == Mode::Reveal && key->matches(QKeySequence::Copy)) {
            onCopyPhraseClicked();
            return true;
        }
        if (m_mode == Mode::Enter && key->matches(QKeySequence::Paste)) {
            const QClipboard* clipboard = QApplication::clipboard();
            if (clipboard) {
                int start = 0;
                for (int i = 0; i < MAX_WORDS; ++i) {
                    if (m_cells[i] == cell) {
                        start = i;
                        break;
                    }
                }
                const QString text = clipboard->text();
                QString normalized = text;
                normalized.replace(IDEOGRAPHIC_SPACE, QLatin1Char(' '));
                const QStringList parts = normalized.split(QRegularExpression(QStringLiteral("[\\s\\x{3000}]+")), Qt::SkipEmptyParts);
                if (parts.size() > 1) {
                    handlePaste(start, text);
                    return true;
                }
            }
        }
    }
    return QWidget::eventFilter(obj, event);
}
