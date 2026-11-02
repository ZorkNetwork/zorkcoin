// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicsetupdialog.h>

#include <common/args.h>
#include <wallet/mnemonic.h>
#include <qt/guiutil.h>

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLocale>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QVBoxLayout>

#include <stdexcept>

MnemonicSetupDialog::MnemonicSetupDialog(QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags)
{
    setWindowTitle(tr("Mnemonic wallet setup"));
    auto* layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel(tr("Choose how many words, which language, and whether to create a new phrase or import an existing one."), this));

    auto* form = new QFormLayout();
    m_word_count = new QComboBox(this);
    for (int n : {12, 15, 18, 21, 24}) {
        m_word_count->addItem(QString::number(n), n);
    }
    m_word_count->setCurrentIndex(m_word_count->findData(24));
    form->addRow(tr("Word count"), m_word_count);

    m_language = new QComboBox(this);
    for (int lang = mnemonic::WLL_ENGLISH; lang < mnemonic::WLL_MAX; ++lang) {
        if (!mnemonic::HaveLanguage(lang)) continue;
        m_language->addItem(QString::fromUtf8(mnemonic::mnLanguagesDesc[lang]),
                            QString::fromUtf8(mnemonic::mnLanguagesTag[lang]));
    }
    const QString default_tag = DefaultLanguageTag();
    const int default_index = m_language->findData(default_tag);
    m_language->setCurrentIndex(default_index >= 0 ? default_index : 0);
    form->addRow(tr("Language"), m_language);
    layout->addLayout(form);

    m_create = new QRadioButton(tr("Create new seed phrase"), this);
    m_import = new QRadioButton(tr("Import existing seed phrase"), this);
    m_create->setChecked(true);
    layout->addWidget(m_create);
    layout->addWidget(m_import);

    m_buttons = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok, this);
    m_buttons->button(QDialogButtonBox::Ok)->setText(tr("Next"));
    connect(m_buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(m_buttons);

    GUIUtil::handleCloseWindowShortcut(this);
}

int MnemonicSetupDialog::wordCount() const
{
    return m_word_count->currentData().toInt();
}

QString MnemonicSetupDialog::languageTag() const
{
    return m_language->currentData().toString();
}

int MnemonicSetupDialog::language() const
{
    try {
        return mnemonic::GetLanguageOffset(languageTag().toStdString());
    } catch (const std::runtime_error&) {
        return mnemonic::WLL_ENGLISH;
    }
}

bool MnemonicSetupDialog::isCreateMode() const
{
    return m_create->isChecked();
}

QString MnemonicSetupDialog::DefaultLanguageTag()
{
    // Mirror GetLangTerritory() priority: system → QSettings → -lang
    QSettings settings;
    QString lang_territory = QLocale::system().name();
    const QString from_settings = settings.value(QStringLiteral("language"), QString()).toString();
    if (!from_settings.isEmpty()) {
        lang_territory = from_settings;
    }
    lang_territory = QString::fromStdString(gArgs.GetArg("-lang", lang_territory.toStdString()));

    const QString lower = lang_territory.toLower().replace(QLatin1Char('-'), QLatin1Char('_'));
    if (lower.startsWith(QStringLiteral("zh_cn")) || lower.startsWith(QStringLiteral("zh_hans")) ||
        lower == QStringLiteral("zh") || lower.startsWith(QStringLiteral("cmn"))) {
        return QStringLiteral("chinese_s");
    }
    if (lower.startsWith(QStringLiteral("zh_tw")) || lower.startsWith(QStringLiteral("zh_hk")) ||
        lower.startsWith(QStringLiteral("zh_hant"))) {
        return QStringLiteral("chinese_t");
    }

    const QString primary = lower.section(QLatin1Char('_'), 0, 0);
    if (primary == QStringLiteral("en")) return QStringLiteral("english");
    if (primary == QStringLiteral("fr")) return QStringLiteral("french");
    if (primary == QStringLiteral("ja")) return QStringLiteral("japanese");
    if (primary == QStringLiteral("es")) return QStringLiteral("spanish");
    if (primary == QStringLiteral("it")) return QStringLiteral("italian");
    if (primary == QStringLiteral("ko")) return QStringLiteral("korean");
    if (primary == QStringLiteral("cs")) return QStringLiteral("czech");
    if (primary == QStringLiteral("pt")) return QStringLiteral("portuguese");
    return QStringLiteral("english");
}
