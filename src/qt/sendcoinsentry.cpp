// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sendcoinsentry.h>
#include <qt/forms/ui_sendcoinsentry.h>

#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>
#include <util/result.h>

#include <algorithm>

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QMessageBox>
#include <QSignalBlocker>
#include <QToolButton>

SendCoinsEntry::SendCoinsEntry(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SendCoinsEntry),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);

    GUIUtil::setupAddressWidget(ui->payTo, this);
    m_address_placeholder = ui->payTo->placeholderText();

    // MWEB: Peg-In / Peg-Out icon buttons beside the address book button
    m_mweb_pegin_button = new QToolButton(this);
    m_mweb_pegin_button->setObjectName(QStringLiteral("mwebPegInButton"));
    m_mweb_pegin_button->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/mweb_pegin")));
    m_mweb_pegin_button->setToolButtonStyle(Qt::ToolButtonIconOnly);
    m_mweb_pegin_button->setIconSize(QSize(22, 22));
    m_mweb_pegin_button->setCheckable(true);
    m_mweb_pegin_button->setToolTip(tr("Peg-In your own funds to the Confidential layer"));
    m_mweb_pegin_button->setAutoRaise(true);

    m_mweb_pegout_button = new QToolButton(this);
    m_mweb_pegout_button->setObjectName(QStringLiteral("mwebPegOutButton"));
    m_mweb_pegout_button->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/mweb_pegout")));
    m_mweb_pegout_button->setToolButtonStyle(Qt::ToolButtonIconOnly);
    m_mweb_pegout_button->setIconSize(QSize(22, 22));
    m_mweb_pegout_button->setCheckable(true);
    m_mweb_pegout_button->setToolTip(tr("Peg-Out your own funds from the Confidential layer"));
    m_mweb_pegout_button->setAutoRaise(true);

    const int addr_idx = ui->payToLayout->indexOf(ui->addressBookButton);
    ui->payToLayout->insertWidget(addr_idx + 1, m_mweb_pegin_button);
    ui->payToLayout->insertWidget(addr_idx + 2, m_mweb_pegout_button);
    m_mweb_pegin_button->hide();
    m_mweb_pegout_button->hide();
    connect(m_mweb_pegin_button, &QToolButton::clicked, this, &SendCoinsEntry::handleMwebPegInClicked);
    connect(m_mweb_pegout_button, &QToolButton::clicked, this, &SendCoinsEntry::handleMwebPegOutClicked);

    // MWEB: address type of a peg-out, beside the address it previews
    m_pegout_address_type = new QComboBox(this);
    m_pegout_address_type->setObjectName(QStringLiteral("pegOutAddressType"));
    m_pegout_address_type->setToolTip(tr("Type of the address of this wallet that the peg-out pays"));
    ui->payToLayout->insertWidget(ui->payToLayout->indexOf(ui->payTo) + 1, m_pegout_address_type);
    m_pegout_address_type->hide();
    connect(m_pegout_address_type, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsEntry::updatePegOutAddress);

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
    connect(ui->checkboxSubtractFeeFromAmount, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
    connect(ui->deleteButton, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->useAvailableBalanceButton, &QPushButton::clicked, this, &SendCoinsEntry::useAvailableBalanceClicked);
}

SendCoinsEntry::~SendCoinsEntry()
{
    delete ui;
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    updateLabel(address);
}

void SendCoinsEntry::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model && _model->getOptionsModel())
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsEntry::updateDisplayUnit);

    // MWEB: a peg-out pays a transparent address of this wallet, so only the types it has addresses of are offered.
    if (_model) {
        const QSignalBlocker blocker(m_pegout_address_type);
        m_pegout_address_type->clear();
        auto add_address_type = [&](OutputType type, const QString& text) {
            if (_model->wallet().peekNewDestination(type)) m_pegout_address_type->addItem(text, (int)type);
        };
        add_address_type(OutputType::LEGACY, tr("Base58 (Legacy)"));
        add_address_type(OutputType::P2SH_SEGWIT, tr("Base58 (P2SH-SegWit)"));
        add_address_type(OutputType::BECH32, tr("Bech32 (SegWit)"));
        add_address_type(OutputType::BECH32M, tr("Bech32m (Taproot)"));
        const int default_index{m_pegout_address_type->findData((int)_model->wallet().getDefaultAddressType())};
        m_pegout_address_type->setCurrentIndex(default_index >= 0 ? default_index : std::max(m_pegout_address_type->findData((int)OutputType::BECH32), 0));
    }

    clear();
    updateMWEBButtons();
}

void SendCoinsEntry::setPaymentKind(SendCoinsRecipient::PaymentKind kind)
{
    recipient.payment_kind = kind;
    syncMWEBButtonState();
    applyPaymentKindUi();
}

void SendCoinsEntry::syncMWEBButtonState()
{
    if (!m_mweb_pegin_button || !m_mweb_pegout_button) return;
    QSignalBlocker peg_in_blocker(m_mweb_pegin_button);
    QSignalBlocker peg_out_blocker(m_mweb_pegout_button);
    m_mweb_pegin_button->setChecked(recipient.payment_kind == SendCoinsRecipient::PaymentKind::PEGIN);
    m_mweb_pegout_button->setChecked(recipient.payment_kind == SendCoinsRecipient::PaymentKind::PEGOUT);
}

void SendCoinsEntry::updateMWEBButtons()
{
    const bool show = model && model->wallet().mwebEnabled();
    if (m_mweb_pegin_button) {
        m_mweb_pegin_button->setVisible(show);
        if (show) {
            m_mweb_pegin_button->setEnabled(true);
            m_mweb_pegin_button->setToolTip(tr("Peg-In your own funds to the Confidential layer"));
        }
    }
    if (m_mweb_pegout_button) {
        m_mweb_pegout_button->setVisible(show);
    }
}

void SendCoinsEntry::handleMwebPegInClicked(bool checked)
{
    if (checked && m_mweb_pegout_button && m_mweb_pegout_button->isChecked()) {
        m_mweb_pegout_button->setChecked(false);
    }
    setPaymentKind(checked ? SendCoinsRecipient::PaymentKind::PEGIN : SendCoinsRecipient::PaymentKind::REGULAR);
    Q_EMIT manualPaymentKindChanged(this, recipient.payment_kind);
}

void SendCoinsEntry::handleMwebPegOutClicked(bool checked)
{
    if (checked && m_mweb_pegin_button && m_mweb_pegin_button->isChecked()) {
        m_mweb_pegin_button->setChecked(false);
    }
    setPaymentKind(checked ? SendCoinsRecipient::PaymentKind::PEGOUT : SendCoinsRecipient::PaymentKind::REGULAR);
    Q_EMIT manualPaymentKindChanged(this, recipient.payment_kind);
}

void SendCoinsEntry::applyPaymentKindUi()
{
    switch (recipient.payment_kind) {
    case SendCoinsRecipient::PaymentKind::PEGIN: {
        if (!model) break;
        StealthAddress pegin;
        if (!model->wallet().getPeginAddress(pegin)) {
            ui->payTo->clear();
            ui->payTo->setReadOnly(true);
            break;
        }
        ui->payTo->setText(QString::fromStdString(EncodeDestination(pegin)));
        ui->payTo->setReadOnly(true);
        ui->payTo->setPlaceholderText(QString());
        ui->addressBookButton->setEnabled(false);
        ui->pasteButton->setEnabled(false);
        break;
    }
    case SendCoinsRecipient::PaymentKind::PEGOUT:
        // A peg-out pays the next address of this wallet, which is taken once the send is confirmed.
        ui->payTo->setReadOnly(true);
        ui->addressBookButton->setEnabled(false);
        ui->pasteButton->setEnabled(false);
        updatePegOutAddress();
        break;
    case SendCoinsRecipient::PaymentKind::REGULAR:
        ui->payTo->setPlaceholderText(m_address_placeholder);
        ui->payTo->setReadOnly(false);
        ui->addressBookButton->setEnabled(true);
        ui->pasteButton->setEnabled(true);
        break;
    }
    m_pegout_address_type->setVisible(recipient.payment_kind == SendCoinsRecipient::PaymentKind::PEGOUT);
}

void SendCoinsEntry::updatePegOutAddress()
{
    if (!model || recipient.payment_kind != SendCoinsRecipient::PaymentKind::PEGOUT) return;
    const auto dest = model->wallet().peekNewDestination(OutputType(m_pegout_address_type->currentData().toInt()));
    ui->payTo->setText(dest ? QString::fromStdString(EncodeDestination(*dest)) : QString());
    ui->payTo->setPlaceholderText(dest ? tr("Peg-Out Address") : QString::fromStdString(util::ErrorString(dest).translated));
}

void SendCoinsEntry::clear()
{
    // clear UI elements for normal payment
    recipient.payment_kind = SendCoinsRecipient::PaymentKind::REGULAR;
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    if (model && model->getOptionsModel()) {
        ui->checkboxSubtractFeeFromAmount->setChecked(model->getOptionsModel()->getSubFeeFromAmount());
    }
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();

    applyPaymentKindUi();
    syncMWEBButtonState();

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendCoinsEntry::checkSubtractFeeFromAmount()
{
    if (recipient.payment_kind != SendCoinsRecipient::PaymentKind::REGULAR) return;
    ui->checkboxSubtractFeeFromAmount->setChecked(true);
}

void SendCoinsEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

void SendCoinsEntry::useAvailableBalanceClicked()
{
    Q_EMIT useAvailableBalance(this);
}

bool SendCoinsEntry::validate(interfaces::Node& node)
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

    const bool is_pegin = recipient.payment_kind == SendCoinsRecipient::PaymentKind::PEGIN;
    const bool is_pegout = recipient.payment_kind == SendCoinsRecipient::PaymentKind::PEGOUT;

    if (!is_pegin && !model->validateAddress(ui->payTo->text()))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if (!ui->payAmount->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(nullptr) <= 0)
    {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // Reject dust outputs:
    if (retval && !is_pegin && GUIUtil::isDust(node, ui->payTo->text(), ui->payAmount->value())) {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // MWEB: reject stealth sends, peg-ins and peg-outs before network activation
    const bool mweb_before_activation = (is_pegin || is_pegout)
        ? !node.isMWEBActive()
        : GUIUtil::isMWEBAddressBeforeActivated(node, ui->payTo->text());
    if (retval && mweb_before_activation) {
        ui->payTo->setValid(false);
        retval = false;

        QMessageBox msgBox;
        msgBox.setInformativeText(tr("You cannot send to an MWEB address until after the feature has been activated."));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.setDefaultButton(QMessageBox::Ok);
        msgBox.exec();
    }

    return retval;
}

SendCoinsRecipient SendCoinsEntry::getValue()
{
    recipient.address = ui->payTo->text();
    recipient.label = ui->addAsLabel->text();
    recipient.amount = ui->payAmount->value();
    recipient.message = ui->messageTextLabel->text();
    recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);
    recipient.pegout_address_type = OutputType(m_pegout_address_type->currentData().toInt()); // MWEB

    return recipient;
}

QWidget *SendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addAsLabel);
    QWidget *w = ui->payAmount->setupTabChain(ui->addAsLabel);
    QWidget::setTabOrder(w, ui->checkboxSubtractFeeFromAmount);
    QWidget::setTabOrder(ui->checkboxSubtractFeeFromAmount, ui->addressBookButton);
    QWidget* last = ui->addressBookButton;
    if (m_mweb_pegin_button && !m_mweb_pegin_button->isHidden()) {
        QWidget::setTabOrder(last, m_mweb_pegin_button);
        last = m_mweb_pegin_button;
    }
    if (m_mweb_pegout_button && !m_mweb_pegout_button->isHidden()) {
        QWidget::setTabOrder(last, m_mweb_pegout_button);
        last = m_mweb_pegout_button;
    }
    QWidget::setTabOrder(last, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void SendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    recipient = value;
    syncMWEBButtonState();
    applyPaymentKindUi();
    {
        // message
        ui->messageTextLabel->setText(recipient.message);
        ui->messageTextLabel->setVisible(!recipient.message.isEmpty());
        ui->messageLabel->setVisible(!recipient.message.isEmpty());

        ui->addAsLabel->clear();
        ui->payTo->setText(recipient.address); // this may set a label from addressbook
        if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            ui->addAsLabel->setText(recipient.label);
        ui->payAmount->setValue(recipient.amount);
    }
}

void SendCoinsEntry::setAddress(const QString &address)
{
    // MWEB: a peg-in or peg-out pays this wallet's own address, so an address given here makes it a regular payment.
    if (recipient.payment_kind != SendCoinsRecipient::PaymentKind::REGULAR) {
        setPaymentKind(SendCoinsRecipient::PaymentKind::REGULAR);
    }
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void SendCoinsEntry::setAmount(const CAmount &amount)
{
    ui->payAmount->setValue(amount);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if (model && model->getOptionsModel()) {
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void SendCoinsEntry::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/address-book")));
        if (m_mweb_pegin_button) {
            m_mweb_pegin_button->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/mweb_pegin")));
        }
        if (m_mweb_pegout_button) {
            m_mweb_pegout_button->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/mweb_pegout")));
        }
        ui->pasteButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editpaste")));
        ui->deleteButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/remove")));
    }

    QWidget::changeEvent(e);
}

bool SendCoinsEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
    {
        ui->addAsLabel->setText(associatedLabel);
        return true;
    }

    return false;
}

#include <moc_sendcoinsentry.cpp>
