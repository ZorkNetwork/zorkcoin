// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/mweb_wallet_tests.h>
#include <qt/test/wallettests.h>
#include <qt/test/util.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <qt/bitcoinamountfield.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/sendcoinsrecipient.h>
#include <qt/transactiondesc.h>
#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <script/solver.h>
#include <kernel/chainparams.h>
#include <outputtype.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <chrono>
#include <memory>
#include <QComboBox>
#include <QLabel>
#include <QAbstractButton>
#include <QStandardItemModel>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QObject>
#include <QPushButton>
#include <QTimer>
#include <QToolButton>
#include <QTest>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QMessageBox>
#include <QDialogButtonBox>
using wallet::AddWallet;
using wallet::CWallet;
using wallet::RemoveWallet;
using wallet::WalletContext;

static SendCoinsEntry* FindSendEntry(SendCoinsDialog& dialog)
{
    for (QObject* child : dialog.findChildren<QObject*>()) {
        if (auto* entry = qobject_cast<SendCoinsEntry*>(child)) {
            return entry;
        }
    }
    return nullptr;
}

void TestGUIMWEBReceive(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    bilingual_str error;
    OptionsModel optionsModel(node);
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(node, &optionsModel);

    WalletContext& context = *node.walletLoader().context();
    AddWallet(context, wallet);
    WalletModel walletModel(interfaces::MakeWallet(context, wallet), clientModel, platformStyle.get());
    RemoveWallet(context, wallet, std::nullopt);

    ReceiveCoinsDialog receiveDialog(platformStyle.get());
    receiveDialog.setModel(&walletModel);

    auto* addressTypeCombo = receiveDialog.findChild<QComboBox*>("addressType");
    QVERIFY(addressTypeCombo);
    bool found_mweb = false;
    for (int i = 0; i < addressTypeCombo->count(); ++i) {
        if (static_cast<OutputType>(addressTypeCombo->itemData(i).toInt()) == OutputType::MWEB) {
            addressTypeCombo->setCurrentIndex(i);
            found_mweb = true;
            break;
        }
    }
    QVERIFY(found_mweb);

    auto* receiveButton = receiveDialog.findChild<QPushButton*>("receiveButton");
    QVERIFY(receiveButton);
    QVERIFY(receiveButton->isEnabled());
    QTest::mouseClick(receiveButton, Qt::LeftButton);

    const QString hrp = QString::fromStdString(Params().MWEB_HRP());
    QString generated_address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (auto* req = qobject_cast<ReceiveRequestDialog*>(widget)) {
            auto* address_label = req->findChild<QLabel*>("address_content");
            QVERIFY(address_label);
            generated_address = address_label->text();
            QVERIFY(generated_address.startsWith(hrp));
            req->close();
            break;
        }
    }
    QVERIFY(!generated_address.isEmpty());

    const int row = walletModel.getAddressTableModel()->lookupAddress(generated_address);
    QVERIFY(row >= 0);

    SendCoinsDialog sendDialog(platformStyle.get());
    sendDialog.setModel(&walletModel);
    SendCoinsEntry* entry = FindSendEntry(sendDialog);
    QVERIFY(entry);
    QVERIFY(walletModel.wallet().mwebEnabled());

    auto* pegInButton = entry->findChild<QToolButton*>("mwebPegInButton");
    auto* pegOutButton = entry->findChild<QToolButton*>("mwebPegOutButton");
    QVERIFY(pegInButton);
    QVERIFY(pegOutButton);
    QVERIFY(!pegInButton->isHidden());
    QVERIFY(!pegOutButton->isHidden());

    auto* payTo = entry->findChild<QValidatedLineEdit*>("payTo");
    QVERIFY(payTo);

    // A peg-out pays the next address of this wallet, which the entry shows in place of the address entered.
    payTo->setText(generated_address);
    QTest::mouseClick(pegOutButton, Qt::LeftButton);
    QVERIFY(pegOutButton->isChecked());
    QVERIFY(!pegInButton->isChecked());
    QVERIFY(entry->paymentKind() == SendCoinsRecipient::PaymentKind::PEGOUT);
    QVERIFY(payTo->isReadOnly());
    QCOMPARE(payTo->text(), QString::fromStdString(EncodeDestination(*Assert(walletModel.wallet().peekNewDestination(OutputType::BECH32)))));
    QCOMPARE(entry->getValue().address, payTo->text());

    // A payment request over the peg-out entry makes it a regular payment again.
    entry->setValue(SendCoinsRecipient{generated_address, QString(), COIN, QString()});
    QVERIFY(entry->paymentKind() == SendCoinsRecipient::PaymentKind::REGULAR);
    QVERIFY(!pegOutButton->isChecked());
    QVERIFY(!payTo->isReadOnly());
    QCOMPARE(payTo->text(), generated_address);
    QVERIFY(!payTo->placeholderText().isEmpty());
    QTest::mouseClick(pegOutButton, Qt::LeftButton);
    QVERIFY(entry->paymentKind() == SendCoinsRecipient::PaymentKind::PEGOUT);

    QTest::mouseClick(pegInButton, Qt::LeftButton);
    QVERIFY(pegInButton->isChecked());
    QVERIFY(!pegOutButton->isChecked());
    QVERIFY(entry->paymentKind() == SendCoinsRecipient::PaymentKind::PEGIN);
    QVERIFY(payTo->isReadOnly());
    QVERIFY(payTo->text().startsWith(QString::fromStdString(Params().MWEB_HRP())));

    // MWEB is not active on this chain, so the peg-in is refused before it is built.
    QVERIFY(!node.isMWEBActive());
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(COIN);
    QString activation_text;
    QTimer::singleShot(0, [&activation_text] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                activation_text = box->informativeText();
                box->accept();
            }
        }
    });
    QVERIFY(!entry->validate(node));
    QVERIFY(activation_text.contains(QStringLiteral("activated")));

    // A peg-out pays one recipient: choosing it on one entry removes the others.
    sendDialog.addEntry();
    SendCoinsEntry* pegout_entry = sendDialog.addEntry();
    auto* entries = sendDialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    QCOMPARE(entries->count(), 3);
    QTest::mouseClick(pegout_entry->findChild<QToolButton*>("mwebPegOutButton"), Qt::LeftButton);
    QCOMPARE(entries->count(), 1);
    QCOMPARE(entries->itemAt(0)->widget(), pegout_entry);
    QVERIFY(pegout_entry->paymentKind() == SendCoinsRecipient::PaymentKind::PEGOUT);
}
