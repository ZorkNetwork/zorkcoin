// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/mwebtests.h>

#include <addresstype.h>
#include <chain.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_types.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/sendcoinsrecipient.h>
#include <qt/transactionrecord.h>
#include <qt/walletmodel.h>
#include <qt/walletmodeltransaction.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <test/util/mweb_setup.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/mweb_util.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

#include <QAbstractButton>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QList>
#include <QMessageBox>
#include <QRadioButton>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

using wallet::AddWallet;
using wallet::CCoinControl;
using wallet::CWallet;
using wallet::RemoveWallet;
using wallet::WalletContext;

namespace {
SendCoinsRecipient Recipient(const CTxDestination& dest, CAmount amount)
{
    return SendCoinsRecipient{QString::fromStdString(EncodeDestination(dest)), QString(), amount, QString()};
}

mw::MutableOutput MWEBOutput(const StealthAddress& address, CAmount amount)
{
    mw::MutableOutput output;
    output.address = address;
    output.amount = amount;
    return output;
}

mw::MutableKernel PegOutKernel(const std::vector<mw::PegOutRecipient>& pegouts)
{
    mw::MutableKernel kernel;
    kernel.pegouts = pegouts;
    return kernel;
}

//! The recipients' amounts after reassignMWEBAmounts.
QList<CAmount> Reassign(const QList<SendCoinsRecipient>& recipients, const CMutableTransaction& tx, const mw::MutableTx& mweb_tx,
                        std::optional<size_t> mweb_change_index, int change_pos)
{
    WalletModelTransaction transaction(recipients);
    transaction.setWtx(MakeTransactionRef(tx));
    transaction.reassignMWEBAmounts(mweb_tx, mweb_change_index, change_pos);
    QList<CAmount> amounts;
    for (const SendCoinsRecipient& rcp : transaction.getRecipients()) {
        amounts.append(rcp.amount);
    }
    return amounts;
}

SendCoinsEntry* Entry(SendCoinsDialog& dialog, int index)
{
    return qobject_cast<SendCoinsEntry*>(dialog.findChild<QVBoxLayout*>("entries")->itemAt(index)->widget());
}

QString PayTo(SendCoinsEntry& entry)
{
    return entry.findChild<QValidatedLineEdit*>("payTo")->text();
}

//! Starts a new send with one peg-out entry of `amount`, and returns the address of `type` it previews.
QString PegOutEntry(SendCoinsDialog& dialog, CAmount amount, OutputType type)
{
    dialog.clear();
    SendCoinsEntry& entry{*Entry(dialog, 0)};
    entry.findChild<QToolButton*>("mwebPegOutButton")->click();
    QComboBox& address_type{*entry.findChild<QComboBox*>("pegOutAddressType")};
    address_type.setCurrentIndex(address_type.findData((int)type));
    entry.findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    entry.findChild<QCheckBox*>("checkboxSubtractFeeFromAmount")->setChecked(false);
    return PayTo(entry);
}

//! Clicks Send and answers the confirmation with `button`, after calling `before_answer`. Returns the
//! transaction the wallet committed, if any, and stores the confirmation's text and details in `confirmation`.
CTransactionRef Send(CWallet& wallet, SendCoinsDialog& dialog, QMessageBox::StandardButton button = QMessageBox::Yes,
                     QString* confirmation = nullptr, const std::function<void()>& before_answer = {})
{
    std::optional<Txid> txid;
    btcsignals::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const Txid& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    // The timer goes when this returns, so a send refused before its confirmation leaves nothing to answer a later one.
    QTimer answer;
    answer.setSingleShot(true);
    QObject::connect(&answer, &QTimer::timeout, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* confirm = qobject_cast<SendConfirmationDialog*>(widget)) {
                if (confirmation) *confirmation = confirm->text() + "\n" + confirm->detailedText();
                if (before_answer) before_answer();
                confirm->button(button)->setEnabled(true);
                confirm->button(button)->click();
            }
        }
    });
    answer.start(0);
    const bool invoked = QMetaObject::invokeMethod(&dialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    if (!txid) return {};
    LOCK(wallet.cs_wallet);
    return wallet.GetWalletTx(*txid)->GetTx();
}
} // namespace

//! With "subtract fee from amount", each recipient must show the amount its own output pays.
void MWEBTests::reassignMWEBAmountsTests()
{
    BasicTestingSetup setup{ChainType::REGTEST};
    const StealthAddress own{StealthAddress::Random()};
    const StealthAddress other{StealthAddress::Random()};
    const CTxDestination l1{WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}};
    const CTxDestination l1_other{WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}};
    const CScript l1_script{GetScriptForDestination(l1)};
    const CScript l1_other_script{GetScriptForDestination(l1_other)};

    // A recipient at the wallet's own change address gets its output, not the change.
    {
        mw::MutableTx mweb_tx;
        mweb_tx.outputs = {MWEBOutput(own, 5 * COIN), MWEBOutput(own, 1 * COIN)};
        QCOMPARE(Reassign({Recipient(own, 2 * COIN)}, CMutableTransaction{}, mweb_tx, /*mweb_change_index=*/0, /*change_pos=*/-1), QList<CAmount>{1 * COIN});
    }

    // An L1 recipient is paid by its L1 output, not by peg-out change to the same script.
    {
        CMutableTransaction tx;
        tx.vout = {CTxOut{3 * COIN, l1_script}};
        mw::MutableTx mweb_tx;
        mweb_tx.kernels = {PegOutKernel({{l1_script, 4 * COIN}})};
        QCOMPARE(Reassign({Recipient(l1, 5 * COIN)}, tx, mweb_tx, std::nullopt, /*change_pos=*/-1), QList<CAmount>{3 * COIN});
    }

    // On a peg-out, the recipient's peg-out comes before peg-out change to the same script.
    {
        mw::MutableTx mweb_tx;
        mweb_tx.kernels = {PegOutKernel({{l1_script, 1 * COIN}, {l1_script, 4 * COIN}})};
        QCOMPARE(Reassign({Recipient(l1, 2 * COIN)}, CMutableTransaction{}, mweb_tx, std::nullopt, /*change_pos=*/-1), QList<CAmount>{1 * COIN});
    }

    // With no change, a stealth and an L1 recipient each get their output.
    {
        CMutableTransaction tx;
        tx.vout = {CTxOut{2 * COIN, l1_script}};
        mw::MutableTx mweb_tx;
        mweb_tx.outputs = {MWEBOutput(other, 1 * COIN)};
        QCOMPARE(Reassign({Recipient(other, 3 * COIN), Recipient(l1, 4 * COIN)}, tx, mweb_tx, std::nullopt, /*change_pos=*/-1),
                 (QList<CAmount>{1 * COIN, 2 * COIN}));
    }

    // A recipient with no matching output keeps its amount.
    {
        mw::MutableTx mweb_tx;
        mweb_tx.outputs = {MWEBOutput(own, 1 * COIN)};
        mweb_tx.kernels = {PegOutKernel({{l1_script, 1 * COIN}})};
        QCOMPARE(Reassign({Recipient(other, 3 * COIN), Recipient(l1_other, 4 * COIN)}, CMutableTransaction{}, mweb_tx, std::nullopt, /*change_pos=*/-1),
                 (QList<CAmount>{3 * COIN, 4 * COIN}));
    }

    // Peg-outs are matched across every kernel.
    {
        mw::MutableTx mweb_tx;
        mweb_tx.kernels = {PegOutKernel({{l1_script, 1 * COIN}}), PegOutKernel({{l1_other_script, 2 * COIN}})};
        QCOMPARE(Reassign({Recipient(l1, 3 * COIN), Recipient(l1_other, 4 * COIN)}, CMutableTransaction{}, mweb_tx, std::nullopt, /*change_pos=*/-1),
                 (QList<CAmount>{1 * COIN, 2 * COIN}));
    }
}

//! Funded sends count MWEB coins and display each recipient's actual prepared amount.
void MWEBTests::availableBalanceTests()
{
    MWEBRegtest100Setup test;
    test.MineToMWEBActivation();
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);

    const std::shared_ptr<CWallet> wallet{wallet::CreateSyncedWallet(*test.m_node.chain,
        WITH_LOCK(Assert(test.m_node.chainman)->GetMutex(), return test.m_node.chainman->ActiveChain()), test.coinbaseKey)};
    const auto notifications = test.m_node.chain->handleNotifications(wallet);
    CAmount mweb_balance{0};
    const auto funded_mweb_coins = wallet::PegInAndMine(test, *wallet, 10 * COIN);
    for (const auto& [output_id, amount] : funded_mweb_coins) {
        mweb_balance += amount;
    }
    QVERIFY(mweb_balance >= 10 * COIN);

    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    bilingual_str error;
    OptionsModel optionsModel(m_node);
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(m_node, &optionsModel);
    WalletContext& context = *m_node.walletLoader().context();
    AddWallet(context, wallet);
    WalletModel walletModel(interfaces::MakeWallet(context, wallet), clientModel, platformStyle.get());
    RemoveWallet(context, wallet, std::nullopt);

    walletModel.pollBalanceChanged();
    const CAmount balance = walletModel.getCachedBalance().balance;
    QVERIFY(balance > mweb_balance);

    CCoinControl include_mweb;
    include_mweb.m_include_mweb = true;
    QCOMPARE(walletModel.getAvailableBalance(&include_mweb), balance);
    // A peg-out spends MWEB coins only.
    CCoinControl peg_out;
    peg_out.m_mweb_peg_out = true;
    QCOMPARE(walletModel.getAvailableBalance(&peg_out), mweb_balance);

    CCoinControl coin_control;
    coin_control.m_feerate = CFeeRate{10'000};
    const auto prepare = [&](const CTxDestination& dest, CAmount amount, SendCoinsRecipient::PaymentKind kind) {
        SendCoinsRecipient rcp{Recipient(dest, amount)};
        rcp.payment_kind = kind;
        WalletModelTransaction transaction(QList<SendCoinsRecipient>{rcp});
        return walletModel.prepareTransaction(transaction, coin_control).status;
    };
    const CTxDestination l1{*walletModel.wallet().getNewDestination(OutputType::BECH32, "")};
    const CTxDestination stealth{*walletModel.wallet().getNewDestination(OutputType::MWEB, "")};

    // A peg-out within the MWEB balance is built; one above it is refused, though the total balance covers it.
    QCOMPARE(prepare(l1, 1 * COIN, SendCoinsRecipient::PaymentKind::PEGOUT), WalletModel::OK);
    QCOMPARE(prepare(l1, mweb_balance + COIN, SendCoinsRecipient::PaymentKind::PEGOUT), WalletModel::AmountExceedsBalance);
    // An MWEB send within the balance is built; one above it is refused.
    QCOMPARE(prepare(stealth, 1 * COIN, SendCoinsRecipient::PaymentKind::REGULAR), WalletModel::OK);
    QCOMPARE(prepare(stealth, balance + COIN, SendCoinsRecipient::PaymentKind::REGULAR), WalletModel::AmountExceedsBalance);

    const auto largest_mweb_coin = std::max_element(funded_mweb_coins.begin(), funded_mweb_coins.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    QVERIFY(largest_mweb_coin != funded_mweb_coins.end());
    QVERIFY(largest_mweb_coin->second > 7 * COIN);
    const auto l1_first = Recipient(WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}, 3 * COIN);
    const auto l1_second = Recipient(WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}, 4 * COIN);
    const CTxDestination transparent_change{WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}};
    std::vector<QList<SendCoinsRecipient>> recipient_orders;
#if ENABLE_MWEB_UNCOMMON_SENDS
    const auto mweb_first = Recipient(StealthAddress::Random(), COIN);
    const auto mweb_second = Recipient(StealthAddress::Random(), 2 * COIN);
    recipient_orders = {
        {mweb_first, l1_first, mweb_second, l1_second},
        {l1_second, mweb_second, l1_first, mweb_first},
        {mweb_first, mweb_second},
    };
#endif
    recipient_orders.push_back({l1_first, l1_second});

    // Four orders, default/custom change and fee subtraction from none/first/all.
    // The strict send policy retains the six transparent-recipient controls.
    for (const auto& original : recipient_orders) {
        const bool has_mweb_recipient = std::any_of(original.begin(), original.end(), [](const auto& recipient) {
            return std::holds_alternative<StealthAddress>(DecodeDestination(recipient.address.toStdString()));
        });
        for (const bool custom_change : {false, true}) {
            CCoinControl control;
            control.m_feerate = CFeeRate{10'000};
            if (custom_change) {
                control.destChange = has_mweb_recipient ? transparent_change : CTxDestination{StealthAddress::Random()};
                if (!has_mweb_recipient) {
                    // Native L1-only sends cannot make MWEB change. Fund these
                    // transparent recipients from MWEB so the GUI infers a peg-out.
                    control.SelectMWEB(largest_mweb_coin->first);
                    control.m_allow_other_inputs = false;
                }
            }
            for (const int subtract_count : {0, 1, static_cast<int>(original.size())}) {
                QList<SendCoinsRecipient> recipients = original;
                for (int i = 0; i < subtract_count; ++i) recipients[i].fSubtractFeeFromAmount = true;
                const auto wallet_tx_count = WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size());
                WalletModelTransaction transaction(recipients);
                QCOMPARE(walletModel.prepareTransaction(transaction, control).status, WalletModel::OK);
                QVERIFY(transaction.getWtx());
                const CTransaction& tx = *transaction.getWtx();
                const auto displayed = transaction.getRecipients();
                QCOMPARE(displayed.size(), recipients.size());
                QVERIFY(!WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.contains(tx.GetHash())));
                QCOMPARE(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size()), wallet_tx_count);

                std::map<std::string, std::vector<CAmount>> actual_outputs;
                CAmount output_total{0};
                for (const CTxOut& output : tx.vout) {
                    mw::Hash kernel_id;
                    if (output.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                        QVERIFY(tx.mweb_tx.GetKernelIDs().contains(kernel_id));
                        continue; // Internal transfer into the extension, counted by its outputs below.
                    }
                    output_total += output.nValue;
                    CTxDestination destination;
                    if (ExtractDestination(output.scriptPubKey, destination)) {
                        actual_outputs[EncodeDestination(destination)].push_back(output.nValue);
                    }
                }
                // Signing saves sender metadata immediately in this architecture;
                // prepared outputs are readable before the transaction is committed.
                for (const auto& output_id : tx.mweb_tx.GetOutputIDs()) {
                    mw::Coin coin;
                    QVERIFY(WITH_LOCK(wallet->cs_wallet, return wallet->GetCoin(output_id, coin)));
                    QVERIFY(coin.output_id == output_id);
                    QVERIFY(coin.HasAddress());
                    actual_outputs[EncodeDestination(*coin.address)].push_back(coin.amount);
                    output_total += coin.amount;
                }
                for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
                    CTxDestination destination;
                    QVERIFY(ExtractDestination(pegout.GetScriptPubKey(), destination));
                    actual_outputs[EncodeDestination(destination)].push_back(pegout.GetAmount());
                    output_total += pegout.GetAmount();
                }
                CAmount input_total{0};
                {
                    LOCK(wallet->cs_wallet);
                    for (const CTxIn& input : tx.vin) {
                        const auto* previous = wallet->GetWalletTx(input.prevout.hash);
                        QVERIFY(previous);
                        QVERIFY(input.prevout.n < previous->GetTx()->vout.size());
                        input_total += previous->GetTx()->vout[input.prevout.n].nValue;
                    }
                    for (const auto& input_id : tx.mweb_tx.GetSpentIDs()) {
                        mw::Coin coin;
                        QVERIFY(wallet->GetCoin(input_id, coin));
                        input_total += coin.amount;
                    }
                }
                QCOMPARE(input_total - output_total, transaction.getTransactionFee());

                CAmount requested_total{0};
                for (int i = 0; i < recipients.size(); ++i) {
                    const auto actual = actual_outputs.find(recipients[i].address.toStdString());
                    QVERIFY(actual != actual_outputs.end());
                    QCOMPARE(actual->second.size(), size_t{1});
                    QCOMPARE(displayed[i].address, recipients[i].address);
                    QCOMPARE(displayed[i].amount, actual->second.front());
                    if (!recipients[i].fSubtractFeeFromAmount) QCOMPARE(displayed[i].amount, recipients[i].amount);
                    requested_total += recipients[i].amount;
                }
                QCOMPARE(transaction.getTotalTransactionAmount(),
                    requested_total - (subtract_count ? transaction.getTransactionFee() : 0));
                if (custom_change) {
                    const auto change = actual_outputs.find(EncodeDestination(control.destChange));
                    QVERIFY(change != actual_outputs.end());
                    QCOMPARE(change->second.size(), size_t{1});
                    QVERIFY(change->second.front() > 0);
                }
                if (!has_mweb_recipient) {
                    if (custom_change) {
                        QVERIFY(tx.IsMWEBOnly());
                        QVERIFY(tx.mweb_tx.GetSpentIDs() == std::set<mw::Hash>{largest_mweb_coin->first});
                    } else {
                        QVERIFY(tx.mweb_tx.IsNull());
                        QVERIFY(!tx.vin.empty());
                    }
                }
            }
        }
    }
}

//! Distinct partial receive records keep their wallet identities through the GUI interface.
void MWEBTests::partialReceiveIdentityTests()
{
    wallet::WalletTestingSetup test{ChainType::REGTEST};
    CWallet& wallet{test.m_wallet};
    WalletContext context;
    context.chain = test.m_node.chain.get();
    context.args = test.m_node.args;
    const std::shared_ptr<CWallet> shared_wallet{&wallet, [](CWallet*) {}};
    const auto interface_wallet = interfaces::MakeWallet(context, shared_wallet);
    std::vector<Txid> receive_ids;
    std::vector<mw::Hash> output_ids;
    Txid spend_id;
    Txid canonical_id;
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(wallet::WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
        const auto* tip = WITH_LOCK(test.m_node.chainman->GetMutex(), return test.m_node.chainman->ActiveChain().Tip());
        QVERIFY(tip);
        wallet.SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
        // Genuine owned output IDs with synthetic wallet notifications. These
        // records model a scan result, without claiming these outputs were mined.
        for (const CAmount amount : {COIN, 2 * COIN}) {
            const auto destination = wallet.GetNewDestination(OutputType::MWEB, "partial receive");
            QVERIFY(destination);
            const auto* address = std::get_if<StealthAddress>(&*destination);
            QVERIFY(address);
            const Output output = Output::Create(nullptr, SecretKey::Random(), *address, amount);
            mw::Coin coin;
            QVERIFY(wallet.GetMWWallet()->RewindOutput(output, coin));
            QVERIFY(coin.IsMine());
            QVERIFY(coin.output_id == output.GetOutputID());
            const auto* received = wallet.AddToWallet(MakeTransactionRef(CMutableTransaction{}),
                wallet::TxStateConfirmed{tip->GetBlockHash(), tip->nHeight, static_cast<int>(receive_ids.size())},
                nullptr, false, MWEB::WalletTxInfo{coin});
            QVERIFY(received);
            QVERIFY(received->IsMWEBPlaceholder());
            receive_ids.push_back(received->GetHash());
            output_ids.push_back(coin.output_id);
        }
        QCOMPARE(wallet.mapWallet.size(), size_t{2});
        QVERIFY(receive_ids[0] != receive_ids[1]);
        // A spend placeholder for the same output occupies a separate S record.
        const auto* spent = wallet.AddToWallet(MakeTransactionRef(CMutableTransaction{}), wallet::TxStateInactive{},
            nullptr, false, MWEB::WalletTxInfo{output_ids.front()});
        QVERIFY(spent);
        spend_id = spent->GetHash();
        QVERIFY(spend_id != receive_ids.front());
        CMutableTransaction canonical;
        canonical.vout.emplace_back(3 * COIN, CScript() << OP_TRUE);
        const auto full = MakeTransactionRef(std::move(canonical));
        QVERIFY(wallet.AddToWallet(full, wallet::TxStateInactive{}));
        canonical_id = full->GetHash();
    }
    for (const auto& receive_id : receive_ids) {
        const auto details = interface_wallet->getWalletTx(receive_id);
        QVERIFY(details.mweb_placeholder_id == receive_id);
        QVERIFY(details.GetHash() == receive_id);
        QCOMPARE(details.mweb_outs.size(), size_t{1});
        const auto parts = TransactionRecord::decomposeTransaction(details);
        QCOMPARE(parts.size(), 1);
        QCOMPARE(parts.front().type, TransactionRecord::RecvWithAddress);
        // Separate checks retain both symptoms in one failing regression run.
        const auto check_identity = [&] { QVERIFY(parts.front().hash == receive_id); };
        const auto check_status = [&] {
            interfaces::WalletTxStatus status;
            int blocks{-1};
            int64_t block_time{-1};
            QVERIFY(interface_wallet->tryGetTxStatus(parts.front().hash, status, blocks, block_time));
            QCOMPARE(status.depth_in_main_chain, 1);
            QCOMPARE(status.is_trusted, true);
        };
        check_identity();
        check_status();
    }
    const auto spend = interface_wallet->getWalletTx(spend_id);
    QVERIFY(spend.mweb_placeholder_id == spend_id);
    QVERIFY(spend.GetHash() == spend_id);
    const auto canonical = interface_wallet->getWalletTx(canonical_id);
    QVERIFY(!canonical.mweb_placeholder_id);
    QVERIFY(canonical.GetHash() == canonical_id);
    QVERIFY(canonical.GetHash() == canonical.tx->GetHash());
    std::set<Txid> enumerated_ids;
    for (const auto& record : interface_wallet->getWalletTxs()) enumerated_ids.insert(record.GetHash());
    const std::set<Txid> expected_ids{receive_ids[0], receive_ids[1], spend_id, canonical_id};
    QVERIFY(enumerated_ids == expected_ids);
}

//! Partial receive history uses wallet identities and native GUI status/balance rules.
void MWEBTests::partialReceiveStatusTests()
{
    TestChain100Setup test;
    const auto* tip = WITH_LOCK(test.m_node.chainman->GetMutex(), return test.m_node.chainman->ActiveChain().Tip());
    QVERIFY(tip);
    QVERIFY(tip->nHeight >= 5);
    const auto* confirmed_block = WITH_LOCK(test.m_node.chainman->GetMutex(), return tip->GetAncestor(tip->nHeight - 5));
    QVERIFY(confirmed_block);
    const auto wallet = std::make_shared<CWallet>(test.m_node.chain.get(), "partial receive statuses", wallet::CreateMockableWalletDatabase());
    WalletContext context;
    context.chain = test.m_node.chain.get();
    context.args = test.m_node.args;
    const auto interface_wallet = interfaces::MakeWallet(context, wallet);
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(wallet::WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();
        wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
    }

    constexpr CAmount MEMPOOL_AMOUNT{COIN};
    constexpr CAmount CONFIRMING_AMOUNT{2 * COIN};
    constexpr CAmount CONFIRMED_AMOUNT{3 * COIN};
    struct ReceiveCase {
        const char* label;
        CAmount amount;
        wallet::TxState state;
        int depth;
        TransactionStatus::Status status;
        bool counts_for_balance;
    };
    const std::vector<ReceiveCase> cases{
        {"mempool", MEMPOOL_AMOUNT, wallet::TxStateInMempool{}, 0, TransactionStatus::Unconfirmed, false},
        {"confirming", CONFIRMING_AMOUNT, wallet::TxStateConfirmed{tip->GetBlockHash(), tip->nHeight, 0}, 1, TransactionStatus::Confirming, true},
        {"confirmed", CONFIRMED_AMOUNT, wallet::TxStateConfirmed{confirmed_block->GetBlockHash(), confirmed_block->nHeight, 0}, 6, TransactionStatus::Confirmed, true},
        {"conflicted", 5 * COIN, wallet::TxStateBlockConflicted{tip->GetBlockHash(), tip->nHeight}, -1, TransactionStatus::Conflicted, false},
        {"inactive", 7 * COIN, wallet::TxStateInactive{}, 0, TransactionStatus::Unconfirmed, false},
        {"abandoned", 11 * COIN, wallet::TxStateInactive{true}, 0, TransactionStatus::Abandoned, false},
    };
    struct ExpectedReceive {
        const ReceiveCase* test_case;
        mw::Hash output_id;
        CTxDestination destination;
    };
    std::map<Txid, ExpectedReceive> expected;
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    const auto add_receive = [&](const ReceiveCase& test_case) {
        LOCK(wallet->cs_wallet);
        const auto destination = wallet->GetNewDestination(OutputType::MWEB, test_case.label);
        QVERIFY(destination);
        const auto* address = std::get_if<StealthAddress>(&*destination);
        QVERIFY(address);
        const Output output = Output::Create(nullptr, SecretKey::Random(), *address, test_case.amount);
        mw::Coin coin;
        QVERIFY(wallet->GetMWWallet()->RewindOutput(output, coin));
        QVERIFY(coin.IsMine());
        QVERIFY(!coin.IsChange());
        QVERIFY(coin.output_id == output.GetOutputID());
        QCOMPARE(coin.amount, test_case.amount);
        // Genuine owned output IDs, with synthetic wallet notifications only:
        // these states do not claim the generated outputs were mined or relayed.
        const auto* received = wallet->AddToWallet(empty, test_case.state, nullptr, false, MWEB::WalletTxInfo{coin});
        QVERIFY(received);
        QVERIFY(received->IsMWEBPlaceholder());
        const Txid receive_id{received->GetHash()};
        QVERIFY(receive_id == Txid::FromUint256(MWEB::WalletTxInfo{coin}.GetHash()));
        QVERIFY(receive_id != empty->GetHash());
        QVERIFY(expected.emplace(receive_id, ExpectedReceive{&test_case, coin.output_id, *destination}).second);
    };

    const auto check_history = [&](CAmount trusted_expected, CAmount pending_expected) {
        const auto history = interface_wallet->getWalletTxs();
        QCOMPARE(history.size(), expected.size());
        std::set<Txid> seen;
        CAmount counted_credit{0};
        for (const auto& wtx : history) {
            const auto found = expected.find(wtx.GetHash());
            QVERIFY(found != expected.end());
            const ExpectedReceive& receive{found->second};
            const ReceiveCase& test_case{*receive.test_case};
            QVERIFY(seen.insert(found->first).second);
            QVERIFY(wtx.tx);
            QVERIFY(wtx.tx->IsNull());
            QVERIFY(!wtx.tx->HasMWEBTx());
            QCOMPARE(wtx.credit, test_case.amount);
            QCOMPARE(wtx.debit, CAmount{0});
            QCOMPARE(wtx.change, CAmount{0});
            QCOMPARE(wtx.fee, CAmount{0});
            QCOMPARE(wtx.mweb_outs.size(), size_t{1});
            const auto& output = wtx.mweb_outs.front();
            QVERIFY(output.output_id == receive.output_id);
            QCOMPARE(output.amount, test_case.amount);
            QVERIFY(output.address == receive.destination);
            QVERIFY(output.is_mine);
            QVERIFY(!output.is_change);
            auto records = TransactionRecord::decomposeTransaction(wtx);
            QCOMPARE(records.size(), 1);
            auto& record = records.front();
            QVERIFY(record.hash == found->first);
            QCOMPARE(record.type, TransactionRecord::RecvWithAddress);
            QVERIFY(record.address == EncodeDestination(receive.destination));
            QCOMPARE(record.credit, test_case.amount);
            QCOMPARE(record.debit, CAmount{0});
            interfaces::WalletTxStatus status;
            int blocks{-1};
            int64_t block_time{-1};
            QVERIFY(interface_wallet->tryGetTxStatus(record.hash, status, blocks, block_time));
            QCOMPARE(blocks, tip->nHeight);
            QCOMPARE(block_time, tip->GetBlockTime());
            QCOMPARE(status.depth_in_main_chain, test_case.depth);
            QCOMPARE(status.is_trusted, test_case.counts_for_balance);
            QCOMPARE(status.blocks_to_maturity, 0);
            QVERIFY(!status.is_coinbase);
            record.updateStatus(status, tip->GetBlockHash(), blocks, block_time);
            QCOMPARE(record.status.status, test_case.status);
            QCOMPARE(record.status.depth, qint64{test_case.depth});
            QCOMPARE(record.status.countsForBalance, test_case.counts_for_balance);
            if (record.status.countsForBalance) counted_credit += record.credit;
        }
        QCOMPARE(seen.size(), expected.size());
        QCOMPARE(counted_credit, trusted_expected);
        const auto gui_balance = interface_wallet->getBalances();
        QCOMPARE(gui_balance.balance, trusted_expected);
        QCOMPARE(gui_balance.unconfirmed_balance, pending_expected);
        QCOMPARE(gui_balance.immature_balance, CAmount{0});
        LOCK(wallet->cs_wallet);
        const auto balance = wallet::GetBalance(*wallet, 0, /*avoid_reuse=*/false,
            /*include_nonmempool=*/false, /*include_mweb=*/true);
        QCOMPARE(balance.m_mine_trusted, trusted_expected);
        QCOMPARE(balance.m_mine_untrusted_pending, pending_expected);
        QCOMPARE(balance.m_mine_immature, CAmount{0});
        const auto l1_balance = wallet::GetBalance(*wallet);
        QCOMPARE(l1_balance.m_mine_trusted, CAmount{0});
        QCOMPARE(l1_balance.m_mine_untrusted_pending, CAmount{0});
        QCOMPARE(l1_balance.m_mine_immature, CAmount{0});
        QCOMPARE(l1_balance.m_mine_used, CAmount{0});
        QCOMPARE(l1_balance.m_mine_nonmempool, CAmount{0});
    };

    // The first phase independently proves the sole unconfirmed partial receive:
    // one visible receive component, pending credit, and no trusted/L1 balance.
    add_receive(cases.front());
    QCOMPARE(expected.size(), size_t{1});
    check_history(/*trusted_expected=*/0, /*pending_expected=*/MEMPOOL_AMOUNT);
    {
        LOCK(wallet->cs_wallet);
        QCOMPARE(wallet->mapWallet.size(), size_t{1});
        QCOMPARE(wallet->wtxOrdered.size(), size_t{1});
        const auto& receive = expected.begin()->second;
        const auto* received = wallet->GetWalletTx(expected.begin()->first);
        QVERIFY(received);
        QCOMPARE(wallet::CachedTxGetAmount(*wallet, *received), MEMPOOL_AMOUNT);
        std::list<wallet::COutputEntry> received_amounts, sent_amounts;
        CAmount fee{-1};
        wallet::CachedTxGetAmounts(*wallet, *received, received_amounts, sent_amounts, fee, /*include_change=*/false);
        QCOMPARE(received_amounts.size(), size_t{1});
        QVERIFY(sent_amounts.empty());
        QCOMPARE(fee, CAmount{0});
        const auto& entry = received_amounts.front();
        QVERIFY(entry.mweb_out == receive.output_id);
        QVERIFY(entry.destination == receive.destination);
        QCOMPARE(entry.amount, MEMPOOL_AMOUNT);
        QCOMPARE(entry.vout, -1);
        const auto available = wallet->ListMWEBUnspent(0, 999, /*include_unsafe=*/true, nullptr, 0, MAX_MONEY);
        QCOMPARE(available.size(), size_t{1});
        QVERIFY(available.front().output_id == receive.output_id);
        QVERIFY(available.front().txid == expected.begin()->first);
        QCOMPARE(available.front().amount, MEMPOOL_AMOUNT);
        QCOMPARE(available.front().depth, 0);
        QVERIFY(!available.front().safe);
        QVERIFY(wallet->ListMWEBUnspent(0, 999, /*include_unsafe=*/false, nullptr, 0, MAX_MONEY).empty());
    }
    for (size_t i{1}; i < cases.size(); ++i) add_receive(cases[i]);
    QCOMPARE(expected.size(), size_t{6});
    check_history(CONFIRMING_AMOUNT + CONFIRMED_AMOUNT, MEMPOOL_AMOUNT);
    {
        LOCK(wallet->cs_wallet);
        QCOMPARE(wallet->mapWallet.size(), size_t{6});
        QCOMPARE(wallet->wtxOrdered.size(), size_t{6});
    }
}

//! A peg-out pays the address its entry previews, which the wallet takes only once the send is confirmed.
void MWEBTests::pegOutSendTests()
{
    MWEBRegtest100Setup test;
    test.MineToMWEBActivation();
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);

    const std::shared_ptr<CWallet> wallet{wallet::CreateSyncedWallet(*test.m_node.chain,
        WITH_LOCK(Assert(test.m_node.chainman)->GetMutex(), return test.m_node.chainman->ActiveChain()), test.coinbaseKey)};
    const auto notifications = test.m_node.chain->handleNotifications(wallet);
    wallet->SetBroadcastTransactions(true);
    QVERIFY(!wallet::PegInAndMine(test, *wallet, 10 * COIN).empty());
    const auto mine = [&] {
        test.MineMWEBEraBlock();
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    };

    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    bilingual_str error;
    OptionsModel optionsModel(m_node);
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(m_node, &optionsModel);
    WalletContext& context = *m_node.walletLoader().context();
    AddWallet(context, wallet);
    WalletModel walletModel(interfaces::MakeWallet(context, wallet), clientModel, platformStyle.get());
    RemoveWallet(context, wallet, std::nullopt);

    SendCoinsDialog dialog(platformStyle.get());
    dialog.setModel(&walletModel);
    dialog.findChild<QRadioButton*>("radioCustomFee")->setChecked(true);
    dialog.findChild<BitcoinAmountField*>("customFee")->setValue(10'000);
    QStringList messages;
    QObject::connect(&dialog, &SendCoinsDialog::message, [&](const QString&, const QString& message, unsigned int) { messages.append(message); });
    QObject::connect(&walletModel, &WalletModel::message, [&](const QString&, const QString& message, unsigned int) { messages.append(message); });

    const auto peek = [&](OutputType type) {
        return QString::fromStdString(EncodeDestination(*Assert(walletModel.wallet().peekNewDestination(type))));
    };
    const auto script = [](const QString& address) { return GetScriptForDestination(DecodeDestination(address.toStdString())); };
    const QString address_changed{"The peg-out address has changed. Please review the new address and send again."};

    // The entry previews the next address of each transparent type.
    {
        dialog.clear();
        SendCoinsEntry& entry{*Entry(dialog, 0)};
        QComboBox& address_type{*entry.findChild<QComboBox*>("pegOutAddressType")};
        QVERIFY(address_type.isHidden());
        entry.findChild<QToolButton*>("mwebPegOutButton")->click();
        QVERIFY(!address_type.isHidden());
        QCOMPARE(OutputType(address_type.currentData().toInt()), OutputType::BECH32);
        QCOMPARE(address_type.findData((int)OutputType::MWEB), -1);
        for (int i = 0; i < address_type.count(); ++i) {
            address_type.setCurrentIndex(i);
            QCOMPARE(PayTo(entry), peek(OutputType(address_type.itemData(i).toInt())));
        }

        // An address given to the entry makes it a regular payment to that address.
        const QString other{QString::fromStdString(EncodeDestination(WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}))};
        entry.setAddress(other);
        QCOMPARE(entry.paymentKind(), SendCoinsRecipient::PaymentKind::REGULAR);
        QCOMPARE(PayTo(entry), other);
        QVERIFY(!entry.findChild<QValidatedLineEdit*>("payTo")->isReadOnly());
        QVERIFY(address_type.isHidden());
    }

    // Cancelling takes no address. Confirming pays the previewed address and takes it.
    {
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::P2SH_SEGWIT)};
        QCOMPARE(previewed, peek(OutputType::P2SH_SEGWIT));
        QString confirmation;
        QVERIFY(!Send(*wallet, dialog, QMessageBox::Cancel, &confirmation));
        QVERIFY(confirmation.contains(previewed));
        QCOMPARE(peek(OutputType::P2SH_SEGWIT), previewed);
        const CTransactionRef tx{Send(*wallet, dialog, QMessageBox::Yes, &confirmation)};
        QVERIFY(tx);
        QVERIFY(tx->IsMWEBOnly());
        const std::vector<PegOutCoin> pegouts{tx->mweb_tx.GetPegOuts()};
        QCOMPARE(pegouts.size(), size_t{1});
        QVERIFY(pegouts[0].GetScriptPubKey() == script(previewed));
        QCOMPARE(pegouts[0].GetAmount(), 1 * COIN);
        QVERIFY(confirmation.contains(previewed + " (Peg-Out)"));
        QVERIFY(peek(OutputType::P2SH_SEGWIT) != previewed);
        mine();
    }

    // An address taken elsewhere after the preview is caught before and after the confirmation.
    {
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::BECH32)};
        QVERIFY(walletModel.wallet().getNewDestination(OutputType::BECH32, ""));
        messages.clear();
        QVERIFY(!Send(*wallet, dialog));
        QVERIFY(messages.contains(address_changed));
        QCOMPARE(PayTo(*Entry(dialog, 0)), peek(OutputType::BECH32));
        QVERIFY(PayTo(*Entry(dialog, 0)) != previewed);

        messages.clear();
        const size_t book_size{WITH_LOCK(wallet->cs_wallet, return wallet->m_address_book.size())};
        QVERIFY(!Send(*wallet, dialog, QMessageBox::Yes, nullptr, [&] { QVERIFY(walletModel.wallet().getNewDestination(OutputType::BECH32, "")); }));
        QVERIFY(messages.contains(address_changed));
        // The refused send takes no address besides the one taken elsewhere.
        QCOMPARE(WITH_LOCK(wallet->cs_wallet, return wallet->m_address_book.size()), book_size + 1);

        const QString refreshed{PayTo(*Entry(dialog, 0))};
        QCOMPARE(refreshed, peek(OutputType::BECH32));
        const CTransactionRef tx{Send(*wallet, dialog)};
        QVERIFY(tx);
        QVERIFY(tx->mweb_tx.GetPegOuts().at(0).GetScriptPubKey() == script(refreshed));
        mine();
    }

    // A peg-out that leaves less than a change output is worth pays the rest as fee.
    {
        std::map<mw::Hash, CAmount> coins;
        {
            LOCK(wallet->cs_wallet);
            for (const auto& entry : wallet->ListMWEBUnspent(/*min_depth=*/1, /*max_depth=*/9999999, /*include_unsafe=*/false, nullptr, 0, MAX_MONEY)) {
                coins.emplace(entry.output_id, entry.amount);
            }
        }
        QVERIFY(!coins.empty());
        // The smallest coin is swept, so that the others still fund the payment of the next section.
        const auto& [coin, value] = *std::min_element(coins.begin(), coins.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::BECH32)};

        CCoinControl sweep;
        sweep.m_mweb_peg_out = true;
        sweep.m_feerate = CFeeRate{10'000};
        sweep.m_allow_other_inputs = false;
        sweep.SelectMWEB(coin);
        const auto res = wallet::CreateTransaction(*wallet, {{DecodeDestination(previewed.toStdString()), value, /*subtract_fee=*/true}},
            /*change_pos=*/std::nullopt, sweep, /*sign=*/false);
        QVERIFY(res);
        const CAmount amount{value - res->fee - 100};

        Entry(dialog, 0)->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
        dialog.getCoinControl()->SelectMWEB(coin);
        const CTransactionRef tx{Send(*wallet, dialog)};
        QVERIFY(tx);
        QVERIFY(tx->mweb_tx.GetSpentIDs() == std::set<mw::Hash>{coin});
        QVERIFY(tx->mweb_tx.GetOutputIDs().empty());
        const std::vector<PegOutCoin> pegouts{tx->mweb_tx.GetPegOuts()};
        QCOMPARE(pegouts.size(), size_t{1});
        QVERIFY(pegouts[0].GetScriptPubKey() == script(previewed));
        QCOMPARE(pegouts[0].GetAmount(), amount);
        QCOMPARE(*tx->mweb_tx.GetFee(), res->fee + 100);
        mine();
    }

    // Change to a transparent address is pegged out after the payment.
    {
        const CTxDestination change{*Assert(walletModel.wallet().getNewDestination(OutputType::BECH32, ""))};
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::BECH32)};
        dialog.getCoinControl()->destChange = change;
        const CTransactionRef tx{Send(*wallet, dialog)};
        QVERIFY(tx);
        QVERIFY(tx->mweb_tx.GetOutputIDs().empty());
        const std::vector<PegOutCoin> pegouts{tx->mweb_tx.GetPegOuts()};
        QCOMPARE(pegouts.size(), size_t{2});
        QVERIFY(pegouts[0].GetScriptPubKey() == script(previewed));
        QCOMPARE(pegouts[0].GetAmount(), 1 * COIN);
        QVERIFY(pegouts[1].GetScriptPubKey() == GetScriptForDestination(change));
        mine();
        dialog.getCoinControl()->destChange = CNoDestination{};
        // The change left the MWEB with the payment, so the sections after need new MWEB coins.
        QVERIFY(!wallet::PegInAndMine(test, *wallet, 10 * COIN).empty());
    }

    // Every recipient of a peg-out is paid by a peg-out, so an MWEB recipient is refused.
    {
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::BECH32)};
        SendCoinsEntry& extra{*dialog.addEntry()};
        extra.findChild<QValidatedLineEdit*>("payTo")->setText(
            QString::fromStdString(EncodeDestination(*Assert(walletModel.wallet().getNewDestination(OutputType::MWEB, "")))));
        extra.findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
        messages.clear();
        QVERIFY(!Send(*wallet, dialog));
        QVERIFY(messages.contains("A peg-out can only pay transparent addresses. Send to MWEB addresses in a separate transaction."));

        const QString other{QString::fromStdString(EncodeDestination(WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}))};
        extra.findChild<QValidatedLineEdit*>("payTo")->setText(other);
        QString confirmation;
        const CTransactionRef tx{Send(*wallet, dialog, QMessageBox::Yes, &confirmation)};
        QVERIFY(tx);
        QVERIFY(tx->IsMWEBOnly());
        const std::vector<PegOutCoin> pegouts{tx->mweb_tx.GetPegOuts()};
        QCOMPARE(pegouts.size(), size_t{2});
        QVERIFY(pegouts[0].GetScriptPubKey() == script(previewed));
        QVERIFY(pegouts[1].GetScriptPubKey() == script(other));
        QCOMPARE(confirmation.count(" (Peg-Out)"), 2);
        mine();
    }

    // A locked wallet must be unlocked to send, and the address is taken only if it is.
    {
        const SecureString passphrase{"passphrase"};
        QVERIFY(walletModel.wallet().encryptWallet(passphrase));
        QCOMPARE(walletModel.getEncryptionStatus(), WalletModel::Locked);
        const QString previewed{PegOutEntry(dialog, 1 * COIN, OutputType::BECH32)};
        QCOMPARE(previewed, peek(OutputType::BECH32));
        QVERIFY(!Send(*wallet, dialog));
        QCOMPARE(peek(OutputType::BECH32), previewed);

        QObject::connect(&walletModel, &WalletModel::requireUnlock, [&] { walletModel.setWalletLocked(false, passphrase); });
        const CTransactionRef tx{Send(*wallet, dialog)};
        QVERIFY(tx);
        QVERIFY(tx->mweb_tx.GetPegOuts().at(0).GetScriptPubKey() == script(previewed));
        QVERIFY(peek(OutputType::BECH32) != previewed);
        QCOMPARE(walletModel.getEncryptionStatus(), WalletModel::Locked);
    }
}

//! "Create Unsigned" in a wallet without private keys gives a PSBT with the MWEB part, which the key holder can sign.
void MWEBTests::createUnsignedTests()
{
    MWEBRegtest100Setup test;
    test.MineToMWEBActivation();
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    ChainstateManager& chainman{*Assert(test.m_node.chainman)};

    const std::shared_ptr<CWallet> signer{wallet::CreateSyncedWallet(*test.m_node.chain,
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain()), test.coinbaseKey)};
    const auto signer_notifications = test.m_node.chain->handleNotifications(signer);
    const std::optional<std::string> exported{WITH_LOCK(signer->cs_wallet, return Assert(dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(
        signer->GetScriptPubKeyMan(OutputType::MWEB, /*internal=*/false)))->GetMWEBAccountWatchOnlyDescriptor())};
    QVERIFY(exported);

    const auto watch = std::make_shared<CWallet>(test.m_node.chain.get(), "watch", wallet::CreateMockableWalletDatabase());
    {
        LOCK2(watch->cs_wallet, ::cs_main);
        watch->SetLastBlockProcessed(chainman.ActiveHeight(), chainman.ActiveTip()->GetBlockHash());
        watch->SetWalletFlag(wallet::WALLET_FLAG_DESCRIPTORS);
        watch->SetWalletFlag(wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        FlatSigningProvider keys;
        std::string error;
        auto descs = Parse(*exported, keys, error, /*require_checksum=*/true);
        QCOMPARE(descs.size(), size_t{1});
        // Indices 0 and 1 are the reserved change and peg-in addresses.
        wallet::WalletDescriptor w_desc(std::move(descs.front()), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/2);
        auto added = watch->AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
        QVERIFY(added);
        watch->AddActiveScriptPubKeyMan(added->get().GetID(), OutputType::MWEB, /*internal=*/false);
    }
    const auto watch_notifications = test.m_node.chain->handleNotifications(watch);

    const CTxDestination watch_address{wallet::getNewDestination(*watch, OutputType::MWEB)};
    QVERIFY(watch_address == wallet::getNewDestination(*signer, OutputType::MWEB));
    CCoinControl pegin_control;
    pegin_control.m_mweb_peg_in = true;
    pegin_control.m_feerate = CFeeRate{10'000};
    const auto pegin = wallet::CreateTransaction(*signer, {{watch_address, 10 * COIN, /*subtract_fee=*/false}},
        /*change_pos=*/std::nullopt, pegin_control);
    QVERIFY(pegin);
    QCOMPARE(WITH_LOCK(::cs_main, return chainman.ProcessTransaction(pegin->tx).m_result_type), MempoolAcceptResult::ResultType::VALID);
    test.MineMWEBEraBlock();
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto coins{WITH_LOCK(watch->cs_wallet, return watch->ListMWEBUnspent(/*min_depth=*/1, /*max_depth=*/9999999, /*include_unsafe=*/false, nullptr, 0, MAX_MONEY))};
    // The peg-in's change goes to the account's change address, which the watch-only copy watches too.
    QCOMPARE(coins.size(), size_t{2});
    const auto paid{std::ranges::find_if(coins, [&](const auto& entry) { return CTxDestination{entry.address} == watch_address; })};
    QVERIFY(paid != coins.end());

    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    bilingual_str error;
    OptionsModel optionsModel(m_node);
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(m_node, &optionsModel);
    WalletContext& context = *m_node.walletLoader().context();
    AddWallet(context, watch);
    WalletModel watch_model(interfaces::MakeWallet(context, watch), clientModel, platformStyle.get());
    RemoveWallet(context, watch, std::nullopt);
    AddWallet(context, signer);
    WalletModel signer_model(interfaces::MakeWallet(context, signer), clientModel, platformStyle.get());
    RemoveWallet(context, signer, std::nullopt);

    //! Clicks "Create Unsigned" in a send dialog of `wallet` with one entry set by `set_entry`, and returns the
    //! transaction the signer makes of the PSBT. The confirmation's text goes to `confirmation`.
    const auto create_unsigned = [&](WalletModel& wallet_model, CWallet& wallet, const std::function<void(SendCoinsDialog&, SendCoinsEntry&)>& set_entry,
                                     QString& confirmation) -> CTransactionRef {
        SendCoinsDialog dialog(platformStyle.get());
        dialog.setModel(&wallet_model);
        dialog.findChild<QRadioButton*>("radioCustomFee")->setChecked(true);
        dialog.findChild<BitcoinAmountField*>("customFee")->setValue(10'000);
        SendCoinsEntry& entry{*Entry(dialog, 0)};
        set_entry(dialog, entry);
        entry.findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
        entry.findChild<QCheckBox*>("checkboxSubtractFeeFromAmount")->setChecked(false);
        QApplication::clipboard()->clear();
        QTimer discard;
        QObject::connect(&discard, &QTimer::timeout, [&] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->objectName() == "psbt_copied_message") {
                    box->button(QMessageBox::Discard)->click();
                    discard.stop();
                }
            }
        });
        discard.start(0);
        if (Send(wallet, dialog, QMessageBox::Save, &confirmation)) return {};

        const std::optional<std::vector<unsigned char>> decoded{DecodeBase64(QApplication::clipboard()->text().toStdString())};
        if (!decoded) return {};
        util::Result<PartiallySignedTransaction> psbt{DecodeRawPSBT(MakeByteSpan(*decoded))};
        if (!psbt || !psbt->ContainsMWEBComponents()) return {};
        bool complete{false};
        if (signer->FillPSBT(*psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete) || !complete) return {};
        CMutableTransaction signed_tx;
        if (!FinalizeAndExtractPSBT(*psbt, signed_tx)) return {};
        return MakeTransactionRef(std::move(signed_tx));
    };
    const auto pay_to = [](const CTxDestination& address) {
        return [address](SendCoinsDialog&, SendCoinsEntry& entry) {
            entry.findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
        };
    };
    const auto accepted = [&](const CTransactionRef& tx) {
        return WITH_LOCK(::cs_main, return chainman.ProcessTransaction(tx, /*test_accept=*/true).m_result_type) == MempoolAcceptResult::ResultType::VALID;
    };
    const mw::Hash coin{paid->output_id};
    const CTxDestination l1{WitnessV0KeyHash{GenerateRandomKey().GetPubKey()}};
    QString confirmation;

    // A watch-only wallet sends from MWEB, and pegs out when paying a transparent address from a selected MWEB coin.
    {
        const auto pay_from_coin = [&](SendCoinsDialog& dialog, SendCoinsEntry& entry) {
            pay_to(StealthAddress::Random())(dialog, entry);
            dialog.getCoinControl()->SelectMWEB(coin);
            dialog.getCoinControl()->m_allow_other_inputs = false;
        };
        const CTransactionRef send{create_unsigned(watch_model, *watch, pay_from_coin, confirmation)};
        QVERIFY(send);
        QVERIFY(send->IsMWEBOnly());
        QVERIFY(send->mweb_tx.GetSpentIDs() == std::set<mw::Hash>{coin});
        QVERIFY(accepted(send));

        const auto select_coin = [&](SendCoinsDialog& dialog, SendCoinsEntry& entry) {
            pay_to(l1)(dialog, entry);
            dialog.getCoinControl()->SelectMWEB(coin);
        };
        const CTransactionRef pegout{create_unsigned(watch_model, *watch, select_coin, confirmation)};
        QVERIFY(confirmation.contains(QString::fromStdString(EncodeDestination(l1)) + " (Peg-Out)"));
        QVERIFY(pegout);
        const std::vector<PegOutCoin> pegouts{pegout->mweb_tx.GetPegOuts()};
        QCOMPARE(pegouts.size(), size_t{1});
        QVERIFY(pegouts[0].GetScriptPubKey() == GetScriptForDestination(l1));
        QVERIFY(accepted(pegout));
    }

    // A wallet that signs its sends gives an unsigned PSBT too, when PSBT controls are enabled.
    {
        optionsModel.setData(optionsModel.index(OptionsModel::EnablePSBTControls, 0), true);
        const CTransactionRef send{create_unsigned(signer_model, *signer, pay_to(StealthAddress::Random()), confirmation)};
        QVERIFY(send);
        QVERIFY(send->IsMWEBOnly());
        QVERIFY(accepted(send));

        const auto pegin_entry = [](SendCoinsDialog&, SendCoinsEntry& entry) { entry.findChild<QToolButton*>("mwebPegInButton")->click(); };
        const CTransactionRef pegin{create_unsigned(signer_model, *signer, pegin_entry, confirmation)};
        QVERIFY(pegin);
        QCOMPARE(pegin->mweb_tx.GetPegIns().size(), size_t{1});
        QVERIFY(accepted(pegin));
        optionsModel.setData(optionsModel.index(OptionsModel::EnablePSBTControls, 0), false);
    }
}
