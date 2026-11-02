// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/test/mnemonicinstall_tests.h>

#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <qt/clientmodel.h>
#include <qt/createwalletdialog.h>
#include <qt/mnemonicinstall.h>
#include <qt/mnemonicphrasedialog.h>
#include <qt/mnemonicphraseview.h>
#include <qt/mnemonicsetupdialog.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <rpc/server.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/result.h>
#include <wallet/mnemonic.h>
#include <wallet/walletutil.h>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QRadioButton>
#include <QString>
#include <QTest>
#include <QTimer>

#include <chrono>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace std::chrono_literals;

namespace {
constexpr auto MNEMONIC_A{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"};
constexpr auto MNEMONIC_B{"legal winner thank year wave sausage worth useful legal winner thank yellow"};
constexpr uint64_t BLANK_DESCRIPTOR_FLAGS{wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_BLANK_WALLET};
//! Output types InstallMnemonicHdKey sets up. Each gets an active receive and change
//! descriptor, except MWEB which has a single active descriptor.
const char* const INSTALLED_TYPES[]{"legacy", "p2sh-segwit", "bech32", "bech32m", "mweb"};
const size_t ACTIVE_DESCRIPTORS{2 * (std::size(INSTALLED_TYPES) - 1) + 1};

//! Node with a wallet loader whose RPCs are reachable through interfaces::Node.
struct WalletNodeSetup {
    TestingSetup test;
    std::unique_ptr<interfaces::WalletLoader> loader;

    explicit WalletNodeSetup(interfaces::Node& node, ChainType chain_type = ChainType::MAIN)
        : test{chain_type}, loader{interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args))}
    {
        loader->registerRpcs();
        test.m_node.wallet_loader = loader.get();
        node.setContext(&test.m_node);
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    }
};

std::string WalletUri(const std::string& name) { return "/wallet/" + name; }

std::string ExpectedXpub(const char* words, const char* passphrase)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> seed;
    Assert(mnemonic::ToSeed(SecureString{words}, SecureString{passphrase}, seed) == 0);
    CExtKey key;
    key.SetSeed(std::as_bytes(std::span{seed}));
    return EncodeExtPubKey(key.Neuter());
}

std::vector<std::string> HdXpubs(interfaces::Node& node, const std::string& wallet_name)
{
    std::vector<std::string> xpubs;
    const UniValue keys = node.executeRpc("gethdkeys", UniValue(UniValue::VARR), WalletUri(wallet_name));
    for (size_t i = 0; i < keys.size(); ++i) {
        xpubs.push_back(keys[i].find_value("xpub").get_str());
    }
    return xpubs;
}

size_t ActiveDescriptorCount(interfaces::Node& node, const std::string& wallet_name)
{
    const UniValue result = node.executeRpc("listdescriptors", UniValue(UniValue::VARR), WalletUri(wallet_name));
    size_t active{0};
    for (const UniValue& desc : result.find_value("descriptors").getValues()) {
        if (desc.find_value("active").get_bool()) ++active;
    }
    return active;
}

bool CanGetNewAddress(interfaces::Node& node, const std::string& wallet_name, const char* type)
{
    UniValue params(UniValue::VARR);
    params.push_back("");
    params.push_back(type);
    try {
        return !node.executeRpc("getnewaddress", params, WalletUri(wallet_name)).get_str().empty();
    } catch (const UniValue&) {
        return false;
    }
}

void AddHdKeyViaRpc(interfaces::Node& node, const std::string& wallet_name, const char* passphrase, const char* words)
{
    UniValue params(UniValue::VARR);
    params.push_back(passphrase);
    params.push_back(words);
    node.executeRpc("addhdkey_mnemonic", params, WalletUri(wallet_name));
}

//! Minimal GUI objects needed to run a CreateWalletActivity.
struct ActivityGui {
    OptionsModel options_model;
    std::unique_ptr<ClientModel> client_model;
    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    std::unique_ptr<WalletController> controller;

    explicit ActivityGui(interfaces::Node& node) : options_model(node)
    {
        bilingual_str error;
        QVERIFY(options_model.Init(error));
        client_model = std::make_unique<ClientModel>(node, &options_model);
        controller = std::make_unique<WalletController>(*client_model, platform_style.get(), nullptr);
    }
};

/** Run a CreateWalletActivity, calling handle_modal once for each new modal dialog it
 *  shows. Actions on dialogs must be queued, since the dialogs run nested event loops.
 *  Returns false on timeout. */
bool RunCreateWalletActivity(WalletController& controller, const std::function<void(QWidget*)>& handle_modal,
                             WalletModel*& created)
{
    QPointer<CreateWalletActivity> activity = new CreateWalletActivity(&controller, nullptr);
    QEventLoop loop;
    bool finished{false};
    QObject::connect(activity, &CreateWalletActivity::created, [&](WalletModel* model) { created = model; });
    QObject::connect(activity, &CreateWalletActivity::finished, [&] {
        finished = true;
        loop.quit();
    });

    QPointer<QWidget> last_handled;
    QTimer driver;
    QObject::connect(&driver, &QTimer::timeout, [&] {
        QWidget* modal = QApplication::activeModalWidget();
        if (!modal || modal == last_handled) return;
        last_handled = modal;
        handle_modal(modal);
    });
    driver.start(20ms);
    QTimer::singleShot(60s, &loop, &QEventLoop::quit);

    activity->create();
    loop.exec();
    driver.stop();
    return finished;
}

void FillCreateWalletDialog(CreateWalletDialog& dialog, const QString& name)
{
    dialog.findChild<QLineEdit*>("wallet_name_line_edit")->setText(name);
    dialog.findChild<QCheckBox*>("mnemonic_wallet_checkbox")->setChecked(true);
    QTimer::singleShot(0, &dialog, &QDialog::accept);
}

void ChooseImport(MnemonicSetupDialog& dialog, int word_count)
{
    const auto radios = dialog.findChildren<QRadioButton*>();
    QCOMPARE(radios.size(), 2);
    radios.at(1)->setChecked(true);
    QComboBox* word_counts = dialog.findChildren<QComboBox*>().at(0);
    word_counts->setCurrentIndex(word_counts->findData(word_count));
    QVERIFY(!dialog.isCreateMode());
    QCOMPARE(dialog.wordCount(), word_count);
    QTimer::singleShot(0, &dialog, &QDialog::accept);
}

void EnterPhrase(MnemonicPhraseDialog& dialog, const char* words, const QString& passphrase)
{
    auto* view = dialog.findChild<MnemonicPhraseView*>();
    QVERIFY(view);
    view->setWords(QString::fromUtf8(words).split(QLatin1Char(' ')));
    view->setPassphrase(passphrase);
    QPushButton* restore{nullptr};
    for (QPushButton* button : dialog.findChildren<QPushButton*>()) {
        if (button->text() == QObject::tr("Restore")) restore = button;
    }
    QVERIFY(restore && restore->isEnabled());
    QTimer::singleShot(0, restore, &QPushButton::click);
}

void DismissMessageBox(QMessageBox& box, QString& text)
{
    text = box.text();
    QTimer::singleShot(0, &box, &QDialog::accept);
}
class FakeSigner : public interfaces::ExternalSigner
{
public:
    std::string getName() override { return "fake-signer"; }
};

struct CreateWalletOptions {
    QCheckBox* encrypt;
    QCheckBox* no_privkeys;
    QCheckBox* blank;
    QCheckBox* mnemonic;
    QCheckBox* external;
};

CreateWalletOptions FindCreateWalletOptions(CreateWalletDialog& dialog)
{
    return {
        dialog.findChild<QCheckBox*>("encrypt_wallet_checkbox"),
        dialog.findChild<QCheckBox*>("disable_privkeys_checkbox"),
        dialog.findChild<QCheckBox*>("blank_wallet_checkbox"),
        dialog.findChild<QCheckBox*>("mnemonic_wallet_checkbox"),
        dialog.findChild<QCheckBox*>("external_signer_checkbox"),
    };
}

std::vector<std::unique_ptr<interfaces::ExternalSigner>> OneSigner()
{
    std::vector<std::unique_ptr<interfaces::ExternalSigner>> signers;
    signers.push_back(std::make_unique<FakeSigner>());
    return signers;
}
} // namespace

void MnemonicInstallTests::rejectDifferentMnemonicAfterInstall()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    auto created = setup.loader->createWallet("mn_install", SecureString(), BLANK_DESCRIPTOR_FLAGS, warnings);
    QVERIFY2(created, "createWallet blank descriptors wallet failed");

    QString error;
    QVERIFY2(InstallMnemonicHdKey(m_node, QStringLiteral("mn_install"), SecureString(),
                                  SecureString{MNEMONIC_A}, error),
             qPrintable(error));

    // Re-installing the same mnemonic must succeed (idempotent descriptor finish).
    error.clear();
    QVERIFY2(InstallMnemonicHdKey(m_node, QStringLiteral("mn_install"), SecureString(),
                                  SecureString{MNEMONIC_A}, error),
             qPrintable(error));

    const std::vector<std::string> xpubs_after_a{HdXpubs(m_node, "mn_install")};
    QCOMPARE(xpubs_after_a.size(), size_t{1});
    QCOMPARE(xpubs_after_a[0], ExpectedXpub(MNEMONIC_A, ""));

    // A different mnemonic must fail — must not bind A's descriptors under B's session.
    error.clear();
    QVERIFY(!InstallMnemonicHdKey(m_node, QStringLiteral("mn_install"), SecureString(),
                                  SecureString{MNEMONIC_B}, error));
    QVERIFY(error.contains(QStringLiteral("different HD key")));
    QCOMPARE(HdXpubs(m_node, "mn_install"), xpubs_after_a);
}

void MnemonicInstallTests::resumeAfterMasterAdded()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    QVERIFY(setup.loader->createWallet("mn_resume", SecureString(), BLANK_DESCRIPTOR_FLAGS, warnings));

    // An earlier attempt stored the master key but created no active descriptors.
    AddHdKeyViaRpc(m_node, "mn_resume", "", MNEMONIC_A);
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_resume"), size_t{0});

    QString error;
    QVERIFY2(InstallMnemonicHdKey(m_node, QStringLiteral("mn_resume"), SecureString(),
                                  SecureString{MNEMONIC_A}, error),
             qPrintable(error));
    QCOMPARE(HdXpubs(m_node, "mn_resume"), std::vector<std::string>{ExpectedXpub(MNEMONIC_A, "")});
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_resume"), ACTIVE_DESCRIPTORS);
    for (const char* type : INSTALLED_TYPES) {
        QVERIFY2(CanGetNewAddress(m_node, "mn_resume", type), type);
    }
}

void MnemonicInstallTests::rejectPassphraseMismatch()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    QVERIFY(setup.loader->createWallet("mn_pass", SecureString(), BLANK_DESCRIPTOR_FLAGS, warnings));

    // Same words, different BIP39 passphrase: a different master key.
    AddHdKeyViaRpc(m_node, "mn_pass", "TREZOR", MNEMONIC_A);

    QString error;
    QVERIFY(!InstallMnemonicHdKey(m_node, QStringLiteral("mn_pass"), SecureString(),
                                  SecureString{MNEMONIC_A}, error));
    QVERIFY(error.contains(QStringLiteral("different HD key")));
    QCOMPARE(HdXpubs(m_node, "mn_pass"), std::vector<std::string>{ExpectedXpub(MNEMONIC_A, "TREZOR")});
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_pass"), size_t{0});
}

void MnemonicInstallTests::installIntoEncryptedWallet()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    const SecureString encryption_passphrase{"encryption passphrase"};
    auto created = setup.loader->createWallet("mn_enc", encryption_passphrase, BLANK_DESCRIPTOR_FLAGS, warnings);
    QVERIFY(created);
    interfaces::Wallet& wallet = **created;
    QVERIFY(wallet.isLocked());

    QString error;
    QVERIFY2(InstallMnemonicIntoNewWallet(m_node, wallet, encryption_passphrase,
                                          SecureString{MNEMONIC_A}, SecureString{"TREZOR"}, error),
             qPrintable(error));
    QVERIFY(wallet.isLocked());
    QCOMPARE(HdXpubs(m_node, "mn_enc"), std::vector<std::string>{ExpectedXpub(MNEMONIC_A, "TREZOR")});
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_enc"), ACTIVE_DESCRIPTORS);
    QVERIFY(CanGetNewAddress(m_node, "mn_enc", "bech32"));
    QVERIFY(CanGetNewAddress(m_node, "mn_enc", "mweb"));
}

void MnemonicInstallTests::installIntoEncryptedWalletWrongPassphrase()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    auto created = setup.loader->createWallet("mn_enc_bad", SecureString{"encryption passphrase"}, BLANK_DESCRIPTOR_FLAGS, warnings);
    QVERIFY(created);
    interfaces::Wallet& wallet = **created;

    QString error;
    QVERIFY(!InstallMnemonicIntoNewWallet(m_node, wallet, SecureString{"wrong passphrase"},
                                          SecureString{MNEMONIC_A}, SecureString(), error));
    QVERIFY(!error.isEmpty());
    QVERIFY(wallet.isLocked());
    QVERIFY(HdXpubs(m_node, "mn_enc_bad").empty());
}

void MnemonicInstallTests::createWalletActivityCancelCreatesNothing()
{
    WalletNodeSetup setup(m_node);
    ActivityGui gui(m_node);

    bool setup_dialog_shown{false};
    WalletModel* created{nullptr};
    QVERIFY(RunCreateWalletActivity(*gui.controller, [&](QWidget* modal) {
        if (auto* dialog = qobject_cast<CreateWalletDialog*>(modal)) {
            FillCreateWalletDialog(*dialog, QStringLiteral("mn_cancel"));
        } else if (auto* dialog = qobject_cast<MnemonicSetupDialog*>(modal)) {
            setup_dialog_shown = true;
            QTimer::singleShot(0, dialog, &QDialog::reject);
        }
    }, created));

    QVERIFY(setup_dialog_shown);
    QVERIFY(!created);
    QVERIFY(!gui.controller->listWalletDir().contains("mn_cancel"));
    QVERIFY(setup.loader->getWallets().empty());
}

void MnemonicInstallTests::createWalletActivityImportsPhrase()
{
    WalletNodeSetup setup(m_node, ChainType::REGTEST);
    std::vector<bilingual_str> warnings;
    QVERIFY(setup.loader->createWallet("mn_funded_source", SecureString(), BLANK_DESCRIPTOR_FLAGS, warnings));
    QString install_error;
    QVERIFY2(InstallMnemonicHdKey(m_node, QStringLiteral("mn_funded_source"), SecureString{"TREZOR"},
                                 SecureString{MNEMONIC_A}, install_error), qPrintable(install_error));
    const std::string funded_address{m_node.executeRpc("getnewaddress", UniValue(UniValue::VARR), WalletUri("mn_funded_source")).get_str()};
    QVERIFY(!generatetoaddress(setup.test.m_node, funded_address).IsNull());
    ActivityGui gui(m_node);

    QString message_box_text;
    WalletModel* created{nullptr};
    QVERIFY(RunCreateWalletActivity(*gui.controller, [&](QWidget* modal) {
        if (auto* dialog = qobject_cast<CreateWalletDialog*>(modal)) {
            FillCreateWalletDialog(*dialog, QStringLiteral("mn_import"));
        } else if (auto* dialog = qobject_cast<MnemonicSetupDialog*>(modal)) {
            ChooseImport(*dialog, 12);
        } else if (auto* dialog = qobject_cast<MnemonicPhraseDialog*>(modal)) {
            EnterPhrase(*dialog, MNEMONIC_A, QStringLiteral("TREZOR"));
        } else if (auto* box = qobject_cast<QMessageBox*>(modal)) {
            DismissMessageBox(*box, message_box_text);
        }
    }, created));

    QVERIFY2(message_box_text.isEmpty(), qPrintable(message_box_text));
    QVERIFY(created);
    QCOMPARE(created->getWalletName(), QStringLiteral("mn_import"));
    QCOMPARE(HdXpubs(m_node, "mn_import"), std::vector<std::string>{ExpectedXpub(MNEMONIC_A, "TREZOR")});
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_import"), ACTIVE_DESCRIPTORS);
    // The payment predates the restored wallet and its descriptors. Correct key
    // derivation alone cannot populate this transaction without the Restore scan.
    const UniValue info{m_node.executeRpc("getwalletinfo", UniValue(UniValue::VARR), WalletUri("mn_import"))};
    QCOMPARE(info.find_value("txcount").getInt<int>(), 1);
    const UniValue balances{m_node.executeRpc("getbalances", UniValue(UniValue::VARR), WalletUri("mn_import"))};
    QCOMPARE(balances.find_value("mine").find_value("immature").getValStr(), std::string{"50.00000000"});
    for (const char* type : INSTALLED_TYPES) {
        QVERIFY2(CanGetNewAddress(m_node, "mn_import", type), type);
    }
}

void MnemonicInstallTests::restoreScanCancellationAndRetry()
{
    WalletNodeSetup setup(m_node);
    std::vector<bilingual_str> warnings;
    const SecureString encryption_passphrase{"encryption passphrase"};
    auto created = setup.loader->createWallet("mn_scan_cancel", encryption_passphrase, BLANK_DESCRIPTOR_FLAGS, warnings);
    QVERIFY(created);
    interfaces::Wallet& wallet = **created;
    bool scan_started{false};
    auto handler = wallet.handleShowProgress([&](const std::string&, int progress) {
        if (progress == 0) {
            scan_started = true;
            wallet.abortRescan();
        }
    });
    QString error;
    QVERIFY(!InstallMnemonicIntoNewWallet(m_node, wallet, encryption_passphrase,
                                         SecureString{MNEMONIC_A}, SecureString{}, error, /*restore=*/true));
    QVERIFY(scan_started);
    QVERIFY(error.contains(QStringLiteral("Rescan aborted")));
    QVERIFY(wallet.isLocked());
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_scan_cancel"), ACTIVE_DESCRIPTORS);
    QCOMPARE(HdXpubs(m_node, "mn_scan_cancel"), std::vector<std::string>{ExpectedXpub(MNEMONIC_A, "")});

    // Cancellation preserves installed descriptors; retry must complete without
    // replacing the master or reporting a duplicate-descriptor failure.
    handler->disconnect();
    error.clear();
    QVERIFY2(InstallMnemonicIntoNewWallet(m_node, wallet, encryption_passphrase,
                                         SecureString{MNEMONIC_A}, SecureString{}, error, /*restore=*/true), qPrintable(error));
    QVERIFY(wallet.isLocked());
    QCOMPARE(ActiveDescriptorCount(m_node, "mn_scan_cancel"), ACTIVE_DESCRIPTORS);
}

void MnemonicInstallTests::createWalletDefaultOptionStates()
{
    CreateWalletDialog dialog(nullptr);
    dialog.setSigners({});
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);

    QVERIFY(o.encrypt->isEnabled());
    QVERIFY(o.no_privkeys->isEnabled());
    QVERIFY(o.blank->isEnabled());
    QVERIFY(o.mnemonic->isEnabled());
    QVERIFY(!o.external->isEnabled());
    QVERIFY(!o.encrypt->isChecked() && !o.no_privkeys->isChecked() && !o.blank->isChecked() &&
            !o.mnemonic->isChecked() && !o.external->isChecked());
}

void MnemonicInstallTests::createWalletDisablePrivateKeysExcludesKeyedOptions()
{
    CreateWalletDialog dialog(nullptr);
    dialog.setSigners({});
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);

    o.no_privkeys->setChecked(true);
    QVERIFY(!o.encrypt->isEnabled());
    QVERIFY(!o.blank->isEnabled());
    QVERIFY(!o.mnemonic->isEnabled());

    o.no_privkeys->setChecked(false);
    QVERIFY(o.encrypt->isEnabled());
    QVERIFY(o.blank->isEnabled());
    QVERIFY(o.mnemonic->isEnabled());
}

void MnemonicInstallTests::createWalletEncryptExcludesDisablePrivateKeys()
{
    CreateWalletDialog dialog(nullptr);
    dialog.setSigners({});
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);

    o.encrypt->setChecked(true);
    QVERIFY(!o.no_privkeys->isEnabled());
    QVERIFY(o.blank->isEnabled());
    QVERIFY(o.mnemonic->isEnabled());

    o.encrypt->setChecked(false);
    QVERIFY(o.no_privkeys->isEnabled());
}

void MnemonicInstallTests::createWalletBlankAndMnemonicAreExclusive()
{
    CreateWalletDialog dialog(nullptr);
    dialog.setSigners({});
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);

    o.blank->setChecked(true);
    QVERIFY(!o.mnemonic->isEnabled());
    QVERIFY(!o.no_privkeys->isEnabled());
    QVERIFY(o.encrypt->isEnabled());
    o.blank->setChecked(false);

    o.mnemonic->setChecked(true);
    QVERIFY(!o.blank->isEnabled());
    QVERIFY(!o.no_privkeys->isEnabled());
    QVERIFY(o.encrypt->isEnabled());
    o.mnemonic->setChecked(false);
    QVERIFY(o.blank->isEnabled());
    QVERIFY(o.no_privkeys->isEnabled());
}

void MnemonicInstallTests::createWalletExternalSignerLocksOptions()
{
#ifdef ENABLE_EXTERNAL_SIGNER
    CreateWalletDialog dialog(nullptr);
    dialog.setSigners(OneSigner());
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);

    QVERIFY(o.external->isEnabled() && o.external->isChecked());
    QVERIFY(o.no_privkeys->isChecked() && !o.no_privkeys->isEnabled());
    QVERIFY(!o.encrypt->isEnabled() && !o.blank->isEnabled() && !o.mnemonic->isEnabled());
    QCOMPARE(dialog.walletName(), QStringLiteral("fake-signer"));

    // Unchecking the signer restores the other options to their default.
    o.external->setChecked(false);
    QVERIFY(!o.no_privkeys->isChecked());
    QVERIFY(o.no_privkeys->isEnabled() && o.encrypt->isEnabled() && o.blank->isEnabled() && o.mnemonic->isEnabled());
#else
    QSKIP("Compiled without external signer support");
#endif
}

void MnemonicInstallTests::createWalletMnemonicBlocksExternalSignerDefault()
{
#ifdef ENABLE_EXTERNAL_SIGNER
    CreateWalletDialog dialog(nullptr);
    const CreateWalletOptions o = FindCreateWalletOptions(dialog);
    o.mnemonic->setChecked(true);
    dialog.setSigners(OneSigner());

    QVERIFY(!o.external->isEnabled() && !o.external->isChecked());
    QVERIFY(o.mnemonic->isChecked());
    QVERIFY(!o.no_privkeys->isChecked());

    o.mnemonic->setChecked(false);
    QVERIFY(o.external->isEnabled());
#else
    QSKIP("Compiled without external signer support");
#endif
}
