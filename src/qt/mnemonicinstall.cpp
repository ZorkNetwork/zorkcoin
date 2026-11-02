// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicinstall.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <univalue.h>
#include <wallet/mnemonic.h>

#include <QUrl>

#include <span>
#include <string>
#include <vector>

namespace {

/** Derive the BIP32 master xpub for a mnemonic + passphrase (seed stays local). */
bool DeriveExpectedXpub(const SecureString& mnemonic, const SecureString& passphrase,
                        std::string& xpub_out, QString& error_message)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> seed;
    if (0 != mnemonic::ToSeed(mnemonic, passphrase, seed)) {
        error_message = QStringLiteral("Failed to derive seed from mnemonic");
        return false;
    }
    CExtKey hdkey;
    hdkey.SetSeed(std::as_bytes(std::span{seed}));
    if (!hdkey.key.IsValid()) {
        error_message = QStringLiteral("Derived HD key is invalid");
        return false;
    }
    xpub_out = EncodeExtPubKey(hdkey.Neuter());
    return true;
}

/** True if gethdkeys result contains expected_xpub. */
bool HdKeysContainXpub(const UniValue& keys, const std::string& expected_xpub)
{
    if (!keys.isArray()) return false;
    for (size_t i = 0; i < keys.size(); ++i) {
        try {
            if (keys[i].find_value("xpub").get_str() == expected_xpub) {
                return true;
            }
        } catch (const std::runtime_error&) {
            continue;
        }
    }
    return false;
}

} // namespace

bool InstallMnemonicHdKey(interfaces::Node& node, const QString& wallet_name,
                          const SecureString& passphrase, const SecureString& mnemonic,
                          QString& error_message, bool restore)
{
    const QByteArray encoded_name = QUrl::toPercentEncoding(wallet_name);
    const std::string uri = "/wallet/" + std::string(encoded_name.constData(), encoded_name.length());

    auto rpc_message = [](const UniValue& objError) -> QString {
        try {
            return QString::fromStdString(objError.find_value("message").get_str());
        } catch (const std::runtime_error&) {
            return QString::fromStdString(objError.write());
        }
    };

    try {
        std::string expected_xpub;
        if (!DeriveExpectedXpub(mnemonic, passphrase, expected_xpub, error_message)) {
            return false;
        }

        // Idempotent resume: expected master already present → finish descriptors only.
        const UniValue keys = node.executeRpc("gethdkeys", UniValue(UniValue::VARR), uri);
        if (HdKeysContainXpub(keys, expected_xpub)) {
            // Continue with expected_xpub below.
        } else if (keys.isArray() && keys.size() > 0) {
            // A different HD master is already installed — do not bind its descriptors
            // to a UI session that presented another mnemonic.
            error_message = QStringLiteral(
                "A different HD key is already installed in this wallet");
            return false;
        } else {
            UniValue params(UniValue::VARR);
            params.push_back(std::string{passphrase.begin(), passphrase.end()});
            params.push_back(std::string{mnemonic.begin(), mnemonic.end()});
            try {
                const UniValue result = node.executeRpc("addhdkey_mnemonic", params, uri);
                const std::string added = result.find_value("xpub").get_str();
                if (added != expected_xpub) {
                    error_message = QStringLiteral(
                        "Installed HD key does not match the entered mnemonic");
                    return false;
                }
            } catch (UniValue& objError) {
                error_message = rpc_message(objError);
                return false;
            }
        }

        // addhdkey_mnemonic only stores unused(xprv), matching addhdkey. A new mnemonic
        // wallet also needs active descriptors so getnewaddress works (same follow-up as
        // after addhdkey in normal scripting). Idempotent: skip types that already exist.
        static const char* const types[] = {"legacy", "p2sh-segwit", "bech32", "bech32m"};
        for (const char* type : types) {
            UniValue cparams(UniValue::VARR);
            cparams.push_back(type);
            UniValue options(UniValue::VOBJ);
            options.pushKV("hdkey", expected_xpub);
            cparams.push_back(options);
            try {
                node.executeRpc("createwalletdescriptor", cparams, uri);
            } catch (UniValue& objError) {
                const QString msg = rpc_message(objError);
                if (msg.contains(QStringLiteral("Descriptor already exists"))) {
                    continue;
                }
                error_message = msg;
                return false;
            }
        }
        if (restore) {
            // Scan only after all L1 descriptors exist. Use the existing
            // RPC so pruning checks, cancellation, passphrase protection and scan
            // failures follow the same contract as an explicit wallet rescan.
            UniValue params(UniValue::VARR);
            params.push_back(0);
            try {
                node.executeRpc("rescanblockchain", params, uri);
            } catch (UniValue& objError) {
                error_message = rpc_message(objError);
                return false;
            }
        }
        return true;
    } catch (UniValue& objError) {
        error_message = rpc_message(objError);
        return false;
    } catch (const std::exception& e) {
        error_message = QString::fromStdString(e.what());
        return false;
    }
}

bool InstallMnemonicIntoNewWallet(interfaces::Node& node, interfaces::Wallet& wallet,
                                  const SecureString& encryption_passphrase,
                                  const SecureString& mnemonic, const SecureString& passphrase,
                                  QString& error_message, bool restore)
{
    const bool encrypted = !encryption_passphrase.empty();
    if (encrypted && !wallet.unlock(encryption_passphrase)) {
        error_message = QStringLiteral("The wallet passphrase entered was incorrect");
        return false;
    }
    const bool ok = InstallMnemonicHdKey(node, QString::fromStdString(wallet.getWalletName()),
                                         passphrase, mnemonic, error_message, restore);
    if (encrypted) wallet.lock();
    return ok;
}
