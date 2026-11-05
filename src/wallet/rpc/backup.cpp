// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <merkleblock.h>
#include <node/types.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/mweb_descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/export.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/mweb_keychain_util.h>

#include <mw/crypto/key_derivation.h>
#include <mw/models/wallet/coin.h>
#include <mw/wallet/keychain.h>

#include <cstdint>
#include <fstream>
#include <tuple>
#include <string>

#include <univalue.h>



using interfaces::FoundBlock;

namespace wallet {
RPCMethod importprunedfunds()
{
    return RPCMethod{
        "importprunedfunds",
        "Imports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n",
                {
                    {"rawtransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A raw transaction in hex funding an already-existing address in wallet"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex output from gettxoutproof that contains the transaction"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    CMerkleBlock merkleBlock;
    SpanReader{ParseHexV(request.params[1], "proof")} >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    std::vector<Txid> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    LOCK(pwallet->cs_wallet);
    int height;
    if (!pwallet->chain().findAncestorByHash(pwallet->GetLastBlockHash(), merkleBlock.header.GetHash(), FoundBlock().height(height))) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
    }

    std::vector<Txid>::const_iterator it;
    if ((it = std::find(vMatch.begin(), vMatch.end(), tx.GetHash())) == vMatch.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
    }

    unsigned int txnIndex = vIndex[it - vMatch.begin()];

    CTransactionRef tx_ref = MakeTransactionRef(tx);
    if (pwallet->IsMine(*tx_ref)) {
        pwallet->AddToWallet(std::move(tx_ref), TxStateConfirmed{merkleBlock.header.GetHash(), height, static_cast<int>(txnIndex)});
        return UniValue::VNULL;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
},
    };
}

RPCMethod removeprunedfunds()
{
    return RPCMethod{
        "removeprunedfunds",
        "(DEPRECATED) This feature will be removed in the next major release. Start bitcoind with the `-deprecatedrpc=removeprunedfunds` option in order to use this.\n"
        "Deletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will affect wallet balances.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded id of the transaction you are deleting"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->chain().rpcEnableDeprecated("removeprunedfunds")) {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "DEPRECATION WARNING: This feature will be removed in the next major release. Start bitcoind with the `-deprecatedrpc=removeprunedfunds` option in order to use this.");
    }

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    std::vector<Txid> vHash;
    vHash.push_back(hash);
    if (auto res = pwallet->RemoveTxs(vHash); !res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    return UniValue::VNULL;
},
    };
}

static int64_t GetImportTimestamp(const UniValue& data, int64_t now)
{
    if (data.exists("timestamp")) {
        const UniValue& timestamp = data["timestamp"];
        if (timestamp.isNum()) {
            return timestamp.getInt<int64_t>();
        } else if (timestamp.isStr() && timestamp.get_str() == "now") {
            return now;
        }
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected number or \"now\" timestamp value for key. got type %s", uvTypeName(timestamp.type())));
    }
    throw JSONRPCError(RPC_TYPE_ERROR, "Missing required timestamp field for key");
}

//! An mweb() descriptor with a public scan key imports only when the wallet already holds the matching
//! scan secret, which is then supplied to the import as if the descriptor had carried it.
static void AddWalletMWEBScanSecretIfPublic(CWallet& wallet, const Descriptor& desc, FlatSigningProvider& keys) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::optional<CKey> scan_ckey;
    std::optional<CKey> spend_ckey;
    if (desc.GetMWEBScanSpendKeys(keys, scan_ckey, spend_ckey)) return;

    if (const std::optional<CPubKey> scan_pubkey = desc.GetMWEBScanPubKey(keys)) {
        const PublicKey scan_point{scan_pubkey->data()};
        for (DescriptorScriptPubKeyMan* spk : wallet.GetMWEBAccountScriptPubKeyMans()) {
            LOCK(spk->cs_desc_man);
            spk->LoadMWEBKeychain();
            if (!spk->HasMWEBScanCapability()) continue;
            const SecretKey scan_secret = spk->GetMWEBScanSecret();
            if (PublicKey::From(scan_secret) != scan_point) continue;
            CKey key;
            key.Set(scan_secret.data(), scan_secret.data() + SecretKey::SIZE, /*fCompressedIn=*/true);
            keys.keys.emplace(scan_pubkey->GetID(), key);
            break;
        }
    }
    if (!desc.GetMWEBScanSpendKeys(keys, scan_ckey, spend_ckey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import mweb() descriptor: the wallet has no scan secret for its scan key");
    }
}

static std::vector<DescriptorScriptPubKeyMan*> GetMWEBAccountsWithScanSecret(const CWallet& wallet, const SecretKey& scan_secret)
{
    std::vector<DescriptorScriptPubKeyMan*> accounts;
    for (DescriptorScriptPubKeyMan* spk : wallet.GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        spk->LoadMWEBKeychain();
        if (spk->IsMWEBAccountDescriptor() && spk->HasMWEBScanCapability() && spk->GetMWEBScanSecret() == scan_secret) {
            accounts.push_back(spk);
        }
    }
    return accounts;
}

//! A single-address entry (not an account) that already holds addr.
static DescriptorScriptPubKeyMan* GetMWEBSingleAddressEntry(const CWallet& wallet, const StealthAddress& addr)
{
    for (DescriptorScriptPubKeyMan* spk : wallet.GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        if (!spk->IsMWEBAccountDescriptor() && spk->IsMine(CTxDestination{addr})) {
            return spk;
        }
    }
    return nullptr;
}

//! The address of an indexed or two-argument mweb() descriptor, derived from its own keys only.
static StealthAddress ExpandMWEBImportAddress(const Descriptor& desc, const FlatSigningProvider& keys)
{
    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    if (desc.ExpandDestinations(0, keys, dests, out, nullptr, nullptr) && !dests.empty()) {
        if (const StealthAddress* addr = std::get_if<StealthAddress>(&dests[0])) {
            return *addr;
        }
    }
    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive the stealth address of the mweb() descriptor");
}

//! "[fingerprint/path]" for a key of desc, or "" when it has no origin beyond itself.
static std::string GetMWEBKeyOrigin(const Descriptor& desc, const FlatSigningProvider& keys, const CPubKey& pubkey)
{
    std::vector<CScript> scripts;
    FlatSigningProvider expanded;
    desc.Expand(0, keys, scripts, expanded);
    const auto it = expanded.origins.find(pubkey.GetID());
    if (it == expanded.origins.end()) return "";
    const KeyOriginInfo& info = it->second.second;
    const CKeyID id = pubkey.GetID();
    if (info.path.empty() && std::equal(std::begin(info.fingerprint), std::end(info.fingerprint), id.begin())) return "";
    const bool apostrophe = desc.ToString().find('\'') != std::string::npos;
    return "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.path, apostrophe) + "]";
}

//! Record addr as the account's address at index, tagged as user-imported. When the import carried
//! the account's master spend secret (given directly, or recovered from b_i), store it with the account.
static void AttachMWEBAddressToAccount(CWallet& wallet, DescriptorScriptPubKeyMan& account, uint32_t index,
                                       const StealthAddress& addr, const std::optional<SecretKey>& spend_secret)
{
    LOCK(account.cs_desc_man);
    WalletBatch batch(wallet.GetDatabase());
    if (spend_secret) {
        if (auto added = account.AddMWEBAccountSpendSecret(batch, *spend_secret); !added) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(added).original);
        }
    }
    if (!account.PersistMWEBInternalIndex(batch, index, addr)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to attach the mweb() address to its account");
    }
    if (account.GetMWEBInternalProtect(index) != DescriptorScriptPubKeyMan::MWEBInternalProtect::KEEP) {
        account.SetMWEBInternalProtect(index, DescriptorScriptPubKeyMan::MWEBInternalProtect::MANUAL);
    }
    account.EnsureMWEBNextIndexAtLeast(index + 1);
    batch.WriteDescriptor(account.GetID(), account.GetWalletDescriptor());
}

static UniValue ProcessDescriptorImport(CWallet& wallet, const UniValue& data, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue warnings(UniValue::VARR);
    UniValue result(UniValue::VOBJ);

    try {
        if (!data.exists("desc")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor not found.");
        }

        const std::string& descriptor = data["desc"].get_str();
        const bool active = data.exists("active") ? data["active"].get_bool() : false;
        const std::string label{LabelFromValue(data["label"])};

        // Parse descriptor string
        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(descriptor, keys, error, /* require_checksum = */ true);
        if (parsed_descs.empty()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
        }
        std::optional<bool> internal;
        if (data.exists("internal")) {
            if (parsed_descs.size() > 1) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot have multipath descriptor while also specifying \'internal\'");
            }
            internal = data["internal"].get_bool();
        }

        // Range check
        std::optional<bool> is_ranged;
        int64_t range_start = 0, range_end = 1, next_index = 0;
        const bool is_mweb_account = GetMWEBForm(*parsed_descs.at(0)) == MWEBDescriptorForm::ACCOUNT;
        if (!parsed_descs.at(0)->IsRange() && data.exists("range") && !is_mweb_account) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
        } else if (parsed_descs.at(0)->IsRange()) {
            if (data.exists("range")) {
                auto range = ParseDescriptorRange(data["range"]);
                range_start = range.first;
                range_end = range.second + 1; // Specified range end is inclusive, but we need range end as exclusive
            } else {
                warnings.push_back("Range not given, using default keypool range");
                range_start = 0;
                range_end = wallet.m_keypool_size;
            }
            next_index = range_start;
            is_ranged = true;

            if (data.exists("next_index")) {
                next_index = data["next_index"].getInt<int64_t>();
                // bound checks
                if (next_index < range_start || next_index >= range_end) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "next_index is out of range");
                }
            }
        }

        const MWEBDescriptorForm parsed_form = GetMWEBForm(*parsed_descs.at(0));
        if (parsed_form == MWEBDescriptorForm::ACCOUNT || parsed_form == MWEBDescriptorForm::INDEXED || parsed_form == MWEBDescriptorForm::SINGLE_SUBADDR) {
            AddWalletMWEBScanSecretIfPublic(wallet, *parsed_descs.at(0), keys);
        }

        // Active descriptors must be ranged (except MWEB account descriptors)
        if (active && !parsed_descs.at(0)->IsRange() && GetMWEBForm(*parsed_descs.at(0)) != MWEBDescriptorForm::ACCOUNT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Active descriptors must be ranged");
        }

        // Multipath descriptors should not have a label
        if (parsed_descs.size() > 1 && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptors should not have a label");
        }

        // Ranged descriptors should not have a label
        if (is_ranged.has_value() && is_ranged.value() && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptors should not have a label");
        }

        bool desc_internal = internal.has_value() && internal.value();
        // Internal addresses should not have a label either
        if (desc_internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal addresses should not have a label");
        }

        // Combo descriptor check
        if (active && !parsed_descs.at(0)->IsSingleType()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Combo descriptors cannot be set to active");
        }

        // If the wallet disabled private keys, abort if private keys exist.
        // An mweb() descriptor may carry its scan private key, which a watch-only MWEB wallet needs.
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !keys.keys.empty()) {
            std::set<CKeyID> scan_key_ids;
            if (parsed_form == MWEBDescriptorForm::ACCOUNT || parsed_form == MWEBDescriptorForm::INDEXED ||
                parsed_form == MWEBDescriptorForm::SINGLE_SUBADDR) {
                if (const auto scan = parsed_descs.at(0)->GetMWEBScanPubKey(keys)) scan_key_ids.insert(scan->GetID());
                if (const auto root = parsed_descs.at(0)->GetMWEBScanRootPubKey()) scan_key_ids.insert(root->GetID());
            }
            for (const auto& [id, _] : keys.keys) {
                if (!scan_key_ids.contains(id)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
                }
            }
            if (const auto spend_root = parsed_descs.at(0)->GetMWEBSpendRootPubKey(); spend_root && keys.keys.contains(spend_root->GetID())) {
                warnings.push_back("The private key given for the scan key also derives the spend key. This wallet has private keys disabled and keeps only the scan secret; to watch every address, import the account as listdescriptors shows it without private keys");
            }
        }

        for (size_t j = 0; j < parsed_descs.size(); ++j) {
            auto parsed_desc = std::move(parsed_descs[j]);
            if (parsed_descs.size() == 2) {
                desc_internal = j == 1;
            } else if (parsed_descs.size() > 2) {
                CHECK_NONFATAL(!desc_internal);
            }
            // Expand to check whether the descriptor can be derived at the first index.
            FlatSigningProvider expand_keys;
            std::vector<CScript> scripts;
            const MWEBDescriptorForm expand_form = GetMWEBForm(*parsed_desc);
            const bool is_mweb_capability = expand_form == MWEBDescriptorForm::ACCOUNT
                || expand_form == MWEBDescriptorForm::INDEXED
                || expand_form == MWEBDescriptorForm::SINGLE_SUBADDR;
            const bool expand_ok = parsed_desc->Expand(0, keys, scripts, expand_keys);
            if (!expand_ok && !is_mweb_capability) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot expand descriptor. Probably because of hardened derivations without private keys provided");
            }

            for (const auto& w : parsed_desc->Warnings()) {
               warnings.push_back(w);
            }

            // If private keys are enabled, check some things.
            // MWEB internal descriptors are public records bound to an
            // already-imported account; spend/scan secrets live on the account.
            const bool is_mweb_internal = expand_form == MWEBDescriptorForm::INTERNAL;
            if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                if (keys.keys.empty() && !is_mweb_internal) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import descriptor without private keys to a wallet with private keys enabled");
                }
                if (!parsed_desc->HavePrivateKeys(keys) && !is_mweb_internal && !is_mweb_capability) {
                    warnings.push_back("Not all private keys provided. Some wallet functionality may return unexpected errors");
                }
            }

            // If this is an unused(KEY) descriptor, check that the wallet doesn't already have other descriptors with this key
            if (!parsed_desc->HasScripts()) {
                const bool is_mweb = parsed_desc->GetOutputType() == OutputType::MWEB;
                if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                    if (!is_mweb) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import unused() to wallet without private keys enabled");
                    }
                } else if (!is_mweb) {
                    // Unused descriptors must contain a single key.
                    // Earlier checks will have enforced that this key is either a private key when private keys are enabled,
                    // or that this key is a public key when private keys are disabled.
                    // If we can retrieve the corresponding private key from the wallet, then this key is already in the wallet
                    // and we should not import it.
                    std::set<CPubKey> pubkeys;
                    std::set<CExtPubKey> extpubs;
                    parsed_desc->GetPubKeys(pubkeys, extpubs);
                    std::transform(extpubs.begin(), extpubs.end(), std::inserter(pubkeys, pubkeys.begin()), [](const CExtPubKey& xpub) { return xpub.pubkey; });
                    CHECK_NONFATAL(pubkeys.size() == 1);
                    if (wallet.GetKey(pubkeys.begin()->GetID())) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import an unused() descriptor when its private key is already in the wallet");
                    }
                }
            }

            WalletDescriptor w_desc(std::move(parsed_desc), timestamp, range_start, range_end, next_index);

            MWEBDescriptorForm mweb_form = GetMWEBForm(*w_desc.descriptor);
            const bool private_keys_enabled = !wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
            const FlatSigningProvider* import_keys = &keys;

            if (mweb_form == MWEBDescriptorForm::INTERNAL) {
                const std::optional<std::string> acct_cksum = GetMWEBAccountChecksum(*w_desc.descriptor);
                if (!acct_cksum) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid MWEB internal descriptor");
                }
                DescriptorScriptPubKeyMan* account_spk = wallet.GetMWEBAccountScriptPubKeyMan(*acct_cksum);
                if (!account_spk) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import MWEB internal descriptor without a matching account descriptor in the wallet");
                }
                const std::optional<uint32_t> index = GetMWEBIndex(*w_desc.descriptor);
                if (!index) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid MWEB internal descriptor");
                }
                // Change (0) and peg-in (1) internals are valid to import when they match
                // the account (watch-only needs them to see change UTXOs). Remapped keys at
                // those indices are rejected by LoadMWEBInternalDescriptorRecord.
                LOCK(account_spk->cs_desc_man);
                account_spk->LoadMWEBKeychain();
                if (auto loaded = account_spk->LoadMWEBInternalDescriptorRecord(w_desc); !loaded) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(loaded).original);
                }
                WalletBatch batch(wallet.GetDatabase());
                if (!batch.WriteMWEBInternalDescriptor(account_spk->GetID(), *index, w_desc)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Writing MWEB internal descriptor failed");
                }
                if (account_spk->GetMWEBInternalProtect(*index) != DescriptorScriptPubKeyMan::MWEBInternalProtect::KEEP) {
                    account_spk->SetMWEBInternalProtect(*index, DescriptorScriptPubKeyMan::MWEBInternalProtect::MANUAL);
                }
                result.pushKV("success", UniValue(true));
                PushWarnings(warnings, result);
                return result;
            }

            // INDEXED: reuse the account with the same master scan/spend keys,
            // or create a supporting account restricted to explicitly imported indices.
            // Never a freestanding INDEXED SPKM.
            if (mweb_form == MWEBDescriptorForm::INDEXED) {
                std::optional<CKey> scan_ckey;
                std::optional<CKey> spend_ckey;
                if (!w_desc.descriptor->GetMWEBScanSpendKeys(keys, scan_ckey, spend_ckey) || !scan_ckey) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "mweb() indexed import requires a private scan key");
                }
                const std::optional<uint32_t> index = GetMWEBIndex(*w_desc.descriptor);
                if (!index) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid MWEB indexed descriptor");
                }
                if (*index == mw::CHANGE_INDEX || *index == mw::PEGIN_INDEX) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "Cannot import reserved MWEB change or peg-in index; these are derived locally");
                }
                const SecretKey imported_scan = KeyToSecretKey(*scan_ckey);
                const std::vector<DescriptorScriptPubKeyMan*> accounts = GetMWEBAccountsWithScanSecret(wallet, imported_scan);
                const StealthAddress addr = ExpandMWEBImportAddress(*w_desc.descriptor, keys);
                std::optional<SecretKey> spend_secret;
                if (spend_ckey && private_keys_enabled) {
                    spend_secret = KeyToSecretKey(*spend_ckey);
                }

                for (DescriptorScriptPubKeyMan* account : accounts) {
                    bool derives{false};
                    {
                        LOCK(account->cs_desc_man);
                        const mw::Keychain* keychain = account->GetMWEBKeychainForExpansion();
                        derives = keychain && keychain->HasSpendPubKey() && keychain->GetStealthAddress(*index) == addr;
                    }
                    if (!derives) continue;
                    AttachMWEBAddressToAccount(wallet, *account, *index, addr, spend_secret);
                    if (active) {
                        warnings.push_back("Indexed mweb() descriptors cannot mint new indices; active flag ignored for minting");
                    }
                    result.pushKV("success", UniValue(true));
                    {
                        LOCK(account->cs_desc_man);
                        result.pushKV("mweb_scan_account", account->GetMWEBAccountChecksum());
                    }
                    PushWarnings(warnings, result);
                    return result;
                }

                // Retain the key expressions and origins, replacing only the fixed
                // subaddress index with the account marker. The account keeps the
                // scan secret and any spend secret through the normal key storage.
                std::string account_body = w_desc.descriptor->ToString();
                account_body.erase(account_body.find('#'));
                account_body.replace(account_body.rfind(','), std::string::npos, ",*)");
                std::string account_error;
                FlatSigningProvider account_keys;
                auto parsed_account = Parse(account_body, account_keys, account_error, /*require_checksum=*/false);
                if (parsed_account.size() != 1 || GetMWEBForm(*parsed_account.at(0)) != MWEBDescriptorForm::ACCOUNT) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build the supporting MWEB account");
                }
                const auto master_spend = parsed_account.at(0)->GetMWEBAccountSpendPubKey(keys);
                if (!master_spend) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive the supporting MWEB account's spend public key");
                }
                const std::string scan_expr = GetMWEBKeyOrigin(*w_desc.descriptor, keys, scan_ckey->GetPubKey()) + EncodeSecret(*scan_ckey);
                const std::string spend_expr = GetMWEBKeyOrigin(*w_desc.descriptor, keys, *master_spend)
                    + (spend_ckey && private_keys_enabled ? EncodeSecret(*spend_ckey) : HexStr(*master_spend));
                // Store resolved master keys, keeping their origins. This lets a
                // later equivalent expression add its spend secret without a
                // dependence on the original HD key-expression spelling.
                account_keys = {};
                parsed_account = Parse(strprintf("mweb(%s,%s,*)", scan_expr, spend_expr), account_keys, account_error, /*require_checksum=*/false);
                CHECK_NONFATAL(parsed_account.size() == 1);
                WalletDescriptor account_desc(std::move(parsed_account.at(0)), timestamp, 0, 1, 0);
                auto& account = wallet.AddMWEBSupportingAccount(account_desc, account_keys);
                AttachMWEBAddressToAccount(wallet, account, *index, addr, spend_secret);
                result.pushKV("success", UniValue(true));
                {
                    LOCK(account.cs_desc_man);
                    result.pushKV("mweb_scan_account", account.GetMWEBAccountChecksum());
                }
                PushWarnings(warnings, result);
                return result;
            }

            // A later explicit account import upgrades a supporting account's
            // discovery scope. Match key material, including equivalent origins
            // or key-expression spellings, without replacing its recorded indices.
            if (mweb_form == MWEBDescriptorForm::ACCOUNT) {
                std::optional<CKey> scan_ckey;
                std::optional<CKey> spend_ckey;
                w_desc.descriptor->GetMWEBScanSpendKeys(keys, scan_ckey, spend_ckey);
                const auto spend_pubkey = w_desc.descriptor->GetMWEBAccountSpendPubKey(keys);
                if (scan_ckey && spend_pubkey) {
                    for (auto* account : GetMWEBAccountsWithScanSecret(wallet, KeyToSecretKey(*scan_ckey))) {
                        LOCK(account->cs_desc_man);
                        const auto* keychain = account->GetMWEBKeychainForExpansion();
                        if (!account->IsMWEBLimitedAccount() || !keychain || !keychain->HasSpendPubKey()
                            || *keychain->GetSpendPubKey() != PublicKey{spend_pubkey->data()}) continue;
                        WalletBatch batch(wallet.GetDatabase());
                        if (spend_ckey && private_keys_enabled) {
                            if (auto added = account->AddMWEBAccountSpendSecret(batch, KeyToSecretKey(*spend_ckey)); !added) {
                                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(added).original);
                            }
                        }
                        if (!account->EnableMWEBAccountDiscovery(batch)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to enable MWEB account discovery");
                        }
                        account->EnsureMWEBNextIndexAtLeast(2);
                        if (!batch.WriteDescriptor(account->GetID(), account->GetWalletDescriptor())) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Writing MWEB account descriptor failed");
                        }
                        if (active) wallet.AddActiveScriptPubKeyMan(account->GetID(), OutputType::MWEB, desc_internal);
                        result.pushKV("success", UniValue(true));
                        result.pushKV("mweb_scan_account", account->GetMWEBAccountChecksum());
                        PushWarnings(warnings, result);
                        return result;
                    }
                }
            }

            // Two-argument (single-address) form: attach to an account that derives the address;
            // otherwise keep it as a separate single-address entry, reusing one that holds the address.
            if (mweb_form == MWEBDescriptorForm::SINGLE_SUBADDR) {
                std::optional<CKey> scan_ckey;
                std::optional<CKey> spend_ckey;
                if (!w_desc.descriptor->GetMWEBScanSpendKeys(*import_keys, scan_ckey, spend_ckey) || !scan_ckey) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "mweb() single-subaddress import requires a private scan key");
                }
                const SecretKey imported_scan = KeyToSecretKey(*scan_ckey);
                const StealthAddress addr = ExpandMWEBImportAddress(*w_desc.descriptor, *import_keys);
                if (!private_keys_enabled) {
                    spend_ckey.reset();
                }

                for (DescriptorScriptPubKeyMan* account : GetMWEBAccountsWithScanSecret(wallet, imported_scan)) {
                    std::optional<uint32_t> index;
                    {
                        LOCK(account->cs_desc_man);
                        index = account->FindMWEBAccountAddressIndex(addr);
                    }
                    if (!index) continue;
                    std::optional<SecretKey> spend_secret;
                    if (spend_ckey) {
                        spend_secret = mw::RecoverMasterSpendSecret(KeyToSecretKey(*spend_ckey), imported_scan, *index);
                    }
                    AttachMWEBAddressToAccount(wallet, *account, *index, addr, spend_secret);
                    result.pushKV("success", UniValue(true));
                    {
                        LOCK(account->cs_desc_man);
                        result.pushKV("mweb_scan_account", account->GetMWEBAccountChecksum());
                    }
                    PushWarnings(warnings, result);
                    return result;
                }

                if (DescriptorScriptPubKeyMan* entry = GetMWEBSingleAddressEntry(wallet, addr)) {
                    LOCK(entry->cs_desc_man);
                    if (spend_ckey && !entry->HaveKey(spend_ckey->GetPubKey().GetID())) {
                        WalletBatch batch(wallet.GetDatabase());
                        if (!entry->AddDescriptorKeyWithDB(batch, *spend_ckey, spend_ckey->GetPubKey())) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store the spend key of the single-address entry");
                        }
                        entry->LoadMWEBKeychain();
                    }
                    result.pushKV("success", UniValue(true));
                    result.pushKV("mweb_scan_account", entry->GetMWEBAccountChecksum());
                    PushWarnings(warnings, result);
                    return result;
                }
            }

            // Active minting is only for ranged ACCOUNT with spend capability.
            // INDEXED warns inside its early-return path above; freestanding INDEXED never reaches here.
            if (active && mweb_form == MWEBDescriptorForm::SINGLE_SUBADDR) {
                warnings.push_back("Single-subaddress mweb() descriptors cannot mint; active flag ignored for minting");
            }

            // Add descriptor to the wallet
            auto spk_manager_res = wallet.AddWalletDescriptor(w_desc, *import_keys, label, desc_internal);

            if (!spk_manager_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Could not add descriptor '%s': %s", descriptor, util::ErrorString(spk_manager_res).original));
            }

            auto& spk_manager = spk_manager_res.value().get();

            // Set descriptor as active if necessary (minting only for ACCOUNT)
            if (active && mweb_form == MWEBDescriptorForm::ACCOUNT) {
                if (!w_desc.descriptor->GetOutputType()) {
                    warnings.push_back("Unknown output type, cannot set descriptor to active.");
                } else {
                    wallet.AddActiveScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else if (active && mweb_form != MWEBDescriptorForm::ACCOUNT && mweb_form != MWEBDescriptorForm::NONE) {
                // Non-minting MWEB forms: still allow as active for receive routing only when ACCOUNT.
                if (w_desc.descriptor->GetOutputType()) {
                    wallet.DeactivateScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else if (active) {
                if (!w_desc.descriptor->GetOutputType()) {
                    warnings.push_back("Unknown output type, cannot set descriptor to active.");
                } else {
                    wallet.AddActiveScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else {
                if (w_desc.descriptor->GetOutputType()) {
                    wallet.DeactivateScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            }

            if (mweb_form == MWEBDescriptorForm::ACCOUNT || mweb_form == MWEBDescriptorForm::INDEXED || mweb_form == MWEBDescriptorForm::SINGLE_SUBADDR) {
                DescriptorScriptPubKeyMan& account_spk = spk_manager;
                std::string scan_cksum;
                {
                    LOCK(account_spk.cs_desc_man);
                    WalletBatch batch(wallet.GetDatabase());
                    account_spk.LoadMWEBKeychain();
                    if (const std::optional<std::string> error = account_spk.CheckMWEBKeychain()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, *error);
                    }
                    if (!account_spk.PersistMWEBLockedMaterial(batch)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Writing the MWEB scan key or descriptor cache failed");
                    }
                    if (mweb_form == MWEBDescriptorForm::ACCOUNT) {
                        account_spk.InitMWEBReservedIndices(batch);
                        account_spk.EnsureMWEBNextIndexAtLeast(2);
                        batch.WriteDescriptor(account_spk.GetID(), account_spk.GetWalletDescriptor());
                    }
                    scan_cksum = account_spk.GetMWEBAccountChecksum();
                }
                if (!scan_cksum.empty()) {
                    result.pushKV("mweb_scan_account", scan_cksum);
                }
            }
        }

        result.pushKV("success", UniValue(true));
    } catch (const UniValue& e) {
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
    }
    PushWarnings(warnings, result);
    return result;
}

RPCMethod importdescriptors()
{
    return RPCMethod{
        "importdescriptors",
        "Import descriptors. This will trigger a rescan of the blockchain based on the earliest timestamp of all descriptors being imported. Requires a new wallet backup.\n"
        "When importing descriptors with multipath key expressions, if the multipath specifier contains exactly two elements, the descriptor produced from the second element will be imported as an internal descriptor.\n"
            "\nNote: This call can take over an hour to complete if using an early timestamp; during that time, other rpc calls\n"
            "may report that the imported keys, addresses or scripts exist but related transactions are still missing.\n"
            "The rescan is significantly faster if block filters are available (using startup option \"-blockfilterindex=1\").\n",
                {
                    {"requests", RPCArg::Type::ARR, RPCArg::Optional::NO, "Data to be imported",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "Descriptor to import."},
                                    {"active", RPCArg::Type::BOOL, RPCArg::Default{false}, "Set this descriptor to be the active descriptor for the corresponding output type/externality"},
                                    {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED, "If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import. For MWEB account descriptors, this raises the stealth-index import scan ceiling above the default keypool size."},
                                    {"next_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If a ranged descriptor is set to active, this specifies the next index to generate addresses from"},
                                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time from which to start rescanning the blockchain for this descriptor, in " + UNIX_EPOCH_TIME_MS + "\n"
                                        "Use the string \"now\" to substitute the current synced blockchain time.\n"
                                        "\"now\" can be specified to bypass scanning, for outputs which are known to never have been used, and\n"
                                        "0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp\n"
                                        "of all descriptors being imported will be scanned as well as the mempool.",
                                        RPCArgOptions{.type_str={"timestamp | \"now\"", "integer / string"}}
                                    },
                                    {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether matching outputs should be treated as not incoming payments (e.g. change)"},
                                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label to assign to the address, only allowed with internal=false. Disabled for ranged descriptors"},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="requests"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Response is an array with the same size as the input that has the execution result",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "success", ""},
                            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR, "", ""},
                            }},
                            {RPCResult::Type::OBJ, "error", /*optional=*/true, "",
                            {
                                {RPCResult::Type::NUM, "code", "JSONRPC error code"},
                                {RPCResult::Type::STR, "message", "JSONRPC error message"},
                            }},
                            {RPCResult::Type::STR, "mweb_scan_account", /*optional=*/true, "Checksum of imported MWEB account descriptor when account import triggers a follow-up scan"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"internal\": true }, "
                                          "{ \"desc\": \"<my descriptor 2>\", \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"active\": true, \"range\": [0,100], \"label\": \"<my bech32 wallet>\" }]'")
                },
        [](const RPCMethod& self, const JSONRPCRequest& main_request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(main_request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    // Ensure that the wallet is not locked for the remainder of this RPC, as
    // the passphrase is used to top up the keypool.
    LOCK(pwallet->m_relock_mutex);

    const UniValue& requests = main_request.params[0];
    const int64_t minimum_timestamp = 1;
    int64_t now = 0;
    int64_t lowest_timestamp = 0;
    bool rescan = false;
    UniValue response(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);

        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(lowest_timestamp).mtpTime(now)));

        // Get all timestamps and extract the lowest timestamp
        struct MWEBAccountScanItem {
            uint256 spkm_id;
            int64_t timestamp;
            std::optional<uint32_t> max_index;
        };
        std::vector<MWEBAccountScanItem> mweb_account_scans;
        for (const UniValue& request : requests.getValues()) {
            // This throws an error if "timestamp" doesn't exist
            const int64_t timestamp = std::max(GetImportTimestamp(request, now), minimum_timestamp);
            const UniValue result = ProcessDescriptorImport(*pwallet, request, timestamp);
            response.push_back(result);

            if (result.exists("mweb_scan_account")) {
                const bool skip_mweb_scan = request.exists("timestamp")
                    && request["timestamp"].isStr()
                    && request["timestamp"].get_str() == "now";
                if (!skip_mweb_scan) {
                    DescriptorScriptPubKeyMan* account_spk = pwallet->GetMWEBAccountScriptPubKeyMan(result["mweb_scan_account"].get_str());
                    if (account_spk) {
                        MWEBAccountScanItem item;
                        item.spkm_id = account_spk->GetID();
                        item.timestamp = timestamp;
                        if (request.exists("range")) {
                            const auto range = ParseDescriptorRange(request["range"]);
                            item.max_index = static_cast<uint32_t>(range.second);
                        }
                        mweb_account_scans.push_back(std::move(item));
                    }
                }
            }

            if (lowest_timestamp > timestamp ) {
                lowest_timestamp = timestamp;
            }

            // If we know the chain tip, and at least one request was successful then allow rescan
            if (!rescan && result["success"].get_bool()) {
                rescan = true;
            }
        }
        pwallet->ConnectScriptPubKeyManNotifiers();
        pwallet->RefreshAllTXOs();

        for (const MWEBAccountScanItem& item : mweb_account_scans) {
            auto* spk_man = pwallet->GetScriptPubKeyMan(item.spkm_id);
            auto* account_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
            if (!account_spk) {
                continue;
            }
            int start_height = 0;
            uint256 start_block;
            if (!pwallet->chain().findFirstBlockWithTimeAndHeight(item.timestamp - TIMESTAMP_WINDOW, 0,
                    FoundBlock().hash(start_block).height(start_height))) {
                start_height = 0;
            }
            CWallet::MWEBIndexScanParams params;
            params.phase1_end = CWallet::MWEB_DEFAULT_PHASE1_END;
            params.gap_limit = CWallet::MWEB_GAP_LIMIT;
            params.max_index = item.max_index;
            pwallet->ScanMWEBUTXOSet(&params);
            (void)pwallet->ScanMWEBAccountIndices(*account_spk, params, start_height);
            // AssumeUTXO: tip-only or failed block history cannot rebuild full MWEB
            // tx history — always warn so operators know to run mwebrescan later.
            if (pwallet->chain().hasAssumedValidChain()) {
                std::vector<UniValue> results = response.getValues();
                for (UniValue& entry : results) {
                    if (!entry.isObject() || !entry.exists("mweb_scan_account")) {
                        continue;
                    }
                    DescriptorScriptPubKeyMan* scanned = pwallet->GetMWEBAccountScriptPubKeyMan(entry["mweb_scan_account"].get_str());
                    if (scanned && scanned->GetID() == item.spkm_id) {
                        UniValue warn_arr(UniValue::VARR);
                        if (entry.exists("warnings")) {
                            for (const UniValue& w : entry["warnings"].getValues()) {
                                warn_arr.push_back(w);
                            }
                        }
                        warn_arr.push_back(
                            "MWEB balance restored from chainstate; transaction history rescan deferred until background sync completes.");
                        entry.pushKV("warnings", std::move(warn_arr));
                        break;
                    }
                }
                response.clear();
                response.setArray();
                for (UniValue& entry : results) {
                    response.push_back(std::move(entry));
                }
            }
        }
    }

    // Rescan the blockchain using the lowest timestamp
    if (rescan) {
        int64_t scanned_time = pwallet->RescanFromTime(lowest_timestamp, reserver);
        pwallet->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_NO_BROADCAST, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }

        if (scanned_time > lowest_timestamp) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();

            // Compose the response
            for (unsigned int i = 0; i < requests.size(); ++i) {
                const UniValue& request = requests.getValues().at(i);

                // If the descriptor timestamp is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (scanned_time <= GetImportTimestamp(request, now) || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else if (pwallet->chain().hasAssumedValidChain() && results.at(i).exists("mweb_scan_account")) {
                    UniValue result = results.at(i);
                    if (result["success"].get_bool()) {
                        UniValue warn_arr(UniValue::VARR);
                        if (result.exists("warnings")) {
                            for (const UniValue& w : result["warnings"].getValues()) {
                                warn_arr.push_back(w);
                            }
                        }
                        warn_arr.push_back(
                            "L1 block rescan deferred until assumeutxo background sync completes; "
                            "MWEB balance restored from chainstate.");
                        result.pushKV("warnings", std::move(warn_arr));
                        response.push_back(std::move(result));
                    } else {
                        response.push_back(std::move(result));
                    }
                } else {
                    std::string error_msg{strprintf("Rescan failed for descriptor with timestamp %d. There "
                            "was an error reading a block from time %d, which is after or within %d seconds "
                            "of key creation, and could contain transactions pertaining to the desc. As a "
                            "result, transactions and coins using this desc may not appear in the wallet.",
                            GetImportTimestamp(request, now), scanned_time - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW / 1000)};
                    if (pwallet->chain().havePruned()) {
                        error_msg += strprintf(" This error could be caused by pruning or data corruption "
                                "(see bitcoind log for details) and could be dealt with by downloading and "
                                "rescanning the relevant blocks (see -reindex option and rescanblockchain RPC).");
                    } else if (pwallet->chain().hasAssumedValidChain()) {
                        error_msg += strprintf(" This error is likely caused by an in-progress assumeutxo "
                                "background sync. Check logs or getchainstates RPC for assumeutxo background "
                                "sync progress and try again later.");
                    } else {
                        error_msg += strprintf(" This error could potentially caused by data corruption. If "
                                "the issue persists you may want to reindex (see -reindex option).");
                    }

                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, error_msg));
                    response.push_back(std::move(result));
                }
            }
        }
    }

    return response;
},
    };
}

RPCMethod listdescriptors()
{
    return RPCMethod{
        "listdescriptors",
        "List all descriptors present in a wallet.\n"
        "MWEB descriptors carry the wallet's MWEB scan secret even without private=true; anyone who has it can see the wallet's MWEB payments and amounts.\n",
        {
            {"private", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show private descriptors."}
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
            {RPCResult::Type::ARR, "descriptors", "Array of descriptor objects (sorted by descriptor string representation)",
            {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "desc", "Descriptor string representation"},
                    {RPCResult::Type::NUM, "timestamp", "The creation time of the descriptor"},
                    {RPCResult::Type::BOOL, "active", "Whether this descriptor is currently used to generate new addresses"},
                    {RPCResult::Type::BOOL, "internal", /*optional=*/true, "True if this descriptor is used to generate change addresses. False if this descriptor is used to generate receiving addresses; defined only for active descriptors"},
                    {RPCResult::Type::ARR_FIXED, "range", /*optional=*/true, "Defined only for ranged descriptors", {
                        {RPCResult::Type::NUM, "", "Range start inclusive"},
                        {RPCResult::Type::NUM, "", "Range end inclusive"},
                    }},
                    {RPCResult::Type::NUM, "next", /*optional=*/true, "Same as next_index field. Kept for compatibility reason."},
                    {RPCResult::Type::NUM, "next_index", /*optional=*/true, "The next index to generate addresses from; defined only for ranged descriptors"},
                }},
            }}
        }},
        RPCExamples{
            HelpExampleCli("listdescriptors", "") + HelpExampleRpc("listdescriptors", "")
            + HelpExampleCli("listdescriptors", "true") + HelpExampleRpc("listdescriptors", "true")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const bool priv = !request.params[0].isNull() && request.params[0].get_bool();
    if (wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && priv) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Can't get private descriptor string for watch-only wallets");
    }
    if (priv) {
        EnsureWalletIsUnlocked(*wallet);
    }

    LOCK(wallet->cs_wallet);
    util::Expected<std::vector<WalletDescInfo>, std::string> exported = ExportDescriptors(*wallet, priv);
    if (!exported) {
        throw JSONRPCError(RPC_WALLET_ERROR, exported.error());
    }
    std::vector<WalletDescInfo> wallet_descriptors = *exported;

    std::sort(wallet_descriptors.begin(), wallet_descriptors.end(), [](const auto& a, const auto& b) {
        return a.descriptor < b.descriptor;
    });

    UniValue descriptors(UniValue::VARR);
    for (const WalletDescInfo& info : wallet_descriptors) {
        UniValue spk(UniValue::VOBJ);
        spk.pushKV("desc", info.descriptor);
        spk.pushKV("timestamp", info.creation_time);
        spk.pushKV("active", info.active);
        if (info.internal.has_value()) {
            spk.pushKV("internal", info.internal.value());
        }
        if (info.range.has_value() && info.range->first < info.range->second) {
            UniValue range(UniValue::VARR);
            range.push_back(info.range->first);
            range.push_back(info.range->second - 1);
            spk.pushKV("range", std::move(range));
            spk.pushKV("next", info.next_index);
            spk.pushKV("next_index", info.next_index);
        }
        descriptors.push_back(std::move(spk));
    }

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_name", wallet->GetName());
    response.pushKV("descriptors", std::move(descriptors));

    return response;
},
    };
}

RPCMethod mwebrescan()
{
    return RPCMethod{
        "mwebrescan",
        "Rescan MWEB extension blocks for stealth indices on a specific account.\n"
        "Ephemeral private derivation is used for indices in the requested window; internal descriptors are persisted only when chain activity is found.\n",
        {
            {"acct_cksum", RPCArg::Type::STR, RPCArg::Optional::NO, "8-character checksum of the MWEB account descriptor"},
            {"start_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "First stealth index to probe (inclusive)"},
            {"end_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Last stealth index to probe (inclusive). Defaults to start_index + keypool size"},
            {"start_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Block height to begin scanning from. Defaults to wallet birth height"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "start_index", ""},
                {RPCResult::Type::NUM, "end_index", ""},
                {RPCResult::Type::NUM, "start_height", ""},
                {RPCResult::Type::NUM, "indices_scanned", ""},
                {RPCResult::Type::NUM, "indices_persisted", ""},
            }
        },
        RPCExamples{
            HelpExampleCli("mwebrescan", "\"qj8x4s2a\" 0 100")
            + HelpExampleRpc("mwebrescan", "\"qj8x4s2a\", 0, 100")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    pwallet->BlockUntilSyncedToCurrentChain();

    const std::string acct_cksum = request.params[0].get_str();
    const uint32_t start_index = request.params[1].getInt<uint32_t>();
    const uint32_t end_index = request.params.size() > 2 && !request.params[2].isNull()
        ? request.params[2].getInt<uint32_t>()
        : start_index + static_cast<uint32_t>(pwallet->m_keypool_size);
    if (end_index < start_index) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "end_index must be >= start_index");
    }

    int start_height = 0;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        start_height = request.params[3].getInt<int>();
        if (start_height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "start_height must be >= 0");
        }
    } else {
        const int64_t birthtime = pwallet->GetBirthTime();
        if (birthtime != UNKNOWN_TIME) {
            uint256 start_block;
            if (!pwallet->chain().findFirstBlockWithTimeAndHeight(birthtime - TIMESTAMP_WINDOW, 0,
                    FoundBlock().hash(start_block).height(start_height))) {
                start_height = 0;
            }
        }
    }

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    DescriptorScriptPubKeyMan* account_spk = pwallet->GetMWEBAccountScriptPubKeyMan(acct_cksum);
    if (!account_spk) {
        throw JSONRPCError(RPC_WALLET_ERROR, "MWEB account not found in wallet");
    }

    {
        LOCK(account_spk->cs_desc_man);
        account_spk->LoadMWEBKeychain();
        account_spk->ResetMWEBScanState();
        if (!account_spk->RegisterEphemeralMWEBIndexRange(start_index, end_index)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to register ephemeral MWEB indices for rescan");
        }
    }

    const size_t before_count = WITH_LOCK(account_spk->cs_desc_man, return account_spk->GetMWEBInternalDescriptorCount());
    if (!pwallet->ScanMWEBBlocksFromHeight(start_height)) {
        LOCK(account_spk->cs_desc_man);
        account_spk->ClearEphemeralMWEBIndices();
        throw JSONRPCError(RPC_WALLET_ERROR, "MWEB rescan failed");
    }

    size_t after_count = before_count;
    {
        LOCK(account_spk->cs_desc_man);
        WalletBatch batch(pwallet->GetDatabase());
        account_spk->CommitActiveMWEBIndices(batch);
        account_spk->ClearEphemeralMWEBIndices();
        after_count = account_spk->GetMWEBInternalDescriptorCount();
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("start_index", start_index);
    result.pushKV("end_index", end_index);
    result.pushKV("start_height", start_height);
    result.pushKV("indices_scanned", static_cast<uint64_t>(end_index - start_index + 1));
    result.pushKV("indices_persisted", static_cast<uint64_t>(after_count - before_count));
    return result;
},
    };
}

RPCMethod mwebscanutxoset()
{
    return RPCMethod{
        "mwebscanutxoset",
        "Scan the MWEB UTXO set in active chainstate at tip and persist matching outputs into the wallet.\n"
        "Without account parameters, registers ephemeral stealth indices for every MWEB account using the\n"
        "default import window (at least indices 0..1000, or keypool size if larger), then scans and\n"
        "commits matches. Optional account parameters use an explicit stealth-index window instead\n"
        "(same registration rules as import/rescan). High indices above the scanned window require a\n"
        "wider explicit range.\n",
        {
            {"acct_cksum", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "8-character checksum of the MWEB account descriptor"},
            {"start_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "First stealth index to probe (inclusive). Requires acct_cksum"},
            {"end_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Last stealth index to probe (inclusive). Defaults to start_index + keypool size"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether the chainstate scan completed"},
                {RPCResult::Type::NUM, "examined", "Number of MWEB UTXOs examined in chainstate"},
                {RPCResult::Type::NUM, "matched", "Number of outputs matching wallet keys"},
                {RPCResult::Type::NUM, "persisted", "Number of new wallet records written"},
                {RPCResult::Type::NUM, "indices_persisted", "Number of ephemeral stealth indices committed"},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages when no outputs matched despite examining UTXOs",
                    {{RPCResult::Type::STR, "", "warning"}}},
            }
        },
        RPCExamples{
            HelpExampleCli("mwebscanutxoset", "\"qj8x4s2a\" 0 100")
            + HelpExampleCli("mwebscanutxoset", "")
            + HelpExampleRpc("mwebscanutxoset", "\"qj8x4s2a\", 0, 100")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    pwallet->BlockUntilSyncedToCurrentChain();

    CWallet::MWEBIndexScanParams scan_params;
    scan_params.phase1_end = CWallet::MWEB_DEFAULT_PHASE1_END;
    scan_params.gap_limit = CWallet::MWEB_GAP_LIMIT;

    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);

        if (!request.params[0].isNull()) {
            const std::string acct_cksum = request.params[0].get_str();
            const uint32_t start_index = request.params.size() > 1 && !request.params[1].isNull()
                ? request.params[1].getInt<uint32_t>() : 0;
            const uint32_t end_index = request.params.size() > 2 && !request.params[2].isNull()
                ? request.params[2].getInt<uint32_t>()
                : start_index + static_cast<uint32_t>(pwallet->m_keypool_size);
            if (end_index < start_index) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "end_index must be >= start_index");
            }
            if (!pwallet->GetMWEBAccountScriptPubKeyMan(acct_cksum)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "MWEB account not found in wallet");
            }
            scan_params.phase1_end = end_index;
            scan_params.max_index = end_index;
        }
    }

    const MWEB::UTXOScanStats stats = pwallet->ScanMWEBUTXOSet(&scan_params);

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", !stats.aborted);
    result.pushKV("examined", stats.examined);
    result.pushKV("matched", stats.matched);
    result.pushKV("persisted", stats.persisted);
    result.pushKV("indices_persisted", stats.indices_persisted);
    if (!stats.aborted && stats.matched == 0 && stats.examined > 0 && pwallet->HasMWEBAccounts()) {
        UniValue warnings(UniValue::VARR);
        warnings.push_back(
            "No outputs matched; if coins exist at higher stealth indices, retry with "
            "mwebscanutxoset <acct_cksum> 0 <N> using a wider end_index.");
        result.pushKV("warnings", std::move(warnings));
    }
    return result;
},
    };
}

RPCMethod mwebkeep()
{
    return RPCMethod{
        "mwebkeep",
        "Set or clear the keep tag on an internal MWEB descriptor index.\n"
        "Kept descriptors are never pruned while the tag is set.\n",
        {
            {"acct_cksum", RPCArg::Type::STR, RPCArg::Optional::NO, "8-character checksum of the MWEB account descriptor"},
            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Stealth index of the internal descriptor"},
            {"keep", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether to set (true, default) or clear (false) the keep tag"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("mwebkeep", "\"qj8x4s2a\" 2")
            + HelpExampleCli("mwebkeep", "\"qj8x4s2a\" 2 false")
            + HelpExampleRpc("mwebkeep", "\"qj8x4s2a\", 2, false")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::string acct_cksum = request.params[0].get_str();
    const uint32_t index = request.params[1].getInt<uint32_t>();
    const bool keep = request.params.size() < 3 || request.params[2].isNull() || request.params[2].get_bool();

    LOCK(pwallet->cs_wallet);
    DescriptorScriptPubKeyMan* account_spk = pwallet->GetMWEBAccountScriptPubKeyMan(acct_cksum);
    if (!account_spk) {
        throw JSONRPCError(RPC_WALLET_ERROR, "MWEB account not found in wallet");
    }

    LOCK(account_spk->cs_desc_man);
    bool found = false;
    for (const WalletDescriptor* wdesc : account_spk->GetMWEBInternalWalletDescriptors()) {
        const std::optional<uint32_t> desc_index = GetMWEBIndex(*wdesc->descriptor);
        if (desc_index && *desc_index == index) {
            found = true;
            break;
        }
    }
    if (!found) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "MWEB internal descriptor not found for index");
    }

    account_spk->SetMWEBInternalProtect(index, keep
        ? DescriptorScriptPubKeyMan::MWEBInternalProtect::KEEP
        : DescriptorScriptPubKeyMan::MWEBInternalProtect::NONE);
    return UniValue::VNULL;
},
    };
}

RPCMethod backupwallet()
{
    return RPCMethod{
        "backupwallet",
        "Safely copies the current wallet file to the specified destination, which can either be a directory or a path with a filename.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination directory or file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return UniValue::VNULL;
},
    };
}


RPCMethod restorewallet()
{
    return RPCMethod{
        "restorewallet",
        "Restores and loads a wallet from backup.\n"
        "\nThe rescan is significantly faster if block filters are available"
        "\n(using startup option \"-blockfilterindex=1\").\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name that will be applied to the restored wallet"},
            {"backup_file", RPCArg::Type::STR, RPCArg::Optional::NO, "The backup file that will be used to restore the wallet."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if restored successfully."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to restoring and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleRpc("restorewallet", R"("testwallet", "home\\backups\\backup-file.bak")")
            + HelpExampleCliNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak"}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak"}, {"load_on_startup", true}})
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{

    WalletContext& context = EnsureWalletContext(request.context);

    auto backup_file = fs::u8path(request.params[1].get_str());

    std::string wallet_name = request.params[0].get_str();

    std::optional<bool> load_on_start = request.params[2].isNull() ? std::nullopt : std::optional<bool>(request.params[2].get_bool());

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    const std::shared_ptr<CWallet> wallet = RestoreWallet(context, backup_file, wallet_name, load_on_start, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;

},
    };
}
} // namespace wallet
