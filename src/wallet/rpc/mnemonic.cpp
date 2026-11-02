// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <wallet/mnemonic.h>
#include <key_io.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

namespace wallet {

/** Install a BIP32 master as an inactive unused(xprv) descriptor; returns its xpub. */
static std::string AddUnusedHDMaster(CWallet& wallet, const CExtKey& hdkey)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string desc_str = "unused(" + EncodeExtKey(hdkey) + ")";
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
    CHECK_NONFATAL(!descs.empty());
    WalletDescriptor w_desc(std::move(descs.at(0)), GetTime(), 0, 0, 0);
    if (wallet.GetDescriptorScriptPubKeyMan(w_desc) != nullptr) {
        throw JSONRPCError(RPC_WALLET_ERROR, "HD key already exists");
    }

    auto spkm = wallet.AddWalletDescriptor(w_desc, keys, /*label=*/"", /*internal=*/false);
    if (!spkm) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(spkm).original);
    }

    const DescriptorScriptPubKeyMan& desc_spkm = spkm->get();
    LOCK(desc_spkm.cs_desc_man);
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> extpubs;
    desc_spkm.GetWalletDescriptor().descriptor->GetPubKeys(pubkeys, extpubs);
    CHECK_NONFATAL(pubkeys.size() == 0);
    CHECK_NONFATAL(extpubs.size() == 1);
    return EncodeExtPubKey(*extpubs.begin());
}

RPCMethod addhdkey_mnemonic()
{
    const std::string lang_list = mnemonic::ListEnabledLanguages(", ");
    return RPCMethod{
        "addhdkey_mnemonic",
        "Add a BIP 32 HD master key derived from a BIP39 mnemonic.\n"
        "\nWhen 'mnemonic' is omitted, a new phrase is generated and returned once in the result.\n"
        "The mnemonic is never stored in the wallet. Prefer the GUI on shared machines; never log\n"
        "RPC parameters or results containing a mnemonic.\n"
        "\nAllowed word counts (generate only): 12, 15, 18, 21, 24 (default 24).\n"
        "Allowed languages (generate only): " + lang_list + " (default english).\n"
        "On import, language and word count are taken from the phrase.\n"
        "This adds only the HD master. To recover transactions, create the desired descriptors\n"
        "with createwalletdescriptor, then run rescanblockchain from height 0.\n",
        {
            {"passphrase", RPCArg::Type::STR, RPCArg::Default{""}, "Optional BIP39 passphrase (may contain spaces). Used for generate and import."},
            {"mnemonic", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "BIP39 mnemonic to import. Omit to generate a new mnemonic."},
            {"wordcount", RPCArg::Type::NUM, RPCArg::Default{24}, "Number of words when generating (12, 15, 18, 21, or 24). Ignored on import."},
            {"language", RPCArg::Type::STR, RPCArg::Default{"english"}, "BIP39 language tag when generating. Ignored on import."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "xpub", "The xpub of the HD key that was added to the wallet"},
                {RPCResult::Type::STR, "mnemonic", /*optional=*/true, "The generated mnemonic (generate only; shown once)"},
            },
        },
        RPCExamples{
            HelpExampleCli("addhdkey_mnemonic", "")
            + HelpExampleCli("-named addhdkey_mnemonic", "wordcount=12 language=english")
            + HelpExampleCli("-named addhdkey_mnemonic", "mnemonic=\"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"")
            + HelpExampleRpc("addhdkey_mnemonic", "")
        },
        [&](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            if (wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "addhdkey_mnemonic is not available for wallets without private keys");
            }

            EnsureWalletIsUnlocked(*wallet);

            SecureString passphrase;
            if (!request.params[0].isNull()) {
                passphrase = std::string_view{request.params[0].get_str()};
            }

            const bool generate = request.params[1].isNull();
            SecureString mnemonic_words;
            std::string sError;

            if (generate) {
                int wordcount = 24;
                if (!request.params[2].isNull()) {
                    wordcount = request.params[2].getInt<int>();
                }
                const size_t n_entropy = mnemonic::EntropyBytesForWordCount(wordcount);
                if (n_entropy == 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "wordcount must be one of 12, 15, 18, 21, or 24");
                }

                std::string language = "english";
                if (!request.params[3].isNull()) {
                    language = request.params[3].get_str();
                }
                int n_language;
                try {
                    n_language = mnemonic::GetLanguageOffset(language);
                } catch (const std::runtime_error&) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown language. Allowed: " + mnemonic::ListEnabledLanguages(", "));
                }

                // Always draw 32 bytes from Core RNG; shorter mnemonics use a prefix only.
                CKey seed_key = GenerateRandomKey();
                std::vector<uint8_t, secure_allocator<uint8_t>> entropy(n_entropy);
                std::transform(seed_key.begin(), seed_key.begin() + n_entropy, entropy.begin(),
                               [](std::byte b) { return static_cast<uint8_t>(b); });
                if (0 != mnemonic::Encode(n_language, entropy, mnemonic_words, sError)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Mnemonic encode failed: " + sError);
                }
            } else {
                mnemonic_words = std::string_view{request.params[1].get_str()};
            }

            std::vector<uint8_t, secure_allocator<uint8_t>> seed;
            if (!generate) {
                int n_language = -1;
                std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
                if (0 != mnemonic::Decode(n_language, mnemonic_words, entropy, sError)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mnemonic: " + sError);
                }
            }

            if (0 != mnemonic::ToSeed(mnemonic_words, passphrase, seed)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive seed from mnemonic");
            }

            CExtKey hdkey;
            hdkey.SetSeed(std::as_bytes(std::span{seed}));
            if (!hdkey.key.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Derived HD key is invalid");
            }

            UniValue response(UniValue::VOBJ);
            {
                LOCK(wallet->cs_wallet);
                response.pushKV("xpub", AddUnusedHDMaster(*wallet, hdkey));
            }

            if (generate) {
                response.pushKV("mnemonic", std::string(mnemonic_words.begin(), mnemonic_words.end()));
            }

            memory_cleanse(mnemonic_words.data(), mnemonic_words.size());
            memory_cleanse(passphrase.data(), passphrase.size());
            return response;
        },
    };
}

} // namespace wallet
