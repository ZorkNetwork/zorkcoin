// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/mnemonic_wallettool.h>

#include <key.h>
#include <wallet/mnemonic.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace wallet {
namespace {

SecureString ReadSeedPhraseFromTerminal()
{
    tfm::format(std::cerr, "Enter BIP39 seed phrase (words separated by space, comma, tab, or newline):\n");
    SecureString phrase;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty() && !phrase.empty()) break;
        if (!phrase.empty() && !phrase.ends_with(' ') && !line.empty()) {
            phrase += ' ';
        }
        for (char c : line) {
            if (c == ',' || c == '\t') {
                phrase += ' ';
            } else {
                phrase += c;
            }
        }
        // Single line is enough when non-empty
        if (!phrase.empty()) break;
    }
    // Normalize commas/tabs already done; collapse runs of spaces via Decode's NormaliseInput
    return phrase;
}

SecureString NormalizeSeedPhraseArg(std::string_view raw)
{
    SecureString out;
    for (char c : raw) {
        if (c == ',' || c == '\t' || c == '\n' || c == '\r') {
            out += ' ';
        } else {
            out += c;
        }
    }
    return out;
}

} // namespace

bool DeriveMasterFromMnemonicArgs(const ArgsManager& args, CExtKey& master_out, SecureString& generated_phrase)
{
    SecureString passphrase;
    if (args.IsArgSet("-passphrase")) {
        passphrase = std::string_view{args.GetArg("-passphrase", "")};
    }

    SecureString mnemonic_words;
    std::string sError;
    const bool has_seedphrase = args.IsArgSet("-seedphrase");

    if (!has_seedphrase) {
        int wordcount = args.GetIntArg("-wordcount", 24);
        const size_t n_entropy = mnemonic::EntropyBytesForWordCount(wordcount);
        if (n_entropy == 0) {
            tfm::format(std::cerr, "Error: -wordcount must be one of 12, 15, 18, 21, or 24.\n");
            return false;
        }
        std::string language = args.GetArg("-language", "english");
        int n_language;
        try {
            n_language = mnemonic::GetLanguageOffset(language);
        } catch (const std::runtime_error&) {
            tfm::format(std::cerr, "Error: Unknown -language. Allowed: %s\n", mnemonic::ListEnabledLanguages(", "));
            return false;
        }

        CKey seed_key = GenerateRandomKey();
        std::vector<uint8_t, secure_allocator<uint8_t>> entropy(n_entropy);
        std::transform(seed_key.begin(), seed_key.begin() + n_entropy, entropy.begin(),
                       [](std::byte b) { return static_cast<uint8_t>(b); });
        if (0 != mnemonic::Encode(n_language, entropy, mnemonic_words, sError)) {
            tfm::format(std::cerr, "Error: mnemonic encode failed: %s\n", sError);
            return false;
        }
    } else {
        const std::string seedphrase_arg = args.GetArg("-seedphrase", "");
        if (seedphrase_arg.empty()) {
            mnemonic_words = ReadSeedPhraseFromTerminal();
        } else {
            mnemonic_words = NormalizeSeedPhraseArg(seedphrase_arg);
        }
        if (mnemonic_words.empty()) {
            tfm::format(std::cerr, "Error: empty seed phrase.\n");
            return false;
        }
        int n_language = -1;
        std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
        if (0 != mnemonic::Decode(n_language, mnemonic_words, entropy, sError)) {
            tfm::format(std::cerr, "Error: invalid mnemonic: %s\n", sError);
            return false;
        }
    }

    std::vector<uint8_t, secure_allocator<uint8_t>> seed;
    if (0 != mnemonic::ToSeed(mnemonic_words, passphrase, seed)) {
        tfm::format(std::cerr, "Error: failed to derive seed from mnemonic.\n");
        return false;
    }
    master_out.SetSeed(std::as_bytes(std::span{seed}));
    if (!master_out.key.IsValid()) {
        tfm::format(std::cerr, "Error: derived HD key is invalid.\n");
        return false;
    }

    if (!has_seedphrase) generated_phrase.swap(mnemonic_words);
    memory_cleanse(mnemonic_words.data(), mnemonic_words.size());
    memory_cleanse(passphrase.data(), passphrase.size());
    return true;
}

bool ValidateMnemonicWalletToolArgs(const ArgsManager& args)
{
    const bool want_mnemonic = args.GetBoolArg("-mnemonic", false);
    const bool has_seedphrase = args.IsArgSet("-seedphrase");
    const bool has_wordcount = args.IsArgSet("-wordcount");
    const bool has_language = args.IsArgSet("-language");
    const bool has_passphrase = args.IsArgSet("-passphrase");

    if (!want_mnemonic && (has_seedphrase || has_wordcount || has_language || has_passphrase)) {
        tfm::format(std::cerr, "Error: -seedphrase/-wordcount/-language/-passphrase require -mnemonic.\n");
        return false;
    }
    return true;
}

void WalletCreateFromMnemonic(CWallet& wallet, uint64_t wallet_creation_flags, const CExtKey& master_key, SecureString& generated_phrase)
{
    {
        LOCK(wallet.cs_wallet);

        wallet.InitWalletFlags(wallet_creation_flags);

        Assert(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        Assert(RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"setup descriptors", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
            wallet.SetupDescriptorScriptPubKeyMans(batch, master_key);
            return true;
        }));

        tfm::format(std::cout, "Topping up keypool...\n");
        wallet.TopUpKeyPool();
    }

    if (!generated_phrase.empty()) {
        tfm::format(std::cout, "Generated BIP39 mnemonic (write it down; it will not be stored):\n%s\n", std::string(generated_phrase.begin(), generated_phrase.end()));
        tfm::format(std::cerr, "WARNING: This is the only time the mnemonic will be shown. Store it offline securely.\n");
        memory_cleanse(generated_phrase.data(), generated_phrase.size());
        generated_phrase.clear();
    }
}

} // namespace wallet
