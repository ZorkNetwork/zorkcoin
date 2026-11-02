// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MNEMONIC_WALLETTOOL_H
#define BITCOIN_WALLET_MNEMONIC_WALLETTOOL_H

#include <common/args.h>
#include <key.h>
#include <support/allocators/secure.h>

#include <cstdint>

namespace wallet {

class CWallet;

/** Validate -mnemonic related args; returns false and prints errors on failure. */
bool ValidateMnemonicWalletToolArgs(const ArgsManager& args);

/**
 * Derive the BIP32 master key from the -mnemonic create args, before any wallet
 * file exists. When no -seedphrase is given a phrase is generated and returned in
 * generated_phrase (not printed). Returns false on failure (errors on stderr).
 */
bool DeriveMasterFromMnemonicArgs(const ArgsManager& args, CExtKey& master_out, SecureString& generated_phrase);

/**
 * Init wallet flags, set up descriptors from master_key, and top up the keypool.
 * A non-empty generated_phrase is then printed once to stdout with a warning,
 * and wiped.
 */
void WalletCreateFromMnemonic(CWallet& wallet, uint64_t wallet_creation_flags, const CExtKey& master_key, SecureString& generated_phrase);

} // namespace wallet

#endif // BITCOIN_WALLET_MNEMONIC_WALLETTOOL_H
