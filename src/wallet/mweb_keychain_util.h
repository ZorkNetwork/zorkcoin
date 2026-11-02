// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MWEB_KEYCHAIN_UTIL_H
#define BITCOIN_WALLET_MWEB_KEYCHAIN_UTIL_H

#include <key.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/wallet/keychain.h>
#include <pubkey.h>

namespace wallet {

class IMWEBKeyStore;

SecretKey KeyToSecretKey(const CKey& key);

/**
 * BIP32 derivation from a wallet master extended key: scan at the chain's
 * MWEB account path then 0', spend at the account path then 1' (m/0'/100'/0'
 * and m/0'/100'/1' on every network), the paths of the default account
 * descriptor's two KEY expressions.
 */
bool DeriveMWEBMasterSecretsFromAccountKey(const CExtKey& master_xprv, SecretKey& scan_secret, SecretKey& spend_secret);

/**
 * Select scan/spend masters for an account whose descriptor root is the wallet
 * master xpub, derived as DeriveMWEBMasterSecretsFromAccountKey does. When
 * preferred_scan is set, succeeds only if the BIP32 scan secret matches it.
 */
bool SelectMWEBAccountMasterSecrets(const CExtPubKey& xpub, const CKey& key,
                                    const SecretKey& preferred_scan,
                                    SecretKey& scan_secret, SecretKey& spend_secret);

mw::Keychain::Ptr MakeMWEBKeychain(IMWEBKeyStore& keystore, const SecretKey& scan_secret, const SecretKey& spend_secret);
//! A watch-only keychain: derives and identifies addresses, cannot produce spend keys.
mw::Keychain::Ptr MakeMWEBKeychain(IMWEBKeyStore& keystore, const SecretKey& scan_secret, const PublicKey& spend_pubkey);

} // namespace wallet

#endif // BITCOIN_WALLET_MWEB_KEYCHAIN_UTIL_H
