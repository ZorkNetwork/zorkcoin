// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/mweb_keychain_util.h>

#include <chainparams.h>
#include <util/bip32.h>

namespace wallet {

namespace {
bool DeriveMWEBMasterSecretsFromExtKey(const CExtKey& account_root, SecretKey& scan_secret, SecretKey& spend_secret)
{
    CExtKey accountKey = account_root;
    for (const uint32_t child : Params().MWEBAccountPath()) {
        CExtKey next;
        if (!accountKey.Derive(next, child)) {
            return false;
        }
        accountKey = next;
    }

    CExtKey scanKey;
    if (!accountKey.Derive(scanKey, BIP32_HARDENED_FLAG)) {
        return false;
    }

    CExtKey spendKey;
    if (!accountKey.Derive(spendKey, BIP32_HARDENED_FLAG | 1)) {
        return false;
    }

    scan_secret = KeyToSecretKey(scanKey.key);
    spend_secret = KeyToSecretKey(spendKey.key);
    return true;
}
} // namespace

SecretKey KeyToSecretKey(const CKey& key)
{
    return SecretKey(reinterpret_cast<const uint8_t*>(key.data()));
}

bool DeriveMWEBMasterSecretsFromAccountKey(const CExtKey& master_xprv, SecretKey& scan_secret, SecretKey& spend_secret)
{
    return DeriveMWEBMasterSecretsFromExtKey(master_xprv, scan_secret, spend_secret);
}

bool SelectMWEBAccountMasterSecrets(const CExtPubKey& xpub, const CKey& key,
                                    const SecretKey& preferred_scan,
                                    SecretKey& scan_secret, SecretKey& spend_secret)
{
    if (!key.VerifyPubKey(xpub.pubkey)) {
        return false;
    }

    const CExtKey account_root(xpub, key);
    SecretKey bip32_scan;
    SecretKey bip32_spend;
    if (!DeriveMWEBMasterSecretsFromAccountKey(account_root, bip32_scan, bip32_spend)) {
        return false;
    }

    if (!preferred_scan.IsNull() && bip32_scan != preferred_scan) {
        return false;
    }

    scan_secret = bip32_scan;
    spend_secret = bip32_spend;
    return true;
}

mw::Keychain::Ptr MakeMWEBKeychain(IMWEBKeyStore& keystore, const SecretKey& scan_secret, const SecretKey& spend_secret)
{
    return std::make_shared<mw::Keychain>(keystore, scan_secret, spend_secret);
}

mw::Keychain::Ptr MakeMWEBKeychain(IMWEBKeyStore& keystore, const SecretKey& scan_secret, const PublicKey& spend_pubkey)
{
    return std::make_shared<mw::Keychain>(keystore, scan_secret, spend_pubkey);
}

} // namespace wallet
