// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/mweb_psbt.h>

#include <key.h>
#include <mw/wallet/keychain.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <memory>

namespace wallet {

std::optional<mw::Coin> WalletMWEBSigningKeyStore::GetCoin(const mw::Hash& output_id) const
{
    mw::Coin coin;
    if (!m_wallet.GetCoin(output_id, coin)) {
        return std::nullopt;
    }
    return coin;
}

std::optional<SecretKey> WalletMWEBSigningKeyStore::GetScanSecret(const mw::Coin& coin) const
{
    LOCK(m_wallet.cs_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForCoin(coin);
    if (!account || !account->GetMWEBKeychain()) {
        return std::nullopt;
    }
    return account->GetMWEBKeychain()->GetScanSecret();
}

std::vector<SecretKey> WalletMWEBSigningKeyStore::GetScanSecrets() const
{
    std::vector<SecretKey> scan_secrets;
    for (const DescriptorScriptPubKeyMan* account : m_wallet.GetMWEBAccountScriptPubKeyMans()) {
        const mw::Keychain::Ptr& keychain = account->GetMWEBKeychain();
        if (!keychain || keychain->GetScanSecret().IsNull()) continue;
        if (std::find(scan_secrets.begin(), scan_secrets.end(), keychain->GetScanSecret()) == scan_secrets.end()) {
            scan_secrets.push_back(keychain->GetScanSecret());
        }
    }
    return scan_secrets;
}

bool WalletMWEBSigningKeyStore::IsMine(const StealthAddress& address) const
{
    LOCK(m_wallet.cs_wallet);
    return m_wallet.GetMWEBAccountForStealthAddress(address) != nullptr;
}

std::optional<SecretKey> WalletMWEBSigningKeyStore::GetSubaddressSpendSecret(const StealthAddress& address) const
{
    LOCK(m_wallet.cs_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForStealthAddress(address);
    if (!account) {
        return std::nullopt;
    }
    CKey stored_key;
    if (account->GetKey(address.B().GetID(), stored_key)) {
        const SecretKey spend_secret{reinterpret_cast<const uint8_t*>(stored_key.data())};
        if (PublicKey::From(spend_secret) == address.B()) return spend_secret;
    }
    const mw::Keychain::Ptr& keychain = account->GetMWEBKeychain();
    if (!keychain || !keychain->HasSpendSecret()) {
        return std::nullopt;
    }
    const std::optional<uint32_t> index = keychain->LookupAddressIndex(address);
    if (!index || *index == mw::CUSTOM_KEY || keychain->GetStealthAddress(*index) != address) {
        return std::nullopt;
    }
    return keychain->GetSpendKey(*index);
}

std::optional<std::string> WalletMWEBSigningKeyStore::InferAddressDescriptor(const mw::Coin& coin) const
{
    LOCK(m_wallet.cs_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForCoin(coin);
    if (!account || !account->GetMWEBKeychain()) {
        return std::nullopt;
    }
    std::optional<uint32_t> index;
    if (coin.address_index != mw::UNKNOWN_INDEX && coin.address_index != mw::CUSTOM_KEY) {
        index = coin.address_index;
    } else if (coin.address) {
        index = account->GetMWEBKeychain()->LookupAddressIndex(*coin.address);
    }
    if (index == mw::CUSTOM_KEY && coin.address) {
        return account->GetMWEBAddressInfoDescriptor(*coin.address);
    }
    if (!index) {
        return std::nullopt;
    }
    return account->GetMWEBAddressDescriptor(*index);
}

std::unique_ptr<MWEBSigningKeyStore> CWallet::MakeMWEBSigningKeyStore() const
{
    return std::make_unique<WalletMWEBSigningKeyStore>(*this);
}

SecretKey CWallet::GetMWEBRewindKeyForSigning() const
{
    AssertLockHeld(cs_wallet);
    const mw::Keychain::Ptr& keychain = GetMWEBKeychain();
    if (!keychain || keychain->GetScanSecret().IsNull()) {
        return SecretKey::Random();
    }
    return keychain->GetRewindKey();
}

} // namespace wallet
