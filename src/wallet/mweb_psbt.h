// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MWEB_PSBT_H
#define BITCOIN_WALLET_MWEB_PSBT_H

#include <mweb/mweb_psbt.h>

namespace wallet {
class CWallet;

//! The MWEB coins and keys of a wallet, as seen by the MWEB PSBT updater and signer.
//! Keychains are resolved across the wallet's MWEB accounts. Callers hold cs_wallet across
//! calls for a consistent view; the interface cannot express that, so methods take it again.
class WalletMWEBSigningKeyStore final : public MWEBSigningKeyStore
{
public:
    explicit WalletMWEBSigningKeyStore(const CWallet& wallet) : m_wallet{wallet} {}

    std::optional<mw::Coin> GetCoin(const mw::Hash& output_id) const override;
    std::optional<SecretKey> GetScanSecret(const mw::Coin& coin) const override;
    std::vector<SecretKey> GetScanSecrets() const override;
    bool IsMine(const StealthAddress& address) const override;
    std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress& address) const override;
    std::optional<std::string> InferAddressDescriptor(const mw::Coin& coin) const override;

private:
    const CWallet& m_wallet;
};
} // namespace wallet

#endif // BITCOIN_WALLET_MWEB_PSBT_H
