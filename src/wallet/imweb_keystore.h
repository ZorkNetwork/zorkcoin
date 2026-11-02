// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_IMWEB_KEYSTORE_H
#define BITCOIN_WALLET_IMWEB_KEYSTORE_H

#include <mw/models/wallet/stealth_address.h>
#include <pubkey.h>
#include <wallet/walletdb.h>

#include <memory>

namespace wallet {

/** Interface for MWEB key/metadata lookup used by mw::Keychain. */
class IMWEBKeyStore
{
public:
    virtual ~IMWEBKeyStore() = default;
    virtual std::unique_ptr<CKeyMetadata> GetMetadata(const StealthAddress& addr) const = 0;
    virtual bool GetKey(const CKeyID& id, CKey& keyOut) const = 0;
    virtual bool HaveKey(const CKeyID& id) const = 0;
};

} // namespace wallet

#endif // BITCOIN_WALLET_IMWEB_KEYSTORE_H
