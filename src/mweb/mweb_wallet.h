// Copyright (c) 2011 - 2020 The Litecoin Core developers
// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_WALLET_H
#define BITCOIN_MWEB_MWEB_WALLET_H

#include <consensus/amount.h>
#include <key.h>
#include <mweb/mweb_wallet_types.h>
#include <mw/models/block/block.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/keychain.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <pubkey.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

class ThreadPool;

namespace Consensus {
struct Params;
}

namespace wallet {
class CWallet;
}

namespace MWEB {

//! True if consensus forbids spending this output (Consensus::Params::frozen_mweb_output_ids).
//! The wallet must not count, list or select it.
bool IsFrozenOutput(const Consensus::Params& params, const mw::Hash& output_id);
bool IsFrozenOutput(const mw::Hash& output_id);

//! Outputs whose view tag matched one of the scan secrets, and the secrets it was checked against.
struct OutputCandidates {
    std::vector<SecretKey> scan_secrets;
    std::vector<size_t> indices;
};

class Wallet
{
    struct SenderKeyMatch {
        mw::Keychain::Ptr keychain;
        CKeyID master_scan_keyid;
        uint64_t index;
        SecretKey sender_key;
    };

    struct SenderKeyCache {
        std::map<PublicKey, uint64_t> pubkeys;
        uint64_t range_end{0};
    };

    wallet::CWallet* m_pWallet;
    std::map<mw::Hash, mw::Coin> m_coins;

    //! Next sender-key index per master scan key id. Guarded by m_pWallet->cs_wallet.
    std::map<CKeyID, uint64_t> m_next_sender_key_indices;
    //! Lookahead of derived sender pubkeys per scan key. Guarded by m_pWallet->cs_wallet.
    std::map<CKeyID, SenderKeyCache> m_sender_key_caches;

    Mutex m_match_pool_mutex;
    std::unique_ptr<ThreadPool> m_match_pool GUARDED_BY(m_match_pool_mutex);
    bool m_match_pool_tried GUARDED_BY(m_match_pool_mutex){false};

public:
    explicit Wallet(wallet::CWallet* pWallet);
    ~Wallet();

    bool IsChange(const StealthAddress& address) const;
    bool GetCoin(const mw::Hash& output_id, mw::Coin& coin) const;

    bool UpgradeCoins();
    void LockSpendMaterial();
    //! Rewrite any on-disk mweb_coin / mweb_info records that still contain spend material.
    //! Returns true if any records were rewritten; throws on storage failure.
    bool SanitizeLegacyCoinsOnDisk();

    std::vector<mw::Coin> RewindOutputs(const CTransaction& tx);
    //! Rewinds receive and/or send metadata. Returns true when the wallet should treat the
    //! output as relevant (owned, or a send with recovered amount).
    bool RewindOutput(const Output& output, mw::Coin& coin);

    //! Scan secrets of the MWEB accounts that have a keychain, loading keychains as needed.
    std::vector<SecretKey> GetScanSecrets();
    //! Collects the scan secrets under cs_wallet, then matches view tags without it. Callers
    //! should not hold cs_wallet, or other wallet work waits for the matching.
    OutputCandidates FindCandidateOutputs(std::span<const Output> outputs) EXCLUSIVE_LOCKS_REQUIRED(!m_match_pool_mutex);
    /**
     * Indices, ascending, of outputs to rewind: view-tag candidates, known coins, or outputs
     * whose sender pubkey matches a derived sender key (after keypool lookahead). Reuses
     * precomputed view-tag candidates when the scan secrets have not changed.
     */
    std::vector<size_t> OutputsToRewind(std::span<const Output> outputs, const OutputCandidates* precomputed = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_match_pool_mutex);

    bool GetStealthAddress(const mw::Coin& coin, StealthAddress& address) const;
    bool GetStealthAddress(uint32_t index, StealthAddress& address) const;

    void LoadToWallet(const mw::Coin& coin);
    //! Persist the whole batch before publishing coins in memory.
    [[nodiscard]] bool SaveToWallet(const std::vector<mw::Coin>& coins);

    //! True when MWEB output creation should derive deterministic sender keys (24.x mode)
    //! rather than random ephemeral sender keys (21.x default privacy mode).
    //! Caller must hold cs_wallet.
    bool UseDeterministicSenderKeys() const;
    //! Next deterministic sender signing key for the active MWEB account (when deterministic
    //! sender mode is enabled), or a random key in default 21.x mode / when there is no keychain.
    //! Caller must hold cs_wallet.
    util::Result<SecretKey> GenerateSenderKey();
    //! Caller must hold cs_wallet.
    void LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index);

private:
    mw::Keychain::Ptr GetKeychain() const;
    //! Caller must hold cs_wallet.
    std::vector<mw::Keychain::Ptr> GetAllKeychains() const;
    ThreadPool* GetMatchPool() EXCLUSIVE_LOCKS_REQUIRED(!m_match_pool_mutex);

    //! Caller must hold cs_wallet.
    std::optional<SenderKeyMatch> FindSenderKey(const PublicKey& sender_pubkey);
    bool AdvanceNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t sender_key_index);
    bool RewindOutputReceivedByMe(const Output& output, mw::Coin& coin) const;
    bool RewindOutputSentByMe(const Output& output, mw::Coin& coin);
    bool RecoverOwnedOutputFromSenderData(const Output& output, mw::Coin& coin) const;
    bool SendMetadataComplete(const mw::Coin& coin) const;
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_WALLET_H
