// Copyright (c) 2011 - 2020 The Litecoin Core developers
// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_wallet.h>

#include <addresstype.h>
#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <mweb/mweb_output_match.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/output_mask.h>
#include <util/threadpool.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <limits>

using namespace MWEB;

bool MWEB::IsFrozenOutput(const Consensus::Params& params, const mw::Hash& output_id)
{
    const auto& frozen_outputs = params.frozen_mweb_output_ids;
    return std::find(frozen_outputs.begin(), frozen_outputs.end(), uint256(output_id.vec())) != frozen_outputs.end();
}

bool MWEB::IsFrozenOutput(const mw::Hash& output_id)
{
    return IsFrozenOutput(Params().GetConsensus(), output_id);
}

namespace {
const mw::Keychain::Ptr& LoadedKeychain(wallet::DescriptorScriptPubKeyMan& spk)
{
    if (!spk.GetMWEBKeychain()) {
        spk.LoadMWEBKeychain();
    }
    return spk.GetMWEBKeychain();
}

bool AlignCoinToKeychain(const mw::Keychain& keychain, mw::Coin& coin)
{
    if (!coin.HasAddress()) {
        return true;
    }
    const std::optional<uint32_t> index = keychain.LookupAddressIndex(*coin.address);
    if (!index) {
        return false;
    }
    if (*index != coin.address_index) {
        coin.address_index = *index;
        coin.ClearSpendMaterial();
    }
    return true;
}

bool TryPopulateSpendMaterial(wallet::CWallet& wallet, mw::Coin& coin) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    wallet::DescriptorScriptPubKeyMan* account_spk = wallet.GetMWEBAccountForCoin(coin);
    if (!account_spk) {
        return false;
    }
    const mw::Keychain::Ptr& keychain = LoadedKeychain(*account_spk);
    if (!keychain || !AlignCoinToKeychain(*keychain, coin)) {
        return false;
    }
    return keychain->PopulateSpendMaterial(coin);
}

void MergeMissingMetadata(mw::Coin& target, const mw::Coin& source)
{
    if (source.IsMine() && !target.IsMine()) {
        target.address_index = source.address_index;
    }
    if (source.sender_key && !target.sender_key) {
        target.sender_key = source.sender_key;
    }
    if (source.address && !target.address) {
        target.address = source.address;
    }
    if (source.shared_secret && !target.shared_secret) {
        target.shared_secret = source.shared_secret;
    }
    if (source.blind && !target.blind) {
        target.blind = source.blind;
    }
    if (source.shared_secret && (target.amount == 0 || !target.HasSharedSecret())) {
        target.amount = source.amount;
    }
    if (source.master_scan_key_id && !target.master_scan_key_id) {
        target.master_scan_key_id = source.master_scan_key_id;
    }
}

bool NeedsRecipientRewind(const wallet::CWallet& wallet, const mw::Coin& coin, bool sent_by_me)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (coin.IsMine() && coin.HasAddress() && coin.HasSharedSecret() && coin.master_scan_key_id) {
        return false;
    }
    const bool known_external_recipient =
        sent_by_me && coin.HasAddress() && !wallet.IsMine(CTxDestination{*coin.address});
    return !known_external_recipient;
}
} // namespace

bool Wallet::UpgradeCoins()
{
    LOCK(m_pWallet->cs_wallet);

    bool any_spend_capable = false;
    for (wallet::DescriptorScriptPubKeyMan* spk : m_pWallet->GetMWEBAccountScriptPubKeyMans()) {
        spk->LoadMWEBKeychain();
        const mw::Keychain::Ptr& keychain = spk->GetMWEBKeychain();
        if (keychain && keychain->HasSpendSecret()) {
            any_spend_capable = true;
            break;
        }
    }
    if (!any_spend_capable) {
        return false;
    }

    for (auto& entry : m_pWallet->mapWallet) {
        wallet::CWalletTx& wtx = entry.second;
        RewindOutputs(*wtx.GetTx());

        if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
            mw::Coin& coin = *wtx.mweb_wtx_info->received_coin;
            if (coin.HasSpendMaterial()) {
                m_coins[coin.output_id] = coin;
                continue;
            }
            if (TryPopulateSpendMaterial(*m_pWallet, coin)) {
                m_coins[coin.output_id] = coin;
            }
        }
    }

    for (auto& [_, coin] : m_coins) {
        if (!coin.HasSpendMaterial()) {
            TryPopulateSpendMaterial(*m_pWallet, coin);
        }
    }

    return true;
}

void Wallet::LockSpendMaterial()
{
    LOCK(m_pWallet->cs_wallet);

    for (auto& [_, coin] : m_coins) {
        coin.ClearSpendMaterial();
    }

    for (auto& entry : m_pWallet->mapWallet) {
        wallet::CWalletTx& wtx = entry.second;
        if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
            wtx.mweb_wtx_info->received_coin->ClearSpendMaterial();
        }
    }
}

bool Wallet::SanitizeLegacyCoinsOnDisk()
{
    LOCK(m_pWallet->cs_wallet);

    bool had_secrets = false;
    for (const auto& [_, coin] : m_coins) {
        if (coin.spend_key || coin.blind || coin.sender_key) {
            had_secrets = true;
            break;
        }
    }
    if (!had_secrets) {
        for (auto& entry : m_pWallet->mapWallet) {
            wallet::CWalletTx& wtx = entry.second;
            if (!wtx.mweb_wtx_info || !wtx.mweb_wtx_info->received_coin) {
                continue;
            }
            const mw::Coin& coin = *wtx.mweb_wtx_info->received_coin;
            if (coin.spend_key || coin.blind || coin.sender_key) {
                had_secrets = true;
                break;
            }
        }
    }
    if (!had_secrets) {
        return false;
    }

    const bool written = wallet::RunWithinTxn(m_pWallet->GetDatabase(), "sanitize MWEB coins",
        [&](wallet::WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet) {
            for (const auto& [_, coin] : m_coins) {
                if (!batch.WriteMWEBCoin(coin)) return false;
            }
            for (const auto& [id, wtx] : m_pWallet->mapWallet) {
                if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin && !batch.WriteTxMetadata(wtx, id)) return false;
            }
            return true;
        });
    if (!written) {
        throw std::runtime_error("Failed to persist sanitized MWEB records");
    }
    return true;
}

Wallet::Wallet(wallet::CWallet* pWallet)
    : m_pWallet(pWallet) {}

Wallet::~Wallet() = default;

ThreadPool* Wallet::GetMatchPool()
{
    LOCK(m_match_pool_mutex);
    if (!m_match_pool_tried) {
        m_match_pool_tried = true;
        const int workers = std::min(GetNumCores() - 1, OUTPUT_MATCH_MAX_THREADS);
        if (workers > 0) {
            auto pool = std::make_unique<ThreadPool>("mwebmatch");
            try {
                pool->Start(workers);
                m_match_pool = std::move(pool);
            } catch (const std::exception& e) {
                LogWarning("MWEB output matching runs on one thread: %s\n", e.what());
            }
        }
    }
    return m_match_pool.get();
}

std::vector<SecretKey> Wallet::GetScanSecrets()
{
    LOCK(m_pWallet->cs_wallet);
    std::vector<SecretKey> scan_secrets;
    for (wallet::DescriptorScriptPubKeyMan* spk : m_pWallet->GetMWEBAccountScriptPubKeyMans()) {
        const mw::Keychain::Ptr& keychain = LoadedKeychain(*spk);
        if (keychain && !keychain->GetScanSecret().IsNull() &&
            std::find(scan_secrets.begin(), scan_secrets.end(), keychain->GetScanSecret()) == scan_secrets.end()) {
            scan_secrets.push_back(keychain->GetScanSecret());
        }
    }
    return scan_secrets;
}

std::vector<mw::Keychain::Ptr> Wallet::GetAllKeychains() const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    std::vector<mw::Keychain::Ptr> keychains;
    for (wallet::DescriptorScriptPubKeyMan* spk : m_pWallet->GetMWEBAccountScriptPubKeyMans()) {
        const mw::Keychain::Ptr& keychain = LoadedKeychain(*spk);
        if (keychain && !keychain->GetScanSecret().IsNull()) {
            keychains.push_back(keychain);
        }
    }
    return keychains;
}

OutputCandidates Wallet::FindCandidateOutputs(std::span<const Output> outputs)
{
    OutputCandidates candidates;
    candidates.scan_secrets = GetScanSecrets();
    if (outputs.size() > OUTPUT_MATCH_CHUNK_SIZE && outputs.size() * candidates.scan_secrets.size() >= OUTPUT_MATCH_MIN_PARALLEL_WORK) {
        candidates.indices = MWEB::FindCandidateOutputs(outputs, candidates.scan_secrets, GetMatchPool());
    } else {
        candidates.indices = MWEB::FindCandidateOutputs(outputs, candidates.scan_secrets, nullptr);
    }
    return candidates;
}

bool Wallet::SendMetadataComplete(const mw::Coin& coin) const
{
    return coin.amount > 0 && coin.HasSharedSecret();
}

std::vector<size_t> Wallet::OutputsToRewind(std::span<const Output> outputs, const OutputCandidates* precomputed)
{
    LOCK(m_pWallet->cs_wallet);
    OutputCandidates fresh;
    if (precomputed == nullptr || precomputed->scan_secrets != GetScanSecrets()) {
        fresh = FindCandidateOutputs(outputs);
        precomputed = &fresh;
    }
    std::vector<size_t> to_rewind;
    to_rewind.reserve(outputs.size());
    auto next_candidate = precomputed->indices.begin();
    mw::Coin known;
    for (size_t i = 0; i < outputs.size(); ++i) {
        const bool candidate = next_candidate != precomputed->indices.end() && *next_candidate == i;
        if (candidate) {
            ++next_candidate;
        }
        if (candidate || GetCoin(outputs[i].GetOutputID(), known) || FindSenderKey(outputs[i].GetSenderPubKey())) {
            to_rewind.push_back(i);
        }
    }
    return to_rewind;
}

std::vector<mw::Coin> Wallet::RewindOutputs(const CTransaction& tx)
{
    std::vector<mw::Coin> coins;

    if (tx.HasMWEBTx()) {
        for (const Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin mweb_coin;
            if (RewindOutput(output, mweb_coin)) {
                coins.push_back(mweb_coin);
            }
        }
    }

    return coins;
}

bool Wallet::RewindOutput(const Output& output, mw::Coin& coin)
{
    LOCK(m_pWallet->cs_wallet);

    GetCoin(output.GetOutputID(), coin);
    coin.output_id = output.GetOutputID();

    mw::Coin sent_coin;
    const bool sent_by_me = RewindOutputSentByMe(output, sent_coin);
    if (sent_by_me) {
        MergeMissingMetadata(coin, sent_coin);
    }

    bool received_by_me{false};
    if (NeedsRecipientRewind(*m_pWallet, coin, sent_by_me)) {
        mw::Coin received_coin;
        received_by_me = RewindOutputReceivedByMe(output, received_coin);
        if (received_by_me) {
            MergeMissingMetadata(coin, received_coin);
        }
    }

    if (sent_by_me && NeedsRecipientRewind(*m_pWallet, coin, sent_by_me) && !coin.IsMine()) {
        RecoverOwnedOutputFromSenderData(output, coin);
    }

    if (!coin.IsMine() && !sent_by_me && !received_by_me) {
        return false;
    }

    wallet::DescriptorScriptPubKeyMan* detected_account{nullptr};
    if (coin.IsMine()) {
        wallet::DescriptorScriptPubKeyMan* account_spk = m_pWallet->GetMWEBAccountForCoin(coin);
        if (account_spk) {
            const mw::Keychain::Ptr& keychain = LoadedKeychain(*account_spk);
            if (keychain) {
                AlignCoinToKeychain(*keychain, coin);
                if (!coin.HasSpendMaterial() && keychain->HasSpendSecret()) {
                    keychain->PopulateSpendMaterial(coin);
                }
                detected_account = account_spk;
            }
        }
    }

    if (!SaveToWallet({coin})) {
        m_pWallet->WalletLogPrintf("Failed to persist rewound MWEB output %s\n", coin.output_id.ToHex());
        return false;
    }
    if (detected_account) m_pWallet->OnMWEBCoinDetected(*detected_account, coin);

    // Relevant if owned, or a send for which amount was recovered (for history/resync).
    return coin.IsMine() || (sent_by_me && SendMetadataComplete(coin));
}

bool Wallet::RewindOutputReceivedByMe(const Output& output, mw::Coin& coin) const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    for (wallet::DescriptorScriptPubKeyMan* spk : m_pWallet->GetMWEBAccountScriptPubKeyMans()) {
        const mw::Keychain::Ptr& keychain = LoadedKeychain(*spk);
        if (!keychain || !keychain->RewindOutput(output, coin)) {
            continue;
        }
        if (!keychain->HasSpendSecret()) {
            coin.ClearSpendMaterial();
        }
        return true;
    }
    return false;
}

bool Wallet::RewindOutputSentByMe(const Output& output, mw::Coin& coin) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);

    if (SendMetadataComplete(coin) && coin.output_id == output.GetOutputID()) {
        // Already have amount + shared_secret; still ensure sender index advances if needed.
        if (const std::optional<SenderKeyMatch> match = FindSenderKey(output.GetSenderPubKey())) {
            return AdvanceNextSenderKeyIndex(match->master_scan_keyid, match->index);
        }
        return true;
    }

    const std::optional<SenderKeyMatch> match = FindSenderKey(output.GetSenderPubKey());
    if (!match) {
        return false;
    }

    if (!AdvanceNextSenderKeyIndex(match->master_scan_keyid, match->index)) {
        return false;
    }

    coin.Reset();
    coin.output_id = output.GetOutputID();
    coin.address_index = mw::UNKNOWN_INDEX;
    coin.sender_key = match->sender_key;
    coin.master_scan_key_id = match->master_scan_keyid;

    if (output.HasStandardFields() && output.GetRangeProof()) {
        const SecretKey proof_nonce = mw::DeriveProofNonce(match->keychain->GetRewindKey(), output.GetCommitment());
        const BigInt<32> proof_message = Bulletproofs::RewindMessage(
            output.GetCommitment(),
            *output.GetRangeProof(),
            output.GetOutputMessage().Serialized(),
            proof_nonce);

        if (!proof_message.IsZero()) {
            const SecretKey shared_secret(proof_message.data());
            const OutputMask mask = OutputMask::FromShared(shared_secret);
            const uint64_t value = mask.MaskValue(output.GetMaskedValue());

            if (value <= static_cast<uint64_t>(MAX_MONEY) && MoneyRange(static_cast<CAmount>(value)) &&
                mask.SwitchCommit(value) == output.GetCommitment()) {
                coin.amount = static_cast<CAmount>(value);
                coin.blind = mask.GetRawBlind();
                coin.shared_secret = shared_secret;
            }
        }
    }

    return true;
}

bool Wallet::RecoverOwnedOutputFromSenderData(const Output& output, mw::Coin& coin) const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    if (!coin.HasSharedSecret()) {
        return false;
    }

    const PublicKey subaddress_spend_pubkey = mw::RecoverSubaddressSpendPubKey(output.GetReceiverPubKey(), *coin.shared_secret);
    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        if (!keychain || !keychain->HasSpendPubKey()) {
            continue;
        }

        const StealthAddress address(subaddress_spend_pubkey.Mul(keychain->GetScanSecret()), subaddress_spend_pubkey);
        std::optional<uint32_t> address_index = keychain->LookupAddressIndex(address);
        if (!address_index.has_value()) {
            continue;
        }
        if (!m_pWallet->IsMine(CTxDestination{address})) {
            continue;
        }

        coin.output_id = output.GetOutputID();
        coin.address = address;
        coin.address_index = *address_index;
        coin.master_scan_key_id = keychain->GetMasterScanKeyID();
        return true;
    }

    return false;
}

bool Wallet::UseDeterministicSenderKeys() const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    if (const std::optional<bool> configured = m_pWallet->GetMWEBDeterministicSenders()) {
        return *configured;
    }
    if (gArgs.IsArgSet("-mwebdeterministicsenders")) {
        return gArgs.GetBoolArg("-mwebdeterministicsenders", wallet::DEFAULT_MWEB_DETERMINISTIC_SENDERS);
    }
    for (const auto& [_, next_index] : m_next_sender_key_indices) {
        if (next_index > 0) {
            return true;
        }
    }
    return wallet::DEFAULT_MWEB_DETERMINISTIC_SENDERS;
}

util::Result<SecretKey> Wallet::GenerateSenderKey() EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);

    if (!UseDeterministicSenderKeys()) {
        return SecretKey::Random();
    }

    mw::Keychain::Ptr keychain = GetKeychain();
    if (!keychain || keychain->GetScanSecret().IsNull()) {
        return SecretKey::Random();
    }

    const CKeyID master_scan_keyid = keychain->GetMasterScanKeyID();
    uint64_t& next_index = m_next_sender_key_indices[master_scan_keyid];
    if (next_index == std::numeric_limits<uint64_t>::max()) {
        return util::Error{Untranslated("MWEB sender key index exhausted")};
    }

    const SecretKey sender_key = keychain->GetSenderSigningKey(next_index);
    const uint64_t next_index_to_write = next_index + 1;
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    if (!batch.WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return util::Error{Untranslated("Failed to write MWEB sender key index")};
    }

    next_index = next_index_to_write;
    return sender_key;
}

void Wallet::LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    m_next_sender_key_indices[master_scan_keyid] = next_index;
}

std::optional<Wallet::SenderKeyMatch> Wallet::FindSenderKey(const PublicKey& sender_pubkey) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);

    const int64_t configured_keypool = gArgs.GetIntArg("-keypool", wallet::DEFAULT_KEYPOOL_SIZE);
    const uint64_t target_size = configured_keypool > 0 ? static_cast<uint64_t>(configured_keypool) : 1;

    std::set<CKeyID> scanned;
    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        const CKeyID master_scan_keyid = keychain->GetMasterScanKeyID();
        if (!scanned.insert(master_scan_keyid).second) {
            continue;
        }
        const uint64_t next_index = m_next_sender_key_indices[master_scan_keyid];
        const uint64_t range_end = next_index > std::numeric_limits<uint64_t>::max() - target_size
                                       ? std::numeric_limits<uint64_t>::max()
                                       : next_index + target_size;
        auto& cache = m_sender_key_caches[master_scan_keyid];
        for (; cache.range_end < range_end; ++cache.range_end) {
            cache.pubkeys.emplace(PublicKey::From(keychain->GetSenderSigningKey(cache.range_end)), cache.range_end);
        }

        const auto sender = cache.pubkeys.find(sender_pubkey);
        if (sender != cache.pubkeys.end()) {
            return SenderKeyMatch{
                keychain,
                master_scan_keyid,
                sender->second,
                keychain->GetSenderSigningKey(sender->second)};
        }
    }

    return std::nullopt;
}

bool Wallet::AdvanceNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t sender_key_index) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet)
{
    AssertLockHeld(m_pWallet->cs_wallet);

    uint64_t& next_index = m_next_sender_key_indices[master_scan_keyid];
    if (sender_key_index < next_index) {
        return true;
    }

    if (sender_key_index == std::numeric_limits<uint64_t>::max()) {
        return false;
    }

    const uint64_t next_index_to_write = sender_key_index + 1;
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    if (!batch.WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return false;
    }

    next_index = next_index_to_write;
    return true;
}

bool Wallet::IsChange(const StealthAddress& address) const
{
    LOCK(m_pWallet->cs_wallet);
    wallet::DescriptorScriptPubKeyMan* account_spk = m_pWallet->GetMWEBAccountForStealthAddress(address);
    if (!account_spk) {
        return false;
    }
    StealthAddress change_addr;
    if (!m_pWallet->GetMWEBStealthAddress(*account_spk, mw::CHANGE_INDEX, change_addr)) {
        return false;
    }
    return change_addr == address;
}

bool Wallet::GetStealthAddress(const mw::Coin& coin, StealthAddress& address) const
{
    if (coin.HasAddress()) {
        address = *coin.address;
        return true;
    }

    LOCK(m_pWallet->cs_wallet);
    wallet::DescriptorScriptPubKeyMan* account_spk = m_pWallet->GetMWEBAccountForCoin(coin);
    if (!account_spk) {
        return false;
    }
    return m_pWallet->GetMWEBStealthAddress(*account_spk, coin.address_index, address);
}

bool Wallet::GetStealthAddress(const uint32_t index, StealthAddress& address) const
{
    LOCK(m_pWallet->cs_wallet);
    wallet::DescriptorScriptPubKeyMan* account_spk = m_pWallet->GetExternalMWEBScriptPubKeyMan();
    if (!account_spk) {
        return false;
    }
    return m_pWallet->GetMWEBStealthAddress(*account_spk, index, address);
}

void Wallet::LoadToWallet(const mw::Coin& coin)
{
    m_coins[coin.output_id] = coin;
}

bool Wallet::SaveToWallet(const std::vector<mw::Coin>& coins)
{
    LOCK(m_pWallet->cs_wallet);
    if (coins.empty()) return true;
    if (!wallet::RunWithinTxn(m_pWallet->GetDatabase(), "write MWEB coins", [&](wallet::WalletBatch& batch) {
        for (const auto& coin : coins) {
            if (!batch.WriteMWEBCoin(coin)) return false;
        }
        return true;
    })) return false;
    for (const auto& coin : coins) m_coins[coin.output_id] = coin;
    return true;
}

bool Wallet::GetCoin(const mw::Hash& output_id, mw::Coin& coin) const
{
    auto iter = m_coins.find(output_id);
    if (iter != m_coins.end()) {
        coin = iter->second;
        return true;
    }

    coin.Reset();
    return false;
}

mw::Keychain::Ptr Wallet::GetKeychain() const
{
    return m_pWallet->GetMWEBKeychain();
}
