// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/chain.h>
#include <logging.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_scan.h>
#include <mweb/mweb_wallet_types.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

using interfaces::FoundBlock;

namespace MWEB {

//! UTXOs whose view tags are matched together, on the wallet's matching pool.
static constexpr size_t UTXO_SCAN_BATCH_SIZE{4096};

UTXOScanStats ScanWalletUTXOSet(
    wallet::CWallet& wallet,
    const wallet::CWallet::MWEBIndexScanParams* index_params)
{
    UTXOScanStats stats;
    LOCK(wallet.cs_wallet);

    std::vector<wallet::DescriptorScriptPubKeyMan*> accounts = wallet.GetMWEBAccountScriptPubKeyMans();
    if (accounts.empty()) {
        return stats;
    }

    for (wallet::DescriptorScriptPubKeyMan* account_spk : accounts) {
        account_spk->LoadMWEBKeychain();
    }

    if (index_params) {
        for (wallet::DescriptorScriptPubKeyMan* account_spk : accounts) {
            uint32_t phase1_end = std::max(index_params->phase1_end, wallet::CWallet::MWEB_DEFAULT_PHASE1_END);
            if (wallet.m_keypool_size > static_cast<int64_t>(phase1_end)) {
                phase1_end = static_cast<uint32_t>(wallet.m_keypool_size);
            }
            if (index_params->max_index) {
                phase1_end = std::max(phase1_end, *index_params->max_index);
            }
            LOCK(account_spk->cs_desc_man);
            account_spk->ResetMWEBScanState();
            if (!account_spk->RegisterEphemeralMWEBIndexRange(0, phase1_end)) {
                stats.aborted = true;
                return stats;
            }
        }
    }

    struct PendingOutput {
        Output output;
        int32_t height;
    };
    // Candidates that did not rewind yet: a later match can move its account's lookahead over them.
    std::vector<PendingOutput> unmatched;
    const auto rewind = [&](const PendingOutput& pending) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) -> bool {
        mw::Coin mweb_coin;
        if (!wallet.GetMWWallet()->RewindOutput(pending.output, mweb_coin)) {
            return false;
        }
        ++stats.matched;

        uint256 block_hash;
        const uint256 tip_hash = wallet.GetLastBlockHash();
        if (!wallet.chain().findAncestorByHeight(tip_hash, pending.height, FoundBlock().hash(block_hash))) {
            block_hash = tip_hash;
        }

        if (wallet.FindWalletTxByOutputId(mweb_coin.output_id)) {
            return true;
        }

        wallet.AddToWallet(
            MakeTransactionRef(CMutableTransaction{}),
            wallet::TxStateConfirmed{block_hash, pending.height, 0},
            /*update_wtx=*/nullptr,
            /*rescanning_old_block=*/true,
            MWEB::WalletTxInfo{std::move(mweb_coin)});
        ++stats.persisted;
        return true;
    };

    std::vector<Output> pending_outputs;
    std::vector<int32_t> pending_heights;
    pending_outputs.reserve(UTXO_SCAN_BATCH_SIZE);
    pending_heights.reserve(UTXO_SCAN_BATCH_SIZE);
    const auto rewind_pending = [&]() EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        for (const size_t i : wallet.GetMWWallet()->OutputsToRewind(pending_outputs)) {
            PendingOutput pending{pending_outputs[i], pending_heights[i]};
            if (!rewind(pending)) {
                unmatched.push_back(std::move(pending));
            }
        }
        pending_outputs.clear();
        pending_heights.clear();
    };

    const auto scan_result = wallet.chain().scanMWEBUTXOs(
        [&](int32_t height, const Output& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) -> bool {
            if (wallet.IsAbortingRescan()) {
                stats.aborted = true;
                return false;
            }

            pending_outputs.push_back(output);
            pending_heights.push_back(height);
            if (pending_outputs.size() >= UTXO_SCAN_BATCH_SIZE) {
                rewind_pending();
            }
            return true;
        },
        [&wallet] {
            if (wallet.IsAbortingRescan()) {
                throw std::runtime_error("MWEB UTXO set scan aborted");
            }
        });

    if (scan_result.success) {
        rewind_pending();
        const uint64_t matched_before_retry = stats.matched;
        bool found = true;
        while (found && !unmatched.empty() && !wallet.IsAbortingRescan()) {
            found = false;
            std::vector<PendingOutput> still_unmatched;
            for (PendingOutput& pending : unmatched) {
                if (rewind(pending)) {
                    found = true;
                } else {
                    still_unmatched.push_back(std::move(pending));
                }
            }
            unmatched = std::move(still_unmatched);
        }
        if (found && !unmatched.empty()) {
            stats.aborted = true;
        }
        if (stats.matched != matched_before_retry) {
            LogDebug(BCLog::SCAN, "MWEB UTXO set scan: %u more coins found after the lookahead moved\n", stats.matched - matched_before_retry);
        }
    }
    stats.examined = scan_result.examined;
    if (!scan_result.success) {
        if (!scan_result.error.empty()) {
            wallet.WalletLogPrintf("MWEB UTXO set scan failed: %s\n", scan_result.error);
        }
        if (index_params) {
            for (wallet::DescriptorScriptPubKeyMan* account_spk : accounts) {
                LOCK(account_spk->cs_desc_man);
                account_spk->ClearEphemeralMWEBIndices();
            }
        }
        stats.aborted = true;
        return stats;
    }

    if (index_params) {
        wallet::WalletBatch batch(wallet.GetDatabase());
        for (wallet::DescriptorScriptPubKeyMan* account_spk : accounts) {
            LOCK(account_spk->cs_desc_man);
            stats.indices_persisted += account_spk->CommitActiveMWEBIndices(batch);
            account_spk->ClearEphemeralMWEBIndices();
        }
    }

    wallet.GetMWWallet()->UpgradeCoins();

    wallet.WalletLogPrintf(
        "MWEB UTXO set scan: examined=%u matched=%u persisted=%u indices_persisted=%u\n",
        stats.examined, stats.matched, stats.persisted, stats.indices_persisted);
    LogDebug(BCLog::SCAN, "MWEB UTXO set scan: examined=%u matched=%u persisted=%u\n",
             stats.examined, stats.matched, stats.persisted);

    return stats;
}

} // namespace MWEB
