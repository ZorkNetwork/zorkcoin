// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_SPEND_H
#define BITCOIN_MWEB_MWEB_SPEND_H

#include <consensus/amount.h>
#include <mweb/mweb_transact.h>
#include <mw/consensus/params.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/wallet.h>

#include <optional>
#include <set>
#include <vector>

namespace MWEB {

/** L1 vsize used for fee budgeting, matching Litecoin fee semantics.
 *
 * MWEB_TO_MWEB (and MWEB-only peg-outs) contribute 0 L1 bytes; MWEB weight is
 * charged separately via GetMWEBFee. Peg-ins include the L1 skeleton size and
 * HogEx input weight converted to vsize.
 */
int32_t EstimateMWEBTxSize(
    TxType mweb_type,
    int32_t signed_l1_vsize,
    const std::set<wallet::CInputCoin>& selected_coins,
    const std::vector<wallet::CRecipient>& recipients);

/** As above, including a change peg-out to pegout_change_script when it is not empty. */
int32_t EstimateMWEBTxSize(
    TxType mweb_type,
    int32_t signed_l1_vsize,
    const std::set<wallet::CInputCoin>& selected_coins,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script);

/** Kernel fee portion (mweb_fee) for the given path.
 *
 * Always GetTotalFee(pegout_bytes, mweb_weight). For MWEB_TO_MWEB this equals
 * GetMWEBFee(mweb_weight) because pegout_bytes is 0.
 */
CAmount ComputeKernelFee(
    const CFeeRate& feerate,
    TxType mweb_type,
    uint64_t mweb_weight,
    const std::vector<wallet::CRecipient>& recipients);

/** As above, including a change peg-out to pegout_change_script when it is not empty. */
CAmount ComputeKernelFee(
    const CFeeRate& feerate,
    TxType mweb_type,
    uint64_t mweb_weight,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script);

/** Total fee required (L1 byte fee + MWEB weight fee + bump fees + MWEB mempool min). */
CAmount ComputeFeeNeeded(
    const CFeeRate& feerate,
    int32_t l1_vsize,
    uint64_t mweb_weight,
    CAmount bump_fees = 0,
    const CFeeRate& mweb_mempool_min = CFeeRate{0});

/**
 * GetTransactionWeight of the transaction once its MWEB part is signed. The MWEB part
 * may still be unsigned, so the weight is computed from its peg-ins and peg-outs.
 */
int32_t EstimateBuiltTxWeight(const CMutableTransaction& tx);

/** Extra amount to add to the L1 selection target when funding a peg-in. */
CAmount PegInSelectionFee(
    const CFeeRate& feerate,
    const std::vector<wallet::CRecipient>& recipients);

/** As above, with the change pegged out to pegout_change_script when it is not empty. */
CAmount PegInSelectionFee(
    const CFeeRate& feerate,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script);

/** Selection targets bounding the changeless window
 * (doc/mweb/descriptors.md "Selection algorithm").
 *
 * A selection total in [no_change, with_change] builds without a change
 * output, committing the excess as kernel fee; a total above with_change
 * builds with a change output.
 */
struct SelectionTargets {
    CAmount no_change{0};   //!< Recipients + kernel fee without a change output
    CAmount with_change{0}; //!< Recipients + kernel fee with a change output
};

SelectionTargets ComputeSelectionTargets(
    const CFeeRate& feerate,
    TxType mweb_type,
    CAmount recipients_sum,
    const std::vector<wallet::CRecipient>& recipients);

/** As above, with the change pegged out to pegout_change_script when it is not empty.
 *  mweb_mempool_min is the rolling MWEB excess (sat per 1000 W) from getmempoolinfo.mwebminfee. */
SelectionTargets ComputeSelectionTargets(
    const CFeeRate& feerate,
    TxType mweb_type,
    CAmount recipients_sum,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script,
    const CFeeRate& mweb_mempool_min = CFeeRate{0});

/** Coin-control UI fee estimate (L1 vsize + MWEB weight).
 *
 * Uses the same CalcMWEBWeight / EstimateMWEBTxSize formulas as CreateTransaction
 * so the displayed fee is not underestimated when MWEB inputs or payees are
 * selected. When payees are empty but MWEB inputs are selected, assumes a
 * MWEB_TO_MWEB (or PEGIN if L1 inputs are also selected) placeholder with
 * change-on-MWEB so weight is not left at zero.
 */
struct CoinControlFeeParams {
    uint64_t mweb_weight{0};
    int32_t l1_vsize{0};
    bool uses_mweb{false};
};

CoinControlFeeParams EstimateCoinControlFeeParams(
    bool has_l1_inputs,
    bool has_mweb_inputs,
    const std::vector<wallet::CRecipient>& recipients,
    const CTxDestination& dest_change,
    int32_t signed_l1_vsize);

/** Result of MWEB coin selection. */
struct SelectionResult {
    std::set<wallet::CInputCoin> coins;
    CAmount total{0};
    bool changeless{false}; //!< Total landed in the changeless window
};

/** MWEB coin selection (doc/mweb/descriptors.md "Selection algorithm").
 *
 * Coins from non-active accounts drain first; within each tier coins
 * accumulate smallest-first until targets.no_change is reached (capped at
 * mw::MAX_NUM_INPUTS). When allow_changeless is set and the total is at
 * most targets.with_change, the result is flagged changeless. Callers that
 * must force the with-change path pass allow_changeless=false (and may pass
 * equal targets). When allow_partial is set and the target cannot be reached
 * (insufficient coins or the input cap), the best capped selection is
 * returned instead of nullopt so the caller can fund the remainder
 * elsewhere (mixed MWEB+L1 funding). */
std::optional<SelectionResult> SelectMWEBCoins(
    const wallet::CWallet& wallet,
    const SelectionTargets& targets,
    bool allow_changeless,
    bool allow_partial,
    int min_depth,
    int max_depth,
    bool include_unsafe) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** As above; without require_spend_material, coins of watch-only or locked accounts are candidates too
 * (for unsigned PSBTs). Coins in exclude are never selected. */
std::optional<SelectionResult> SelectMWEBCoins(
    const wallet::CWallet& wallet,
    const SelectionTargets& targets,
    bool allow_changeless,
    bool allow_partial,
    int min_depth,
    int max_depth,
    bool include_unsafe,
    bool require_spend_material,
    const std::set<mw::Hash>& exclude = {}) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** MWEB balance split into selectable / locked / watch-only
 * (doc/mweb/descriptors.md "Spendable set"). */
struct Balances {
    CAmount selectable{0};
    CAmount locked{0};     //!< Spend keys exist but are encrypted (wallet locked)
    CAmount watch_only{0}; //!< No account in this wallet can ever spend these
};

Balances GetBalances(
    const wallet::CWallet& wallet,
    int min_depth,
    int max_depth,
    bool include_unsafe) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Mutable MWEB funding state threaded through CreateTransactionInternal. */
struct FundingState {
    std::set<wallet::CInputCoin> mweb_selected;
    bool funded_with_mweb{false};
    /** MWEB coins selected but L1 peg-in still required (uncommon mixed path). */
    bool mixed_pegin{false};
    CAmount mweb_fee_budget{0};
    bool mweb_changeless{false};
    bool allow_mweb_changeless{false};
    /** When mixed_pegin: L1 SelectCoins target for the peg-in remainder. */
    CAmount l1_pegin_target{0};
};

/** Gate MWEB destinations before building: the wallet needs an MWEB keychain. */
util::Result<void> CheckRecipientPreconditions(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    bool sign) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/**
 * Coin-control MWEB picks + auto MWEB_TO_MWEB when sending to MWEB
 * (before L1 SelectCoins). Sets funded_with_mweb / fee budget / changeless.
 * When ENABLE_MWEB_UNCOMMON_SENDS, may set mixed_pegin (partial MWEB + L1 peg-in).
 * m_mweb_peg_in never funds from MWEB; m_mweb_peg_out funds from MWEB only, or fails.
 * Pre-selected MWEB output_ids that are missing or unspendable fail closed
 * (parity with L1 "Unable to find UTXO for external input").
 */
util::Result<void> TryEarlyFunding(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    FundingState& state) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** As above; without require_spend_material, coins lacking spend material can fund an unsigned PSBT. */
util::Result<void> TryEarlyFunding(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    FundingState& state,
    bool require_spend_material) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Extra L1 selection_target when pegging in (0 otherwise). */
CAmount PegInTargetBump(
    bool funded_with_mweb,
    bool sending_to_mweb,
    const CFeeRate& effective_feerate,
    const std::vector<wallet::CRecipient>& recipients);

/** As above, with the change pegged out to pegout_change_script when it is not empty. */
CAmount PegInTargetBump(
    bool funded_with_mweb,
    bool sending_to_mweb,
    const CFeeRate& effective_feerate,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script);

/** After L1 SelectCoins fails: full MWEB peg-out, or partial for mixed funding. */
struct PegoutFallback {
    enum class Kind { None, FullMWEB, PartialForMixed };
    Kind kind{Kind::None};
    std::set<wallet::CInputCoin> mweb_selected;
    bool mweb_changeless{false};
    CAmount l1_target{0}; //!< For PartialForMixed: remainder for L1 SelectCoins
};

PegoutFallback TryPegoutFallback(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    bool allow_mweb_changeless) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** As above; without require_spend_material, coins lacking spend material can fund an unsigned PSBT. */
PegoutFallback TryPegoutFallback(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    bool allow_mweb_changeless,
    bool require_spend_material) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/**
 * When funds are short: prefer locked / watch-only MWEB error strings over
 * generic insufficient funds when those balances would cover the shortfall.
 */
util::Result<void> DiagnoseFundingShortfall(
    const wallet::CWallet& wallet,
    const wallet::CCoinControl& coin_control,
    CAmount recipients_sum,
    CAmount l1_available) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** As above; without require_spend_material every MWEB coin was already selectable, so the
 * shortfall is plain insufficient funds. */
util::Result<void> DiagnoseFundingShortfall(
    const wallet::CWallet& wallet,
    const wallet::CCoinControl& coin_control,
    CAmount recipients_sum,
    CAmount l1_available,
    bool require_spend_material) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Inputs for MWEB fee-convergence / AddMWEBTx loop. */
struct FeeConvergenceInput {
    CMutableTransaction tx_before_mweb;
    std::vector<wallet::CRecipient> recipients;
    wallet::CCoinControl coin_control;
    CFeeRate effective_feerate;
    //! Signed size of the transparent skeleton, before MWEB adjustments.
    int32_t signed_l1_vsize{0};
    CAmount recipients_sum{0};
    CAmount bump_fees{0};
    bool sign{true};
    bool funded_with_mweb{false};
    TxType mweb_type{TxType::BTC_TO_BTC};
    bool change_on_mweb{false};
    //! When not empty, MWEB-side change is pegged out to this script.
    CScript pegout_change_script;
    //! Peg-out change below this amount is added to the kernel fee.
    CAmount min_pegout_change{0};
    bool mweb_changeless{false};
    CAmount mweb_fee_budget{0};
    uint64_t mweb_weight{0};
    CAmount fee_needed{0};
    CAmount selected_input_value{0};
    std::set<wallet::CInputCoin> mweb_selected;
    std::set<wallet::CInputCoin> all_selected;
    int change_position{-1};
};

struct FeeConvergenceOutput {
    CMutableTransaction tx;
    CAmount fee_needed{0};
    std::set<wallet::CInputCoin> mweb_selected;
    CAmount selected_input_value{0};
    bool change_on_mweb{false};
    bool mweb_changeless{false};
    CAmount mweb_fee_budget{0};
    uint64_t mweb_weight{0};
};

/**
 * Build extension tx with fee convergence (Litecoin TxAssembler semantics).
 * Host supplies L1 skeleton in tx_before_mweb; returns filled tx + fee.
 */
util::Result<FeeConvergenceOutput> ConvergeAndBuild(
    wallet::CWallet& wallet,
    FeeConvergenceInput in) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_SPEND_H
