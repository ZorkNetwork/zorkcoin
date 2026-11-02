// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_spend.h>

#include <addresstype.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <mw/consensus/params.h>
#include <mw/models/wallet/coin.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <wallet/scriptpubkeyman.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <utility>
#include <variant>

namespace MWEB {

int32_t EstimateMWEBTxSize(
    TxType mweb_type,
    int32_t signed_l1_vsize,
    const std::set<wallet::CInputCoin>& selected_coins,
    const std::vector<wallet::CRecipient>& recipients)
{
    return EstimateMWEBTxSize(mweb_type, signed_l1_vsize, selected_coins, recipients, CScript{});
}

int32_t EstimateMWEBTxSize(
    TxType mweb_type,
    int32_t signed_l1_vsize,
    const std::set<wallet::CInputCoin>& selected_coins,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script)
{
    // MWEB-only paths have no L1 vin/vout contribution (matches Litecoin
    // CalculateMaximumTxSize and GetTransactionWeight for IsMWEBOnly).
    const bool has_l1_input = std::any_of(selected_coins.begin(), selected_coins.end(),
        [](const wallet::CInputCoin& coin) { return !coin.IsMWEB(); });

    int64_t bytes = 0;
    if (mweb_type != TxType::MWEB_TO_MWEB && (mweb_type != TxType::PEGOUT || has_l1_input)) {
        if (signed_l1_vsize < 0) return -1;
        bytes = signed_l1_vsize;
    }

    // HogEx input for each peg-in (41 bytes).
    if (ContainsPegIn(mweb_type, selected_coins)) {
        bytes += ::GetSerializeSize(CTxIn());
    }

    bytes += CalcPegOutBytes(mweb_type, recipients, pegout_change_script);

    if (bytes > std::numeric_limits<int32_t>::max()) {
        return std::numeric_limits<int32_t>::max();
    }
    return static_cast<int32_t>(bytes);
}

CAmount ComputeKernelFee(
    const CFeeRate& feerate,
    TxType mweb_type,
    uint64_t mweb_weight,
    const std::vector<wallet::CRecipient>& recipients)
{
    return ComputeKernelFee(feerate, mweb_type, mweb_weight, recipients, CScript{});
}

CAmount ComputeKernelFee(
    const CFeeRate& feerate,
    TxType mweb_type,
    uint64_t mweb_weight,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script)
{
    const int64_t pegout_bytes = CalcPegOutBytes(mweb_type, recipients, pegout_change_script);
    return feerate.GetTotalFee(static_cast<int32_t>(pegout_bytes), mweb_weight);
}

CAmount ComputeFeeNeeded(
    const CFeeRate& feerate,
    int32_t l1_vsize,
    uint64_t mweb_weight,
    CAmount bump_fees,
    const CFeeRate& mweb_mempool_min)
{
    const int32_t weight_i{static_cast<int32_t>(std::min(mweb_weight, uint64_t{std::numeric_limits<int32_t>::max()}))};
    return feerate.GetTotalFee(l1_vsize, mweb_weight) + bump_fees + mweb_mempool_min.GetFee(weight_i);
}

int32_t EstimateBuiltTxWeight(const CMutableTransaction& tx)
{
    int64_t weight{0};
    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOutCoins()) {
        const CTxOut pegout_output(pegout.GetAmount(), pegout.GetScriptPubKey());
        weight += static_cast<int64_t>(::GetSerializeSize(pegout_output)) * WITNESS_SCALE_FACTOR;
    }
    if (tx.mweb_tx.IsNull() || !tx.vin.empty() || !tx.vout.empty()) {
        CMutableTransaction base_tx{tx};
        base_tx.mweb_tx.SetNull();
        // Each peg-in is spent by a HogEx input (41 bytes * WITNESS_SCALE_FACTOR).
        weight += GetTransactionWeight(CTransaction{base_tx}) + 164 * static_cast<int64_t>(tx.mweb_tx.GetPegIns().size());
    }
    return static_cast<int32_t>(std::min<int64_t>(weight, std::numeric_limits<int32_t>::max()));
}

CAmount PegInSelectionFee(
    const CFeeRate& feerate,
    const std::vector<wallet::CRecipient>& recipients)
{
    return PegInSelectionFee(feerate, recipients, CScript{});
}

CAmount PegInSelectionFee(
    const CFeeRate& feerate,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script)
{
    // L1 input fees are covered by effective-value coin selection.
    // Budget MWEB-weight fee plus the HogEx input that spends the peg-in output.
    const uint64_t mweb_weight = CalcMWEBWeight(TxType::PEGIN, /*change_on_mweb=*/true, recipients, pegout_change_script);
    const int32_t hogex_vsize = static_cast<int32_t>(::GetSerializeSize(CTxIn()));
    const int64_t pegout_vsize = CalcPegOutBytes(TxType::PEGIN, recipients, pegout_change_script);
    return feerate.GetTotalFee(hogex_vsize + static_cast<int32_t>(pegout_vsize), mweb_weight);
}

SelectionTargets ComputeSelectionTargets(
    const CFeeRate& feerate,
    TxType mweb_type,
    CAmount recipients_sum,
    const std::vector<wallet::CRecipient>& recipients)
{
    return ComputeSelectionTargets(feerate, mweb_type, recipients_sum, recipients, CScript{}, CFeeRate{0});
}

SelectionTargets ComputeSelectionTargets(
    const CFeeRate& feerate,
    TxType mweb_type,
    CAmount recipients_sum,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script,
    const CFeeRate& mweb_mempool_min)
{
    const uint64_t weight_nc = CalcMWEBWeight(mweb_type, /*change_on_mweb=*/false, recipients);
    const uint64_t weight_c = CalcMWEBWeight(mweb_type, /*change_on_mweb=*/true, recipients, pegout_change_script);
    const auto mweb_min_fee = [&](uint64_t weight) {
        return mweb_mempool_min.GetFee(static_cast<int32_t>(std::min(weight, uint64_t{std::numeric_limits<int32_t>::max()})));
    };
    return SelectionTargets{
        recipients_sum + ComputeKernelFee(feerate, mweb_type, weight_nc, recipients) + mweb_min_fee(weight_nc),
        recipients_sum + ComputeKernelFee(feerate, mweb_type, weight_c, recipients, pegout_change_script) + mweb_min_fee(weight_c),
    };
}

CoinControlFeeParams EstimateCoinControlFeeParams(
    bool has_l1_inputs,
    bool has_mweb_inputs,
    const std::vector<wallet::CRecipient>& recipients,
    const CTxDestination& dest_change,
    int32_t signed_l1_vsize)
{
    CoinControlFeeParams out;
    if (!has_mweb_inputs && recipients.empty()) {
        out.l1_vsize = signed_l1_vsize;
        return out;
    }

    std::vector<wallet::CRecipient> effective = recipients;
    if (effective.empty()) {
        // No payees yet (coin-control browser): budget a stealth receive so
        // selected MWEB inputs are not quoted at mweb_weight=0.
        wallet::CRecipient placeholder;
        placeholder.dest = StealthAddress{};
        placeholder.nAmount = 0;
        placeholder.fSubtractFeeFromAmount = false;
        effective.push_back(std::move(placeholder));
    }

    // Minimal selected set — GetTxType / EstimateMWEBTxSize only need IsMWEB().
    std::set<wallet::CInputCoin> selected;
    if (has_mweb_inputs) {
        selected.insert(wallet::CInputCoin(mw::Coin{}));
    }
    if (has_l1_inputs) {
        CMutableTransaction mtx;
        mtx.vout.resize(1);
        selected.insert(wallet::CInputCoin(MakeTransactionRef(std::move(mtx)), 0));
    }

    // Pure L1 payees with no MWEB inputs → BTC_TO_BTC (no MWEB weight).
    if (!has_mweb_inputs && !std::holds_alternative<StealthAddress>(effective.front().dest)) {
        out.l1_vsize = signed_l1_vsize;
        return out;
    }

    const TxType mweb_type = GetTxType(effective, selected);
    const CScript pegout_change_script = GetPegoutChangeScript(dest_change);

    out.uses_mweb = mweb_type != TxType::BTC_TO_BTC;
    out.mweb_weight = out.uses_mweb ? CalcMWEBWeight(mweb_type, /*change_on_mweb=*/true, effective, pegout_change_script) : 0;
    out.l1_vsize = EstimateMWEBTxSize(mweb_type, signed_l1_vsize, selected, effective, pegout_change_script);
    return out;
}

std::optional<SelectionResult> SelectMWEBCoins(
    const wallet::CWallet& wallet,
    const SelectionTargets& targets,
    bool allow_changeless,
    bool allow_partial,
    int min_depth,
    int max_depth,
    bool include_unsafe)
{
    return SelectMWEBCoins(wallet, targets, allow_changeless, allow_partial, min_depth, max_depth, include_unsafe, /*require_spend_material=*/true);
}

std::optional<SelectionResult> SelectMWEBCoins(
    const wallet::CWallet& wallet,
    const SelectionTargets& targets,
    bool allow_changeless,
    bool allow_partial,
    int min_depth,
    int max_depth,
    bool include_unsafe,
    bool require_spend_material,
    const std::set<mw::Hash>& exclude)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<wallet::CWallet::MWEBUnspentEntry> entries = wallet.ListMWEBUnspent(
        min_depth, max_depth, include_unsafe, nullptr, 1, MAX_MONEY);

    // Candidate pool per doc/mweb/descriptors.md: non-active accounts drain
    // first; within each tier, smallest coins first (inputs carry no MWEB
    // weight, so consuming many small coins is free and prunes the leafset).
    const wallet::DescriptorScriptPubKeyMan* active_spk = wallet.GetExternalMWEBScriptPubKeyMan();
    std::vector<std::pair<bool, mw::Coin>> candidates; // {is_active_account, coin}
    candidates.reserve(entries.size());
    for (const auto& entry : entries) {
        if (wallet.IsLockedCoin(entry.output_id) || exclude.contains(entry.output_id)) {
            continue;
        }
        mw::Coin coin;
        if (!wallet.GetCoin(entry.output_id, coin)) {
            continue;
        }
        // Skip coins that cannot be spent yet (locked wallet or incomplete material).
        if (require_spend_material && !coin.HasSpendMaterial()) {
            continue;
        }
        const bool is_active = active_spk && wallet.GetMWEBAccountForCoin(coin) == active_spk;
        candidates.emplace_back(is_active, std::move(coin));
    }
    std::stable_sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return !a.first; // non-active tier first
        return a.second.amount < b.second.amount;
    });

    const CAmount target = allow_changeless ? targets.no_change : targets.with_change;
    SelectionResult result;
    for (auto& [is_active, coin] : candidates) {
        if (result.coins.size() >= mw::MAX_NUM_INPUTS) {
            break;
        }
        result.total += coin.amount;
        result.coins.emplace(std::move(coin));
        if (result.total >= target) {
            result.changeless = allow_changeless && result.total <= targets.with_change;
            return result;
        }
    }
    if (allow_partial && !result.coins.empty()) {
        return result;
    }
    return std::nullopt;
}

Balances GetBalances(
    const wallet::CWallet& wallet,
    int min_depth,
    int max_depth,
    bool include_unsafe)
{
    AssertLockHeld(wallet.cs_wallet);
    Balances balances;
    for (const auto& entry : wallet.ListMWEBUnspent(min_depth, max_depth, include_unsafe, nullptr, 0, MAX_MONEY)) {
        mw::Coin coin;
        if (wallet.GetCoin(entry.output_id, coin) && coin.HasSpendMaterial()) {
            balances.selectable += entry.amount;
            continue;
        }
        // Spend material is also absent while an encrypted wallet is locked;
        // classify by whether the owning account holds (possibly encrypted)
        // private keys so locked funds aren't misreported as watch-only.
        const wallet::DescriptorScriptPubKeyMan* spk_man = wallet.GetMWEBAccountForCoin(coin);
        if (spk_man && spk_man->HavePrivateKeys()) {
            balances.locked += entry.amount;
        } else {
            balances.watch_only += entry.amount;
        }
    }
    return balances;
}

util::Result<void> CheckRecipientPreconditions(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    bool sign)
{
    AssertLockHeld(wallet.cs_wallet);
    if (std::any_of(recipients.cbegin(), recipients.cend(), [](const wallet::CRecipient& r) { return r.IsMWEB(); })) {
        if (!wallet.GetMWEBKeychain()) {
            return util::Error{Untranslated("MWEB is not available for this wallet")};
        }
    }
    return {};
}

/**
 * Fee for the transparent bytes a mixed peg-in pays besides its inputs: the transaction header,
 * the peg-in output and the HogEx input that spends it.
 */
static CAmount PegInOverheadFee(const CFeeRate& feerate)
{
    const size_t header_size = 10 + GetSizeOfCompactSize(1);
    const size_t pegin_output_size = ::GetSerializeSize(CTxOut(0, GetScriptForPegin(mw::Hash())));
    return feerate.GetFee(static_cast<int32_t>(header_size + pegin_output_size + ::GetSerializeSize(CTxIn())));
}

util::Result<void> TryEarlyFunding(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    FundingState& state)
{
    return TryEarlyFunding(wallet, recipients, coin_control, effective_feerate, subtract_fee_outputs, recipients_sum,
        sending_to_mweb, state, /*require_spend_material=*/true);
}

util::Result<void> TryEarlyFunding(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    FundingState& state,
    bool require_spend_material)
{
    AssertLockHeld(wallet.cs_wallet);
    state.allow_mweb_changeless = !subtract_fee_outputs
        && std::holds_alternative<CNoDestination>(coin_control.destChange);
    const CScript pegout_change_script = GetPegoutChangeScript(coin_control.destChange);
    const CFeeRate mweb_mempool_min{wallet.chain().mempoolMWEBMinFee()};
    // A peg-in moves L1 coins into MWEB, so it is never funded from MWEB coins.
    if (coin_control.m_mweb_peg_in) {
        if (coin_control.HasMWEBSelected()) {
            return util::Error{_("A peg-in cannot spend MWEB inputs")};
        }
        return {};
    }
    // A peg-out moves MWEB coins to L1, so it is never funded from L1 coins.
    if (coin_control.m_mweb_peg_out && coin_control.HasL1Selected()) {
        return util::Error{_("A peg-out cannot spend L1 inputs")};
    }
    // Spent from MWEB coins alone, any transparent recipient is paid by a peg-out.
    const bool pays_transparent = std::any_of(recipients.begin(), recipients.end(),
        [](const wallet::CRecipient& r) { return !r.IsMWEB(); });
    const TxType mweb_spend_type = pays_transparent ? TxType::PEGOUT : TxType::MWEB_TO_MWEB;

    if (!coin_control.m_mweb_selected.empty()) {
        for (const mw::Hash& output_id : coin_control.m_mweb_selected) {
            if (IsFrozenOutput(output_id)) {
                return util::Error{strprintf(_("MWEB output %s is frozen and cannot be spent"), output_id.ToHex())};
            }
            mw::Coin coin;
            if (!wallet.GetCoin(output_id, coin)) {
                return util::Error{strprintf(_("Unable to find MWEB output %s"), output_id.ToHex())};
            }
            if (require_spend_material && !coin.HasSpendMaterial()) {
                return util::Error{strprintf(_("MWEB output %s is not spendable"), output_id.ToHex())};
            }
            state.mweb_selected.emplace(coin);
        }
        const CAmount mweb_preset_total = std::accumulate(
            state.mweb_selected.begin(), state.mweb_selected.end(), CAmount{0},
            [](CAmount sum, const wallet::CInputCoin& c) { return sum + c.GetAmount(); });
        if (coin_control.HasL1Selected() && !sending_to_mweb) {
            // Transparent recipients from both kinds of presets: the L1 inputs are pegged in
            // and the recipients are paid as peg-outs.
            state.mixed_pegin = true;
            state.funded_with_mweb = false;
            const CAmount target = subtract_fee_outputs
                ? recipients_sum
                : ComputeSelectionTargets(effective_feerate, TxType::PEGOUT, recipients_sum, recipients,
                      pegout_change_script, mweb_mempool_min).with_change + PegInOverheadFee(effective_feerate);
            state.l1_pegin_target = std::max(CAmount{0}, target - mweb_preset_total);
        } else if (coin_control.HasL1Selected()) {
            // Dual L1+MWEB presets toward an MWEB dest (uncommon / privacy-compromising).
            // Never silently drop either side.
#if ENABLE_MWEB_UNCOMMON_SENDS
            state.mixed_pegin = true;
            state.funded_with_mweb = false;
            state.l1_pegin_target = std::max(CAmount{0}, recipients_sum - mweb_preset_total)
                + (subtract_fee_outputs ? 0 : PegInSelectionFee(effective_feerate, recipients, pegout_change_script));
#else
            state.funded_with_mweb = true;
#endif
        } else {
            state.funded_with_mweb = true;
        }
        if (!coin_control.HasL1Selected()) {
            const CAmount preset_total = mweb_preset_total;
            const SelectionTargets targets = ComputeSelectionTargets(effective_feerate,
                mweb_spend_type, recipients_sum, recipients, pegout_change_script, mweb_mempool_min);
            // With SFFO the fee comes out of the recipients, so the target is just their sum.
            const CAmount target = subtract_fee_outputs ? recipients_sum : targets.with_change;
            if (preset_total < target && state.allow_mweb_changeless && preset_total >= targets.no_change) {
                state.mweb_changeless = true;
            } else if (preset_total < target) {
                if (!coin_control.m_allow_other_inputs) {
                    return util::Error{_("Insufficient funds")};
                }
                const CAmount shortfall = target - preset_total;
                auto extra = SelectMWEBCoins(wallet, SelectionTargets{shortfall, shortfall}, /*allow_changeless=*/false,
                    /*allow_partial=*/false, coin_control.m_min_depth, coin_control.m_max_depth,
                    coin_control.m_include_unsafe_inputs, require_spend_material, coin_control.m_mweb_selected);
                if (!extra) {
                    return util::Error{_("Insufficient funds")};
                }
                state.mweb_selected.insert(extra->coins.begin(), extra->coins.end());
            }
        }
    }

    // Everyday path: full MWEB→MWEB only. Do not auto-mix leftover MWEB with a
    // peg-in (that is privacy-compromising); use explicit dual presets instead.
    if (!state.funded_with_mweb && !state.mixed_pegin && !coin_control.HasSelected()) {
        if (sending_to_mweb) {
            const SelectionTargets mweb_targets = ComputeSelectionTargets(
                effective_feerate, mweb_spend_type, recipients_sum, recipients, pegout_change_script, mweb_mempool_min);
            state.mweb_fee_budget = mweb_targets.with_change - recipients_sum;
            // With SFFO the fee comes out of the recipients, so the target is just their sum.
            const SelectionTargets selection_targets = subtract_fee_outputs
                ? SelectionTargets{recipients_sum, recipients_sum}
                : mweb_targets;
            if (auto mweb_selection = SelectMWEBCoins(wallet, selection_targets, state.allow_mweb_changeless,
                    /*allow_partial=*/false,
                    coin_control.m_min_depth, coin_control.m_max_depth, coin_control.m_include_unsafe_inputs, require_spend_material)) {
                state.mweb_selected = std::move(mweb_selection->coins);
                state.mweb_changeless = mweb_selection->changeless;
                state.funded_with_mweb = true;
            }
        }
    }

    if (coin_control.m_mweb_peg_out && !state.funded_with_mweb) {
        if (!sending_to_mweb && coin_control.m_mweb_selected.empty() && coin_control.m_allow_other_inputs) {
            const SelectionTargets pegout_targets = ComputeSelectionTargets(
                effective_feerate, TxType::PEGOUT, recipients_sum, recipients, pegout_change_script, mweb_mempool_min);
            // With SFFO the fee comes out of the recipients, so the target is just their sum.
            const SelectionTargets selection_targets = subtract_fee_outputs
                ? SelectionTargets{recipients_sum, recipients_sum}
                : pegout_targets;
            if (auto mweb_selection = SelectMWEBCoins(wallet, selection_targets, state.allow_mweb_changeless,
                    /*allow_partial=*/false,
                    coin_control.m_min_depth, coin_control.m_max_depth, coin_control.m_include_unsafe_inputs, require_spend_material)) {
                state.mweb_selected = std::move(mweb_selection->coins);
                state.mweb_changeless = mweb_selection->changeless;
                state.funded_with_mweb = true;
            }
        }
        if (!state.funded_with_mweb) {
            return util::Error{_("Insufficient MWEB funds for a peg-out")};
        }
    }
    return {};
}

CAmount PegInTargetBump(
    bool funded_with_mweb,
    bool sending_to_mweb,
    const CFeeRate& effective_feerate,
    const std::vector<wallet::CRecipient>& recipients)
{
    return PegInTargetBump(funded_with_mweb, sending_to_mweb, effective_feerate, recipients, CScript{});
}

CAmount PegInTargetBump(
    bool funded_with_mweb,
    bool sending_to_mweb,
    const CFeeRate& effective_feerate,
    const std::vector<wallet::CRecipient>& recipients,
    const CScript& pegout_change_script)
{
    if (!funded_with_mweb && sending_to_mweb) {
        return PegInSelectionFee(effective_feerate, recipients, pegout_change_script);
    }
    return 0;
}

PegoutFallback TryPegoutFallback(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    bool allow_mweb_changeless)
{
    return TryPegoutFallback(wallet, recipients, coin_control, effective_feerate, subtract_fee_outputs, recipients_sum,
        sending_to_mweb, allow_mweb_changeless, /*require_spend_material=*/true);
}

PegoutFallback TryPegoutFallback(
    const wallet::CWallet& wallet,
    const std::vector<wallet::CRecipient>& recipients,
    const wallet::CCoinControl& coin_control,
    const CFeeRate& effective_feerate,
    bool subtract_fee_outputs,
    CAmount recipients_sum,
    bool sending_to_mweb,
    bool allow_mweb_changeless,
    bool require_spend_material)
{
    AssertLockHeld(wallet.cs_wallet);
    PegoutFallback out;
    if (sending_to_mweb || coin_control.HasSelected()) {
        return out;
    }

    const SelectionTargets pegout_targets = ComputeSelectionTargets(
        effective_feerate, TxType::PEGOUT, recipients_sum, recipients, GetPegoutChangeScript(coin_control.destChange),
        wallet.chain().mempoolMWEBMinFee());
    // With SFFO the fee comes out of the recipients, so the target is just their sum.
    const SelectionTargets mweb_targets = subtract_fee_outputs
        ? SelectionTargets{recipients_sum, recipients_sum}
        : pegout_targets;

    if (auto mweb_selection = SelectMWEBCoins(wallet, mweb_targets, allow_mweb_changeless,
            /*allow_partial=*/false,
            coin_control.m_min_depth, coin_control.m_max_depth, coin_control.m_include_unsafe_inputs, require_spend_material)) {
        out.kind = PegoutFallback::Kind::FullMWEB;
        out.mweb_selected = std::move(mweb_selection->coins);
        out.mweb_changeless = mweb_selection->changeless;
        return out;
    }

    // Mixed funding: spend as much of the MWEB balance as the input cap allows.
    if (auto partial_mweb = SelectMWEBCoins(wallet, mweb_targets,
            /*allow_changeless=*/false, /*allow_partial=*/true,
            coin_control.m_min_depth, coin_control.m_max_depth, coin_control.m_include_unsafe_inputs, require_spend_material)) {
        out.kind = PegoutFallback::Kind::PartialForMixed;
        out.mweb_selected = std::move(partial_mweb->coins);
        out.l1_target = std::max(CAmount{0}, mweb_targets.with_change - partial_mweb->total);
        if (!subtract_fee_outputs) {
            out.l1_target += PegInOverheadFee(effective_feerate);
        }
    }
    return out;
}

util::Result<void> DiagnoseFundingShortfall(
    const wallet::CWallet& wallet,
    const wallet::CCoinControl& coin_control,
    CAmount recipients_sum,
    CAmount l1_available)
{
    return DiagnoseFundingShortfall(wallet, coin_control, recipients_sum, l1_available, /*require_spend_material=*/true);
}

util::Result<void> DiagnoseFundingShortfall(
    const wallet::CWallet& wallet,
    const wallet::CCoinControl& coin_control,
    CAmount recipients_sum,
    CAmount l1_available,
    bool require_spend_material)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!require_spend_material) {
        // Selection already considered every MWEB coin.
        return util::Error{_("Insufficient funds")};
    }
    const Balances mweb_balances = GetBalances(
        wallet, coin_control.m_min_depth, coin_control.m_max_depth, coin_control.m_include_unsafe_inputs);
    const CAmount reachable = l1_available + mweb_balances.selectable;
    if (reachable < recipients_sum) {
        if (mweb_balances.locked > 0 && reachable + mweb_balances.locked >= recipients_sum) {
            return util::Error{_("Error: Please enter the wallet passphrase with walletpassphrase first.")};
        }
        if (mweb_balances.watch_only > 0
            && reachable + mweb_balances.locked + mweb_balances.watch_only >= recipients_sum) {
            return util::Error{_("Insufficient funds: watch-only MWEB outputs would cover this amount but cannot be spent by this wallet")};
        }
    }
    return util::Error{_("Insufficient funds")};
}

util::Result<FeeConvergenceOutput> ConvergeAndBuild(
    wallet::CWallet& wallet,
    FeeConvergenceInput in)
{
    AssertLockHeld(wallet.cs_wallet);

    constexpr int MAX_MWEB_FEE_ITERS = 5;
    bool built = false;
    FeeConvergenceOutput out;
    out.fee_needed = in.fee_needed;
    out.mweb_selected = std::move(in.mweb_selected);
    out.selected_input_value = in.selected_input_value;
    out.change_on_mweb = in.change_on_mweb;
    out.mweb_changeless = in.mweb_changeless;
    out.mweb_fee_budget = in.mweb_fee_budget;
    out.mweb_weight = in.mweb_weight;

    std::set<wallet::CInputCoin> all_selected = std::move(in.all_selected);
    const bool subtract_fee = std::any_of(in.recipients.begin(), in.recipients.end(),
        [](const wallet::CRecipient& r) { return r.fSubtractFeeFromAmount; });
    bool repriced_without_change{false};

    for (int attempt = 0; attempt < MAX_MWEB_FEE_ITERS; ++attempt) {
        // Re-select MWEB inputs when budget grew beyond the prior selection.
        // Retries always take the with-change path.
        if (in.funded_with_mweb && in.mweb_type == TxType::MWEB_TO_MWEB
            && !in.coin_control.HasMWEBSelected() && attempt > 0 && !repriced_without_change) {
            if (out.mweb_changeless) {
                // Transitioning off the changeless path adds a change
                // output; grow the budget by its weight fee so the
                // re-selection target isn't one output fee short.
                out.mweb_changeless = false;
                out.mweb_fee_budget += CFeeRate::GetMWEBFee(mw::STANDARD_OUTPUT_WEIGHT);
                out.change_on_mweb = IsChangeOnMWEB(wallet, in.mweb_type, in.recipients, in.coin_control.destChange);
                out.mweb_weight = CalcMWEBWeight(in.mweb_type, out.change_on_mweb, in.recipients, in.pegout_change_script);
            }
            const CAmount target = in.recipients_sum + out.mweb_fee_budget;
            auto mweb_selection = SelectMWEBCoins(wallet,
                SelectionTargets{target, target}, /*allow_changeless=*/false, /*allow_partial=*/false,
                in.coin_control.m_min_depth, in.coin_control.m_max_depth, in.coin_control.m_include_unsafe_inputs,
                /*require_spend_material=*/in.sign);
            if (!mweb_selection) {
                return util::Error{_("Insufficient funds")};
            }
            out.mweb_selected = std::move(mweb_selection->coins);
            all_selected = out.mweb_selected;
            out.selected_input_value = mweb_selection->total;
        }

        // When the recipients pay the fee and take every input (a sweep), the change is
        // zero and no change output is built, so the fee must not pay for one.
        if (subtract_fee && !repriced_without_change
            && out.change_on_mweb && out.selected_input_value == in.recipients_sum) {
            repriced_without_change = true;
            out.change_on_mweb = false;
            out.mweb_weight = CalcMWEBWeight(in.mweb_type, /*change_on_mweb=*/false, in.recipients);
            const int32_t l1_vsize{EstimateMWEBTxSize(in.mweb_type, in.signed_l1_vsize, all_selected, in.recipients)};
            const CAmount fee_without_change{ComputeFeeNeeded(in.effective_feerate, l1_vsize, out.mweb_weight, in.bump_fees,
                wallet.chain().mempoolMWEBMinFee())};
            out.fee_needed = std::min(out.fee_needed, fee_without_change);
            out.mweb_fee_budget = std::min(out.mweb_fee_budget, fee_without_change);
        }

        InProcessTx iptx;
        iptx.tx = in.tx_before_mweb;
        iptx.recipients = in.recipients;
        iptx.selected_coins = all_selected;
        iptx.change_position = in.change_position;
        iptx.change_on_mweb = out.change_on_mweb;
        iptx.change_addr = in.coin_control.destChange;
        iptx.pegout_change_script = in.pegout_change_script;
        iptx.min_pegout_change = in.min_pegout_change;
        iptx.mweb_type = in.mweb_type;
        iptx.sign = in.sign;
        iptx.total_fee = out.fee_needed;
        // Kernel fee is GetTotalFee(pegout_bytes, weight) — for MWEB_TO_MWEB this is
        // GetMWEBFee only (L1 bytes are 0), matching Litecoin fee semantics.
        iptx.mweb_fee = ComputeKernelFee(in.effective_feerate, in.mweb_type, out.mweb_weight, in.recipients,
            out.change_on_mweb ? in.pegout_change_script : CScript{});
        if (out.mweb_changeless) {
            // Changeless window: the entire excess over the recipients is
            // committed as kernel fee (doc/mweb/descriptors.md).
            iptx.mweb_fee = out.selected_input_value - in.recipients_sum;
            iptx.total_fee = iptx.mweb_fee;
        } else if (in.funded_with_mweb && in.mweb_type == TxType::MWEB_TO_MWEB) {
            iptx.mweb_fee = std::max(iptx.mweb_fee, out.mweb_fee_budget > 0 ? out.mweb_fee_budget : iptx.mweb_fee);
            iptx.mweb_fee = std::max(iptx.mweb_fee, out.fee_needed);
            iptx.total_fee = iptx.mweb_fee;
        }
        // Floor: base MWEB fee + rolling mwebminfee (and any caller-set m_mweb_min_fee).
        const CFeeRate mweb_mempool_min{wallet.chain().mempoolMWEBMinFee()};
        const int32_t weight_i{static_cast<int32_t>(std::min(out.mweb_weight, uint64_t{std::numeric_limits<int32_t>::max()}))};
        const CAmount mweb_floor{CFeeRate::GetMWEBFee(out.mweb_weight) + mweb_mempool_min.GetFee(weight_i)};
        const CAmount min_total{std::max(mweb_floor, in.coin_control.m_mweb_min_fee.value_or(0))};
        if (iptx.total_fee < min_total) {
            const CAmount extra_fee{min_total - iptx.total_fee};
            iptx.total_fee += extra_fee;
            iptx.mweb_fee += extra_fee;
        }

        try {
            Transact(wallet).AddMWEBTx(iptx);
        } catch (const CreateTxError& e) {
            if (e.IsInsufficientFeeBudget() && in.funded_with_mweb
                && in.mweb_type == TxType::MWEB_TO_MWEB && attempt + 1 < MAX_MWEB_FEE_ITERS) {
                // Bump budget and re-select on the next iteration.
                out.mweb_fee_budget = std::max(out.mweb_fee_budget, out.fee_needed) + 1;
                out.fee_needed = out.mweb_fee_budget;
                wallet.WalletLogPrintf("MWEB fee convergence: retry attempt %d budget=%d\n",
                    attempt + 1, out.mweb_fee_budget);
                continue;
            }
            return util::Error{e.GetError()};
        }
        out.tx = std::move(iptx.tx);

        // Package fee = L1 fee (inputs - outputs) + kernel fee. For MWEB-only
        // paths L1 fee is 0 and the kernel carries the full relay fee.
        const int32_t mempool_vsize = GetVirtualTransactionSize(EstimateBuiltTxWeight(out.tx), 0, 0);
        const uint64_t actual_mweb_weight = out.tx.mweb_tx.GetMWEBWeight();
        const CAmount required_fee = ComputeFeeNeeded(
            in.effective_feerate, mempool_vsize, actual_mweb_weight, in.bump_fees,
            wallet.chain().mempoolMWEBMinFee());
        const CAmount kernel_fee = out.tx.mweb_tx.kernels.empty() ? CAmount{0} : out.tx.mweb_tx.kernels.front().fee.value_or(0);
        const CAmount l1_fee = (in.mweb_type == TxType::MWEB_TO_MWEB)
            ? CAmount{0}
            : (iptx.total_fee - iptx.mweb_fee);
        const CAmount package_fee = l1_fee + kernel_fee;
        if (package_fee >= required_fee) {
            out.fee_needed = package_fee;
            built = true;
            break;
        }
        if (!(in.funded_with_mweb && in.mweb_type == TxType::MWEB_TO_MWEB)) {
            // Peg-in/peg-out: L1 selection already ran; surface the shortfall.
            return util::Error{_("Transaction fee and change calculation failed")};
        }
        if (attempt + 1 >= MAX_MWEB_FEE_ITERS) {
            return util::Error{_("Transaction fee and change calculation failed")};
        }
        out.fee_needed = required_fee;
        out.mweb_fee_budget = required_fee;
        wallet.WalletLogPrintf("MWEB fee convergence: package fee %d < required %d, retrying\n",
            package_fee, required_fee);
    }
    if (!built) {
        return util::Error{_("Transaction fee and change calculation failed")};
    }
    return out;
}

} // namespace MWEB
