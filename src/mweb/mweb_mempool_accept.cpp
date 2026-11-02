// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_mempool_accept.h>

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <mw/consensus/params.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/transaction.h>
#include <policy/feerate.h>
#include <sync.h>

#include <algorithm>
#include <limits>

using namespace MWEB;

CAmount MempoolAccept::MaxRawTxFee(const CFeeRate& max_feerate, const CFeeRate& default_feerate, int32_t vsize, uint64_t mweb_weight)
{
    constexpr CAmount max_amount{std::numeric_limits<CAmount>::max()};
    const CAmount max_per_k{max_feerate.GetFeePerK()};
    if (max_per_k == 0) return 0;
    const CAmount l1_cap{max_feerate.GetFee(vsize)};
    if (mweb_weight == 0) return l1_cap;

    const CAmount base_fee{CFeeRate::GetMWEBFee(mweb_weight)};
    const CAmount change_fee{CFeeRate::GetMWEBFee(mw::STANDARD_OUTPUT_WEIGHT)};
    CAmount mweb_cap{base_fee > max_amount - change_fee ? max_amount : base_fee + change_fee};
    const CAmount default_per_k{default_feerate.GetFeePerK()};
    if (default_per_k > 0 && max_per_k > default_per_k) {
        mweb_cap = mweb_cap > max_amount / max_per_k ? max_amount : mweb_cap * max_per_k / default_per_k;
    }
    return l1_cap > max_amount - mweb_cap ? max_amount : l1_cap + mweb_cap;
}

bool MempoolAccept::ExceedsClientMaxFeeRate(const CFeeRate& max_feerate, const CFeeRate& default_feerate, CAmount fee, int32_t vsize, uint64_t mweb_weight)
{
    if (mweb_weight == 0) return CFeeRate(fee, vsize) > max_feerate;
    return fee > MaxRawTxFee(max_feerate, default_feerate, vsize, mweb_weight);
}

int64_t MempoolAccept::AdjustedVSize(int64_t vsize, uint64_t mweb_weight, int64_t adjusted_weight)
{
    if (mweb_weight == 0) return vsize;
    return (adjusted_weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

CFeeRate MempoolAccept::EffectiveFeeRate(CAmount fee, int64_t vsize, uint64_t mweb_weight, int64_t adjusted_weight)
{
    constexpr int64_t max_size{std::numeric_limits<int32_t>::max()};
    return CFeeRate(fee, static_cast<int32_t>(std::min(AdjustedVSize(vsize, mweb_weight, adjusted_weight), max_size)));
}

bool MempoolAccept::HaveMWEBInputsAfterReorg(const CTransaction& tx, const CTxMemPool& pool, const CCoinsView& chain)
{
    AssertLockHeld(pool.cs);
    if (!tx.HasMWEBTx()) return true;
    for (const Input& input : tx.mweb_tx.m_transaction->GetInputs()) {
        if (pool.GetMWEBOutputTx(input.GetOutputID())) continue;
        Output coin;
        if (!chain.GetMWEBCoin(input.GetOutputID(), coin)) return false;
    }
    return true;
}

bool MempoolAccept::RejectBeforeActivation(const CTransaction& tx, bool mweb_active, TxValidationState& state)
{
    if (tx.HasMWEBTx() && !mweb_active) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "mweb-before-activation");
    }
    return true;
}

bool MempoolAccept::RejectLooseHogEx(const CTransaction& tx, TxValidationState& state)
{
    if (tx.IsHogEx()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "hogex");
    }
    return true;
}

bool MempoolAccept::RejectNonFinalAttached(const CTransaction& tx, TxValidationState& state)
{
    if (tx.HadAttachedMWEB() && !tx.HasMWEBTx()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-mweb-not-final");
    }
    return true;
}

bool MempoolAccept::LooksAlreadyKnown(
    const CTransaction& tx,
    CCoinsView& view,
    const CCoinsViewCache& tip_cache)
{
    for (const CTxOutput& txout : tx.GetOutputs()) {
        if (!txout.IsMWEB() && tip_cache.HaveCoinInCache(std::get<COutPoint>(txout.GetIndex()))) {
            return true;
        }
        if (txout.IsMWEB()) {
            Output existing;
            if (view.GetMWEBCoin(txout.ToMWEB(), existing)) {
                return true;
            }
        }
    }
    return false;
}

bool MempoolAccept::CheckMWEBInputExists(
    const CTransaction& tx,
    const mw::Hash& output_id,
    CCoinsView& view,
    const CCoinsViewCache& tip_cache,
    TxValidationState& state)
{
    Output mweb_coin;
    if (!view.GetMWEBCoin(output_id, mweb_coin)) {
        if (LooksAlreadyKnown(tx, view, tip_cache)) {
            return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
        }
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    }
    return true;
}
