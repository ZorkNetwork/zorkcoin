#include <mweb/mweb_policy.h>

#include <mw/consensus/params.h>
#include <mw/models/tx/transaction.h>
#include <primitives/transaction.h>
#include <tinyformat.h>

#include <limits>
#include <set>

using namespace MWEB;

// Relay/mempool policy limits for standalone MWEB transactions (non-consensus).
//
// The consensus limits (mw::MAX_BLOCK_WEIGHT / mw::MAX_NUM_INPUTS) permit a
// single transaction to contain an entire block's worth of inputs, outputs, and
// kernels. Because MWEB signature and rangeproof verification runs during
// mempool acceptance before any fee is required, relaying such a transaction
// would let a peer force a full block's worth of crypto verification for free.
// We therefore bound relayed MWEB transactions to ~2% of the consensus limits.
// (Note inputs carry no MWEB weight, so they must be bounded by count.)
static constexpr size_t MAX_STANDARD_MWEB_TX_WEIGHT = mw::MAX_BLOCK_WEIGHT / 50; // 4,000
static constexpr size_t MAX_STANDARD_MWEB_TX_INPUTS = mw::MAX_NUM_INPUTS / 50;   // 1,000

bool Policy::IsStandardTx(const CTransaction& tx, std::string& reason)
{
    // MWEB: To help avoid mempool bugs, we don't yet allow transaction aggregation
    // for transactions with canonical BTC data.
    if (!tx.IsMWEBOnly()) {
        std::set<mw::Hash> pegin_kernels;
        for (const CTxOut& txout : tx.vout) {
            mw::Hash kernel_id;
            if (txout.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                pegin_kernels.insert(std::move(kernel_id));
            }
        }

        // Always require L1 peg-in scripts to match MWEB kernel IDs (including the
        // empty==empty case). Guarding on non-empty sets allowed a peg-in script
        // with no mweb_tx (kernel_ids empty) to pass as standard and enter the
        // mempool, poisoning CreateNewBlock.
        if (pegin_kernels != tx.mweb_tx.GetKernelIDs()) {
            reason = "kernel-mismatch";
            return false;
        }
    }

    // MWEB: Check MWEB transaction for non-standard kernel features
    if (tx.HasMWEBTx() && !tx.mweb_tx.m_transaction->IsStandard()) {
        reason = "non-standard-mweb-tx";
        return false;
    }

    return true;
}

bool Policy::CheckWeight(const CTransaction& tx, std::string& reason)
{
    if (!tx.HasMWEBTx()) {
        return true;
    }

    // HasMWEBTx() guarantees m_transaction is non-null.
    if (tx.mweb_tx.m_transaction->GetInputs().size() > MAX_STANDARD_MWEB_TX_INPUTS) {
        reason = "mweb-txn-too-many-inputs";
        return false;
    }

    if (tx.mweb_tx.m_transaction->CalcWeight() > MAX_STANDARD_MWEB_TX_WEIGHT) {
        reason = "mweb-txn-oversize";
        return false;
    }

    return true;
}

bool Policy::HasUncommittedMWEBPayload(const CTransaction& tx)
{
    // HadAttachedMWEB: non-final attach rejected at mempool; same txid/wtxid as bare L1.
    if (tx.HasMWEBTx() || tx.IsHogEx() || tx.HadAttachedMWEB()) return true;

    for (const CTxOut& txout : tx.vout) {
        if (txout.scriptPubKey.IsMWEBPegin()) return true;
    }

    return false;
}

std::optional<std::string> Policy::CheckReplacementFeeRate(const FeeFrac& replacement,
                                                           bool replacement_has_mweb,
                                                           const FeeFrac& replaced,
                                                           bool replaced_has_mweb,
                                                           const Txid& replaced_txid)
{
    if (!replacement_has_mweb && !replaced_has_mweb) return std::nullopt;

    // replacement.fee / replacement.size >= 1.5 * replaced.fee / replaced.size, compared as
    // 2 * replacement.fee * replaced.size >= 3 * replaced.fee * replacement.size.
    const bool sizes_ok{replacement.size > 0 && replaced.size > 0 &&
                        replaced.size <= std::numeric_limits<int32_t>::max() / 2 &&
                        replacement.size <= std::numeric_limits<int32_t>::max() / 3};
    if (!sizes_ok ||
        FeeFrac::Mul(replacement.fee, 2 * replaced.size) < FeeFrac::Mul(replaced.fee, 3 * replacement.size)) {
        return strprintf("rejecting replacement of %s, an MWEB replacement must pay 1.5x its fee rate; "
                         "fee %d over adjusted weight %d < 1.5x fee %d over adjusted weight %d",
                         replaced_txid.ToString(), replacement.fee, replacement.size, replaced.fee, replaced.size);
    }
    return std::nullopt;
}
