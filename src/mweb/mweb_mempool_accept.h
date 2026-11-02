// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_MEMPOOL_ACCEPT_H
#define BITCOIN_MWEB_MWEB_MEMPOOL_ACCEPT_H

//! MemPoolAccept::PreChecks MWEB helpers (cheap phase only — no batch crypto).
//! Crypto remains at PolicyScriptChecks via MWEB::Node::VerifyTransactionCrypto.
//! Also the MWEB part of the RPC maxfeerate cap (MaxRawTxFee) and of the effective fee rate.

#include <consensus/amount.h>
#include <mw/models/crypto/hash.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <cstdint>

class CCoinsView;
class CCoinsViewCache;
class CFeeRate;
class TxValidationState;

namespace MWEB {

class MempoolAccept
{
public:
    /** Reject HasMWEBTx before DEPLOYMENT_MWEB (mweb-before-activation). */
    static bool RejectBeforeActivation(const CTransaction& tx, bool mweb_active, TxValidationState& state);

    /** HogEx is only valid in a block. */
    static bool RejectLooseHogEx(const CTransaction& tx, TxValidationState& state);

    /**
     * Attached MWEB that failed Finalized() must not enter the mempool as a
     * stripped L1-only view. Final attached MWEB is handled elsewhere.
     */
    static bool RejectNonFinalAttached(const CTransaction& tx, TxValidationState& state);

    /**
     * MWEB input existence + already-known scan for one MWEB input.
     * On missing input fills state (missing or txn-already-known) and returns false.
     */
    static bool CheckMWEBInputExists(
        const CTransaction& tx,
        const mw::Hash& output_id,
        CCoinsView& view,
        const CCoinsViewCache& tip_cache,
        TxValidationState& state);

    /** Shared already-known probe used when an L1 input is also missing. */
    static bool LooksAlreadyKnown(
        const CTransaction& tx,
        CCoinsView& view,
        const CCoinsViewCache& tip_cache);

    /**
     * After a reorg: whether every MWEB input of a mempool transaction is still created by
     * another mempool transaction (a parent may have returned from a disconnected block) or
     * is unspent in chain.
     */
    static bool HaveMWEBInputsAfterReorg(const CTransaction& tx, const CTxMemPool& pool, const CCoinsView& chain)
        EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

    /** Keep mempool backend attached when extension inputs are present. */
    static bool KeepMempoolBackend(const CTransaction& tx) { return tx.HasMWEBTx(); }

    /**
     * Fee cap for sendrawtransaction and testmempoolaccept. The L1 vsize is capped at
     * max_feerate. The MWEB fee is fixed, so its allowance is the base MWEB fee plus one
     * output's MWEB fee (the most a wallet adds to the fee when it drops change). The
     * allowance grows in proportion when max_feerate is above default_feerate (the RPC
     * default), so a caller can pay more, e.g. to replace a transaction. A zero max_feerate
     * returns 0, which disables the cap.
     */
    static CAmount MaxRawTxFee(const CFeeRate& max_feerate, const CFeeRate& default_feerate, int32_t vsize, uint64_t mweb_weight);

    /**
     * Client maxfeerate check for package submission. Without MWEB weight this is the
     * upstream fee rate comparison; with it, the fee is checked against MaxRawTxFee,
     * because the MWEB fee has no L1 vsize to be rated against.
     */
    static bool ExceedsClientMaxFeeRate(const CFeeRate& max_feerate, const CFeeRate& default_feerate, CAmount fee, int32_t vsize, uint64_t mweb_weight);

    /**
     * Size of a transaction or package for fee rates and TRUC size limits. Without MWEB
     * weight this is the upstream vsize. With it, it is the adjusted weight (sigop-adjusted
     * L1 weight plus MWEB weight, the measure the mempool ranks by) in vbytes, rounded up,
     * because an MWEB-only transaction has no L1 vsize.
     */
    static int64_t AdjustedVSize(int64_t vsize, uint64_t mweb_weight, int64_t adjusted_weight);

    /** Effective fee rate of a transaction or package: fee over AdjustedVSize(). */
    static CFeeRate EffectiveFeeRate(CAmount fee, int64_t vsize, uint64_t mweb_weight, int64_t adjusted_weight);
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_MEMPOOL_ACCEPT_H
