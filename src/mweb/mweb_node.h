// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_NODE_H
#define BITCOIN_MWEB_MWEB_NODE_H

#include <consensus/params.h>
#include <kernel/cs_main.h>
#include <mw/node/coins_view.h>
#include <threadsafety.h>

#include <set>

class CBlock;
class CBlockUndo;
class CBlockIndex;
class CCoinsViewCache;
class CTransaction;
class BlockValidationState;
class TxValidationState;

namespace MWEB {

class Node
{
public:
    static bool CheckBlock(const CBlock& block, BlockValidationState& state);

    static bool ContextualCheckBlock(
        const CBlock& block,
        const Consensus::Params& consensus_params,
        const CBlockIndex* pindexPrev,
        BlockValidationState& state,
        bool mweb_active,
        bool mweb_active_at_prev,
        const mw::ICoinsView* utxo_view = nullptr);

    static bool ConnectBlock(
        const CBlock& block,
        const Consensus::Params& consensus_params,
        const CBlockIndex* pindexPrev,
        CBlockUndo& blockundo,
        mw::CoinsViewCache& mweb_view,
        BlockValidationState& state,
        bool mweb_active_at_prev);

    //! Cheap mempool PreChecks helper: peg-in alignment + MWEB structural checks
    //! (weight/sort/duplicates). Does NOT run Schnorr/Bulletproof/kernel-sum crypto.
    static bool CheckTransaction(const CTransaction& tx, TxValidationState& state);

    //! Expensive MWEB cryptography (Schnorr, Bulletproofs, kernel-sum, stealth-sum).
    //! Must run after cheap PreChecks and before mempool admission / test_accept success.
    static bool VerifyTransactionCrypto(const CTransaction& tx, TxValidationState& state);

    //! Verify that the MWEB chainstate PMMR roots match the given header.
    static bool VerifyChainstateRoots(const mw::Header& header, const mw::ICoinsView& view);

    //! True when this block is the single grandfathered historical exception for
    //! spent-UTXO metadata/pubkey binding (Consensus::Params pin).
    static bool AllowInputMetadataMismatch(const CBlock& block, const Consensus::Params& consensus_params);

    //! Defense-in-depth binding of MWEB inputs to UTXO receiver pubkeys.
    //! Honors AllowInputMetadataMismatch so redundant checks cannot hard-reject
    //! a block that ApplyBlockChanges would forgive.
    static bool CheckInputMetadataBinding(
        const CBlock& block,
        const mw::ICoinsView* utxo_view,
        bool allow_historical_metadata_mismatch);

    //! Persist BLOCK_HAVE_MWEB / header / hogex_hash / mweb_amount on successful connect.
    //! No-op when the block has no extension or the index already has MWEB data.
    static void ApplyBlockIndexMetadata(CBlockIndex& pindex, const CBlock& block, std::set<CBlockIndex*>& dirty)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    //! Undo extension-block coins via the existing MWEB cache view (never rewrap).
    //! Returns false if undo was required but the cache view is missing or UndoBlock throws.
    static bool DisconnectExtension(const CBlockUndo& blockundo, CCoinsViewCache& view);

    //! True when a block rejected via a BIP 152 compact block should still get
    //! the peer discouraged. The compact-block exemption assumes the header
    //! commits to everything that was checked; MWEB bodies are not committed
    //! by the header, so a bad body would otherwise be replayable for free.
    static bool IsPunishableCompactBlockReject(const BlockValidationState& state);

private:
    static bool ValidateMWEBBlock(const CBlock& block, const mw::ICoinsView* utxo_view, const Consensus::Params& consensus_params);
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_NODE_H
