#include <mweb/mweb_node.h>

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <logging.h>
#include <mw/consensus/amount.h>
#include <mw/node/block_validator.h>
#include <mw/models/tx/utxo.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <undo.h>
#include <util/moneystr.h>

#include <set>

using namespace MWEB;

bool Node::AllowInputMetadataMismatch(const CBlock& block, const Consensus::Params& consensus_params)
{
    return !consensus_params.mweb_input_metadata_grandfather_blockhash.IsNull()
        && block.GetHash() == consensus_params.mweb_input_metadata_grandfather_blockhash;
}

bool Node::CheckInputMetadataBinding(
    const CBlock& block,
    const mw::ICoinsView* utxo_view,
    bool allow_historical_metadata_mismatch)
{
    if (block.mweb_block.IsNull() || utxo_view == nullptr) {
        return true;
    }
    for (const auto& input : block.mweb_block.m_block->GetInputs()) {
        if (UTXO::CPtr pUTXO = utxo_view->GetUTXO(input.GetOutputID())) {
            if (pUTXO->GetReceiverPubKey() != input.GetOutputPubKey()
                && !allow_historical_metadata_mismatch) {
                return false;
            }
        }
    }
    return true;
}

void Node::ApplyBlockIndexMetadata(CBlockIndex& pindex, const CBlock& block, std::set<CBlockIndex*>& dirty)
{
    if (block.mweb_block.IsNull()) return;
    const CTransactionRef pHogEx = block.GetHogEx();
    if (!pHogEx) return;
    if ((pindex.nStatus & BLOCK_HAVE_MWEB) != 0) return;
    pindex.nStatus |= BLOCK_HAVE_MWEB;
    pindex.mweb_header = block.mweb_block.GetMWEBHeader();
    pindex.hogex_hash = pHogEx->GetHash();
    pindex.mweb_amount = pHogEx->vout.front().nValue;
    dirty.insert(&pindex);
}

bool Node::DisconnectExtension(const CBlockUndo& blockundo, CCoinsViewCache& view)
{
    if (blockundo.mwundo == nullptr) {
        return true;
    }
    auto mweb_view = view.GetMWEBCacheView();
    if (!mweb_view) {
        // Permanent fail-closed check: views built over a bare CCoinsViewDB
        // (fuzz/tests) legitimately lack an MWEB layer. Never undo partially.
        LogError("DisconnectBlock(): MWEB undo required but MWEB cache view is missing");
        return false;
    }
    try {
        mweb_view->UndoBlock(blockundo.mwundo);
    } catch (const std::exception& e) {
        LogError("DisconnectBlock(): Failed to disconnect MWEB block: %s", e.what());
        return false;
    }
    return true;
}

bool Node::IsPunishableCompactBlockReject(const BlockValidationState& state)
{
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) return false;
    const std::string& reason = state.GetRejectReason();
    return reason == "bad-blk-mweb" ||
           reason == "bad-mweb-empty-pegout" ||
           reason == "bad-mweb-empty-extradata";
}

bool Node::CheckBlock(const CBlock& block, BlockValidationState& state)
{
    for (const CTransactionRef& pTx : block.vtx) {
        // HadAttachedMWEB covers non-finalizable payloads that Finalized() dropped
        // (e.g. feature-0 inputs). Litecoin D keeps the decoded pointer and rejects
        // the same encoding as unexpected-mweb-data.
        if (pTx->HasMWEBTx() || pTx->HadAttachedMWEB()) {
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-mweb-data", "Block contains transactions with MWEB data attached");
        }
    }

    return true;
}

bool Node::ContextualCheckBlock(
    const CBlock& block,
    const Consensus::Params& consensus_params,
    const CBlockIndex* pindexPrev,
    BlockValidationState& state,
    bool mweb_active,
    bool mweb_active_at_prev,
    const mw::ICoinsView* utxo_view)
{
    if (!mweb_active) {
        if (!block.mweb_block.IsNull()) {
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-mweb-data", "MWEB not activated, but extension block found");
        }

        for (const CTransactionRef& pTx : block.vtx) {
            if (pTx->IsHogEx()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-mweb-data", "MWEB not activated, but HogEx marker found");
            }
        }

        return true;
    }

    if (block.mweb_block.IsNull()) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "mweb-missing", "MWEB activated but extension block not found");
    }

    // The HogEx marker is not committed by the block hash, so its placement is
    // checked (as BLOCK_MUTATED) before any rule that depends on it can
    // permanently invalidate the block.
    const CTransactionRef& pHogEx = block.vtx.back();
    if (!pHogEx->IsHogEx()) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "hogex-missing", "hogex missing");
    }

    for (size_t i = 0; i < block.vtx.size() - 1; i++) {
        if (block.vtx[i]->IsHogEx()) {
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-hogex-position", "hogex in wrong position");
        }
    }

    for (const auto& tx : block.vtx) {
        if (tx->IsCoinBase() || tx->IsHogEx()) {
            for (const CTxOut& out : tx->vout) {
                if (out.scriptPubKey.IsMWEBPegin()) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-unexpected-pegin", "Pegin found in coinbase or HogEx");
                }
            }
        }
    }

    assert(!pHogEx->vout.empty());

    mw::Hash mweb_hash;
    if (!pHogEx->vout.front().scriptPubKey.IsMWEBHogAddr(&mweb_hash)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-hogex", "HogEx missing or invalid");
    }

    if (mweb_hash != block.mweb_block.m_block->GetHash()) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "mweb-hash-mismatch", "MWEB header hash doesn't match hogex hash");
    }

    if (block.mweb_block.GetHeight() != (pindexPrev->nHeight + 1)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "mweb-height-mismatch", "Invalid MWEB block height");
    }

    // Kernel data is not directly committed by the block hash, so authenticate
    // it against the HogEx-committed MWEB header before using feature bits.
    if (!block.mweb_block.m_block->HasValidKernelMMR()) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-blk-mweb", "MWEB kernel root doesn't match body");
    }

    // Empty feature fields can have alternate wire encodings that reserialize
    // to the same kernel MMR leaf, so these failures must not permanently
    // invalidate the block hash: report them as BLOCK_MUTATED.
    if (pindexPrev->nHeight + 1 >= consensus_params.mweb_pegout_feature_activation_height) {
        for (const Kernel& kernel : block.mweb_block.m_block->GetKernels()) {
            if (!kernel.HasCanonicalPegOutFeature()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-mweb-empty-pegout", "Pegout feature set without pegouts");
            }
        }
    }

    if (pindexPrev->nHeight + 1 >= consensus_params.mweb_extradata_feature_activation_height) {
        for (const Kernel& kernel : block.mweb_block.m_block->GetKernels()) {
            if (!kernel.HasCanonicalExtraDataFeature()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-mweb-empty-extradata", "Extra data feature set without extra data");
            }
        }
    }

    const bool is_first_hogex = !mweb_active_at_prev;
    size_t next_pegin_idx = is_first_hogex ? 0 : 1;

    for (size_t nTx = 1; nTx < block.vtx.size() - 1; nTx++) {
        const CTransactionRef& pTx = block.vtx[nTx];
        for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
            const CTxOut& output = pTx->vout[nOut];
            if (output.scriptPubKey.IsMWEBPegin()) {
                if (pHogEx->vin.size() <= next_pegin_idx) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pegins-missing", "Pegins missing from HogEx");
                }

                const COutPoint& hogex_input = pHogEx->vin[next_pegin_idx++].prevout;
                if (hogex_input.n != nOut || hogex_input.hash != pTx->GetHash()) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pegin-mismatch", "HogEx pegins do not match block's pegins");
                }
            }
        }
    }

    if (next_pegin_idx != pHogEx->vin.size()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "extra-hogex-input", "HogEx contains unexpected input(s)");
    }

    if (!Node::ValidateMWEBBlock(block, utxo_view, consensus_params)) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-blk-mweb", "BlockValidator::ValidateBlock failed");
    }

    return true;
}

bool Node::ValidateMWEBBlock(const CBlock& block, const mw::ICoinsView* utxo_view, const Consensus::Params& consensus_params)
{
    if (!block.mweb_block.IsNull()) {
        for (const auto& input : block.mweb_block.m_block->GetInputs()) {
            for (const uint256& frozen_output_id : consensus_params.frozen_mweb_output_ids) {
                if (uint256(input.GetOutputID().vec()) == frozen_output_id) {
                    return false;
                }
            }
        }

        const bool allow_historical_metadata_mismatch = AllowInputMetadataMismatch(block, consensus_params);
        if (!CheckInputMetadataBinding(block, utxo_view, allow_historical_metadata_mismatch)) {
            return false;
        }
    }

    const CTransactionRef& pHogEx = block.vtx.back();

    std::vector<PegInCoin> block_pegins;
    for (size_t i = 1; i < block.vtx.size() - 1; i++) {
        for (const CTxOut& out : block.vtx[i]->vout) {
            mw::Hash kernel_id;
            if (out.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                block_pegins.emplace_back(out.nValue, std::move(kernel_id));
            }
        }
    }

    std::vector<PegOutCoin> hogex_pegouts;
    for (size_t i = 1; i < pHogEx->vout.size(); i++) {
        const CTxOut& out = pHogEx->vout[i];
        hogex_pegouts.push_back(PegOutCoin(out.nValue, {out.scriptPubKey.begin(), out.scriptPubKey.end()}));
    }

    return BlockValidator::ValidateBlock(
        block.mweb_block.m_block,
        block_pegins,
        hogex_pegouts,
        consensus_params.mweb_kernel_lock_height_grandfather);
}

bool Node::ConnectBlock(
    const CBlock& block,
    const Consensus::Params& consensus_params,
    const CBlockIndex* pindexPrev,
    CBlockUndo& blockundo,
    mw::CoinsViewCache& mweb_view,
    BlockValidationState& state,
    bool mweb_active_at_prev)
{
    if (!block.mweb_block.IsNull()) {
        const CTransactionRef& pHogEx = block.vtx.back();

        const bool is_first_hogex = !mweb_active_at_prev;
        if (!is_first_hogex) {
            const COutPoint& prev_hogex_out = pHogEx->vin.front().prevout;
            if (prev_hogex_out.n != 0 || pindexPrev->hogex_hash != prev_hogex_out.hash) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "invalid-hogex-input", "First input of HogEx does not point to previous HogEx");
            }
        }

        CAmount hogex_input_amount = pindexPrev->mweb_amount;
        for (size_t nTx = 1; nTx < block.vtx.size() - 1; nTx++) {
            const CTransactionRef& pTx = block.vtx[nTx];
            for (const CTxOut& output : pTx->vout) {
                if (output.scriptPubKey.IsMWEBPegin()) {
                    hogex_input_amount += output.nValue;
                    if (!MoneyRange(hogex_input_amount)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "accumulated-pegin-outofrange", "Accumulated pegin amount for the block is out of range");
                    }
                }
            }
        }

        const auto mweb_fee = block.mweb_block.GetTotalFee();
        const auto supply_change = block.mweb_block.GetSupplyChange();
        if (!mweb_fee || !supply_change) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-mweb-amount", "Invalid MWEB amount accounting");
        }

        CAmount hogex_fee = hogex_input_amount - pHogEx->GetValueOut();
        if (!MoneyRange(hogex_fee) || hogex_fee != *mweb_fee) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-mweb-fee-mismatch", "HogEx fee does not match MWEB fee.");
        }

        const auto mweb_amount = AmountUtil::TrySafeAdd(pindexPrev->mweb_amount, *supply_change);
        if (!mweb_amount) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-mweb-amount", "Invalid MWEB supply change");
        }

        if (!MoneyRange(*mweb_amount) || *mweb_amount != pHogEx->vout.front().nValue) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "mweb-amount-mismatch", "HogEx amount does not match expected MWEB amount");
        }

        const bool allow_historical_metadata_mismatch = AllowInputMetadataMismatch(block, consensus_params);

        try {
            blockundo.mwundo = mweb_view.ApplyBlock(block.mweb_block.m_block, allow_historical_metadata_mismatch);
        } catch (const std::exception& e) {
            // Re-classify metadata binding failures as BLOCK_MUTATED, but only when
            // the grandfather exception does not apply (same rule as ApplyBlockChanges).
            if (!CheckInputMetadataBinding(block, &mweb_view, allow_historical_metadata_mismatch)) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-blk-mweb", "BlockValidator::ValidateBlock failed");
            }
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "mweb-connect-failed", strprintf("MWEB::Node::ConnectBlock(): Failed to connect MWEB block: %s", e.what()));
        }

        for (const auto& input : block.mweb_block.m_block->GetInputs()) {
            for (const uint256& frozen_output_id : consensus_params.frozen_mweb_output_ids) {
                if (uint256(input.GetOutputID().vec()) == frozen_output_id) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "frozen-mweb-output-spent",
                        strprintf("MWEB::Node::ConnectBlock(): Frozen MWEB output spent: %s", input.GetOutputID().ToHex()));
                }
            }
        }
    }

    return true;
}

bool Node::CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    std::unordered_map<mw::Hash, CAmount> tx_pegins;
    for (const CTxOut& out : tx.vout) {
        mw::Hash kernel_id;
        if (out.scriptPubKey.IsMWEBPegin(&kernel_id)) {
            if (tx_pegins.contains(kernel_id)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "duplicate-tx-pegins");
            }
            tx_pegins.insert({std::move(kernel_id), out.nValue});
        }
    }

    auto pegin_coins = tx.mweb_tx.GetPegIns();
    // Peg-in scriptPubKeys must be matched by MWEB peg-in kernels (and vice versa).
    // Skipping when pegin_coins is empty would allow a standard v9 peg-in with no
    // mweb_tx into the mempool, which poisons every block template (HogEx cannot
    // consume it). Match Litecoin: always compare counts and amounts.
    if (pegin_coins.size() != tx_pegins.size()) {
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "pegin-count-mismatch");
    }

    for (const auto& pegin : pegin_coins) {
        auto iter = tx_pegins.find(pegin.GetKernelID());
        if (iter == tx_pegins.end() || pegin.GetAmount() != iter->second) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "pegin-mismatch");
        }
    }

    if (tx.HasMWEBTx()) {
        try {
            tx.mweb_tx.m_transaction->ValidateStructure();
        } catch (const std::exception&) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn");
        }
    }

    return true;
}

bool Node::VerifyTransactionCrypto(const CTransaction& tx, TxValidationState& state)
{
    if (!tx.HasMWEBTx()) {
        return true;
    }

    try {
        tx.mweb_tx.m_transaction->VerifyCrypto();
    } catch (const std::exception&) {
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn");
    }

    return true;
}

bool Node::VerifyChainstateRoots(const mw::Header& header, const mw::ICoinsView& view)
{
    const IMMR::Ptr output_mmr = view.GetOutputPMMR();
    const ILeafSet::Ptr leaf_set = view.GetLeafSet();
    if (!output_mmr || !leaf_set) {
        return false;
    }

    return header.GetOutputRoot() == output_mmr->Root()
        && header.GetNumTXOs() == output_mmr->GetNumLeaves()
        && header.GetLeafsetRoot() == leaf_set->Root();
}
