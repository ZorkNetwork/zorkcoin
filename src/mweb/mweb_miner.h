// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_MINER_H
#define BITCOIN_MWEB_MWEB_MINER_H

#include <mw/node/block_builder.h>
#include <kernel/mempool_entry.h>

#include <cstddef>
#include <optional>
#include <vector>

class CBlockIndex;
class CBlock;

namespace MWEB {

/**
 * Conservative pad for coinbase + witness commitment in the assembler size
 * estimate. Measured CreateNewBlock coinbases (BIP34 height + OP_0 pad +
 * witness commitment output) are a few hundred bytes; 4 KiB leaves headroom
 * for scriptSig extras and future commitment growth. Prefer over-estimate.
 */
static constexpr size_t BLOCK_SERIALIZED_COINBASE_RESERVE = 4096;

/** When remaining serialized budget is below this, apply aggressive size-skips. */
static constexpr size_t BLOCK_SERIALIZED_SIZE_PRESSURE = 2'000'000;

/** Result of MWEB-specific chunk fit checks (L1 weight/sigops stay on BlockAssembler). */
enum class ChunkFitReject {
    None,
    WeightOrInputs,
    Size,
};

class Miner
{
public:
    void NewBlock(uint64_t nHeight, const mw::ICoinsView::Ptr& coins_view, bool has_prev_hogex);
    bool AddMWEBTransaction(const CTxMemPoolEntry& entry);
    void AddHogExTransaction(const CBlockIndex* pIndexPrev, CBlock* pblock, std::vector<CAmount>& vTxFees, std::vector<int64_t>& vTxSigOpsCost, CAmount& nFees);
    static int64_t GetHogExSigOpCost(const CTransaction& tx);

    /** Staged extension state at one point, so a chunk that fails part-way can be unstaged. */
    struct Checkpoint {
        std::optional<mw::BlockBuilder::Checkpoint> builder;
        CAmount mweb_amount_change;
        CAmount hogex_fees;
        int64_t hogex_sigops;
        size_t num_hogex_inputs;
        size_t num_hogex_outputs;
        size_t mweb_body_bytes;
        size_t mweb_input_count;
    };
    Checkpoint GetCheckpoint() const;
    /** Unstages every MWEB transaction added after the checkpoint was taken. */
    void Restore(const Checkpoint& checkpoint);

    /** Pessimistic estimate of final HogEx + mweb_block wire bytes. */
    size_t EstimateSerializedExtensionBytes() const;

    /** Bytes currently attributed to staged MWEB body components (pessimistic sum). */
    size_t GetStagedMWEBBodyBytes() const { return m_mweb_body_bytes; }
    size_t GetStagedMWEBInputCount() const { return m_mweb_input_count; }

    /** Pessimistic MWEB body serialize size of a single mempool tx (for chunk pre-check). */
    static size_t EstimateTxMWEBBodyBytes(const CTransaction& tx);
    /** Peg-in CTxIn + peg-out CTxOut bytes this tx would add to HogEx. */
    static size_t EstimateTxHogExDeltaBytes(const CTransaction& tx);
    static size_t CountTxMWEBInputs(const CTransaction& tx);
    /** L1 stub size after stripping embedded mweb_tx (0 for MWEB-only). */
    static size_t EstimateTxL1StubBytes(const CTransaction& tx);

    static size_t CountChunkMWEBInputs(const std::vector<CTxMemPoolEntryRef>& txs);
    /** Pessimistic vtx + extension growth for a chunk (L1 stubs + MWEB body + HogEx delta). */
    static uint64_t EstimateChunkSerializedDelta(const std::vector<CTxMemPoolEntryRef>& txs);
    /** Residual-fill order: smallest serialized delta first, then more MWEB inputs first. */
    static bool ResidualFillBefore(const CTxMemPoolEntryRef& a, const CTxMemPoolEntryRef& b);

    /**
     * MWEB fit gates for CreateNewBlock selection (separate from L1 weight/sigops).
     * Uses Litecoin-compatible `>` vs mw::MAX_BLOCK_WEIGHT (equality is allowed).
     */
    ChunkFitReject CheckChunkFit(
        uint64_t nBlockMWEBWeight,
        uint64_t chunk_mweb_weight,
        uint64_t nBlockSerializedSize,
        const std::vector<CTxMemPoolEntryRef>& txs) const;

private:
    bool ValidatePegIns(const CTransactionRef& pTx, const std::vector<PegInCoin>& pegins) const;
    size_t EstimateHogExSerializedBytes() const;
    size_t EstimateMwebBlockSerializedBytes() const;

    mw::BlockBuilder::Ptr mweb_builder;
    CAmount mweb_amount_change{0};
    CAmount hogex_fees{0};
    int64_t hogex_sigops{0};
    std::vector<CTxIn> hogex_inputs;
    std::vector<CTxOut> hogex_outputs;
    bool m_has_prev_hogex{false};
    size_t m_mweb_body_bytes{0};
    size_t m_mweb_input_count{0};
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_MINER_H
