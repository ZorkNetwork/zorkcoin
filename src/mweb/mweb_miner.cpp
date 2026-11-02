#include <mweb/mweb_miner.h>

#include <chain.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <util/log.h>
#include <util/moneystr.h>

#include <boost/functional/hash.hpp>

#include <unordered_set>

using namespace MWEB;

namespace {

//! Max CompactSize width used as a pessimistic pad when vectors grow.
constexpr size_t MAX_COMPACTSIZE_BYTES = 9;

//! Assembler MWEB caps. Production uses consensus maxima. MINE_TEST_MWEB_SIZE
//! raises by one partial (+39 weight) and +1 input so reject functionals can
//! assemble near-max templates that DUT still rejects under stock consensus.
#if defined(MINE_TEST_MWEB_SIZE)
constexpr size_t ASSEMBLER_MWEB_INPUT_CAP = mw::MAX_NUM_INPUTS + 1;
constexpr uint64_t ASSEMBLER_MWEB_WEIGHT_CAP = mw::MAX_BLOCK_WEIGHT + 39;
#else
constexpr size_t ASSEMBLER_MWEB_INPUT_CAP = mw::MAX_NUM_INPUTS;
constexpr uint64_t ASSEMBLER_MWEB_WEIGHT_CAP = mw::MAX_BLOCK_WEIGHT;
#endif



size_t SerializeSizeTxIn(const CTxIn& in)
{
    return ::GetSerializeSize(in);
}

size_t SerializeSizeTxOut(const CTxOut& out)
{
    return ::GetSerializeSize(out);
}

} // namespace

void Miner::NewBlock(const uint64_t nHeight, const mw::ICoinsView::Ptr& coins_view, bool has_prev_hogex)
{
    mweb_builder = std::make_shared<mw::BlockBuilder>(nHeight, coins_view, ASSEMBLER_MWEB_WEIGHT_CAP);
    hogex_fees = 0;
    hogex_sigops = 0;
    mweb_amount_change = 0;
    hogex_inputs.clear();
    hogex_outputs.clear();
    m_has_prev_hogex = has_prev_hogex;
    m_mweb_body_bytes = 0;
    m_mweb_input_count = 0;
}

int64_t Miner::GetHogExSigOpCost(const CTransaction& tx)
{
    int64_t sigops = 0;
    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
        sigops += WITNESS_SCALE_FACTOR * pegout.GetScriptPubKey().GetSigOpCount(false);
    }

    return sigops;
}

Miner::Checkpoint Miner::GetCheckpoint() const
{
    return Checkpoint{
        .builder = mweb_builder ? std::make_optional(mweb_builder->GetCheckpoint()) : std::nullopt,
        .mweb_amount_change = mweb_amount_change,
        .hogex_fees = hogex_fees,
        .hogex_sigops = hogex_sigops,
        .num_hogex_inputs = hogex_inputs.size(),
        .num_hogex_outputs = hogex_outputs.size(),
        .mweb_body_bytes = m_mweb_body_bytes,
        .mweb_input_count = m_mweb_input_count,
    };
}

void Miner::Restore(const Checkpoint& checkpoint)
{
    assert(checkpoint.builder.has_value() == (mweb_builder != nullptr));
    if (mweb_builder) {
        mweb_builder->Rollback(*checkpoint.builder);
    }
    mweb_amount_change = checkpoint.mweb_amount_change;
    hogex_fees = checkpoint.hogex_fees;
    hogex_sigops = checkpoint.hogex_sigops;
    hogex_inputs.resize(checkpoint.num_hogex_inputs);
    hogex_outputs.resize(checkpoint.num_hogex_outputs);
    m_mweb_body_bytes = checkpoint.mweb_body_bytes;
    m_mweb_input_count = checkpoint.mweb_input_count;
}

size_t Miner::EstimateTxMWEBBodyBytes(const CTransaction& tx)
{
    if (!tx.HasMWEBTx() || !tx.mweb_tx.m_transaction) {
        return 0;
    }
    // Pessimistic: per-tx body size overestimates the merged block body
    // CompactSizes (one vector CS per component vs one shared).
    return tx.mweb_tx.m_transaction->GetBody().Serialized().size();
}

size_t Miner::CountTxMWEBInputs(const CTransaction& tx)
{
    if (!tx.HasMWEBTx() || !tx.mweb_tx.m_transaction) {
        return 0;
    }
    return tx.mweb_tx.m_transaction->GetInputs().size();
}

size_t Miner::EstimateTxHogExDeltaBytes(const CTransaction& tx)
{
    if (!tx.HasMWEBTx()) {
        return 0;
    }

    size_t bytes = 0;
    for (size_t nOut = 0; nOut < tx.vout.size(); nOut++) {
        if (IsPegInOutput(tx.GetOutput(nOut))) {
            // CTxIn{txid, nOut} with empty scriptSig / default sequence.
            bytes += SerializeSizeTxIn(CTxIn{tx.GetHash(), static_cast<uint32_t>(nOut)});
            bytes += MAX_COMPACTSIZE_BYTES; // vin CompactSize growth
        }
    }
    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
        bytes += SerializeSizeTxOut(CTxOut{CAmount(pegout.GetAmount()), pegout.GetScriptPubKey()});
        bytes += MAX_COMPACTSIZE_BYTES; // vout CompactSize growth
    }
    return bytes;
}

size_t Miner::EstimateTxL1StubBytes(const CTransaction& tx)
{
    if (tx.IsMWEBOnly()) {
        return 0;
    }
    if (!tx.HasMWEBTx()) {
        return ::GetSerializeSize(TX_WITH_WITNESS(tx));
    }
    CMutableTransaction mutable_tx(tx);
    mutable_tx.ClearAttachedMWEB();
    return ::GetSerializeSize(TX_WITH_WITNESS(CTransaction(std::move(mutable_tx))));
}

size_t Miner::CountChunkMWEBInputs(const std::vector<CTxMemPoolEntryRef>& txs)
{
    size_t n = 0;
    for (const auto& tx : txs) {
        n += CountTxMWEBInputs(tx.get().GetTx());
    }
    return n;
}

uint64_t Miner::EstimateChunkSerializedDelta(const std::vector<CTxMemPoolEntryRef>& txs)
{
    uint64_t delta = 0;
    for (const auto& entry_ref : txs) {
        const CTransaction& tx = entry_ref.get().GetTx();
        const size_t l1_bytes = EstimateTxL1StubBytes(tx);
        if (l1_bytes > 0) {
            delta += l1_bytes + MAX_COMPACTSIZE_BYTES;
        }
        if (tx.HasMWEBTx()) {
            delta += EstimateTxMWEBBodyBytes(tx);
            delta += EstimateTxHogExDeltaBytes(tx);
        }
    }
    return delta;
}

bool Miner::ResidualFillBefore(const CTxMemPoolEntryRef& a, const CTxMemPoolEntryRef& b)
{
    const std::vector<CTxMemPoolEntryRef> ca{a};
    const std::vector<CTxMemPoolEntryRef> cb{b};
    const uint64_t da = EstimateChunkSerializedDelta(ca);
    const uint64_t db = EstimateChunkSerializedDelta(cb);
    if (da != db) return da < db;
    // Spending MWEB inputs shrinks the UTXO set, so equal-size transactions spending more go first.
    return CountChunkMWEBInputs(ca) > CountChunkMWEBInputs(cb);
}

ChunkFitReject Miner::CheckChunkFit(
    uint64_t nBlockMWEBWeight,
    uint64_t chunk_mweb_weight,
    uint64_t nBlockSerializedSize,
    const std::vector<CTxMemPoolEntryRef>& txs) const
{
    // Consensus ExceedsMaximum / BlockBuilder reject only when weight *exceeds* MAX (`>`).
    // Mine-test assembler may allow +ε / +1 input for reject-template construction.
    if (nBlockMWEBWeight + chunk_mweb_weight > ASSEMBLER_MWEB_WEIGHT_CAP) {
        return ChunkFitReject::WeightOrInputs;
    }
    if (m_mweb_input_count + CountChunkMWEBInputs(txs) > ASSEMBLER_MWEB_INPUT_CAP) {
        return ChunkFitReject::WeightOrInputs;
    }

    const uint64_t chunk_ser_delta = EstimateChunkSerializedDelta(txs);
    if (nBlockSerializedSize + chunk_ser_delta > MAX_BLOCK_SERIALIZED_SIZE_MINE) {
        return ChunkFitReject::Size;
    }

    const uint64_t remaining = MAX_BLOCK_SERIALIZED_SIZE_MINE - nBlockSerializedSize;
    if (remaining < BLOCK_SERIALIZED_SIZE_PRESSURE) {
        if (CountChunkMWEBInputs(txs) * mw::INPUT_BYTES > remaining) {
            return ChunkFitReject::Size;
        }
    }
    return ChunkFitReject::None;
}

size_t Miner::EstimateHogExSerializedBytes() const
{
    CMutableTransaction hogExTransaction;
    hogExTransaction.m_hogEx = true;

    if (m_has_prev_hogex) {
        // Dummy prev HogEx input — same serialized size as a real CTxIn.
        hogExTransaction.vin.emplace_back();
    }
    hogExTransaction.vin.insert(hogExTransaction.vin.end(), hogex_inputs.cbegin(), hogex_inputs.cend());

    // HogAddr: OP_8 + 32-byte program
    CTxOut hogAddr;
    hogAddr.scriptPubKey = CScript() << OP_8 << std::vector<unsigned char>(32, 0);
    hogAddr.nValue = 0;
    hogExTransaction.vout.push_back(std::move(hogAddr));
    hogExTransaction.vout.insert(hogExTransaction.vout.end(), hogex_outputs.cbegin(), hogex_outputs.cend());

    // Prefer over-estimate: pad CompactSize vector growth already embedded in
    // the constructed tx; add a small pad for any encoding variance.
    return ::GetSerializeSize(TX_WITH_WITNESS(CTransaction(std::move(hogExTransaction)))) + MAX_COMPACTSIZE_BYTES;
}

size_t Miner::EstimateMwebBlockSerializedBytes() const
{
    // MWEB::Block = WrapOptionalPtr(mw::Block) = present flag + header + body.
    // Header is ~180 bytes; body CompactSizes are overstated by summing per-tx
    // bodies into m_mweb_body_bytes. Pad for optional-ptr + header + CS.
    constexpr size_t MWEB_HEADER_AND_WRAPPER_PAD = 256;
    return MWEB_HEADER_AND_WRAPPER_PAD + m_mweb_body_bytes + 3 * MAX_COMPACTSIZE_BYTES;
}

size_t Miner::EstimateSerializedExtensionBytes() const
{
    return EstimateHogExSerializedBytes() + EstimateMwebBlockSerializedBytes();
}

bool Miner::AddMWEBTransaction(const CTxMemPoolEntry& entry)
{
    CTransactionRef pTx = entry.GetSharedTx();

    //
    // Pegin
    //
    std::vector<CTxIn> vin;
    CAmount pegin_amount = 0;
    std::vector<PegInCoin> pegins = pTx->mweb_tx.GetPegIns();

    if (!ValidatePegIns(pTx, pegins)) {
        LogInfo("Peg-in Mismatch\n");
        return false;
    }

    for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
        if (IsPegInOutput(pTx->GetOutput(nOut))) {
            vin.emplace_back(pTx->GetHash(), static_cast<uint32_t>(nOut));

            assert(MoneyRange(pTx->vout[nOut].nValue));
            pegin_amount += pTx->vout[nOut].nValue;

            if (!MoneyRange(pegin_amount)) {
                LogInfo("Invalid total peg-in amount\n");
                return false;
            }
        }
    }

    //
    // Pegout
    //
    std::vector<CTxOut> vout;
    CAmount pegout_amount = 0;
    std::vector<PegOutCoin> pegouts = pTx->mweb_tx.GetPegOuts();

    for (const PegOutCoin& pegout : pegouts) {
        CAmount amount(pegout.GetAmount());
        assert(MoneyRange(amount));

        vout.emplace_back(amount, pegout.GetScriptPubKey());

        pegout_amount += amount;
        if (!MoneyRange(pegout_amount)) {
            LogInfo("Invalid total peg-out amount\n");
            return false;
        }
    }

    // Validate fee amount range
    const auto tx_fee = pTx->mweb_tx.GetFee();
    if (!tx_fee || !MoneyRange(*tx_fee)) {
        LogInfo("Invalid MWEB fee amount\n");
        return false;
    }

    // Defense-in-depth: consensus forbids > MAX_NUM_INPUTS in the merged body.
    // Primary gate is BlockAssembler::TestChunkBlockLimits; this catches mid-chunk adds.
    // Mine-test may allow MAX_NUM_INPUTS+1 for reject functionals.
    const size_t tx_inputs = CountTxMWEBInputs(*pTx);
    if (m_mweb_input_count + tx_inputs > ASSEMBLER_MWEB_INPUT_CAP) {
        LogInfo("MWEB input count would exceed assembler input cap\n");
        return false;
    }

    //
    // Add transaction to MWEB
    //
    if (!mweb_builder->AddTransaction(pTx->mweb_tx.m_transaction, pegins)) {
        LogInfo("Failed to add MWEB transaction\n");
        return false;
    }

    m_mweb_body_bytes += EstimateTxMWEBBodyBytes(*pTx);
    m_mweb_input_count += tx_inputs;

    hogex_inputs.insert(hogex_inputs.end(), vin.cbegin(), vin.cend());
    hogex_outputs.insert(hogex_outputs.end(), vout.cbegin(), vout.cend());
    mweb_amount_change += (CAmount(pegin_amount) - CAmount(pegout_amount + *tx_fee));

    hogex_fees += *tx_fee;
    hogex_sigops += GetHogExSigOpCost(*pTx);

    return true;
}

namespace std {
template <>
struct hash<PegInCoin> {
    size_t operator()(const PegInCoin& pegin) const
    {
        return boost::hash_value(pegin.GetKernelID().vec()) + boost::hash_value(pegin.GetAmount());
    }
};
} // namespace std

bool Miner::ValidatePegIns(const CTransactionRef& pTx, const std::vector<PegInCoin>& pegins) const
{
    std::unordered_set<PegInCoin> pegin_set(pegins.cbegin(), pegins.cend());

    for (const CTxOut& output : pTx->vout) {
        mw::Hash kernel_id;
        if (output.scriptPubKey.IsMWEBPegin(&kernel_id)) {
            PegInCoin pegin(output.nValue, std::move(kernel_id));
            if (pegin_set.erase(pegin) != 1) {
                return false;
            }
        }
    }

    if (!pegin_set.empty()) {
        return false;
    }

    return true;
}

void Miner::AddHogExTransaction(const CBlockIndex* pIndexPrev, CBlock* pblock, std::vector<CAmount>& vTxFees, std::vector<int64_t>& vTxSigOpsCost, CAmount& nFees)
{
    CMutableTransaction hogExTransaction;
    hogExTransaction.m_hogEx = true;

    CAmount previous_amount = 0;

    //
    // Add previous HogAddr as new HogEx input
    //
    if (pIndexPrev->mweb_header != nullptr) {
        previous_amount = pIndexPrev->mweb_amount;

        CTxIn prevHogExIn(pIndexPrev->hogex_hash, 0);
        hogExTransaction.vin.push_back(std::move(prevHogExIn));
    }

    //
    // Add Peg-in inputs
    //
    hogExTransaction.vin.insert(hogExTransaction.vin.end(), hogex_inputs.cbegin(), hogex_inputs.cend());

    //
    // Add New HogAddr
    //
    mw::Block::Ptr mweb_block = mweb_builder->BuildBlock();

    CTxOut hogAddr;
    hogAddr.scriptPubKey = CScript() << OP_8 << mweb_block->GetHash().vec();
    hogAddr.nValue = previous_amount + mweb_amount_change;
    assert(MoneyRange(hogAddr.nValue));
    hogExTransaction.vout.push_back(std::move(hogAddr));

    //
    // Add Peg-out outputs
    //
    hogExTransaction.vout.insert(hogExTransaction.vout.end(), hogex_outputs.cbegin(), hogex_outputs.cend());

    //
    // Update block & template
    //
    pblock->vtx.emplace_back(MakeTransactionRef(std::move(hogExTransaction)));
    pblock->mweb_block = MWEB::Block(mweb_block);

    vTxFees.push_back(hogex_fees);
    vTxSigOpsCost.push_back(hogex_sigops);
}
