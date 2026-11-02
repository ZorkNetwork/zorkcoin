#include <mw/node/coins_view.h>
#include <mw/node/coins_view_materialize.h>

#include <stdexcept>

using namespace mw;

MemLeafSet::MemLeafSet(const mw::DynamicBitSet& bits)
    : ILeafSet(mmr::LeafIndex::At(bits.size()))
{
    m_bytes = bits.bytes();
}

uint8_t MemLeafSet::GetByte(const uint64_t byteIdx) const
{
    if (byteIdx >= m_bytes.size()) {
        return 0;
    }
    return m_bytes[byteIdx];
}

void MemLeafSet::SetByte(const uint64_t byteIdx, const uint8_t value)
{
    if (byteIdx >= m_bytes.size()) {
        m_bytes.resize(byteIdx + 1, 0);
    }
    m_bytes[byteIdx] = value;
}

void MemLeafSet::ApplyUpdates(
    const uint32_t /*file_index*/,
    const mmr::LeafIndex& nextLeafIdx,
    const std::unordered_map<uint64_t, uint8_t>& modifiedBytes)
{
    m_nextLeafIdx = nextLeafIdx;
    for (const auto& [byte_idx, value] : modifiedBytes) {
        SetByte(byte_idx, value);
    }
}

CoinsViewMemory::Ptr CoinsViewMemory::Materialize(const ICoinsView& source)
{
    const auto pLeafSet = source.GetLeafSet();
    const auto pOutputPMMR = source.GetOutputPMMR();
    if (!pLeafSet || !pOutputPMMR) {
        throw std::runtime_error("CoinsViewMemory::Materialize: source missing leafset or PMMR");
    }

    auto mem_leafset = std::make_shared<MemLeafSet>(pLeafSet->ToDynamicBitSet());
    auto mem_pmmr = std::make_shared<MemMMR>();
    const uint64_t num_leaves = pOutputPMMR->GetNumLeaves();
    for (uint64_t i = 0; i < num_leaves; ++i) {
        mem_pmmr->AddLeaf(pOutputPMMR->GetLeaf(mmr::LeafIndex::At(i)));
    }

    std::unordered_map<mw::Hash, UTXO::CPtr> utxos;
    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < pLeafSet->GetNextLeafIdx(); ++idx) {
        if (!pLeafSet->Contains(idx)) {
            continue;
        }
        const mmr::Leaf leaf = pOutputPMMR->GetLeaf(idx);
        const mw::Hash output_id{leaf.vec()};
        UTXO::CPtr utxo = source.GetUTXO(output_id);
        if (!utxo) {
            throw std::runtime_error("CoinsViewMemory::Materialize: missing UTXO for unspent leaf");
        }
        utxos.emplace(output_id, std::move(utxo));
    }

    return Create(
        source.GetBestHeader(),
        std::move(mem_leafset),
        std::move(mem_pmmr),
        std::move(utxos));
}

CoinsViewMemory::Ptr CoinsViewMemory::MaterializeAssumeUTXOSnapshot(const ICoinsView& source)
{
    // Sync helper for non-serve callers. Serve/warm paths must use MaterializeStep
    // under an I11 budget (see MWEBHistoricalViewCache::ProcessOneAssumeUTXOWarmStep).
    MaterializeProgress progress;
    MaterializeProgressBegin(progress, source, /*assumeutxo_snapshot=*/true);
    MaterializeBudget budget{/*max_leaf_ops=*/1024, /*max_bytes=*/1 << 20};
    CoinsViewMemory::Ptr out;
    while (!MaterializeStep(progress, budget, out)) {
    }
    return out;
}

CoinsViewMemory::Ptr CoinsViewMemory::Create(
    const mw::Header::CPtr& pHeader,
    ILeafSet::Ptr pLeafSet,
    IMMR::Ptr pOutputPMMR,
    std::unordered_map<mw::Hash, UTXO::CPtr> utxos)
{
    return Ptr(new CoinsViewMemory(
        pHeader,
        std::move(pLeafSet),
        std::move(pOutputPMMR),
        std::move(utxos)));
}

UTXO::CPtr CoinsViewMemory::GetUTXO(const mw::Hash& output_id) const
{
    const auto it = m_utxos.find(output_id);
    if (it == m_utxos.end()) {
        return nullptr;
    }
    return it->second;
}

void CoinsViewMemory::WriteBatch(
    const mw::DBBatch::UPtr&,
    const CoinsViewUpdates&,
    const mw::Header::CPtr&)
{
    throw std::logic_error("CoinsViewMemory::WriteBatch");
}
