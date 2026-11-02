// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/coins_view_materialize.h>

#include <mw/mmr/leaf_set.h>
#include <mw/mmr/mmr.h>
#include <mw/common/dynamic_bit_set.h>

#include <stdexcept>

MW_NAMESPACE

void MaterializeProgressBegin(MaterializeProgress& progress, const ICoinsView& source, bool assumeutxo_snapshot)
{
    progress = MaterializeProgress{};
    progress.assumeutxo_snapshot = assumeutxo_snapshot;
    progress.header = source.GetBestHeader();
    progress.source = source.shared_from_this();
    progress.phase = MaterializeProgress::Phase::INIT;
}

bool MaterializeStep(MaterializeProgress& progress, const MaterializeBudget& budget, CoinsViewMemory::Ptr& out)
{
    out.reset();
    if (progress.phase == MaterializeProgress::Phase::DONE) {
        return true;
    }
    if (!progress.source) {
        throw std::runtime_error("MaterializeStep: missing source");
    }
    const ICoinsView& source{*progress.source};
    const auto pLeafSet = source.GetLeafSet();
    const auto pOutputPMMR = source.GetOutputPMMR();
    if (!pLeafSet || !pOutputPMMR) {
        throw std::runtime_error("MaterializeStep: source missing leafset or PMMR");
    }

    size_t leaf_ops{0};
    size_t bytes_used{0};

    if (progress.phase == MaterializeProgress::Phase::INIT) {
        const auto bits{pLeafSet->ToDynamicBitSet()};
        progress.leafset_src_bytes = bits.bytes();
        progress.leafset_total_bytes = progress.leafset_src_bytes.size();
        progress.leafset_bit_count = bits.size();
        progress.leafset_bytes.clear();
        progress.leafset_bytes.reserve(progress.leafset_total_bytes);
        progress.pmmr_total_leaves = pOutputPMMR->GetNumLeaves();
        progress.pmmr_total_nodes = pOutputPMMR->GetNumNodes();
        progress.cursor = 0;
        progress.built_pmmr = std::make_shared<MemMMR>();
        progress.phase = MaterializeProgress::Phase::LEAFSET_BYTES;
        return false;
    }

    if (progress.phase == MaterializeProgress::Phase::LEAFSET_BYTES) {
        // Stream from INIT snapshot — do not call ToDynamicBitSet again (materialize leafset stream).
        while (progress.cursor < progress.leafset_total_bytes &&
               bytes_used < budget.max_bytes) {
            progress.leafset_bytes.push_back(progress.leafset_src_bytes[progress.cursor]);
            ++progress.cursor;
            ++bytes_used;
        }
        if (progress.cursor < progress.leafset_total_bytes) {
            return false;
        }
        mw::DynamicBitSet built_bits = mw::DynamicBitSet::From(progress.leafset_bytes);
        if (built_bits.bitset.size() > progress.leafset_bit_count) {
            built_bits.bitset.resize(progress.leafset_bit_count);
        }
        progress.built_leafset = std::make_shared<MemLeafSet>(built_bits);
        progress.leafset_src_bytes.clear();
        progress.leafset_src_bytes.shrink_to_fit();
        progress.cursor = 0;
        if (progress.assumeutxo_snapshot) {
            auto* mem_pmmr = dynamic_cast<MemMMR*>(progress.built_pmmr.get());
            if (!mem_pmmr) {
                throw std::runtime_error("MaterializeStep: built_pmmr not MemMMR");
            }
            mem_pmmr->PrepareClone(progress.pmmr_total_leaves, progress.pmmr_total_nodes);
            progress.phase = MaterializeProgress::Phase::PMMR_HASHES;
        } else {
            progress.phase = MaterializeProgress::Phase::PMMR_LEAVES;
        }
        return false;
    }

    if (progress.phase == MaterializeProgress::Phase::PMMR_HASHES) {
        auto* mem_pmmr = dynamic_cast<MemMMR*>(progress.built_pmmr.get());
        if (!mem_pmmr) {
            throw std::runtime_error("MaterializeStep: built_pmmr not MemMMR");
        }
        while (progress.cursor < progress.pmmr_total_nodes &&
               leaf_ops < budget.max_leaf_ops && bytes_used < budget.max_bytes) {
            mem_pmmr->AppendHash(pOutputPMMR->GetHash(mmr::Index::At(progress.cursor)));
            ++progress.cursor;
            ++leaf_ops;
            bytes_used += 32;
        }
        if (progress.cursor < progress.pmmr_total_nodes) {
            return false;
        }
        progress.phase = MaterializeProgress::Phase::PMMR_LEAVES;
        progress.cursor = 0;
        return false;
    }

    if (progress.phase == MaterializeProgress::Phase::PMMR_LEAVES) {
        auto* mem_pmmr = dynamic_cast<MemMMR*>(progress.built_pmmr.get());
        if (!mem_pmmr) {
            throw std::runtime_error("MaterializeStep: built_pmmr not MemMMR");
        }
        if (progress.assumeutxo_snapshot) {
            while (progress.cursor < progress.pmmr_total_leaves &&
                   leaf_ops < budget.max_leaf_ops && bytes_used < budget.max_bytes) {
                const mmr::LeafIndex idx{mmr::LeafIndex::At(progress.cursor)};
                ++progress.cursor;
                ++leaf_ops;
                if (!pLeafSet->Contains(idx)) {
                    continue;
                }
                const mmr::Leaf leaf{pOutputPMMR->GetLeaf(idx)};
                mem_pmmr->SetLeafAt(idx, leaf);
                bytes_used += leaf.vec().size();
            }
        } else {
            while (progress.cursor < progress.pmmr_total_leaves &&
                   leaf_ops < budget.max_leaf_ops && bytes_used < budget.max_bytes) {
                const mmr::Leaf leaf{pOutputPMMR->GetLeaf(mmr::LeafIndex::At(progress.cursor))};
                mem_pmmr->AddLeaf(leaf);
                ++progress.cursor;
                ++leaf_ops;
                bytes_used += leaf.vec().size();
            }
        }
        if (progress.cursor < progress.pmmr_total_leaves) {
            return false;
        }
        progress.phase = MaterializeProgress::Phase::UTXO_LEAVES;
        progress.utxo_next_leaf = 0;
        return false;
    }

    if (progress.phase == MaterializeProgress::Phase::UTXO_LEAVES) {
        const mmr::LeafIndex end{pLeafSet->GetNextLeafIdx()};
        while (progress.utxo_next_leaf < end.Get() &&
               leaf_ops < budget.max_leaf_ops && bytes_used < budget.max_bytes) {
            const mmr::LeafIndex idx{mmr::LeafIndex::At(progress.utxo_next_leaf)};
            ++progress.utxo_next_leaf;
            ++leaf_ops;
            if (!pLeafSet->Contains(idx)) {
                continue;
            }
            const mmr::Leaf leaf{pOutputPMMR->GetLeaf(idx)};
            const mw::Hash output_id{leaf.vec()};
            if (progress.built_utxos.contains(output_id)) {
                continue;
            }
            UTXO::CPtr utxo = source.GetUTXO(output_id);
            if (!utxo) {
                throw std::runtime_error("MaterializeStep: missing UTXO for unspent leaf");
            }
            progress.built_utxos.emplace(output_id, std::move(utxo));
            bytes_used += 64;
        }
        if (progress.utxo_next_leaf < end.Get()) {
            return false;
        }
        out = CoinsViewMemory::Create(
            progress.header,
            progress.built_leafset,
            progress.built_pmmr,
            std::move(progress.built_utxos));
        progress.phase = MaterializeProgress::Phase::DONE;
        return true;
    }

    return false;
}

bool MaterializeStepWithSparseFallback(MaterializeProgress& progress, const MaterializeBudget& budget, CoinsViewMemory::Ptr& out)
{
    try {
        return MaterializeStep(progress, budget, out);
    } catch (const std::exception&) {
        if (progress.assumeutxo_snapshot || !progress.source) throw;
        const ICoinsView::CPtr source{progress.source};
        MaterializeProgressBegin(progress, *source, /*assumeutxo_snapshot=*/true);
        return false;
    }
}

END_NAMESPACE
