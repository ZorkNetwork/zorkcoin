// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_utxo_enumerate.h>

#include <mw/mmr/leaf.h>
#include <mw/mmr/leaf_index.h>
#include <mw/node/coins_view.h>
#include <util/translation.h>

namespace node {

util::Result<uint64_t> ForEachUnspentMWEBUTXO(
    const mw::ICoinsView& view,
    const std::function<bool(MWEBUnspentEntry&&)>& fn,
    const std::function<void()>& interruption_point)
{
    const auto pLeafSet = view.GetLeafSet();
    const auto pOutputPMMR = view.GetOutputPMMR();
    if (!pLeafSet || !pOutputPMMR) {
        return util::Error{Untranslated("MWEB UTXO enumeration requires leafset and output PMMR")};
    }

    uint64_t examined{0};
    for (mmr::LeafIndex idx = mmr::LeafIndex::At(0); idx < pLeafSet->GetNextLeafIdx(); ++idx) {
        if (!pLeafSet->Contains(idx)) {
            continue;
        }
        if (examined % 5000 == 0 && interruption_point) {
            interruption_point();
        }
        const mmr::Leaf leaf = pOutputPMMR->GetLeaf(idx);
        const mw::Hash output_id{leaf.vec()};
        const UTXO::CPtr pUTXO = view.GetUTXO(output_id);
        if (!pUTXO) {
            return util::Error{Untranslated(strprintf(
                "MWEB UTXO enumeration: unspent leaf %u has no UTXO for output %s",
                idx.Get(), output_id.ToHex()))};
        }
        if (pUTXO->GetLeafIndex() != idx) {
            return util::Error{Untranslated(strprintf(
                "MWEB UTXO enumeration: UTXO %s leaf index mismatch (got %u, expected %u)",
                output_id.ToHex(), pUTXO->GetLeafIndex().Get(), idx.Get()))};
        }
        ++examined;
        if (!fn(MWEBUnspentEntry{
                output_id,
                pUTXO->GetBlockHeight(),
                idx,
                leaf.vec(),
                pUTXO->GetOutput()})) {
            return examined;
        }
    }
    return examined;
}

} // namespace node
