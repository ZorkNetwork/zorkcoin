// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_snapshot_base_block.h>

#include <chain.h>
#include <kernel/chainparams.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <sync.h>
#include <util/check.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

namespace node {

util::Result<void> EnsureSnapshotBaseBlock(NodeContext& node, const uint256& base_blockhash)
{
    ChainstateManager& chainman{*Assert(node.chainman)};

    const auto au_data{chainman.GetParams().AssumeutxoForBlockhash(base_blockhash)};
    if (!au_data || !au_data->mweb_hash_serialized.has_value() ||
        *au_data->mweb_hash_serialized == AssumeutxoHash{uint256{}}) {
        return {};
    }

    const CBlockIndex* index{WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(base_blockhash))};
    if (!index) {
        return util::Error{Untranslated(strprintf(
            "The base block header (%s) must appear in the headers chain. Make sure all headers are syncing, and call loadtxoutset again",
            base_blockhash.ToString()))};
    }

    if (WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA)) {
        return {};
    }

    PeerManager* peerman{node.peerman.get()};
    if (!peerman) {
        return util::Error{Untranslated(
            "Unable to fetch MWEB snapshot base block: no peer manager. Connect to a NODE_MWEB peer that has that block, then retry loadtxoutset. Do not wait for IBD to the snapshot height.")};
    }

    if (const auto fetch{peerman->FetchBlockFromCapablePeer(*index)}; !fetch) {
        return util::Error{Untranslated(strprintf(
            "Unable to fetch MWEB snapshot base block %s: %s. Connect to a NODE_MWEB peer that has that block, then retry loadtxoutset. Do not wait for IBD to the snapshot height.",
            base_blockhash.ToString(), fetch.error()))};
    }

    LogInfo("Waiting for MWEB snapshot base block %s after requesting it from a peer\n",
            base_blockhash.ToString());

    const auto deadline{NodeClock::now() + SNAPSHOT_BASE_BLOCK_FETCH_TIMEOUT};
    while (true) {
        node.rpc_interruption_point();
        const bool have_data{WITH_LOCK(::cs_main, {
            const CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(base_blockhash)};
            return idx && (idx->nStatus & BLOCK_HAVE_DATA);
        })};
        if (have_data) {
            return {};
        }
        if (NodeClock::now() >= deadline) {
            return util::Error{Untranslated(strprintf(
                "Timed out waiting for MWEB snapshot base block %s from peer. Connect to a NODE_MWEB peer that has that block, then retry loadtxoutset. Do not wait for IBD to the snapshot height.",
                base_blockhash.ToString()))};
        }
        UninterruptibleSleep(100ms);
    }
}

} // namespace node
