// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/register.h> // IWYU pragma: associated

#include <chain.h>
#include <core_io.h>
#include <crypto/hex_base.h>
#include <mweb/mweb_node.h>
#include <mw/mmr/leaf_set.h>
#include <mw/mmr/segment.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/utxo.h>
#include <mw/node/coins_view.h>
#include <node/blockstorage.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <undo.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

mw::Hash ParseMWEBHash(const UniValue& value, std::string_view name)
{
    // Validate hex length/charset via ParseHashV, then parse in libmw byte order
    // (same as mw::Hash::ToHex / wallet output_id). Do not copy uint256 begin()/end()
    // (little-endian), which would reverse the id.
    ParseHashV(value, name);
    return mw::Hash::FromHex(value.get_str());
}

UniValue SegmentToJSON(const mmr::Segment& segment)
{
    UniValue hashes(UniValue::VARR);
    for (const mw::Hash& hash : segment.hashes) {
        hashes.push_back(hash.ToHex());
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hashes", std::move(hashes));
    if (segment.lower_peak) {
        obj.pushKV("lower_peak", segment.lower_peak->ToHex());
    }
    return obj;
}

mmr::Segment SegmentFromJSON(const UniValue& segment_obj, const mmr::Leaf& leaf)
{
    if (!segment_obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "segment must be an object");
    }

    const UniValue& hashes_val = segment_obj.find_value("hashes");
    if (!hashes_val.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "segment.hashes must be an array");
    }

    mmr::Segment segment;
    segment.leaves = {leaf};
    segment.hashes.reserve(hashes_val.size());
    for (size_t i = 0; i < hashes_val.size(); ++i) {
        segment.hashes.push_back(ParseMWEBHash(hashes_val[i], "segment.hashes"));
    }

    const UniValue& lower_peak = segment_obj.find_value("lower_peak");
    if (!lower_peak.isNull() && !lower_peak.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "segment.lower_peak must be hex or null");
    }
    if (lower_peak.isStr()) {
        segment.lower_peak = ParseMWEBHash(lower_peak, "segment.lower_peak");
    }
    return segment;
}

std::string SerializeOutputHex(const Output& output)
{
    DataStream ss{};
    ss << output;
    return HexStr(ss);
}

Output DeserializeOutputHex(const std::string& hex)
{
    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "output must be hex");
    }
    const std::vector<unsigned char> data = ParseHex(hex);
    SpanReader reader{data};
    Output output;
    try {
        reader >> output;
    } catch (const std::exception&) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "output decode failed");
    }
    if (!reader.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "output decode leftover data");
    }
    return output;
}

struct OutputProofContext {
    mw::ICoinsView::Ptr view;
    const CBlockIndex* pindex{nullptr};
    UTXO::CPtr utxo;
};

//! Cap undo rewinds for getmweboutputproof (RPC DoS bound; independent of
//! P2P MAX_MWEB_LEAFSET_DEPTH peer policy).
static constexpr int MAX_MWEB_OUTPUT_PROOF_REWIND = 100'000;

//! Rewind a tip-backed MWEB cache until output_id is unspent in the leafset at
//! target (or at the first height where it is unspent, then optionally to inclusion).
OutputProofContext BuildOutputProofContext(
    Chainstate& chainstate,
    const mw::Hash& output_id,
    const CBlockIndex* requested) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);

    mw::ICoinsView::Ptr tip_view = chainstate.CoinsTip().GetMWEBView();
    if (!tip_view) {
        throw JSONRPCError(RPC_MISC_ERROR, "MWEB is not active on this chain");
    }

    const CBlockIndex* tip = chainstate.m_chain.Tip();
    if (!tip) {
        throw JSONRPCError(RPC_MISC_ERROR, "Chain tip unavailable");
    }

    if (requested) {
        if (!chainstate.m_chain.Contains(*requested)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in active chain");
        }
        if (!requested->mweb_header) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block has no MWEB header");
        }
        if (tip->nHeight - requested->nHeight > MAX_MWEB_OUTPUT_PROOF_REWIND) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                "Requested block is more than %d blocks below tip; cannot build historical proof",
                MAX_MWEB_OUTPUT_PROOF_REWIND));
        }
    }

    auto leaf_contains = [](const mw::ICoinsView& view, const UTXO& utxo) {
        const ILeafSet::Ptr leafset = view.GetLeafSet();
        return leafset && leafset->Contains(utxo.GetLeafIndex());
    };

    UTXO::CPtr tip_utxo = tip_view->GetUTXO(output_id);
    if (!requested && tip_utxo && leaf_contains(*tip_view, *tip_utxo)) {
        return OutputProofContext{tip_view, tip, tip_utxo};
    }

    mw::ICoinsView::Ptr view = std::make_shared<mw::CoinsViewCache>(tip_view);
    const CBlockIndex* pindex = tip;
    const CBlockIndex* target = requested;
    bool found_unspent = tip_utxo && leaf_contains(*view, *tip_utxo);
    int undo_steps = 0;

    while (pindex) {
        UTXO::CPtr utxo = view->GetUTXO(output_id);
        const bool unspent = utxo && leaf_contains(*view, *utxo);
        if (unspent) {
            found_unspent = true;
            if (!target) {
                // Default for spent outputs: prove at the inclusion height.
                const int incl_height = utxo->GetBlockHeight();
                if (incl_height < 0 || incl_height > pindex->nHeight) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "MWEB UTXO inclusion height out of range");
                }
                if (tip->nHeight - incl_height > MAX_MWEB_OUTPUT_PROOF_REWIND) {
                    throw JSONRPCError(RPC_MISC_ERROR, strprintf(
                        "MWEB output inclusion is more than %d blocks below tip; cannot build historical proof",
                        MAX_MWEB_OUTPUT_PROOF_REWIND));
                }
                target = chainstate.m_chain[incl_height];
                if (!target || !target->mweb_header) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "MWEB inclusion block unavailable");
                }
            }
            if (pindex == target) {
                if (!MWEB::Node::VerifyChainstateRoots(*pindex->mweb_header, *view)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "MWEB historical view roots mismatch header");
                }
                return OutputProofContext{view, pindex, utxo};
            }
        } else if (target && pindex == target) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "MWEB output is not unspent in the leafset at the requested block");
        }

        if (!pindex->pprev || (target && pindex->nHeight <= target->nHeight)) {
            break;
        }

        if (++undo_steps > MAX_MWEB_OUTPUT_PROOF_REWIND) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf(
                "Exceeded %d MWEB undo rewinds while building output proof",
                MAX_MWEB_OUTPUT_PROOF_REWIND));
        }

        CheckBlockDataAvailability(chainstate.m_blockman, *pindex, /*check_for_undo=*/true);
        CBlockUndo block_undo;
        if (!chainstate.m_blockman.ReadBlockUndo(block_undo, *pindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf(
                "MWEB undo data unavailable for block %s (height %d); cannot build historical proof",
                pindex->GetBlockHash().ToString(), pindex->nHeight));
        }
        if (block_undo.mwundo) {
            try {
                auto replay_cache = std::make_shared<mw::CoinsViewCache>(view);
                replay_cache->UndoBlock(block_undo.mwundo);
                view = std::move(replay_cache);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("MWEB undo failed: %s", e.what()));
            }
        }
        pindex = pindex->pprev;
    }

    if (!found_unspent) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "MWEB output not found in chainstate or undo history");
    }
    throw JSONRPCError(RPC_MISC_ERROR, "Failed to build MWEB output proof view");
}

UniValue BuildProofObject(const OutputProofContext& ctx)
{
    assert(ctx.pindex && ctx.pindex->mweb_header && ctx.utxo && ctx.view);

    const mmr::LeafIndex leaf_idx = ctx.utxo->GetLeafIndex();
    mmr::Segment segment = mmr::SegmentFactory::Assemble(
        *ctx.view->GetOutputPMMR(),
        *ctx.view->GetLeafSet(),
        leaf_idx,
        /*num_leaves=*/1);
    if (segment.leaves.size() != 1) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to assemble MWEB output segment");
    }

    const mw::Hash& output_root = ctx.pindex->mweb_header->GetOutputRoot();
    if (!mmr::SegmentFactory::VerifyAgainstRoot(segment, *ctx.view->GetLeafSet(), output_root)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Assembled MWEB segment does not match block output_root");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("output_id", ctx.utxo->GetOutputID().ToHex());
    result.pushKV("leaf_index", leaf_idx.Get());
    result.pushKV("num_leaves", ctx.pindex->mweb_header->GetNumTXOs());
    result.pushKV("blockhash", ctx.pindex->GetBlockHash().GetHex());
    result.pushKV("output_root", output_root.ToHex());
    result.pushKV("segment", SegmentToJSON(segment));
    result.pushKV("output", SerializeOutputHex(ctx.utxo->GetOutput()));
    return result;
}

} // namespace

static RPCMethod getmweboutputproof()
{
    return RPCMethod{
        "getmweboutputproof",
        "Returns a compact TXO PMMR inclusion proof for an MWEB output.\n"
        "\nFor unspent outputs, the proof is built against the tip by default.\n"
        "For spent outputs, the node rewinds using undo data to the inclusion\n"
        "block (or to blockhash if provided). Missing undo data fails closed.\n"
        "Historical rewinds are capped (100000 blocks below tip).\n",
        {
            {"output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The MWEB output id"},
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Prove against this block's output_root (must be on the active chain with MWEB). "
                "Default: tip if unspent, otherwise the inclusion block"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "output_id", "MWEB output id"},
                {RPCResult::Type::NUM, "leaf_index", "Output MMR leaf index"},
                {RPCResult::Type::NUM, "num_leaves", "Output MMR leaf count at the proof block"},
                {RPCResult::Type::STR_HEX, "blockhash", "Block the proof is bound to"},
                {RPCResult::Type::STR_HEX, "output_root", "MWEB header output_root at blockhash"},
                {RPCResult::Type::OBJ, "segment", "PMMR segment hashes for the leaf",
                    {
                        {RPCResult::Type::ARR, "hashes", "Sibling and peak hashes in index order",
                            {{RPCResult::Type::STR_HEX, "", "Hash"}}},
                        {RPCResult::Type::STR_HEX, "lower_peak", /*optional=*/true, "Bagged lower peak, or null"},
                    }},
                {RPCResult::Type::STR_HEX, "output", "Serialized MWEB output"},
            }
        },
        RPCExamples{
            HelpExampleCli("getmweboutputproof", "\"<output_id>\"")
            + HelpExampleCli("getmweboutputproof", "\"<output_id>\" \"<blockhash>\"")
            + HelpExampleRpc("getmweboutputproof", "\"<output_id>\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const mw::Hash output_id = ParseMWEBHash(request.params[0], "output_id");

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& chainstate = chainman.ActiveChainstate();

            const CBlockIndex* requested = nullptr;
            if (!request.params[1].isNull()) {
                const uint256 blockhash = ParseHashV(request.params[1], "blockhash");
                requested = chainman.m_blockman.LookupBlockIndex(blockhash);
                if (!requested) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            return BuildProofObject(BuildOutputProofContext(chainstate, output_id, requested));
        },
    };
}

static RPCMethod verifymweboutputproof()
{
    return RPCMethod{
        "verifymweboutputproof",
        "Verifies an MWEB TXO PMMR inclusion proof produced by getmweboutputproof.\n"
        "\nWhen blockhash is present in the proof (or supplied), the node checks that\n"
        "the active-chain block's mweb_header.output_root matches the proof.\n"
        "When output_root is supplied without a matching chain header, verification is\n"
        "purely cryptographic against that root.\n",
        {
            // Named mwebproof (not "proof") so conversion stays distinct from
            // verifytxoutproof's hex STR "proof" (rpc_help arg-name consistency).
            {"mwebproof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof object from getmweboutputproof",
                {
                    {"output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "MWEB output id"},
                    {"leaf_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output MMR leaf index"},
                    {"num_leaves", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output MMR leaf count at the proof block"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Block the proof claims"},
                    {"output_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Expected output MMR root"},
                    // Nested RPCArg::Type::OBJ is unsupported by ToStringObj (help crash).
                    // Runtime still accepts a JSON object; type check is skipped.
                    {"segment", RPCArg::Type::STR, RPCArg::Optional::NO,
                        "Segment object: {\"hashes\":[hex...], optional \"lower_peak\" hex}",
                        RPCArgOptions{.skip_type_check = true, .type_str = {"obj", "obj"}}},
                    {"output", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized MWEB output"},
                },
            },
            {"output_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Override expected output_root (offline verify)"},
        },
        RPCResult{RPCResult::Type::BOOL, "verified", "True if the proof is valid"},
        RPCExamples{
            HelpExampleCli("verifymweboutputproof", "'{\"output_id\":\"...\", ...}'")
            + HelpExampleRpc("verifymweboutputproof", "{\"output_id\":\"...\"}")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const UniValue& proof = request.params[0].get_obj();

            const mw::Hash output_id = ParseMWEBHash(proof.find_value("output_id"), "output_id");
            if (!proof.find_value("leaf_index").isNum() || !proof.find_value("num_leaves").isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "leaf_index and num_leaves are required");
            }
            const uint64_t leaf_index = proof.find_value("leaf_index").getInt<uint64_t>();
            const uint64_t num_leaves = proof.find_value("num_leaves").getInt<uint64_t>();
            if (leaf_index >= num_leaves) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "leaf_index out of range for num_leaves");
            }

            const Output output = DeserializeOutputHex(proof.find_value("output").get_str());
            if (output.GetOutputID() != output_id) {
                return false;
            }

            const mmr::Leaf leaf = mmr::Leaf::Create(mmr::LeafIndex::At(leaf_index), output_id.Serialized());
            const mmr::Segment segment = SegmentFromJSON(proof.find_value("segment"), leaf);

            mw::Hash expected_root;
            bool have_root = false;
            if (!request.params[1].isNull()) {
                expected_root = ParseMWEBHash(request.params[1], "output_root");
                have_root = true;
            } else if (proof.exists("output_root") && proof.find_value("output_root").isStr()) {
                expected_root = ParseMWEBHash(proof.find_value("output_root"), "output_root");
                have_root = true;
            }

            if (proof.exists("blockhash") && proof.find_value("blockhash").isStr()) {
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                const uint256 blockhash = ParseHashV(proof.find_value("blockhash"), "blockhash");
                const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(blockhash);
                if (!pindex || !chainman.ActiveChain().Contains(*pindex) || !pindex->mweb_header) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in active chain or has no MWEB header");
                }
                if (pindex->mweb_header->GetNumTXOs() != num_leaves) {
                    return false;
                }
                if (have_root && expected_root != pindex->mweb_header->GetOutputRoot()) {
                    return false;
                }
                expected_root = pindex->mweb_header->GetOutputRoot();
                have_root = true;
            }

            if (!have_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "output_root or blockhash is required to verify");
            }

            mw::DynamicBitSet bits(num_leaves);
            bits.set(leaf_index);
            const MemLeafSet leafset(bits);
            return mmr::SegmentFactory::VerifyAgainstRoot(segment, leafset, expected_root);
        },
    };
}

void RegisterMWEBOutputProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getmweboutputproof},
        {"blockchain", &verifymweboutputproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
