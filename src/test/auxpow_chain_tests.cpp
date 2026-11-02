// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/check.h>
#include <auxpow/version.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <interfaces/mining.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/script.h>
#include <sync.h>
#include <streams.h>
#include <txmempool.h>
#include <test/util/auxpow.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <ios>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace auxpow;
using namespace auxpow::test;

namespace auxpow_chain_tests {
struct AuxPowChainSetup : public TestingSetup {
    explicit AuxPowChainSetup(TestOpts opts = {}) : TestingSetup{ChainType::REGTEST, std::move(opts)} {}
    int m_cb_tag{0};
    std::shared_ptr<CBlock> MakeUniqueBlock(const uint256& prev_hash, std::optional<uint64_t> time = std::nullopt);
    void FinalizeNative(const std::shared_ptr<CBlock>& pblock);
    void FinalizeAuxPow(const std::shared_ptr<CBlock>& pblock, size_t extra_parents);
    bool AcceptBlock(const std::shared_ptr<const CBlock>& block);
    const CBlockIndex* Index(const uint256& hash);
    uint256 TipHash();
};

struct AuxPowAsertSetup : public AuxPowChainSetup {
    AuxPowAsertSetup() : AuxPowChainSetup{{.extra_args = {"-test=asert"}}} {}
};
} // namespace auxpow_chain_tests

BOOST_FIXTURE_TEST_SUITE(auxpow_chain_tests, auxpow_chain_tests::AuxPowChainSetup)

std::shared_ptr<CBlock> AuxPowChainSetup::MakeUniqueBlock(const uint256& prev_hash, std::optional<uint64_t> time)
{
    auto mining{interfaces::MakeMining(m_node)};
    auto block_template{mining->createNewBlock({
        .coinbase_output_script = CScript{} << ++m_cb_tag << OP_TRUE,
    }, /*cooldown=*/false)};
    BOOST_REQUIRE(block_template);
    auto pblock = std::make_shared<CBlock>(block_template->getBlock());
    pblock->hashPrevBlock = prev_hash;

    const CBlockIndex* prev{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash))};
    BOOST_REQUIRE(prev);
    pblock->nTime = time.value_or(prev->GetBlockTime() + 1000 + static_cast<uint64_t>(m_cb_tag));
    pblock->nBits = GetNextWorkRequired(prev, pblock.get(), Params().GetConsensus());

    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = CScript{} << (prev->nHeight + 1) << OP_0;
    txCoinbase.nLockTime = static_cast<uint32_t>(prev->nHeight);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev);
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    return pblock;
}

void AuxPowChainSetup::FinalizeNative(const std::shared_ptr<CBlock>& pblock)
{
    GrindBlockPoW(*pblock, Params().GetConsensus());
}

void AuxPowChainSetup::FinalizeAuxPow(const std::shared_ptr<CBlock>& pblock, size_t extra_parents)
{
    const auto& params = Params().GetConsensus();
    pblock->nVersion = MakeAuxPowVersion(pblock->nVersion);
    pblock->nNonce = MakeAuxPowNonce(params.auxpow.nChainId);
    CAuxPow aux = MakeStructuralAuxPow(*pblock, /*kaspa_bits=*/0x207fffff, extra_parents);
    const DualTargets t = ComputeDualTargets(pblock->nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    std::string err;
    BOOST_REQUIRE_MESSAGE(CheckAuxPow(*pblock, aux, params, &err), err);
    pblock->auxpow = std::move(aux);
}

bool AuxPowChainSetup::AcceptBlock(const std::shared_ptr<const CBlock>& block)
{
    bool new_block = false;
    const bool ok = Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
    BOOST_CHECK(ok);
    BOOST_CHECK(new_block);
    return ok && new_block;
}

const CBlockIndex* AuxPowChainSetup::Index(const uint256& hash)
{
    LOCK(::cs_main);
    return m_node.chainman->m_blockman.LookupBlockIndex(hash);
}

uint256 AuxPowChainSetup::TipHash()
{
    LOCK(::cs_main);
    return m_node.chainman->ActiveChain().Tip()->GetBlockHash();
}

BOOST_AUTO_TEST_CASE(three_way_same_height_best_chain)
{
    // Parent on the active chain.
    auto parent = MakeUniqueBlock(TipHash());
    FinalizeNative(parent);
    BOOST_REQUIRE(AcceptBlock(parent));
    const uint256 parent_hash = parent->GetHash();
    BOOST_REQUIRE(TipHash() == parent_hash);

    constexpr size_t FAT_EXTRA_PARENTS = 12;
    auto fat = MakeUniqueBlock(parent_hash);
    FinalizeAuxPow(fat, FAT_EXTRA_PARENTS);
    auto lean = MakeUniqueBlock(parent_hash);
    FinalizeAuxPow(lean, /*extra_parents=*/0);
    auto native = MakeUniqueBlock(parent_hash);
    FinalizeNative(native);

    const size_t fat_sz = GetSerializeSizeAuxPow(*fat->auxpow);
    const size_t lean_sz = GetSerializeSizeAuxPow(*lean->auxpow);
    BOOST_REQUIRE_LT(lean_sz, fat_sz);
    BOOST_REQUIRE_LE(fat_sz, Params().GetConsensus().auxpow.nMaxSerializedSize);
    BOOST_REQUIRE_GT(fat_sz, lean_sz + 300);

    // Submit fat, then lean, then native. On regtest nBits is so easy that
    // native work is 2 and every AuxPoW size discounts to 1, so lean does not
    // outrank fat; native still outranks both.
    BOOST_REQUIRE(AcceptBlock(fat));
    BOOST_CHECK(TipHash() == fat->GetHash());
    BOOST_REQUIRE(AcceptBlock(lean));
    BOOST_CHECK(TipHash() == fat->GetHash());
    BOOST_REQUIRE(AcceptBlock(native));
    BOOST_CHECK(TipHash() == native->GetHash());

    const CBlockIndex* pfat = Index(fat->GetHash());
    const CBlockIndex* plean = Index(lean->GetHash());
    const CBlockIndex* pnative = Index(native->GetHash());
    BOOST_REQUIRE(pfat && plean && pnative);
    BOOST_CHECK_EQUAL(pfat->nHeight, plean->nHeight);
    BOOST_CHECK_EQUAL(plean->nHeight, pnative->nHeight);
    BOOST_CHECK(pnative->nChainWork > plean->nChainWork);
    BOOST_CHECK(pnative->nChainWork > pfat->nChainWork);
    BOOST_CHECK(plean->nChainWork >= pfat->nChainWork);
    BOOST_CHECK_EQUAL(pfat->nAuxPowSize, static_cast<uint32_t>(fat_sz));
    BOOST_CHECK_EQUAL(plean->nAuxPowSize, static_cast<uint32_t>(lean_sz));
    BOOST_CHECK_EQUAL(pnative->nAuxPowSize, 0u);

    // Native child on each fork. Extend the current best first so a single
    // native child of a weaker fork cannot reorg (W_aux + W_n < 2*W_n).
    auto native_child = MakeUniqueBlock(native->GetHash());
    FinalizeNative(native_child);
    auto lean_child = MakeUniqueBlock(lean->GetHash());
    FinalizeNative(lean_child);
    auto fat_child = MakeUniqueBlock(fat->GetHash());
    FinalizeNative(fat_child);

    BOOST_REQUIRE(AcceptBlock(native_child));
    BOOST_CHECK(TipHash() == native_child->GetHash());
    BOOST_REQUIRE(AcceptBlock(lean_child));
    BOOST_CHECK(TipHash() == native_child->GetHash());
    BOOST_REQUIRE(AcceptBlock(fat_child));
    BOOST_CHECK(TipHash() == native_child->GetHash());

    const CBlockIndex* pfat_c = Index(fat_child->GetHash());
    const CBlockIndex* plean_c = Index(lean_child->GetHash());
    const CBlockIndex* pnative_c = Index(native_child->GetHash());
    BOOST_REQUIRE(pfat_c && plean_c && pnative_c);
    BOOST_CHECK(pnative_c->nChainWork > plean_c->nChainWork);
    BOOST_CHECK(pnative_c->nChainWork > pfat_c->nChainWork);
    BOOST_CHECK(plean_c->nChainWork >= pfat_c->nChainWork);

    // One more native block only on the fat (losing) fork: W_f + 2*W_n > 2*W_n, so it is used (reorg).
    auto fat_gc = MakeUniqueBlock(fat_child->GetHash());
    FinalizeNative(fat_gc);
    BOOST_REQUIRE(AcceptBlock(fat_gc));
    BOOST_CHECK(TipHash() == fat_gc->GetHash());
    const CBlockIndex* pfat_gc = Index(fat_gc->GetHash());
    BOOST_REQUIRE(pfat_gc);
    BOOST_CHECK(pfat_gc->nChainWork > pnative_c->nChainWork);
    // Losing native/lean forks remain indexed, not discarded.
    BOOST_CHECK(Index(native_child->GetHash()) != nullptr);
    BOOST_CHECK(Index(lean_child->GetHash()) != nullptr);
}

BOOST_AUTO_TEST_CASE(auxpow_header_indexed_missing_extension_rejected)
{
    auto pblock = MakeUniqueBlock(TipHash());
    FinalizeAuxPow(pblock, /*extra_parents=*/0);

    BlockValidationState state;
    const CBlockIndex* pindex = nullptr;
    std::vector<CBlockHeader> good_headers{*pblock};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders(good_headers, /*min_pow_checked=*/true, state, &pindex));
    BOOST_REQUIRE(pindex);
    BOOST_CHECK(Index(pblock->GetHash()) != nullptr);
    BOOST_CHECK(pindex->auxpow.has_value());
    BOOST_CHECK_GT(pindex->nAuxPowSize, 0u);
    BOOST_CHECK(pindex->GetBlockHeader().auxpow.has_value());

    auto missing = MakeUniqueBlock(TipHash());
    FinalizeAuxPow(missing, /*extra_parents=*/0);
    const uint256 missing_hash = missing->GetHash();
    BOOST_CHECK(Index(missing_hash) == nullptr);
    missing->auxpow.reset();
    BOOST_CHECK(auxpow::IsAuxPow(missing->nVersion));
    BOOST_CHECK(!missing->auxpow.has_value());
    BOOST_CHECK(missing->GetHash() == missing_hash);
    BOOST_CHECK(!HasValidProofOfWork(std::vector<CBlockHeader>{*missing}, Params().GetConsensus()));

    BlockValidationState bad_state;
    const CBlockIndex* bad_index = nullptr;
    bool accepted = false;
    std::vector<CBlockHeader> bad_headers{*missing};
    accepted = m_node.chainman->ProcessNewBlockHeaders(bad_headers, /*min_pow_checked=*/true, bad_state, &bad_index);
    BOOST_CHECK(!accepted);
    BOOST_CHECK(Index(missing_hash) == nullptr);
    BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "bad-auxpow-missing");
}

BOOST_AUTO_TEST_CASE(compact_block_keeps_auxpow)
{
    auto pblock = MakeUniqueBlock(TipHash());
    FinalizeAuxPow(pblock, /*extra_parents=*/0);
    BOOST_REQUIRE(pblock->auxpow.has_value());

    CTxMemPool& pool = *Assert(m_node.mempool);
    CBlockHeaderAndShortTxIDs shortIDs{*pblock, /*nonce=*/1};
    DataStream stream{};
    stream << shortIDs;
    BOOST_CHECK_GT(GetSerializeSize(shortIDs.header), 88u);

    CBlockHeaderAndShortTxIDs shortIDs2;
    stream >> shortIDs2;
    BOOST_REQUIRE(shortIDs2.header.auxpow.has_value());
    BOOST_CHECK(shortIDs2.header.GetHash() == pblock->GetHash());

    PartiallyDownloadedBlock partial(&pool);
    BOOST_CHECK(partial.InitData(shortIDs2, {}) == READ_STATUS_OK);
    CBlock reconstructed;
    BOOST_CHECK(partial.FillBlock(reconstructed, {}, /*segwit_active=*/true) == READ_STATUS_OK);
    BOOST_REQUIRE(reconstructed.auxpow.has_value());
    BOOST_CHECK(reconstructed.GetHash() == pblock->GetHash());
    BOOST_CHECK(CheckAuxPow(reconstructed, *reconstructed.auxpow, Params().GetConsensus()));
}

BOOST_AUTO_TEST_CASE(first_seen_auxpow_extension_is_pinned)
{
    auto pblock = MakeUniqueBlock(TipHash());
    const auto& params = Params().GetConsensus();
    pblock->nVersion = MakeAuxPowVersion(pblock->nVersion);
    pblock->nNonce = MakeAuxPowNonce(params.auxpow.nChainId);
    CAuxPow lean = MakeStructuralAuxPow(*pblock, /*kaspa_bits=*/0x207fffff, /*extra_parents=*/0);
    CAuxPow fat = MakeStructuralAuxPow(*pblock, /*kaspa_bits=*/0x207fffff, /*extra_parents=*/12);
    const DualTargets t = ComputeDualTargets(pblock->nBits, lean.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(lean.peer_header, t.T_kd, t.T_floor));
    BOOST_REQUIRE(GrindPeerToMeetBoth(fat.peer_header, t.T_kd, t.T_floor));
    BOOST_REQUIRE(!AuxPowEqual(lean, fat));
    BOOST_REQUIRE_LT(GetSerializeSizeAuxPow(lean), GetSerializeSizeAuxPow(fat));

    std::string err;
    BOOST_REQUIRE_MESSAGE(CheckAuxPow(*pblock, lean, params, &err), err);
    BOOST_REQUIRE_MESSAGE(CheckAuxPow(*pblock, fat, params, &err), err);

    pblock->auxpow = lean;
    BlockValidationState state;
    const CBlockIndex* pindex = nullptr;
    std::vector<CBlockHeader> headers{*pblock};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &pindex));
    BOOST_REQUIRE(pindex);
    const uint32_t lean_sz = pindex->nAuxPowSize;
    const arith_uint256 work = pindex->nChainWork;

    pblock->auxpow = std::move(fat);
    bool new_block = false;
    BOOST_CHECK(!m_node.chainman->ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    const CBlockIndex* pinned = Index(pblock->GetHash());
    BOOST_REQUIRE(pinned);
    BOOST_CHECK_EQUAL(pinned->nAuxPowSize, lean_sz);
    BOOST_CHECK(pinned->nChainWork == work);
}

BOOST_AUTO_TEST_CASE(incomplete_auxpow_index_does_not_serialize)
{
    auto pblock = MakeUniqueBlock(TipHash());
    FinalizeAuxPow(pblock, /*extra_parents=*/0);
    BlockValidationState state;
    const CBlockIndex* pindex = nullptr;
    std::vector<CBlockHeader> headers{*pblock};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &pindex));
    BOOST_REQUIRE(pindex);
    BOOST_CHECK(pindex->HasCompleteAuxPow());

    {
        LOCK(::cs_main);
        auto it = m_node.chainman->m_blockman.m_block_index.find(pblock->GetHash());
        BOOST_REQUIRE(it != m_node.chainman->m_blockman.m_block_index.end());
        it->second.auxpow.reset();
        BOOST_CHECK(!it->second.HasCompleteAuxPow());
        const CBlockHeader hdr = it->second.GetBlockHeader();
        BOOST_CHECK(!hdr.HasCompleteAuxPow());
        BOOST_CHECK_THROW((DataStream{} << hdr), std::ios_base::failure);
        BOOST_CHECK_NO_THROW(m_node.chainman->m_blockman.WriteBlockIndexDB());
    }
}

BOOST_FIXTURE_TEST_CASE(asert_ignores_block_type, AuxPowAsertSetup)
{
    const auto& params = Params().GetConsensus();
    BOOST_REQUIRE(!params.fPowNoRetargeting);
    const int64_t T = params.nPowTargetSpacing;
    // Mostly faster than schedule so ASERT tightens the target; the 3*T gap
    // triggers the regtest min-difficulty rule.
    const std::vector<int64_t> gaps{T / 4, T / 2, T / 8, T, T / 4, T / 3, 3 * T, T / 4, T / 2, T / 8, T / 4, T / 2};

    // The same timestamps on an all-native chain: index entries carrying only what ASERT reads.
    std::vector<std::unique_ptr<CBlockIndex>> native_chain;
    const CBlockIndex* genesis = Index(TipHash());
    BOOST_REQUIRE(genesis && genesis->nHeight == 0);
    const auto extend_native = [&](uint64_t time, uint32_t bits) {
        auto next = std::make_unique<CBlockIndex>();
        next->pprev = native_chain.empty() ? nullptr : native_chain.back().get();
        next->nHeight = native_chain.empty() ? 0 : native_chain.back()->nHeight + 1;
        next->nTime = time;
        next->nBits = bits;
        next->BuildSkip();
        native_chain.push_back(std::move(next));
    };
    extend_native(genesis->nTime, genesis->nBits);

    std::set<uint32_t> seen_bits;
    for (size_t i = 0; i < gaps.size(); ++i) {
        CBlockHeader candidate;
        candidate.nTime = native_chain.back()->nTime + gaps[i];
        const uint32_t native_bits = GetNextWorkRequired(native_chain.back().get(), &candidate, params);
        seen_bits.insert(native_bits);

        auto block = MakeUniqueBlock(TipHash(), candidate.nTime);
        BOOST_CHECK_EQUAL(block->nBits, native_bits);
        if (i % 2 == 0) {
            FinalizeAuxPow(block, /*extra_parents=*/0);
        } else {
            FinalizeNative(block);
        }
        BOOST_REQUIRE(AcceptBlock(block));
        BOOST_REQUIRE(TipHash() == block->GetHash());
        extend_native(candidate.nTime, native_bits);
    }
    // ASERT moved the target and the min-difficulty rule reset it at least once.
    BOOST_CHECK_GT(seen_bits.size(), 2U);

    // An AuxPoW block claiming any other target is rejected like a native one.
    const uint64_t next_time = native_chain.back()->nTime + T / 4;
    auto wrong = MakeUniqueBlock(TipHash(), next_time);
    const uint32_t required = wrong->nBits;
    wrong->nBits = UintToArith256(params.powLimit).GetCompact();
    BOOST_REQUIRE(wrong->nBits != required);
    FinalizeAuxPow(wrong, /*extra_parents=*/0);
    BlockValidationState state;
    std::vector<CBlockHeader> headers{*wrong};
    BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-diffbits");
}

BOOST_AUTO_TEST_SUITE_END()
