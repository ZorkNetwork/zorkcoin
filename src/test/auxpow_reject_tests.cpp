// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/chainwork.h>
#include <auxpow/check.h>
#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_header.h>
#include <auxpow/kaspa_merkle.h>
#include <auxpow/kaspa_pow.h>
#include <auxpow/kaspa_tx.h>
#include <auxpow/version.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/data/auxpow/kaspa_goldens.txt.h>
#include <test/util/auxpow.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <map>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace auxpow;
using namespace auxpow::test;

BOOST_FIXTURE_TEST_SUITE(auxpow_reject_tests, BasicTestingSetup)

static CBlockHeader MakeAuxHdr()
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr;
    hdr.nVersion = MakeAuxPowVersion(0x20000000);
    hdr.hashPrevBlock = uint256::ZERO;
    hdr.hashMerkleRoot = uint256::ZERO;
    hdr.nTime = 1296688602ull * 1000;
    hdr.nBits = 0x207fffff;
    hdr.nNonce = MakeAuxPowNonce(params.auxpow.nChainId);
    return hdr;
}

static std::vector<unsigned char> MakeMMRecord(const uint256& root_internal, uint32_t merkle_size, uint32_t merkle_nonce)
{
    std::vector<unsigned char> rec;
    rec.insert(rec.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + 4);
    uint256 rev = root_internal;
    std::reverse(rev.begin(), rev.end());
    rec.insert(rec.end(), rev.begin(), rev.end());
    WriteLE32Vec(rec, merkle_size);
    WriteLE32Vec(rec, merkle_nonce);
    return rec;
}

static void SetPayloadExtra(KaspaTransaction& tx, const std::vector<unsigned char>& extra)
{
    tx.payload.assign(19, 0);
    tx.payload.insert(tx.payload.end(), extra.begin(), extra.end());
}

static CAuxPow GrindValid(const CBlockHeader& hdr)
{
    const auto& params = Params().GetConsensus();
    CAuxPow aux = MakeStructuralAuxPow(hdr, /*kaspa_bits=*/0x207fffff);
    const DualTargets t = ComputeDualTargets(hdr.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    std::string err;
    BOOST_REQUIRE_MESSAGE(CheckAuxPow(hdr, aux, params, &err), err);
    return aux;
}

static void ExpectCheckFail(const CBlockHeader& hdr, const CAuxPow& aux, const Consensus::Params& params, const std::string& want)
{
    std::string err;
    BOOST_CHECK(!CheckAuxPow(hdr, aux, params, &err));
    BOOST_CHECK_EQUAL(err, want);
}

static void AppendU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char buf[2];
    WriteLE16(buf, v);
    out.insert(out.end(), buf, buf + 2);
}

static void AppendU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char buf[8];
    WriteLE64(buf, v);
    out.insert(out.end(), buf, buf + 8);
}

BOOST_AUTO_TEST_CASE(mm_record_placement)
{
    const uint256 root = uint256::ONE;
    const auto rec = MakeMMRecord(root, /*merkle_size=*/1, /*merkle_nonce=*/0);
    BOOST_REQUIRE_EQUAL(rec.size(), 44u);

    uint256 got;
    uint32_t sz = 0, nonce = 0;
    std::string err;
    uint256 expect_rev = root;
    std::reverse(expect_rev.begin(), expect_rev.end());

    std::vector<unsigned char> before = {0x11, 0x22, 0x33};
    before.insert(before.end(), rec.begin(), rec.end());
    BOOST_CHECK(FindMergedMiningRecord(before, got, sz, nonce, &err));
    BOOST_CHECK(got == expect_rev);
    BOOST_CHECK_EQUAL(sz, 1u);
    BOOST_CHECK_EQUAL(nonce, 0u);

    std::vector<unsigned char> after = rec;
    after.insert(after.end(), {0x44, 0x55});
    BOOST_CHECK(FindMergedMiningRecord(after, got, sz, nonce, &err));
    BOOST_CHECK(got == expect_rev);

    std::vector<unsigned char> both = {0xaa};
    both.insert(both.end(), rec.begin(), rec.end());
    both.push_back(0xbb);
    BOOST_CHECK(FindMergedMiningRecord(both, got, sz, nonce, &err));
    BOOST_CHECK(got == expect_rev);

    std::vector<unsigned char> dup = rec;
    dup.insert(dup.end(), rec.begin(), rec.end());
    BOOST_CHECK(!FindMergedMiningRecord(dup, got, sz, nonce, &err));
    BOOST_CHECK_EQUAL(err, "merged-mining magic not unique");

    // Magic inside the 32-byte reversed root is a second occurrence → not unique.
    std::vector<unsigned char> in_root;
    in_root.insert(in_root.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + 4);
    in_root.insert(in_root.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + 4);
    in_root.insert(in_root.end(), 28, 0);
    WriteLE32Vec(in_root, 1);
    WriteLE32Vec(in_root, 0);
    BOOST_CHECK(!FindMergedMiningRecord(in_root, got, sz, nonce, &err));
    BOOST_CHECK_EQUAL(err, "merged-mining magic not unique");

    std::vector<unsigned char> truncated(rec.begin(), rec.begin() + 10);
    BOOST_CHECK(!FindMergedMiningRecord(truncated, got, sz, nonce, &err));
    BOOST_CHECK_EQUAL(err, "merged-mining record truncated");

    std::vector<unsigned char> empty;
    BOOST_CHECK(!FindMergedMiningRecord(empty, got, sz, nonce, &err));
    BOOST_CHECK_EQUAL(err, "merged-mining magic missing");
}

BOOST_AUTO_TEST_CASE(mm_record_checkauxpow_prefix_suffix)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr = MakeAuxHdr();

    auto try_extra = [&](const std::vector<unsigned char>& extra, bool expect_ok, const std::string& want_err) {
        CAuxPow aux = MakeStructuralAuxPow(hdr, 0x207fffff);
        SetPayloadExtra(aux.coinbase_tx, extra);
        aux.peer_header.hash_merkle_root = KaspaTransactionHash(aux.coinbase_tx);
        const DualTargets t = ComputeDualTargets(hdr.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
        BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
        std::string err;
        const bool ok = CheckAuxPow(hdr, aux, params, &err);
        BOOST_CHECK_MESSAGE(ok == expect_ok, err);
        if (!expect_ok) BOOST_CHECK_EQUAL(err, want_err);
    };

    const auto rec = MakeMMRecord(hdr.GetHash(), 1, 0);
    std::vector<unsigned char> before = {0x01, 0x02};
    before.insert(before.end(), rec.begin(), rec.end());
    try_extra(before, true, "");

    std::vector<unsigned char> after = rec;
    after.push_back(0x03);
    try_extra(after, true, "");

    std::vector<unsigned char> both = {0x01};
    both.insert(both.end(), rec.begin(), rec.end());
    both.push_back(0x02);
    try_extra(both, true, "");

    std::vector<unsigned char> dup = rec;
    dup.insert(dup.end(), rec.begin(), rec.end());
    try_extra(dup, false, "merged-mining magic not unique");

    try_extra(MakeMMRecord(uint256::ZERO, 1, 0), false, "merged-mining root mismatch");
    try_extra(MakeMMRecord(hdr.GetHash(), /*merkle_size=*/2, 0), false, "merkle_size mismatch");
}

BOOST_AUTO_TEST_CASE(mm_nchainindex_mismatch)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr = MakeAuxHdr();
    CAuxPow aux = GrindValid(hdr);
    aux.nChainIndex = 1;
    ExpectCheckFail(hdr, aux, params, "nChainIndex mismatch");
}

BOOST_AUTO_TEST_CASE(mm_record_in_script_public_key_is_ignored)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr = MakeAuxHdr();
    CAuxPow aux = MakeStructuralAuxPow(hdr, 0x207fffff);
    const auto rec = MakeMMRecord(hdr.GetHash(), 1, 0);
    BOOST_REQUIRE_EQUAL(rec.size(), 44u);
    aux.coinbase_tx.payload.assign(19 + 44, 0);
    aux.coinbase_tx.payload[18] = 44;
    std::memcpy(aux.coinbase_tx.payload.data() + 19, rec.data(), rec.size());
    aux.peer_header.hash_merkle_root = KaspaTransactionHash(aux.coinbase_tx);
    const DualTargets t = ComputeDualTargets(hdr.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    ExpectCheckFail(hdr, aux, params, "merged-mining magic missing");
}

BOOST_AUTO_TEST_CASE(checkauxpow_reject_strings)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr = MakeAuxHdr();
    CAuxPow aux = GrindValid(hdr);

    {
        Consensus::Params inactive = params;
        inactive.auxpow.fGenesisActive = false;
        ExpectCheckFail(hdr, aux, inactive, "auxpow not active");
    }

    {
        CBlockHeader native = hdr;
        native.nVersion = 0x20000000;
        ExpectCheckFail(native, aux, params, "auxpow bit not set");
    }

    {
        CBlockHeader bad_id = hdr;
        bad_id.nNonce = MakeAuxPowNonce(static_cast<uint16_t>(params.auxpow.nChainId ^ 1));
        ExpectCheckFail(bad_id, aux, params, "auxpow chain id mismatch");
    }

    {
        CBlockHeader bad_marker = hdr;
        bad_marker.nNonce ^= uint64_t{1} << 40;
        ExpectCheckFail(bad_marker, aux, params, "auxpow nonce marker mismatch");
    }

    {
        CBlockHeader zero_nonce = hdr;
        zero_nonce.nNonce = 0;
        ExpectCheckFail(zero_nonce, aux, params, "auxpow nonce marker mismatch");
    }

    {
        CAuxPow bad = aux;
        bad.version = 2;
        ExpectCheckFail(hdr, bad, params, "auxpow version must be 1");
    }

    {
        CAuxPow bad = aux;
        bad.peer_header.version = 1;
        ExpectCheckFail(hdr, bad, params, "peer header version must be 2");
    }

    {
        CAuxPow bad = aux;
        bad.peer_header.parents_by_level.clear();
        ExpectCheckFail(hdr, bad, params, "peer_header serialize failed");
    }

    {
        CAuxPow bad = aux;
        bad.coinbase_tx.version = 0;
        ExpectCheckFail(hdr, bad, params, "coinbase version must be 1");
    }

    {
        CAuxPow bad = aux;
        bad.coinbase_tx.gas = 1;
        ExpectCheckFail(hdr, bad, params, "coinbase gas must be 0");
    }

    {
        CAuxPow bad = aux;
        bad.coinbase_tx.storage_mass = 1;
        ExpectCheckFail(hdr, bad, params, "coinbase storage_mass must be 0");
    }

    {
        CAuxPow bad = aux;
        std::memset(bad.coinbase_tx.subnetwork_id, 0, KASPA_SUBNETWORK_ID_SIZE);
        ExpectCheckFail(hdr, bad, params, "not coinbase subnetwork");
    }

    {
        CAuxPow bad = aux;
        bad.coinbase_tx.payload.assign(18, 0);
        ExpectCheckFail(hdr, bad, params, "coinbase payload length out of range");
    }

    {
        CAuxPow bad = aux;
        bad.peer_header.bits = 0x01800000;
        ExpectCheckFail(hdr, bad, params, "kaspa compact bits negative");
    }

    {
        CAuxPow bad = aux;
        bad.peer_header.bits = 0x01000000;
        ExpectCheckFail(hdr, bad, params, "kaspa compact bits zero");
    }

    {
        CBlockHeader bad_bits = hdr;
        bad_bits.nBits = 0;
        ExpectCheckFail(bad_bits, aux, params, "invalid zork nBits");
    }

    {
        Consensus::Params derived_zero = params;
        derived_zero.auxpow.nFloorMultiplier = 0;
        ExpectCheckFail(hdr, aux, derived_zero, "derived auxpow target is zero");
    }

    {
        CAuxPow bad = aux;
        bad.peer_header.hash_merkle_root = uint256::ONE;
        const DualTargets t = ComputeDualTargets(hdr.nBits, bad.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
        BOOST_REQUIRE(GrindPeerToMeetBoth(bad.peer_header, t.T_kd, t.T_floor));
        ExpectCheckFail(hdr, bad, params, "kaspa tx merkle root mismatch");
    }
}

BOOST_AUTO_TEST_CASE(dual_target_reject_strings)
{
    const auto& params = Params().GetConsensus();
    constexpr uint32_t EASY = 0x207fffff;
    constexpr uint32_t HARDER = 0x1f0fffff;

    auto run = [&](uint32_t zork_bits, uint32_t kaspa_bits, const WorkFlags& want, const std::string& err_want) {
        CBlockHeader hdr = MakeAuxHdr();
        hdr.nBits = zork_bits;
        const DualTargets t = ComputeDualTargets(zork_bits, kaspa_bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
        CAuxPow aux = MakeStructuralAuxPow(hdr, kaspa_bits);
        BOOST_REQUIRE(GrindPeerNonce(aux.peer_header, [&](const uint256& h) {
            return FlagsEq(ClassifyPow(h, t), want);
        }));
        ExpectCheckFail(hdr, aux, params, err_want);
    };

    run(EASY, EASY, {/*K*/ false, /*KD*/ false, /*Z*/ false, /*ZF*/ false}, "peer pow exceeds T_K");
    run(EASY, EASY, {true, false, true, true}, "peer pow exceeds T_K/3000");
    run(HARDER, EASY, {true, true, true, false}, "peer pow exceeds T_Z/4");
}

BOOST_AUTO_TEST_CASE(size_limit_components)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr = MakeAuxHdr();
    CAuxPow aux = MakeStructuralAuxPow(hdr, 0x207fffff);
    std::string err;

    {
        CAuxPow bad = aux;
        bad.vMerkleBranch.assign(params.auxpow.nMaxTxMerkleBranchHashes + 1, uint256::ZERO);
        BOOST_CHECK(!CheckAuxPowSizeLimits(bad, params.auxpow, &err));
        BOOST_CHECK_EQUAL(err, "tx merkle branch too long");
    }
    {
        CAuxPow bad = aux;
        bad.vChainMerkleBranch.assign(params.auxpow.nMaxChainMerkleBranchHashes + 1, uint256::ZERO);
        BOOST_CHECK(!CheckAuxPowSizeLimits(bad, params.auxpow, &err));
        BOOST_CHECK_EQUAL(err, "chain merkle branch too long");
    }
    {
        Consensus::Params::AuxPow lim = params.auxpow;
        lim.nMaxChainMerkleBranchHashes = 40;
        CAuxPow bad = aux;
        bad.vChainMerkleBranch.assign(31, uint256::ZERO);
        BOOST_CHECK(!CheckAuxPowSizeLimits(bad, lim, &err));
        BOOST_CHECK_EQUAL(err, "chain merkle branch exceeds Dogecoin limit");
    }
    {
        CAuxPow fat = aux;
        size_t extra = 1;
        std::vector<unsigned char> header_bytes;
        for (; extra < 64; ++extra) {
            fat = aux;
            InflatePeerParents(fat.peer_header, extra);
            BOOST_REQUIRE(SerializeKaspaHeader(fat.peer_header, header_bytes));
            if (header_bytes.size() > params.auxpow.nMaxPeerHeaderSize) break;
        }
        BOOST_REQUIRE(header_bytes.size() > params.auxpow.nMaxPeerHeaderSize);
        BOOST_CHECK(!CheckAuxPowSizeLimits(fat, params.auxpow, &err));
        BOOST_CHECK_EQUAL(err, "peer_header too large");
    }
    {
        CAuxPow fat = aux;
        fat.coinbase_tx.payload.assign(380, 0xab);
        std::vector<unsigned char> tx_bytes;
        BOOST_REQUIRE(SerializeKaspaTransaction(fat.coinbase_tx, tx_bytes));
        BOOST_REQUIRE_GT(tx_bytes.size(), params.auxpow.nMaxCoinbaseTxSize);
        BOOST_CHECK(!CheckAuxPowSizeLimits(fat, params.auxpow, &err));
        BOOST_CHECK_EQUAL(err, "coinbase_tx too large");
    }
    {
        CAuxPow fat = aux;
        std::vector<unsigned char> header_bytes, tx_bytes;
        size_t extra = 0;
        for (;;) {
            CAuxPow trial = fat;
            InflatePeerParents(trial.peer_header, extra + 1);
            BOOST_REQUIRE(SerializeKaspaHeader(trial.peer_header, header_bytes));
            if (header_bytes.size() > params.auxpow.nMaxPeerHeaderSize) break;
            ++extra;
        }
        InflatePeerParents(fat.peer_header, extra);
        size_t pay = fat.coinbase_tx.payload.size();
        for (;;) {
            CAuxPow trial = fat;
            trial.coinbase_tx.payload.assign(pay + 1, 0xab);
            BOOST_REQUIRE(SerializeKaspaTransaction(trial.coinbase_tx, tx_bytes));
            if (tx_bytes.size() > params.auxpow.nMaxCoinbaseTxSize) break;
            ++pay;
        }
        fat.coinbase_tx.payload.assign(pay, 0xab);
        fat.vMerkleBranch.assign(params.auxpow.nMaxTxMerkleBranchHashes, uint256::ONE);
        fat.vChainMerkleBranch.assign(params.auxpow.nMaxChainMerkleBranchHashes, uint256::ONE);
        BOOST_REQUIRE(SerializeKaspaHeader(fat.peer_header, header_bytes));
        BOOST_REQUIRE(SerializeKaspaTransaction(fat.coinbase_tx, tx_bytes));
        BOOST_REQUIRE_LE(header_bytes.size(), params.auxpow.nMaxPeerHeaderSize);
        BOOST_REQUIRE_LE(tx_bytes.size(), params.auxpow.nMaxCoinbaseTxSize);
        BOOST_REQUIRE_GT(GetSerializeSizeAuxPow(fat), params.auxpow.nMaxSerializedSize);
        BOOST_CHECK(!CheckAuxPowSizeLimits(fat, params.auxpow, &err));
        BOOST_CHECK_EQUAL(err, "auxpow header extension exceeds max serialized size");
    }
}

BOOST_AUTO_TEST_CASE(unserialize_component_caps)
{
    CAuxPow lean;
    lean.version = 1;
    InitLeanPeerHeader(lean.peer_header, 0x207fffff);
    lean.coinbase_tx.version = 1;
    std::memcpy(lean.coinbase_tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    lean.coinbase_tx.payload.assign(19, 0);
    std::vector<unsigned char> header_bytes, tx_bytes;
    BOOST_REQUIRE(SerializeKaspaHeader(lean.peer_header, header_bytes));
    BOOST_REQUIRE(SerializeKaspaTransaction(lean.coinbase_tx, tx_bytes));

    {
        DataStream ss{};
        ss << lean.version << header_bytes;
        WriteCompactSize(ss, MAX_AUXPOW_COINBASE_TX_SIZE + 1);
        CAuxPow out;
        BOOST_CHECK_THROW(ss >> out, std::ios_base::failure);
    }
    {
        DataStream ss{};
        ss << lean.version << header_bytes << tx_bytes;
        WriteCompactSize(ss, MAX_AUXPOW_TX_MERKLE_BRANCH_HASHES + 1);
        CAuxPow out;
        BOOST_CHECK_THROW(ss >> out, std::ios_base::failure);
    }
    {
        DataStream ss{};
        ss << lean.version << header_bytes << tx_bytes;
        WriteCompactSize(ss, 0);
        WriteCompactSize(ss, MAX_AUXPOW_CHAIN_MERKLE_BRANCH_HASHES + 1);
        CAuxPow out;
        BOOST_CHECK_THROW(ss >> out, std::ios_base::failure);
    }
    {
        CAuxPow fat = lean;
        std::vector<unsigned char> hb, tb;
        size_t extra = 0;
        for (;;) {
            CAuxPow trial = fat;
            InflatePeerParents(trial.peer_header, extra + 1);
            BOOST_REQUIRE(SerializeKaspaHeader(trial.peer_header, hb));
            if (hb.size() > MAX_AUXPOW_PEER_HEADER_SIZE) break;
            ++extra;
        }
        InflatePeerParents(fat.peer_header, extra);
        size_t pay = fat.coinbase_tx.payload.size();
        for (;;) {
            CAuxPow trial = fat;
            trial.coinbase_tx.payload.assign(pay + 1, 0xab);
            BOOST_REQUIRE(SerializeKaspaTransaction(trial.coinbase_tx, tb));
            if (tb.size() > MAX_AUXPOW_COINBASE_TX_SIZE) break;
            ++pay;
        }
        fat.coinbase_tx.payload.assign(pay, 0xab);
        fat.vMerkleBranch.assign(MAX_AUXPOW_TX_MERKLE_BRANCH_HASHES, uint256::ONE);
        fat.vChainMerkleBranch.assign(MAX_AUXPOW_CHAIN_MERKLE_BRANCH_HASHES, uint256::ONE);
        BOOST_REQUIRE_GT(GetSerializeSizeAuxPow(fat), MAX_AUXPOW_SERIALIZED_SIZE);
        DataStream ss{};
        ss << fat;
        CAuxPow out;
        BOOST_CHECK_THROW(ss >> out, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(chainwork_zero_and_ref)
{
    BOOST_CHECK(GetAuxPowBlockProof(/*nBits=*/0, 100, 8192) == 0);
    BOOST_CHECK(GetAuxPowBlockProof(0x207fffff, 100, /*chainwork_ref=*/0) == 0);
    const uint32_t negative_bits = 0x04800001;
    BOOST_CHECK(GetAuxPowBlockProof(negative_bits, 100, 8192) == 0);
}

BOOST_AUTO_TEST_CASE(expanded_parents_and_expected_index)
{
    KaspaHeader h;
    BOOST_CHECK_EQUAL(h.ExpandedLevelCount(), 0u);
    h.parents_by_level.push_back(KaspaParentRun{2, {KaspaHashFromU64(1)}});
    h.parents_by_level.push_back(KaspaParentRun{4, {KaspaHashFromU64(2)}});
    BOOST_CHECK_EQUAL(h.ExpandedLevelCount(), 4u);
    const auto expanded = h.ExpandedParents();
    BOOST_REQUIRE_EQUAL(expanded.size(), 4u);
    BOOST_CHECK(expanded[0][0] == KaspaHashFromU64(1));
    BOOST_CHECK(expanded[1][0] == KaspaHashFromU64(1));
    BOOST_CHECK(expanded[2][0] == KaspaHashFromU64(2));
    BOOST_CHECK(expanded[3][0] == KaspaHashFromU64(2));

    BOOST_CHECK_EQUAL(GetExpectedIndex(/*nNonce=*/123, /*nChainId=*/0x525a, /*h=*/32), 0);
    BOOST_CHECK_LT(GetExpectedIndex(123, 0x525a, /*h=*/8), 256);

    const uint256 leaf = uint256::ONE;
    const uint256 sib = uint256::ZERO;
    const uint256 even = ComputeAuxChainRoot(leaf, {sib}, /*index=*/0);
    const uint256 odd = ComputeAuxChainRoot(leaf, {sib}, /*index=*/1);
    BOOST_CHECK(even != odd);
    BOOST_CHECK(even == AuxChainMerkleHash(leaf, sib));
    BOOST_CHECK(odd == AuxChainMerkleHash(sib, leaf));
}

BOOST_AUTO_TEST_CASE(rle_and_compact_bits_errors)
{
    KaspaHeader h;
    std::string err;
    BOOST_CHECK(!h.IsRleCanonical(&err));
    BOOST_CHECK_EQUAL(err, "empty parents_by_level");

    h.parents_by_level.push_back(KaspaParentRun{0, {KaspaHashFromU64(1)}});
    BOOST_CHECK(!h.IsRleCanonical(&err));
    BOOST_CHECK_EQUAL(err, "first cum_count is 0");

    h.parents_by_level[0].cum_count = 2;
    h.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(2)}});
    BOOST_CHECK(!h.IsRleCanonical(&err));
    BOOST_CHECK_EQUAL(err, "cum_count not strictly increasing");

    h.parents_by_level[1] = KaspaParentRun{4, {KaspaHashFromU64(1)}};
    BOOST_CHECK(!h.IsRleCanonical(&err));
    BOOST_CHECK_EQUAL(err, "adjacent RLE runs identical");

    uint256 target;
    BOOST_CHECK(!DecodeKaspaCompactBits(0x1e8ffff0, target, &err));
    BOOST_CHECK_EQUAL(err, "kaspa compact bits negative");
    BOOST_CHECK(!DecodeKaspaCompactBits(0x01000000, target, &err));
    BOOST_CHECK_EQUAL(err, "kaspa compact bits zero");
    BOOST_CHECK(!DecodeKaspaCompactBits(0xff7fffff, target, &err));
    BOOST_CHECK_EQUAL(err, "kaspa compact bits overflow");
}

BOOST_AUTO_TEST_CASE(kaspa_header_tx_parse_failures)
{
    KaspaHeader h;
    size_t consumed = 0;
    std::string err;
    std::vector<unsigned char> empty;
    BOOST_CHECK(!DeserializeKaspaHeader(empty, h, consumed, &err));
    BOOST_CHECK_EQUAL(err, "kaspa header truncated");

    {
        std::vector<unsigned char> too_many_runs;
        AppendU16(too_many_runs, 2);
        AppendU64(too_many_runs, 256);
        BOOST_CHECK(!DeserializeKaspaHeader(too_many_runs, h, consumed, &err));
        BOOST_CHECK_EQUAL(err, "too many parent runs");
    }
    {
        std::vector<unsigned char> too_many_parents;
        AppendU16(too_many_parents, 2);
        AppendU64(too_many_parents, 1);
        too_many_parents.push_back(1);
        AppendU64(too_many_parents, 1025);
        BOOST_CHECK(!DeserializeKaspaHeader(too_many_parents, h, consumed, &err));
        BOOST_CHECK_EQUAL(err, "too many parents in run");
    }

    KaspaHeader lean;
    InitLeanPeerHeader(lean, 0x207fffff);
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeKaspaHeader(lean, wire));
    {
        auto blue_long = wire;
        BOOST_REQUIRE_GE(blue_long.size(), 40u);
        blue_long.resize(blue_long.size() - 32); // drop pruning_point
        BOOST_REQUIRE_GE(blue_long.size(), 8u);
        WriteLE64(blue_long.data() + blue_long.size() - 8, 25);
        blue_long.insert(blue_long.end(), 25, 0);
        blue_long.insert(blue_long.end(), 32, 0);
        BOOST_CHECK(!DeserializeKaspaHeader(blue_long, h, consumed, &err));
        BOOST_CHECK_EQUAL(err, "blue_work length > 24");
    }
    {
        auto trunc_blue = wire;
        trunc_blue.resize(wire.size() - 32);
        BOOST_REQUIRE_GE(trunc_blue.size(), 8u);
        WriteLE64(trunc_blue.data() + trunc_blue.size() - 8, 5);
        trunc_blue.insert(trunc_blue.end(), 2, 0);
        BOOST_CHECK(!DeserializeKaspaHeader(trunc_blue, h, consumed, &err));
        BOOST_CHECK_EQUAL(err, "blue_work truncated");
    }

    KaspaTransaction tx;
    BOOST_CHECK(!DeserializeKaspaTransaction(empty, tx, consumed, &err));
    BOOST_CHECK_EQUAL(err, "kaspa tx truncated");

    {
        std::vector<unsigned char> has_inputs;
        AppendU16(has_inputs, 1);
        AppendU64(has_inputs, 1);
        BOOST_CHECK(!DeserializeKaspaTransaction(has_inputs, tx, consumed, &err));
        BOOST_CHECK_EQUAL(err, "kaspa auxpow tx must have 0 inputs");
    }
    {
        std::vector<unsigned char> many_out;
        AppendU16(many_out, 1);
        AppendU64(many_out, 0);
        AppendU64(many_out, 65);
        BOOST_CHECK(!DeserializeKaspaTransaction(many_out, tx, consumed, &err));
        BOOST_CHECK_EQUAL(err, "too many outputs");
    }
    {
        std::vector<unsigned char> long_payload;
        AppendU16(long_payload, 1);
        AppendU64(long_payload, 0);
        AppendU64(long_payload, 0);
        AppendU64(long_payload, 0); // lock_time
        long_payload.insert(long_payload.end(), KASPA_SUBNETWORK_ID_SIZE, 0);
        AppendU64(long_payload, 0); // gas
        AppendU64(long_payload, 2049);
        BOOST_CHECK(!DeserializeKaspaTransaction(long_payload, tx, consumed, &err));
        BOOST_CHECK_EQUAL(err, "var bytes too long");
    }
    {
        std::vector<unsigned char> trunc_var;
        AppendU16(trunc_var, 1);
        AppendU64(trunc_var, 0);
        AppendU64(trunc_var, 0);
        AppendU64(trunc_var, 0);
        trunc_var.insert(trunc_var.end(), KASPA_SUBNETWORK_ID_SIZE, 0);
        AppendU64(trunc_var, 0);
        AppendU64(trunc_var, 4);
        trunc_var.push_back(0x01);
        BOOST_CHECK(!DeserializeKaspaTransaction(trunc_var, tx, consumed, &err));
        BOOST_CHECK_EQUAL(err, "var bytes truncated");
    }
    {
        std::vector<unsigned char> bad_cov;
        AppendU16(bad_cov, 1);
        AppendU64(bad_cov, 0);
        AppendU64(bad_cov, 1);
        AppendU64(bad_cov, 0); // value
        AppendU16(bad_cov, 0); // script_version
        AppendU64(bad_cov, 0); // empty script
        bad_cov.push_back(2);  // invalid covenant flag
        BOOST_CHECK(!DeserializeKaspaTransaction(bad_cov, tx, consumed, &err));
        BOOST_CHECK_EQUAL(err, "invalid covenant flag");
    }

    uint64_t blue = 0, subsidy = 0;
    uint16_t spk_ver = 0;
    std::vector<unsigned char> spk, extra;
    std::vector<unsigned char> payload(10, 0);
    BOOST_CHECK(!ParseKaspaCoinbasePayload(payload, blue, subsidy, spk_ver, spk, extra, &err));
    BOOST_CHECK_EQUAL(err, "payload too short");

    std::vector<unsigned char> trunc_spk(20, 0);
    trunc_spk[18] = 10;
    BOOST_CHECK(!ParseKaspaCoinbasePayload(trunc_spk, blue, subsidy, spk_ver, spk, extra, &err));
    BOOST_CHECK_EQUAL(err, "payload script truncated");
}

BOOST_AUTO_TEST_CASE(kaspa_goldens_file_matches_hardcoded)
{
    const auto& goldens{::test::data::kaspa_goldens};
    std::istringstream in{std::string{reinterpret_cast<const char*>(goldens.data()), goldens.size()}};
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    BOOST_CHECK(KaspaHashFromHex(kv["header_pre_pow_hash"]) ==
                KaspaHashFromHex("3a43e4da7749ef6071df024308306846a1c5d7acfbeb9c6df76363e3f940df0b"));
    BOOST_CHECK(KaspaHashFromHex(kv["header_hash"]) ==
                KaspaHashFromHex("dc4426bec5c022cee4f05c1983b2aa56b3d91138d3419cfab2654f1a0078c1e8"));
    BOOST_CHECK(KaspaHashFromHex(kv["powhash_out"]) ==
                KaspaHashFromHex("2fb72b63dd0dd0d82b00cd9f83d4eca0710b7eb8c05966888f39ebc578978abf"));
    BOOST_CHECK(KaspaHashFromHex(kv["heavyhash_out"]) ==
                KaspaHashFromHex("ad4ded01225705fea9aa043dd0a4e22ca28068bb41d5c6e06d35ca507d5656c7"));
    BOOST_CHECK(KaspaHashFromHex(kv["coinbase_tx_hash"]) ==
                KaspaHashFromHex("85a2bc47826ae53354783eb2d16d013a8432da8a32f3350d42e38c42767b3877"));
    BOOST_CHECK(KaspaHashFromHex(kv["merkle_two"]) ==
                KaspaHashFromHex("29bad7e6df870b3924055095dc73c84dea97c336afdc43509875a2e7f215f6c6"));
}

BOOST_AUTO_TEST_CASE(kaspa_header_truncated_at_every_offset)
{
    KaspaHeader full;
    InitLeanPeerHeader(full, EASIEST_KASPA_BITS);
    full.parents_by_level.push_back(KaspaParentRun{3, {KaspaHashFromU64(7), KaspaHashFromU64(8)}});
    full.blue_work[21] = 0x01;
    full.blue_work[23] = 0xff;
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeKaspaHeader(full, wire));

    KaspaHeader out;
    size_t consumed = 0;
    std::string err;
    BOOST_REQUIRE(DeserializeKaspaHeader(wire, out, consumed, &err));
    BOOST_CHECK_EQUAL(consumed, wire.size());
    std::vector<unsigned char> again;
    BOOST_REQUIRE(SerializeKaspaHeader(out, again));
    BOOST_CHECK(again == wire);

    for (size_t len = 0; len < wire.size(); ++len) {
        const std::span<const unsigned char> prefix{wire.data(), len};
        BOOST_CHECK_MESSAGE(!DeserializeKaspaHeader(prefix, out, consumed, &err), "prefix " << len);
        BOOST_CHECK_MESSAGE(err == "kaspa header truncated" || err == "blue_work truncated", "prefix " << len << ": " << err);
    }

    // Trailing bytes are left for the caller (CAuxPow rejects them).
    auto trailing = wire;
    trailing.push_back(0);
    BOOST_REQUIRE(DeserializeKaspaHeader(trailing, out, consumed, &err));
    BOOST_CHECK_EQUAL(consumed, wire.size());

    // Well-formed bytes that decode to a non-canonical RLE are rejected.
    std::vector<unsigned char> bad_wire = wire;
    const size_t second_run_offset = 2 + 8 + 1 + 8 + 32;
    BOOST_REQUIRE_EQUAL(bad_wire[second_run_offset], 3);
    bad_wire[second_run_offset] = 1;
    BOOST_CHECK(!DeserializeKaspaHeader(bad_wire, out, consumed, &err));
    BOOST_CHECK_EQUAL(err, "cum_count not strictly increasing");
}

BOOST_AUTO_TEST_CASE(kaspa_tx_truncated_at_every_offset)
{
    KaspaTransaction full;
    full.version = 1;
    KaspaTxOutput plain;
    plain.value = 5;
    plain.script = {0x51, 0x52};
    KaspaTxOutput covenant;
    covenant.value = 6;
    covenant.script_version = 1;
    covenant.script = {0x53};
    covenant.covenant.present = true;
    covenant.covenant.authorizing_input = 2;
    covenant.covenant.covenant_id = KaspaHashFromU64(9);
    full.outputs = {plain, covenant};
    full.lock_time = 3;
    std::memcpy(full.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    full.payload.assign(24, 0xab);
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeKaspaTransaction(full, wire));

    KaspaTransaction out;
    size_t consumed = 0;
    std::string err;
    BOOST_REQUIRE(DeserializeKaspaTransaction(wire, out, consumed, &err));
    BOOST_CHECK_EQUAL(consumed, wire.size());
    BOOST_CHECK(KaspaTransactionHash(out) == KaspaTransactionHash(full));
    BOOST_CHECK(out.outputs.at(1).covenant.present);
    BOOST_CHECK(out.outputs.at(1).covenant.covenant_id == covenant.covenant.covenant_id);

    for (size_t len = 0; len < wire.size(); ++len) {
        const std::span<const unsigned char> prefix{wire.data(), len};
        BOOST_CHECK_MESSAGE(!DeserializeKaspaTransaction(prefix, out, consumed, &err), "prefix " << len);
        BOOST_CHECK_MESSAGE(err == "kaspa tx truncated" || err == "var bytes truncated", "prefix " << len << ": " << err);
    }
}

BOOST_AUTO_TEST_CASE(kaspa_compact_bits_boundaries)
{
    // Valid encodings agree with Bitcoin's compact decoding.
    for (const uint32_t bits : {EASIEST_KASPA_BITS, 0x207fffffU, 0x220000ffU, 0x21000001U, 0x1d00ffffU, 0x03123456U, 0x02123456U, 0x01120000U, 0x04000001U}) {
        uint256 target;
        std::string err;
        BOOST_CHECK_MESSAGE(DecodeKaspaCompactBits(bits, target, &err), err);
        arith_uint256 expected;
        bool negative{false}, overflow{false};
        expected.SetCompact(bits, &negative, &overflow);
        BOOST_REQUIRE(!negative && !overflow);
        BOOST_CHECK_MESSAGE(target == ArithToUint256(expected), strprintf("bits %08x", bits));
    }

    uint256 easiest;
    BOOST_REQUIRE(DecodeKaspaCompactBits(EASIEST_KASPA_BITS, easiest));
    BOOST_CHECK(UintToArith256(easiest) == arith_uint256{0xffff} << 240);

    const std::vector<std::pair<uint32_t, std::string>> rejects{
        {0x21010000, "kaspa compact bits overflow"}, // one bit past the top byte
        {0x22000100, "kaspa compact bits overflow"},
        {0x23000001, "kaspa compact bits overflow"},
        {0xff000001, "kaspa compact bits overflow"}, // shift beyond 256 bits
        {0x23000000, "kaspa compact bits zero"},
        {0x01003456, "kaspa compact bits zero"}, // mantissa shifted out
        {0x00000000, "kaspa compact bits zero"},
        {0x21800000, "kaspa compact bits negative"},
    };
    for (const auto& [bits, want] : rejects) {
        uint256 target{uint256::ONE};
        std::string err;
        BOOST_CHECK_MESSAGE(!DecodeKaspaCompactBits(bits, target, &err), strprintf("bits %08x", bits));
        BOOST_CHECK_EQUAL(err, want);
        BOOST_CHECK(target.IsNull());
    }
}

BOOST_AUTO_TEST_SUITE_END()
