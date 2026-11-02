// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/check.h>
#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_pow.h>
#include <auxpow/version.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/auxpow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

using namespace auxpow;
using namespace auxpow::test;

BOOST_FIXTURE_TEST_SUITE(auxpow_check_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valid_solo_auxpow_regtest)
{
    const auto& params = Params().GetConsensus();
    CBlock block;
    block.nVersion = MakeAuxPowVersion(0x20000000);
    block.hashPrevBlock = uint256::ZERO;
    block.hashMerkleRoot = uint256::ZERO;
    block.nTime = 1296688602ull * 1000;
    block.nBits = 0x207fffff;
    block.nNonce = MakeAuxPowNonce(params.auxpow.nChainId);

    const uint256 hash_aux = block.GetHash();
    CAuxPow aux;
    aux.version = 1;
    aux.nChainIndex = 0;
    aux.coinbase_tx = MakeCoinbaseWithMM(hash_aux, /*merkle_size=*/1, /*merkle_nonce=*/0);
    const uint256 cb_hash = KaspaTransactionHash(aux.coinbase_tx);

    aux.peer_header.version = 2;
    aux.peer_header.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(9)}});
    aux.peer_header.hash_merkle_root = cb_hash;
    aux.peer_header.accepted_id_merkle_root = KaspaHashFromU64(3);
    aux.peer_header.utxo_commitment = KaspaHashFromU64(4);
    aux.peer_header.timestamp = 1'700'000'000'000ull;
    aux.peer_header.bits = 0x207fffff; // easy Kaspa target
    aux.peer_header.daa_score = 1;
    aux.peer_header.blue_score = 1;
    aux.peer_header.pruning_point = KaspaHashFromU64(5);

    uint256 T_K;
    BOOST_REQUIRE(DecodeKaspaCompactBits(aux.peer_header.bits, T_K));
    const uint256 T_kd = ArithToUint256(UintToArith256(T_K) / params.auxpow.nKaspaMultiplier);
    uint256 T_Z;
    {
        arith_uint256 bn;
        bool neg = false, over = false;
        bn.SetCompact(block.nBits, &neg, &over);
        T_Z = ArithToUint256(bn);
    }
    const uint256 T_floor = ArithToUint256(UintToArith256(T_Z) / params.auxpow.nFloorMultiplier);
    const uint256 limit = UintToArith256(T_kd) < UintToArith256(T_floor) ? T_kd : T_floor;

    bool found = false;
    for (uint64_t nonce = 0; nonce < 500000; ++nonce) {
        aux.peer_header.nonce = nonce;
        const uint256 pow = KaspaPeerPoW(aux.peer_header);
        if (UintToArith256(pow) <= UintToArith256(limit)) {
            found = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found, "failed to grind easy auxpow nonce");

    std::string err;
    BOOST_CHECK_MESSAGE(CheckAuxPow(block, aux, params, &err), err);

    block.auxpow = aux;
    DataStream ss{};
    ss << TX_WITH_WITNESS(block);
    CBlock block2;
    ss >> TX_WITH_WITNESS(block2);
    BOOST_CHECK(block2.auxpow.has_value());
    BOOST_CHECK(CheckAuxPow(block2, *block2.auxpow, params, &err));
}

static CBlock MakeEasyAuxPowHeader()
{
    const auto& params = Params().GetConsensus();
    CBlock block;
    block.nVersion = MakeAuxPowVersion(0x20000000);
    block.hashPrevBlock = uint256::ZERO;
    block.hashMerkleRoot = uint256::ZERO;
    block.nTime = 1296688602ull * 1000;
    block.nBits = 0x207fffff;
    block.nNonce = MakeAuxPowNonce(params.auxpow.nChainId);
    return block;
}

BOOST_AUTO_TEST_CASE(valid_two_leaf_auxpow_regtest)
{
    const auto& params = Params().GetConsensus();
    CBlock block = MakeEasyAuxPowHeader();
    constexpr uint32_t merkle_nonce = 7;
    CAuxPow aux = MakeTwoLeafAuxPow(block, /*kaspa_bits=*/0x207fffff, params.auxpow.nChainId, merkle_nonce);
    BOOST_CHECK_EQUAL(aux.vChainMerkleBranch.size(), 1u);
    BOOST_CHECK_EQUAL(aux.nChainIndex, GetExpectedIndex(merkle_nonce, params.auxpow.nChainId, /*h=*/1));
    const DualTargets t = ComputeDualTargets(block.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    std::string err;
    BOOST_CHECK_MESSAGE(CheckAuxPow(block, aux, params, &err), err);
}

BOOST_AUTO_TEST_CASE(two_leaf_wrong_sibling_rejected)
{
    const auto& params = Params().GetConsensus();
    CBlock block = MakeEasyAuxPowHeader();
    CAuxPow aux = MakeTwoLeafAuxPow(block, /*kaspa_bits=*/0x207fffff, params.auxpow.nChainId);
    const DualTargets t = ComputeDualTargets(block.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    aux.vChainMerkleBranch[0] = KaspaHashFromU64(12345);
    std::string err;
    BOOST_CHECK(!CheckAuxPow(block, aux, params, &err));
}

BOOST_AUTO_TEST_CASE(two_leaf_flipped_index_rejected)
{
    const auto& params = Params().GetConsensus();
    CBlock block = MakeEasyAuxPowHeader();
    CAuxPow aux = MakeTwoLeafAuxPow(block, /*kaspa_bits=*/0x207fffff, params.auxpow.nChainId);
    const DualTargets t = ComputeDualTargets(block.nBits, aux.peer_header.bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    BOOST_REQUIRE(GrindPeerToMeetBoth(aux.peer_header, t.T_kd, t.T_floor));
    aux.nChainIndex = 1 - aux.nChainIndex;
    std::string err;
    BOOST_CHECK(!CheckAuxPow(block, aux, params, &err));
}

BOOST_AUTO_TEST_CASE(rejects_missing_mm_magic)
{
    const auto& params = Params().GetConsensus();
    CBlockHeader hdr;
    hdr.nVersion = MakeAuxPowVersion(0x20000000);
    hdr.nNonce = MakeAuxPowNonce(params.auxpow.nChainId);
    hdr.nBits = 0x207fffff;
    CAuxPow aux;
    aux.version = 1;
    aux.peer_header.version = 2;
    aux.peer_header.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    aux.peer_header.bits = 0x207fffff;
    aux.coinbase_tx.version = 1;
    std::memcpy(aux.coinbase_tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    aux.coinbase_tx.payload.assign(19, 0);
    std::string err;
    BOOST_CHECK(!CheckAuxPow(hdr, aux, params, &err));
}

struct DualCase {
    const char* name;
    uint32_t zork_bits;
    uint32_t kaspa_bits;
    WorkFlags want;
    bool accept;
};

static void RunDualCase(const DualCase& c)
{
    const auto& params = Params().GetConsensus();
    CBlock block;
    block.nVersion = MakeAuxPowVersion(0x20000000);
    block.hashPrevBlock = uint256::ZERO;
    block.hashMerkleRoot = uint256::ZERO;
    block.nTime = 1296688602ull * 1000;
    block.nBits = c.zork_bits;
    block.nNonce = MakeAuxPowNonce(params.auxpow.nChainId);

    const DualTargets t = ComputeDualTargets(c.zork_bits, c.kaspa_bits, params.auxpow.nFloorMultiplier, params.auxpow.nKaspaMultiplier);
    CAuxPow aux = MakeStructuralAuxPow(block, c.kaspa_bits);
    BOOST_REQUIRE_MESSAGE(GrindPeerNonce(aux.peer_header, [&](const uint256& h) {
                              return FlagsEq(ClassifyPow(h, t), c.want);
                          }),
                          std::string("failed to grind dual-target band: ") + c.name);

    const WorkFlags got = ClassifyPow(KaspaPeerPoW(aux.peer_header), t);
    BOOST_REQUIRE(FlagsEq(got, c.want));

    std::string err;
    const bool ok = CheckAuxPow(block, aux, params, &err);
    BOOST_CHECK_MESSAGE(ok == c.accept, std::string(c.name) + ": " + err);
    if (c.accept) {
        BOOST_CHECK(got.le_TK && got.le_TK3000 && got.le_TZ4);
    } else {
        BOOST_CHECK(!(got.le_TK && got.le_TK3000 && got.le_TZ4));
    }
}

BOOST_AUTO_TEST_CASE(dual_target_permutations)
{
    // KD ⇒ K and ZF ⇒ Z. Bands that cannot exist for a bits pair are omitted.
    // 0x207fffff ≈ 2^255 (regtest). 0x1f0fffff ≈ 2^244.
    constexpr uint32_t EASY = 0x207fffff;
    constexpr uint32_t HARDER = 0x1f0fffff;

    const DualCase cases[] = {
        // Equal easy targets: T_kd < T_floor < T_Z ≈ T_K
        {"fail_all", EASY, EASY, {/*K*/ false, /*KD*/ false, /*Z*/ false, /*ZF*/ false}, false},
        {"kaspa_met_not_3000x_and_zork_met_not_4x", EASY, EASY, {true, false, true, false}, false},
        {"kaspa_met_not_3000x_and_zork_4x", EASY, EASY, {true, false, true, true}, false},
        {"both_multipliers_met", EASY, EASY, {true, true, true, true}, true},

        // Zork easier than Kaspa: can miss Kaspa while still meeting Zork 4x.
        // 0x1f7fffff keeps T_K/3000 grindable (~2^-21).
        {"zork_4x_but_kaspa_not_met", EASY, 0x1f7fffff, {false, false, true, true}, false},
        {"zork_met_not_4x_and_kaspa_not_met", EASY, 0x1f7fffff, {false, false, true, false}, false},
        {"kaspa_met_not_3000x_zork_4x_harder_k", EASY, 0x1f7fffff, {true, false, true, true}, false},
        {"kaspa_3000x_and_zork_4x_harder_k", EASY, 0x1f7fffff, {true, true, true, true}, true},

        // Kaspa easier than Zork (T_floor < T_kd): 3000x can hold while Zork 4x fails
        {"kaspa_3000x_and_zork_met_not_4x", HARDER, EASY, {true, true, true, false}, false},
        {"kaspa_3000x_and_zork_4x_harder_z", HARDER, EASY, {true, true, true, true}, true},
        {"kaspa_met_not_3000x_and_zork_not_met", HARDER, EASY, {true, false, false, false}, false},

        // Zork much harder: T_K/3000 can still exceed T_Z, so 3000x does not imply Zork-met
        {"kaspa_3000x_but_zork_not_met", 0x1e7fffff, EASY, {true, true, false, false}, false},
    };

    for (const auto& c : cases) {
        RunDualCase(c);
    }
}

BOOST_AUTO_TEST_CASE(kaspa_pow_golden_as_auxpow_peer_header)
{
    // Exact Kaspa PoW golden from kaspa_pow_tests (header with u64 parents/roots).
    // Coinbase/MM need not be a valid Zork AuxPoW; this pins endianness and
    // KaspaPeerPoW through CAuxPow serialize/deserialize.
    KaspaHeader h;
    h.version = 2;
    h.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    h.hash_merkle_root = KaspaHashFromU64(2);
    h.accepted_id_merkle_root = KaspaHashFromU64(3);
    h.utxo_commitment = KaspaHashFromU64(4);
    h.timestamp = 1700000000000ull;
    h.bits = 0x1e0ffff0;
    h.nonce = 42;
    h.daa_score = 100;
    h.blue_score = 50;
    std::memset(h.blue_work, 0, sizeof(h.blue_work));
    h.pruning_point = KaspaHashFromU64(5);

    const uint256 expected = KaspaHashFromHex("f884a18b54fe55bcf0699003aa12a45eedd8fb813c02725edbbf15a9cc19c76e");
    BOOST_CHECK(KaspaPeerPoW(h) == expected);

    CAuxPow aux;
    aux.version = 1;
    aux.peer_header = h;
    aux.coinbase_tx = MakeCoinbaseWithMM(uint256::ZERO, /*merkle_size=*/1, /*merkle_nonce=*/0);
    aux.nChainIndex = 0;

    DataStream ss{};
    ss << aux;
    CAuxPow out;
    ss >> out;
    BOOST_CHECK(out.peer_header.version == 2);
    BOOST_CHECK_EQUAL(out.peer_header.timestamp, 1700000000000ull);
    BOOST_CHECK_EQUAL(out.peer_header.bits, 0x1e0ffff0u);
    BOOST_CHECK_EQUAL(out.peer_header.nonce, 42ull);
    BOOST_CHECK(KaspaPeerPoW(out.peer_header) == expected);
}

BOOST_AUTO_TEST_SUITE_END()
