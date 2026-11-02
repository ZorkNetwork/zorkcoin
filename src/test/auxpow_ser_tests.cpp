// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/chainwork.h>
#include <auxpow/check.h>
#include <auxpow/kaspa_hash.h>
#include <auxpow/kaspa_merkle.h>
#include <auxpow/kaspa_pow.h>
#include <auxpow/version.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <streams.h>
#include <test/util/auxpow.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <ios>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace auxpow;

BOOST_FIXTURE_TEST_SUITE(auxpow_ser_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(version_helpers)
{
    BOOST_CHECK(!IsAuxPow(0x20000000));
    BOOST_CHECK(IsAuxPow(0x20000100));
    // Only bit 8 is added; BIP9 top bits and signalling bits are preserved.
    BOOST_CHECK_EQUAL(MakeAuxPowVersion(0x20000000), 0x20000100);
    BOOST_CHECK_EQUAL(MakeAuxPowVersion(0x20000010), 0x20000110);
    BOOST_CHECK_EQUAL(MakeAuxPowVersion(0x20000100), 0x20000100);
}

BOOST_AUTO_TEST_CASE(nonce_helpers)
{
    const uint64_t nonce = MakeAuxPowNonce(0x525a);
    BOOST_CHECK_EQUAL(nonce, uint64_t{0x576F50787541525a});
    BOOST_CHECK(HasAuxPowNonceMarker(nonce));
    BOOST_CHECK_EQUAL(GetAuxPowNonceChainId(nonce), 0x525a);
    BOOST_CHECK(HasAuxPowNonceMarker(MakeAuxPowNonce(0)));
    BOOST_CHECK(HasAuxPowNonceMarker(MakeAuxPowNonce(0xffff)));
    BOOST_CHECK(!HasAuxPowNonceMarker(0));
    BOOST_CHECK(!HasAuxPowNonceMarker(nonce ^ (uint64_t{1} << 16)));
    BOOST_CHECK(!HasAuxPowNonceMarker(nonce ^ (uint64_t{1} << 63)));
}

BOOST_AUTO_TEST_CASE(auxpow_bit_reserved_from_versionbits)
{
    // Unknown-deployment warnings only scan the live BIP9 bits, which must not reach bit 8.
    BOOST_CHECK_GE(VERSION_AUXPOW_BIT, 1 << VERSIONBITS_NUM_BITS);
    BOOST_CHECK_EQUAL(VERSION_AUXPOW_BIT & VERSIONBITS_TOP_MASK, 0);
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(ArgsManager{}, chain);
        for (const auto& dep : params->GetConsensus().vDeployments) {
            BOOST_CHECK_MESSAGE((uint32_t{1} << dep.bit) != uint32_t{VERSION_AUXPOW_BIT},
                                ChainTypeToString(chain) + " deployment uses the AuxPoW version bit");
        }
    }
}

BOOST_AUTO_TEST_CASE(auxpow_blocks_do_not_trigger_unknown_version_warnings)
{
    const auto chainparams = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const int blocks = 3 * 2016;
    constexpr int unknown_bit = 3;
    for (const auto& dep : chainparams->GetConsensus().vDeployments) {
        BOOST_REQUIRE(dep.bit != unknown_bit);
    }

    const auto unknown_activations = [&](int32_t version) {
        std::vector<CBlockIndex> chain(blocks);
        for (int i = 0; i < blocks; ++i) {
            chain[i].nHeight = i;
            chain[i].nTime = chainparams->GenesisBlock().nTime + i * 131'072ULL;
            chain[i].nVersion = version;
            chain[i].pprev = i ? &chain[i - 1] : nullptr;
            chain[i].BuildSkip();
        }
        VersionBitsCache cache;
        return cache.CheckUnknownActivations(&chain.back(), *chainparams);
    };

    BOOST_CHECK(unknown_activations(MakeAuxPowVersion(VERSIONBITS_TOP_BITS)).empty());

    // Control: an unknown signalling bit is reported whether or not bit 8 is also set.
    for (const int32_t version : {VERSIONBITS_TOP_BITS | (1 << unknown_bit), MakeAuxPowVersion(VERSIONBITS_TOP_BITS | (1 << unknown_bit))}) {
        const auto result = unknown_activations(version);
        BOOST_REQUIRE_EQUAL(result.size(), 1U);
        BOOST_CHECK_EQUAL(result[0].first, unknown_bit);
    }
}

BOOST_AUTO_TEST_CASE(nonce_wire_bytes_per_network)
{
    const std::vector<std::pair<ChainType, std::string>> expected{
        {ChainType::MAIN, "ZKAuxPoW"},
        {ChainType::TESTNET, "ZTAuxPoW"},
        {ChainType::TESTNET4, "ZTAuxPoW"},
        {ChainType::SIGNET, "ZSAuxPoW"},
        {ChainType::REGTEST, "ZRAuxPoW"},
    };
    for (const auto& [chain, text] : expected) {
        const auto params = CreateChainParams(ArgsManager{}, chain);
        DataStream ss{};
        ss << MakeAuxPowNonce(params->GetConsensus().auxpow.nChainId);
        BOOST_CHECK_EQUAL(std::string(reinterpret_cast<const char*>(ss.data()), ss.size()), text);
    }
}

BOOST_AUTO_TEST_CASE(auxpow_round_trip_empty_branches)
{
    CAuxPow aux;
    aux.version = 1;
    aux.peer_header.version = 2;
    aux.peer_header.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    aux.peer_header.hash_merkle_root = KaspaHashFromU64(2);
    aux.peer_header.accepted_id_merkle_root = KaspaHashFromU64(3);
    aux.peer_header.utxo_commitment = KaspaHashFromU64(4);
    aux.peer_header.timestamp = 1;
    aux.peer_header.bits = 0x207fffff;
    aux.peer_header.nonce = 1;
    aux.peer_header.daa_score = 1;
    aux.peer_header.blue_score = 1;
    aux.peer_header.pruning_point = KaspaHashFromU64(5);
    aux.coinbase_tx.version = 1;
    std::memcpy(aux.coinbase_tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE);
    aux.coinbase_tx.payload.assign(19, 0);
    aux.nChainIndex = 0;

    DataStream ss{};
    ss << aux;
    CAuxPow out;
    ss >> out;
    BOOST_CHECK_EQUAL(out.version, aux.version);
    BOOST_CHECK_EQUAL(out.nChainIndex, 0);
    BOOST_CHECK_EQUAL(out.peer_header.nonce, aux.peer_header.nonce);
}

BOOST_AUTO_TEST_CASE(size_limit_rejects_oversized)
{
    const auto& params = Params().GetConsensus().auxpow;
    CAuxPow aux;
    aux.version = 1;
    aux.peer_header.version = 2;
    aux.peer_header.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    // Inflate merkle branch past caps
    aux.vMerkleBranch.assign(params.nMaxTxMerkleBranchHashes + 1, uint256::ZERO);
    std::string err;
    BOOST_CHECK(!CheckAuxPowSizeLimits(aux, params, &err));
}

BOOST_AUTO_TEST_CASE(chainwork_discount)
{
    const uint32_t bits = 0x207fffff;
    const auto native = GetBitsProof(bits);
    const auto aux = GetAuxPowBlockProof(bits, 400, 8192);
    BOOST_CHECK(aux < native);
    BOOST_CHECK(aux > 0);
}

BOOST_AUTO_TEST_CASE(get_expected_index_solo)
{
    BOOST_CHECK_EQUAL(GetExpectedIndex(/*nNonce=*/0, /*nChainId=*/0x525a, /*h=*/0), 0);
}

BOOST_AUTO_TEST_CASE(header_hash_excludes_auxpow_extension)
{
    CBlockHeader hdr;
    hdr.nVersion = MakeAuxPowVersion(0x20000000);
    hdr.hashPrevBlock = uint256::ZERO;
    hdr.hashMerkleRoot = uint256::ONE;
    hdr.nTime = 1;
    hdr.nBits = 0x207fffff;
    hdr.nNonce = MakeAuxPowNonce(0x525a);

    const uint256 hash_without = hdr.GetHash();
    DataStream hashed_only{};
    hdr.SerializeHashedFields(hashed_only);
    BOOST_CHECK_EQUAL(hashed_only.size(), 88u);
    BOOST_CHECK_THROW((DataStream{} << hdr), std::ios_base::failure);
    BOOST_CHECK(!hdr.HasCompleteAuxPow());

    CAuxPow aux;
    aux.version = 1;
    aux.peer_header.version = 2;
    aux.peer_header.parents_by_level.push_back(KaspaParentRun{1, {KaspaHashFromU64(1)}});
    aux.peer_header.hash_merkle_root = KaspaHashFromU64(2);
    aux.peer_header.accepted_id_merkle_root = KaspaHashFromU64(3);
    aux.peer_header.utxo_commitment = KaspaHashFromU64(4);
    aux.peer_header.timestamp = 1;
    aux.peer_header.bits = 0x207fffff;
    aux.peer_header.nonce = 1;
    aux.peer_header.daa_score = 1;
    aux.peer_header.blue_score = 1;
    aux.peer_header.pruning_point = KaspaHashFromU64(5);
    hdr.auxpow = aux;

    BOOST_CHECK(hdr.GetHash() == hash_without);
    DataStream wire{};
    wire << hdr;
    BOOST_CHECK_GT(wire.size(), 88u);
    BOOST_CHECK_LE(wire.size(), 88u + MAX_AUXPOW_SERIALIZED_SIZE);

    CBlockHeader out;
    wire >> out;
    BOOST_CHECK(out.auxpow.has_value());
    BOOST_CHECK(out.GetHash() == hash_without);
    BOOST_CHECK(hdr.HasCompleteAuxPow());
    BOOST_CHECK(out.HasCompleteAuxPow());
}

BOOST_AUTO_TEST_CASE(bit8_header_without_extension_unserialize_fails)
{
    CBlockHeader hdr;
    hdr.nVersion = MakeAuxPowVersion(0x20000000);
    hdr.nBits = 0x207fffff;
    DataStream hashed{};
    hdr.SerializeHashedFields(hashed);
    BOOST_CHECK_EQUAL(hashed.size(), 88u);
    CBlockHeader out;
    BOOST_CHECK_THROW(hashed >> out, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(unserialize_enforces_compactsize_caps)
{
    DataStream ss{};
    const uint32_t version = 1;
    ss << version;
    WriteCompactSize(ss, MAX_AUXPOW_PEER_HEADER_SIZE + 1);
    CAuxPow aux;
    BOOST_CHECK_THROW(ss >> aux, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(auxpow_serialize_and_unserialize_failures)
{
    CAuxPow valid;
    test::InitLeanPeerHeader(valid.peer_header, test::EASIEST_KASPA_BITS);
    valid.coinbase_tx = test::MakeCoinbaseWithMM(uint256::ONE, /*merkle_size=*/1, /*merkle_nonce=*/0);
    std::vector<unsigned char> header_bytes, tx_bytes;
    BOOST_REQUIRE(SerializeKaspaHeader(valid.peer_header, header_bytes));
    BOOST_REQUIRE(SerializeKaspaTransaction(valid.coinbase_tx, tx_bytes));

    const auto raw = [](const std::vector<unsigned char>& hdr, const std::vector<unsigned char>& tx) {
        DataStream ss{};
        ss << uint32_t{1} << hdr << tx << std::vector<uint256>{} << std::vector<uint256>{} << int32_t{0};
        return ss;
    };
    {
        DataStream ss{raw(header_bytes, tx_bytes)};
        CAuxPow out;
        ss >> out;
        BOOST_CHECK(AuxPowEqual(out, valid));
    }

    auto hdr_short{header_bytes}, hdr_long{header_bytes}, tx_short{tx_bytes}, tx_long{tx_bytes};
    hdr_short.pop_back();
    hdr_long.push_back(0);
    tx_short.pop_back();
    tx_long.push_back(0);
    const std::vector<std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, std::string>> cases{
        {hdr_short, tx_bytes, "bad auxpow peer_header"},
        {hdr_long, tx_bytes, "bad auxpow peer_header"},
        {header_bytes, tx_short, "bad auxpow coinbase_tx"},
        {header_bytes, tx_long, "bad auxpow coinbase_tx"},
    };
    for (const auto& [hdr, tx, reason] : cases) {
        DataStream ss{raw(hdr, tx)};
        CAuxPow out;
        BOOST_CHECK_EXCEPTION(ss >> out, std::ios_base::failure, HasReason(reason));
    }

    // An in-memory proof whose peer header is not canonical cannot be serialized.
    CAuxPow bad{valid};
    bad.peer_header.parents_by_level.clear();
    DataStream sink{};
    BOOST_CHECK_EXCEPTION(sink << bad, std::ios_base::failure, HasReason("serialize auxpow peer_header"));
    BOOST_CHECK_EXCEPTION((void)GetSerializeSizeAuxPow(bad), std::ios_base::failure, HasReason("serialize auxpow peer_header"));
    std::string err;
    BOOST_CHECK(!CheckAuxPowSizeLimits(bad, Params().GetConsensus().auxpow, &err));
    BOOST_CHECK_EQUAL(err, "peer_header serialize failed");
}

BOOST_AUTO_TEST_CASE(chainwork_tiny_target_does_not_wrap)
{
    arith_uint256 one = 1;
    const uint32_t bits = one.GetCompact();
    const arith_uint256 proof = GetAuxPowBlockProof(bits, /*auxpow_size=*/1280, /*chainwork_ref=*/8192);
    BOOST_CHECK(proof > 1);
    BOOST_CHECK_GE(proof.bits(), 200u);
}

BOOST_AUTO_TEST_SUITE_END()
