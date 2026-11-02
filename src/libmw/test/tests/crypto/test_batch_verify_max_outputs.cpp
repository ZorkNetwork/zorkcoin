// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/params.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/models/crypto/blinding_factor.h>

#include <test_framework/test_mweb.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string>
#include <vector>

namespace {

/** Opt-in gate for consensus-max BatchVerify. Default ctest skips these. */
bool MegaExtendedTestEnabled()
{
    const char* e = std::getenv("MEGA_EXTENDED_TEST");
    return e != nullptr && std::string(e) != "" && std::string(e) != "0";
}

boost::test_tools::assertion_result MegaExtendedTestPrecondition(boost::unit_test::test_unit_id)
{
    if (MegaExtendedTestEnabled()) {
        return true;
    }
    boost::test_tools::assertion_result res(false);
    res.message() << "set MEGA_EXTENDED_TEST=1 to run mega BatchVerify max-output tests";
    return res;
}

std::vector<ProofData> GenerateProofs(size_t n)
{
    const ProofMessage message = RandomBigInt<20>();
    const std::vector<uint8_t> extraData; // empty extra data matches standard outputs

    std::vector<ProofData> rangeProofs;
    rangeProofs.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        const uint64_t value = 1 + (i % 1000);
        const BlindingFactor blind = BlindingFactor::Random();
        const Commitment commit = Commitment::Blinded(blind, value);
        const SecretKey nonce = SecretKey::Random();

        RangeProof::CPtr proof = Bulletproofs::Generate(
            value,
            SecretKey(blind.vec()),
            nonce,
            nonce,
            message,
            extraData);
        BOOST_REQUIRE(proof);

        rangeProofs.push_back(ProofData{commit, std::move(proof), extraData});
    }
    return rangeProofs;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestBatchVerifyMaxOutputs, MWEBTestingSetup,
                         *boost::unit_test::precondition(MegaExtendedTestPrecondition))

// A consensus-max MWEB body can carry this many base-weight outputs alongside one
// base kernel. BatchVerify must succeed for that many proofs under the configured
// scratch (64 MiB). Regression for the 32 MiB scratch / CreateNewBlock failure.
//
// Mega-tier only (MEGA_EXTENDED_TEST=1 / test_runner --mega): generating ~12k
// bulletproofs is too slow for default/extended ctest (notably s390x qemu).
// Full Transaction / ATMP / CreateNewBlock paths live in mweb_block_packing_tests.
BOOST_AUTO_TEST_CASE(BatchVerifyMaxWeightOutputs)
{
    constexpr size_t max_outputs =
        (mw::MAX_BLOCK_WEIGHT - mw::BASE_KERNEL_WEIGHT) / mw::BASE_OUTPUT_WEIGHT;
    BOOST_REQUIRE_EQUAL(max_outputs, 11764);
    BOOST_REQUIRE_LE(max_outputs * mw::BASE_OUTPUT_WEIGHT + mw::BASE_KERNEL_WEIGHT, mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE_GT((max_outputs + 1) * mw::BASE_OUTPUT_WEIGHT + mw::BASE_KERNEL_WEIGHT, mw::MAX_BLOCK_WEIGHT);

    std::vector<ProofData> rangeProofs = GenerateProofs(max_outputs);
    BOOST_REQUIRE_EQUAL(rangeProofs.size(), max_outputs);
    BOOST_REQUIRE(Bulletproofs::BatchVerify(rangeProofs));
}

// Standard outputs (18 WU) under one stealth kernel (3 WU): N = 11,110.
// MakeFanOut uses a plain kernel; this companion covers the stealth budget floor.
BOOST_AUTO_TEST_CASE(BatchVerifyMaxStandardOutputsStealthKernel)
{
    constexpr size_t max_outputs =
        (mw::MAX_BLOCK_WEIGHT - mw::KERNEL_WITH_STEALTH_WEIGHT) / mw::STANDARD_OUTPUT_WEIGHT;
    BOOST_REQUIRE_EQUAL(max_outputs, 11110);
    BOOST_REQUIRE_LE(max_outputs * mw::STANDARD_OUTPUT_WEIGHT + mw::KERNEL_WITH_STEALTH_WEIGHT,
                     mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE_GT((max_outputs + 1) * mw::STANDARD_OUTPUT_WEIGHT + mw::KERNEL_WITH_STEALTH_WEIGHT,
                     mw::MAX_BLOCK_WEIGHT);

    std::vector<ProofData> rangeProofs = GenerateProofs(max_outputs);
    BOOST_REQUIRE_EQUAL(rangeProofs.size(), max_outputs);
    BOOST_REQUIRE(Bulletproofs::BatchVerify(rangeProofs));
}

BOOST_AUTO_TEST_SUITE_END()
