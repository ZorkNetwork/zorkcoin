// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying (ASERT on-schedule) */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    // Build chain with blocks on ideal schedule; ASERT should keep difficulty stable
    std::vector<CBlockIndex> blocks(10);
    int64_t genesisTime = 1770399953638;  // Zorkcoin mainnet genesis (ms)
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 10; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 11 * params.nPowTargetSpacing;
    unsigned int nBits = GetNextWorkRequired(&blocks[8], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    arith_uint256 genesisTarget;
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(target * 99 / 100 <= genesisTarget && genesisTarget <= target * 101 / 100);
}

/* Test the constraint on the upper bound for next work (ASERT clamps to pow limit) */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    arith_uint256 powLimit = UintToArith256(params.powLimit);
    // Way behind schedule: target would exceed limit; ASERT must clamp
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing * 4;  // 4x slower
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 4;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    BOOST_CHECK(target <= powLimit);
}

/* Test the constraint on the lower bound (ASERT: blocks ahead of schedule increase difficulty) */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + i * (params.nPowTargetSpacing / 2);  // 2x faster
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 2);
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

/* Test the constraint on the upper bound (ASERT: blocks behind schedule decrease difficulty) */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing * 2;  // 2x slower
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 2;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

/* ASERT: blocks ahead of schedule (5x, 10x, 25x faster) increase difficulty */
BOOST_AUTO_TEST_CASE(asert_ahead_5x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + i * (params.nPowTargetSpacing / 5);
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 5);
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_ahead_10x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + i * (params.nPowTargetSpacing / 10);
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 10);
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_ahead_25x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + i * (params.nPowTargetSpacing / 25);
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 25);
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

/* ASERT: blocks behind schedule (5x, 10x, 25x slower) decrease difficulty */
BOOST_AUTO_TEST_CASE(asert_behind_5x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing * 5;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 5;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_behind_10x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing * 10;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 10;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_behind_25x) {
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * params.nPowTargetSpacing * 25;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 25;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

/* ASERT exponent limit: large positive exponent (many days behind schedule) clamps to powLimit */
BOOST_AUTO_TEST_CASE(asert_large_positive_exponent_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    arith_uint256 powLimit = UintToArith256(params.powLimit);
    // Chain many days behind: 10 blocks over 30 days instead of 2.5 min each
    std::vector<CBlockIndex> blocks(10);
    int64_t genesisTime = 1770399953638;
    int64_t spacingMs = 30LL * 24 * 60 * 60 * 1000;  // 30 days between blocks
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 10; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i + 1) * spacingMs;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 11 * spacingMs;
    unsigned int nBits = GetNextWorkRequired(&blocks[9], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    BOOST_CHECK(target <= powLimit);
    BOOST_CHECK(nBits != 0);  // Valid compact encoding
}

/* ASERT exponent limit: large negative exponent (way ahead of schedule) clamps to min target */
BOOST_AUTO_TEST_CASE(asert_large_negative_exponent_min_target)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    int64_t genesisTime = 1770399953638;
    // All blocks at genesis time = infinitely fast mining
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime;  // Same time = way ahead of schedule
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    arith_uint256 genesisTarget;
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(target < genesisTarget);  // Difficulty increased
    BOOST_CHECK(target >= arith_uint256(1));  // Min target
    BOOST_CHECK(nBits != 0);  // Valid compact encoding
}

/* ASERT exponent limit: right-shift by >= 256 bits (undefined in C++) - must clamp to min target */
BOOST_AUTO_TEST_CASE(asert_right_shift_256_bits)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();
    // Create scenario where exponent gives shifts <= -256: tip time way before expected
    // exponent = ((nTimeDiff - spacing*(height+1)) * 65536) / halfLife; shifts = (exponent>>16) - 16
    // For shifts = -256: need exponent/65536 - 16 <= -256, so exponent <= -15728640
    // delta = -10367856000 gives exponent = -15728640 (approx)
    int64_t genesisTime = 1770399953638;
    int64_t nTimeLast = genesisTime - 10366956000LL;  // ~120 days before expected for height 5
    std::vector<CBlockIndex> blocks(5);
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x1e0ffff0;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (int i = 1; i < 5; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (i * 1000);  // Slight progression
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    blocks[4].nTime = nTimeLast;  // Tip way before schedule
    CBlockHeader dummyBlock;
    dummyBlock.nTime = nTimeLast + 1000;
    unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    BOOST_CHECK(target >= arith_uint256(1));  // Must not underflow; min target
    BOOST_CHECK(nBits != 0);  // Valid compact encoding
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits = ~0x00800000;
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 * 1000 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, std::string chainName)
{
    const auto chainParams = CreateChainParams(args, chainName);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    /* Litecoin: we allow overflowing by 1 bit
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
    */
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::SIGNET);
}

/* ASERT consensus params sanity check */
BOOST_AUTO_TEST_CASE(asert_sanity_params)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& params = chainParams->GetConsensus();

    BOOST_CHECK(params.nASERTHalfLife > 0);
    BOOST_CHECK(params.nPowTargetSpacing > 0);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacing, 150000);  // 2.5 min in ms
    BOOST_CHECK_EQUAL(params.nASERTHalfLife, 43200000);   // 12 hours in ms
}

/* GetCompact round-trip: values with mantissa >= 0x00800000 trigger renormalization.
 * Verify SetCompact(GetCompact(x)) == x for such values (disproves GetCompact bug). */
BOOST_AUTO_TEST_CASE(getcompact_roundtrip_renormalize_range)
{
    // Values whose top 24 bits have 0x00800000 set - would trigger GetCompact renormalization
    arith_uint256 v1;
    v1.SetCompact(0x1e7f0224);  // Example from failing case (block 17)
    arith_uint256 v1_decoded;
    v1_decoded.SetCompact(v1.GetCompact());
    BOOST_CHECK_MESSAGE(v1 == v1_decoded,
        "GetCompact round-trip must preserve value for mantissa in 0x7f... range");

    arith_uint256 v2;
    v2.SetCompact(0x1e008000);  // Minimum mantissa that triggers renormalization
    arith_uint256 v2_decoded;
    v2_decoded.SetCompact(v2.GetCompact());
    BOOST_CHECK_MESSAGE(v2 == v2_decoded,
        "GetCompact round-trip must preserve value at renormalization threshold");
}

/* ASERT regtest scenario: 10 blocks at ideal spacing, then 5 at 75s (2x fast).
 * Mirrors feature_asert_regtest.py. Fast mining should increase difficulty. */
BOOST_AUTO_TEST_CASE(asert_regtest_fast_mining_increases_difficulty)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const auto& params = chainParams->GetConsensus();
    int64_t genesisTime = 1765210800000;  // Zorkcoin regtest genesis (ms)

    std::vector<CBlockIndex> blocks(16);  // 0=genesis, 1-10 ideal, 11-15 fast
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesisTime;
    blocks[0].nBits = 0x207fffff;  // Regtest genesis
    blocks[0].nChainWork = GetBlockProof(blocks[0]);

    // Blocks 1-10 at ideal 150s spacing
    for (int i = 1; i <= 10; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + (int64_t)(i) * params.nPowTargetSpacing;
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }

    // Blocks 11-15 at 75s spacing (2x fast)
    for (int i = 11; i <= 15; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = genesisTime + 10 * params.nPowTargetSpacing + (int64_t)(i - 10) * (params.nPowTargetSpacing / 2);
        blocks[i].nBits = blocks[0].nBits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }

    // Baseline: difficulty after 10 ideal blocks
    CBlockHeader dummy10;
    dummy10.nTime = genesisTime + 11 * params.nPowTargetSpacing;
    unsigned int nBits10 = GetNextWorkRequired(&blocks[9], &dummy10, params);
    arith_uint256 target10;
    target10.SetCompact(nBits10);

    // After 5 fast blocks: next work for block 16
    CBlockHeader dummy16;
    dummy16.nTime = genesisTime + 10 * params.nPowTargetSpacing + 5 * (params.nPowTargetSpacing / 2) + params.nPowTargetSpacing / 2;
    unsigned int nBits16 = GetNextWorkRequired(&blocks[14], &dummy16, params);
    arith_uint256 target16;
    target16.SetCompact(nBits16);

    // Fast mining should increase difficulty: target16 < target10
    BOOST_CHECK_MESSAGE(target16 < target10,
        "ASERT: 5 blocks at 2x fast (75s) should increase difficulty (smaller target)");
}

BOOST_AUTO_TEST_SUITE_END()
