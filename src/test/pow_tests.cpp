// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

static void BuildAsertChain(std::vector<CBlockIndex>& blocks, int64_t genesis_time, uint32_t n_bits, int64_t step_ms)
{
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    blocks[0].nTime = genesis_time;
    blocks[0].nBits = n_bits;
    blocks[0].nChainWork = GetBlockProof(blocks[0]);
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].nTime = genesis_time + static_cast<int64_t>(i) * step_ms;
        blocks[i].nBits = n_bits;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
}

BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(10);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 11 * params.nPowTargetSpacing;
    const unsigned int nBits = GetNextWorkRequired(&blocks[8], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    arith_uint256 genesisTarget;
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(target * 99 / 100 <= genesisTarget && genesisTarget <= target * 101 / 100);
}

BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    std::vector<CBlockIndex> blocks(5);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing * 4);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 4;
    const unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 target;
    target.SetCompact(nBits);
    BOOST_CHECK(target <= powLimit);
}

BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing / 2);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 2);
    const unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing * 2);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 2;
    const unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_ahead_5x)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing / 5);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 5 * (params.nPowTargetSpacing / 5);
    const unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget < genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_behind_5x)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(5);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing * 5);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 6 * params.nPowTargetSpacing * 5;
    const unsigned int nBits = GetNextWorkRequired(&blocks[4], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    BOOST_CHECK(nextTarget > genesisTarget);
}

BOOST_AUTO_TEST_CASE(asert_sanity_params)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    BOOST_CHECK(params.nASERTHalfLife > 0);
    BOOST_CHECK(params.nPowTargetSpacing > 0);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacing, 1LL << 17);
    BOOST_CHECK_EQUAL(params.nASERTHalfLife, 1LL << 25);
}

BOOST_AUTO_TEST_CASE(asert_on_schedule_classic_bias)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    std::vector<CBlockIndex> blocks(10);
    const int64_t genesisTime = 1770399953638;
    BuildAsertChain(blocks, genesisTime, 0x1e0ffff0, params.nPowTargetSpacing);
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + 11 * params.nPowTargetSpacing;
    const unsigned int nBits = GetNextWorkRequired(&blocks[8], &dummyBlock, params);
    arith_uint256 target, genesisTarget;
    target.SetCompact(nBits);
    genesisTarget.SetCompact(0x1e0ffff0);
    // Classic aserti3-2d on-schedule bias is 2^(-T/half_life) ≈ 0.9973, not the
    // extra-+1 0.9946 factor.
    BOOST_CHECK(target * 1000 >= genesisTarget * 996);
    BOOST_CHECK(target * 1000 <= genesisTarget * 999);
}

BOOST_AUTO_TEST_CASE(asert_anchor_remains_genesis_past_65536)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    constexpr size_t n = 65537;
    std::vector<CBlockIndex> blocks(n);
    const int64_t genesisTime = 1770399953638;
    const uint32_t genesis_bits = 0x1e0ffff0;
    const uint32_t other_bits = 0x1d00ffff;
    BuildAsertChain(blocks, genesisTime, genesis_bits, params.nPowTargetSpacing);
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].nBits = other_bits;
    }
    CBlockHeader dummyBlock;
    dummyBlock.nTime = genesisTime + static_cast<int64_t>(n) * params.nPowTargetSpacing;
    const unsigned int nBits = GetNextWorkRequired(&blocks[n - 1], &dummyBlock, params);
    arith_uint256 nextTarget, genesisTarget, otherTarget;
    nextTarget.SetCompact(nBits);
    genesisTarget.SetCompact(genesis_bits);
    otherTarget.SetCompact(other_bits);
    BOOST_CHECK(nextTarget * 1000 >= genesisTarget * 996);
    BOOST_CHECK(nextTarget * 1000 <= genesisTarget * 999);
    BOOST_CHECK(nextTarget > otherTarget);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
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
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443LL * 1000 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg);
    BOOST_CHECK(pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // SMA overflow check does not apply: ASERT is the only retarget.
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& genesis = chainParams->GenesisBlock();
    BOOST_CHECK(CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, chainParams->GetConsensus()));
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto& genesis = chainParams->GenesisBlock();
    BOOST_CHECK(CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, chainParams->GetConsensus()));
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto& genesis = chainParams->GenesisBlock();
    BOOST_CHECK(CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, chainParams->GetConsensus()));
}

BOOST_AUTO_TEST_SUITE_END()
