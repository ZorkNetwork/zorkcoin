// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mweb_setup.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/solver.h>
#include <sync.h>
#include <test/util/mining.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <memory>

MWEBRegtest100Setup::MWEBRegtest100Setup()
    : TestChain100Setup(ChainType::REGTEST, {.extra_args = {"-vbparams=mweb:1601450001000:9999999999000"}}) {}

void MWEBRegtest100Setup::MineMWEBEraBlock()
{
    std::shared_ptr<CBlock> block = PrepareBlock(m_node, {.coinbase_output_script = GetScriptForRawPubKey(coinbaseKey.GetPubKey())});
    {
        LOCK(::cs_main);
        const int64_t mtp = Assert(m_node.chainman)->ActiveChain().Tip()->GetMedianTimePast();
        block->nTime = std::max({mtp + 1, MWEB_VB_START_TIME});
    }
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    node::RegenerateCommitments(*block, *Assert(m_node.chainman));
    while (!CheckProofOfWork(block->GetPoWHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
    }
    ProcessBlock(m_node, block);
}

void MWEBRegtest100Setup::MineToMWEBActivation()
{
    SetMockTime(std::chrono::seconds{MWEB_VB_START_TIME_SEC});
    while (WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveHeight()) < FIRST_MWEB_HEIGHT - 1) {
        MineMWEBEraBlock();
    }
}
