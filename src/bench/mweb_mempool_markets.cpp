// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_mempool_markets.h>

#include <bench/bench.h>
#include <consensus/amount.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/peg_out_coin.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/wallet/stealth_address.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txgraph.h>
#include <txmempool.h>
#include <util/check.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {
constexpr int BENCH_GROUPS{50};

mw::MutableTx MWEBBody(CAmount fee)
{
    BlindingFactor blind;
    const Output output{Output::Create(&blind, SecretKey::Random(), StealthAddress::Random(), COIN)};
    const Kernel kernel{Kernel::Create(BlindingFactor::Random(), std::nullopt, fee, std::nullopt, {}, std::nullopt)};
    return mw::MutableTx::From(*mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {}, {output}, {kernel}));
}

//! Per group: an L1-only parent, its hybrid child, an unrelated L1-only and two MWEB-only transactions.
std::vector<std::pair<CTransactionRef, CAmount>> MixedPool(FastRandomContext& rng)
{
    std::vector<std::pair<CTransactionRef, CAmount>> txs;
    for (int i{0}; i < BENCH_GROUPS; ++i) {
        CMutableTransaction parent;
        parent.vin.emplace_back(COutPoint{Txid::FromUint256(rng.rand256()), 0});
        parent.vout.emplace_back(COIN, CScript() << OP_1);
        const CTransactionRef parent_ref{MakeTransactionRef(parent)};
        txs.emplace_back(parent_ref, rng.randrange<CAmount>(20'000));

        CMutableTransaction hybrid;
        hybrid.vin.emplace_back(COutPoint{parent_ref->GetHash(), 0});
        hybrid.vout.emplace_back(COIN / 2, CScript() << OP_2);
        hybrid.mweb_tx = MWEBBody(rng.randrange<CAmount>(20'000));
        txs.emplace_back(MakeTransactionRef(hybrid), rng.randrange<CAmount>(40'000));

        CMutableTransaction l1;
        l1.vin.emplace_back(COutPoint{Txid::FromUint256(rng.rand256()), 0});
        l1.vout.emplace_back(COIN, CScript() << OP_3);
        txs.emplace_back(MakeTransactionRef(l1), rng.randrange<CAmount>(20'000));

        for (int j{0}; j < 2; ++j) {
            const CAmount fee{rng.randrange<CAmount>(20'000)};
            CMutableTransaction mweb;
            mweb.mweb_tx = MWEBBody(fee);
            txs.emplace_back(MakeTransactionRef(mweb), fee);
        }
    }
    return txs;
}
} // namespace

// Add a mixed pool, query each market's worst chunk, and remove the pool as a block would.
static void MempoolMarketsMixed(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool{*Assert(testing_setup->m_node.mempool)};
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto txs{MixedPool(rng)};
    std::vector<CTransactionRef> block;
    block.reserve(txs.size());
    for (const auto& [tx, fee] : txs) block.push_back(tx);

    LOCK2(cs_main, pool.cs);
    uint64_t sequence{0};
    bench.batch(txs.size()).unit("tx").run([&]() NO_THREAD_SAFETY_ANALYSIS {
        for (const auto& [tx, fee] : txs) {
            TryAddToMempool(pool, CTxMemPoolEntry(tx, fee, /*time=*/0, /*entry_height=*/1, sequence++,
                                                  /*spends_coinbase=*/false, /*sigops_cost=*/4, LockPoints{}));
        }
        Assert(pool.size() == txs.size());
        for (MempoolMarket market : {MempoolMarket::L1, MempoolMarket::MWEB}) {
            ankerl::nanobench::doNotOptimizeAway(pool.m_mweb_markets->Graph(market).GetWorstMainChunk());
        }
        pool.removeForBlock(block);
    });
}

BENCHMARK(MempoolMarketsMixed);
