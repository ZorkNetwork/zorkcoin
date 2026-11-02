// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_output_match.h>

#include <bench/bench.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/stealth_address.h>
#include <test/util/setup_common.h>
#include <util/threadpool.h>

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

//! About the outputs of a 40% full MWEB block.
static constexpr size_t BENCH_OUTPUTS{4096};

static std::vector<Output> BenchOutputs()
{
    std::vector<Output> distinct;
    for (int i = 0; i < 16; ++i) {
        BlindingFactor blind;
        distinct.push_back(Output::Create(&blind, SecretKey::Random(), StealthAddress::Random(), COIN));
    }
    std::vector<Output> outputs;
    outputs.reserve(BENCH_OUTPUTS);
    for (size_t i = 0; i < BENCH_OUTPUTS; ++i) {
        outputs.push_back(distinct[i % distinct.size()]);
    }
    return outputs;
}

static void MWEBOutputMatch(benchmark::Bench& bench, bool use_pool)
{
    const auto test_setup = MakeNoLogFileContext<BasicTestingSetup>();
    const std::vector<Output> outputs = BenchOutputs();
    const std::vector<SecretKey> scan_secrets{SecretKey::Random()};

    ThreadPool pool("mwmatchbch");
    if (use_pool) {
        pool.Start(std::max(1, std::min(GetNumCores() - 1, MWEB::OUTPUT_MATCH_MAX_THREADS)));
    }
    bench.unit("output").batch(outputs.size()).run([&] {
        const auto candidates = MWEB::FindCandidateOutputs(outputs, scan_secrets, use_pool ? &pool : nullptr);
        ankerl::nanobench::doNotOptimizeAway(candidates);
    });
    pool.Stop();
}

static void MWEBOutputMatchOneThread(benchmark::Bench& bench) { MWEBOutputMatch(bench, /*use_pool=*/false); }
static void MWEBOutputMatchPool(benchmark::Bench& bench) { MWEBOutputMatch(bench, /*use_pool=*/true); }

BENCHMARK(MWEBOutputMatchOneThread);
BENCHMARK(MWEBOutputMatchPool);
