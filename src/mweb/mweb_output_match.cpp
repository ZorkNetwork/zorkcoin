// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_output_match.h>

#include <logging.h>
#include <mw/crypto/key_derivation.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/tx/output.h>
#include <util/threadpool.h>

#include <algorithm>
#include <functional>

namespace MWEB {

static bool OutputMatchesAnyScanSecret(const Output& output, std::span<const SecretKey> scan_secrets)
{
    if (!output.HasStandardFields() || !output.Ko().IsValid() || !output.Ke().IsValid()) {
        return false;
    }
    for (const SecretKey& scan_secret : scan_secrets) {
        try {
            if (mw::RecoverViewTag(output.Ke(), scan_secret) == output.GetViewTag()) {
                return true;
            }
        } catch (const CryptoException&) {
        }
    }
    return false;
}

static void MatchRange(std::span<const Output> outputs, std::span<const SecretKey> scan_secrets, size_t begin, size_t end, std::vector<size_t>& matches)
{
    for (size_t i = begin; i < end; ++i) {
        if (OutputMatchesAnyScanSecret(outputs[i], scan_secrets)) {
            matches.push_back(i);
        }
    }
}

std::vector<size_t> FindCandidateOutputs(std::span<const Output> outputs, std::span<const SecretKey> scan_secrets, ThreadPool* pool)
{
    std::vector<size_t> matches;
    if (outputs.empty() || scan_secrets.empty()) {
        return matches;
    }

    const size_t num_chunks = (outputs.size() + OUTPUT_MATCH_CHUNK_SIZE - 1) / OUTPUT_MATCH_CHUNK_SIZE;
    if (pool == nullptr || num_chunks < 2 || outputs.size() * scan_secrets.size() < OUTPUT_MATCH_MIN_PARALLEL_WORK || pool->WorkersCount() == 0) {
        MatchRange(outputs, scan_secrets, 0, outputs.size(), matches);
        return matches;
    }

    std::vector<std::vector<size_t>> chunk_matches(num_chunks);
    std::vector<std::function<void()>> tasks;
    tasks.reserve(num_chunks);
    for (size_t chunk = 0; chunk < num_chunks; ++chunk) {
        const size_t begin = chunk * OUTPUT_MATCH_CHUNK_SIZE;
        const size_t end = std::min(begin + OUTPUT_MATCH_CHUNK_SIZE, outputs.size());
        tasks.emplace_back([&, begin, end, chunk] { MatchRange(outputs, scan_secrets, begin, end, chunk_matches[chunk]); });
    }

    auto futures{pool->Submit(std::move(tasks))};
    if (!futures) {
        LogDebug(BCLog::SCAN, "MWEB output matching runs on one thread: %s\n", SubmitErrorString(futures.error()));
        MatchRange(outputs, scan_secrets, 0, outputs.size(), matches);
        return matches;
    }
    while (pool->ProcessTask()) {}
    // Tasks reference this frame, so all must finish before any exception leaves it.
    for (auto& future : *futures) {
        future.wait();
    }
    for (auto& future : *futures) {
        future.get();
    }
    for (const std::vector<size_t>& chunk : chunk_matches) {
        matches.insert(matches.end(), chunk.begin(), chunk.end());
    }
    return matches;
}

} // namespace MWEB
