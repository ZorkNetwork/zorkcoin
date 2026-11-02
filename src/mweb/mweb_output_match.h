// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_OUTPUT_MATCH_H
#define BITCOIN_MWEB_MWEB_OUTPUT_MATCH_H

#include <cstddef>
#include <span>
#include <vector>

class ThreadPool;
class Output;
class SecretKey;

namespace MWEB {

//! Outputs per thread pool task.
static constexpr size_t OUTPUT_MATCH_CHUNK_SIZE{256};
//! Below this many (output, scan secret) checks, matching runs on the calling thread.
static constexpr size_t OUTPUT_MATCH_MIN_PARALLEL_WORK{512};
//! Upper bound on the worker threads of a wallet's output matching pool.
static constexpr int OUTPUT_MATCH_MAX_THREADS{8};

/**
 * Indices, in ascending order, of the outputs whose view tag matches at least one of the scan
 * secrets. Every output a wallet holding these scan secrets can rewind is among them; about one
 * in 256 of the others is too. Needs no wallet lock. With a started pool and enough work, chunks
 * of OUTPUT_MATCH_CHUNK_SIZE outputs run on the pool and the calling thread helps.
 */
std::vector<size_t> FindCandidateOutputs(std::span<const Output> outputs, std::span<const SecretKey> scan_secrets, ThreadPool* pool);

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_OUTPUT_MATCH_H
