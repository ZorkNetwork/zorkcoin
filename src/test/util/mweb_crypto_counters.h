// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MWEB_CRYPTO_COUNTERS_H
#define BITCOIN_TEST_UTIL_MWEB_CRYPTO_COUNTERS_H

#include <mw/crypto/bulletproofs.h>
#include <mw/crypto/schnorr.h>

#include <cstdint>

//! Test helpers for mempool fail-fast observability (batch-verify entry counts).
namespace mweb_test {

inline void ResetBatchVerifyCounts() noexcept
{
    Schnorr::ResetBatchVerifyCount();
    Bulletproofs::ResetBatchVerifyCount();
}

inline uint64_t GetSchnorrBatchVerifyCount() noexcept
{
    return Schnorr::GetBatchVerifyCount();
}

inline uint64_t GetBulletproofsBatchVerifyCount() noexcept
{
    return Bulletproofs::GetBatchVerifyCount();
}

inline uint64_t GetTotalBatchVerifyCount() noexcept
{
    return GetSchnorrBatchVerifyCount() + GetBulletproofsBatchVerifyCount();
}

} // namespace mweb_test

#endif // BITCOIN_TEST_UTIL_MWEB_CRYPTO_COUNTERS_H
