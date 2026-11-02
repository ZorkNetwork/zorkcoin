// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MWEB_SETUP_H
#define BITCOIN_TEST_UTIL_MWEB_SETUP_H

#include <test/util/setup_common.h>

#include <cstdint>

//! A regtest chain of 100 blocks on which MWEB activates once mined past its start time.
struct MWEBRegtest100Setup : public TestChain100Setup {
    //! Regtest MWEB versionbits start time (matches the -vbparams this setup passes).
    static constexpr uint32_t MWEB_VB_START_TIME{1601450001};
    //! First MWEB block height on this chain.
    static constexpr int FIRST_MWEB_HEIGHT{432};

    MWEBRegtest100Setup();

    //! Mines the mempool into a block timed at or after the MWEB start time.
    void MineMWEBEraBlock();

    //! The first MWEB block needs a peg-in, so this stops one block short of it.
    void MineToMWEBActivation();
};

#endif // BITCOIN_TEST_UTIL_MWEB_SETUP_H
