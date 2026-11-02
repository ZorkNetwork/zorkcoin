// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/kernel_sum_validator.h>
#include <mw/consensus/stealth_sum_validator.h>
#include <mw/consensus/aggregation.h>
#include <mw/crypto/pedersen.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/node/coins_view.h>

#include <test_framework/test_mweb.h>
#include <test_framework/models/tx.h>
#include <test_framework/miner.h>
#include <test_framework/tx_builder.h>

// FUTURE: Create official test vectors for the consensus rules being tested

BOOST_FIXTURE_TEST_SUITE(TestMWEBIncrementalSums, MWEBTestingSetup)

// The positive prefix of the sorted aggregate must stay in range even when later withdrawals cancel it.
BOOST_AUTO_TEST_CASE(IncrementalSupplyRangePreservesState)
{
    const auto pegin = test::Tx::CreatePegIn(MAX_MONEY).GetTransaction();
    const auto pegout = test::TxBuilder().AddInput(MAX_MONEY).AddPegoutKernel(MAX_MONEY, 0).Build().GetTransaction();
    const auto extra = test::Tx::CreatePegIn(1).GetTransaction();
    KernelSumValidator::SumState sums;
    sums = KernelSumValidator::ValidateAndAdd(*pegin, sums);
    sums = KernelSumValidator::ValidateAndAdd(*pegout, sums);
    BOOST_CHECK_EQUAL(sums.positive_supply + sums.negative_supply, 0);
    const auto before = sums;
    BOOST_CHECK_EXCEPTION(KernelSumValidator::ValidateAndAdd(*extra, sums), ValidationException,
        [](const ValidationException& error) { return error.GetType() == EConsensusError::AMOUNT_OUT_OF_RANGE; });
    BOOST_CHECK(sums.utxo_sum == before.utxo_sum);
    BOOST_CHECK(sums.kernel_sum == before.kernel_sum);
    BOOST_CHECK(sums.kernel_offset == before.kernel_offset);
    BOOST_CHECK_EQUAL(sums.positive_supply, before.positive_supply);
    BOOST_CHECK_EQUAL(sums.negative_supply, before.negative_supply);
}

BOOST_AUTO_TEST_SUITE_END()
