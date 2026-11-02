// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/kernel_sum_validator.h>

#include <test_framework/deserializer.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

BOOST_FIXTURE_TEST_SUITE(TestTransaction, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(TxTransaction)
{
    const CAmount pegInAmount = 123;
    const CAmount fee = 5;

    mw::Transaction::CPtr tx = test::TxBuilder()
        .AddInput(20).AddInput(30)
        .AddOutput(45).AddOutput(pegInAmount)
        .AddPlainKernel(fee).AddPeginKernel(pegInAmount)
        .Build().GetTransaction();

    KernelSumValidator::ValidateForTx(*tx);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = tx->Serialized();

        Deserializer deserializer(serialized);
        BOOST_REQUIRE(deserializer.Read<BlindingFactor>() == tx->GetKernelOffset());
        BOOST_REQUIRE(deserializer.Read<BlindingFactor>() == tx->GetStealthOffset());
        BOOST_REQUIRE(deserializer.Read<TxBody>() == tx->GetBody());

        Deserializer deserializer2(serialized);
        BOOST_REQUIRE(*tx == deserializer2.Read<mw::Transaction>());
    }

    //
    // Getters
    //
    {
        const auto total_fee = tx->GetTotalFee();
        BOOST_REQUIRE(total_fee.has_value());
        BOOST_REQUIRE(*total_fee == fee);
    }

    BOOST_REQUIRE(!tx->GetValidationError().has_value());
}

BOOST_AUTO_TEST_CASE(GetValidationErrorReportsConsensusError)
{
    mw::Transaction::CPtr tx = test::TxBuilder()
        .AddInput(20)
        .AddOutput(15)
        .AddPlainKernel(5)
        .Build().GetTransaction();
    BOOST_REQUIRE(!tx->GetValidationError().has_value());

    const mw::Transaction bad_offset(BlindingFactor::Random(), tx->GetStealthOffset(), tx->GetBody());
    const std::optional<EConsensusError> error = bad_offset.GetValidationError();
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(ConsensusErrorString(*error), "BLOCK_SUMS");
    BOOST_CHECK_THROW(bad_offset.Validate(), ValidationException);
}

BOOST_AUTO_TEST_SUITE_END()
