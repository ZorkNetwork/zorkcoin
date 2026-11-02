// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/script.h>
#include <test/util/psbt.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <vector>

namespace {

struct MWEBRPCTestingSetup : public TestingSetup {
    UniValue DecodePSBT(const PartiallySignedTransaction& psbt)
    {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = "decodepsbt";
        request.params = UniValue{UniValue::VARR};
        request.params.push_back(EncodeBase64(psbt_test::Ser(psbt)));
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
        return tableRPC.execute(request);
    }
};

//! An unsigned PSBTv2 with known amounts; fee display needs no signatures.
PartiallySignedTransaction FeeDisplayPSBT(
    const std::vector<CAmount>& l1_inputs,
    const std::vector<CAmount>& mweb_inputs,
    const std::vector<CAmount>& l1_outputs,
    const std::vector<CAmount>& mweb_outputs,
    const std::vector<PSBTKernel>& kernels)
{
    PartiallySignedTransaction psbt = psbt_test::EmptyPSBT();
    for (CAmount amount : l1_inputs) {
        PSBTInput input = psbt_test::CanonicalInput(Txid::FromUint256(uint256::ONE), psbt.inputs.size());
        input.witness_utxo = CTxOut{amount, CScript{} << OP_TRUE};
        psbt.inputs.push_back(input);
    }
    for (CAmount amount : mweb_inputs) {
        PSBTInput input = psbt_test::MWEBInput(psbt_test::TestHash(psbt.inputs.size() + 1));
        input.mweb_amount = amount;
        psbt.inputs.push_back(input);
    }
    for (CAmount amount : l1_outputs) {
        psbt.outputs.push_back(psbt_test::CanonicalOutput(amount));
    }
    for (CAmount amount : mweb_outputs) {
        psbt.outputs.push_back(psbt_test::MWEBOutput(amount));
    }
    psbt.kernels = kernels;
    return psbt;
}

PSBTKernel FeeDisplayKernel(CAmount fee, std::optional<CAmount> pegin = {}, const std::vector<CAmount>& pegouts = {})
{
    PSBTKernel kernel;
    kernel.fee = fee;
    kernel.pegin_amount = pegin;
    for (CAmount amount : pegouts) {
        kernel.pegouts.emplace_back(amount, CScript{} << OP_TRUE);
    }
    return kernel;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_rpc_tests, MWEBRPCTestingSetup)

// The fee covers both input layers and every kernel transfer, counts kernel
// fees once, and is unchanged for transparent PSBTv0 and PSBTv2.
BOOST_AUTO_TEST_CASE(decodepsbt_mweb_fees)
{
    struct FeeCase {
        const char* name;
        PartiallySignedTransaction psbt;
        CAmount expected_fee;
    };
    const std::vector<FeeCase> cases{
        {"transparent", FeeDisplayPSBT({100'000}, {}, {90'000}, {}, {}), 10'000},
        {"MWEB only", FeeDisplayPSBT({}, {100'000}, {}, {90'000}, {FeeDisplayKernel(10'000)}), 10'000},
        {"peg-in", FeeDisplayPSBT({100'000}, {}, {90'000}, {85'000}, {FeeDisplayKernel(5'000, 90'000)}), 15'000},
        {"peg-out", FeeDisplayPSBT({}, {100'000}, {}, {50'000}, {FeeDisplayKernel(5'000, {}, {20'000, 25'000})}), 5'000},
        {"combined", FeeDisplayPSBT({100'000}, {50'000}, {90'000, 5'000}, {90'000}, {FeeDisplayKernel(10'000, 90'000, {40'000})}), 15'000},
        {"multiple kernels", FeeDisplayPSBT({100'000}, {20'000, 30'000}, {30'000, 60'000}, {80'000},
            {FeeDisplayKernel(2'000, 30'000, {7'000, 11'000}), FeeDisplayKernel(4'000, 60'000, {17'000, 19'000})}), 16'000},
        {"zero fee", FeeDisplayPSBT({}, {0, 50'000}, {}, {50'000}, {FeeDisplayKernel(0)}), 0},
    };
    for (const FeeCase& test : cases) {
        BOOST_TEST_CONTEXT(test.name) {
            const UniValue decoded = DecodePSBT(test.psbt);
            BOOST_REQUIRE(decoded.exists("fee"));
            BOOST_CHECK_EQUAL(AmountFromValue(decoded["fee"]), test.expected_fee);
        }
    }

    CMutableTransaction previous;
    previous.vin.emplace_back();
    previous.vout.emplace_back(100'000, CScript{} << OP_TRUE);
    CMutableTransaction spending;
    spending.vin.emplace_back(COutPoint{previous.GetHash(), 0});
    spending.vout.emplace_back(90'000, CScript{} << OP_TRUE);
    for (uint32_t version : {0U, 2U}) {
        PartiallySignedTransaction psbt{spending, version};
        psbt.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
        for (bool also_witness_utxo : {false, true}) {
            if (also_witness_utxo) psbt.inputs[0].witness_utxo = previous.vout[0];
            const UniValue decoded = DecodePSBT(psbt);
            BOOST_REQUIRE(decoded.exists("fee"));
            BOOST_CHECK_EQUAL(AmountFromValue(decoded["fee"]), 10'000);
        }
    }
}

// A missing input amount, or an out-of-range input, output or kernel amount,
// omits the fee instead of showing a misleading partial total.
BOOST_AUTO_TEST_CASE(decodepsbt_fee_requires_known_amounts)
{
    const auto original = FeeDisplayPSBT({100'000}, {50'000}, {90'000}, {80'000}, {FeeDisplayKernel(10'000, 90'000, {50'000})});
    BOOST_REQUIRE(DecodePSBT(original).exists("fee"));
    for (int missing_input : {0, 1}) {
        auto psbt = original;
        if (missing_input == 0) {
            psbt.inputs[0].witness_utxo.SetNull();
        } else {
            psbt.inputs[1].mweb_amount.reset();
        }
        BOOST_CHECK(!DecodePSBT(psbt).exists("fee"));
    }
    for (CAmount amount : {CAmount{-1}, MAX_MONEY + 1}) {
        for (int field : {0, 1, 2, 3, 4}) {
            BOOST_TEST_CONTEXT("amount " << amount << " field " << field) {
                auto psbt = original;
                if (field == 0) psbt.inputs[0].witness_utxo.nValue = amount;
                if (field == 1) psbt.inputs[1].mweb_amount = amount;
                if (field == 2) psbt.outputs[1].amount = amount;
                if (field == 3) psbt.kernels[0].pegin_amount = amount;
                if (field == 4) psbt.kernels[0].pegouts[0] = PegOutCoin{amount, CScript{} << OP_TRUE};
                BOOST_CHECK(!DecodePSBT(psbt).exists("fee"));
            }
        }
    }
    // Each amount may be in range while their sum is not.
    for (bool inputs : {false, true}) {
        auto psbt = original;
        if (inputs) {
            psbt.inputs[1].mweb_amount = MAX_MONEY;
        } else {
            psbt.kernels[0].pegouts[0] = PegOutCoin{MAX_MONEY, CScript{} << OP_TRUE};
        }
        BOOST_CHECK(!DecodePSBT(psbt).exists("fee"));
    }
}

BOOST_AUTO_TEST_SUITE_END()
