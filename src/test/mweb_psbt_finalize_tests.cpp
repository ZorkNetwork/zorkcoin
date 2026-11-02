// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <addresstype.h>
#include <key.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <optional>

using namespace psbt_test;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_finalize_tests, BasicTestingSetup)

namespace {

void CheckFinalizeFails(PartiallySignedTransaction psbt)
{
    const std::string before = SerHex(psbt);
    BOOST_CHECK(!FinalizePSBT(psbt));
    BOOST_CHECK_EQUAL(SerHex(psbt), before);
    CMutableTransaction result;
    BOOST_CHECK(!FinalizeAndExtractPSBT(psbt, result));
}

CMutableTransaction FinalizeAndExtract(PartiallySignedTransaction& psbt)
{
    CMutableTransaction result;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, result));
    return result;
}

} // namespace

BOOST_AUTO_TEST_CASE(finalize_mweb_golden)
{
    PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
    const CMutableTransaction result = FinalizeAndExtract(psbt);

    // The extracted transaction carries the MWEB payload and validates
    // (bulletproofs, Schnorr signatures, kernel balance).
    BOOST_REQUIRE(!result.mweb_tx.IsNull());
    const CTransaction tx{result};
    BOOST_REQUIRE(!tx.mweb_tx.IsNull());
    BOOST_CHECK(!tx.mweb_tx.m_transaction->GetValidationError().has_value());

    // Extraction reproduces the PSBT's unsigned transaction.
    BOOST_CHECK(result.GetHash() == psbt.GetUnsignedTx()->GetHash());
    // Finalizing a complete PSBT changes nothing.
    BOOST_CHECK_EQUAL(SerHex(psbt), PSBT_MWEB_SIGNED);
}

BOOST_AUTO_TEST_CASE(finalize_pegin_golden)
{
    PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
    const CMutableTransaction result = FinalizeAndExtract(psbt);

    // The extracted transaction's peg-in output carries the final script,
    // committing to the signed kernel's ID.
    BOOST_REQUIRE_EQUAL(result.vout.size(), 1U);
    mw::Hash kernel_id;
    BOOST_REQUIRE(result.vout[0].scriptPubKey.IsMWEBPegin(&kernel_id));
    BOOST_CHECK(!kernel_id.IsZero());
    BOOST_REQUIRE_EQUAL(result.mweb_tx.kernels.size(), 1U);
    BOOST_CHECK(result.mweb_tx.kernels[0].GetKernelID() == std::optional<mw::Hash>{kernel_id});
}

BOOST_AUTO_TEST_CASE(finalize_pegout_golden)
{
    PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGOUT_SIGNED);
    const CMutableTransaction result = FinalizeAndExtract(psbt);
    BOOST_REQUIRE(!result.mweb_tx.IsNull());
    BOOST_CHECK(!CTransaction{result}.mweb_tx.m_transaction->GetValidationError().has_value());
    BOOST_CHECK(!result.mweb_tx.GetPegOutCoins().empty());
}

BOOST_AUTO_TEST_CASE(finalize_mixed_golden)
{
    PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MIXED_SIGNED);
    const CMutableTransaction result = FinalizeAndExtract(psbt);

    // Both the canonical witness and the MWEB components survive extraction.
    BOOST_REQUIRE_EQUAL(result.vin.size(), 1U);
    BOOST_CHECK(result.vin[0].scriptWitness.stack == psbt.inputs[0].final_script_witness.stack);
    BOOST_CHECK(!result.mweb_tx.IsNull());
    BOOST_CHECK(!CTransaction{result}.mweb_tx.m_transaction->GetValidationError().has_value());
}

BOOST_AUTO_TEST_CASE(finalize_fails_incomplete_mweb)
{
    // Each removal covers a different gate: the output rangeproof and kernel
    // signature fail IsComplete(); the offsets additionally feed the final
    // MWEB validation.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.outputs[0].mweb_rangeproof.reset();
        CheckFinalizeFails(std::move(psbt));
    }
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.kernels[0].sig.reset();
        CheckFinalizeFails(std::move(psbt));
    }
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.mweb_tx_offset.reset();
        CheckFinalizeFails(std::move(psbt));
    }
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.mweb_stealth_offset.reset();
        CheckFinalizeFails(std::move(psbt));
    }
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_sig.reset();
        CheckFinalizeFails(std::move(psbt));
    }
}

BOOST_AUTO_TEST_CASE(finalize_fails_tampered)
{
    // A wrong input signature is caught by per-input Schnorr verification.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_sig = TestSignature('1');
        BOOST_CHECK(psbt.IsComplete());
        BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
        CheckFinalizeFails(std::move(psbt));
    }
    // An input public key that is not a valid point does not throw.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_input_pubkey = PublicKey{BigInt<33>::FromHex("02" + std::string(64, 'f'))};
        BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
        CheckFinalizeFails(std::move(psbt));
    }
    // A signature without the input public key it was made with cannot be verified.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_input_pubkey.reset();
        BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
    }
    // A wrong rangeproof passes IsComplete() and input verification but is
    // caught by the full MWEB transaction validation (bulletproof check).
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.outputs[0].mweb_rangeproof = TestRangeProof(1);
        BOOST_CHECK(psbt.IsComplete());
        BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));
        CheckFinalizeFails(std::move(psbt));
    }
    // So is a wrong kernel fee (the kernel signature no longer verifies).
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        *psbt.kernels[0].fee += 1;
        BOOST_CHECK(psbt.IsComplete());
        CheckFinalizeFails(std::move(psbt));
    }
}

BOOST_AUTO_TEST_CASE(finalize_fails_pegin_association_mismatch)
{
    // Final script commits to the wrong kernel.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
        psbt.outputs[0].script = GetScriptForPegin(TestHash(5));
        BOOST_CHECK(psbt.IsComplete());
        CheckFinalizeFails(std::move(psbt));
    }

    // A placeholder is valid only during construction, never extraction.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
        psbt.outputs[0].script = GetScriptForPegin(mw::Hash{});
        BOOST_CHECK(psbt.IsComplete());
        CheckFinalizeFails(std::move(psbt));
    }

    // The canonical output amount must equal the paired kernel peg-in amount.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
        psbt.outputs[0].amount = *psbt.kernels[0].pegin_amount + 1;
        BOOST_CHECK(psbt.IsComplete());
        CheckFinalizeFails(std::move(psbt));
    }
}

BOOST_AUTO_TEST_CASE(finalize_canonical_partial_sigs)
{
    const CKey key = ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    const auto make_psbt = [&] {
        PartiallySignedTransaction psbt = EmptyPSBT();
        PSBTInput input = CanonicalInput();
        input.witness_utxo = CTxOut(100'000, wpkh_script);
        psbt.inputs.push_back(input);
        psbt.outputs.push_back(CanonicalOutput(90'000, wpkh_script));
        return psbt;
    };

    // A partial signature (finalize=false) is combined into a final witness
    // by FinalizePSBT.
    {
        PartiallySignedTransaction psbt = make_psbt();
        FlatSigningProvider provider;
        provider.keys.emplace(key.GetPubKey().GetID(), key);
        provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());
        const std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(psbt);
        BOOST_REQUIRE(txdata);
        BOOST_REQUIRE(SignPSBTInput(provider, psbt, 0, &*txdata, {.sighash_type = SIGHASH_ALL, .finalize = false}).has_value());
        BOOST_REQUIRE_EQUAL(psbt.inputs[0].partial_sigs.size(), 1U);
        BOOST_REQUIRE(psbt.inputs[0].final_script_witness.IsNull());
        BOOST_CHECK(!psbt.IsComplete());

        const CMutableTransaction result = FinalizeAndExtract(psbt);
        BOOST_CHECK(psbt.IsComplete());
        BOOST_CHECK(!psbt.inputs[0].final_script_witness.IsNull());
        BOOST_CHECK(!result.vin[0].scriptWitness.IsNull());
        BOOST_CHECK(result.mweb_tx.IsNull());
    }

    // An unsigned input cannot be finalized.
    {
        PartiallySignedTransaction psbt = make_psbt();
        BOOST_CHECK(!FinalizePSBT(psbt));
    }
}

BOOST_AUTO_TEST_SUITE_END()
