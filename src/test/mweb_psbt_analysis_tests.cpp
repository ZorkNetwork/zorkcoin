// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/psbt.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <mw/consensus/weight.h>
#include <policy/feerate.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

using namespace psbt_test;
using node::AnalyzePSBT;
using node::PSBTAnalysis;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_analysis_tests, BasicTestingSetup)

namespace {

//! A canonical PSBTv2 with one wpkh input and one output.
PartiallySignedTransaction WpkhPSBT(const CKey& key)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.inputs.push_back(CanonicalInput());
    psbt.outputs.push_back(CanonicalOutput(90'000, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()))));
    return psbt;
}

CFeeRate ExpectedFeeRate(CAmount fee, size_t vsize, size_t mweb_weight)
{
    const CAmount mweb_fee = CFeeRate::GetMWEBFee(mweb_weight);
    if (mweb_fee > 0 && fee < mweb_fee) return CFeeRate(0, vsize);
    return CFeeRate(fee - mweb_fee, vsize);
}

} // namespace

BOOST_AUTO_TEST_CASE(analyze_canonical_role_progression)
{
    const CKey key = ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    // No UTXO: the Updater must attach one; no fee can be computed.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(WpkhPSBT(key));
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(!analysis.inputs[0].has_utxo);
        BOOST_CHECK(!analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.fee.has_value());
        BOOST_CHECK(!analysis.estimated_mweb_weight.has_value());
    }

    // UTXO present but the signing pubkey is unknown (no BIP32 keypath):
    // more than signatures is missing, so the Updater is still next.
    PartiallySignedTransaction psbt = WpkhPSBT(key);
    psbt.inputs[0].witness_utxo = CTxOut(100'000, wpkh_script);
    {
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.inputs[0].has_utxo);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.inputs[0].missing_pubkeys.empty());
    }

    // With the keypath attached only signatures are missing: Signer is next,
    // and the fee is computable.
    psbt.inputs[0].hd_keypaths.emplace(key.GetPubKey(), KeyOriginInfo{});
    {
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::SIGNER);
        BOOST_CHECK(!analysis.inputs[0].missing_sigs.empty());
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});
    }

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());

    // With a partial signature the input can be finalized.
    {
        PartiallySignedTransaction partial = psbt;
        const std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(partial);
        BOOST_REQUIRE(txdata);
        BOOST_REQUIRE(SignPSBTInput(provider, partial, 0, &*txdata, {.sighash_type = SIGHASH_ALL, .finalize = false}).has_value());
        const PSBTAnalysis analysis = AnalyzePSBT(partial);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::FINALIZER);
        BOOST_CHECK(analysis.next == PSBTRole::FINALIZER);
    }

    // Finalized: nothing left but extraction. Without MWEB components no MWEB
    // weight is reported, and the feerate is the plain canonical feerate.
    {
        PartiallySignedTransaction final_psbt = psbt;
        const std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(final_psbt);
        BOOST_REQUIRE(txdata);
        BOOST_REQUIRE(SignPSBTInput(provider, final_psbt, 0, &*txdata, {.sighash_type = SIGHASH_ALL, .finalize = true}).has_value());
        const PSBTAnalysis analysis = AnalyzePSBT(final_psbt);
        BOOST_CHECK(analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::EXTRACTOR);
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
        BOOST_REQUIRE(analysis.estimated_vsize.has_value());
        BOOST_CHECK(!analysis.estimated_mweb_weight.has_value());
        BOOST_CHECK(*analysis.estimated_feerate == CFeeRate(10'000, *analysis.estimated_vsize));
    }
}

BOOST_AUTO_TEST_CASE(analyze_mweb_role)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    // Fully signed: every MWEB component shares the EXTRACTOR role.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(full);
        BOOST_CHECK(analysis.error.empty());
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(analysis.inputs[0].is_final);
        BOOST_CHECK(!analysis.inputs[0].has_utxo); // MWEB inputs carry no canonical UTXO
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::EXTRACTOR);
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
    }

    // Unsigned MWEB components: the (single, shared) MWEB role is SIGNER.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(StripMWEBSignatures(full));
        BOOST_CHECK(!analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::SIGNER);
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
    }

    // Signed but missing either global offset: still the Signer's job.
    {
        PartiallySignedTransaction no_offsets = full;
        no_offsets.mweb_tx_offset.reset();
        BOOST_CHECK(AnalyzePSBT(no_offsets).next == PSBTRole::SIGNER);
    }
    {
        PartiallySignedTransaction no_offsets = full;
        no_offsets.mweb_stealth_offset.reset();
        BOOST_CHECK(AnalyzePSBT(no_offsets).next == PSBTRole::SIGNER);
    }

    // MWEB components present but no kernel yet: still the Signer's job.
    {
        PartiallySignedTransaction no_kernels = full;
        no_kernels.kernels.clear();
        BOOST_CHECK(AnalyzePSBT(no_kernels).next == PSBTRole::SIGNER);
    }

    // An incomplete output or kernel also leaves the shared role at SIGNER.
    {
        PartiallySignedTransaction psbt = full;
        psbt.outputs[0].mweb_rangeproof.reset();
        BOOST_CHECK(AnalyzePSBT(psbt).next == PSBTRole::SIGNER);
    }
    {
        PartiallySignedTransaction psbt = full;
        psbt.kernels[0].sig.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::SIGNER);
    }
    // A kernel field without its feature bit isn't read back, so the kernel is incomplete.
    for (const uint8_t bit : {uint8_t{Kernel::FEE_FEATURE_BIT}, uint8_t{Kernel::STEALTH_EXCESS_FEATURE_BIT}}) {
        PartiallySignedTransaction psbt = full;
        BOOST_REQUIRE(*psbt.kernels[0].features & bit);
        *psbt.kernels[0].features &= ~bit;
        BOOST_CHECK(AnalyzePSBT(psbt).next == PSBTRole::SIGNER);
    }

    // The peg-out and mixed peg-in vectors are fully signed too.
    BOOST_CHECK(AnalyzePSBT(DecodeHexPSBT(PSBT_PEGOUT_SIGNED)).next == PSBTRole::EXTRACTOR);
    BOOST_CHECK(AnalyzePSBT(DecodeHexPSBT(PSBT_PEGIN_SIGNED)).next == PSBTRole::EXTRACTOR);

    // A peg-in has no MWEB inputs: an unsigned kernel still holds the PSBT at
    // SIGNER even though every canonical input is final.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
        psbt.kernels[0].sig.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        for (const auto& input : analysis.inputs) {
            BOOST_CHECK(input.next == PSBTRole::EXTRACTOR);
        }
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
    }
}

BOOST_AUTO_TEST_CASE(analyze_mweb_amount_required)
{
    // An ID-only Creator PSBT still needs an updater to attach the
    // confidential amount. It is incomplete, not malformed.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_amount.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.error.empty());
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(!analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.fee.has_value());
        BOOST_CHECK(!analysis.estimated_mweb_weight.has_value());
    }

    // Public coin metadata is also updater data.
    for (int field = 0; field < 2; ++field) {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        if (field == 0) psbt.inputs[0].mweb_output_commit.reset();
        if (field == 1) psbt.inputs[0].mweb_output_pubkey.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.error.empty());
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
    }

    // A supplied amount outside the monetary range is malformed.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_amount = MAX_MONEY + 1;
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK_EQUAL(analysis.error, "PSBT is not valid. Input 0 has invalid value");
        BOOST_CHECK(analysis.next == PSBTRole::CREATOR);
    }
}

BOOST_AUTO_TEST_CASE(analyze_fee_and_weight)
{
    // MWEB-to-MWEB: fee = inputs - outputs.
    {
        const PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});

        // The estimated weight is composed from the consensus weight
        // primitives, one term per MWEB component.
        const bool standard_fields = !psbt.outputs[0].mweb_features.has_value() ||
                                     (*psbt.outputs[0].mweb_features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT);
        const size_t expected_weight =
            Weight::CalcInputWeight(psbt.inputs[0].mweb_extra_data) +
            Weight::CalcOutputWeight(standard_fields, psbt.outputs[0].mweb_extra_data) +
            Weight::CalcKernelWeight(/*has_stealth_excess=*/true, psbt.kernels[0].pegouts, psbt.kernels[0].extra_data);
        BOOST_CHECK(analysis.estimated_mweb_weight == std::optional<size_t>{expected_weight});

        // The estimate matches the weight of the extracted transaction.
        PartiallySignedTransaction finalized = psbt;
        CMutableTransaction extracted;
        BOOST_REQUIRE(FinalizeAndExtractPSBT(finalized, extracted));
        BOOST_CHECK_EQUAL(expected_weight, extracted.mweb_tx.GetMWEBWeight());

        BOOST_REQUIRE(analysis.estimated_vsize.has_value());
        BOOST_REQUIRE(analysis.estimated_feerate.has_value());
        BOOST_CHECK(*analysis.estimated_feerate == ExpectedFeeRate(10'000, *analysis.estimated_vsize, expected_weight));

        // With no kernels yet, one estimated kernel is added to the weight.
        PartiallySignedTransaction no_kernels = psbt;
        no_kernels.kernels.clear();
        const PSBTAnalysis no_kernel_analysis = AnalyzePSBT(no_kernels);
        const size_t expected_kernel_less =
            Weight::CalcInputWeight(psbt.inputs[0].mweb_extra_data) +
            Weight::CalcOutputWeight(standard_fields, psbt.outputs[0].mweb_extra_data) +
            Weight::CalcKernelWeight(/*has_stealth_excess=*/true, std::vector<PegOutCoin>{});
        BOOST_CHECK(no_kernel_analysis.estimated_mweb_weight == std::optional<size_t>{expected_kernel_less});

        // An output without features is estimated with standard fields.
        PartiallySignedTransaction no_features = StripMWEBSignatures(psbt);
        no_features.outputs[0].mweb_features.reset();
        const PSBTAnalysis no_features_analysis = AnalyzePSBT(no_features);
        BOOST_CHECK(no_features_analysis.estimated_mweb_weight ==
                    std::optional<size_t>{Weight::CalcInputWeight(psbt.inputs[0].mweb_extra_data) +
                                          Weight::CalcOutputWeight(true, psbt.outputs[0].mweb_extra_data) +
                                          Weight::CalcKernelWeight(true, psbt.kernels[0].pegouts, psbt.kernels[0].extra_data)});
    }

    // A fee below the MWEB weight fee gives a zero feerate, not a negative one.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MIXED_SIGNED);
        const auto mweb_output = std::find_if(psbt.outputs.begin(), psbt.outputs.end(), [](const PSBTOutput& o) { return o.IsMWEB(); });
        BOOST_REQUIRE(mweb_output != psbt.outputs.end());
        mweb_output->amount += 19'999;
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{1});
        BOOST_REQUIRE(analysis.estimated_vsize.has_value());
        BOOST_REQUIRE(analysis.estimated_mweb_weight.has_value());
        BOOST_CHECK_GT(*analysis.estimated_vsize, 0U);
        BOOST_CHECK_GT(CFeeRate::GetMWEBFee(*analysis.estimated_mweb_weight), 1);
        BOOST_REQUIRE(analysis.estimated_feerate.has_value());
        BOOST_CHECK(*analysis.estimated_feerate == CFeeRate(0, *analysis.estimated_vsize));
    }

    // Above the MWEB weight fee, only the remainder pays for the canonical bytes.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(DecodeHexPSBT(PSBT_MIXED_SIGNED));
        BOOST_REQUIRE(analysis.estimated_feerate.has_value());
        const CAmount mweb_fee = CFeeRate::GetMWEBFee(*analysis.estimated_mweb_weight);
        BOOST_REQUIRE_LT(mweb_fee, 20'000);
        BOOST_CHECK(*analysis.estimated_feerate == CFeeRate(20'000 - mweb_fee, *analysis.estimated_vsize));
    }

    // Peg-out: fee = inputs - outputs - pegouts.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(DecodeHexPSBT(PSBT_PEGOUT_SIGNED));
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});
    }

    // Mixed peg-in: fee = canonical input + pegin - outputs, i.e. the
    // canonical fee (10k) plus the MWEB kernel fee (10k).
    {
        const PSBTAnalysis analysis = AnalyzePSBT(DecodeHexPSBT(PSBT_MIXED_SIGNED));
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{20'000});
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
        BOOST_CHECK(analysis.estimated_vsize.has_value());
        BOOST_CHECK(analysis.estimated_mweb_weight.has_value());
    }
}

BOOST_AUTO_TEST_CASE(analyze_invalid_amounts_and_utxos)
{
    // Output amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.outputs[0].amount = MAX_MONEY + 1;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Output amount invalid");
    }
    // Pegin amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.kernels[0].pegin_amount = MAX_MONEY + 1;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Pegin amount invalid");
    }
    // Pegout amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.kernels[0].pegouts.emplace_back(MAX_MONEY + 1, CScript() << OP_TRUE);
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Pegout amount invalid");
    }
    // Unspendable UTXO
    {
        const CKey key = ToCKey(TestSecret('7'));
        PartiallySignedTransaction psbt = WpkhPSBT(key);
        psbt.inputs[0].witness_utxo = CTxOut(100'000, CScript() << OP_RETURN);
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Input 0 spends unspendable output");
    }
    // Previous transaction attached, but the outpoint index is out of range
    {
        CMutableTransaction prev;
        prev.vout.emplace_back(100'000, CScript() << OP_TRUE);
        const CTransactionRef prev_ref = MakeTransactionRef(prev);

        const CKey key = ToCKey(TestSecret('7'));
        PartiallySignedTransaction psbt = WpkhPSBT(key);
        psbt.inputs[0].non_witness_utxo = prev_ref;
        psbt.inputs[0].prev_txid = prev_ref->GetHash();
        psbt.inputs[0].prev_out = 5;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Input 0 specifies invalid prevout");
    }
}

BOOST_AUTO_TEST_SUITE_END()
