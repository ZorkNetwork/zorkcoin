// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <key.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <optional>
#include <vector>

using namespace psbt_test;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_merge_tests, BasicTestingSetup)

namespace {

//! A canonical (non-MWEB) PSBTv2 with one input and one output.
PartiallySignedTransaction CanonicalPSBT(CAmount out_amount = 1'000)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.inputs.push_back(CanonicalInput());
    psbt.outputs.push_back(CanonicalOutput(out_amount));
    return psbt;
}

//! A PSBT containing only the given kernel: minimal MWEB merge context.
PartiallySignedTransaction KernelOnlyPSBT(PSBTKernel kernel)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.kernels.push_back(std::move(kernel));
    return psbt;
}

PSBTKernel FeeKernel()
{
    PSBTKernel kernel;
    kernel.fee = 5;
    return kernel;
}

//! Expect a failed merge that leaves the destination unchanged.
void CheckMergeFailsUntouched(PartiallySignedTransaction dst, const PartiallySignedTransaction& src)
{
    const std::string before = SerHex(dst);
    BOOST_CHECK(!dst.Merge(src));
    BOOST_CHECK_EQUAL(SerHex(dst), before);
}

SigPair DummySigPair()
{
    return SigPair(CPubKey(), std::vector<unsigned char>{0x30});
}

} // namespace

BOOST_AUTO_TEST_CASE(merge_identical_signed_is_noop)
{
    for (const std::string* vec : {&PSBT_MWEB_SIGNED, &PSBT_PEGIN_SIGNED, &PSBT_MIXED_SIGNED, &PSBT_PEGOUT_SIGNED}) {
        PartiallySignedTransaction psbt = DecodeHexPSBT(*vec);
        BOOST_CHECK(psbt.Merge(DecodeHexPSBT(*vec)));
        BOOST_CHECK_EQUAL(SerHex(psbt), *vec);
    }

    PartiallySignedTransaction canonical = CanonicalPSBT();
    const std::string before = SerHex(canonical);
    BOOST_CHECK(canonical.Merge(CanonicalPSBT()));
    BOOST_CHECK_EQUAL(SerHex(canonical), before);
}

BOOST_AUTO_TEST_CASE(merge_disjoint_union)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    PartiallySignedTransaction a = full;
    a.inputs[0].mweb_sig.reset();
    a.inputs[0].mweb_shared_secret.reset();

    PartiallySignedTransaction b = full;
    b.outputs[0].mweb_rangeproof.reset();
    b.outputs[0].mweb_sig.reset();
    b.kernels[0].sig.reset();
    b.mweb_tx_offset.reset();
    b.mweb_stealth_offset.reset();

    // Each side fills the other's gaps; both orders reassemble the original.
    PartiallySignedTransaction merged = a;
    BOOST_REQUIRE(merged.Merge(b));
    BOOST_CHECK_EQUAL(SerHex(merged), PSBT_MWEB_SIGNED);

    PartiallySignedTransaction reversed = b;
    BOOST_REQUIRE(reversed.Merge(a));
    BOOST_CHECK_EQUAL(SerHex(reversed), PSBT_MWEB_SIGNED);
}

BOOST_AUTO_TEST_CASE(merge_mweb_input_ignores_base_fields)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    PartiallySignedTransaction src = full;
    PSBTInput& input = src.inputs[0];
    input.sequence = 7;
    input.partial_sigs.emplace(CKeyID(), DummySigPair());
    input.witness_utxo = CTxOut(1'000, CScript() << OP_TRUE);
    input.sha256_preimages.emplace(uint256::ONE, std::vector<unsigned char>{0x01});
    input.hd_keypaths.emplace(CPubKey(TestPubKey('7').vec()), KeyOriginInfo{});
    input.redeem_script = CScript() << OP_TRUE;

    PartiallySignedTransaction merged = full;
    BOOST_REQUIRE(merged.Merge(src));
    BOOST_CHECK_EQUAL(SerHex(merged), PSBT_MWEB_SIGNED);
    const PSBTInput& merged_input = merged.inputs[0];
    BOOST_CHECK(!merged_input.sequence.has_value());
    BOOST_CHECK(merged_input.partial_sigs.empty());
    BOOST_CHECK(merged_input.witness_utxo.IsNull());
    BOOST_CHECK(merged_input.sha256_preimages.empty());
    BOOST_CHECK(merged_input.hd_keypaths.empty());
    BOOST_CHECK(merged_input.redeem_script.empty());
}

BOOST_AUTO_TEST_CASE(merge_without_mweb_components_skips_pegin_checks)
{
    // A final peg-in script with no kernel can never be extracted validly, but a PSBT without MWEB components
    // merges exactly as upstream.
    PartiallySignedTransaction psbt = CanonicalPSBT();
    psbt.outputs.push_back(CanonicalOutput(1'000, GetScriptForPegin(TestHash(5))));
    BOOST_REQUIRE(!psbt.ContainsMWEBComponents());
    BOOST_CHECK(!VerifyPeginOutputs(psbt, /*require_final=*/false));

    PartiallySignedTransaction merged = psbt;
    BOOST_CHECK(merged.Merge(psbt));
}

BOOST_AUTO_TEST_CASE(merge_conflicting_input_fields_fail)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    // Each setter assigns one MWEB input field to one of two distinct values.
    using Setter = std::function<void(PSBTInput&, int)>;
    const std::vector<Setter> setters{
        [](PSBTInput& in, int v) { in.mweb_output_commit = TestCommitment(70 + v); },
        [](PSBTInput& in, int v) { in.mweb_output_pubkey = TestPubKey(v ? '1' : '2'); },
        [](PSBTInput& in, int v) { in.mweb_input_pubkey = TestPubKey(v ? '3' : '4'); },
        [](PSBTInput& in, int v) { in.mweb_features = static_cast<uint8_t>(v); },
        [](PSBTInput& in, int v) { in.mweb_sig = TestSignature(v ? '5' : '6'); },
        [](PSBTInput& in, int v) { in.mweb_amount = 100 + v; },
        [](PSBTInput& in, int v) { in.mweb_shared_secret = TestSecret(v ? '7' : '8'); },
        [](PSBTInput& in, int v) { in.mweb_key_exchange_pubkey = TestPubKey(v ? '9' : 'a'); },
        [](PSBTInput& in, int v) { in.mweb_address_descriptor = v ? "mweb(a)" : "mweb(b)"; },
        [](PSBTInput& in, int v) { in.mweb_extra_data = {static_cast<uint8_t>(v)}; },
        [](PSBTInput& in, int v) { in.unknown[{0xa0}] = {static_cast<uint8_t>(v)}; },
        [](PSBTInput& in, int v) { in.prev_txid = TestTxid(1 + v); },
        [](PSBTInput& in, int v) { in.prev_out = v; },
    };

    for (size_t i = 0; i < setters.size(); ++i) {
        PartiallySignedTransaction x = full;
        PartiallySignedTransaction y = full;
        setters[i](x.inputs[0], 0);
        setters[i](y.inputs[0], 1);
        BOOST_TEST_CONTEXT("input setter #" << i) CheckMergeFailsUntouched(x, y);
    }
}

BOOST_AUTO_TEST_CASE(merge_conflicting_output_fields_fail)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    using Setter = std::function<void(PSBTOutput&, int)>;
    const std::vector<Setter> setters{
        [](PSBTOutput& out, int v) { out.amount = 100 + v; },
        [](PSBTOutput& out, int v) { out.mweb_stealth_address = TestStealthAddress(v ? '1' : '2', '3'); },
        [](PSBTOutput& out, int v) { out.mweb_commit = TestCommitment(80 + v); },
        [](PSBTOutput& out, int v) { out.mweb_features = static_cast<uint8_t>(v); },
        [](PSBTOutput& out, int v) { out.mweb_sender_pubkey = TestPubKey(v ? '4' : '5'); },
        [](PSBTOutput& out, int v) { out.mweb_output_pubkey = TestPubKey(v ? '6' : '7'); },
        [](PSBTOutput& out, int v) { out.mweb_sig = TestSignature(v ? '8' : '9'); },
        [](PSBTOutput& out, int v) { out.mweb_extra_data = {static_cast<uint8_t>(v)}; },
        [](PSBTOutput& out, int v) { out.mweb_rangeproof = TestRangeProof(v); },
        // Each sub-field of the standard fields conflicts independently.
        [](PSBTOutput& out, int v) { out.mweb_standard_fields = OutputStandardFields(TestPubKey(v ? 'a' : 'b'), 1, 2, BigInt<16>::ValueOf(3)); },
        [](PSBTOutput& out, int v) { out.mweb_standard_fields = OutputStandardFields(TestPubKey('a'), v, 2, BigInt<16>::ValueOf(3)); },
        [](PSBTOutput& out, int v) { out.mweb_standard_fields = OutputStandardFields(TestPubKey('a'), 1, v, BigInt<16>::ValueOf(3)); },
        [](PSBTOutput& out, int v) { out.mweb_standard_fields = OutputStandardFields(TestPubKey('a'), 1, 2, BigInt<16>::ValueOf(v)); },
        [](PSBTOutput& out, int v) { out.unknown[{0xa0}] = {static_cast<uint8_t>(v)}; },
    };

    for (size_t i = 0; i < setters.size(); ++i) {
        PartiallySignedTransaction x = full;
        PartiallySignedTransaction y = full;
        setters[i](x.outputs[0], 0);
        setters[i](y.outputs[0], 1);
        BOOST_TEST_CONTEXT("output setter #" << i) CheckMergeFailsUntouched(x, y);
    }
}

BOOST_AUTO_TEST_CASE(merge_signed_vs_alt_signed_fails)
{
    // Two independent signings of the same structure: structurally
    // compatible, cryptographically conflicting on every signature,
    // commitment, and offset.
    CheckMergeFailsUntouched(DecodeHexPSBT(PSBT_MWEB_SIGNED), DecodeHexPSBT(PSBT_MWEB_SIGNED_ALT));
}

BOOST_AUTO_TEST_CASE(merge_kernel_rules)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    // Disjoint fields union.
    {
        PartiallySignedTransaction x = full;
        x.kernels[0].sig.reset();
        BOOST_REQUIRE(x.Merge(full));
        BOOST_CHECK(x.kernels[0].sig == full.kernels[0].sig);
    }

    // Conflicting values fail.
    {
        PartiallySignedTransaction x = full;
        x.kernels[0].fee = 9'999;
        CheckMergeFailsUntouched(x, full);
    }
    {
        PartiallySignedTransaction y = full;
        y.kernels[0].sig = TestSignature('0');
        CheckMergeFailsUntouched(full, y);
    }
    {
        PSBTKernel kx;
        kx.lock_height = 1;
        PSBTKernel ky;
        ky.lock_height = 2;
        CheckMergeFailsUntouched(KernelOnlyPSBT(kx), KernelOnlyPSBT(ky));
    }
    {
        const CScript script = CScript() << OP_TRUE;
        PSBTKernel kx;
        kx.pegouts.emplace_back(1, script);
        PSBTKernel ky;
        ky.pegouts.emplace_back(2, script);
        CheckMergeFailsUntouched(KernelOnlyPSBT(kx), KernelOnlyPSBT(ky));

        // Fill-empty still works for pegout vectors.
        PartiallySignedTransaction empty = KernelOnlyPSBT(PSBTKernel{});
        BOOST_REQUIRE(empty.Merge(KernelOnlyPSBT(kx)));
        BOOST_CHECK(empty.kernels[0].pegouts == kx.pegouts);
    }

    // A features byte inconsistent with the populated fields fails the merge.
    {
        PSBTKernel kx;
        kx.features = Kernel::FEE_FEATURE_BIT;
        kx.fee = 5;
        PSBTKernel ky = kx;
        ky.lock_height = 7; // features byte now understates the fields
        CheckMergeFailsUntouched(KernelOnlyPSBT(kx), KernelOnlyPSBT(ky));
    }

    // After a successful merge that adds fields, the features byte is
    // recomputed to cover the union.
    {
        PSBTKernel kx;
        kx.features = Kernel::FEE_FEATURE_BIT;
        kx.fee = 5;
        PSBTKernel ky;
        ky.fee = 5;
        ky.lock_height = 7; // no features byte, so consistent

        PartiallySignedTransaction merged = KernelOnlyPSBT(kx);
        BOOST_REQUIRE(merged.Merge(KernelOnlyPSBT(ky)));
        BOOST_CHECK(merged.kernels[0].lock_height == std::optional<int32_t>{7});
        BOOST_CHECK(merged.kernels[0].features == std::optional<uint8_t>{Kernel::FEE_FEATURE_BIT | Kernel::HEIGHT_LOCK_FEATURE_BIT});
    }
}

BOOST_AUTO_TEST_CASE(merge_structure_mismatch)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    // Component count mismatch
    {
        PartiallySignedTransaction extra_kernel = full;
        extra_kernel.kernels.emplace_back();
        CheckMergeFailsUntouched(full, extra_kernel);
    }
    {
        PartiallySignedTransaction extra_output = full;
        extra_output.outputs.push_back(MWEBOutput());
        CheckMergeFailsUntouched(full, extra_output);
    }

    // Transaction version mismatch
    {
        PartiallySignedTransaction a = CanonicalPSBT();
        PartiallySignedTransaction b = CanonicalPSBT();
        b.tx_version = 3;
        CheckMergeFailsUntouched(a, b);
    }
    {
        PartiallySignedTransaction b = full;
        b.tx_version = 3;
        CheckMergeFailsUntouched(full, b);
    }

    // MWEB input vs canonical input at the same index
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        a.inputs.push_back(MWEBInput(TestHash(1)));
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        b.inputs.push_back(CanonicalInput());
        CheckMergeFailsUntouched(a, b);
    }

    // Different MWEB output IDs
    {
        PartiallySignedTransaction x = full;
        x.inputs[0].mweb_output_id = TestHash(0x77);
        CheckMergeFailsUntouched(x, full);
    }

    // Different canonical outpoints, in an MWEB context (bypasses the
    // unique-ID gate, exercising the per-input structural check).
    {
        const auto with_input = [&](uint32_t vout) {
            PartiallySignedTransaction psbt = KernelOnlyPSBT(FeeKernel());
            psbt.inputs.push_back(CanonicalInput(Txid::FromUint256(uint256::ONE), vout));
            return psbt;
        };
        CheckMergeFailsUntouched(with_input(0), with_input(1));
    }

    // Output MWEB-ness disagreement at the same index
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        a.outputs.push_back(CanonicalOutput());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        b.outputs.push_back(MWEBOutput());
        CheckMergeFailsUntouched(a, b);
    }

    // PSBT versions must match.
    {
        PartiallySignedTransaction v0(CMutableTransaction{*full.GetUnsignedTx()}, /*version=*/0);
        CheckMergeFailsUntouched(full, v0);
    }
}

BOOST_AUTO_TEST_CASE(merge_unique_id_vs_structural)
{
    // Non-MWEB PSBTs over different transactions refuse to merge (unique-ID gate).
    {
        PartiallySignedTransaction a = CanonicalPSBT(1'000);
        PartiallySignedTransaction b = CanonicalPSBT(2'000);
        BOOST_CHECK(a.GetUniqueID() != b.GetUniqueID());
        CheckMergeFailsUntouched(a, b);
    }

    // MWEB PSBTs whose canonical parts differ only in a peg-in script
    // (placeholder vs final, hence different base txids) still merge: MWEB
    // signing finalizes peg-in scriptPubKeys, so the comparison is structural.
    {
        const PartiallySignedTransaction final_psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
        PartiallySignedTransaction placeholder = final_psbt;
        placeholder.outputs[0].script = GetScriptForPegin(mw::Hash{});

        BOOST_CHECK(placeholder.GetUniqueID() != final_psbt.GetUniqueID());
        BOOST_REQUIRE(placeholder.Merge(final_psbt));
        BOOST_CHECK(placeholder.outputs[0].script == final_psbt.outputs[0].script);
    }

    // MWEB merges require matching effective locktimes.
    {
        const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        PartiallySignedTransaction later = full;
        later.fallback_locktime = 7;
        CheckMergeFailsUntouched(full, later);
    }
}

BOOST_AUTO_TEST_CASE(merge_unknown_proprietary_semantics)
{
    const auto with_canonical_maps = [] {
        PartiallySignedTransaction psbt = KernelOnlyPSBT(FeeKernel());
        const PartiallySignedTransaction canonical = CanonicalPSBT();
        psbt.inputs = canonical.inputs;
        psbt.outputs = canonical.outputs;
        return psbt;
    };

    // MWEB context: same unknown key with a different value fails, at every map level.
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        a.unknown[{0xa0}] = {0x01};
        b.unknown[{0xa0}] = {0x02};
        CheckMergeFailsUntouched(a, b);
    }
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        a.kernels[0].unknown[{0xa0}] = {0x01};
        b.kernels[0].unknown[{0xa0}] = {0x02};
        CheckMergeFailsUntouched(a, b);
    }
    {
        PartiallySignedTransaction a = with_canonical_maps();
        PartiallySignedTransaction b = with_canonical_maps();
        a.inputs[0].unknown[{0xa0}] = {0x01};
        b.inputs[0].unknown[{0xa0}] = {0x02};
        CheckMergeFailsUntouched(a, b);
    }
    {
        PartiallySignedTransaction a = with_canonical_maps();
        PartiallySignedTransaction b = with_canonical_maps();
        a.outputs[0].unknown[{0xa0}] = {0x01};
        b.outputs[0].unknown[{0xa0}] = {0x02};
        CheckMergeFailsUntouched(a, b);
    }

    // Same key, same value merges.
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        a.unknown[{0xa0}] = {0x01};
        b.unknown[{0xa0}] = {0x01};
        BOOST_CHECK(a.Merge(b));
    }

    // Proprietary: same key, different value fails in an MWEB context.
    {
        PSBTProprietary p1 = TestProprietary();
        PSBTProprietary p2 = TestProprietary();
        p2.value = {0xff};

        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        a.m_proprietary.insert(p1);
        b.m_proprietary.insert(p2);
        CheckMergeFailsUntouched(a, b);
    }
    {
        PSBTProprietary p1 = TestProprietary("canonical-input");
        PSBTProprietary p2 = p1;
        p2.value = {0xff};

        PartiallySignedTransaction a = with_canonical_maps();
        PartiallySignedTransaction b = with_canonical_maps();
        a.inputs[0].m_proprietary.insert(p1);
        b.inputs[0].m_proprietary.insert(p2);
        CheckMergeFailsUntouched(a, b);
    }
    {
        PSBTProprietary p1 = TestProprietary("canonical-output");
        PSBTProprietary p2 = p1;
        p2.value = {0xff};

        PartiallySignedTransaction a = with_canonical_maps();
        PartiallySignedTransaction b = with_canonical_maps();
        a.outputs[0].m_proprietary.insert(p1);
        b.outputs[0].m_proprietary.insert(p2);
        CheckMergeFailsUntouched(a, b);
    }

    // Non-conflicting metadata in canonical maps is preserved in an MWEB
    // packet, including source-only proprietary records.
    {
        const PSBTProprietary input_prop = TestProprietary("canonical-input");
        const PSBTProprietary output_prop = TestProprietary("canonical-output");
        PartiallySignedTransaction a = with_canonical_maps();
        PartiallySignedTransaction b = with_canonical_maps();
        a.inputs[0].unknown[{0xa0}] = {0x01};
        b.inputs[0].unknown[{0xa0}] = {0x01};
        b.inputs[0].m_proprietary.insert(input_prop);
        b.outputs[0].m_proprietary.insert(output_prop);

        BOOST_REQUIRE(a.Merge(b));
        BOOST_CHECK(a.inputs[0].unknown[{0xa0}] == std::vector<unsigned char>{0x01});
        BOOST_CHECK_EQUAL(a.inputs[0].m_proprietary.count(input_prop), 1U);
        BOOST_CHECK_EQUAL(a.outputs[0].m_proprietary.count(output_prop), 1U);
    }

    // Non-MWEB PSBTs keep upstream's permissive semantics: conflicting
    // unknowns merge and the destination's value wins.
    {
        PartiallySignedTransaction a = CanonicalPSBT();
        PartiallySignedTransaction b = CanonicalPSBT();
        a.unknown[{0xa0}] = {0x01};
        b.unknown[{0xa0}] = {0x02};
        BOOST_REQUIRE(a.Merge(b));
        BOOST_CHECK(a.unknown[{0xa0}] == std::vector<unsigned char>{0x01});
    }
}

BOOST_AUTO_TEST_CASE(merge_tx_modifiable)
{
    using Flags = std::optional<std::bitset<8>>;

    // Non-MWEB: upstream BIP-370 merging (AND, except the SIGHASH_SINGLE bit
    // which is OR'd; an absent field counts as no flags).
    {
        PartiallySignedTransaction a = CanonicalPSBT();
        PartiallySignedTransaction b = CanonicalPSBT();
        a.m_tx_modifiable = std::bitset<8>{0x03};
        b.m_tx_modifiable = std::bitset<8>{0x06};
        BOOST_REQUIRE(a.Merge(b));
        BOOST_CHECK(a.m_tx_modifiable == Flags{std::bitset<8>{0x06}});

        PartiallySignedTransaction c = CanonicalPSBT();
        b.m_tx_modifiable = std::bitset<8>{0x03};
        BOOST_REQUIRE(c.Merge(b));
        BOOST_CHECK(c.m_tx_modifiable == Flags{std::bitset<8>{0x00}});
    }

    // MWEB without signatures or proofs: OR, and an absent field carries no information.
    {
        PartiallySignedTransaction a = KernelOnlyPSBT(FeeKernel());
        PartiallySignedTransaction b = KernelOnlyPSBT(FeeKernel());
        a.m_tx_modifiable = std::bitset<8>{0x01};
        b.m_tx_modifiable = std::bitset<8>{0x02};
        PartiallySignedTransaction merged = a;
        BOOST_REQUIRE(merged.Merge(b));
        BOOST_CHECK(merged.m_tx_modifiable == Flags{std::bitset<8>{0x03}});

        PartiallySignedTransaction absent = KernelOnlyPSBT(FeeKernel());
        merged = absent;
        BOOST_REQUIRE(merged.Merge(b));
        BOOST_CHECK(merged.m_tx_modifiable == Flags{std::bitset<8>{0x02}});
        merged = b;
        BOOST_REQUIRE(merged.Merge(absent));
        BOOST_CHECK(merged.m_tx_modifiable == Flags{std::bitset<8>{0x02}});
        merged = absent;
        BOOST_REQUIRE(merged.Merge(absent));
        BOOST_CHECK(!merged.m_tx_modifiable.has_value());
    }

    // MWEB: the presence of any signature or proof after the merge zeroes the
    // modifiable flags. Each of the four trigger locations:
    const auto check_cleared = [](PartiallySignedTransaction psbt) {
        psbt.m_tx_modifiable = std::bitset<8>{0x03};
        PartiallySignedTransaction other = psbt;
        BOOST_REQUIRE(psbt.Merge(other));
        BOOST_REQUIRE(psbt.m_tx_modifiable.has_value());
        BOOST_CHECK(psbt.m_tx_modifiable->none());
    };

    // (a) input signature
    {
        PartiallySignedTransaction psbt = EmptyPSBT();
        PSBTInput input = MWEBInput(TestHash(1));
        input.mweb_sig = TestSignature('1');
        psbt.inputs.push_back(input);
        check_cleared(psbt);
    }
    // (b) output rangeproof, (c) output signature
    {
        PartiallySignedTransaction psbt = EmptyPSBT();
        PSBTOutput output = MWEBOutput();
        output.mweb_commit = TestCommitment(1);
        output.mweb_rangeproof = TestRangeProof(1);
        psbt.outputs.push_back(output);
        check_cleared(psbt);

        psbt.outputs[0].mweb_rangeproof.reset();
        psbt.outputs[0].mweb_sig = TestSignature('2');
        check_cleared(psbt);
    }
    // (d) kernel signature
    {
        PSBTKernel kernel;
        kernel.sig = TestSignature('3');
        check_cleared(KernelOnlyPSBT(kernel));
    }
    // A signature from only one side is enough.
    {
        PartiallySignedTransaction unsigned_psbt = EmptyPSBT();
        unsigned_psbt.inputs.push_back(MWEBInput(TestHash(1)));
        unsigned_psbt.m_tx_modifiable = std::bitset<8>{0x03};
        PartiallySignedTransaction signed_psbt = unsigned_psbt;
        signed_psbt.inputs[0].mweb_sig = TestSignature('1');
        signed_psbt.m_tx_modifiable.reset();
        BOOST_REQUIRE(unsigned_psbt.Merge(signed_psbt));
        BOOST_CHECK(unsigned_psbt.m_tx_modifiable == Flags{std::bitset<8>{0x00}});
    }

    // An MWEB PSBT with no signatures or proofs keeps its flags.
    {
        PartiallySignedTransaction psbt = KernelOnlyPSBT(FeeKernel());
        psbt.m_tx_modifiable = std::bitset<8>{0x03};
        PartiallySignedTransaction other = psbt;
        BOOST_REQUIRE(psbt.Merge(other));
        BOOST_CHECK(psbt.m_tx_modifiable == Flags{std::bitset<8>{0x03}});
    }
}

BOOST_AUTO_TEST_CASE(merge_pegin_scripts)
{
    const PartiallySignedTransaction final_psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);
    PartiallySignedTransaction placeholder = final_psbt;
    placeholder.outputs[0].script = GetScriptForPegin(mw::Hash{});

    // Placeholder adopts the final script.
    {
        PartiallySignedTransaction merged = placeholder;
        BOOST_REQUIRE(merged.Merge(final_psbt));
        BOOST_CHECK(merged.outputs[0].script == final_psbt.outputs[0].script);
    }
    // Final keeps the final script when merged with a placeholder.
    {
        PartiallySignedTransaction merged = final_psbt;
        BOOST_REQUIRE(merged.Merge(placeholder));
        BOOST_CHECK(merged.outputs[0].script == final_psbt.outputs[0].script);
    }

    // Canonical base signatures lock the scripts in: a signer that committed
    // to the placeholder script cannot adopt (or hand off) a rewrite.
    {
        const auto with_canonical_input = [](const PartiallySignedTransaction& base, bool with_sigs) {
            PartiallySignedTransaction psbt = base;
            PSBTInput input = CanonicalInput();
            if (with_sigs) {
                input.partial_sigs.emplace(CKeyID(), DummySigPair());
            }
            psbt.inputs.insert(psbt.inputs.begin(), input);
            return psbt;
        };

        CheckMergeFailsUntouched(with_canonical_input(placeholder, /*with_sigs=*/true),
                                 with_canonical_input(final_psbt, /*with_sigs=*/false));
        CheckMergeFailsUntouched(with_canonical_input(final_psbt, /*with_sigs=*/false),
                                 with_canonical_input(placeholder, /*with_sigs=*/true));
    }

    // Two different final peg-in scripts conflict.
    {
        PartiallySignedTransaction other_final = final_psbt;
        other_final.outputs[0].script = GetScriptForPegin(TestHash(5));
        CheckMergeFailsUntouched(final_psbt, other_final);
    }

    // Even two otherwise identical partial packets cannot be combined when
    // the peg-in output amount disagrees with its associated kernel.
    {
        PartiallySignedTransaction bad_amount = placeholder;
        bad_amount.outputs[0].amount = *bad_amount.kernels[0].pegin_amount + 1;
        CheckMergeFailsUntouched(bad_amount, bad_amount);
    }

    // Arbitrary differing non-peg-in scripts conflict (MWEB context).
    {
        const auto with_script = [](const CScript& script) {
            PartiallySignedTransaction psbt = KernelOnlyPSBT(FeeKernel());
            psbt.outputs.push_back(CanonicalOutput(1'000, script));
            return psbt;
        };
        CheckMergeFailsUntouched(with_script(CScript() << OP_TRUE), with_script(CScript() << OP_2));
    }
}

BOOST_AUTO_TEST_CASE(verify_pegin_outputs_direct)
{
    // No peg-in scripts at all: trivially consistent.
    BOOST_CHECK(VerifyPeginOutputs(CanonicalPSBT(), /*require_final=*/false));
    BOOST_CHECK(VerifyPeginOutputs(CanonicalPSBT(), /*require_final=*/true));

    const PartiallySignedTransaction final_psbt = DecodeHexPSBT(PSBT_PEGIN_SIGNED);

    // The signed vector's script commits to its kernel.
    BOOST_CHECK(VerifyPeginOutputs(final_psbt, /*require_final=*/false));
    BOOST_CHECK(VerifyPeginOutputs(final_psbt, /*require_final=*/true));

    // Placeholder-only scripts are valid while constructing, but not final.
    {
        PartiallySignedTransaction placeholder = final_psbt;
        placeholder.outputs[0].script = GetScriptForPegin(mw::Hash{});
        BOOST_CHECK(VerifyPeginOutputs(placeholder, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(placeholder, /*require_final=*/true));
    }

    // Final peg-in script count must match the peg-in kernel count.
    {
        PartiallySignedTransaction extra_kernel = final_psbt;
        extra_kernel.kernels.push_back(final_psbt.kernels[0]);
        BOOST_CHECK(!VerifyPeginOutputs(extra_kernel, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(extra_kernel, /*require_final=*/true));
    }

    // Unequal placeholder/kernel counts are allowed during construction only.
    {
        PartiallySignedTransaction extra_kernel = final_psbt;
        extra_kernel.outputs[0].script = GetScriptForPegin(mw::Hash{});
        extra_kernel.kernels.push_back(final_psbt.kernels[0]);
        BOOST_CHECK(VerifyPeginOutputs(extra_kernel, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(extra_kernel, /*require_final=*/true));

        extra_kernel.outputs[0].amount = *extra_kernel.kernels[0].pegin_amount + 1;
        BOOST_CHECK(!VerifyPeginOutputs(extra_kernel, /*require_final=*/false));
    }

    // A final script committing to the wrong kernel ID fails.
    {
        PartiallySignedTransaction wrong_id = final_psbt;
        wrong_id.outputs[0].script = GetScriptForPegin(TestHash(5));
        BOOST_CHECK(!VerifyPeginOutputs(wrong_id, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(wrong_id, /*require_final=*/true));
    }

    // A final script whose kernel is missing its signature (no kernel ID yet) fails.
    {
        PartiallySignedTransaction incomplete_kernel = final_psbt;
        incomplete_kernel.kernels[0].sig.reset();
        BOOST_CHECK(!VerifyPeginOutputs(incomplete_kernel, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(incomplete_kernel, /*require_final=*/true));
    }

    // Amount equality is enforced as soon as both sides of the association
    // exist, even when the script still contains a placeholder ID.
    {
        PartiallySignedTransaction wrong_amount = final_psbt;
        wrong_amount.outputs[0].script = GetScriptForPegin(mw::Hash{});
        wrong_amount.outputs[0].amount = *wrong_amount.kernels[0].pegin_amount + 1;
        BOOST_CHECK(!VerifyPeginOutputs(wrong_amount, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(wrong_amount, /*require_final=*/true));
    }

    // Mixed placeholder + final positions are valid only while constructing.
    {
        PartiallySignedTransaction mixed = final_psbt;
        mixed.kernels.push_back(final_psbt.kernels[0]); // 2 pegin kernels

        const PSBTOutput placeholder_out = CanonicalOutput(*final_psbt.kernels[0].pegin_amount, GetScriptForPegin(mw::Hash{}));
        mixed.outputs.insert(mixed.outputs.begin() + 1, placeholder_out); // [final, placeholder]
        BOOST_CHECK(VerifyPeginOutputs(mixed, /*require_final=*/false));
        BOOST_CHECK(!VerifyPeginOutputs(mixed, /*require_final=*/true));
    }
}

BOOST_AUTO_TEST_CASE(combine_psbts)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    PartiallySignedTransaction a = full;
    a.inputs[0].mweb_sig.reset();

    PartiallySignedTransaction b = full;
    b.kernels[0].sig.reset();
    b.mweb_tx_offset.reset();
    b.mweb_stealth_offset.reset();

    // A three-way combine of complementary partials reassembles the original.
    {
        const std::optional<PartiallySignedTransaction> out = CombinePSBTs({a, b, full});
        BOOST_REQUIRE(out);
        BOOST_CHECK_EQUAL(SerHex(*out), PSBT_MWEB_SIGNED);
    }

    // An incompatible member aborts the combine.
    BOOST_CHECK(!CombinePSBTs({full, DecodeHexPSBT(PSBT_MWEB_SIGNED_ALT)}));

    // A single element is copied through.
    {
        const std::optional<PartiallySignedTransaction> out = CombinePSBTs({a});
        BOOST_REQUIRE(out);
        BOOST_CHECK_EQUAL(SerHex(*out), SerHex(a));
    }
}

BOOST_AUTO_TEST_CASE(merge_globals_misc)
{
    // xpubs: copied when new; same keypath unions the xpub sets.
    {
        CExtKey master1;
        CExtKey master2;
        const std::vector<std::byte> seed1(32, std::byte{1});
        const std::vector<std::byte> seed2(32, std::byte{2});
        master1.SetSeed(seed1);
        master2.SetSeed(seed2);

        KeyOriginInfo origin{};
        origin.path = {0x80000000};

        for (const bool mweb : {false, true}) {
            PartiallySignedTransaction a = CanonicalPSBT();
            PartiallySignedTransaction b = CanonicalPSBT();
            if (mweb) {
                a.kernels.push_back(FeeKernel());
                b.kernels.push_back(FeeKernel());
            }
            a.m_xpubs[origin] = {master1.Neuter()};
            b.m_xpubs[origin] = {master2.Neuter()};
            PartiallySignedTransaction c = a;
            c.m_xpubs.clear();
            BOOST_REQUIRE(a.Merge(b));
            BOOST_CHECK_EQUAL(a.m_xpubs[origin].size(), 2U);

            BOOST_REQUIRE(c.Merge(b));
            BOOST_CHECK_EQUAL(c.m_xpubs.count(origin), 1U);
        }
    }

    // fallback_locktime: copied if absent -- reachable only when the
    // effective locktime is unchanged (here pinned by an input height lock,
    // so the unique IDs still match).
    {
        PartiallySignedTransaction a = CanonicalPSBT();
        PartiallySignedTransaction b = CanonicalPSBT();
        a.inputs[0].height_locktime = 100;
        a.fallback_locktime.reset();
        b.inputs[0].height_locktime = 100;
        b.fallback_locktime = 5;
        BOOST_REQUIRE(a.Merge(b));
        BOOST_CHECK(a.fallback_locktime == std::optional<uint32_t>{5});
    }

    // Conflicting global offsets fail.
    {
        const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        PartiallySignedTransaction other = full;
        other.mweb_tx_offset = BlindingFactor{TestSecret('9')};
        CheckMergeFailsUntouched(full, other);

        other = full;
        other.mweb_stealth_offset = BlindingFactor{TestSecret('9')};
        CheckMergeFailsUntouched(full, other);
    }
}

BOOST_AUTO_TEST_SUITE_END()
