// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <addresstype.h>
#include <key.h>
#include <mw/crypto/key_derivation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/data/rpc_psbt.json.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

using namespace psbt_test;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_format_tests, BasicTestingSetup)

namespace {

//! One raw key/value map entry. The key includes the type byte; the value is
//! the payload without its compact-size length prefix (added on write).
using RawEntry = std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;
using RawMap = std::vector<RawEntry>;

RawEntry Entry(uint8_t type, std::vector<unsigned char> value, std::vector<unsigned char> key_extra = {})
{
    std::vector<unsigned char> key{type};
    key.insert(key.end(), key_extra.begin(), key_extra.end());
    return {std::move(key), std::move(value)};
}

std::vector<unsigned char> ToBytes(const DataStream& s)
{
    const auto bytes = MakeUCharSpan(s);
    return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

//! Serialize the arguments into a payload suitable for RawEntry's value.
template <typename... Args>
std::vector<unsigned char> Payload(const Args&... args)
{
    DataStream s{};
    (s << ... << args);
    return ToBytes(s);
}

//! Assemble raw PSBT bytes: magic, then each map's entries followed by a separator.
std::vector<unsigned char> BuildRawPSBT(const std::vector<RawMap>& maps)
{
    DataStream s{};
    s << PSBT_MAGIC_BYTES;
    for (const RawMap& map : maps) {
        for (const RawEntry& entry : map) {
            s << entry.first;
            s << entry.second;
        }
        s << PSBT_SEPARATOR;
    }
    return ToBytes(s);
}

util::Result<PartiallySignedTransaction> DecodeRaw(const std::vector<unsigned char>& raw)
{
    return DecodeRawPSBT(std::as_bytes(std::span{raw}));
}

void CheckDecodeFails(const std::vector<unsigned char>& raw, const std::string& expected_error)
{
    const util::Result<PartiallySignedTransaction> psbt = DecodeRaw(raw);
    BOOST_CHECK(!psbt);
    const std::string error = psbt ? "" : util::ErrorString(psbt).original;
    BOOST_CHECK_MESSAGE(error.find(expected_error) != std::string::npos,
                        "error was \"" + error + "\", expected \"" + expected_error + "\"");
}

PartiallySignedTransaction CheckDecodeSucceeds(const std::vector<unsigned char>& raw)
{
    return Deser(raw);
}

CMutableTransaction MinimalTx()
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
    return mtx;
}

//! Global map of a PSBTv0 carrying a minimal 1-in/1-out unsigned transaction.
RawMap V0GlobalMap()
{
    DataStream tx_stream{};
    tx_stream << TX_NO_WITNESS_NO_MWEB(MinimalTx());
    return {Entry(PSBT_GLOBAL_UNSIGNED_TX, ToBytes(tx_stream))};
}

//! Global map of a PSBTv2 with the required tx version and counts.
RawMap V2GlobalMap(uint64_t num_inputs, uint64_t num_outputs, std::optional<uint64_t> num_kernels = std::nullopt)
{
    RawMap global;
    global.push_back(Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})));
    global.push_back(Entry(PSBT_GLOBAL_INPUT_COUNT, Payload(CompactSizeWriter(num_inputs))));
    global.push_back(Entry(PSBT_GLOBAL_OUTPUT_COUNT, Payload(CompactSizeWriter(num_outputs))));
    if (num_kernels.has_value()) {
        global.push_back(Entry(PSBT_GLOBAL_MWEB_KERNEL_COUNT, Payload(CompactSizeWriter(*num_kernels))));
    }
    global.push_back(Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{2})));
    return global;
}

RawMap V2CanonicalInputMap()
{
    RawMap map;
    map.push_back(Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE)));
    map.push_back(Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{0})));
    return map;
}

RawMap V2MWEBInputMap()
{
    return {Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(9)))};
}

RawMap V2CanonicalOutputMap()
{
    const CScript script = CScript() << OP_TRUE;
    RawMap map;
    map.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000})));
    map.push_back(Entry(PSBT_OUT_SCRIPT, std::vector<unsigned char>(script.begin(), script.end())));
    return map;
}

RawMap V2MWEBOutputMap()
{
    RawMap map;
    map.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000})));
    map.push_back(Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2'))));
    return map;
}

//! A PSBT whose MWEB components are all present (IsComplete only checks
//! presence, not cryptographic validity): one canonical input with a final
//! witness, one all-fields MWEB input/output, one all-fields kernel, and
//! both global offsets.
PartiallySignedTransaction PresenceCompletePSBT()
{
    PartiallySignedTransaction psbt = AllFieldsPSBT();
    psbt.inputs[0].final_script_witness.stack.push_back({0x01});
    BOOST_REQUIRE(psbt.IsComplete());
    return psbt;
}

SigPair DummySigPair()
{
    return SigPair(CPubKey(), std::vector<unsigned char>{0x30});
}

} // namespace

// ---------------------------------------------------------------------------
// Golden-vector serialization
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(allfields_golden_roundtrip)
{
    const PartiallySignedTransaction built = AllFieldsPSBT();

    // The builder is deterministic: its serialization is pinned to freeze the
    // wire format of every MWEB keytype.
    BOOST_CHECK_EQUAL(SerHex(built), PSBT_V2_ALLFIELDS);

    const PartiallySignedTransaction decoded = DecodeHexPSBT(PSBT_V2_ALLFIELDS);
    BOOST_CHECK_EQUAL(SerHex(decoded), PSBT_V2_ALLFIELDS);

    BOOST_REQUIRE_EQUAL(decoded.inputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(decoded.outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(decoded.kernels.size(), 1U);
    BOOST_CHECK(decoded.inputs[1].mweb_output_id == std::optional<mw::Hash>{TestHash(0x11)});
    BOOST_CHECK(decoded.inputs[1].mweb_shared_secret == std::optional<SecretKey>{TestSecret('5')});
    BOOST_CHECK(decoded.inputs[1].mweb_address_descriptor == std::optional<std::string>{"mweb(test)"});
    BOOST_CHECK(decoded.outputs[1].mweb_stealth_address == std::optional<StealthAddress>{TestStealthAddress('7', '8')});
    BOOST_REQUIRE(decoded.outputs[1].mweb_rangeproof.has_value());
    BOOST_CHECK(*decoded.outputs[1].mweb_rangeproof == TestRangeProof(3));
    BOOST_REQUIRE_EQUAL(decoded.kernels[0].pegouts.size(), 2U);
    BOOST_CHECK(decoded.kernels[0].pegouts[0].GetAmount() == 600);
    BOOST_CHECK(decoded.kernels[0].pegouts[1].GetAmount() == 700);
    BOOST_CHECK(decoded.mweb_tx_offset == std::optional<BlindingFactor>{TestSecret('1')});
    BOOST_CHECK(decoded.mweb_stealth_offset == std::optional<BlindingFactor>{TestSecret('2')});
    BOOST_CHECK(decoded.unknown.count({0xa0}) == 1);
    BOOST_CHECK(decoded.m_proprietary.count(TestProprietary()) == 1);
    BOOST_CHECK(decoded.ContainsMWEBComponents());
    BOOST_CHECK_EQUAL(SerHex(decoded), SerHex(built));
}

BOOST_AUTO_TEST_CASE(signed_vectors_roundtrip)
{
    for (const std::string* vec : {&PSBT_MWEB_SIGNED, &PSBT_MWEB_SIGNED_ALT, &PSBT_PEGIN_SIGNED, &PSBT_MIXED_SIGNED, &PSBT_PEGOUT_SIGNED}) {
        BOOST_REQUIRE(!vec->empty());
        const PartiallySignedTransaction decoded = DecodeHexPSBT(*vec);
        BOOST_CHECK_EQUAL(SerHex(decoded), *vec);
        BOOST_CHECK(decoded.ContainsMWEBComponents());
        BOOST_CHECK(decoded.IsComplete());
        for (unsigned int i = 0; i < decoded.inputs.size(); ++i) {
            if (decoded.inputs[i].IsMWEB()) {
                BOOST_CHECK(PSBTInputSignedAndVerified(decoded, i, nullptr));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(field_subset_roundtrip)
{
    // Clearing any one optional MWEB field must still round-trip: the absence
    // encoding is as load-bearing as the presence encoding. Fields whose
    // removal makes the PSBT structurally invalid (input output_id, output
    // amount, both output identifiers at once) are intentionally not cleared.
    using Clearer = std::function<void(PartiallySignedTransaction&)>;
    const std::vector<Clearer> clearers{
        [](auto& p) { p.inputs[1].mweb_output_commit.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_input_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_features.reset(); },
        [](auto& p) { p.inputs[1].mweb_sig.reset(); },
        [](auto& p) { p.inputs[1].mweb_amount.reset(); },
        [](auto& p) { p.inputs[1].mweb_shared_secret.reset(); },
        [](auto& p) { p.inputs[1].mweb_key_exchange_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_extra_data.clear(); },
        [](auto& p) { p.inputs[1].mweb_address_descriptor.reset(); },
        [](auto& p) { p.outputs[1].mweb_stealth_address.reset(); }, // mweb_commit still marks it MWEB
        [](auto& p) { p.outputs[1].mweb_commit.reset(); },          // stealth address still marks it MWEB
        [](auto& p) { p.outputs[1].mweb_features.reset(); },
        [](auto& p) { p.outputs[1].mweb_sender_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_extra_data.clear(); },
        [](auto& p) { p.outputs[1].mweb_standard_fields.reset(); },
        [](auto& p) { p.outputs[1].mweb_rangeproof.reset(); },
        [](auto& p) { p.outputs[1].mweb_sig.reset(); },
        [](auto& p) { p.kernels[0].commit.reset(); },
        [](auto& p) { p.kernels[0].stealth_commit.reset(); },
        [](auto& p) { p.kernels[0].fee.reset(); },
        [](auto& p) { p.kernels[0].pegin_amount.reset(); },
        [](auto& p) { p.kernels[0].pegouts.clear(); },
        [](auto& p) { p.kernels[0].lock_height.reset(); },
        [](auto& p) { p.kernels[0].extra_data.clear(); },
        [](auto& p) { p.kernels[0].sig.reset(); },
        [](auto& p) { p.kernels[0].features.reset(); },
        [](auto& p) { p.kernels.clear(); }, // drops the global kernel count entirely
        [](auto& p) { p.mweb_tx_offset.reset(); },
        [](auto& p) { p.mweb_stealth_offset.reset(); },
        [](auto& p) { p.fallback_locktime.reset(); },
        [](auto& p) { p.m_tx_modifiable.reset(); },
    };

    for (size_t i = 0; i < clearers.size(); ++i) {
        PartiallySignedTransaction psbt = AllFieldsPSBT();
        clearers[i](psbt);
        BOOST_TEST_CONTEXT("clearer #" << i) CheckRoundTrip(psbt);
    }
}

// ---------------------------------------------------------------------------
// PSBTv0/v2 gating and decode errors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v0_rejects_mweb_keytypes)
{
    const std::vector<RawEntry> input_entries{
        Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(1))),
        Entry(PSBT_IN_MWEB_COMMIT, Payload(TestCommitment(1))),
        Entry(PSBT_IN_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('2'))),
        Entry(PSBT_IN_MWEB_INPUT_PUBKEY, Payload(TestPubKey('3'))),
        Entry(PSBT_IN_MWEB_FEATURES, Payload(uint8_t{1})),
        Entry(PSBT_IN_MWEB_INPUT_SIG, Payload(TestSignature('4'))),
        Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {'m', 'w', 'e', 'b', '(', 't', ')'}),
        Entry(PSBT_IN_MWEB_AMOUNT, Payload(CAmount{1})),
        Entry(PSBT_IN_MWEB_SHARED_SECRET, Payload(TestSecret('5'))),
        Entry(PSBT_IN_MWEB_KEY_EXCHANGE_PK, Payload(TestPubKey('6'))),
        Entry(PSBT_IN_MWEB_EXTRA_DATA, {0x01}),
    };
    for (const RawEntry& entry : input_entries) {
        BOOST_TEST_CONTEXT("input keytype 0x" << HexStr(entry.first))
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {entry}, {}}), "not allowed in PSBTv0");
    }

    const std::vector<RawEntry> output_entries{
        Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2'))),
        Entry(PSBT_OUT_MWEB_COMMIT, Payload(TestCommitment(2))),
        Entry(PSBT_OUT_MWEB_FEATURES, Payload(uint8_t{1})),
        Entry(PSBT_OUT_MWEB_SENDER_PUBKEY, Payload(TestPubKey('7'))),
        Entry(PSBT_OUT_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('8'))),
        Entry(PSBT_OUT_MWEB_STANDARD_FIELDS, Payload(OutputStandardFields(TestPubKey('9'), 1, 2, BigInt<16>::ValueOf(3)))),
        Entry(PSBT_OUT_MWEB_RANGEPROOF, Payload(TestRangeProof(1))),
        Entry(PSBT_OUT_MWEB_SIG, Payload(TestSignature('a'))),
        Entry(PSBT_OUT_MWEB_EXTRA_DATA, {0x01}),
    };
    for (const RawEntry& entry : output_entries) {
        BOOST_TEST_CONTEXT("output keytype 0x" << HexStr(entry.first))
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {}, {entry}}), "not allowed in PSBTv0");
    }

    RawMap global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('1'))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_TX_OFFSET is not allowed in PSBTv0");

    global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET, Payload(TestSecret('2'))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET is not allowed in PSBTv0");

    global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_KERNEL_COUNT, Payload(CompactSizeWriter(1))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_KERNEL_COUNT is not allowed in PSBTv0");
}

BOOST_AUTO_TEST_CASE(v0_serialize_with_mweb_throws)
{
    PartiallySignedTransaction psbt(MinimalTx(), /*version=*/0);
    psbt.outputs[0].mweb_commit = TestCommitment(1);

    DataStream ss{};
    BOOST_CHECK_EXCEPTION(ss << psbt, std::ios_base::failure, [](const std::ios_base::failure& e) {
        return std::string(e.what()).find("MWEB fields are not allowed in PSBTv0") != std::string::npos;
    });

    // A v0 PSBT built from a transaction with an MWEB payload carries no MWEB components.
    CMutableTransaction mtx = MinimalTx();
    mtx.mweb_tx.kernels.emplace_back();
    mtx.mweb_tx.kernels.back().fee = 1;
    const PartiallySignedTransaction from_mweb_tx(mtx, /*version=*/0);
    BOOST_CHECK(!from_mweb_tx.ContainsMWEBComponents());
}

BOOST_AUTO_TEST_CASE(duplicate_keys_rejected)
{
    // Global map: canonical and MWEB keytypes, unknown, and proprietary.
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('1'))));
        global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('2'))));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(0xa0, {0x01}));
        global.push_back(Entry(0xa0, {0x02}));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key");
    }

    // Input map
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(9))));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key");
    }
    {
        RawMap input = V2CanonicalInputMap();
        input.push_back(Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE)));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key");
    }
    {
        const PSBTProprietary prop = TestProprietary();
        RawMap input = V2CanonicalInputMap();
        input.emplace_back(prop.key, prop.value);
        input.emplace_back(prop.key, prop.value);
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key");
    }

    // Output map
    {
        RawMap output = V2MWEBOutputMap();
        output.push_back(Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('3', '4'))));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), output}), "Duplicate Key");
    }
    {
        RawMap output = V2CanonicalOutputMap();
        output.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{2'000})));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), output}), "Duplicate Key");
    }

    // Kernel map
    {
        RawMap kernel{Entry(PSBT_KERN_FEE, Payload(CAmount{1})), Entry(PSBT_KERN_FEE, Payload(CAmount{2}))};
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), kernel}), "Duplicate Key");
    }
}

BOOST_AUTO_TEST_CASE(unknown_and_proprietary_preserved)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.unknown[{0xa0}] = {0x01};
    psbt.m_proprietary.insert(TestProprietary("global"));

    PSBTInput input = CanonicalInput();
    input.unknown[{0xa1, 0x02}] = {0x02, 0x03};
    input.m_proprietary.insert(TestProprietary("input"));
    psbt.inputs.push_back(input);

    PSBTOutput output = CanonicalOutput();
    output.unknown[{0xa2}] = {0x04};
    output.m_proprietary.insert(TestProprietary("output"));
    psbt.outputs.push_back(output);

    PSBTKernel kernel;
    kernel.fee = 5;
    kernel.unknown[{0xa3}] = {0x05};
    psbt.kernels.push_back(kernel);

    const std::vector<unsigned char> bytes = Ser(psbt);
    const PartiallySignedTransaction decoded = Deser(bytes);
    BOOST_CHECK_EQUAL(HexStr(bytes), HexStr(Ser(decoded)));
    BOOST_CHECK(decoded.unknown == psbt.unknown);
    BOOST_CHECK(decoded.m_proprietary == psbt.m_proprietary);
    BOOST_CHECK(decoded.inputs[0].unknown == input.unknown);
    BOOST_CHECK(decoded.inputs[0].m_proprietary == input.m_proprietary);
    BOOST_CHECK(decoded.outputs[0].unknown == output.unknown);
    BOOST_CHECK(decoded.outputs[0].m_proprietary == output.m_proprietary);
    BOOST_CHECK(decoded.kernels[0].unknown == kernel.unknown);
}

BOOST_AUTO_TEST_CASE(v2_required_fields)
{
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin()); // drop tx version
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_TX_VERSION is required in PSBTv2");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin() + 1); // drop input count
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin() + 2); // drop output count
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2");
    }

    // Canonical v2 inputs require the previous outpoint.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), {Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{0}))}}),
                     "Previous TXID is required in PSBTv2");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), {Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE))}}),
                     "Previous output's index is required in PSBTv2");

    // MWEB inputs are exempt from the previous-outpoint requirement.
    const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(1, 1), V2MWEBInputMap(), V2MWEBOutputMap()}));
    BOOST_CHECK(psbt.inputs[0].IsMWEB());
    BOOST_CHECK(!psbt.inputs[0].prev_out.has_value());

    // v2 outputs require an amount, and a script unless MWEB.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), {Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2')))}}),
                     "Output amount is required in PSBTv2");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), {Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000}))}}),
                     "Output script is required in PSBTv2");
}

BOOST_AUTO_TEST_CASE(version_gating)
{
    for (const auto& [entry, error] : std::vector<std::pair<RawEntry, std::string>>{
             {Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})), "PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_FALLBACK_LOCKTIME, Payload(uint32_t{100})), "PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_INPUT_COUNT, Payload(CompactSizeWriter(1))), "PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_OUTPUT_COUNT, Payload(CompactSizeWriter(1))), "PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_TX_MODIFIABLE, Payload(uint8_t{1})), "PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0"},
         }) {
        RawMap global = V0GlobalMap();
        global.push_back(entry);
        BOOST_TEST_CONTEXT(error) CheckDecodeFails(BuildRawPSBT({global, {}, {}}), error);
    }

    {
        RawMap global = V2GlobalMap(0, 0);
        global.insert(global.begin(), V0GlobalMap()[0]);
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2");
    }

    CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE))}, {}}),
                     "Previous txid is not allowed in PSBTv0");
    CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {}, {Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1}))}}),
                     "Output amount is not allowed in PSBTv0");

    CheckDecodeFails(BuildRawPSBT({{Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{1}))}}), "There is no PSBT version 1");
    CheckDecodeFails(BuildRawPSBT({{Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{3}))}}), "Unsupported version number");
}

BOOST_AUTO_TEST_CASE(mweb_ordering_enforced)
{
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(2, 0), V2MWEBInputMap(), V2CanonicalInputMap()}),
                     "MWEB inputs must be last");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 2), V2MWEBOutputMap(), V2CanonicalOutputMap()}),
                     "MWEB outputs must be last");
    CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(2, 2), V2CanonicalInputMap(), V2MWEBInputMap(), V2CanonicalOutputMap(), V2MWEBOutputMap()}));

    // Declared counts must match the maps present.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(2, 0), V2CanonicalInputMap()}),
                     "Inputs provided does not match the number of inputs in transaction");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 2), V2CanonicalInputMap(), V2CanonicalOutputMap()}),
                     "Outputs provided does not match the number of outputs in transaction");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 1, 2), V2CanonicalInputMap(), V2CanonicalOutputMap(), {Entry(PSBT_KERN_FEE, Payload(CAmount{1}))}}),
                     "Kernels provided does not match the number of kernels in transaction");
}

BOOST_AUTO_TEST_CASE(kernel_pegout_encoding)
{
    const CScript script = CScript() << OP_TRUE;
    const auto pegout_entry = [&](uint64_t index, CAmount amount) {
        return Entry(PSBT_KERN_PEGOUT, Payload(amount, script), Payload(CompactSizeWriter(index)));
    };

    // Two pegouts round-trip in index order even when serialized out of order.
    {
        const RawMap kernel{pegout_entry(1, 700), pegout_entry(0, 600)};
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(0, 0, 1), kernel}));
        BOOST_REQUIRE_EQUAL(psbt.kernels[0].pegouts.size(), 2U);
        BOOST_CHECK_EQUAL(psbt.kernels[0].pegouts[0].GetAmount(), 600);
        BOOST_CHECK_EQUAL(psbt.kernels[0].pegouts[1].GetAmount(), 700);
        CheckRoundTrip(psbt);
    }

    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {pegout_entry(0, 600), pegout_entry(2, 700)}}),
                     "Kernel pegout indexes must be contiguous");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {pegout_entry(0, 600), pegout_entry(0, 600)}}),
                     "Duplicate Key");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, script))}}),
                     "Kernel pegout key is missing index");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, script), {0x00, 0xff})}}),
                     "Kernel pegout key has unexpected data after index");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, CScript()), Payload(CompactSizeWriter(0)))}}),
                     "Pegout scriptPubKey must not be empty");
}

BOOST_AUTO_TEST_CASE(decode_api_errors)
{
    {
        const util::Result<PartiallySignedTransaction> psbt = DecodeBase64PSBT("this is not base64!!!");
        BOOST_REQUIRE(!psbt);
        BOOST_CHECK_EQUAL(util::ErrorString(psbt).original, "invalid base64");
    }

    CheckDecodeFails({'p', 's', 'b', 't', 0x00}, "Invalid PSBT magic bytes");

    std::vector<unsigned char> with_trailing = BuildRawPSBT({V2GlobalMap(0, 0)});
    with_trailing.push_back(0x00);
    CheckDecodeFails(with_trailing, "extra data after PSBT");

    std::vector<unsigned char> truncated = BuildRawPSBT({V2GlobalMap(0, 0)});
    truncated.resize(truncated.size() / 2);
    {
        const util::Result<PartiallySignedTransaction> psbt = DecodeRaw(truncated);
        BOOST_REQUIRE(!psbt);
        BOOST_CHECK(!util::ErrorString(psbt).original.empty());
    }

    {
        DataStream s{};
        s << PSBT_MAGIC_BYTES;
        const RawEntry entry = Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{2}));
        s << entry.first << entry.second;
        CheckDecodeFails(ToBytes(s), "Separator is missing at the end of the global map");
    }
    {
        std::vector<unsigned char> bytes = BuildRawPSBT({V2GlobalMap(1, 0), V2CanonicalInputMap()});
        bytes.pop_back(); // strip the input map's separator
        CheckDecodeFails(bytes, "Separator is missing at the end of an input map");
    }
}

BOOST_AUTO_TEST_CASE(mweb_addr_descriptor_validation)
{
    // A 4-byte value (the legacy MWEB address index encoding) is silently ignored.
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {0x01, 0x00, 0x00, 0x00}));
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(1, 0), input}));
        BOOST_CHECK(!psbt.inputs[0].mweb_address_descriptor.has_value());
        // ...and never written back.
        BOOST_CHECK_EQUAL(SerHex(psbt), HexStr(BuildRawPSBT({V2GlobalMap(1, 0), V2MWEBInputMap()})));
    }
    // Anything else must be an ASCII mweb() descriptor.
    for (const std::vector<unsigned char>& value : std::vector<std::vector<unsigned char>>{
             {'w', 'p', 'k', 'h', '(', 'x', ')'},
             {'m', 'w', 'e', 'b', '(', 0xff, ')'},
             {'m', 'w', 'e', 'b', 'x'},
             {},
             {'m', 'w', 'e', 'b', '(', '\n', ')'},
         }) {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, value));
        BOOST_TEST_CONTEXT("value " << HexStr(value))
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "MWEB address descriptor must be an ASCII mweb() descriptor");
    }
    // A full single-address descriptor with key origins round-trips verbatim.
    {
        const std::string desc{"mweb([deadbeef/1000h/2h/0h]cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA,[deadbeef/1000h/2h/0h]03aaaa,7)#abcdefgh"};
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, std::vector<unsigned char>(desc.begin(), desc.end())));
        const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(1, 0), input});
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(raw);
        BOOST_CHECK(psbt.inputs[0].mweb_address_descriptor == std::optional<std::string>{desc});
        BOOST_CHECK_EQUAL(SerHex(psbt), HexStr(raw));
    }
}

BOOST_AUTO_TEST_CASE(mweb_input_triplet_without_output_id)
{
    // PSBT_IN_MWEB_OUTPUT_ID is what marks an input map as MWEB. An input
    // carrying only the commitment/pubkey fields is treated as a canonical
    // input and rejected by the PSBTv2 previous-outpoint requirement.
    const RawMap input{
        Entry(PSBT_IN_MWEB_COMMIT, Payload(TestCommitment(1))),
        Entry(PSBT_IN_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('2'))),
        Entry(PSBT_IN_MWEB_INPUT_PUBKEY, Payload(TestPubKey('3'))),
    };
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Previous TXID is required in PSBTv2");
}

// ---------------------------------------------------------------------------
// Wire edge cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(mweb_input_stray_prev_fields_preserved)
{
    // Both stray outpoint fields
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE)));
        input.push_back(Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{3})));
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(1, 0), input}));
        BOOST_CHECK(psbt.inputs[0].IsMWEB());
        BOOST_CHECK(psbt.inputs[0].prev_txid == Txid::FromUint256(uint256::ONE));
        BOOST_CHECK(psbt.inputs[0].prev_out == std::optional<uint32_t>{3});
        CheckRoundTrip(psbt);
    }
    // A stray output index of 0 without a txid is kept as present.
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{0})));
        const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(1, 0), input});
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(raw);
        BOOST_CHECK(psbt.inputs[0].prev_txid.IsNull());
        BOOST_CHECK(psbt.inputs[0].prev_out == std::optional<uint32_t>{0});
        const PartiallySignedTransaction redecoded = Deser(Ser(psbt));
        BOOST_CHECK(redecoded.inputs[0].prev_out == std::optional<uint32_t>{0});
    }
    // Without stray fields nothing is emitted.
    {
        const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(1, 0), V2MWEBInputMap()});
        BOOST_CHECK_EQUAL(SerHex(CheckDecodeSucceeds(raw)), HexStr(raw));
    }
    // Stray fields are strictly merged.
    {
        PartiallySignedTransaction a = EmptyPSBT();
        a.inputs.push_back(MWEBInput(TestHash(1)));
        PartiallySignedTransaction b = a;
        b.inputs[0].prev_out = 3;
        PartiallySignedTransaction merged = a;
        BOOST_REQUIRE(merged.Merge(b));
        BOOST_CHECK(merged.inputs[0].prev_out == std::optional<uint32_t>{3});

        PartiallySignedTransaction c = a;
        c.inputs[0].prev_out = 4;
        merged = b;
        BOOST_CHECK(!merged.Merge(c));
        BOOST_CHECK_EQUAL(SerHex(merged), SerHex(b));
    }
}

BOOST_AUTO_TEST_CASE(mweb_output_explicit_empty_script)
{
    RawMap output = V2MWEBOutputMap();
    output.push_back(Entry(PSBT_OUT_SCRIPT, {}));
    const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(0, 1), output});
    const PartiallySignedTransaction with_empty = CheckDecodeSucceeds(raw);
    BOOST_CHECK(with_empty.outputs[0].IsMWEB());
    BOOST_CHECK(with_empty.outputs[0].m_has_script);
    BOOST_CHECK(with_empty.outputs[0].script.empty());

    // The explicit empty script survives re-serialization (and is distinct from an absent one).
    const std::vector<unsigned char> ser = Ser(with_empty);
    BOOST_CHECK(Deser(ser).outputs[0].m_has_script);
    const PartiallySignedTransaction without = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(0, 1), V2MWEBOutputMap()}));
    BOOST_CHECK(!without.outputs[0].m_has_script);
    BOOST_CHECK(SerHex(without) != HexStr(ser));

    // Absent + explicit empty merges to explicit empty.
    {
        PartiallySignedTransaction merged = without;
        BOOST_REQUIRE(merged.Merge(with_empty));
        BOOST_CHECK(merged.outputs[0].m_has_script);
        BOOST_CHECK_EQUAL(SerHex(merged), HexStr(ser));
    }

    // Explicit empty vs non-empty conflicts, in either direction.
    PartiallySignedTransaction non_empty = with_empty;
    non_empty.outputs[0].script = CScript() << OP_TRUE;
    {
        PartiallySignedTransaction merged = with_empty;
        BOOST_CHECK(!merged.Merge(non_empty));
        BOOST_CHECK_EQUAL(SerHex(merged), SerHex(with_empty));
    }
    {
        PartiallySignedTransaction merged = non_empty;
        BOOST_CHECK(!merged.Merge(with_empty));
        BOOST_CHECK_EQUAL(SerHex(merged), SerHex(non_empty));
    }
}

BOOST_AUTO_TEST_CASE(kernel_count_zero_omitted)
{
    const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(1, 1, 0), V2CanonicalInputMap(), V2CanonicalOutputMap()});
    const PartiallySignedTransaction psbt = CheckDecodeSucceeds(raw);
    BOOST_CHECK(psbt.kernels.empty());
    BOOST_CHECK(!psbt.ContainsMWEBComponents());
    BOOST_CHECK_EQUAL(SerHex(psbt), HexStr(BuildRawPSBT({V2GlobalMap(1, 1), V2CanonicalInputMap(), V2CanonicalOutputMap()})));
}

BOOST_AUTO_TEST_CASE(kernel_negative_lock_height_rejected)
{
    const auto kernel_with_lock_height = [](int32_t lock_height) {
        return BuildRawPSBT({V2GlobalMap(0, 0, 1), RawMap{
            Entry(PSBT_KERN_FEE, Payload(CAmount{1})),
            Entry(PSBT_KERN_LOCK_HEIGHT, Payload(lock_height)),
        }});
    };
    CheckDecodeFails(kernel_with_lock_height(-1), "Kernel lock height must not be negative");
    const PartiallySignedTransaction psbt = CheckDecodeSucceeds(kernel_with_lock_height(0));
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK_EQUAL(psbt.kernels[0].lock_height.value(), 0);
}

BOOST_AUTO_TEST_CASE(kernel_high_keytypes_are_unknown)
{
    // The kernel key type is a single byte: keys starting 0xfd..0xff are not
    // compact-size prefixes, just unknown keys to preserve.
    const RawMap kernel{
        Entry(PSBT_KERN_FEE, Payload(CAmount{1})),
        Entry(0xfd, {0x01}, {0x00, 0x00}),
        Entry(0xfe, {0x02}, {0x01}),
        Entry(0xff, {0x03}),
        Entry(PSBT_KERN_PROPRIETARY, {0x04}, {0x01, 'x', 0x00}),
    };
    const std::vector<unsigned char> raw = BuildRawPSBT({V2GlobalMap(0, 0, 1), kernel});
    const PartiallySignedTransaction psbt = CheckDecodeSucceeds(raw);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK_EQUAL(psbt.kernels[0].unknown.size(), 4U);
    BOOST_CHECK(psbt.kernels[0].unknown.count({0xfd, 0x00, 0x00}) == 1);
    BOOST_CHECK(psbt.kernels[0].unknown.count({0xfe, 0x01}) == 1);
    BOOST_CHECK(psbt.kernels[0].unknown.count({0xff}) == 1);
    CheckRoundTrip(psbt);
}

// ---------------------------------------------------------------------------
// BIP-174/BIP-370 vectors
// ---------------------------------------------------------------------------
// The decoder must keep accepting and rejecting the upstream vectors, and
// re-serialization must be stable (idempotent after one normalization pass).

namespace {
UniValue ReadPSBTJson()
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(json_tests::rpc_psbt));
    BOOST_REQUIRE(doc.isObject());
    return doc;
}
} // namespace

BOOST_AUTO_TEST_CASE(bip174_invalid_vectors)
{
    const UniValue doc = ReadPSBTJson();
    const UniValue& invalid = doc["invalid"];
    BOOST_REQUIRE(invalid.isArray());
    BOOST_REQUIRE(invalid.size() > 0);
    for (size_t i = 0; i < invalid.size(); ++i) {
        BOOST_TEST_CONTEXT("invalid[" << i << "]")
        BOOST_CHECK(!DecodeBase64PSBT(invalid[i].get_str()));
    }

    const UniValue& invalid_with_msg = doc["invalid_with_msg"];
    BOOST_REQUIRE(invalid_with_msg.isArray());
    for (size_t i = 0; i < invalid_with_msg.size(); ++i) {
        BOOST_TEST_CONTEXT("invalid_with_msg[" << i << "]")
        {
            const util::Result<PartiallySignedTransaction> psbt = DecodeBase64PSBT(invalid_with_msg[i][0].get_str());
            BOOST_REQUIRE(!psbt);
            const std::string error = util::ErrorString(psbt).original;
            BOOST_CHECK_MESSAGE(error.find(invalid_with_msg[i][1].get_str()) != std::string::npos,
                                "error was \"" + error + "\", expected \"" + invalid_with_msg[i][1].get_str() + "\"");
        }
    }
}

BOOST_AUTO_TEST_CASE(bip174_valid_vectors)
{
    const UniValue doc = ReadPSBTJson();
    const UniValue& valid = doc["valid"];
    BOOST_REQUIRE(valid.isArray());
    BOOST_REQUIRE(valid.size() > 0);
    for (size_t i = 0; i < valid.size(); ++i) {
        BOOST_TEST_CONTEXT("valid[" << i << "]")
        {
            const util::Result<PartiallySignedTransaction> psbt = DecodeBase64PSBT(valid[i].get_str());
            BOOST_REQUIRE_MESSAGE(psbt, util::ErrorString(psbt).original);
            BOOST_CHECK(!psbt->ContainsMWEBComponents());
            const std::vector<unsigned char> normalized = Ser(*psbt);
            const PartiallySignedTransaction redecoded = Deser(normalized);
            BOOST_CHECK_EQUAL(HexStr(Ser(redecoded)), HexStr(normalized));
        }
    }
}

// ---------------------------------------------------------------------------
// Structure and utility functions
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(get_unsigned_tx_mapping)
{
    const PartiallySignedTransaction psbt = AllFieldsPSBT();
    const std::optional<CMutableTransaction> mtx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(mtx);

    BOOST_REQUIRE_EQUAL(mtx->vin.size(), 1U);
    BOOST_CHECK(mtx->vin[0].prevout == COutPoint(Txid::FromUint256(uint256::ONE), 0));
    BOOST_CHECK_EQUAL(mtx->vin[0].nSequence, 0xfffffffe);
    BOOST_REQUIRE_EQUAL(mtx->vout.size(), 1U);
    BOOST_CHECK_EQUAL(mtx->vout[0].nValue, 50'000);

    BOOST_REQUIRE_EQUAL(mtx->mweb_tx.inputs.size(), 1U);
    const mw::MutableInput& mweb_in = mtx->mweb_tx.inputs[0];
    BOOST_CHECK(mweb_in.output_id == TestHash(0x11));
    BOOST_CHECK(mweb_in.commitment == std::optional<Commitment>{TestCommitment(1)});
    BOOST_CHECK(mweb_in.output_pubkey == std::optional<PublicKey>{TestPubKey('2')});
    BOOST_CHECK(mweb_in.input_pubkey == std::optional<PublicKey>{TestPubKey('3')});
    BOOST_CHECK(mweb_in.amount == std::optional<CAmount>{12345});
    BOOST_CHECK(mweb_in.features == std::optional<uint8_t>{0x03});
    BOOST_CHECK(mweb_in.signature == std::optional<Signature>{TestSignature('4')});
    BOOST_CHECK(mweb_in.key_exchange_pubkey == std::optional<PublicKey>{TestPubKey('6')});
    BOOST_CHECK(mweb_in.shared_secret == std::optional<SecretKey>{TestSecret('5')});
    BOOST_CHECK(mweb_in.extradata == (std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    // The shared secret also implies the pre-switch blinding factor.
    BOOST_CHECK(mweb_in.raw_blind == std::optional<BlindingFactor>{mw::DeriveOutputRawBlind(TestSecret('5'))});

    BOOST_REQUIRE_EQUAL(mtx->mweb_tx.outputs.size(), 1U);
    const mw::MutableOutput& mweb_out = mtx->mweb_tx.outputs[0];
    BOOST_CHECK(mweb_out.commitment == std::optional<Commitment>{TestCommitment(2)});
    BOOST_CHECK(mweb_out.sender_pubkey == std::optional<PublicKey>{TestPubKey('9')});
    BOOST_CHECK(mweb_out.receiver_pubkey == std::optional<PublicKey>{TestPubKey('a')});
    BOOST_CHECK(mweb_out.amount == std::optional<CAmount>{90'000});
    BOOST_CHECK(mweb_out.address == std::optional<StealthAddress>{TestStealthAddress('7', '8')});
    BOOST_REQUIRE(mweb_out.message.has_value());
    BOOST_CHECK_EQUAL(mweb_out.message->features, 0x03);
    BOOST_CHECK(mweb_out.message->GetStandardFields().has_value());
    BOOST_REQUIRE(mweb_out.proof.has_value());
    BOOST_CHECK(**mweb_out.proof == TestRangeProof(3));
    BOOST_CHECK(mweb_out.signature == std::optional<Signature>{TestSignature('d')});

    BOOST_REQUIRE_EQUAL(mtx->mweb_tx.kernels.size(), 1U);
    const mw::MutableKernel& kernel = mtx->mweb_tx.kernels[0];
    BOOST_CHECK(kernel.fee == std::optional<CAmount>{1'000});
    BOOST_CHECK(kernel.pegin == std::optional<CAmount>{5'000});
    BOOST_REQUIRE_EQUAL(kernel.GetPegOuts().size(), 2U);
    BOOST_CHECK(kernel.GetPegOuts()[0].GetAmount() == 600);
    BOOST_CHECK(kernel.lock_height == std::optional<int32_t>{123});
    BOOST_CHECK(kernel.excess == std::optional<Commitment>{TestCommitment(4)});
    BOOST_CHECK(kernel.stealth_excess == std::optional<PublicKey>{TestPubKey('e')});
    BOOST_CHECK(kernel.signature == std::optional<Signature>{TestSignature('f')});
    BOOST_CHECK(kernel.CalcFeatureByte() == *psbt.kernels[0].features);

    BOOST_CHECK(mtx->mweb_tx.kernel_offset == BlindingFactor{TestSecret('1')});
    BOOST_CHECK(mtx->mweb_tx.stealth_offset == BlindingFactor{TestSecret('2')});

    // A missing sequence defaults to SEQUENCE_FINAL.
    {
        PartiallySignedTransaction seq_psbt = EmptyPSBT();
        seq_psbt.inputs.push_back(CanonicalInput());
        BOOST_CHECK_EQUAL(seq_psbt.GetUnsignedTx()->vin[0].nSequence, uint32_t{CTxIn::SEQUENCE_FINAL});
    }

    // The v0 path reproduces the transaction it was built from.
    {
        const CMutableTransaction v0_mtx = MinimalTx();
        const PartiallySignedTransaction v0_psbt(v0_mtx, 0);
        BOOST_CHECK(v0_psbt.GetUnsignedTx()->GetHash() == v0_mtx.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(get_unique_id_semantics)
{
    // v2: the unique ID is invariant under sequence changes.
    {
        PartiallySignedTransaction psbt = AllFieldsPSBT();
        const std::optional<Txid> id = psbt.GetUniqueID();
        BOOST_REQUIRE(id);
        psbt.inputs[0].sequence = 1;
        BOOST_CHECK(psbt.GetUniqueID() == id);
    }

    // Two MWEB PSBTs differing only in MWEB payload share a unique ID: the
    // canonical txid does not commit to MWEB data. This is why Merge
    // compares MWEB PSBTs structurally instead of by unique ID.
    {
        PartiallySignedTransaction a = AllFieldsPSBT();
        PartiallySignedTransaction b = AllFieldsPSBT();
        b.kernels[0].sig = TestSignature('0');
        b.outputs[1].mweb_commit = TestCommitment(99);
        BOOST_CHECK(a.GetUniqueID() == b.GetUniqueID());

        PartiallySignedTransaction c = AllFieldsPSBT();
        c.outputs[0].amount = 60'000;
        BOOST_CHECK(a.GetUniqueID() != c.GetUniqueID());
    }

    // v0: the unique ID is the unsigned transaction's hash.
    {
        const CMutableTransaction mtx = MinimalTx();
        const PartiallySignedTransaction psbt(mtx, 0);
        BOOST_CHECK(psbt.GetUniqueID() == mtx.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(setup_from_tx_mapping)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 555;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 3));
    mtx.vin[0].nSequence = 0xfffffffd;
    mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);

    mw::MutableInput mweb_in(TestHash(0x21));
    mweb_in.commitment = TestCommitment(1);
    mweb_in.output_pubkey = TestPubKey('2');
    mweb_in.input_pubkey = TestPubKey('3');
    mweb_in.features = 1;
    mweb_in.signature = TestSignature('4');
    mweb_in.amount = 777;
    mweb_in.extradata = {0x01};
    mtx.mweb_tx.inputs.push_back(mweb_in);

    mw::MutableOutput mweb_out;
    mweb_out.amount = 888;
    mweb_out.address = TestStealthAddress('5', '6');
    mweb_out.commitment = TestCommitment(2);
    mweb_out.sender_pubkey = TestPubKey('7');
    mweb_out.receiver_pubkey = TestPubKey('8');
    mweb_out.message = OutputMessage(OutputMessage::EXTRA_DATA_FEATURE_BIT, std::nullopt, {0x02});
    mweb_out.proof = std::make_shared<const RangeProof>(TestRangeProof(9));
    mweb_out.signature = TestSignature('a');
    mtx.mweb_tx.outputs.push_back(mweb_out);

    mw::MutableKernel kernel;
    kernel.fee = 10;
    kernel.pegin = 20;
    kernel.SetPegOuts({PegOutCoin(30, CScript() << OP_TRUE)});
    kernel.lock_height = 40;
    kernel.stealth_excess = TestPubKey('b');
    kernel.extradata = {0x03};
    kernel.excess = TestCommitment(3);
    kernel.signature = TestSignature('c');
    mtx.mweb_tx.kernels.push_back(kernel);

    mtx.mweb_tx.kernel_offset = BlindingFactor{TestSecret('d')};
    mtx.mweb_tx.stealth_offset = BlindingFactor{TestSecret('e')};

    const PartiallySignedTransaction psbt(mtx, 2);

    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(psbt.outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.fallback_locktime == std::optional<uint32_t>{555});

    BOOST_CHECK(psbt.inputs[0].prev_txid == Txid::FromUint256(uint256::ONE));
    BOOST_CHECK(psbt.inputs[0].prev_out == std::optional<uint32_t>{3});
    BOOST_CHECK(psbt.inputs[0].sequence == std::optional<uint32_t>{0xfffffffd});

    BOOST_CHECK(psbt.inputs[1].mweb_output_id == std::optional<mw::Hash>{TestHash(0x21)});
    BOOST_CHECK(psbt.inputs[1].mweb_output_commit == mweb_in.commitment);
    BOOST_CHECK(psbt.inputs[1].mweb_output_pubkey == mweb_in.output_pubkey);
    BOOST_CHECK(psbt.inputs[1].mweb_input_pubkey == mweb_in.input_pubkey);
    BOOST_CHECK(psbt.inputs[1].mweb_features == mweb_in.features);
    BOOST_CHECK(psbt.inputs[1].mweb_sig == mweb_in.signature);
    BOOST_CHECK(psbt.inputs[1].mweb_amount == mweb_in.amount);
    BOOST_CHECK(psbt.inputs[1].mweb_extra_data == mweb_in.extradata);
    BOOST_CHECK(!psbt.inputs[1].prev_out.has_value());

    BOOST_CHECK(psbt.outputs[0].amount == 1'000);
    BOOST_CHECK(psbt.outputs[1].amount == 888);
    BOOST_CHECK(!psbt.outputs[1].m_has_script);
    BOOST_CHECK(psbt.outputs[1].mweb_stealth_address == mweb_out.address);
    BOOST_CHECK(psbt.outputs[1].mweb_commit == mweb_out.commitment);
    BOOST_CHECK(psbt.outputs[1].mweb_features == std::optional<uint8_t>{OutputMessage::EXTRA_DATA_FEATURE_BIT});
    BOOST_CHECK(psbt.outputs[1].mweb_sender_pubkey == mweb_out.sender_pubkey);
    BOOST_CHECK(psbt.outputs[1].mweb_output_pubkey == mweb_out.receiver_pubkey);
    BOOST_CHECK(psbt.outputs[1].mweb_extra_data == std::vector<uint8_t>{0x02});
    BOOST_CHECK(!psbt.outputs[1].mweb_standard_fields.has_value());
    BOOST_CHECK(psbt.outputs[1].mweb_rangeproof == std::optional<RangeProof>{TestRangeProof(9)});
    BOOST_CHECK(psbt.outputs[1].mweb_sig == mweb_out.signature);

    BOOST_CHECK(psbt.kernels[0].features == std::optional<uint8_t>{kernel.CalcFeatureByte()});
    BOOST_CHECK(psbt.kernels[0].commit == kernel.excess);
    BOOST_CHECK(psbt.kernels[0].stealth_commit == kernel.stealth_excess);
    BOOST_CHECK(psbt.kernels[0].fee == kernel.fee);
    BOOST_CHECK(psbt.kernels[0].pegin_amount == kernel.pegin);
    BOOST_CHECK(psbt.kernels[0].pegouts == kernel.GetPegOuts());
    BOOST_CHECK(psbt.kernels[0].lock_height == kernel.lock_height);
    BOOST_CHECK(psbt.kernels[0].extra_data == kernel.extradata);
    BOOST_CHECK(psbt.kernels[0].sig == kernel.signature);

    BOOST_CHECK(psbt.mweb_tx_offset == std::optional<BlindingFactor>{TestSecret('d')});
    BOOST_CHECK(psbt.mweb_stealth_offset == std::optional<BlindingFactor>{TestSecret('e')});

    // The PSBT maps back onto the same MWEB transaction.
    const std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_tx);
    BOOST_CHECK(unsigned_tx->GetHash() == mtx.GetHash());
    BOOST_CHECK(unsigned_tx->mweb_tx.kernels[0].GetKernelID() == kernel.GetKernelID());
}

BOOST_AUTO_TEST_CASE(construct_from_tx_keeps_kernel_feature_byte)
{
    // A kernel read from a finalized transaction may carry a bit its fields don't
    // imply. The PSBT shows the signed byte, and IsComplete reports it incomplete.
    CMutableTransaction mtx;
    mw::MutableKernel kernel;
    kernel.features = Kernel::PEGOUT_FEATURE_BIT;
    kernel.excess = TestCommitment(3);
    kernel.signature = TestSignature('c');
    mtx.mweb_tx.kernels.push_back(kernel);

    const PartiallySignedTransaction psbt(mtx, 2);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.kernels[0].features == std::optional<uint8_t>{Kernel::PEGOUT_FEATURE_BIT});
    BOOST_CHECK(psbt.kernels[0].pegouts.empty());
    BOOST_CHECK(!psbt.IsComplete());

    // Signing passes rebuild the transaction from the PSBT; the signed byte survives.
    const std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_tx);
    BOOST_CHECK_EQUAL(unsigned_tx->mweb_tx.kernels[0].GetFeatureByte(), Kernel::PEGOUT_FEATURE_BIT);
    BOOST_CHECK(unsigned_tx->mweb_tx.kernels[0].GetKernelID() == kernel.GetKernelID());

    // A byte without the bit of a field that is present isn't taken from the PSBT.
    PartiallySignedTransaction missing_bit{psbt};
    missing_bit.kernels[0].fee = 10;
    const std::optional<CMutableTransaction> rebuilt = missing_bit.GetUnsignedTx();
    BOOST_REQUIRE(rebuilt);
    BOOST_CHECK_EQUAL(rebuilt->mweb_tx.kernels[0].GetFeatureByte(), Kernel::FEE_FEATURE_BIT);

    // Unassigned bits survive like the peg-out bit; a bit whose field would be read back doesn't.
    for (const uint8_t extra : {uint8_t{0x40}, uint8_t{0x80}}) {
        PartiallySignedTransaction unassigned{psbt};
        *unassigned.kernels[0].features |= extra;
        const std::optional<CMutableTransaction> kept = unassigned.GetUnsignedTx();
        BOOST_REQUIRE(kept);
        BOOST_CHECK_EQUAL(kept->mweb_tx.kernels[0].GetFeatureByte(), Kernel::PEGOUT_FEATURE_BIT | extra);
    }
    for (const uint8_t extra : {uint8_t{Kernel::FEE_FEATURE_BIT}, uint8_t{Kernel::PEGIN_FEATURE_BIT},
                                uint8_t{Kernel::HEIGHT_LOCK_FEATURE_BIT}, uint8_t{Kernel::STEALTH_EXCESS_FEATURE_BIT}}) {
        PartiallySignedTransaction absent_field{psbt};
        *absent_field.kernels[0].features |= extra;
        const std::optional<CMutableTransaction> dropped = absent_field.GetUnsignedTx();
        BOOST_REQUIRE(dropped);
        BOOST_CHECK_EQUAL(dropped->mweb_tx.kernels[0].GetFeatureByte(), 0);
    }
}

BOOST_AUTO_TEST_CASE(compute_timelock)
{
    const auto make_psbt = [](std::optional<uint32_t> fallback = std::nullopt) {
        PartiallySignedTransaction psbt = EmptyPSBT();
        psbt.fallback_locktime = fallback;
        return psbt;
    };
    const auto locked_input = [](uint32_t vout, std::optional<uint32_t> time_lock, std::optional<uint32_t> height_lock) {
        PSBTInput input = CanonicalInput(Txid::FromUint256(uint256::ONE), vout);
        input.time_locktime = time_lock;
        input.height_locktime = height_lock;
        return input;
    };

    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(0, std::nullopt, 100));
        psbt.inputs.push_back(locked_input(1, std::nullopt, 200));
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{200});
    }
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(0, 500'000'100, std::nullopt));
        psbt.inputs.push_back(locked_input(1, 500'000'200, std::nullopt));
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{500'000'200});
    }
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(0, 500'000'100, 100));
        psbt.inputs.push_back(locked_input(1, std::nullopt, 200));
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{200});
    }
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(0, 500'000'100, std::nullopt));
        psbt.inputs.push_back(locked_input(1, std::nullopt, 200));
        BOOST_CHECK(!psbt.ComputeTimeLock());
    }
    {
        PartiallySignedTransaction psbt = make_psbt(777);
        psbt.inputs.push_back(locked_input(0, std::nullopt, std::nullopt));
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{777});
    }
    {
        PartiallySignedTransaction psbt = make_psbt();
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{0});
    }
    // MWEB inputs carry no locktime requirements.
    {
        PartiallySignedTransaction psbt = make_psbt(777);
        psbt.inputs.push_back(MWEBInput(TestHash(1)));
        BOOST_CHECK(psbt.ComputeTimeLock() == std::optional<uint32_t>{777});
    }
}

BOOST_AUTO_TEST_CASE(add_input_rules)
{
    // v0: duplicate outpoints are rejected; existing signatures are cleared on add.
    {
        PartiallySignedTransaction psbt(MinimalTx(), 0);

        BOOST_CHECK(!psbt.AddInput(PSBTInput(0, Txid::FromUint256(uint256::ONE), 0)));

        PSBTInput fresh(0, Txid::FromUint256(uint256::ONE), 1);
        fresh.partial_sigs.emplace(CKeyID(), DummySigPair());
        fresh.final_script_sig = CScript() << OP_TRUE;
        BOOST_CHECK(psbt.AddInput(fresh));
        BOOST_CHECK(psbt.inputs.back().partial_sigs.empty());
        BOOST_CHECK(psbt.inputs.back().final_script_sig.empty());
        BOOST_CHECK_EQUAL(psbt.GetUnsignedTx()->vin.size(), 2U);
    }

    // v2 rules
    {
        PartiallySignedTransaction psbt = EmptyPSBT();

        // Inputs-modifiable flag must be present and set
        const PSBTInput input = CanonicalInput(Txid::FromUint256(uint256::ONE), 0);
        BOOST_CHECK(!psbt.AddInput(input));
        psbt.m_tx_modifiable = std::bitset<8>{0x02};
        BOOST_CHECK(!psbt.AddInput(input));
        psbt.m_tx_modifiable = std::bitset<8>{0x01};
        BOOST_CHECK(psbt.AddInput(input));

        // Duplicates rejected
        BOOST_CHECK(!psbt.AddInput(CanonicalInput(Txid::FromUint256(uint256::ONE), 0)));

        // Adding a locktime-bearing input that changes the effective locktime
        // is rejected once another input carries partial signatures.
        psbt.inputs[0].partial_sigs.emplace(CKeyID(), DummySigPair());
        PSBTInput locked = CanonicalInput(Txid::FromUint256(uint256::ONE), 1);
        locked.height_locktime = 500;
        BOOST_CHECK(!psbt.AddInput(locked));

        psbt.inputs[0].partial_sigs.clear();
        BOOST_CHECK(psbt.AddInput(locked));
    }

    // MWEB inputs stay last: canonical inputs are inserted before the first MWEB input.
    {
        PartiallySignedTransaction psbt = EmptyPSBT();
        psbt.m_tx_modifiable = std::bitset<8>{0x01};
        BOOST_REQUIRE(psbt.AddInput(MWEBInput(TestHash(1))));
        BOOST_REQUIRE(psbt.AddInput(CanonicalInput(TestTxid(1), 0)));
        BOOST_REQUIRE(psbt.AddInput(MWEBInput(TestHash(2))));
        BOOST_REQUIRE(psbt.AddInput(CanonicalInput(TestTxid(2), 0)));
        BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 4U);
        BOOST_CHECK(psbt.inputs[0].prev_txid == TestTxid(1));
        BOOST_CHECK(psbt.inputs[1].prev_txid == TestTxid(2));
        BOOST_CHECK(psbt.inputs[2].mweb_output_id == std::optional<mw::Hash>{TestHash(1)});
        BOOST_CHECK(psbt.inputs[3].mweb_output_id == std::optional<mw::Hash>{TestHash(2)});
        CheckRoundTrip(psbt);

        // Duplicate MWEB output IDs are rejected.
        BOOST_CHECK(!psbt.AddInput(MWEBInput(TestHash(1))));
        BOOST_CHECK_EQUAL(psbt.inputs.size(), 4U);
    }
}

BOOST_AUTO_TEST_CASE(add_output_rules)
{
    const PSBTOutput valid = CanonicalOutput();

    // v0 appends to the transaction.
    {
        PartiallySignedTransaction psbt(MinimalTx(), 0);
        BOOST_CHECK(psbt.AddOutput(PSBTOutput(0, 1'000, CScript() << OP_TRUE)));
        BOOST_CHECK_EQUAL(psbt.GetUnsignedTx()->vout.size(), 2U);
        BOOST_CHECK(!psbt.AddOutput(valid)); // version mismatch
    }

    // v2 requires the outputs-modifiable bit.
    {
        PartiallySignedTransaction psbt = EmptyPSBT();
        BOOST_CHECK(!psbt.AddOutput(valid));
        psbt.m_tx_modifiable = std::bitset<8>{0x01};
        BOOST_CHECK(!psbt.AddOutput(valid));
        psbt.m_tx_modifiable = std::bitset<8>{0x02};
        BOOST_CHECK(psbt.AddOutput(valid));
        BOOST_CHECK_EQUAL(psbt.outputs.size(), 1U);
    }

    // MWEB outputs stay last: canonical outputs are inserted before the first MWEB output.
    {
        PartiallySignedTransaction psbt = EmptyPSBT();
        psbt.m_tx_modifiable = std::bitset<8>{0x02};
        BOOST_REQUIRE(psbt.AddOutput(MWEBOutput(1'000)));
        BOOST_REQUIRE(psbt.AddOutput(CanonicalOutput(2'000)));
        BOOST_REQUIRE(psbt.AddOutput(MWEBOutput(3'000)));
        BOOST_REQUIRE(psbt.AddOutput(CanonicalOutput(4'000)));
        BOOST_REQUIRE_EQUAL(psbt.outputs.size(), 4U);
        BOOST_CHECK_EQUAL(psbt.outputs[0].amount, 2'000);
        BOOST_CHECK_EQUAL(psbt.outputs[1].amount, 4'000);
        BOOST_CHECK(psbt.outputs[2].IsMWEB());
        BOOST_CHECK_EQUAL(psbt.outputs[2].amount, 1'000);
        BOOST_CHECK(psbt.outputs[3].IsMWEB());
        BOOST_CHECK_EQUAL(psbt.outputs[3].amount, 3'000);
        CheckRoundTrip(psbt);
    }
}

BOOST_AUTO_TEST_CASE(is_complete_mweb_requirements)
{
    BOOST_REQUIRE(PresenceCompletePSBT().IsComplete());

    // Each requirement, removed in isolation, must flip IsComplete() to false.
    using Breaker = std::function<void(PartiallySignedTransaction&)>;
    const std::vector<Breaker> breakers{
        [](auto& p) { p.inputs[0].final_script_witness.SetNull(); },
        [](auto& p) { p.inputs[1].mweb_sig.reset(); },
        [](auto& p) { p.inputs[1].mweb_features.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_commit.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_input_pubkey.reset(); }, // stealth-key feature bit set
        [](auto& p) { p.inputs[1].mweb_extra_data.clear(); },   // extra-data feature bit set
        [](auto& p) { p.kernels.clear(); },
        [](auto& p) { p.kernels[0].commit.reset(); },
        [](auto& p) { p.kernels[0].features.reset(); },
        [](auto& p) { p.kernels[0].sig.reset(); },
        [](auto& p) { p.kernels[0].fee.reset(); },
        [](auto& p) { p.kernels[0].pegin_amount.reset(); },
        [](auto& p) { p.kernels[0].pegouts.clear(); },
        [](auto& p) { p.kernels[0].lock_height.reset(); },
        [](auto& p) { p.kernels[0].stealth_commit.reset(); },
        [](auto& p) { p.kernels[0].extra_data.clear(); },
        [](auto& p) { *p.kernels[0].features &= ~Kernel::FEE_FEATURE_BIT; }, // field present without its bit
        [](auto& p) { *p.kernels[0].features &= ~Kernel::PEGIN_FEATURE_BIT; },
        [](auto& p) { *p.kernels[0].features &= ~Kernel::PEGOUT_FEATURE_BIT; },
        [](auto& p) { *p.kernels[0].features &= ~Kernel::HEIGHT_LOCK_FEATURE_BIT; },
        [](auto& p) { *p.kernels[0].features &= ~Kernel::STEALTH_EXCESS_FEATURE_BIT; },
        [](auto& p) { *p.kernels[0].features &= ~Kernel::EXTRA_DATA_FEATURE_BIT; },
        [](auto& p) { p.outputs[1].mweb_commit.reset(); },
        [](auto& p) { p.outputs[1].mweb_features.reset(); },
        [](auto& p) { p.outputs[1].mweb_sender_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_rangeproof.reset(); },
        [](auto& p) { p.outputs[1].mweb_sig.reset(); },
        [](auto& p) { p.outputs[1].mweb_standard_fields.reset(); }, // standard-fields feature bit set
        [](auto& p) { p.outputs[1].mweb_extra_data.clear(); },      // extra-data feature bit set
        [](auto& p) { p.mweb_tx_offset.reset(); },
        [](auto& p) { p.mweb_stealth_offset.reset(); },
    };

    for (size_t i = 0; i < breakers.size(); ++i) {
        PartiallySignedTransaction psbt = PresenceCompletePSBT();
        breakers[i](psbt);
        BOOST_CHECK_MESSAGE(!psbt.IsComplete(), "breaker #" << i << " did not invalidate completeness");
    }

    // The output stealth address is not needed once the commitment is present.
    PartiallySignedTransaction psbt = PresenceCompletePSBT();
    psbt.outputs[1].mweb_stealth_address.reset();
    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(count_unsigned_inputs)
{
    PartiallySignedTransaction psbt = EmptyPSBT();

    PSBTInput script_sig = CanonicalInput(TestTxid(1));
    script_sig.final_script_sig = CScript() << OP_TRUE;
    psbt.inputs.push_back(script_sig);

    PSBTInput witness = CanonicalInput(TestTxid(2));
    witness.final_script_witness.stack.push_back({0x01});
    psbt.inputs.push_back(witness);

    PSBTInput mweb = MWEBInput(TestHash(1));
    mweb.mweb_sig = TestSignature('1');
    psbt.inputs.push_back(mweb);

    psbt.inputs.push_back(CanonicalInput(TestTxid(3))); // unsigned
    psbt.inputs.push_back(MWEBInput(TestHash(2)));     // unsigned

    BOOST_CHECK_EQUAL(CountPSBTUnsignedInputs(psbt), 2U);

    // An MWEB signature on a canonical input does not count as a signature.
    PSBTInput stray = CanonicalInput(TestTxid(4));
    stray.mweb_sig = TestSignature('2');
    BOOST_CHECK(!PSBTInputSigned(stray));
}

BOOST_AUTO_TEST_CASE(remove_unnecessary_transactions)
{
    const CScript taproot_script = CScript() << OP_1 << std::vector<unsigned char>(32, 0x01);
    const CScript segwit_v0_script = CScript() << OP_0 << std::vector<unsigned char>(20, 0x01);

    CMutableTransaction prev;
    prev.vout.emplace_back(1'000, taproot_script);
    const CTransactionRef prev_ref = MakeTransactionRef(prev);

    const auto make_input = [&](const CScript& spk) {
        PSBTInput input = CanonicalInput(prev_ref->GetHash(), 0);
        input.witness_utxo = CTxOut(1'000, spk);
        input.non_witness_utxo = prev_ref;
        return input;
    };
    const auto make_psbt = [&](const CScript& second_spk) {
        PartiallySignedTransaction psbt = EmptyPSBT();
        psbt.inputs.push_back(make_input(taproot_script));
        psbt.inputs.push_back(make_input(second_spk));
        return psbt;
    };

    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        RemoveUnnecessaryTransactions(psbt);
        BOOST_CHECK(!psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(!psbt.inputs[1].non_witness_utxo);
    }
    {
        PartiallySignedTransaction psbt = make_psbt(segwit_v0_script);
        RemoveUnnecessaryTransactions(psbt);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(psbt.inputs[1].non_witness_utxo);
    }
    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        psbt.inputs[1].witness_utxo.SetNull();
        RemoveUnnecessaryTransactions(psbt);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    }
    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        psbt.inputs[1].sighash_type = SIGHASH_ALL | SIGHASH_ANYONECANPAY;
        RemoveUnnecessaryTransactions(psbt);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(psbt.inputs[1].non_witness_utxo);
    }
}

BOOST_AUTO_TEST_CASE(update_psbt_output)
{
    const CKey key = ToCKey(TestSecret('7'));
    const CPubKey pubkey = key.GetPubKey();

    FlatSigningProvider provider;
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);
    KeyOriginInfo origin{};
    origin.path = {0x80000000};
    provider.origins.emplace(pubkey.GetID(), std::make_pair(pubkey, origin));

    const CScript multisig = GetScriptForMultisig(1, {pubkey});
    provider.scripts.emplace(CScriptID(multisig), multisig);

    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.inputs.push_back(CanonicalInput());
    psbt.outputs.push_back(CanonicalOutput(1'000, GetScriptForDestination(WitnessV0KeyHash(pubkey))));
    psbt.outputs.push_back(CanonicalOutput(1'000, GetScriptForDestination(WitnessV0ScriptHash(multisig))));
    psbt.outputs.push_back(MWEBOutput(1'000, TestStealthAddress('1', '2')));

    UpdatePSBTOutput(provider, psbt, 0);
    BOOST_CHECK_EQUAL(psbt.outputs[0].hd_keypaths.count(pubkey), 1U);

    UpdatePSBTOutput(provider, psbt, 1);
    BOOST_CHECK(psbt.outputs[1].witness_script == multisig);
    BOOST_CHECK_EQUAL(psbt.outputs[1].hd_keypaths.count(pubkey), 1U);

    // MWEB outputs are a no-op.
    const PSBTOutput before = psbt.outputs[2];
    UpdatePSBTOutput(provider, psbt, 2);
    BOOST_CHECK(psbt.outputs[2] == before);
}

BOOST_AUTO_TEST_CASE(psbt_input_get_utxo)
{
    CMutableTransaction prev;
    prev.vout.emplace_back(1'234, CScript() << OP_TRUE);
    const CTransactionRef prev_ref = MakeTransactionRef(prev);

    CTxOut utxo;

    // non_witness_utxo: hash and index must match.
    {
        PSBTInput input = CanonicalInput(prev_ref->GetHash(), 0);
        input.non_witness_utxo = prev_ref;
        BOOST_REQUIRE(input.GetUTXO(utxo));
        BOOST_CHECK_EQUAL(utxo.nValue, 1'234);

        input.prev_out = 5;
        BOOST_CHECK(!input.GetUTXO(utxo));

        input.prev_out.reset();
        BOOST_CHECK(!input.GetUTXO(utxo));

        input.prev_out = 0;
        input.prev_txid = Txid::FromUint256(uint256::ONE);
        BOOST_CHECK(!input.GetUTXO(utxo));
    }
    // witness_utxo fallback
    {
        PSBTInput input = CanonicalInput();
        input.witness_utxo = CTxOut(4'321, CScript() << OP_TRUE);
        BOOST_REQUIRE(input.GetUTXO(utxo));
        BOOST_CHECK_EQUAL(utxo.nValue, 4'321);
    }
    // neither
    {
        const PSBTInput input = CanonicalInput();
        BOOST_CHECK(!input.GetUTXO(utxo));
    }
    // MWEB inputs have no canonical UTXO.
    {
        const PSBTInput input = MWEBInput(TestHash(1));
        BOOST_CHECK(!input.GetUTXO(utxo));
    }
}

BOOST_AUTO_TEST_SUITE_END()
