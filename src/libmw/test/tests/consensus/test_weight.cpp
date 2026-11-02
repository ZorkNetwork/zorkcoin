// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/weight.h>
#include <mweb/mweb_policy.h>
#include <primitives/transaction.h>
#include <random.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestWeight, MWEBTestingSetup)

static std::vector<Output> CreateStandardOutputs(const size_t num_outputs)
{
    std::vector<Output> outputs;
    for (size_t i = 0; i < num_outputs; i++) {
        OutputMessage message;
        message.features = static_cast<uint8_t>(FastRandomContext{}.rand<uint8_t>()) | OutputMessage::STANDARD_FIELDS_FEATURE_BIT;

        Output standard_output(
            Commitment{},
            PublicKey{},
            PublicKey{},
            std::move(message),
            std::make_shared<RangeProof>(),
            Signature{});
        outputs.push_back(std::move(standard_output));
    }

    return outputs;
}

static Kernel CreateKernel(const bool with_stealth, const std::vector<PegOutCoin>& pegouts = {})
{
    return Kernel(
        0,
        std::nullopt,
        std::nullopt,
        pegouts,
        std::nullopt,
        with_stealth ? std::make_optional(PublicKey()) : std::nullopt,
        std::vector<uint8_t>{},
        Commitment(),
        Signature()
    );
}

static std::vector<Kernel> CreateKernels(const size_t plain_kernels, const size_t stealth_kernels)
{
    std::vector<Kernel> kernels;
    kernels.reserve(plain_kernels);
    for (size_t i = 0; i < plain_kernels; i++) {
        kernels.push_back(CreateKernel(false));
    }

    for (size_t i = 0; i < stealth_kernels; i++) {
        kernels.push_back(CreateKernel(true));
    }

    return kernels;
}

BOOST_AUTO_TEST_CASE(ExceedsMaximum)
{
    BOOST_CHECK(mw::MAX_NUM_INPUTS == 50'000);
    BOOST_CHECK(mw::BASE_KERNEL_WEIGHT == 2);
    BOOST_CHECK(mw::KERNEL_WITH_STEALTH_WEIGHT == 3);
    BOOST_CHECK(mw::BASE_OUTPUT_WEIGHT == 17);
    BOOST_CHECK(mw::STANDARD_OUTPUT_WEIGHT == 18);
    BOOST_CHECK(mw::BYTES_PER_WEIGHT == 42);
    BOOST_CHECK(mw::MAX_BLOCK_WEIGHT == 200'000);


    // 10,000 outputs + 10,000 plain kernels = 200,000 Weight
    {
        std::vector<Input> inputs(mw::MAX_NUM_INPUTS);
        std::vector<Output> outputs = CreateStandardOutputs(10'000);
        std::vector<Kernel> kernels = CreateKernels(10'000, 0);

        TxBody tx(inputs, outputs, kernels);

        BOOST_CHECK(Weight::Calculate(tx) == 200'000);
        BOOST_CHECK(!Weight::ExceedsMaximum(tx));
    }

    // 50,000 inputs max, so 50,001 should exceed maximum
    {
        std::vector<Input> inputs(mw::MAX_NUM_INPUTS + 1);
        std::vector<Output> outputs = CreateStandardOutputs(10'000);
        std::vector<Kernel> kernels = CreateKernels(10'000, 0);
        BOOST_CHECK(inputs.size() == 50'001);

        TxBody tx(inputs, outputs, kernels);

        BOOST_CHECK(Weight::Calculate(tx) == 200'000);
        BOOST_CHECK(Weight::ExceedsMaximum(tx));
    }

    // 10,000 outputs + 10,000 plain kernels and 1 stealth kernel = 200,003 Weight
    {
        std::vector<Input> inputs(mw::MAX_NUM_INPUTS);
        std::vector<Output> outputs = CreateStandardOutputs(10'000);
        std::vector<Kernel> kernels = CreateKernels(10'000, 1);
        BOOST_CHECK(inputs.size() == 50'000);

        TxBody tx(inputs, outputs, kernels);

        BOOST_CHECK(Weight::Calculate(tx) == 200'003);
        BOOST_CHECK(Weight::ExceedsMaximum(tx));
    }

}

static Output CreateOutput(const bool standard_fields, std::vector<uint8_t> extra_data)
{
    OutputMessage message;
    message.features = (standard_fields ? OutputMessage::STANDARD_FIELDS_FEATURE_BIT : 0) |
                       (extra_data.empty() ? 0 : OutputMessage::EXTRA_DATA_FEATURE_BIT);
    message.extra_data = std::move(extra_data);
    return Output(Commitment{}, PublicKey{}, PublicKey{}, std::move(message), std::make_shared<RangeProof>(), Signature{});
}

static Kernel CreateKernel(const bool with_stealth, const std::vector<PegOutCoin>& pegouts, std::vector<uint8_t> extra_data)
{
    uint8_t features = pegouts.empty() ? 0 : Kernel::PEGOUT_FEATURE_BIT;
    if (with_stealth) features |= Kernel::STEALTH_EXCESS_FEATURE_BIT;
    if (!extra_data.empty()) features |= Kernel::EXTRA_DATA_FEATURE_BIT;
    return Kernel(
        features,
        std::nullopt,
        std::nullopt,
        pegouts,
        std::nullopt,
        with_stealth ? std::make_optional(PublicKey()) : std::nullopt,
        std::move(extra_data),
        Commitment(),
        Signature()
    );
}

static Input CreateInput(std::vector<uint8_t> extra_data)
{
    const uint8_t features = extra_data.empty() ? 0 : Input::EXTRA_DATA_FEATURE_BIT;
    return Input(features, mw::Hash{}, Commitment{}, PublicKey{}, PublicKey{}, std::move(extra_data), Signature{});
}

static PegOutCoin CreatePegOut(const size_t script_size)
{
    const std::vector<uint8_t> script(script_size, 0x51);
    return PegOutCoin(1'000, CScript(script.begin(), script.end()));
}

BOOST_AUTO_TEST_CASE(ExtraBytesBoundaries)
{
    // Extra bytes cost ceil(n / BYTES_PER_WEIGHT) weight.
    const std::vector<std::pair<size_t, size_t>> cases{{0, 0}, {1, 1}, {41, 1}, {42, 1}, {43, 2}, {84, 2}, {85, 3}};
    for (const auto& [bytes, weight] : cases) {
        BOOST_CHECK_EQUAL(Weight::CalcInputWeight(std::vector<uint8_t>(bytes)), weight);
        BOOST_CHECK_EQUAL(Weight::CalcOutputWeight(true, std::vector<uint8_t>(bytes)), mw::STANDARD_OUTPUT_WEIGHT + weight);
        BOOST_CHECK_EQUAL(Weight::CalcKernelWeight(false, std::vector<PegOutCoin>{}, std::vector<uint8_t>(bytes)), mw::BASE_KERNEL_WEIGHT + weight);
    }
}

BOOST_AUTO_TEST_CASE(OutputExtraData)
{
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {CreateOutput(false, std::vector<uint8_t>(43))}, {})), 17U + 2U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {CreateOutput(true, std::vector<uint8_t>(84))}, {})), 18U + 2U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {CreateOutput(true, {}), CreateOutput(true, std::vector<uint8_t>(1))}, {})), 18U + 18U + 1U);
}

BOOST_AUTO_TEST_CASE(InputExtraData)
{
    // Inputs are weightless apart from their extra data.
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({CreateInput({})}, {}, {})), 0U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({CreateInput(std::vector<uint8_t>(42))}, {}, {})), 1U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({CreateInput(std::vector<uint8_t>(43)), CreateInput(std::vector<uint8_t>(1))}, {}, {})), 3U);
}

BOOST_AUTO_TEST_CASE(KernelExtraDataAndPegouts)
{
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {}, {CreateKernel(false, {}, std::vector<uint8_t>(42))})), 2U + 1U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {}, {CreateKernel(true, {CreatePegOut(25)}, {})})), 3U + 1U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {}, {CreateKernel(false, {CreatePegOut(21), CreatePegOut(21)}, {})})), 2U + 1U + 1U);
    BOOST_CHECK_EQUAL(Weight::Calculate(TxBody({}, {}, {CreateKernel(true, {CreatePegOut(43)}, std::vector<uint8_t>(85))})), 3U + 2U + 3U);
}

BOOST_AUTO_TEST_CASE(ExceedsMaximumWithExtraData)
{
    // 10,000 standard outputs (180,000) + 9,999 plain kernels (19,998) leave 2 weight,
    // filled here by 84 bytes of input or kernel extra data.
    std::vector<Output> outputs = CreateStandardOutputs(10'000);
    std::vector<Kernel> kernels = CreateKernels(9'999, 0);
    {
        TxBody body({CreateInput(std::vector<uint8_t>(84))}, outputs, kernels);
        BOOST_CHECK_EQUAL(Weight::Calculate(body), mw::MAX_BLOCK_WEIGHT);
        BOOST_CHECK(!Weight::ExceedsMaximum(body));
    }
    {
        TxBody body({CreateInput(std::vector<uint8_t>(85))}, outputs, kernels);
        BOOST_CHECK_EQUAL(Weight::Calculate(body), mw::MAX_BLOCK_WEIGHT + 1);
        BOOST_CHECK(Weight::ExceedsMaximum(body));
    }

    std::vector<Kernel> kernels_with_data = CreateKernels(9'998, 0);
    kernels_with_data.push_back(CreateKernel(false, {}, std::vector<uint8_t>(84)));
    {
        TxBody body({}, outputs, kernels_with_data);
        BOOST_CHECK_EQUAL(Weight::Calculate(body), mw::MAX_BLOCK_WEIGHT);
        BOOST_CHECK(!Weight::ExceedsMaximum(body));
    }
    kernels_with_data.back() = CreateKernel(false, {}, std::vector<uint8_t>(85));
    {
        TxBody body({}, outputs, kernels_with_data);
        BOOST_CHECK_EQUAL(Weight::Calculate(body), mw::MAX_BLOCK_WEIGHT + 1);
        BOOST_CHECK(Weight::ExceedsMaximum(body));
    }
}

BOOST_AUTO_TEST_CASE(PegOutScriptsWithinMaxBlockBytes)
{
    // Pegout scripts are charged per BYTES_PER_WEIGHT, so a body at the weight cap made of
    // kernels with 42-byte pegout scripts is the densest kernel encoding. mw::MAX_BLOCK_BYTES
    // still bounds its serialization; the node's serialized block size limit is checked separately.
    const size_t kernel_weight = Weight::CalcKernelWeight(true, std::vector<PegOutCoin>{CreatePegOut(42)}, std::vector<uint8_t>{});
    BOOST_CHECK_EQUAL(kernel_weight, 4U);
    std::vector<Kernel> kernels(mw::MAX_BLOCK_WEIGHT / kernel_weight, CreateKernel(true, {CreatePegOut(42)}, {}));
    TxBody body({}, {}, kernels);
    BOOST_CHECK_EQUAL(Weight::Calculate(body), mw::MAX_BLOCK_WEIGHT);
    BOOST_CHECK(!Weight::ExceedsMaximum(body));
    BOOST_CHECK_LE(body.Serialized().size(), mw::MAX_BLOCK_BYTES);
}

static CTransaction WrapMWEBTransaction(const mw::Transaction::CPtr& mweb_tx)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx);
    return CTransaction{std::move(tx)};
}

BOOST_AUTO_TEST_CASE(NoPerTransactionRelayLimits)
{
    // IsStandardTx applies no input count or weight limit; the relay limits are enforced
    // separately by MWEB::Policy::CheckWeight (see RelayWeightAndInputLimits).
    std::string reason;

    const Input finalized_input(Input::STEALTH_KEY_FEATURE_BIT, mw::Hash{}, Commitment{}, PublicKey{}, PublicKey{}, {}, Signature{});
    const CTransaction many_inputs = WrapMWEBTransaction(mw::Transaction::Create(
        {}, {}, std::vector<Input>(1'001, finalized_input), {}, CreateKernels(1, 0)));
    BOOST_CHECK(MWEB::Policy::IsStandardTx(many_inputs, reason));

    std::vector<Output> outputs;
    for (size_t i = 0; i < 223; i++) {
        OutputMessage message;
        message.features = OutputMessage::STANDARD_FIELDS_FEATURE_BIT;
        message.key_exchange_pubkey = PublicKey::Random();
        outputs.emplace_back(Commitment{}, PublicKey::Random(), PublicKey::Random(), std::move(message), std::make_shared<RangeProof>(), Signature{});
    }
    const CTransaction heavy = WrapMWEBTransaction(mw::Transaction::Create({}, {}, {}, outputs, CreateKernels(1, 0)));
    BOOST_CHECK_GT(Weight::Calculate(heavy.mweb_tx.m_transaction->GetBody()), 4'000U);
    BOOST_CHECK(MWEB::Policy::IsStandardTx(heavy, reason));

    // A zero key-exchange or receiver pubkey is not a valid point and is non-standard.
    outputs.back() = Output(Commitment{}, PublicKey::Random(), PublicKey{}, outputs.back().GetOutputMessage(), std::make_shared<RangeProof>(), Signature{});
    const CTransaction bad_receiver = WrapMWEBTransaction(mw::Transaction::Create({}, {}, {}, outputs, CreateKernels(1, 0)));
    BOOST_CHECK(!MWEB::Policy::IsStandardTx(bad_receiver, reason));
    BOOST_CHECK_EQUAL(reason, "non-standard-mweb-tx");
}

BOOST_AUTO_TEST_CASE(RelayWeightAndInputLimits)
{
    // MWEB::Policy::CheckWeight bounds relayed MWEB transactions to 1/50 of the
    // consensus limits: 1,000 inputs and 4,000 MWEB weight.
    std::string reason;
    BOOST_CHECK(MWEB::Policy::CheckWeight(CTransaction{CMutableTransaction{}}, reason));

    const Input finalized_input(Input::STEALTH_KEY_FEATURE_BIT, mw::Hash{}, Commitment{}, PublicKey{}, PublicKey{}, {}, Signature{});
    const CTransaction max_inputs = WrapMWEBTransaction(mw::Transaction::Create(
        {}, {}, std::vector<Input>(1'000, finalized_input), {}, CreateKernels(1, 0)));
    BOOST_CHECK(MWEB::Policy::CheckWeight(max_inputs, reason));
    const CTransaction many_inputs = WrapMWEBTransaction(mw::Transaction::Create(
        {}, {}, std::vector<Input>(1'001, finalized_input), {}, CreateKernels(1, 0)));
    BOOST_CHECK(!MWEB::Policy::CheckWeight(many_inputs, reason));
    BOOST_CHECK_EQUAL(reason, "mweb-txn-too-many-inputs");

    std::vector<Output> outputs;
    const auto make_tx = [&] { return WrapMWEBTransaction(mw::Transaction::Create({}, {}, {}, outputs, CreateKernels(1, 0))); };
    while (Weight::Calculate(make_tx().mweb_tx.m_transaction->GetBody()) <= 4'000U) {
        OutputMessage message;
        message.features = OutputMessage::STANDARD_FIELDS_FEATURE_BIT;
        message.key_exchange_pubkey = PublicKey::Random();
        outputs.emplace_back(Commitment{}, PublicKey::Random(), PublicKey::Random(), std::move(message), std::make_shared<RangeProof>(), Signature{});
    }
    reason.clear();
    BOOST_CHECK(!MWEB::Policy::CheckWeight(make_tx(), reason));
    BOOST_CHECK_EQUAL(reason, "mweb-txn-oversize");
    outputs.pop_back();
    BOOST_CHECK(MWEB::Policy::CheckWeight(make_tx(), reason));
}

BOOST_AUTO_TEST_SUITE_END()
