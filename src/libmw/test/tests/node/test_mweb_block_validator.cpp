// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/block_validator.h>
#include <mw/consensus/weight.h>
#include <mw/crypto/schnorr.h>
#include <mw/models/tx/mutable_tx.h>

#include <test_framework/miner.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestMWEBBlockValidator, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InputSorting)
{
    test::Miner miner(GetDataDir());

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(10'000'000)
        .AddOutput(4'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddOutput(6'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddInput(funding_tx.GetOutputs()[1])
        .AddOutput(10'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    // Swap inputs so they're no longer in order
    std::vector<Input> inputs = pBlock->GetInputs();
    Input tmp = inputs[0];
    inputs[0] = inputs[1];
    inputs[1] = tmp;

    BOOST_REQUIRE(inputs[0].GetOutputID() > inputs[1].GetOutputID());
    mw::Block::CPtr pUnsortedBlock = mw::MutBlock(pBlock)
        .SetInputs(std::move(inputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pUnsortedBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_BlockWeight)
{
    test::Miner miner(GetDataDir());

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<Output> outputs = pBlock->GetOutputs();
    const Output& output = outputs.front();
    const size_t current_weight = Weight::Calculate(pBlock->GetTxBody());
    const size_t output_weight = Weight::CalcOutputWeight(output.HasStandardFields(), output.GetExtraData());
    const size_t additional_outputs = ((mw::MAX_BLOCK_WEIGHT - current_weight) / output_weight) + 1;
    outputs.insert(outputs.end(), additional_outputs, output);

    BOOST_REQUIRE(Weight::ExceedsMaximum(TxBody(pBlock->GetInputs(), outputs, pBlock->GetKernels())));

    mw::Block::CPtr pHeavyBlock = mw::MutBlock(pBlock)
        .SetOutputs(std::move(outputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pHeavyBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateSpentIDs)
{
    test::Miner miner(GetDataDir());

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<Input> inputs = pBlock->GetInputs();
    inputs.push_back(inputs.front());

    mw::Block::CPtr pDuplicateBlock = mw::MutBlock(pBlock)
        .SetInputs(std::move(inputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateOutputIDs)
{
    test::Miner miner(GetDataDir());

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<Output> outputs = pBlock->GetOutputs();
    outputs.push_back(outputs.front());

    mw::Block::CPtr pDuplicateBlock = mw::MutBlock(pBlock)
        .SetOutputs(std::move(outputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateKernelIDs)
{
    test::Miner miner(GetDataDir());

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<Kernel> kernels = pBlock->GetKernels();
    kernels.push_back(kernels.front());

    mw::Block::CPtr pDuplicateBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetNumKernels(kernels.size())
            .Build(),
        TxBody(pBlock->GetInputs(), pBlock->GetOutputs(), kernels)
    );

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidInputSignature)
{
    test::Miner miner(GetDataDir());

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.inputs.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidOutputSignature)
{
    test::Miner miner(GetDataDir());

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.outputs.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidKernelSignature)
{
    test::Miner miner(GetDataDir());

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.kernels.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidRangeProof)
{
    test::Miner miner(GetDataDir());

    SecretKey sender_key = SecretKey::Random();
    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, sender_key, StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    std::vector<uint8_t> proof_bytes(RangeProof::SIZE, 0);
    mutable_tx.outputs.front().proof = std::make_shared<RangeProof>(std::move(proof_bytes));

    Output resigned_output(
        *mutable_tx.outputs.front().commitment,
        *mutable_tx.outputs.front().sender_pubkey,
        *mutable_tx.outputs.front().receiver_pubkey,
        *mutable_tx.outputs.front().message,
        *mutable_tx.outputs.front().proof,
        Signature()
    );
    mutable_tx.outputs.front().signature = Schnorr::Sign(sender_key.data(), resigned_output.BuildSignedMsg().GetMsgHash());

    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();
    mw::Block::CPtr pInvalidProofBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidProofBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_SUITE_END()
