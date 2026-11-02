// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <mweb/mweb_mempool_accept.h>
#include <mweb/mweb_node.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/transaction.h>
#include <node/miner.h>
#include <policy/packages.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/util/mining.h>
#include <test/util/mweb_crypto_counters.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test_framework/miner.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <optional>

using namespace MWEB;

namespace {

struct MWEBMempoolOrderSetup : public TestChain100Setup {
    MWEBMempoolOrderSetup()
        : TestChain100Setup(ChainType::REGTEST, {.extra_args = {"-vbparams=mweb:1601450001000:9999999999000"}}) {}
};

constexpr int64_t MWEB_VB_START_TIME = 1601450001LL * 1000;
constexpr int64_t MWEB_VB_START_TIME_SEC = 1601450001;
constexpr int FIRST_MWEB_HEIGHT = 432;

void MineMwebEraBlock(node::NodeContext& node, const CScript& coinbase_script)
{
    std::shared_ptr<CBlock> block = PrepareBlock(node, {.coinbase_output_script = coinbase_script});
    {
        LOCK(::cs_main);
        const int64_t mtp = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast();
        block->nTime = std::max({mtp + 1, MWEB_VB_START_TIME});
    }
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    node::RegenerateCommitments(*block, *Assert(node.chainman));
    while (!CheckProofOfWork(block->GetPoWHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }
    ProcessBlock(node, block);
}

void SubmitPeginToMempool(TestChain100Setup& setup, node::NodeContext& node, CAmount pegin_amount = COIN, size_t coinbase_idx = 0)
{
    test::Tx mweb_pegin = test::Tx::CreatePegIn(pegin_amount);
    const auto pegin_coin = mweb_pegin.GetPegInCoin();
    const CScript pegin_script = GetScriptForPegin(pegin_coin.GetKernelID());

    const CTransactionRef& coinbase = setup.m_coinbase_txns.at(coinbase_idx);
    const CAmount fee{10'000};
    const CAmount change = coinbase->vout[0].nValue - pegin_amount - fee;

    const CScript change_script = CScript() << ToByteVector(setup.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction mtx = setup.CreateValidTransaction(
        {coinbase},
        {COutPoint{coinbase->GetHash(), 0}},
        1,
        {setup.coinbaseKey},
        {CTxOut{pegin_amount, pegin_script}, CTxOut{change, change_script}},
        std::nullopt,
        std::nullopt).first;
    mtx.mweb_tx = mw::MutableTx::From(*mweb_pegin.GetTransaction());

    LOCK2(::cs_main, Assert(node.mempool)->cs);
    const MempoolAcceptResult result = Assert(node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        throw std::runtime_error(strprintf("SubmitPeginToMempool failed: %s", result.m_state.ToString()));
    }
}

void MineToMwebChain(TestChain100Setup& setup, node::NodeContext& node, int post_activation_blocks = 4)
{
    const CScript coinbase_script{CScript() << OP_TRUE};
    SetMockTime(std::chrono::seconds{MWEB_VB_START_TIME_SEC});

    int height{WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight())};
    while (height < FIRST_MWEB_HEIGHT - 1) {
        MineMwebEraBlock(node, coinbase_script);
        height = WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight());
    }

    SubmitPeginToMempool(setup, node);
    for (int i = 0; i < post_activation_blocks; ++i) {
        MineMwebEraBlock(node, coinbase_script);
    }
}

CMutableTransaction MakePeginMtx(TestChain100Setup& setup, const mw::Transaction::CPtr& mweb_tx, size_t coinbase_idx, CAmount pegin_amount = COIN)
{
    const auto pegins = mweb_tx->GetPegIns();
    BOOST_REQUIRE_EQUAL(pegins.size(), 1U);
    const CScript pegin_script = GetScriptForPegin(pegins.front().GetKernelID());

    const CTransactionRef& coinbase = setup.m_coinbase_txns.at(coinbase_idx);
    const CAmount fee{10'000};
    const CAmount change = coinbase->vout[0].nValue - pegin_amount - fee;
    const CScript change_script = CScript() << ToByteVector(setup.coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction mtx = setup.CreateValidTransaction(
        {coinbase},
        {COutPoint{coinbase->GetHash(), 0}},
        1,
        {setup.coinbaseKey},
        {CTxOut{pegin_amount, pegin_script}, CTxOut{change, change_script}},
        std::nullopt,
        std::nullopt).first;
    mtx.mweb_tx = mw::MutableTx::From(*mweb_tx);
    return mtx;
}

mw::Transaction::CPtr WithCorruptedKernelSignature(const mw::Transaction::CPtr& tx)
{
    BOOST_REQUIRE(tx);
    BOOST_REQUIRE(!tx->GetKernels().empty());

    std::vector<Kernel> kernels = tx->GetKernels();
    const Kernel& k = kernels.front();

    Signature bad_sig = k.GetSignature();
    bad_sig.data()[0] ^= 0xff;

    const std::optional<CAmount> fee =
        (k.GetFeatures() & Kernel::FEE_FEATURE_BIT) ? std::optional<CAmount>(k.GetFee()) : std::nullopt;
    const std::optional<CAmount> pegin =
        k.HasPegIn() ? std::optional<CAmount>(k.GetPegIn()) : std::nullopt;
    const std::optional<int32_t> lock_height =
        (k.GetFeatures() & Kernel::HEIGHT_LOCK_FEATURE_BIT) ? std::optional<int32_t>(k.GetLockHeight()) : std::nullopt;
    const std::optional<PublicKey> stealth =
        k.HasStealthExcess() ? std::optional<PublicKey>(k.GetStealthExcess()) : std::nullopt;

    kernels.front() = Kernel(
        k.GetFeatures(),
        fee,
        pegin,
        k.GetPegOuts(),
        lock_height,
        stealth,
        k.GetExtraData(),
        k.GetExcess(),
        std::move(bad_sig));

    return std::make_shared<mw::Transaction>(
        tx->GetKernelOffset(),
        tx->GetStealthOffset(),
        TxBody{tx->GetInputs(), tx->GetOutputs(), std::move(kernels)});
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_mempool_order_tests, MWEBMempoolOrderSetup)

BOOST_AUTO_TEST_CASE(missing_mweb_input_skips_batch_verify)
{
    MineToMwebChain(*this, m_node);

    // Structurally valid MWEB-only tx spending a nonexistent output.
    const auto mweb = test::TxBuilder()
                          .AddInput(COIN)
                          .AddPlainKernel(/*fee=*/1000)
                          .AddOutput(COIN - 1000)
                          .Build()
                          .GetTransaction();

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.mweb_tx = mw::MutableTx::From(*mweb);

    mweb_test::ResetBatchVerifyCounts();
    {
        LOCK2(::cs_main, Assert(m_node.mempool)->cs);
        const MempoolAcceptResult rejected =
            Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_CHECK(rejected.m_result_type != MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "bad-txns-inputs-missingorspent");
    }
    BOOST_CHECK_EQUAL(mweb_test::GetTotalBatchVerifyCount(), 0U);
}

BOOST_AUTO_TEST_CASE(invalid_crypto_after_inputs_runs_batch_verify)
{
    MineToMwebChain(*this, m_node);

    test::Tx mweb_pegin = test::Tx::CreatePegIn(COIN);
    const auto corrupted = WithCorruptedKernelSignature(mweb_pegin.GetTransaction());
    CMutableTransaction mtx = MakePeginMtx(*this, corrupted, /*coinbase_idx=*/1);

    mweb_test::ResetBatchVerifyCounts();
    {
        LOCK2(::cs_main, Assert(m_node.mempool)->cs);
        const MempoolAcceptResult rejected =
            Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_CHECK(rejected.m_result_type != MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "bad-mweb-txn");
    }
    BOOST_CHECK_GT(mweb_test::GetTotalBatchVerifyCount(), 0U);
}

BOOST_AUTO_TEST_CASE(valid_pegin_still_accepted)
{
    MineToMwebChain(*this, m_node);

    test::Tx mweb_pegin = test::Tx::CreatePegIn(COIN);
    CMutableTransaction mtx = MakePeginMtx(*this, mweb_pegin.GetTransaction(), /*coinbase_idx=*/1);

    LOCK2(::cs_main, Assert(m_node.mempool)->cs);
    const MempoolAcceptResult accepted =
        Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
    BOOST_REQUIRE_MESSAGE(accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          accepted.m_state.ToString());
}

BOOST_AUTO_TEST_CASE(package_test_accept_rejects_invalid_mweb_crypto)
{
    MineToMwebChain(*this, m_node);

    test::Tx mweb_pegin = test::Tx::CreatePegIn(COIN);
    const auto corrupted = WithCorruptedKernelSignature(mweb_pegin.GetTransaction());
    CMutableTransaction mtx = MakePeginMtx(*this, corrupted, /*coinbase_idx=*/1);
    const CTransactionRef tx = MakeTransactionRef(mtx);

    Package package{tx};
    LOCK2(::cs_main, Assert(m_node.mempool)->cs);
    const PackageMempoolAcceptResult result = ProcessNewPackage(
        m_node.chainman->ActiveChainstate(),
        *m_node.mempool,
        package,
        /*test_accept=*/true,
        /*client_maxfeerate=*/{});

    BOOST_CHECK(result.m_state.IsInvalid());
    const auto it = result.m_tx_results.find(tx->GetWitnessHash());
    BOOST_REQUIRE(it != result.m_tx_results.end());
    BOOST_CHECK(it->second.m_result_type != MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK_EQUAL(it->second.m_state.GetRejectReason(), "bad-mweb-txn");
}

BOOST_AUTO_TEST_CASE(relay_input_limit_rejects_before_mweb_checks)
{
    MineToMwebChain(*this, m_node);

    // 1,001 MWEB inputs exceed the relay limit. The inputs are placeholders, so a
    // structural check, input lookup or batch verify would reject differently.
    const Input placeholder_input(Input::STEALTH_KEY_FEATURE_BIT, mw::Hash{}, Commitment{}, PublicKey{}, PublicKey{}, {}, Signature{});
    const Kernel kernel(0, std::nullopt, std::nullopt, {}, std::nullopt, std::nullopt, {}, Commitment{}, Signature{});
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(
        {}, {}, std::vector<Input>(1'001, placeholder_input), {}, {kernel}));

    mweb_test::ResetBatchVerifyCounts();
    {
        LOCK2(::cs_main, Assert(m_node.mempool)->cs);
        const MempoolAcceptResult rejected =
            Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_CHECK(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK(rejected.m_state.GetResult() == TxValidationResult::TX_NOT_STANDARD);
        BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "mweb-txn-too-many-inputs");
    }
    BOOST_CHECK_EQUAL(mweb_test::GetTotalBatchVerifyCount(), 0U);
}

BOOST_AUTO_TEST_CASE(check_transaction_structure_only_no_batch_verify)
{
    // Cheap CheckTransaction must not invoke batch cryptography.
    test::Tx mweb_pegin = test::Tx::CreatePegIn(COIN);
    CMutableTransaction mtx;
    mtx.vout.emplace_back(COIN, GetScriptForPegin(mweb_pegin.GetPegInCoin().GetKernelID()));
    mtx.mweb_tx = mw::MutableTx::From(*mweb_pegin.GetTransaction());

    mweb_test::ResetBatchVerifyCounts();
    TxValidationState state;
    BOOST_CHECK(Node::CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(mweb_test::GetTotalBatchVerifyCount(), 0U);

    mweb_test::ResetBatchVerifyCounts();
    BOOST_CHECK(Node::VerifyTransactionCrypto(CTransaction(mtx), state));
    BOOST_CHECK_GT(mweb_test::GetTotalBatchVerifyCount(), 0U);
}

BOOST_AUTO_TEST_CASE(mweb_inputs_after_reorg)
{
    // After a reorg, an MWEB input must be created by a mempool transaction or be
    // unspent in the chain.
    struct ChainView : CoinsViewEmpty {
        std::optional<Output> unspent;
        bool GetMWEBCoin(const mw::Hash& output_id, Output& coin) const override
        {
            if (!unspent || unspent->GetOutputID() != output_id) return false;
            coin = *unspent;
            return true;
        }
    };

    const test::Tx parent = test::TxBuilder().AddInput(COIN).AddPlainKernel(/*fee=*/1000).AddOutput(COIN - 1000).Build();
    const test::TxOutput& parent_output = parent.GetOutputs().front();
    const test::Tx child = test::TxBuilder().AddInput(parent_output).AddPlainKernel(/*fee=*/1000).AddOutput(COIN - 2000).Build();

    CMutableTransaction parent_mtx;
    parent_mtx.version = 2;
    parent_mtx.mweb_tx = mw::MutableTx::From(*parent.GetTransaction());
    CMutableTransaction child_mtx;
    child_mtx.version = 2;
    child_mtx.mweb_tx = mw::MutableTx::From(*child.GetTransaction());
    const CTransaction child_tx{child_mtx};

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    ChainView chain;

    BOOST_CHECK(MempoolAccept::HaveMWEBInputsAfterReorg(CTransaction{CMutableTransaction{}}, pool, chain));
    BOOST_CHECK(!MempoolAccept::HaveMWEBInputsAfterReorg(child_tx, pool, chain));

    chain.unspent = parent_output.GetOutput();
    BOOST_CHECK(MempoolAccept::HaveMWEBInputsAfterReorg(child_tx, pool, chain));

    chain.unspent.reset();
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.FromTx(parent_mtx));
    BOOST_CHECK(MempoolAccept::HaveMWEBInputsAfterReorg(child_tx, pool, chain));
}

BOOST_AUTO_TEST_SUITE_END()
