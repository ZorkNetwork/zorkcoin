// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <mweb/mweb_mempool_accept.h>
#include <mweb/mweb_miner.h>
#include <mweb/mweb_node.h>
#include <mweb/mweb_policy.h>
#include <mweb/mweb_models.h>
#include <node/mweb_rollback_clone.h>
#include <node/mweb_snapshot.h>
#include <txdb.h>
#include <mw/file/file_path.h>
#include <util/result.h>
#include <util/string.h>
#include <validationinterface.h>

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <mw/consensus/params.h>
#include <mw/crypto/blinds.h>
#include <mw/crypto/schnorr.h>
#include <mw/crypto/secret_keys.h>
#include <mw/mmr/mmr.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/tx_body.h>
#include <mw/node/coins_view.h>
#include <net.h>
#include <node/miner.h>
#include <node/utxo_snapshot.h>
#include <node/transaction.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <mw/models/block/block_undo.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <validation.h>
#include <kernel/disconnected_transactions.h>

#include <test/util/mining.h>
#include <test/util/mweb_setup.h>
#include <test_framework/miner.h>
#include <test_framework/models/tx.h>
#include <test_framework/test_mweb.h>
#include <script/standard.h>
#include <test_framework/tx_builder.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>

using namespace MWEB;

namespace {

//! Simulates a coins view cache whose base has no MWEB layer (no-MWEB-undo trigger).
class NoMWEBViewWrapper : public CCoinsViewBacked
{
public:
    explicit NoMWEBViewWrapper(CCoinsView* in_view) : CCoinsViewBacked(in_view) {}
    mw::ICoinsView::Ptr GetMWEBView() const override { return nullptr; }
};

class MWEBBackedEmptyView : public CCoinsViewBacked
{
    mw::ICoinsView::Ptr m_mweb;
public:
    explicit MWEBBackedEmptyView(mw::ICoinsView::Ptr mweb)
        : CCoinsViewBacked(&CoinsViewEmpty::Get()), m_mweb(std::move(mweb)) {}
    mw::ICoinsView::Ptr GetMWEBView() const override { return m_mweb; }
};

//! Names the protected Chainstate::RollforwardBlock as a member pointer; never instantiated.
struct RollforwardAccess : public Chainstate {
    using Chainstate::RollforwardBlock;
};

//! Regtest MWEB versionbits start time in milliseconds (matches -vbparams).
constexpr int64_t MWEB_VB_START_TIME = 1601450001LL * 1000;
constexpr int64_t MWEB_VB_START_TIME_SEC = 1601450001;
//! First MWEB block height on a clean regtest chain with MWEB_VBPARAMS.
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

CBlockIndex* FindTipWithMwundo(Chainstate& chainstate, CChain& chain)
{
    for (CBlockIndex* pindex = chain.Tip(); pindex; pindex = pindex->pprev) {
        if (pindex->nHeight < FIRST_MWEB_HEIGHT) {
            break;
        }
        CBlockUndo undo;
        if (chainstate.m_blockman.ReadBlockUndo(undo, *pindex) && undo.mwundo != nullptr) {
            return pindex;
        }
    }
    return nullptr;
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

CMutableTransaction MakeLockedPeginMtx(TestChain100Setup& setup, int32_t lock_height, size_t coinbase_idx, CAmount pegin_amount = COIN)
{
    test::Tx mweb_pegin = test::TxBuilder()
        .AddPeginKernel(pegin_amount, /*fee=*/std::nullopt, /*add_stealth_excess=*/false, lock_height)
        .AddOutput(pegin_amount)
        .Build();
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
    return mtx;
}

//! Input with features 0 (no stealth key / input pubkey) via wire decode.
Input MakeFeature0Input()
{
    DataStream ss{};
    const uint8_t features{0};
    const mw::Hash output_id{};
    const Commitment commitment{};
    const PublicKey output_pubkey{};
    const Signature signature{};
    ss << features << output_id << commitment << output_pubkey << signature;
    Input input;
    ss >> input;
    assert(input.GetFeatures() == 0);
    assert(!input.GetInputPubKey().has_value());
    return input;
}

mw::MutableTx MakeNonFinalFeature0MutableTx()
{
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, /*pegin_amount=*/std::nullopt,
        std::vector<PegOutCoin>{}, /*lock_height=*/std::nullopt);
    const auto tx = mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {MakeFeature0Input()}, {}, {kernel});
    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx);
    assert(!mutable_tx.IsNull());
    assert(!mutable_tx.IsFinal());
    return mutable_tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_validation_tests, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(node_check_block_rejects_mweb_in_vtx)
{
    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(1'000'000).GetTransaction());
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(mtx));

    BlockValidationState state;
    BOOST_CHECK(!Node::CheckBlock(block, state));
    BOOST_CHECK(state.GetRejectReason() == "unexpected-mweb-data");
}

BOOST_AUTO_TEST_CASE(node_contextual_check_pre_activation)
{
    CBlock block;
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>());

    BlockValidationState state;
    BOOST_CHECK(!Node::ContextualCheckBlock(block, ::Params().GetConsensus(), nullptr, state, /*mweb_active=*/false, /*mweb_active_at_prev=*/false));
    BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK(state.GetRejectReason() == "unexpected-mweb-data");
}

BOOST_AUTO_TEST_CASE(node_check_transaction_pegin_mismatch)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(1'000'000, CScript() << OP_RETURN);
    auto pegin_tx = test::Tx::CreatePegIn(2'000'000);
    mtx.mweb_tx = mw::MutableTx::From(*pegin_tx.GetTransaction());

    TxValidationState state;
    BOOST_CHECK(!Node::CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.GetResult() == TxValidationResult::TX_WITNESS_MUTATED);
    BOOST_CHECK(state.GetRejectReason() == "pegin-count-mismatch");
}

// Peg-in scriptPubKey with no mweb_tx must be rejected (orphan peg-in / mining liveness).
BOOST_AUTO_TEST_CASE(node_check_transaction_pegin_without_mweb_body)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(1'000'000, GetScriptForPegin(mw::Hash::FromHex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));

    TxValidationState state;
    BOOST_CHECK(!Node::CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "pegin-count-mismatch");
}

BOOST_AUTO_TEST_CASE(policy_rejects_pegin_without_mweb_body)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(1'000'000, GetScriptForPegin(mw::Hash::FromHex(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")));

    std::string reason;
    BOOST_CHECK(!Policy::IsStandardTx(CTransaction(mtx), reason));
    BOOST_CHECK_EQUAL(reason, "kernel-mismatch");
}

BOOST_AUTO_TEST_CASE(policy_rejects_dust_pegout)
{
    const CScript pegout_script{GetScriptForDestination(WitnessV0KeyHash{uint160{}})};
    const CAmount threshold{GetDustThreshold(CTxOut{0, pegout_script}, CFeeRate{DUST_RELAY_TX_FEE})};
    const auto pegout_tx = [&](CAmount amount) {
        const Kernel kernel{Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, std::nullopt,
                                           {PegOutCoin(amount, pegout_script)}, std::nullopt)};
        CMutableTransaction mtx;
        mtx.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {}, {}, {kernel}));
        return CTransaction{mtx};
    };

    std::string reason;
    BOOST_CHECK(!IsStandardTx(pegout_tx(threshold - 1), MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, CFeeRate{DUST_RELAY_TX_FEE}, reason));
    BOOST_CHECK_EQUAL(reason, "dust");

    reason.clear();
    IsStandardTx(pegout_tx(threshold), MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, CFeeRate{DUST_RELAY_TX_FEE}, reason);
    BOOST_CHECK(reason != "dust");
}

// The fee estimator rates MWEB transactions by their L1 fee rate. MWEB-only
// transactions have no L1 vsize and must rate as 0, not divide by zero.
BOOST_AUTO_TEST_CASE(feerate_excludes_mweb_fee_and_handles_empty_size)
{
    BOOST_CHECK_EQUAL(CFeeRate(10'000, /*virtual_bytes=*/0).GetFeePerK(), 0);

    const uint64_t mweb_weight{mw::STANDARD_OUTPUT_WEIGHT};
    const CAmount mweb_fee{CFeeRate::GetMWEBFee(mweb_weight)};
    BOOST_REQUIRE_GT(mweb_fee, 0);

    BOOST_CHECK_EQUAL(CFeeRate(mweb_fee + 5'000, /*virtual_bytes=*/0, mweb_weight).GetFeePerK(), 0);
    BOOST_CHECK_EQUAL(CFeeRate(mweb_fee + 5'000, /*virtual_bytes=*/250, mweb_weight).GetFeePerK(), 20'000);
    BOOST_CHECK_EQUAL(CFeeRate(mweb_fee - 1, /*virtual_bytes=*/250, mweb_weight).GetFeePerK(), 0);
    BOOST_CHECK(CFeeRate(5'000, /*virtual_bytes=*/250, /*mweb_weight=*/0) == CFeeRate(5'000, 250));
}

BOOST_AUTO_TEST_CASE(max_raw_tx_fee_caps_mweb_fee)
{
    const CFeeRate default_rate{node::DEFAULT_MAX_RAW_TX_FEE_RATE};
    const uint64_t weight{39};
    const CAmount allowance{CFeeRate::GetMWEBFee(weight) + CFeeRate::GetMWEBFee(mw::STANDARD_OUTPUT_WEIGHT)};
    BOOST_REQUIRE_EQUAL(allowance, 5'700);

    // A zero rate disables the cap; without MWEB weight the cap is upstream's.
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{0}, default_rate, 200, weight), 0);
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(default_rate, default_rate, 200, 0), default_rate.GetFee(200));

    // MWEB-only: the allowance at or below the default rate, scaled above it.
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(default_rate, default_rate, 0, weight), allowance);
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{default_rate.GetFeePerK() / 10}, default_rate, 0, weight), allowance);
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{default_rate.GetFeePerK() * 2}, default_rate, 0, weight), 2 * allowance);
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{COIN}, default_rate, 0, weight), 10 * allowance);
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{COIN}, CFeeRate{0}, 0, weight), allowance);

    // Mixed: the L1 cap plus the MWEB allowance.
    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(default_rate, default_rate, 200, weight), default_rate.GetFee(200) + allowance);

    BOOST_CHECK_EQUAL(MempoolAccept::MaxRawTxFee(CFeeRate{COIN}, default_rate, std::numeric_limits<int32_t>::max(), std::numeric_limits<uint64_t>::max()),
                      std::numeric_limits<CAmount>::max());
}

BOOST_AUTO_TEST_CASE(client_max_fee_rate_caps_mweb_fee)
{
    const CFeeRate default_rate{node::DEFAULT_MAX_RAW_TX_FEE_RATE};
    const uint64_t weight{39};
    const CAmount allowance{5'700};

    // Without MWEB weight: upstream's fee rate comparison.
    BOOST_CHECK(!MempoolAccept::ExceedsClientMaxFeeRate(default_rate, default_rate, default_rate.GetFee(200), 200, 0));
    BOOST_CHECK(MempoolAccept::ExceedsClientMaxFeeRate(default_rate, default_rate, default_rate.GetFee(200) + 1, 200, 0));

    // MWEB-only has no L1 vsize to rate the fee against; the MWEB allowance caps it.
    BOOST_CHECK(!MempoolAccept::ExceedsClientMaxFeeRate(default_rate, default_rate, allowance, 0, weight));
    BOOST_CHECK(MempoolAccept::ExceedsClientMaxFeeRate(default_rate, default_rate, allowance + 1, 0, weight));
    BOOST_CHECK(MempoolAccept::ExceedsClientMaxFeeRate(default_rate, default_rate, COIN / 2, 0, weight));
    BOOST_CHECK(!MempoolAccept::ExceedsClientMaxFeeRate(CFeeRate{default_rate.GetFeePerK() * 2}, default_rate, 2 * allowance, 0, weight));

    // A peg-in at 2 sat/vB is not rated as L1 fee per vbyte, which would read 21.5 sat/vB.
    const CFeeRate tight{10'000};
    const CAmount pegin_fee{CFeeRate{2'000}.GetFee(200) + CFeeRate::GetMWEBFee(weight)};
    BOOST_CHECK(CFeeRate(pegin_fee, 200) > tight);
    BOOST_CHECK(!MempoolAccept::ExceedsClientMaxFeeRate(tight, default_rate, pegin_fee, 200, weight));
    BOOST_CHECK(MempoolAccept::ExceedsClientMaxFeeRate(tight, default_rate, tight.GetFee(200) + allowance + 1, 200, weight));
}

// Snapshots are written as version 3, which may carry the MWEB section; version 2
// files still load and later versions are refused.
BOOST_AUTO_TEST_CASE(snapshot_metadata_versions)
{
    const MessageStartChars magic{::Params().MessageStart()};
    DataStream written;
    written << node::SnapshotMetadata{magic, uint256::ONE, 7};
    const size_t version_pos{SNAPSHOT_MAGIC_BYTES.size()};
    BOOST_CHECK(written[version_pos] == std::byte{3});
    BOOST_CHECK(written[version_pos + 1] == std::byte{0});

    for (const uint8_t version : {2, 3, 4}) {
        DataStream stream{written};
        stream[version_pos] = std::byte{version};
        node::SnapshotMetadata read{magic};
        if (version == 4) {
            BOOST_CHECK_EXCEPTION(stream >> read, std::ios_base::failure, HasReason("Version of snapshot 4 does not match"));
            continue;
        }
        stream >> read;
        BOOST_CHECK(read.m_base_blockhash == uint256::ONE);
        BOOST_CHECK_EQUAL(read.m_coins_count, 7U);
    }
}

BOOST_AUTO_TEST_CASE(bip324_serialized_size_constant)
{
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_BIP324, (1u << 24) - 1 - 1);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB, MAX_BLOCK_SERIALIZED_SIZE + mw::MAX_BLOCK_BYTES);
    BOOST_CHECK(MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB > MAX_BLOCK_SERIALIZED_SIZE_BIP324);
    BOOST_CHECK(MAX_PROTOCOL_MESSAGE_LENGTH > MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);
    // Default build: mine budget equals BIP324 send gate.
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_MINE, MAX_BLOCK_SERIALIZED_SIZE_BIP324);
}

BOOST_AUTO_TEST_CASE(checkblock_rejects_above_max_mweb_envelope)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = static_cast<CAmount>(1ULL << 32);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    // HogEx last so CBlock serializer emits mweb_block.
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vout.emplace_back(0, CScript() << OP_8 << std::vector<unsigned char>(32, 0x00));
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));

    const Input sample(
        /*features=*/0x01,
        mw::Hash{},
        Commitment{},
        PublicKey{},
        PublicKey{},
        Signature{});
    // Weightless inputs dominate wire bytes: 132k * 196 B ≈ 25.9 MB > consensus cap,
    // while L1 remains tiny so bad-blk-length does not fire first.
    std::vector<Input> inputs(132'000, sample);
    auto header = std::make_shared<mw::Header>(
        /*height=*/1,
        mw::Hash{}, mw::Hash{}, mw::Hash{},
        BlindingFactor{}, BlindingFactor{},
        /*outputMMRSize=*/0, /*kernelMMRSize=*/0);
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>(header, TxBody(std::move(inputs), {}, {})));

    BOOST_REQUIRE(::GetSerializeSize(TX_WITH_WITNESS(block)) > MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);
    BOOST_REQUIRE(::GetSerializeSize(TX_NO_WITNESS_NO_MWEB(block)) * WITNESS_SCALE_FACTOR <= MAX_BLOCK_WEIGHT);

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-serialized-size");
}

BOOST_AUTO_TEST_CASE(bip324_payload_gate_helper)
{
    BOOST_CHECK(!ExceedsBip324BlockPayload(0));
    BOOST_CHECK(!ExceedsBip324BlockPayload(MAX_BLOCK_SERIALIZED_SIZE_BIP324));
    BOOST_CHECK(ExceedsBip324BlockPayload(MAX_BLOCK_SERIALIZED_SIZE_BIP324 + 1));
    BOOST_CHECK(ExceedsBip324BlockPayload(MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB));
}

BOOST_AUTO_TEST_CASE(checkblock_tests_above_bip324_below_max_mweb_no_bad_blk_serialized_size)
{
    // Size in (BIP324, WITH_MWEB]: CheckBlock must not reject for bad-blk-serialized-size.
    // Synthetic MWEB body fails later crypto/structure checks — that is expected.
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = static_cast<CAmount>(1ULL << 32);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vout.emplace_back(0, CScript() << OP_8 << std::vector<unsigned char>(32, 0x00));
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));

    const Input sample(
        /*features=*/0x01,
        mw::Hash{},
        Commitment{},
        PublicKey{},
        PublicKey{},
        Signature{});
    // ~100k weightless inputs ≈ 19.6 MB: above BIP324 mine/v2 gate, under WITH_MWEB.
    std::vector<Input> inputs(100'000, sample);
    auto header = std::make_shared<mw::Header>(
        /*height=*/1,
        mw::Hash{}, mw::Hash{}, mw::Hash{},
        BlindingFactor{}, BlindingFactor{},
        /*outputMMRSize=*/0, /*kernelMMRSize=*/0);
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>(header, TxBody(std::move(inputs), {}, {})));

    const auto ser = ::GetSerializeSize(TX_WITH_WITNESS(block));
    BOOST_REQUIRE(ser > MAX_BLOCK_SERIALIZED_SIZE_BIP324);
    BOOST_REQUIRE(ser <= MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);
    BOOST_REQUIRE(::GetSerializeSize(TX_NO_WITNESS_NO_MWEB(block)) * WITNESS_SCALE_FACTOR <= MAX_BLOCK_WEIGHT);

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK(state.GetRejectReason() != "bad-blk-serialized-size");
}

BOOST_AUTO_TEST_CASE(frozen_mweb_output_ids_configured)
{
    const auto& params = ::Params().GetConsensus();
    BOOST_CHECK(params.frozen_mweb_output_ids.empty());
    BOOST_CHECK(params.mweb_input_metadata_grandfather_blockhash.IsNull());
}

BOOST_AUTO_TEST_CASE(frozen_mweb_output_rejected_in_check_tx_inputs)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pMwebView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock1 = miner.MineBlock(1, {pegin_tx}).GetBlock();
    pMwebView->ApplyBlock(pBlock1, /*allow_historical_metadata_mismatch=*/false);

    test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front(), /*fee=*/1'000);
    const Input& spend_input = pegout_tx.GetTransaction()->GetInputs().front();
    const uint256 frozen_oid{spend_input.GetOutputID().vec()};

    Consensus::Params params = ::Params().GetConsensus();
    params.frozen_mweb_output_ids = {frozen_oid};

    MWEBBackedEmptyView backing{pMwebView};
    CCoinsViewCache inputs{&backing};

    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*pegout_tx.GetTransaction());

    TxValidationState state;
    CAmount txfee{0};
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{mtx}, state, inputs, /*nSpendHeight=*/2, params, txfee));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-frozen-mweb-output");
}

BOOST_AUTO_TEST_CASE(input_metadata_grandfather_allow_and_binding)
{
    // Null grandfather never allows a mismatch.
    Consensus::Params params = ::Params().GetConsensus();
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256::ONE;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.nNonce = 0;
    BOOST_REQUIRE(params.mweb_input_metadata_grandfather_blockhash.IsNull());
    BOOST_CHECK(!Node::AllowInputMetadataMismatch(block, params));

    // Matching grandfather hash allows; any other hash does not.
    params.mweb_input_metadata_grandfather_blockhash = block.GetHash();
    BOOST_CHECK(Node::AllowInputMetadataMismatch(block, params));
    CBlock other = block;
    other.nNonce = 1;
    BOOST_CHECK(!Node::AllowInputMetadataMismatch(other, params));

    // Build a spendable UTXO, then an input that lies about the receiver pubkey.
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock1 = miner.MineBlock(1, {pegin_tx}).GetBlock();
    pCachedView->ApplyBlock(pBlock1, /*allow_historical_metadata_mismatch=*/false);

    test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front(), /*fee=*/1'000);
    mw::Block::CPtr honest = miner.MineBlock(2, {pegout_tx}).GetBlock();
    const Input& good = honest->GetInputs().front();
    BOOST_REQUIRE(good.GetInputPubKey());
    Input lied(
        /*features=*/0x01,
        good.GetOutputID(),
        good.GetCommitment(),
        *good.GetInputPubKey(),
        PublicKey::From(SecretKey::Random()), // wrong receiver pubkey
        good.GetSignature());
    mw::Block::CPtr bad = mw::MutBlock(honest).SetInputs({lied}).Build();

    CBlock cblock;
    cblock.mweb_block = MWEB::Block(bad);

    // Without grandfather: binding must fail.
    BOOST_CHECK(!Node::CheckInputMetadataBinding(cblock, pCachedView.get(), /*allow_historical_metadata_mismatch=*/false));
    // With grandfather exception: same mismatch is forgiven.
    BOOST_CHECK(Node::CheckInputMetadataBinding(cblock, pCachedView.get(), /*allow_historical_metadata_mismatch=*/true));

    // ApplyBlock mirrors the same rule (ConnectBlock path). Throw does not
    // mutate the parent cache (validation uses a temporary layer).
    BOOST_CHECK_THROW(pCachedView->ApplyBlock(bad, /*allow_historical_metadata_mismatch=*/false), std::exception);
    BOOST_CHECK_NO_THROW(pCachedView->ApplyBlock(bad, /*allow_historical_metadata_mismatch=*/true));
}

// Grandfather lives on Consensus::Params, not a mutable process global.
BOOST_AUTO_TEST_CASE(kernel_lock_height_grandfather_in_consensus_params)
{
    // MWEBTestingSetup selects MAIN; CreateChainParams(Main) must agree without
    // any CreateChainParams side-effect mutation of a process global.
    BOOST_CHECK_EQUAL(::Params().GetConsensus().mweb_kernel_lock_height_grandfather, 0);
    const auto main = CChainParams::Main();
    BOOST_CHECK_EQUAL(main->GetConsensus().mweb_kernel_lock_height_grandfather, 0);

    // Regtest enforces lock heights from the first MWEB block (grandfather 0).
    const auto regtest = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(regtest->GetConsensus().mweb_kernel_lock_height_grandfather, 0);
}

BOOST_AUTO_TEST_CASE(regtest_mweb_inactive_by_default)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& mweb = params->GetConsensus().vDeployments[Consensus::DEPLOYMENT_MWEB];
    BOOST_CHECK(mweb.nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE);
    BOOST_CHECK_EQUAL(mweb.period, 144U);
    BOOST_CHECK_EQUAL(mweb.threshold, 108U);
}

BOOST_AUTO_TEST_CASE(regtest_mweb_vbparams_enable)
{
    ArgsManager args;
    args.ForceSetArg("-vbparams", "mweb:1601450001000:9999999999000");
    const auto params = CreateChainParams(args, ChainType::REGTEST);
    const auto& mweb = params->GetConsensus().vDeployments[Consensus::DEPLOYMENT_MWEB];
    BOOST_CHECK_EQUAL(mweb.nStartTime, 1601450001000);
    BOOST_CHECK_EQUAL(mweb.nTimeout, 9999999999000);
}

BOOST_AUTO_TEST_CASE(unserialize_block_undo_replaces_previous_contents)
{
    const auto make_undo{[](std::initializer_list<CAmount> values) {
        CBlockUndo undo;
        for (const CAmount value : values) {
            CTxUndo tx_undo;
            tx_undo.vprevout.emplace_back(CTxOut{value, CScript{} << OP_TRUE}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false);
            undo.vtxundo.push_back(std::move(tx_undo));
        }
        return undo;
    }};
    const CBlockUndo first{make_undo({1, 2})};
    const CBlockUndo second{make_undo({3})};

    // Readers such as BaseIndex::Rewind reuse one CBlockUndo across blocks.
    CBlockUndo read;
    read.mwundo = std::make_shared<const mw::BlockUndo>();
    for (const CBlockUndo* expected : {&first, &second}) {
        DataStream stream;
        stream << *expected;
        UnserializeBlockUndo(read, stream, GetSerializeSize(*expected));
        BOOST_CHECK(stream.empty());
        BOOST_CHECK(read.mwundo == nullptr);
        BOOST_REQUIRE_EQUAL(read.vtxundo.size(), expected->vtxundo.size());
        for (size_t i = 0; i < read.vtxundo.size(); ++i) {
            BOOST_CHECK_EQUAL(read.vtxundo[i].vprevout.at(0).out.nValue, expected->vtxundo[i].vprevout.at(0).out.nValue);
        }
    }
}

namespace {

//! Minimal coinbase + peg-in deposit + HogEx block around an MWEB body, built on
//! top of a previous MWEB block (so HogEx input 0 spends the previous HogEx).
CBlock MakeHogExBlock(const mw::Block::CPtr& body, const CBlockIndex& previous, CAmount pegin_amount,
                      const mw::Hash& pegin_id, CAmount mweb_amount_change, const std::vector<CTxOut>& pegouts = {})
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.emplace_back(0, CScript() << OP_TRUE);

    CMutableTransaction deposit;
    deposit.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{2}), 0});
    deposit.vout.emplace_back(pegin_amount, GetScriptForPegin(pegin_id));

    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vin.emplace_back(COutPoint{previous.hogex_hash, 0});
    hogex.vin.emplace_back(COutPoint{deposit.GetHash(), 0});
    hogex.vout.emplace_back(previous.mweb_amount + mweb_amount_change, CScript() << OP_8 << body->GetHash().vec());
    for (const CTxOut& pegout : pegouts) {
        hogex.vout.push_back(pegout);
    }

    CBlock block;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(deposit), MakeTransactionRef(hogex)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.mweb_block = MWEB::Block{body};
    return block;
}

Kernel WithFeatureBit(const Kernel& kernel, uint8_t feature_bit)
{
    return Kernel(
        kernel.GetFeatures() | feature_bit,
        kernel.GetOptionalFee(),
        kernel.GetOptionalPegIn(),
        kernel.GetPegOuts(),
        (kernel.GetFeatures() & Kernel::HEIGHT_LOCK_FEATURE_BIT) ? std::make_optional(kernel.GetLockHeight()) : std::nullopt,
        kernel.HasStealthExcess() ? std::make_optional(kernel.GetStealthExcess()) : std::nullopt,
        kernel.GetExtraData(),
        kernel.GetExcess(),
        kernel.GetSignature());
}

} // namespace

// A peer can flip the uncommitted HogEx marker or rewrite uncommitted kernel
// feature fields without changing the block hash. None of those bodies may be
// reported as BLOCK_CONSENSUS, or the honest block with the same hash would be
// permanently invalidated.
BOOST_AUTO_TEST_CASE(contextual_check_same_hash_mutations_are_mutated)
{
    Consensus::Params consensus = ::Params().GetConsensus();
    const int height = 1000;
    consensus.mweb_pegout_feature_activation_height = height;
    consensus.mweb_extradata_feature_activation_height = height;

    test::Miner miner(GetDataDir());
    const auto prior = miner.MineBlock(height - 1, {test::Tx::CreatePegIn(10'000)}).GetBlock();
    const auto pegin_tx = test::Tx::CreatePegIn(1'000);
    const auto valid_mweb = miner.MineBlock(height, {pegin_tx}).GetBlock();
    const auto pegin = pegin_tx.GetPegInCoin();

    CBlockIndex previous;
    previous.nHeight = height - 1;
    previous.hogex_hash = Txid::FromUint256(uint256::ONE);
    previous.mweb_header = prior->GetHeader();
    previous.mweb_amount = 10'000;

    const auto check = [&](const CBlock& block, BlockValidationState& state) {
        return Node::ContextualCheckBlock(block, consensus, &previous, state, /*mweb_active=*/true, /*mweb_active_at_prev=*/true);
    };

    const CBlock valid = MakeHogExBlock(valid_mweb, previous, pegin.GetAmount(), pegin.GetKernelID(), pegin.GetAmount());
    BlockValidationState accepted;
    BOOST_REQUIRE_MESSAGE(check(valid, accepted), accepted.ToString());

    // HogEx marker on the peg-in deposit: placement must be checked before the
    // coinbase/HogEx peg-in rule.
    CBlock extra_hogex_marker = valid;
    CMutableTransaction marked_deposit(*extra_hogex_marker.vtx[1]);
    marked_deposit.m_hogEx = true;
    extra_hogex_marker.vtx[1] = MakeTransactionRef(std::move(marked_deposit));
    BOOST_REQUIRE(extra_hogex_marker.GetHash() == valid.GetHash());

    BlockValidationState marker_state;
    BOOST_CHECK(!check(extra_hogex_marker, marker_state));
    BOOST_CHECK(marker_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(marker_state.GetRejectReason(), "bad-hogex-position");

    const auto check_kernel_feature = [&](uint8_t feature_bit, const std::string& reject_reason) {
        // Same block hash, kernel body no longer matches the committed root.
        CBlock mutated = valid;
        mutated.mweb_block = MWEB::Block{mw::MutBlock(valid_mweb)
            .SetKernels({WithFeatureBit(valid_mweb->GetKernels().front(), feature_bit)})
            .Build()};
        BOOST_REQUIRE(mutated.GetHash() == valid.GetHash());

        BlockValidationState state;
        BOOST_CHECK(!check(mutated, state));
        BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-mweb");

        // Even with a root that commits to the non-canonical kernel, the
        // feature rule reports BLOCK_MUTATED (alternate encodings may share a leaf).
        MemMMR kernel_mmr;
        for (const Kernel& kernel : mutated.mweb_block.m_block->GetKernels()) {
            kernel_mmr.Add(kernel);
        }
        const auto committed_mweb = std::make_shared<mw::Block>(
            mw::MutHeader(mutated.mweb_block.m_block->GetHeader()).SetKernelRoot(kernel_mmr.Root()).Build(),
            mutated.mweb_block.m_block->GetTxBody());
        const CBlock committed = MakeHogExBlock(committed_mweb, previous, pegin.GetAmount(), pegin.GetKernelID(), pegin.GetAmount());

        BlockValidationState committed_state;
        BOOST_CHECK(!check(committed, committed_state));
        BOOST_CHECK(committed_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
        BOOST_CHECK_EQUAL(committed_state.GetRejectReason(), reject_reason);
    };
    check_kernel_feature(Kernel::PEGOUT_FEATURE_BIT, "bad-mweb-empty-pegout");
    check_kernel_feature(Kernel::EXTRA_DATA_FEATURE_BIT, "bad-mweb-empty-extradata");

    // Compact-block peers are discouraged for every one of these MWEB body reasons.
    for (const std::string reason : {"bad-blk-mweb", "bad-mweb-empty-pegout", "bad-mweb-empty-extradata"}) {
        BlockValidationState state;
        state.Invalid(BlockValidationResult::BLOCK_MUTATED, reason);
        BOOST_CHECK(Node::IsPunishableCompactBlockReject(state));
    }
    BlockValidationState consensus_state;
    consensus_state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-mweb");
    BOOST_CHECK(!Node::IsPunishableCompactBlockReject(consensus_state));
    BOOST_CHECK(!Node::IsPunishableCompactBlockReject(marker_state));

    // The HogEx commits to a header whose kernel root the body does not match.
    const auto invalid_root = std::make_shared<mw::Block>(
        mw::MutHeader(valid_mweb->GetHeader()).SetKernelRoot(mw::Hash{}).Build(),
        valid_mweb->GetTxBody());
    BlockValidationState root_state;
    BOOST_CHECK(!check(MakeHogExBlock(invalid_root, previous, pegin.GetAmount(), pegin.GetKernelID(), pegin.GetAmount()), root_state));
    BOOST_CHECK(root_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(root_state.GetRejectReason(), "bad-blk-mweb");

    // The peg-in script names a kernel that is not in the body.
    BlockValidationState pegin_state;
    BOOST_CHECK(!check(MakeHogExBlock(valid_mweb, previous, pegin.GetAmount(), mw::Hash{}, pegin.GetAmount()), pegin_state));
    BOOST_CHECK(pegin_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(pegin_state.GetRejectReason(), "bad-blk-mweb");
}

// A kernel whose wire encoding has an empty peg-out list can reserialize to the
// same bytes (and kernel MMR leaf) as a canonical kernel. The non-canonical body
// must be rejected as BLOCK_MUTATED so the canonical body is still accepted.
BOOST_AUTO_TEST_CASE(contextual_check_kernel_serialization_collision_is_mutated)
{
    Consensus::Params consensus = ::Params().GetConsensus();
    const int height = 1000;
    consensus.mweb_pegout_feature_activation_height = height;
    consensus.mweb_extradata_feature_activation_height = height;

    constexpr CAmount pegin_amount = 6;
    constexpr CAmount output_amount = 1;
    constexpr CAmount pegout_amount = 5;
    const uint8_t features =
        Kernel::PEGIN_FEATURE_BIT |
        Kernel::PEGOUT_FEATURE_BIT |
        Kernel::HEIGHT_LOCK_FEATURE_BIT |
        Kernel::EXTRA_DATA_FEATURE_BIT;
    const std::optional<CAmount> pegin(pegin_amount);
    const std::vector<PegOutCoin> pegouts{PegOutCoin(pegout_amount, CScript() << OP_TRUE)};
    const auto lock_height = std::make_optional<int32_t>(0);
    const std::vector<uint8_t> extra_data{0x42};

    const BlindingFactor excess_blind = BlindingFactor::Random();
    const Commitment excess = Commitment::Blinded(excess_blind, 0);
    const Signature signature = Schnorr::Sign(
        excess_blind.data(),
        Kernel::GetSignatureMessage(features, excess, std::nullopt, std::nullopt, pegin, pegouts, lock_height, extra_data));
    const Kernel valid_kernel(features, std::nullopt, pegin, pegouts, lock_height, std::nullopt, extra_data, excess, signature);

    const SecretKey sender_key = SecretKey::Random();
    const test::TxOutput output = test::TxOutput::Create(sender_key, SecretKey::Random(), SecretKey::Random(), output_amount);
    Blinds kernel_offset;
    kernel_offset.Add(output.GetBlind()).Sub(excess_blind);
    Blinds stealth_offset;
    stealth_offset.Add(sender_key);
    const auto valid_tx = mw::Transaction::Create(
        kernel_offset.Total(), stealth_offset.Total(), {}, {output.GetOutput()}, {valid_kernel});
    BOOST_REQUIRE_NO_THROW(valid_tx->Validate());

    test::Miner miner(GetDataDir());
    const auto prior = miner.MineBlock(height - 1).GetBlock();
    const auto valid_mweb = miner.MineBlock(height, {test::Tx(valid_tx, {output})}).GetBlock();

    CBlockIndex previous;
    previous.nHeight = height - 1;
    previous.hogex_hash = Txid::FromUint256(uint256::ONE);
    previous.mweb_header = prior->GetHeader();
    previous.mweb_amount = 100;

    const auto check = [&](const CBlock& block, BlockValidationState& state) {
        return Node::ContextualCheckBlock(block, consensus, &previous, state, /*mweb_active=*/true, /*mweb_active_at_prev=*/true);
    };

    const std::vector<CTxOut> hogex_pegouts{CTxOut(pegout_amount, CScript() << OP_TRUE)};
    const CBlock valid_block = MakeHogExBlock(valid_mweb, previous, pegin_amount, valid_kernel.GetKernelID(), output_amount, hogex_pegouts);
    BlockValidationState valid_state;
    BOOST_REQUIRE_MESSAGE(check(valid_block, valid_state), valid_state.ToString());

    auto collision_bytes = valid_kernel.Serialized();
    BOOST_REQUIRE(collision_bytes.size() >= 2);
    BOOST_REQUIRE_EQUAL(collision_bytes[0], features);
    BOOST_REQUIRE_EQUAL(collision_bytes[1], pegin_amount);
    collision_bytes.insert(collision_bytes.begin() + 2, 0x00);
    const Kernel collision_kernel = Kernel::Deserialize(collision_bytes);

    BOOST_REQUIRE(collision_kernel.GetPegOuts().empty());
    BOOST_REQUIRE_EQUAL(collision_kernel.GetLockHeight(), 1);
    BOOST_REQUIRE(collision_kernel.GetExtraData() == std::vector<uint8_t>({0x01, 0x51, 0x00, 0x01, 0x42}));
    BOOST_REQUIRE(collision_kernel.Serialized() == valid_kernel.Serialized());
    BOOST_REQUIRE(collision_kernel.GetKernelID() == valid_kernel.GetKernelID());

    const auto collision_mweb = mw::MutBlock(valid_mweb).SetKernels({collision_kernel}).Build();
    BOOST_REQUIRE(collision_mweb->GetHash() == valid_mweb->GetHash());
    BOOST_REQUIRE(collision_mweb->HasValidKernelMMR());

    CBlock collision_block = valid_block;
    collision_block.mweb_block = MWEB::Block{collision_mweb};
    BOOST_REQUIRE(collision_block.GetHash() == valid_block.GetHash());

    BlockValidationState collision_state;
    BOOST_CHECK(!check(collision_block, collision_state));
    BOOST_CHECK(collision_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(collision_state.GetRejectReason(), "bad-mweb-empty-pegout");

    BlockValidationState replacement_state;
    BOOST_CHECK(check(valid_block, replacement_state));
}

// Peg-ins are only credited from ordinary transactions; a peg-in script in the
// coinbase or HogEx is a committed consensus failure.
BOOST_AUTO_TEST_CASE(contextual_check_rejects_pegin_in_coinbase_or_hogex)
{
    const Consensus::Params& consensus = ::Params().GetConsensus();
    const int height = 1000;

    test::Miner miner(GetDataDir());
    const auto prior = miner.MineBlock(height - 1, {test::Tx::CreatePegIn(10'000)}).GetBlock();
    const auto pegin_tx = test::Tx::CreatePegIn(1'000);
    const auto valid_mweb = miner.MineBlock(height, {pegin_tx}).GetBlock();
    const auto pegin = pegin_tx.GetPegInCoin();

    CBlockIndex previous;
    previous.nHeight = height - 1;
    previous.hogex_hash = Txid::FromUint256(uint256::ONE);
    previous.mweb_header = prior->GetHeader();
    previous.mweb_amount = 10'000;

    const auto check = [&](const CBlock& block, BlockValidationState& state) {
        return Node::ContextualCheckBlock(block, consensus, &previous, state, /*mweb_active=*/true, /*mweb_active_at_prev=*/true);
    };

    const CBlock valid = MakeHogExBlock(valid_mweb, previous, pegin.GetAmount(), pegin.GetKernelID(), pegin.GetAmount());
    BlockValidationState accepted;
    BOOST_REQUIRE_MESSAGE(check(valid, accepted), accepted.ToString());

    const CTxOut stray_pegin{0, GetScriptForPegin(pegin.GetKernelID())};
    for (const size_t tx_index : {size_t{0}, valid.vtx.size() - 1}) {
        CBlock with_pegin = valid;
        CMutableTransaction mtx(*with_pegin.vtx[tx_index]);
        mtx.vout.push_back(stray_pegin);
        with_pegin.vtx[tx_index] = MakeTransactionRef(std::move(mtx));
        with_pegin.hashMerkleRoot = BlockMerkleRoot(with_pegin);

        BlockValidationState state;
        BOOST_CHECK(!check(with_pegin, state));
        BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_CONSENSUS);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-tx-unexpected-pegin");
    }
}

// Peg-out scripts become HogEx outputs, so their sigops count against the
// transaction that carries them, as on Litecoin. The miner moves exactly that
// cost to the HogEx, so it must never exceed the transaction's own cost.
BOOST_AUTO_TEST_CASE(legacy_sigop_count_includes_pegout_scripts)
{
    const CScript p2pkh = GetScriptForDestination(PKHash{uint160{}});
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, /*pegin_amount=*/std::nullopt,
        std::vector<PegOutCoin>{PegOutCoin(5'000, p2pkh), PegOutCoin(6'000, p2pkh)}, /*lock_height=*/std::nullopt);
    CMutableTransaction mtx;
    mtx.vout.emplace_back(1'000, p2pkh);
    mtx.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {}, {}, {kernel}));
    const CTransaction tx{mtx};
    BOOST_REQUIRE(tx.HasMWEBTx());
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 3U);
    BOOST_CHECK_EQUAL(MWEB::Miner::GetHogExSigOpCost(tx), 2 * WITNESS_SCALE_FACTOR);
    BOOST_CHECK_GE(int64_t{GetLegacySigOpCount(tx)} * WITNESS_SCALE_FACTOR, MWEB::Miner::GetHogExSigOpCost(tx));

    CMutableTransaction stripped{mtx};
    stripped.mweb_tx.SetNull();
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(CTransaction{stripped}), 1U);
}

// Txids do not commit to attached MWEB data, so a copy of a valid block with
// peg-outs attached keeps its merkle root. It must fail as mutated, not as a
// consensus failure that would mark the real block invalid.
BOOST_AUTO_TEST_CASE(checkblock_rejects_attached_mweb_data_before_sigops)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.emplace_back(0, CScript() << OP_TRUE);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BlockValidationState valid_state;
    BOOST_REQUIRE_MESSAGE(CheckBlock(block, valid_state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true), valid_state.ToString());

    CScript heavy;
    for (int64_t i = 0; i <= MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR; ++i) {
        heavy << OP_CHECKSIG;
    }
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, /*pegin_amount=*/std::nullopt,
        std::vector<PegOutCoin>{PegOutCoin(1'000, heavy)}, /*lock_height=*/std::nullopt);
    coinbase.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {}, {}, {kernel}));
    CBlock tampered{block};
    tampered.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_REQUIRE(tampered.vtx[0]->HasMWEBTx());
    BOOST_REQUIRE(BlockMerkleRoot(tampered) == block.hashMerkleRoot);
    BOOST_REQUIRE_GT(int64_t{GetLegacySigOpCount(*tampered.vtx[0])} * WITNESS_SCALE_FACTOR, MAX_BLOCK_SIGOPS_COST);

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(tampered, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
    BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "unexpected-mweb-data");
}

// Non-finalizable attached MWEB (feature-0 inputs) must not be silently
// stripped past CheckBlock. Sticky HadAttachedMWEB restores D's BLOCK_MUTATED path.
BOOST_AUTO_TEST_CASE(checkblock_rejects_nonfinal_attached_mweb_feature0)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.emplace_back(0, CScript() << OP_TRUE);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BlockValidationState valid_state;
    BOOST_REQUIRE_MESSAGE(CheckBlock(block, valid_state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true), valid_state.ToString());

    coinbase.mweb_tx = MakeNonFinalFeature0MutableTx();
    CBlock tampered{block};
    tampered.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_REQUIRE(tampered.vtx[0]->HadAttachedMWEB());
    BOOST_REQUIRE(!tampered.vtx[0]->HasMWEBTx());
    BOOST_REQUIRE(BlockMerkleRoot(tampered) == block.hashMerkleRoot);

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(tampered, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
    BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "unexpected-mweb-data");
    BlockValidationState node_state;
    BOOST_CHECK(!Node::CheckBlock(tampered, node_state));
    BOOST_CHECK_EQUAL(node_state.GetRejectReason(), "unexpected-mweb-data");
}

BOOST_AUTO_TEST_CASE(had_attached_mweb_sticky_bit_roundtrip)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.emplace_back(1, CScript() << OP_TRUE);

    // Wire a present optional mw::Transaction with feature-0 input (not via MutableTx write,
    // which would Finalized()-drop before the bytes leave).
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, /*pegin_amount=*/std::nullopt,
        std::vector<PegOutCoin>{}, /*lock_height=*/std::nullopt);
    mw::Transaction::CPtr feature0_tx =
        mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {MakeFeature0Input()}, {}, {kernel});

    DataStream ss{};
    ss << mtx.version;
    std::vector<CTxIn> vin_dummy;
    ss << vin_dummy;
    const uint8_t flags{8};
    ss << flags;
    ss << mtx.vin << mtx.vout;
    ss << WrapOptionalPtr(feature0_tx);
    ss << mtx.nLockTime;

    CMutableTransaction decoded;
    ss >> TX_WITH_WITNESS(decoded);
    BOOST_REQUIRE(!decoded.mweb_tx.IsNull());
    BOOST_REQUIRE(!decoded.mweb_tx.IsFinal());
    BOOST_CHECK(decoded.HadAttachedMWEB());

    const CTransaction tx{decoded};
    BOOST_CHECK(tx.HadAttachedMWEB());
    BOOST_CHECK(!tx.HasMWEBTx());
    BOOST_CHECK(!tx.IsHogEx());

    const CMutableTransaction roundtrip{tx};
    BOOST_CHECK(roundtrip.HadAttachedMWEB());
    BOOST_CHECK(roundtrip.mweb_tx.IsNull());
}

BOOST_AUTO_TEST_CASE(hogex_null_optional_does_not_set_had_attached_mweb)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.emplace_back(0, CScript() << OP_8 << std::vector<unsigned char>(32, 0x00));
    mtx.m_hogEx = true;

    DataStream ss{};
    ss << TX_WITH_WITNESS(mtx);
    CMutableTransaction decoded;
    ss >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(decoded.m_hogEx);
    BOOST_CHECK(decoded.mweb_tx.IsNull());
    BOOST_CHECK(!decoded.HadAttachedMWEB());
    const CTransaction tx{decoded};
    BOOST_CHECK(tx.IsHogEx());
    BOOST_CHECK(!tx.HadAttachedMWEB());
}

BOOST_AUTO_TEST_CASE(mempool_rejects_nonfinal_attached_mweb)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.emplace_back(1, CScript() << OP_TRUE);
    mtx.mweb_tx = MakeNonFinalFeature0MutableTx();
    const CTransaction tx{mtx};
    BOOST_REQUIRE(tx.HadAttachedMWEB());
    BOOST_REQUIRE(!tx.HasMWEBTx());

    TxValidationState state;
    BOOST_CHECK(!MempoolAccept::RejectNonFinalAttached(tx, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-mweb-not-final");

    TxValidationState ok;
    BOOST_CHECK(MempoolAccept::RejectNonFinalAttached(CTransaction{CMutableTransaction{}}, ok));
}

// Intentional strip of final attached MWEB (miner / BIP152) must not leave sticky
// bits that fail CheckBlock on the canonical vtx stub.
BOOST_AUTO_TEST_CASE(strip_final_attached_mweb_clears_sticky_for_checkblock)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    mtx.vout.emplace_back(0, CScript() << OP_TRUE);
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, /*fee=*/1'000, /*pegin_amount=*/std::nullopt,
        std::vector<PegOutCoin>{}, /*lock_height=*/std::nullopt);
    mtx.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(BlindingFactor{}, BlindingFactor{}, {}, {}, {kernel}));
    const CTransaction with_mweb{mtx};
    BOOST_REQUIRE(with_mweb.HasMWEBTx());
    BOOST_REQUIRE(!with_mweb.HadAttachedMWEB());

    CMutableTransaction stripped{with_mweb};
    stripped.ClearAttachedMWEB();
    const CTransaction stub{stripped};
    BOOST_CHECK(!stub.HasMWEBTx());
    BOOST_CHECK(!stub.HadAttachedMWEB());

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(stub));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BlockValidationState state;
    BOOST_CHECK_MESSAGE(CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true), state.ToString());
    BOOST_CHECK(Node::CheckBlock(block, state));
}

BOOST_AUTO_TEST_CASE(had_attached_mweb_is_uncommitted_payload)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.emplace_back(1, CScript() << OP_TRUE);
    mtx.mweb_tx = MakeNonFinalFeature0MutableTx();
    const CTransaction tx{mtx};
    BOOST_REQUIRE(tx.HadAttachedMWEB());
    BOOST_CHECK(Policy::HasUncommittedMWEBPayload(tx));
    BOOST_CHECK(!Policy::HasUncommittedMWEBPayload(CTransaction{CMutableTransaction{}}));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_validation_tests_mining, MWEBRegtest100Setup)

// Invariant: the MWEB view is attached at InitCoinsDB (even pre-activation), so
// every coins cache wraps an MWEB layer from construction and the first MWEB
// block mines with no explicit attach step.
BOOST_AUTO_TEST_CASE(mweb_view_invariant_enables_first_mweb_mining)
{
    auto& chainman = *Assert(m_node.chainman);

    {
        LOCK(cs_main);
        auto& chainstate = chainman.ActiveChainstate();
        // Pre-activation (height 100): view already attached, caches already wrapped.
        BOOST_CHECK(chainstate.CoinsDB().GetMWEBView() != nullptr);
        BOOST_CHECK(chainstate.CoinsTip().GetMWEBView() != nullptr);
    }

    // Advance block times through activation and supply the first HogEx input.
    MineToMWEBActivation();
    SubmitPeginToMempool(*this, m_node);

    // First MWEB block mines without any explicit MWEB view setup.
    BOOST_CHECK_NO_THROW(MineMWEBEraBlock());
    LOCK(cs_main);
    BOOST_REQUIRE_EQUAL(chainman.ActiveHeight(), FIRST_MWEB_HEIGHT);
    BOOST_CHECK(DeploymentActiveAt(*chainman.ActiveChain().Tip(), chainman.GetConsensus(), Consensus::DEPLOYMENT_MWEB, chainman.m_versionbitscache));
    BOOST_CHECK(chainman.ActiveChainstate().CoinsTip().GetMWEBView() != nullptr);

    CBlock block;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block, *chainman.ActiveChain().Tip()));
    BOOST_CHECK(!block.mweb_block.IsNull());
    const CTransactionRef hogex{block.GetHogEx()};
    BOOST_REQUIRE(hogex);
    BOOST_CHECK_EQUAL(hogex->vin.size(), 1U);
    size_t pegins{0};
    for (const auto& tx : block.vtx) {
        for (const auto& output : tx->vout) {
            pegins += output.scriptPubKey.IsMWEBPegin();
        }
    }
    BOOST_CHECK_EQUAL(pegins, 1U);
}

BOOST_AUTO_TEST_CASE(disconnectblock_fails_without_mweb_view)
{
    MineToMwebChain(*this, m_node);

    LOCK(::cs_main);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    CBlockIndex* pindex_tip = FindTipWithMwundo(chainstate, chainman.ActiveChain());
    BOOST_REQUIRE(pindex_tip);
    BOOST_REQUIRE(pindex_tip->pprev);

    CBlock block;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block, *pindex_tip));

    CBlockUndo block_undo;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlockUndo(block_undo, *pindex_tip));
    BOOST_REQUIRE(block_undo.mwundo != nullptr);
    BOOST_REQUIRE(block_undo.mwundo->GetPreviousHeader());

    const uint256 tip_hash{pindex_tip->GetBlockHash()};
    NoMWEBViewWrapper nomweb{&chainstate.CoinsTip()};
    CCoinsViewCache broken_view{&nomweb};
    broken_view.SetBestBlock(tip_hash);

    // Must not return OK when mwundo exists but the view has no MWEB cache.
    // On failure the caller must not flush; best block must remain at the tip.
    const DisconnectResult result = chainstate.DisconnectBlock(block, pindex_tip, broken_view);
    BOOST_CHECK(result == DISCONNECT_FAILED);
    BOOST_CHECK(broken_view.GetBestBlock() == tip_hash);
}

BOOST_AUTO_TEST_CASE(disconnectblock_succeeds_with_mweb_view)
{
    MineToMwebChain(*this, m_node);

    LOCK(::cs_main);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    CBlockIndex* pindex_tip = FindTipWithMwundo(chainstate, chainman.ActiveChain());
    BOOST_REQUIRE(pindex_tip);
    BOOST_REQUIRE(pindex_tip->pprev);

    CBlock block;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block, *pindex_tip));

    CBlockUndo block_undo;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlockUndo(block_undo, *pindex_tip));
    BOOST_REQUIRE(block_undo.mwundo != nullptr);
    BOOST_REQUIRE(block_undo.mwundo->GetPreviousHeader());

    CCoinsViewCache view{&chainstate.CoinsTip()};
    view.SetBestBlock(pindex_tip->GetBlockHash());

    const DisconnectResult result = chainstate.DisconnectBlock(block, pindex_tip, view);
    BOOST_CHECK(result == DISCONNECT_OK || result == DISCONNECT_UNCLEAN);

    const auto mweb_view = view.GetMWEBCacheView();
    BOOST_REQUIRE(mweb_view);
    BOOST_REQUIRE(mweb_view->GetBestHeader());
    BOOST_CHECK(*mweb_view->GetBestHeader() == *block_undo.mwundo->GetPreviousHeader());
    BOOST_CHECK(view.GetBestBlock() == pindex_tip->pprev->GetBlockHash());
}

// ConnectBlock must re-run the contextual MWEB checks on the body it connects:
// a body reloaded from disk, or a replacement with the same block hash, never
// went through AcceptBlock and must not inherit the earlier body's acceptance.
BOOST_AUTO_TEST_CASE(connectblock_revalidates_disk_body)
{
    MineToMwebChain(*this, m_node, /*post_activation_blocks=*/1);

    LOCK(::cs_main);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    CBlockIndex* pindex = chainman.ActiveChain().Tip();
    BOOST_REQUIRE(pindex && pindex->pprev);

    CBlock valid;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(valid, *pindex));
    BOOST_REQUIRE(!valid.mweb_block.IsNull());
    const auto valid_mweb = valid.mweb_block.m_block;
    BOOST_REQUIRE(!valid_mweb->GetKernels().empty());

    CCoinsViewCache parent_view{&chainstate.CoinsTip()};
    parent_view.SetBestBlock(pindex->GetBlockHash());
    const DisconnectResult disconnected = chainstate.DisconnectBlock(valid, pindex, parent_view);
    BOOST_REQUIRE(disconnected == DISCONNECT_OK || disconnected == DISCONNECT_UNCLEAN);
    BOOST_REQUIRE(parent_view.GetBestBlock() == pindex->pprev->GetBlockHash());
    BOOST_REQUIRE(!valid_mweb->GetOutputs().empty());
    const mw::Hash output_id = valid_mweb->GetOutputs().front().GetOutputID();
    // The parent is the last block before MWEB, so its MWEB view has no header yet.
    BOOST_REQUIRE(!Assert(parent_view.GetMWEBCacheView())->GetBestHeader());
    BOOST_REQUIRE(!parent_view.GetMWEBCacheView()->HasCoin(output_id));

    const auto check_connection = [&](const CBlock& block, const std::string& reject_reason) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        BOOST_REQUIRE(block.GetHash() == valid.GetHash());

        DataStream disk{};
        disk << TX_WITH_WITNESS(block);
        CBlock reloaded;
        disk >> TX_WITH_WITNESS(reloaded);
        BOOST_REQUIRE(disk.empty());

        CCoinsViewCache view{&parent_view};
        BlockValidationState state;
        const bool connected = chainstate.ConnectBlock(reloaded, state, pindex, view, /*fJustCheck=*/true);
        const auto mweb_view = view.GetMWEBCacheView();
        BOOST_REQUIRE(mweb_view);
        if (reject_reason.empty()) {
            BOOST_CHECK_MESSAGE(connected, state.ToString());
            BOOST_CHECK(mweb_view->HasCoin(output_id));
            BOOST_REQUIRE(mweb_view->GetBestHeader());
            BOOST_CHECK(*mweb_view->GetBestHeader() == *valid_mweb->GetHeader());
        } else {
            BOOST_CHECK(!connected);
            BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
            BOOST_CHECK_EQUAL(state.GetRejectReason(), reject_reason);
            BOOST_CHECK(!mweb_view->HasCoin(output_id));
            BOOST_CHECK(!mweb_view->GetBestHeader());
        }
    };

    auto kernels = valid_mweb->GetKernels();
    auto serialized_kernel = kernels.front().Serialized();
    serialized_kernel.back() ^= 1;
    kernels.front() = Kernel::Deserialize(serialized_kernel);
    CBlock invalid_signature = valid;
    invalid_signature.mweb_block = MWEB::Block{mw::MutBlock(valid_mweb).SetKernels(kernels).Build()};
    check_connection(invalid_signature, "bad-blk-mweb");

    CBlock invalid_root = valid;
    invalid_root.mweb_block = MWEB::Block{std::make_shared<mw::Block>(
        mw::MutHeader(valid_mweb->GetHeader()).SetKernelRoot(mw::Hash{}).Build(),
        valid_mweb->GetTxBody())};
    check_connection(invalid_root, "mweb-hash-mismatch");

    CBlock stripped = valid;
    stripped.mweb_block = MWEB::Block{};
    check_connection(stripped, "mweb-missing");

    check_connection(valid, "");
}

// RollforwardBlock (ReplayBlocks after an interrupted flush) must also re-run the
// contextual MWEB checks on the body it reads from disk.
BOOST_AUTO_TEST_CASE(rollforwardblock_revalidates_disk_body)
{
    MineToMwebChain(*this, m_node, /*post_activation_blocks=*/1);

    LOCK(::cs_main);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    CBlockIndex* pindex = chainman.ActiveChain().Tip();
    BOOST_REQUIRE(pindex && pindex->pprev);

    CBlock valid;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(valid, *pindex));
    BOOST_REQUIRE(!valid.mweb_block.IsNull());
    const auto valid_mweb = valid.mweb_block.m_block;
    BOOST_REQUIRE(!valid_mweb->GetKernels().empty());

    CCoinsViewCache parent_view{&chainstate.CoinsTip()};
    parent_view.SetBestBlock(pindex->GetBlockHash());
    const DisconnectResult disconnected = chainstate.DisconnectBlock(valid, pindex, parent_view);
    BOOST_REQUIRE(disconnected == DISCONNECT_OK || disconnected == DISCONNECT_UNCLEAN);

    auto kernels = valid_mweb->GetKernels();
    auto serialized_kernel = kernels.front().Serialized();
    serialized_kernel.back() ^= 1;
    kernels.front() = Kernel::Deserialize(serialized_kernel);
    CBlock invalid_signature = valid;
    invalid_signature.mweb_block = MWEB::Block{mw::MutBlock(valid_mweb).SetKernels(kernels).Build()};
    BOOST_REQUIRE(invalid_signature.GetHash() == valid.GetHash());

    const FlatFilePos valid_pos{pindex->GetBlockPos()};
    const FlatFilePos invalid_pos{chainstate.m_blockman.WriteBlock(invalid_signature, pindex->nHeight)};
    BOOST_REQUIRE(!invalid_pos.IsNull());

    const auto rollforward = [&](const FlatFilePos& pos) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        pindex->nFile = pos.nFile;
        pindex->nDataPos = pos.nPos;
        CCoinsViewCache view{&parent_view};
        return (chainstate.*&RollforwardAccess::RollforwardBlock)(pindex, view);
    };

    {
        ASSERT_DEBUG_LOG("RollforwardBlock(): MWEB contextual check failed");
        ASSERT_DEBUG_LOG("(bad-blk-mweb");
        BOOST_CHECK(!rollforward(invalid_pos));
    }

    // The MWEB body is not committed by the block hash, so a copy without it
    // still matches the index and must be rejected rather than replayed as L1-only.
    CBlock stripped = valid;
    stripped.mweb_block = MWEB::Block{};
    BOOST_REQUIRE(stripped.GetHash() == valid.GetHash());
    const FlatFilePos stripped_pos{chainstate.m_blockman.WriteBlock(stripped, pindex->nHeight)};
    BOOST_REQUIRE(!stripped_pos.IsNull());
    {
        ASSERT_DEBUG_LOG("RollforwardBlock(): MWEB contextual check failed");
        ASSERT_DEBUG_LOG("(mweb-missing");
        BOOST_CHECK(!rollforward(stripped_pos));
    }
    BOOST_CHECK(rollforward(valid_pos));
}

// ConnectTip must connect against the current tip's MWEB header. After
// DisconnectTip rewinds the tip, an MWEB layer built at the end of the previous
// ConnectTip still holds the disconnected block's kernel offset, and the next
// honest block fails its kernel sums (BLOCK_SUMS) on the first attempt.
BOOST_AUTO_TEST_CASE(connecttip_after_disconnect_uses_current_mweb_header)
{
    class FailedBlockChecks final : public CValidationInterface
    {
    public:
        std::vector<std::string> failures;

    protected:
        void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
        {
            if (!state.IsValid()) failures.push_back(state.ToString());
        }
    };

    MineToMwebChain(*this, m_node, /*post_activation_blocks=*/1);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();

    // Branch A: a peg-in block and one block on top of it.
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/1);
    MineMwebEraBlock(m_node, CScript() << OP_TRUE);
    MineMwebEraBlock(m_node, CScript() << OP_TRUE);
    CBlockIndex* branch_a_tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
    CBlockIndex* branch_a = branch_a_tip->pprev;

    FailedBlockChecks failed_checks;
    m_node.validation_signals->RegisterValidationInterface(&failed_checks);

    // Branch B: one sibling of A that also moves the kernel offset (the
    // disconnected peg-in returns to the mempool and is mined again).
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, branch_a));
    MineMwebEraBlock(m_node, CScript() << OP_2);
    {
        LOCK(::cs_main);
        const CBlockIndex* branch_b = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(branch_b != branch_a && branch_b->pprev == branch_a->pprev);
        BOOST_REQUIRE(branch_b->mweb_header && branch_b->pprev->mweb_header);
        // A stale header is only detectable if B moved the kernel offset.
        BOOST_REQUIRE(branch_b->mweb_header->GetKernelOffset() != branch_b->pprev->mweb_header->GetKernelOffset());
    }

    // Reorg back to the longer branch A: DisconnectTip(B), then ConnectTip(A),
    // in one activation step.
    {
        LOCK(::cs_main);
        chainstate.ResetBlockFailureFlags(branch_a);
        chainman.RecalculateBestHeader();
    }
    BOOST_REQUIRE(chainstate.ActivateBestChain(state));

    m_node.validation_signals->UnregisterValidationInterface(&failed_checks);
    BOOST_CHECK_MESSAGE(failed_checks.failures.empty(),
                        "honest blocks failed to connect: " + util::Join(failed_checks.failures, "; "));

    LOCK(::cs_main);
    BOOST_CHECK(chainman.ActiveChain().Tip() == branch_a_tip);
}

BOOST_AUTO_TEST_CASE(disconnecttip_reorg_preserves_mweb_consistency)
{
    MineToMwebChain(*this, m_node, 6);

    CBlockIndex* pindex_tip{nullptr};
    CBlockUndo block_undo;
    int height_before{0};
    mw::Header::CPtr expected_mweb_header;

    {
        LOCK(::cs_main);
        auto& chainman = *Assert(m_node.chainman);
        auto& chainstate = chainman.ActiveChainstate();
        pindex_tip = FindTipWithMwundo(chainstate, chainman.ActiveChain());
        BOOST_REQUIRE(pindex_tip);
        BOOST_REQUIRE(pindex_tip->pprev);
        BOOST_REQUIRE(chainstate.m_blockman.ReadBlockUndo(block_undo, *pindex_tip));
        BOOST_REQUIRE(block_undo.mwundo != nullptr);
        BOOST_REQUIRE(block_undo.mwundo->GetPreviousHeader());
        height_before = chainman.ActiveHeight();
        expected_mweb_header = block_undo.mwundo->GetPreviousHeader();
    }

    {
        auto& chainman = *Assert(m_node.chainman);
        auto& chainstate = chainman.ActiveChainstate();
        LOCK2(::cs_main, chainstate.MempoolMutex());
        CBlockIndex* const disconnected_tip{chainman.ActiveChain().Tip()};
        BlockValidationState state;
        DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};
        BOOST_CHECK(chainstate.DisconnectTip(state, &disconnectpool));
        chainstate.setBlockIndexCandidates.erase(disconnected_tip);
        chainstate.setBlockIndexCandidates.insert(chainman.ActiveChain().Tip());
        BOOST_CHECK_EQUAL(chainman.ActiveHeight(), height_before - 1);

        const auto mweb_view = chainstate.CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(mweb_view);
        BOOST_REQUIRE(mweb_view->GetBestHeader());
        BOOST_CHECK(*mweb_view->GetBestHeader() == *expected_mweb_header);
        disconnectpool.clear();
    }
}

// Multi-block walker undo integrity: VerifyDB level 3, ReplayBlocks, and ActivateArbitraryChain
// disconnect multiple blocks through a SINGLE CCoinsViewCache. MWEB undo state must
// accumulate in the view's nested MWEB layer across blocks; a per-block re-wrap of
// the layer (RefreshMWEBCache) discards the earlier blocks' undo, leaving coins from
// the later block still visible after all blocks are disconnected.
BOOST_AUTO_TEST_CASE(multiblock_disconnect_single_view_preserves_undo_layers)
{
    MineToMwebChain(*this, m_node, 2);

    // Mine two more MWEB blocks, each with its own pegin so both have mwundo
    // with non-empty added-coin sets.
    const CScript coinbase_script{CScript() << OP_TRUE};
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/1);
    MineMwebEraBlock(m_node, coinbase_script);
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/2);
    MineMwebEraBlock(m_node, coinbase_script);

    LOCK(::cs_main);
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();

    CBlockIndex* const pindex_n = chainman.ActiveChain().Tip();
    BOOST_REQUIRE(pindex_n);
    CBlockIndex* const pindex_n1 = pindex_n->pprev;
    BOOST_REQUIRE(pindex_n1);
    BOOST_REQUIRE(pindex_n1->pprev);

    CBlock block_n, block_n1;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block_n, *pindex_n));
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block_n1, *pindex_n1));

    CBlockUndo undo_n, undo_n1;
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlockUndo(undo_n, *pindex_n));
    BOOST_REQUIRE(chainstate.m_blockman.ReadBlockUndo(undo_n1, *pindex_n1));
    BOOST_REQUIRE(undo_n.mwundo != nullptr);
    BOOST_REQUIRE(undo_n1.mwundo != nullptr);
    BOOST_REQUIRE(!undo_n.mwundo->GetCoinsAdded().empty());
    BOOST_REQUIRE(!undo_n1.mwundo->GetCoinsAdded().empty());
    BOOST_REQUIRE(undo_n1.mwundo->GetPreviousHeader());

    // Single view for the whole walk, exactly like VerifyDB level 3.
    CCoinsViewCache view{&chainstate.CoinsTip()};
    BOOST_REQUIRE(view.GetBestBlock() == pindex_n->GetBlockHash());

    BOOST_CHECK(chainstate.DisconnectBlock(block_n, pindex_n, view) == DISCONNECT_OK);
    BOOST_CHECK(chainstate.DisconnectBlock(block_n1, pindex_n1, view) == DISCONNECT_OK);

    const auto mweb_view = view.GetMWEBCacheView();
    BOOST_REQUIRE(mweb_view);
    BOOST_REQUIRE(mweb_view->GetBestHeader());
    BOOST_CHECK(*mweb_view->GetBestHeader() == *undo_n1.mwundo->GetPreviousHeader());

    // Every coin created by either disconnected block must be gone from the view.
    // If block N's undo layer was wiped before undoing N-1, N's coins remain visible.
    for (const mw::Hash& added : undo_n.mwundo->GetCoinsAdded()) {
        BOOST_CHECK_MESSAGE(mweb_view->GetUTXO(added) == nullptr,
                            "coin added in tip block still present after multi-block disconnect");
    }
    for (const mw::Hash& added : undo_n1.mwundo->GetCoinsAdded()) {
        BOOST_CHECK_MESSAGE(mweb_view->GetUTXO(added) == nullptr,
                            "coin added in tip-1 block still present after multi-block disconnect");
    }
}

void CopyL1CoinsForRollbackTest(Chainstate& chainstate, CCoinsViewDB& temp_db)
{
    CCoinsViewCache temp_cache(&temp_db);
    std::unique_ptr<CCoinsViewCursor> cursor;
    const CBlockIndex* tip{nullptr};
    {
        LOCK(::cs_main);
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
        tip = chainstate.m_chain.Tip();
        cursor = chainstate.CoinsDB().Cursor();
    }
    BOOST_REQUIRE(tip);
    temp_cache.SetBestBlock(tip->GetBlockHash());
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (cursor->GetKey(key) && cursor->GetValue(coin)) {
            temp_cache.AddCoin(key, std::move(coin), false);
        }
        cursor->Next();
    }
    temp_cache.Flush();
}

BOOST_AUTO_TEST_CASE(clone_mweb_disconnect_leaves_live_tip)
{
    MineToMwebChain(*this, m_node, 4);

    const fs::path temp_path = m_path_root / "temp_mweb_rollback_disconnect";
    fs::create_directories(temp_path);

    uint256 live_tip_hash;
    mw::Header live_header_copy;
    {
        LOCK(::cs_main);
        auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
        live_tip_hash = chainstate.m_chain.Tip()->GetBlockHash();
        const auto live_view = chainstate.CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(live_view);
        BOOST_REQUIRE(live_view->GetBestHeader());
        live_header_copy = *live_view->GetBestHeader();
    }

    {
        LOCK(::cs_main);
        auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
        DBParams db_params{
            .path = temp_path,
            .cache_bytes = 0,
            .memory_only = true,
            .wipe_data = true,
            .obfuscate = false,
            .options = DBOptions{}
        };
        CCoinsViewDB temp_db{std::move(db_params), CoinsViewOptions{}};
        CopyL1CoinsForRollbackTest(chainstate, temp_db);
        BOOST_REQUIRE(node::CloneMWEBChainstateForRollback(
            chainstate.CoinsDB(),
            FilePath{chainstate.StoragePath()},
            temp_db,
            FilePath{temp_path},
            /*interruption_point=*/nullptr));
        BOOST_REQUIRE(temp_db.GetMWEBView());
        BOOST_REQUIRE(temp_db.GetMWEBView()->GetBestHeader());

        CCoinsViewCache rollback_cache(&temp_db);
        BOOST_REQUIRE(rollback_cache.GetMWEBCacheView());
        rollback_cache.SetBestBlock(live_tip_hash);
        CBlockIndex* pindex_tip = chainstate.m_chain.Tip();
        CBlock block;
        BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block, *pindex_tip));
        const DisconnectResult dres = chainstate.DisconnectBlock(block, pindex_tip, rollback_cache);
        BOOST_CHECK_EQUAL(static_cast<int>(dres), static_cast<int>(DISCONNECT_OK));
        BOOST_CHECK(rollback_cache.GetBestBlock() == pindex_tip->pprev->GetBlockHash());
        const auto rolled = rollback_cache.GetMWEBCacheView();
        BOOST_REQUIRE(rolled);
        BOOST_REQUIRE(rolled->GetBestHeader());
        BOOST_CHECK(rolled->GetBestHeader()->GetHash() != live_header_copy.GetHash());
    }

    {
        LOCK(::cs_main);
        auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() == live_tip_hash);
        const auto live_view = chainstate.CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(live_view);
        BOOST_REQUIRE(live_view->GetBestHeader());
        BOOST_CHECK(*live_view->GetBestHeader() == live_header_copy);
    }
}

BOOST_AUTO_TEST_CASE(clone_mweb_rollback_snapshot_hash_matches_unadvanced)
{
    MineToMwebChain(*this, m_node, 4);

    uint256 hash_at_h;
    int height_h{0};
    {
        LOCK(::cs_main);
        auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
        height_h = chainstate.m_chain.Height();
        const auto view = chainstate.CoinsTip().GetMWEBCacheView();
        BOOST_REQUIRE(view);
        BOOST_REQUIRE(view->GetBestHeader());
        auto hashed = node::ComputeMWEBSnapshotHashFromChainstate(
            chainstate.CoinsDB(),
            FilePath{chainstate.StoragePath()},
            *view->GetBestHeader(),
            view.get(),
            /*interruption_point=*/nullptr);
        BOOST_REQUIRE(hashed.has_value());
        hash_at_h = *hashed;
    }

    const CScript coinbase_script{CScript() << OP_TRUE};
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/1);
    MineMwebEraBlock(m_node, coinbase_script);
    SubmitPeginToMempool(*this, m_node, COIN, /*coinbase_idx=*/2);
    MineMwebEraBlock(m_node, coinbase_script);

    const fs::path temp_path = m_path_root / "temp_mweb_rollback_hash";
    fs::create_directories(temp_path);
    uint256 hash_rolled;
    {
        LOCK(::cs_main);
        auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
        DBParams db_params{
            .path = temp_path,
            .cache_bytes = 0,
            .memory_only = true,
            .wipe_data = true,
            .obfuscate = false,
            .options = DBOptions{}
        };
        CCoinsViewDB temp_db{std::move(db_params), CoinsViewOptions{}};
        CopyL1CoinsForRollbackTest(chainstate, temp_db);
        BOOST_REQUIRE(node::CloneMWEBChainstateForRollback(
            chainstate.CoinsDB(),
            FilePath{chainstate.StoragePath()},
            temp_db,
            FilePath{temp_path},
            /*interruption_point=*/nullptr));

        CCoinsViewCache rollback_cache(&temp_db);
        const CBlockIndex* block_index = chainstate.m_chain.Tip();
        rollback_cache.SetBestBlock(block_index->GetBlockHash());
        while (block_index->nHeight > height_h) {
            CBlock block;
            BOOST_REQUIRE(chainstate.m_blockman.ReadBlock(block, *block_index));
            BOOST_REQUIRE(chainstate.DisconnectBlock(block, block_index, rollback_cache) == DISCONNECT_OK);
            block_index = block_index->pprev;
        }
        BOOST_REQUIRE(rollback_cache.GetBestBlock() == block_index->GetBlockHash());
        rollback_cache.Flush();
        const auto rolled = rollback_cache.GetMWEBCacheView();
        BOOST_REQUIRE(rolled);
        BOOST_REQUIRE(rolled->GetBestHeader());
        auto hashed = node::ComputeMWEBSnapshotHashFromChainstate(
            temp_db,
            FilePath{temp_path},
            *rolled->GetBestHeader(),
            rolled.get(),
            /*interruption_point=*/nullptr);
        BOOST_REQUIRE(hashed.has_value());
        hash_rolled = *hashed;
        BOOST_CHECK(chainstate.m_chain.Height() > height_h);
    }
    BOOST_CHECK(hash_rolled == hash_at_h);
}

BOOST_AUTO_TEST_CASE(mweb_kernel_lock_height_mempool_finality)
{
    MineToMwebChain(*this, m_node);

    const CScript coinbase_script{CScript() << OP_TRUE};
    int tip_height{WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveHeight())};
    const int32_t lock_height = tip_height + 5; // requires tip+1 >= lock_height => tip >= lock_height - 1

    CMutableTransaction mtx = MakeLockedPeginMtx(*this, lock_height, /*coinbase_idx=*/1);
    const CTransaction tx{mtx};

    BOOST_CHECK_EQUAL(tx.mweb_tx.GetLockHeight(), lock_height);
    BOOST_CHECK(!IsFinalTx(tx, tip_height + 1, /*nBlockTime=*/0));
    BOOST_CHECK(IsFinalTx(tx, lock_height, /*nBlockTime=*/0));

    {
        LOCK2(::cs_main, Assert(m_node.mempool)->cs);
        const MempoolAcceptResult rejected =
            Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_CHECK(rejected.m_result_type != MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "non-final");
    }

    // Mine until the next block height equals the lock height (tip+1 == lock_height).
    while (WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveHeight()) + 1 < lock_height) {
        MineMwebEraBlock(m_node, coinbase_script);
    }
    tip_height = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveHeight());
    BOOST_REQUIRE_EQUAL(tip_height + 1, lock_height);
    BOOST_CHECK(IsFinalTx(tx, tip_height + 1, /*nBlockTime=*/0));

    {
        LOCK2(::cs_main, Assert(m_node.mempool)->cs);
        const MempoolAcceptResult accepted =
            Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_REQUIRE_MESSAGE(accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              accepted.m_state.ToString());
    }

    BOOST_CHECK_NO_THROW(MineMwebEraBlock(m_node, coinbase_script));
    tip_height = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveHeight());
    BOOST_CHECK_EQUAL(tip_height, lock_height);
    BOOST_CHECK(Assert(m_node.mempool)->size() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
