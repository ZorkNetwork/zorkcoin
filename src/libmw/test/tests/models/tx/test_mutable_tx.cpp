// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/weight.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/mutable_tx.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <streams.h>

#include <test_framework/models/tx.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

BOOST_FIXTURE_TEST_SUITE(TestMutableTx, MWEBTestingSetup)

namespace {

template <typename T>
std::vector<uint8_t> Ser(const T& obj)
{
    DataStream stream;
    stream << obj;
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

template <typename T>
std::vector<uint8_t> SerTx(const T& tx, const TransactionSerParams& params)
{
    DataStream stream;
    stream << params(tx);
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

std::vector<mw::Transaction::CPtr> SampleTransactions()
{
    return {
        test::TxBuilder().AddInput(5'000'000).AddOutput(4'000'000).AddOutput(990'000).AddPlainKernel(10'000, true).Build().GetTransaction(),
        test::TxBuilder().AddInput(5'000'000).AddOutput(4'990'000).AddPlainKernel(10'000, false, 100).Build().GetTransaction(),
        test::Tx::CreatePegIn(1'000'000, 1'000).GetTransaction(),
        test::TxBuilder().AddInput(5'000'000).AddOutput(1'000'000).AddPegoutKernel(3'990'000, 10'000, true).Build().GetTransaction(),
    };
}

} // namespace

BOOST_AUTO_TEST_CASE(FromAndFinalizedRoundTrip)
{
    for (const mw::Transaction::CPtr& tx : SampleTransactions()) {
        const mw::MutableTx mutable_tx = mw::MutableTx::From(*tx);
        BOOST_CHECK(!mutable_tx.IsNull());
        BOOST_CHECK(mutable_tx.IsFinal());

        const std::optional<mw::Transaction::CPtr> finalized = mutable_tx.Finalized();
        BOOST_REQUIRE(finalized && *finalized);
        BOOST_CHECK((*finalized)->GetHash() == tx->GetHash());
        BOOST_CHECK(Ser(**finalized) == Ser(*tx));
        BOOST_CHECK(Ser(mutable_tx) == Ser(MWEB::Tx(tx)));
        BOOST_CHECK(mw::MutableTx::From(**finalized) == mutable_tx);

        for (size_t i = 0; i < tx->GetKernels().size(); ++i) {
            BOOST_CHECK(*mutable_tx.kernels[i].GetKernelID() == tx->GetKernels()[i].GetKernelID());
            BOOST_CHECK_EQUAL(mutable_tx.kernels[i].CalcFeatureByte(), tx->GetKernels()[i].GetFeatures());
        }
    }
}

BOOST_AUTO_TEST_CASE(TransactionSerializationMatchesImmutable)
{
    for (const mw::Transaction::CPtr& tx : SampleTransactions()) {
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
        mtx.vin.back().scriptWitness.stack.push_back({0x01});
        mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
        mtx.mweb_tx = mw::MutableTx::From(*tx);
        const CTransaction ctx(mtx);
        BOOST_REQUIRE(ctx.HasMWEBTx());

        for (const TransactionSerParams& params : {TX_WITH_WITNESS, TX_NO_WITNESS, TX_NO_MWEB, TX_NO_WITNESS_NO_MWEB}) {
            const std::vector<uint8_t> bytes = SerTx(mtx, params);
            BOOST_CHECK(bytes == SerTx(ctx, params));

            // The extended format is only readable when witnesses are allowed.
            if (params.allow_mweb && !params.allow_witness) continue;
            CMutableTransaction decoded;
            SpanReader{bytes} >> params(decoded);
            BOOST_CHECK(SerTx(decoded, params) == bytes);
            BOOST_CHECK_EQUAL(decoded.HasMWEBTx(), params.allow_mweb);
        }
        BOOST_CHECK(mtx.GetHash() == ctx.GetHash());
        BOOST_CHECK(CMutableTransaction(ctx).mweb_tx == mtx.mweb_tx);
    }
}

BOOST_AUTO_TEST_CASE(MWEBOnlyHashMatchesImmutable)
{
    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*SampleTransactions().front());
    BOOST_REQUIRE(mtx.IsMWEBOnly());
    const CTransaction ctx(mtx);
    BOOST_CHECK(mtx.GetHash() == ctx.GetHash());
    BOOST_CHECK(mtx.GetHash().ToUint256() == uint256(ctx.mweb_tx.m_transaction->GetKernels().front().GetHash().vec()));
}

BOOST_AUTO_TEST_CASE(NonFinalHasNoPayload)
{
    mw::MutableTx mutable_tx;
    mw::MutableOutput output;
    output.amount = 1'000;
    output.address = StealthAddress::Random();
    mutable_tx.outputs.push_back(output);
    mutable_tx.SetPeginAmount(1'000);

    BOOST_CHECK(!mutable_tx.IsNull());
    BOOST_CHECK(!mutable_tx.IsFinal());
    BOOST_CHECK(!mutable_tx.Finalized());
    BOOST_CHECK(MWEB::Tx(mutable_tx).IsNull());
    BOOST_CHECK(Ser(mutable_tx) == std::vector<uint8_t>{0x00});

    mw::MutableTx decoded = mutable_tx;
    SpanReader{std::vector<uint8_t>{0x00}} >> decoded;
    BOOST_CHECK(decoded.IsNull());

    // A kernel-less but otherwise empty MutableTx is not final.
    mw::MutableTx offset_only;
    offset_only.kernel_offset = BlindingFactor::Random();
    BOOST_CHECK(!offset_only.IsNull());
    BOOST_CHECK(!offset_only.IsFinal());

    BOOST_CHECK(mw::MutableTx{}.IsFinal());
    BOOST_CHECK(!mw::MutableTx{}.Finalized());
}

BOOST_AUTO_TEST_CASE(DeserializationResetsMWEBState)
{
    CMutableTransaction plain;
    plain.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    plain.vout.emplace_back(1'000, CScript() << OP_TRUE);
    const std::vector<uint8_t> plain_bytes = SerTx(plain, TX_WITH_WITNESS);

    CMutableTransaction reused;
    reused.mweb_tx = mw::MutableTx::From(*SampleTransactions().front());
    reused.m_hogEx = true;
    SpanReader{plain_bytes} >> TX_WITH_WITNESS(reused);
    BOOST_CHECK(reused.mweb_tx.IsNull());
    BOOST_CHECK(!reused.m_hogEx);
    BOOST_CHECK(SerTx(reused, TX_WITH_WITNESS) == plain_bytes);
}

BOOST_AUTO_TEST_CASE(KernelAccessors)
{
    mw::MutableTx tx;
    BOOST_CHECK(!tx.GetPeginAmount());

    tx.SetFee(1'000);
    BOOST_REQUIRE_EQUAL(tx.kernels.size(), 1U);
    tx.SetPeginAmount(50'000);
    tx.AddPegout(CScript() << OP_TRUE, 10'000, true);
    tx.AddPegout(mw::PegOutRecipient{CScript() << OP_2, 20'000, false});
    BOOST_REQUIRE_EQUAL(tx.kernels.size(), 1U);

    BOOST_CHECK_EQUAL(*tx.GetPeginAmount(), 50'000);
    BOOST_CHECK_EQUAL(tx.GetTotalPegoutAmount(), 30'000);
    BOOST_REQUIRE_EQUAL(tx.GetPegouts().size(), 2U);
    BOOST_CHECK(tx.GetPegouts()[0].fSubtractFeeFromAmount);
    BOOST_REQUIRE_EQUAL(tx.GetPegOutCoins().size(), 2U);
    BOOST_CHECK(tx.GetPegOutCoins()[1] == PegOutCoin(20'000, CScript() << OP_2));

    const std::vector<PegInCoin> pegins = tx.GetPegIns();
    BOOST_REQUIRE_EQUAL(pegins.size(), 1U);
    BOOST_CHECK_EQUAL(pegins[0].GetAmount(), 50'000);
    BOOST_CHECK(pegins[0].GetKernelID().IsZero());

    const mw::MutableKernel& kernel = tx.kernels.front();
    BOOST_CHECK_EQUAL(kernel.CalcFeatureByte(), Kernel::FEE_FEATURE_BIT | Kernel::PEGIN_FEATURE_BIT | Kernel::PEGOUT_FEATURE_BIT);
    BOOST_CHECK(!kernel.IsFinal());
    BOOST_CHECK(!kernel.GetKernelID());

    mw::MutableTx copy = tx;
    BOOST_CHECK(copy == tx);
    copy.kernels.front().pegouts.front().fSubtractFeeFromAmount = false;
    BOOST_CHECK(!(copy == tx));

    tx.SetNull();
    BOOST_CHECK(tx.IsNull());
}

BOOST_AUTO_TEST_CASE(WeightEstimate)
{
    BOOST_CHECK_EQUAL(mw::MutableTx{}.GetMWEBWeight(), 0U);

    // Stealth kernels are priced exactly.
    const mw::Transaction::CPtr tx = SampleTransactions().front();
    BOOST_CHECK_EQUAL(mw::MutableTx::From(*tx).GetMWEBWeight(), tx->CalcWeight());

    // Non-stealth kernels are priced as stealth kernels.
    const mw::Transaction::CPtr plain = SampleTransactions()[1];
    BOOST_CHECK_GT(mw::MutableTx::From(*plain).GetMWEBWeight(), plain->CalcWeight());

    // A transaction without kernels is priced as having one stealth kernel.
    mw::MutableTx unsigned_tx;
    unsigned_tx.outputs.push_back(mw::MutableOutput{});
    BOOST_CHECK_EQUAL(unsigned_tx.GetMWEBWeight(), Weight::CalcOutputWeight(true) + Weight::CalcKernelWeight(true, std::vector<PegOutCoin>{}));
}

BOOST_AUTO_TEST_CASE(InputFromCoinAndOutput)
{
    const SecretKey scan = SecretKey::Random();
    const SecretKey spend = SecretKey::Random();
    const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(spend), scan, 3);
    BlindingFactor raw_blind;
    const Output output = Output::Create(&raw_blind, SecretKey::Random(), address, 12'345);
    const SecretKey shared_secret = mw::RecoverSharedSecret(output.GetKeyExchangePubKey(), scan);

    mw::Coin coin;
    coin.output_id = output.GetOutputID();
    coin.amount = 12'345;
    coin.blind = raw_blind;
    coin.shared_secret = shared_secret;
    coin.address = address;

    const mw::MutableInput from_coin = mw::MutableInput::FromCoin(coin);
    BOOST_CHECK(from_coin.output_id == output.GetOutputID());
    BOOST_CHECK(*from_coin.commitment == output.GetCommitment());
    BOOST_CHECK(*from_coin.output_pubkey == output.GetReceiverPubKey());
    BOOST_CHECK(*from_coin.raw_blind == raw_blind);
    BOOST_CHECK_EQUAL(*from_coin.amount, 12'345);
    BOOST_CHECK(!from_coin.spend_key);

    // Coins loaded from disk keep only the shared secret; the blind is re-derived from it.
    mw::Coin sanitized = coin;
    sanitized.blind = std::nullopt;
    const mw::MutableInput from_sanitized = mw::MutableInput::FromCoin(sanitized);
    BOOST_CHECK(*from_sanitized.raw_blind == raw_blind);
    BOOST_CHECK(*from_sanitized.commitment == output.GetCommitment());

    const mw::MutableInput from_output = mw::MutableInput::FromOutput(output);
    BOOST_CHECK(*from_output.commitment == output.GetCommitment());
    BOOST_CHECK(*from_output.output_pubkey == output.GetReceiverPubKey());
    BOOST_CHECK(*from_output.key_exchange_pubkey == output.GetKeyExchangePubKey());
    BOOST_CHECK(!from_output.amount);

    mw::Coin bare;
    bare.output_id = output.GetOutputID();
    bare.amount = 1;
    const mw::MutableInput from_bare = mw::MutableInput::FromCoin(bare);
    BOOST_CHECK(!from_bare.commitment && !from_bare.output_pubkey && !from_bare.raw_blind);
}

BOOST_AUTO_TEST_CASE(OutputEqualityComparesProofBytes)
{
    const Output output = test::TxBuilder().AddInput(1'000).AddOutput(990).AddPlainKernel(10).Build().GetTransaction()->GetOutputs().front();
    mw::MutableOutput a;
    a.Update(output);
    mw::MutableOutput b = a;
    b.proof = std::make_shared<const RangeProof>(*output.GetRangeProof());
    BOOST_CHECK(a.proof != b.proof);
    BOOST_CHECK(a == b);
    BOOST_CHECK(*a.CalcOutputID() == output.GetOutputID());

    b.proof = RangeProof::CPtr{};
    BOOST_CHECK(!(a == b));
    BOOST_CHECK(!b.IsFinal());
}

BOOST_AUTO_TEST_SUITE_END()
