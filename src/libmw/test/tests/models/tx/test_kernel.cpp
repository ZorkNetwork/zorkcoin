// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/schnorr.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/tx/tx_body.h>

#include <chainparams.h>
#include <mweb/mweb_policy.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test_framework/test_mweb.h>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(TestKernel, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(FeatureActivationHeights_Test)
{
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(*m_node.args, chain);
        BOOST_CHECK_EQUAL(params->GetConsensus().mweb_pegout_feature_activation_height, 0);
        BOOST_CHECK_EQUAL(params->GetConsensus().mweb_extradata_feature_activation_height, 0);
    }
}

BOOST_AUTO_TEST_CASE(CreateWithExtraData_Test)
{
    const std::vector<uint8_t> extra_data{0xde, 0xad, 0xbe, 0xef};
    const BlindingFactor excess_blind = BlindingFactor::Random();
    const Kernel kernel = Kernel::Create(excess_blind, SecretKey::Random(), 1000, std::nullopt, std::vector<PegOutCoin>{}, std::nullopt, extra_data);

    BOOST_CHECK(kernel.GetExtraData() == extra_data);
    BOOST_CHECK(kernel.HasStealthExcess());
    BOOST_CHECK_EQUAL(kernel.GetFeatures(), Kernel::FEE_FEATURE_BIT | Kernel::STEALTH_EXCESS_FEATURE_BIT | Kernel::EXTRA_DATA_FEATURE_BIT);
    BOOST_CHECK(!kernel.IsStandard());
    BOOST_CHECK(kernel.HasCanonicalExtraDataFeature());
    BOOST_CHECK(Schnorr::BatchVerify({kernel.BuildSignedMsg()}));

    const Kernel roundtrip = Kernel::Deserialize(kernel.Serialized());
    BOOST_CHECK(roundtrip == kernel);
    BOOST_CHECK(roundtrip.GetExtraData() == extra_data);

    const Kernel plain = Kernel::Create(excess_blind, std::nullopt, 1000, std::nullopt, std::vector<PegOutCoin>{}, std::nullopt, std::vector<uint8_t>{});
    BOOST_CHECK(plain == Kernel::Create(excess_blind, std::nullopt, 1000, std::nullopt, std::vector<PegOutCoin>{}, std::nullopt));
    BOOST_CHECK_EQUAL(plain.GetFeatures(), Kernel::FEE_FEATURE_BIT);
}

BOOST_AUTO_TEST_CASE(PlainKernel_Test)
{
    CAmount fee = 1000;
    BlindingFactor excess_blind = BlindingFactor::Random();
    Kernel kernel = Kernel::Create(excess_blind, std::nullopt, fee, std::nullopt, std::vector<PegOutCoin>{}, std::nullopt);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = kernel.Serialized();

        Kernel kernel2 = Kernel::Deserialize(serialized);
        BOOST_REQUIRE(kernel == kernel2);
    }

    //
    // Signature Message
    //
    {
        Hasher hasher;
        hasher << uint8_t(1);
        hasher << Commitment::Blinded(excess_blind, 0);
        ::WriteVarInt<Hasher, VarIntMode::NONNEGATIVE_SIGNED, CAmount>(hasher, fee);
        BOOST_REQUIRE(kernel.BuildSignedMsg().GetMsgHash() == hasher.hash());
    }

    //
    // Getters
    //
    {
        BOOST_REQUIRE(!kernel.HasPegIn());
        BOOST_REQUIRE(!kernel.HasPegOut());
        BOOST_REQUIRE(!kernel.HasStealthExcess());
        BOOST_REQUIRE(kernel.GetPegIn() == 0);
        BOOST_REQUIRE(kernel.GetPegOuts().empty());
        BOOST_REQUIRE(kernel.GetLockHeight() == 0);
        BOOST_REQUIRE(kernel.GetFee() == fee);
        BOOST_REQUIRE(kernel.GetCommitment() == Commitment::Blinded(excess_blind, 0));
        BOOST_REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.BuildSignedMsg().GetMsgHash()));
    }
}

BOOST_AUTO_TEST_CASE(NonStandardKernel_Test)
{
    CAmount fee = 1000;
    CAmount pegin = 10000;
    std::vector<uint8_t> rand1 = RandomBytes<30>();
    PegOutCoin pegout(2000, CScript(rand1.data(), rand1.data() + rand1.size()));
    int32_t lock_height = 123456;
    std::vector<uint8_t> rand2 = RandomBytes<30>();
    Kernel standard_kernel(
        Kernel::FEE_FEATURE_BIT | Kernel::PEGIN_FEATURE_BIT | Kernel::PEGOUT_FEATURE_BIT | Kernel::HEIGHT_LOCK_FEATURE_BIT | Kernel::STEALTH_EXCESS_FEATURE_BIT,
        fee,
        pegin,
        std::vector<PegOutCoin>{PegOutCoin(2000, CScript(rand2.data(), rand2.data() + rand2.size()))},
        lock_height,
        PublicKey::Random(),
        std::vector<uint8_t>{},
        Commitment::Random(),
        Signature(RandomBigInt<Signature::SIZE>())
    );
    std::vector<uint8_t> rand3 = RandomBytes<30>();
    Kernel nonstandard_kernel1(
        Kernel::ALL_FEATURE_BITS,
        fee,
        pegin,
        std::vector<PegOutCoin>{PegOutCoin(2000, CScript(rand3.data(), rand3.data() + rand3.size()))},
        lock_height,
        PublicKey::Random(),
        RandomBytes<20>(),
        standard_kernel.GetCommitment(),
        standard_kernel.GetSignature()
    );

    Kernel nonstandard_kernel2(
        0x20,
        std::nullopt,
        std::nullopt,
        std::vector<PegOutCoin>{},
        std::nullopt,
        PublicKey::Random(),
        std::vector<uint8_t>{},
        standard_kernel.GetCommitment(),
        standard_kernel.GetSignature()
    );

    // A peg-out bit with no peg-outs, read from the wire as a peer would send it.
    DataStream serialized;
    serialized << uint8_t(Kernel::PEGOUT_FEATURE_BIT);
    serialized << std::vector<PegOutCoin>{};
    serialized << standard_kernel.GetCommitment();
    serialized << standard_kernel.GetSignature();
    Kernel nonstandard_kernel3;
    serialized >> nonstandard_kernel3;
    BOOST_REQUIRE(serialized.empty());

    BOOST_REQUIRE(standard_kernel.IsStandard());
    BOOST_REQUIRE(!nonstandard_kernel1.IsStandard());
    BOOST_REQUIRE(!nonstandard_kernel2.IsStandard());
    BOOST_REQUIRE(!nonstandard_kernel3.IsStandard());
    BOOST_REQUIRE(standard_kernel.HasCanonicalPegOutFeature());
    BOOST_REQUIRE(standard_kernel.HasCanonicalExtraDataFeature());
    BOOST_REQUIRE(nonstandard_kernel1.HasCanonicalExtraDataFeature());
    BOOST_REQUIRE(!nonstandard_kernel2.HasCanonicalExtraDataFeature());
    BOOST_REQUIRE(!nonstandard_kernel3.HasCanonicalPegOutFeature());

    for (const Kernel& nonstandard_kernel : {nonstandard_kernel2, nonstandard_kernel3}) {
        const mw::Transaction::CPtr nonstandard_tx = mw::Transaction::Create(
            BlindingFactor::Random(), BlindingFactor::Random(), {}, {}, {nonstandard_kernel});
        CMutableTransaction transaction;
        transaction.mweb_tx = mw::MutableTx::From(*nonstandard_tx);
        const CTransaction tx{std::move(transaction)};
        std::string reason;
        BOOST_REQUIRE(!MWEB::Policy::IsStandardTx(tx, reason));
        BOOST_REQUIRE_EQUAL(reason, "non-standard-mweb-tx");

        // The kernel keeps the feature byte its signature covers.
        BOOST_REQUIRE(!tx.mweb_tx.IsNull());
        BOOST_REQUIRE(tx.mweb_tx.m_transaction->GetKernels().front() == nonstandard_kernel);
        BOOST_REQUIRE(tx.mweb_tx.m_transaction->Serialized() == nonstandard_tx->Serialized());
    }
}

static Kernel SignedFeatureOnlyKernel(const uint8_t features)
{
    const BlindingFactor blind = BlindingFactor::Random();
    const Commitment excess = Commitment::Blinded(blind, 0);
    const mw::Hash message = Kernel::GetSignatureMessage(
        features, excess, std::nullopt, std::nullopt, std::nullopt, {}, std::nullopt, {});
    return Kernel(features, std::nullopt, std::nullopt, {}, std::nullopt, std::nullopt, {}, excess,
                  Schnorr::Sign(blind.data(), message));
}

BOOST_AUTO_TEST_CASE(EmptyPegOutFeature_Test)
{
    // Context-free validation accepts the empty peg-out bit; it is refused only by the
    // block-level feature rule (bad-mweb-empty-pegout).
    const Kernel kernel = SignedFeatureOnlyKernel(Kernel::PEGOUT_FEATURE_BIT);
    BOOST_REQUIRE(!kernel.HasCanonicalPegOutFeature());
    BOOST_REQUIRE_NO_THROW(TxBody({}, {}, {kernel}).Validate());
}

BOOST_AUTO_TEST_CASE(EmptyExtraDataFeature_Test)
{
    const Kernel kernel = SignedFeatureOnlyKernel(Kernel::EXTRA_DATA_FEATURE_BIT);
    BOOST_REQUIRE(!kernel.HasCanonicalExtraDataFeature());
    BOOST_REQUIRE_NO_THROW(TxBody({}, {}, {kernel}).Validate());
}

BOOST_AUTO_TEST_CASE(PegOutAmountOutOfRange_Test)
{
    std::vector<uint8_t> script_bytes = RandomBytes<30>();
    CScript script(script_bytes.data(), script_bytes.data() + script_bytes.size());

    Kernel kernel = Kernel::Create(
        BlindingFactor::Random(),
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::vector<PegOutCoin>{ PegOutCoin(MAX_MONEY, script), PegOutCoin(1, script) },
        std::nullopt
    );

    BOOST_REQUIRE(!kernel.GetPegOutAmount().has_value());
}

BOOST_AUTO_TEST_CASE(SupplyChangeOutOfRange_Test)
{
    std::vector<uint8_t> script_bytes = RandomBytes<30>();
    CScript script(script_bytes.data(), script_bytes.data() + script_bytes.size());

    Kernel kernel = Kernel::Create(
        BlindingFactor::Random(),
        std::nullopt,
        std::numeric_limits<CAmount>::max(),
        std::nullopt,
        std::vector<PegOutCoin>{ PegOutCoin(1, script) },
        std::nullopt
    );

    BOOST_REQUIRE(!kernel.GetSupplyChange().has_value());
}

BOOST_AUTO_TEST_SUITE_END()
