// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/hasher.h>
#include <mw/crypto/schnorr.h>
#include <mw/crypto/secret_keys.h>
#include <mw/models/tx/input.h>
#include <mw/models/crypto/secret_key.h>

#include <test_framework/test_mweb.h>
#include <streams.h>

#include <array>

namespace {
struct InputTestCase {
    uint8_t features;
    std::vector<uint8_t> extra_data;
};

mw::Hash BuildExpectedMessage(const uint8_t features, const mw::Hash& output_id, const std::vector<uint8_t>& extra_data)
{
    Hasher msg_hasher;
    msg_hasher << features << output_id;
    if ((features & Input::EXTRA_DATA_FEATURE_BIT) > 0) {
        msg_hasher << extra_data;
    }
    return msg_hasher.hash();
}

SecretKey BuildExpectedSignatureKey(const uint8_t features, const SecretKey& input_key, const SecretKey& output_key)
{
    if ((features & Input::STEALTH_KEY_FEATURE_BIT) == 0) {
        return output_key;
    }
    const SecretKey key_hash(Hasher().Append(PublicKey::From(input_key)).Append(PublicKey::From(output_key)).hash());
    return SecretKeys::From(output_key).Mul(key_hash).Add(input_key).Total();
}

PublicKey BuildExpectedPublicKey(const uint8_t features, const SecretKey& input_key, const SecretKey& output_key)
{
    const PublicKey input_pubkey = PublicKey::From(input_key);
    PublicKey output_pubkey = PublicKey::From(output_key);
    if ((features & Input::STEALTH_KEY_FEATURE_BIT) == 0) {
        return output_pubkey;
    }
    const SecretKey key_hash(Hasher().Append(input_pubkey).Append(output_pubkey).hash());
    return output_pubkey.Mul(key_hash).Add(input_pubkey);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(TestInput, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(InputFeatureBits)
{
    const std::array<InputTestCase, 4> test_cases{{
        {0, {}},
        {Input::STEALTH_KEY_FEATURE_BIT, {}},
        {Input::EXTRA_DATA_FEATURE_BIT, {0x00, 0x2A, 0x80, 0xFF}},
        {Input::STEALTH_KEY_FEATURE_BIT | Input::EXTRA_DATA_FEATURE_BIT, {0x01, 0x03, 0x05, 0x07}},
    }};

    for (const InputTestCase& test_case : test_cases) {
        BOOST_TEST_CONTEXT("features=" << static_cast<uint32_t>(test_case.features)) {
            const mw::Hash output_id = SecretKey::Random().GetBigInt();
            const Commitment commit = Commitment::Random();
            const SecretKey input_key = SecretKey::Random();
            const SecretKey output_key = SecretKey::Random();
            const PublicKey input_pubkey = PublicKey::From(input_key);
            const PublicKey output_pubkey = PublicKey::From(output_key);
            const mw::Hash expected_message = BuildExpectedMessage(test_case.features, output_id, test_case.extra_data);
            const PublicKey expected_public_key = BuildExpectedPublicKey(test_case.features, input_key, output_key);
            const SecretKey expected_signature_key = BuildExpectedSignatureKey(test_case.features, input_key, output_key);
            const Signature signature = Schnorr::Sign(expected_signature_key.data(), expected_message);

            const Input input(test_case.features, output_id, commit, input_pubkey, output_pubkey, test_case.extra_data, signature);

            const std::vector<uint8_t> serialized = input.Serialized();
            SpanReader deserializer(std::span<const uint8_t>{serialized});

            uint8_t features;
            deserializer >> features;
            BOOST_REQUIRE_EQUAL(features, test_case.features);

            mw::Hash output_id2;
            deserializer >> output_id2;
            BOOST_REQUIRE(output_id2 == output_id);

            Commitment commit2;
            deserializer >> commit2;
            BOOST_REQUIRE(commit2 == commit);

            PublicKey output_pubkey2;
            deserializer >> output_pubkey2;
            BOOST_REQUIRE(output_pubkey2 == output_pubkey);

            if ((test_case.features & Input::STEALTH_KEY_FEATURE_BIT) > 0) {
                PublicKey input_pubkey2;
                deserializer >> input_pubkey2;
                BOOST_REQUIRE(input_pubkey2 == input_pubkey);
            }

            if ((test_case.features & Input::EXTRA_DATA_FEATURE_BIT) > 0) {
                std::vector<uint8_t> extra_data2;
                deserializer >> extra_data2;
                BOOST_REQUIRE(extra_data2 == test_case.extra_data);
            }

            Signature signature2;
            deserializer >> signature2;
            BOOST_REQUIRE(signature2 == signature);
            BOOST_REQUIRE(deserializer.empty());

            const Input deserialized = Input::Deserialize(serialized);
            BOOST_REQUIRE(input == deserialized);
            BOOST_REQUIRE(deserialized.GetFeatures() == test_case.features);
            BOOST_REQUIRE(deserialized.GetOutputID() == output_id);
            BOOST_REQUIRE(deserialized.GetCommitment() == commit);
            BOOST_REQUIRE(deserialized.GetOutputPubKey() == output_pubkey);
            BOOST_REQUIRE(deserialized.GetSignature() == signature);
            BOOST_REQUIRE(deserialized.IsStandard() == (test_case.features < Input::EXTRA_DATA_FEATURE_BIT));

            if ((test_case.features & Input::STEALTH_KEY_FEATURE_BIT) > 0) {
                BOOST_REQUIRE(deserialized.GetInputPubKey().has_value());
                BOOST_REQUIRE(*deserialized.GetInputPubKey() == input_pubkey);
            } else {
                BOOST_REQUIRE(!deserialized.GetInputPubKey().has_value());
            }

            if ((test_case.features & Input::EXTRA_DATA_FEATURE_BIT) > 0) {
                BOOST_REQUIRE(deserialized.GetExtraData() == test_case.extra_data);
            } else {
                BOOST_REQUIRE(deserialized.GetExtraData().empty());
            }

            const SignedMessage expected_signed_message(expected_message, expected_public_key, signature);
            BOOST_REQUIRE(input.BuildSignedMsg() == expected_signed_message);
            BOOST_REQUIRE(deserialized.BuildSignedMsg() == expected_signed_message);
            BOOST_REQUIRE(Schnorr::BatchVerify({input.BuildSignedMsg(), deserialized.BuildSignedMsg()}));
        }
    }
}

BOOST_AUTO_TEST_CASE(PlainTxInput)
{
    mw::Hash output_id = SecretKey::Random().GetBigInt();
    Commitment commit = Commitment::Random();
    PublicKey input_pubkey = PublicKey::Random();
    PublicKey output_pubkey = PublicKey::Random();
    Signature signature(RandomBigInt<Signature::SIZE>());
    Input input(1, output_id, commit, input_pubkey, output_pubkey, signature);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = input.Serialized();

        SpanReader deserializer(std::span<const uint8_t>{serialized});
        uint8_t features;
        deserializer >>  features;
        BOOST_REQUIRE(features == 1);

        mw::Hash output_id2;
        deserializer >> output_id2;
        BOOST_REQUIRE(output_id2 == output_id);

        Commitment commit2;
        deserializer >> commit2;
        BOOST_REQUIRE(commit2 == commit);

        PublicKey output_pubkey2;
        deserializer >> output_pubkey2;
        BOOST_REQUIRE(output_pubkey2 == output_pubkey);

        PublicKey input_pubkey2;
        deserializer >> input_pubkey2;
        BOOST_REQUIRE(input_pubkey2 == input_pubkey);

        Signature signature2;
        deserializer >> signature2;
        BOOST_REQUIRE(signature2 == signature);

        BOOST_REQUIRE(input == Input::Deserialize(serialized));
    }

    //
    // Getters
    //
    {
        BOOST_REQUIRE(input.GetOutputID() == output_id);
        BOOST_REQUIRE(input.GetCommitment() == commit);
        BOOST_REQUIRE(*input.GetInputPubKey() == input_pubkey);
        BOOST_REQUIRE(input.GetOutputPubKey() == output_pubkey);
        BOOST_REQUIRE(input.GetSignature() == signature);
    }

    // MW: TODO - Input version tests
}

BOOST_AUTO_TEST_SUITE_END()
