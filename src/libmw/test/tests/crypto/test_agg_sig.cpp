// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/mu_sig.h>
#include <mw/crypto/public_keys.h>
#include <mw/crypto/schnorr.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestAggSig, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(AggSigInteraction)
{
    mw::Hash message = SecretKey::Random().GetBigInt();

    // Generate sender keypairs
    SecretKey secretKeySender = SecretKey::Random();
    PublicKey publicKeySender = PublicKey::From(secretKeySender);
    SecretKey secretNonceSender = MuSig::GenerateSecureNonce();
    PublicKey publicNonceSender = PublicKey::From(secretNonceSender);

    // Generate receiver keypairs
    SecretKey secretKeyReceiver = SecretKey::Random();
    PublicKey publicKeyReceiver = PublicKey::From(secretKeyReceiver);
    SecretKey secretNonceReceiver = MuSig::GenerateSecureNonce();
    PublicKey publicNonceReceiver = PublicKey::From(secretNonceReceiver);

    // Add pubKeys and pubNonces
    PublicKey sumPubKeys = PublicKeys::Add(
        std::vector<PublicKey>({ publicKeySender, publicKeyReceiver })
    );

    PublicKey sumPubNonces = PublicKeys::Add(
        std::vector<PublicKey>({ publicNonceSender, publicNonceReceiver })
    );

    // Generate partial signatures
    CompactSignature senderPartialSignature = MuSig::CalculatePartial(
        secretKeySender,
        secretNonceSender,
        sumPubKeys,
        sumPubNonces,
        message
    );
    CompactSignature receiverPartialSignature = MuSig::CalculatePartial(
        secretKeyReceiver,
        secretNonceReceiver,
        sumPubKeys,
        sumPubNonces,
        message
    );

    // Validate partial signatures
    const bool senderSigValid = MuSig::VerifyPartial(
        senderPartialSignature,
        publicKeySender,
        sumPubKeys,
        sumPubNonces,
        message
    );
    BOOST_REQUIRE(senderSigValid == true);

    const bool receiverSigValid = MuSig::VerifyPartial(
        receiverPartialSignature,
        publicKeyReceiver,
        sumPubKeys,
        sumPubNonces,
        message
    );
    BOOST_REQUIRE(receiverSigValid == true);

    // Aggregate signature and validate
    Signature aggregateSignature = MuSig::Aggregate(
        std::vector<CompactSignature>({ senderPartialSignature, receiverPartialSignature }),
        sumPubNonces
    );
    const bool aggSigValid = Schnorr::Verify(
        aggregateSignature,
        sumPubKeys,
        message
    );
    BOOST_REQUIRE(aggSigValid == true);
}

BOOST_AUTO_TEST_CASE(SingleSchnorrSig)
{
    mw::Hash message = SecretKey::Random().GetBigInt();
    SecretKey secret_key = SecretKey::Random();
    PublicKey public_key = PublicKey::From(secret_key);
    Signature signature = Schnorr::Sign(secret_key.data(), message);

    const bool valid = Schnorr::Verify(signature, public_key, message);
    BOOST_REQUIRE(valid == true);
}

BOOST_AUTO_TEST_CASE(DeterministicAggSigVector)
{
    const mw::Hash message = mw::Hash::FromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const SecretKey secret_sender = SecretKey::FromHex("1111111111111111111111111111111111111111111111111111111111111111");
    const SecretKey nonce_sender = SecretKey::FromHex("2222222222222222222222222222222222222222222222222222222222222222");
    const SecretKey secret_receiver = SecretKey::FromHex("3333333333333333333333333333333333333333333333333333333333333333");
    const SecretKey nonce_receiver = SecretKey::FromHex("4444444444444444444444444444444444444444444444444444444444444444");

    const PublicKey pub_sender = PublicKey::From(secret_sender);
    const PublicKey pub_nonce_sender = PublicKey::From(nonce_sender);
    const PublicKey pub_receiver = PublicKey::From(secret_receiver);
    const PublicKey pub_nonce_receiver = PublicKey::From(nonce_receiver);

    const PublicKey sum_pubkeys = PublicKeys::Add({pub_sender, pub_receiver});
    const PublicKey sum_nonces = PublicKeys::Add({pub_nonce_sender, pub_nonce_receiver});

    const CompactSignature partial_sender = MuSig::CalculatePartial(
        secret_sender, nonce_sender, sum_pubkeys, sum_nonces, message);
    const CompactSignature partial_receiver = MuSig::CalculatePartial(
        secret_receiver, nonce_receiver, sum_pubkeys, sum_nonces, message);

    BOOST_CHECK_EQUAL(partial_sender.ToHex(),
        "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f278664044b923001d625053bc3f0c431ceff317c3098d4c3caf5cab62e3126da4e");
    BOOST_CHECK_EQUAL(partial_receiver.ToHex(),
        "2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991b54e2f04d8b227a49131d56df46eb7906507b9cd3d57cd4743afe61fe5606fcb");

    BOOST_REQUIRE(MuSig::VerifyPartial(partial_sender, pub_sender, sum_pubkeys, sum_nonces, message));
    BOOST_REQUIRE(MuSig::VerifyPartial(partial_receiver, pub_receiver, sum_pubkeys, sum_nonces, message));

    const Signature agg_sig = MuSig::Aggregate({partial_sender, partial_receiver}, sum_nonces);
    BOOST_CHECK_EQUAL(agg_sig.ToHex(),
        "5ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c303bb233506ae2297ab6371131e532e960a98a591726e3f0d679a83dc1465108d8");
    BOOST_REQUIRE(Schnorr::Verify(agg_sig, sum_pubkeys, message));
}

BOOST_AUTO_TEST_SUITE_END()
