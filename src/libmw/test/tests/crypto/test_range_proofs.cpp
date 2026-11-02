// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/bulletproofs.h>
#include <mw/models/crypto/blinding_factor.h>
#include <util/strencodings.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestRangeProofs, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(RangeProofs)
{
    const uint64_t value = 123;
    BlindingFactor blind = BlindingFactor::Random();
    Commitment commit = Commitment::Blinded(blind, value);
    SecretKey nonce = SecretKey::Random();
    SecretKey nonce2 = SecretKey::Random();
    ProofMessage message = RandomBigInt<20>();
    std::vector<uint8_t> extraData = RandomBytes<100>();

    // Create a RangeProof via Bulletproofs::Generate. Use the same value for privateNonce and rewindNonce.
    RangeProof::CPtr pRangeProof = Bulletproofs::Generate(
        value,
        SecretKey(blind.vec()),
        nonce,
        nonce,
        message,
        extraData
    );

    // Try rewinding it via Bulletproofs::Rewind using the *wrong* rewindNonce. Make sure it returns null.
    BOOST_REQUIRE(!Bulletproofs::Rewind(commit, *pRangeProof, extraData, nonce2));

    // Try rewinding it via Bulletproofs::Rewind using the *correct* rewindNonce. Make sure it returns a valid RewoundProof.
    std::unique_ptr<RewoundProof> pRewoundProof = Bulletproofs::Rewind(commit, *pRangeProof, extraData, nonce);
    BOOST_REQUIRE(pRewoundProof);

    // Make sure amount, blindingFactor (aka 'key'), and ProofMessage match the values passed to Bulletproofs::Generate
    BOOST_REQUIRE(*pRewoundProof == RewoundProof(
        value,
        std::make_unique<SecretKey>(SecretKey(blind.vec())),
        ProofMessage(message)
    ));

    // Make sure BatchVerify returns true.
    std::vector<ProofData> rangeProofs;
    rangeProofs.push_back(ProofData{ commit, pRangeProof, extraData });
    BOOST_REQUIRE(Bulletproofs::BatchVerify(rangeProofs));
}

BOOST_AUTO_TEST_CASE(RangeProofs32ByteMessage)
{
    const uint64_t value = 12345678;
    BlindingFactor blind = BlindingFactor::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    Commitment commit = Commitment::Blinded(blind, value);
    SecretKey nonce = SecretKey::FromHex("5021e7378095d5dc0dc59d7886a4f65c126db9580a1dde3fedc4fe6dc7734cd5");
    BigInt<32> message = BigInt<32>::FromHex("c2ca9d0aa93184f598f595147cd6c786f2bafb7000112233445566778899aabb");
    std::vector<uint8_t> extraData = ParseHex("d21cf3d38aa9a7de357949164d8134a7686a7b107c279f50735d487874ffc56fe0b62b759baf6ecde5a73dd6932634f97501");

    RangeProof::CPtr pRangeProof = Bulletproofs::Generate(value, SecretKey(blind.vec()), nonce, message, extraData);
    BOOST_CHECK_EQUAL(pRangeProof->GetHash().ToHex(), "eb8ac2d405834bd51a3754f2dfe14c92402588b67c561e6f46b7da8e409fac07");

    BOOST_CHECK(Bulletproofs::RewindMessage(commit, *pRangeProof, extraData, nonce) == message);
    BOOST_CHECK(Bulletproofs::RewindMessage(commit, *pRangeProof, extraData, SecretKey::Random()) != message);

    std::vector<ProofData> rangeProofs;
    rangeProofs.push_back(ProofData{ commit, pRangeProof, extraData });
    BOOST_REQUIRE(Bulletproofs::BatchVerify(rangeProofs));
}

BOOST_AUTO_TEST_CASE(RangeProofMessageAboveGroupOrder)
{
    // Messages >= the group order are flagged in the proof and restored on rewind.
    const uint64_t value = 5;
    BlindingFactor blind = BlindingFactor::Random();
    Commitment commit = Commitment::Blinded(blind, value);
    SecretKey nonce = SecretKey::Random();
    for (const char* hex : {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"}) {
        const BigInt<32> message = BigInt<32>::FromHex(hex);
        RangeProof::CPtr proof = Bulletproofs::Generate(value, SecretKey(blind.vec()), nonce, message, {});
        BOOST_CHECK(Bulletproofs::RewindMessage(commit, *proof, {}, nonce) == message);
        BOOST_CHECK(Bulletproofs::BatchVerify({ProofData{commit, proof, {}}}));
    }
}

BOOST_AUTO_TEST_CASE(RangeProofLegacyFormat)
{
    // Proofs made before the 32-byte message format carry no flags in the high nibble of byte 64.
    // Apart from those flags the prover output is unchanged, so clearing them reproduces a legacy
    // proof, which must still verify and rewind.
    const uint64_t value = 987'654'321;
    BlindingFactor blind = BlindingFactor::Random();
    Commitment commit = Commitment::Blinded(blind, value);
    SecretKey nonce = SecretKey::Random();
    ProofMessage message = RandomBigInt<20>();
    std::vector<uint8_t> extraData = RandomBytes<60>();

    RangeProof::CPtr flagged = Bulletproofs::Generate(value, SecretKey(blind.vec()), nonce, nonce, message, extraData);
    std::vector<uint8_t> legacy_bytes = flagged->vec();
    BOOST_CHECK_EQUAL(legacy_bytes[64] & 0xF0, 0x10);
    legacy_bytes[64] &= 0x0F;
    RangeProof::CPtr legacy = std::make_shared<RangeProof>(std::move(legacy_bytes));

    BOOST_REQUIRE(Bulletproofs::BatchVerify({ProofData{commit, legacy, extraData}}));

    std::unique_ptr<RewoundProof> rewound = Bulletproofs::Rewind(commit, *legacy, extraData, nonce);
    BOOST_REQUIRE(rewound);
    BOOST_CHECK(*rewound == RewoundProof(value, std::make_unique<SecretKey>(SecretKey(blind.vec())), ProofMessage(message)));

    // Both formats rewind to [0x00000000 || message || value (BE)].
    const BigInt<32> legacy_msg = Bulletproofs::RewindMessage(commit, *legacy, extraData, nonce);
    BOOST_CHECK(legacy_msg == Bulletproofs::RewindMessage(commit, *flagged, extraData, nonce));
    BOOST_CHECK(std::equal(message.data(), message.data() + 20, legacy_msg.data() + 4));
    BOOST_CHECK_EQUAL(legacy_msg[31], value & 0xFF);
}

BOOST_AUTO_TEST_SUITE_END()
