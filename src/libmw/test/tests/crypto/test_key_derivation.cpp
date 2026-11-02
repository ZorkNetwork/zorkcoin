// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/output_mask.h>

#include <test_framework/test_mweb.h>

#include <array>

namespace {
SecretKey ScanSecret() { return SecretKey::FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); }
SecretKey SpendSecret() { return SecretKey::FromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"); }
SecretKey SenderSecret() { return SecretKey::FromHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"); }

struct DerivationVector {
    uint32_t index;
    const char* scan_pubkey;
    const char* spend_pubkey;
    const char* spend_secret;
};

constexpr std::array<DerivationVector, 4> DERIVATION_VECTORS{{
    {0, "03826d3f8e180da6ab4dcd512f06670c2aa018b134953312de8095433f5da4bd91",
        "02a5ca62e733cf7bd9c2592ecc793970c4090a191cbc5cc34bef3a0a6793d3e236",
        "dd2e9d1894e5782f5b00ad726b098a31985ddf35c97e4149ab1c4f9f3e2b943a"},
    {1, "0203386c706772e81f58b8da550f6433fe35e6553cb2e7c041997da9592f84dabd",
        "0307855c0a8ae877bf9de8583928f857322e91727a4639bc96c2956e490444133d",
        "5d71b3b569974352e724620c02e8202550bd5725b3635c0ab6207ca4754ea7d0"},
    {10, "0398ced716ba3e1d3d9b983783fe675243d4f878ec4bc6bc50e0a307f33d6e943b",
         "039412686710c264fc11881d45100eb50a1dbd9e987d1fd67a7d83c45fa8dd8bd7",
         "cbfd1b1e8969e4df915fa3702547c6f5f15f4d3717344d9774465a5cff8a434b"},
    {42, "03f78aabcf1759cbec37dd395fad62f2c92d1fb8578dc2e8397bd31aa38e6efa91",
         "02193b11a4716bc4646e6dbe25287d483dd10cbb1ac883363ae581abb810e57d01",
         "86cdef719db3a2900ed66df3ef14b3bc4f7df62f034ef4975eb51dbd30b84353"},
}};
} // namespace

BOOST_FIXTURE_TEST_SUITE(TestKeyDerivation, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(DeterministicVectors)
{
    BOOST_CHECK_EQUAL(mw::DeriveRewindKey(ScanSecret()).ToHex(), "ba520343da9cebd5b8b2acce4f5bb4e3d232d35156411ba4853f583ed39e873b");
    BOOST_CHECK_EQUAL(mw::DeriveSenderSigningKey(ScanSecret(), 0).ToHex(), "287de0d46e27a3b2d7c2549a3711dd826d397096254838a01495735637a5dfd5");
    BOOST_CHECK_EQUAL(mw::DeriveSenderSigningKey(ScanSecret(), 1).ToHex(), "b26baf37f7baeaa90c28d802d589bb3669b39bbccd80d3ec55be688397be4f4c");

    for (const DerivationVector& vector : DERIVATION_VECTORS) {
        const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(SpendSecret()), ScanSecret(), vector.index);
        const SecretKey spend_key = mw::DeriveSubaddressSpendKey(SpendSecret(), ScanSecret(), vector.index);
        BOOST_CHECK_EQUAL(address.A().ToHex(), vector.scan_pubkey);
        BOOST_CHECK_EQUAL(address.B().ToHex(), vector.spend_pubkey);
        BOOST_CHECK_EQUAL(spend_key.ToHex(), vector.spend_secret);
        BOOST_CHECK(PublicKey::From(spend_key) == address.B());
        BOOST_CHECK(address.A() == address.B().Mul(ScanSecret()));
    }
}

BOOST_AUTO_TEST_CASE(ProofNonceBindsRewindKeyAndCommitment)
{
    const SecretKey rewind_key = mw::DeriveRewindKey(ScanSecret());
    const Commitment commit1 = Commitment::Blinded(BlindingFactor::Random(), 5);
    const Commitment commit2 = Commitment::Blinded(BlindingFactor::Random(), 5);
    BOOST_CHECK(mw::DeriveProofNonce(rewind_key, commit1) == mw::DeriveProofNonce(rewind_key, commit1));
    BOOST_CHECK(mw::DeriveProofNonce(rewind_key, commit1) != mw::DeriveProofNonce(rewind_key, commit2));
    BOOST_CHECK(mw::DeriveProofNonce(rewind_key, commit1) != mw::DeriveProofNonce(mw::DeriveRewindKey(SenderSecret()), commit1));
}

BOOST_AUTO_TEST_CASE(ForwardAndRecoveryAgree)
{
    const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(SpendSecret()), ScanSecret(), 10);
    const uint64_t amount = 1'234'567;
    const Output output = Output::Create(nullptr, SenderSecret(), address, amount);

    const SecretKey shared_secret = mw::DeriveSharedSecret(SenderSecret(), address, amount);
    BOOST_CHECK(mw::RecoverSharedSecret(output.Ke(), ScanSecret()) == shared_secret);
    BOOST_CHECK_EQUAL(mw::RecoverViewTag(output.Ke(), ScanSecret()), output.GetViewTag());
    BOOST_CHECK(mw::DeriveOutputPubKey(address, shared_secret) == output.Ko());
    BOOST_CHECK(mw::RecoverSubaddressSpendPubKey(output.Ko(), shared_secret) == address.B());
    BOOST_CHECK(mw::RecoverSubaddress(output.Ko(), shared_secret, ScanSecret()) == address);

    const BigInt<16> nonce = mw::DeriveOutputNonce(SenderSecret());
    const SecretKey send_key = mw::DeriveOutputSendKey(address, amount, nonce);
    BOOST_CHECK(mw::DeriveOutputKeyExchangePubKey(address, send_key) == output.Ke());

    const SecretKey spend_key = mw::DeriveOutputSpendKey(mw::DeriveSubaddressSpendKey(SpendSecret(), ScanSecret(), 10), shared_secret);
    BOOST_CHECK(PublicKey::From(spend_key) == output.Ko());
    BOOST_CHECK(Commitment::Switch(mw::DeriveOutputRawBlind(shared_secret), amount) == output.GetCommitment());
    BOOST_CHECK(mw::DeriveOutputRawBlind(shared_secret) == OutputMask::FromShared(shared_secret).GetRawBlind());
}

BOOST_AUTO_TEST_SUITE_END()
