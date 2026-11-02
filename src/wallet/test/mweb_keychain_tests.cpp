// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/output.h>
#include <mw/wallet/keychain.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <wallet/imweb_keystore.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <optional>

namespace wallet {
namespace {

constexpr uint32_t TEST_ADDRESS_INDEX{10};

SecretKey ScanSecret() { return SecretKey::FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); }
SecretKey SpendSecret() { return SecretKey::FromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"); }
SecretKey SenderSecret() { return SecretKey::FromHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"); }
SecretKey CustomSpendSecret() { return SecretKey::FromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"); }

class TestKeyStore final : public IMWEBKeyStore
{
public:
    void AddMetadata(const StealthAddress& address, const std::optional<uint32_t>& mweb_index)
    {
        CKeyMetadata metadata;
        if (mweb_index) metadata.mweb_index = *mweb_index;
        m_metadata[address] = metadata;
    }

    void AddKey(const StealthAddress& address, const SecretKey& secret)
    {
        CKey key;
        key.Set(secret.data(), secret.data() + secret.size(), /*fCompressedIn=*/true);
        m_keys[address.B().GetID()] = key;
    }

    std::unique_ptr<CKeyMetadata> GetMetadata(const StealthAddress& addr) const override
    {
        const auto it = m_metadata.find(addr);
        if (it == m_metadata.end()) return nullptr;
        return std::make_unique<CKeyMetadata>(it->second);
    }

    bool GetKey(const CKeyID& id, CKey& key_out) const override
    {
        const auto it = m_keys.find(id);
        if (it == m_keys.end()) return false;
        key_out = it->second;
        return true;
    }

    bool HaveKey(const CKeyID& id) const override { return m_keys.contains(id); }

private:
    std::map<StealthAddress, CKeyMetadata> m_metadata;
    std::map<CKeyID, CKey> m_keys;
};

Output CreateOutput(const StealthAddress& address, const uint64_t amount)
{
    return Output::Create(nullptr, SenderSecret(), ScanSecret(), address, amount, std::vector<uint8_t>{});
}

void CheckRewoundCoin(const mw::Coin& coin, const Output& output, const uint32_t address_index, const uint64_t amount, const StealthAddress& address)
{
    BOOST_CHECK_EQUAL(coin.address_index, address_index);
    BOOST_CHECK_EQUAL(coin.amount, static_cast<CAmount>(amount));
    BOOST_CHECK(coin.output_id == output.GetOutputID());
    BOOST_REQUIRE(coin.address.has_value());
    BOOST_CHECK(*coin.address == address);
    BOOST_CHECK(coin.blind.has_value());
    BOOST_CHECK(coin.shared_secret.has_value());
    BOOST_REQUIRE(coin.master_scan_key_id.has_value());
    BOOST_CHECK(*coin.master_scan_key_id == PublicKey::From(ScanSecret()).GetID());
}

Output WithStandardFields(const Output& output, const OutputStandardFields& fields)
{
    return Output(output.GetCommitment(), output.GetSenderPubKey(), output.GetReceiverPubKey(),
                  OutputMessage(OutputMessage::STANDARD_FIELDS_FEATURE_BIT, fields), output.GetRangeProof(), output.GetSignature());
}

PublicKey MalformedPublicKey(const uint8_t prefix, const uint8_t fill)
{
    std::array<uint8_t, 33> bytes;
    bytes.fill(fill);
    bytes[0] = prefix;
    return PublicKey(bytes.data());
}

void CheckNotRewound(const mw::Keychain& keychain, const Output& output)
{
    mw::Coin coin;
    coin.Reset();
    BOOST_CHECK(!keychain.RewindOutput(output, coin));
    BOOST_CHECK(!coin.IsMine());
    BOOST_CHECK(!coin.master_scan_key_id.has_value());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_keychain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deterministic_derivations)
{
    TestKeyStore keystore;
    mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());
    BOOST_CHECK(keychain.HasSpendPubKey());
    BOOST_CHECK(keychain.HasSpendSecret());
    BOOST_CHECK_EQUAL(keychain.GetRewindKey().ToHex(), "ba520343da9cebd5b8b2acce4f5bb4e3d232d35156411ba4853f583ed39e873b");
    BOOST_CHECK_EQUAL(keychain.GetSenderSigningKey(0).ToHex(), "287de0d46e27a3b2d7c2549a3711dd826d397096254838a01495735637a5dfd5");
    BOOST_CHECK_EQUAL(keychain.GetSenderSigningKey(1).ToHex(), "b26baf37f7baeaa90c28d802d589bb3669b39bbccd80d3ec55be688397be4f4c");
    BOOST_CHECK(keychain.GetMasterScanKeyID() == PublicKey::From(ScanSecret()).GetID());

    const StealthAddress address_10 = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    BOOST_CHECK_EQUAL(address_10.B().ToHex(), "039412686710c264fc11881d45100eb50a1dbd9e987d1fd67a7d83c45fa8dd8bd7");
    BOOST_CHECK(PublicKey::From(keychain.GetSubaddressSpendKey(TEST_ADDRESS_INDEX)) == address_10.B());

    keychain.Lock();
    BOOST_CHECK(keychain.HasSpendPubKey());
    BOOST_CHECK(!keychain.HasSpendSecret());
    BOOST_CHECK(keychain.DeriveAddress(TEST_ADDRESS_INDEX) == address_10);

    keychain.Unlock(SpendSecret());
    BOOST_CHECK(keychain.HasSpendSecret());
    BOOST_CHECK(PublicKey::From(keychain.GetSubaddressSpendKey(TEST_ADDRESS_INDEX)) == address_10.B());
}

BOOST_AUTO_TEST_CASE(watch_only_keychain_matches_full_keychain)
{
    TestKeyStore keystore;
    const mw::Keychain full(keystore, ScanSecret(), SpendSecret());
    const mw::Keychain watch_only(keystore, ScanSecret(), PublicKey::From(SpendSecret()));
    BOOST_CHECK(watch_only.HasSpendPubKey());
    BOOST_CHECK(!watch_only.HasSpendSecret());
    for (uint32_t index = 0; index <= 100; ++index) {
        BOOST_CHECK(watch_only.DeriveAddress(index) == full.GetStealthAddress(index));
    }
    BOOST_CHECK(watch_only.DeriveAddress(mw::CHANGE_INDEX) == full.GetStealthAddress(0));
    BOOST_CHECK(watch_only.DeriveAddress(mw::PEGIN_INDEX) == full.GetStealthAddress(1));
    BOOST_CHECK(watch_only.GetRewindKey() == full.GetRewindKey());
    BOOST_CHECK(watch_only.GetSenderSigningKey(7) == full.GetSenderSigningKey(7));
}

BOOST_AUTO_TEST_CASE(watch_only_keychain_identifies_but_cannot_sign)
{
    TestKeyStore keystore;
    const mw::Keychain watch_only(keystore, ScanSecret(), PublicKey::From(SpendSecret()));
    const mw::Keychain full(keystore, ScanSecret(), SpendSecret());

    for (const uint32_t index : {mw::CHANGE_INDEX, mw::PEGIN_INDEX, TEST_ADDRESS_INDEX}) {
        const StealthAddress address = watch_only.DeriveAddress(index);
        keystore.AddMetadata(address, index);
        const Output output = CreateOutput(address, 1'000 + index);

        mw::Coin coin;
        coin.Reset();
        BOOST_REQUIRE(watch_only.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, index, 1'000 + index, address);
        BOOST_CHECK(!coin.HasSpendKey());
        BOOST_CHECK(!watch_only.CalculateOutputKey(coin));
        BOOST_CHECK(!watch_only.CalculateOutputSpendKey(coin));

        mw::Coin populated = coin;
        BOOST_CHECK(!watch_only.PopulateSpendMaterial(populated));
        BOOST_CHECK(!populated.HasSpendKey());

        const std::optional<SecretKey> spend_key = full.CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.Ko());
    }
}

BOOST_AUTO_TEST_CASE(indexed_owned_outputs_rewind_zero_and_one)
{
    TestKeyStore keystore;
    const mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());
    const StealthAddress address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    keystore.AddMetadata(address, TEST_ADDRESS_INDEX);

    for (const uint64_t amount : {uint64_t{0}, uint64_t{1}}) {
        BlindingFactor blind;
        const Output output = Output::Create(&blind, SenderSecret(), ScanSecret(), address, amount, {});
        BOOST_REQUIRE(Bulletproofs::BatchVerify({output.BuildProofData()}));
        mw::Coin coin;
        BOOST_REQUIRE(keychain.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, TEST_ADDRESS_INDEX, amount, address);
        BOOST_CHECK(coin.IsMine());
        BOOST_REQUIRE(coin.blind);
        BOOST_CHECK(*coin.blind == blind);
        BOOST_REQUIRE(coin.shared_secret);
        BOOST_CHECK(*coin.shared_secret == mw::RecoverSharedSecret(output.Ke(), ScanSecret()));
        BOOST_CHECK(coin.HasSpendMaterial());
        const auto spend_key = keychain.CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(coin.spend_key == spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.Ko());
    }
}

BOOST_AUTO_TEST_CASE(scan_only_keychain_requires_owned_address_metadata)
{
    TestKeyStore keystore;
    const mw::Keychain full(keystore, ScanSecret(), SpendSecret());
    const mw::Keychain scan_only(keystore, ScanSecret(), SecretKey::Null());
    BOOST_CHECK(!scan_only.HasSpendSecret());
    BOOST_CHECK(!scan_only.HasSpendPubKey());
    const StealthAddress address = full.DeriveAddress(TEST_ADDRESS_INDEX);
    const Output output = CreateOutput(address, 1'234'567);

    CheckNotRewound(scan_only, output);
    keystore.AddMetadata(address, TEST_ADDRESS_INDEX);
    mw::Coin coin;
    BOOST_REQUIRE(scan_only.RewindOutput(output, coin));
    CheckRewoundCoin(coin, output, TEST_ADDRESS_INDEX, 1'234'567, address);
    BOOST_CHECK(coin.IsMine());
    // Low-level rewind recovers the blind, but no spending key is available.
    BOOST_CHECK(!coin.HasSpendMaterial());
    BOOST_CHECK(!coin.HasSpendKey());
    BOOST_CHECK(!scan_only.CalculateOutputKey(coin));
    BOOST_CHECK(!scan_only.CalculateOutputSpendKey(coin));
    BOOST_CHECK(!scan_only.PopulateSpendMaterial(coin));
    CheckNotRewound(scan_only, CreateOutput(full.DeriveAddress(TEST_ADDRESS_INDEX + 1), 5));
}

BOOST_AUTO_TEST_CASE(lookup_address_index)
{
    TestKeyStore keystore;
    const mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());

    const StealthAddress indexed_address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    keystore.AddMetadata(indexed_address, TEST_ADDRESS_INDEX);
    BOOST_CHECK_EQUAL(keychain.LookupAddressIndex(indexed_address).value(), TEST_ADDRESS_INDEX);

    const StealthAddress custom_address = keychain.DeriveAddress(42);
    keystore.AddMetadata(custom_address, std::nullopt);
    BOOST_CHECK_EQUAL(keychain.LookupAddressIndex(custom_address).value(), mw::CUSTOM_KEY);

    BOOST_CHECK(!keychain.LookupAddressIndex(keychain.DeriveAddress(1)).has_value());
}

BOOST_AUTO_TEST_CASE(rewind_custom_key_outputs)
{
    const PublicKey custom_spend = PublicKey::From(CustomSpendSecret());
    const StealthAddress custom_address(custom_spend.Mul(ScanSecret()), custom_spend);
    const Output output = CreateOutput(custom_address, 1);

    {
        TestKeyStore keystore;
        keystore.AddMetadata(custom_address, std::nullopt);
        const mw::Keychain keychain(keystore, ScanSecret(), PublicKey::From(SpendSecret()));
        mw::Coin coin;
        coin.Reset();
        BOOST_REQUIRE(keychain.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, mw::CUSTOM_KEY, 1, custom_address);
        BOOST_CHECK(!keychain.CalculateOutputSpendKey(coin));
    }
    {
        TestKeyStore keystore;
        keystore.AddMetadata(custom_address, std::nullopt);
        keystore.AddKey(custom_address, CustomSpendSecret());
        const mw::Keychain keychain(keystore, ScanSecret(), PublicKey::From(SpendSecret()));
        mw::Coin coin;
        coin.Reset();
        BOOST_REQUIRE(keychain.RewindOutput(output, coin));
        const std::optional<SecretKey> spend_key = keychain.CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.Ko());
    }
}

BOOST_AUTO_TEST_CASE(calculate_output_spend_key_rejects_mismatched_address)
{
    TestKeyStore keystore;
    const mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());
    const StealthAddress address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    keystore.AddMetadata(address, TEST_ADDRESS_INDEX);
    mw::Coin coin;
    coin.Reset();
    BOOST_REQUIRE(keychain.RewindOutput(CreateOutput(address, 5), coin));
    BOOST_CHECK(keychain.CalculateOutputSpendKey(coin));

    coin.address_index = TEST_ADDRESS_INDEX + 1;
    BOOST_CHECK(!keychain.CalculateOutputSpendKey(coin));
}

BOOST_AUTO_TEST_CASE(rewind_replaces_the_callers_coin)
{
    TestKeyStore keystore;
    const mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());
    const StealthAddress address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    keystore.AddMetadata(address, TEST_ADDRESS_INDEX);
    const Output output = CreateOutput(address, 5);

    mw::Coin coin;
    coin.Reset();
    coin.spend_key = CustomSpendSecret();
    coin.sender_key = CustomSpendSecret();
    BOOST_REQUIRE(keychain.RewindOutput(output, coin));
    CheckRewoundCoin(coin, output, TEST_ADDRESS_INDEX, 5, address);
    BOOST_REQUIRE(coin.HasSpendKey());
    BOOST_CHECK(PublicKey::From(*coin.spend_key) == output.Ko());
    BOOST_CHECK(!coin.sender_key);

    mw::Coin unchanged = coin;
    BOOST_CHECK(!keychain.RewindOutput(CreateOutput(keychain.DeriveAddress(TEST_ADDRESS_INDEX + 1), 6), unchanged));
    BOOST_CHECK(unchanged.output_id == coin.output_id);
}

BOOST_AUTO_TEST_CASE(rewind_rejections)
{
    TestKeyStore keystore;
    const mw::Keychain keychain(keystore, ScanSecret(), SpendSecret());
    const StealthAddress address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    keystore.AddMetadata(address, TEST_ADDRESS_INDEX);
    const Output output = CreateOutput(address, 1'234'567);

    CheckNotRewound(mw::Keychain(keystore, SenderSecret(), SpendSecret()), output);
    CheckNotRewound(keychain, Output(output.GetCommitment(), output.GetSenderPubKey(), output.GetReceiverPubKey(),
                                     OutputMessage(0, std::optional<OutputStandardFields>{}, std::vector<uint8_t>{}),
                                     output.GetRangeProof(), output.GetSignature()));
    CheckNotRewound(keychain, WithStandardFields(output, OutputStandardFields(MalformedPublicKey(0x04, 0x00), output.GetViewTag(), output.GetMaskedValue(), output.GetMaskedNonce())));
    CheckNotRewound(keychain, Output(output.GetCommitment(), output.GetSenderPubKey(), MalformedPublicKey(0x02, 0xff),
                                     output.GetOutputMessage(), output.GetRangeProof(), output.GetSignature()));

    TestKeyStore unknown_keystore;
    CheckNotRewound(mw::Keychain(unknown_keystore, ScanSecret(), SpendSecret()), output);

    CheckNotRewound(keychain, WithStandardFields(output, OutputStandardFields(output.Ke(), output.GetViewTag() ^ 0x01, output.GetMaskedValue(), output.GetMaskedNonce())));
    CheckNotRewound(keychain, WithStandardFields(output, OutputStandardFields(output.Ke(), output.GetViewTag(), output.GetMaskedValue() ^ 0x01, output.GetMaskedNonce())));
    BigInt<16> tampered_nonce = output.GetMaskedNonce();
    tampered_nonce[0] ^= 0x01;
    CheckNotRewound(keychain, WithStandardFields(output, OutputStandardFields(output.Ke(), output.GetViewTag(), output.GetMaskedValue(), tampered_nonce)));

    // A failed rewind leaves a coin the caller already filled in byte-identical.
    mw::Coin valid_coin;
    BOOST_REQUIRE(keychain.RewindOutput(output, valid_coin));
    const auto serialize = [](const mw::Coin& coin) {
        DataStream stream;
        stream << coin;
        return std::vector<std::byte>(stream.begin(), stream.end());
    };
    for (const Output& malformed : {
             WithStandardFields(output, OutputStandardFields(MalformedPublicKey(0x04, 0x00), output.GetViewTag(), output.GetMaskedValue(), output.GetMaskedNonce())),
             Output(output.GetCommitment(), output.GetSenderPubKey(), MalformedPublicKey(0x04, 0x00),
                    output.GetOutputMessage(), output.GetRangeProof(), output.GetSignature())}) {
        mw::Coin coin = valid_coin;
        bool rewound = true;
        BOOST_CHECK_NO_THROW(rewound = keychain.RewindOutput(malformed, coin));
        BOOST_CHECK(!rewound);
        BOOST_CHECK(serialize(coin) == serialize(valid_coin));
    }
}

BOOST_AUTO_TEST_CASE(sender_pubkey_lookup)
{
    TestKeyStore keystore;
    mw::Keychain keychain(keystore, ScanSecret(), PublicKey::From(SpendSecret()));
    const PublicKey sender_pubkey_5 = PublicKey::From(keychain.GetSenderSigningKey(5));
    BOOST_CHECK(!keychain.LookupSenderPubKeyIndex(sender_pubkey_5));
    keychain.TopUpSenderPubKeys(5);
    BOOST_CHECK(!keychain.LookupSenderPubKeyIndex(sender_pubkey_5));
    keychain.TopUpSenderPubKeys(6);
    BOOST_CHECK_EQUAL(keychain.LookupSenderPubKeyIndex(sender_pubkey_5).value(), 5U);
    keychain.TopUpSenderPubKeys(3);
    BOOST_CHECK_EQUAL(keychain.LookupSenderPubKeyIndex(sender_pubkey_5).value(), 5U);
}

BOOST_AUTO_TEST_CASE(coin_master_scan_key_id_serialization)
{
    mw::Coin coin;
    coin.Reset();
    coin.address_index = 3;
    coin.amount = 12345;
    coin.output_id = mw::Hash::FromHex("0101010101010101010101010101010101010101010101010101010101010101");
    coin.shared_secret = SecretKey::Random();
    coin.master_scan_key_id = PublicKey::From(ScanSecret()).GetID();

    const std::vector<uint8_t> bytes = coin.Serialized();
    BOOST_CHECK_EQUAL(bytes.front(), mw::Coin::LATEST_VERSION);
    BOOST_CHECK_EQUAL(mw::Coin::LATEST_VERSION, 3);
    const mw::Coin decoded = mw::Coin::Deserialize(bytes);
    BOOST_REQUIRE(decoded.master_scan_key_id.has_value());
    BOOST_CHECK(*decoded.master_scan_key_id == *coin.master_scan_key_id);
    BOOST_CHECK(decoded.output_id == coin.output_id);

    // Version 2 records (no master scan key id) still load.
    std::vector<uint8_t> v2_bytes(bytes.begin(), bytes.end() - 21);
    v2_bytes.front() = 2;
    const mw::Coin v2 = mw::Coin::Deserialize(v2_bytes);
    BOOST_CHECK(!v2.master_scan_key_id.has_value());
    BOOST_CHECK(v2.shared_secret.has_value());
    BOOST_CHECK(v2.output_id == coin.output_id);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
