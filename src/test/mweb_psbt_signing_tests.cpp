// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_psbt.h>

#include <key.h>
#include <key_io.h>
#include <mw/crypto/key_derivation.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/psbt.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <optional>
#include <string>

using namespace psbt_test;

namespace {

//! In-memory key store with no wallet behind it.
class MockMWEBKeyStore final : public MWEBSigningKeyStore
{
public:
    std::map<mw::Hash, mw::Coin> m_coins;
    std::optional<SecretKey> m_coin_scan_secret;
    std::vector<SecretKey> m_scan_secrets;
    std::map<StealthAddress, std::optional<SecretKey>> m_subaddresses;
    std::optional<std::string> m_inferred_descriptor;

    std::optional<mw::Coin> GetCoin(const mw::Hash& output_id) const override
    {
        const auto it = m_coins.find(output_id);
        return it == m_coins.end() ? std::nullopt : std::make_optional(it->second);
    }
    std::optional<SecretKey> GetScanSecret(const mw::Coin&) const override { return m_coin_scan_secret; }
    std::vector<SecretKey> GetScanSecrets() const override { return m_scan_secrets; }
    bool IsMine(const StealthAddress& address) const override { return m_subaddresses.contains(address); }
    std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress& address) const override
    {
        const auto it = m_subaddresses.find(address);
        return it == m_subaddresses.end() ? std::nullopt : it->second;
    }
    std::optional<std::string> InferAddressDescriptor(const mw::Coin&) const override { return m_inferred_descriptor; }
};

//! Deterministic MWEB master keypair with subaddress and descriptor derivation.
struct MWEBTestKeys {
    SecretKey scan_secret;
    SecretKey master_spend_secret;

    static MWEBTestKeys Create(char scan_hex_char = '1', char spend_hex_char = '2')
    {
        return MWEBTestKeys{TestSecret(scan_hex_char), TestSecret(spend_hex_char)};
    }

    SecretKey SubaddressSpendSecret(uint32_t index) const
    {
        return mw::DeriveSubaddressSpendKey(master_spend_secret, scan_secret, index);
    }

    StealthAddress Address(uint32_t index) const
    {
        return mw::DeriveSubaddress(PublicKey::From(master_spend_secret), scan_secret, index);
    }

    //! Single-index mweb() descriptor carrying both private keys.
    std::string Descriptor(uint32_t index) const
    {
        return strprintf("mweb(%s,%s,%u)", EncodeSecret(ToCKey(scan_secret)), EncodeSecret(ToCKey(master_spend_secret)), index);
    }

    //! Ranged account descriptor; with a public spend key unless spend_private.
    std::string AccountDescriptor(bool spend_private) const
    {
        const std::string spend = spend_private ? EncodeSecret(ToCKey(master_spend_secret)) : HexStr(PublicKey::From(master_spend_secret).vec());
        return strprintf("mweb(%s,%s,*)", EncodeSecret(ToCKey(scan_secret)), spend);
    }

    PublicKey OutputPubKey(uint32_t index, const SecretKey& shared_secret) const
    {
        return mw::DeriveOutputPubKey(Address(index), shared_secret);
    }
};

mw::SenderKeyGenerator TestSenderKeyGenerator()
{
    return []() -> util::Result<SecretKey> { return SecretKey::Random(); };
}

//! An MWEB-to-MWEB transaction: one input (100k), one output (90k), fee kernel (10k).
PartiallySignedTransaction SignableMWEBPSBT(const mw::Hash& input_output_id, const SecretKey& input_shared_secret, const StealthAddress& recipient)
{
    CMutableTransaction mtx;

    mw::MutableInput input(input_output_id);
    input.amount = 100'000;
    mtx.mweb_tx.inputs.push_back(std::move(input));

    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = recipient;
    mtx.mweb_tx.outputs.push_back(std::move(output));

    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs.back().mweb_amount = 100'000;
    psbt.inputs.back().mweb_shared_secret = input_shared_secret;
    return psbt;
}

//! A peg-in: canonical peg-in output (placeholder script), one MWEB output (90k), peg-in kernel (100k, fee 10k).
CMutableTransaction PeginTx(const StealthAddress& recipient, CAmount pegin_vout_amount = 100'000)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(pegin_vout_amount, GetScriptForPegin(mw::Hash{}));

    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = recipient;
    mtx.mweb_tx.outputs.push_back(std::move(output));

    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.pegin = 100'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    return mtx;
}

//! An MWEB input owned by keys at index, spendable with only the PSBT's own fields and a private 0x96.
PartiallySignedTransaction KeylessSignablePSBT(const MWEBTestKeys& keys, uint32_t index, const SecretKey& shared_secret)
{
    PartiallySignedTransaction psbt = SignableMWEBPSBT(TestHash(0x31), shared_secret, keys.Address(0));
    psbt.inputs[0].mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);
    psbt.inputs[0].mweb_address_descriptor = keys.Descriptor(index);
    return psbt;
}

std::unique_ptr<Descriptor> ParseOne(const std::string& str, FlatSigningProvider& keys)
{
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> descs = Parse(str, keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    return std::move(descs.front());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_signing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shared_secret_ecdh_symmetric)
{
    const SecretKey a = TestSecret('1');
    const SecretKey e = TestSecret('2');

    BOOST_CHECK(mw::RecoverSharedSecret(PublicKey::From(e), a) == mw::RecoverSharedSecret(PublicKey::From(a), e));
    BOOST_CHECK(!(mw::RecoverSharedSecret(PublicKey::From(e), a) == mw::RecoverSharedSecret(PublicKey::From(e), e)));
}

BOOST_AUTO_TEST_CASE(parse_address_descriptor_forms)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    // Indexed form with both private keys.
    util::Result<MWEBAddressDescriptorData> indexed = ParseMWEBAddressDescriptor(keys.Descriptor(7));
    BOOST_REQUIRE(bool{indexed});
    BOOST_CHECK(indexed->address == keys.Address(7));
    BOOST_CHECK(indexed->scan_secret == std::optional<SecretKey>{keys.scan_secret});
    BOOST_CHECK(indexed->subaddress_spend_secret == std::optional<SecretKey>{keys.SubaddressSpendSecret(7)});
    BOOST_CHECK(indexed->index == std::optional<uint32_t>{7});

    // Indexed form with a public master spend key: the address and scan secret, but no spend secret.
    const std::string watch_only = strprintf("mweb(%s,%s,7)", EncodeSecret(ToCKey(keys.scan_secret)), HexStr(PublicKey::From(keys.master_spend_secret).vec()));
    util::Result<MWEBAddressDescriptorData> public_spend = ParseMWEBAddressDescriptor(watch_only);
    BOOST_REQUIRE(bool{public_spend});
    BOOST_CHECK(public_spend->address == keys.Address(7));
    BOOST_CHECK(public_spend->scan_secret.has_value());
    BOOST_CHECK(!public_spend->subaddress_spend_secret.has_value());

    // Single-subaddress form with the subaddress spend secret.
    const std::string single = strprintf("mweb(%s,%s)", EncodeSecret(ToCKey(keys.scan_secret)), EncodeSecret(ToCKey(keys.SubaddressSpendSecret(4))));
    util::Result<MWEBAddressDescriptorData> single_data = ParseMWEBAddressDescriptor(single);
    BOOST_REQUIRE(bool{single_data});
    BOOST_CHECK(single_data->address == keys.Address(4));
    BOOST_CHECK(single_data->subaddress_spend_secret == std::optional<SecretKey>{keys.SubaddressSpendSecret(4)});
    BOOST_CHECK(!single_data->index.has_value());

    // A ranged account is not a single address.
    util::Result<MWEBAddressDescriptorData> account = ParseMWEBAddressDescriptor(keys.AccountDescriptor(/*spend_private=*/true));
    BOOST_REQUIRE(!account);
    BOOST_CHECK(util::ErrorString(account).original.find("single-address") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolve_from_descriptor_private_keys)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{3};
    const SecretKey shared_secret = TestSecret('c');

    PSBTInput input = MWEBInput(TestHash(1));
    input.mweb_address_descriptor = keys.Descriptor(index);
    input.mweb_shared_secret = shared_secret;
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    const EmptyMWEBSigningKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());

    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
    BOOST_CHECK(**result == mw::DeriveOutputSpendKey(keys.SubaddressSpendSecret(index), shared_secret));
}

BOOST_AUTO_TEST_CASE(resolve_infers_descriptor_from_coin)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{0};
    const mw::Hash output_id = TestHash(2);
    const SecretKey shared_secret = TestSecret('d');

    MockMWEBKeyStore keystore;
    mw::Coin coin;
    coin.output_id = output_id;
    coin.shared_secret = shared_secret;
    keystore.m_coins[output_id] = coin;
    keystore.m_inferred_descriptor = keys.Descriptor(index);

    PSBTInput input = MWEBInput(output_id);
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});

    BOOST_CHECK(input.mweb_address_descriptor == keystore.m_inferred_descriptor);
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == shared_secret);
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_populates_id_only_input_from_coin)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{2};
    const mw::Hash output_id = TestHash(20);
    const SecretKey shared_secret = TestSecret('d');
    const BlindingFactor blind = BlindingFactor::FromHex(std::string(64, '3'));

    mw::Coin coin;
    coin.address_index = index;
    coin.address = keys.Address(index);
    coin.amount = 125'000;
    coin.blind = blind;
    coin.output_id = output_id;
    coin.shared_secret = shared_secret;

    MockMWEBKeyStore keystore;
    keystore.m_coins[output_id] = coin;
    keystore.m_inferred_descriptor = keys.Descriptor(index);

    PSBTInput input = MWEBInput(output_id);
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());

    BOOST_CHECK(input.mweb_amount == std::optional<CAmount>{coin.amount});
    BOOST_CHECK(input.mweb_output_commit == std::optional<Commitment>{Commitment::Switch(blind, coin.amount)});
    BOOST_CHECK(input.mweb_output_pubkey == std::optional<PublicKey>{keys.OutputPubKey(index, shared_secret)});
    BOOST_CHECK(input.mweb_shared_secret == std::optional<SecretKey>{shared_secret});
    BOOST_CHECK(input.mweb_address_descriptor == keystore.m_inferred_descriptor);
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_derives_shared_secret_from_key_exchange_pubkey)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{1};
    const PublicKey key_exchange_pubkey = PublicKey::From(TestSecret('e'));
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, keys.scan_secret);

    PSBTInput input = MWEBInput(TestHash(3));
    input.mweb_address_descriptor = keys.Descriptor(index);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = keys.OutputPubKey(index, expected_secret);

    const EmptyMWEBSigningKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_scan_only_account_exports_shared_secret)
{
    const SecretKey scan_secret = TestSecret('4');
    const PublicKey key_exchange_pubkey = PublicKey::From(TestSecret('5'));
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, scan_secret);
    const mw::Hash output_id = TestHash(9);

    MockMWEBKeyStore keystore;
    keystore.m_coin_scan_secret = scan_secret;
    mw::Coin coin;
    coin.output_id = output_id;
    coin.address_index = 2;
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);

    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->has_value());
    BOOST_REQUIRE(input.mweb_shared_secret);
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
}

BOOST_AUTO_TEST_CASE(resolve_descriptor_precedes_account_scan_secret)
{
    const MWEBTestKeys descriptor_keys = MWEBTestKeys::Create('6', '7');
    const PublicKey key_exchange_pubkey = PublicKey::From(TestSecret('9'));
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, descriptor_keys.scan_secret);
    const mw::Hash output_id = TestHash(10);

    MockMWEBKeyStore keystore;
    keystore.m_coin_scan_secret = TestSecret('8');
    mw::Coin coin;
    coin.output_id = output_id;
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_address_descriptor = descriptor_keys.Descriptor(4);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = descriptor_keys.OutputPubKey(4, expected_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());
    BOOST_REQUIRE(input.mweb_shared_secret);
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_searches_store_accounts)
{
    // Two accounts; the input belongs to the second, and carries only its key exchange and output pubkeys.
    const MWEBTestKeys other = MWEBTestKeys::Create('6', '7');
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{5};
    const PublicKey key_exchange_pubkey = PublicKey::From(TestSecret('9'));
    const SecretKey shared_secret = mw::RecoverSharedSecret(key_exchange_pubkey, keys.scan_secret);

    MockMWEBKeyStore keystore;
    keystore.m_scan_secrets = {other.scan_secret, keys.scan_secret};
    keystore.m_subaddresses[other.Address(index)] = other.SubaddressSpendSecret(index);
    keystore.m_subaddresses[keys.Address(index)] = keys.SubaddressSpendSecret(index);

    PSBTInput input = MWEBInput(TestHash(11));
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(input.mweb_shared_secret == std::optional<SecretKey>{shared_secret});
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);

    // Without the owning account, nothing is resolved and nothing is written.
    keystore.m_scan_secrets = {other.scan_secret};
    PSBTInput unknown = MWEBInput(TestHash(11));
    unknown.mweb_key_exchange_pubkey = key_exchange_pubkey;
    unknown.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);
    util::Result<std::optional<SecretKey>> unresolved = ResolveMWEBInputKeys(unknown, keystore);
    BOOST_REQUIRE(bool{unresolved});
    BOOST_CHECK(!unresolved->has_value());
    BOOST_CHECK(!unknown.mweb_shared_secret.has_value());
}

BOOST_AUTO_TEST_CASE(resolve_ignores_store_spend_secret_for_other_output)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{2};
    const SecretKey shared_secret = TestSecret('c');

    MockMWEBKeyStore keystore;
    keystore.m_scan_secrets = {keys.scan_secret};
    keystore.m_subaddresses[keys.Address(index)] = TestSecret('9');

    PSBTInput input = MWEBInput(TestHash(12));
    input.mweb_shared_secret = shared_secret;
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->has_value());
}

BOOST_AUTO_TEST_CASE(resolve_descriptor_mismatch_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const SecretKey shared_secret = TestSecret('c');

    PSBTInput input = MWEBInput(TestHash(4));
    input.mweb_address_descriptor = keys.Descriptor(0);
    input.mweb_shared_secret = shared_secret;
    // Output pubkey belongs to a different address (index 5, not 0).
    input.mweb_output_pubkey = keys.OutputPubKey(5, shared_secret);

    const EmptyMWEBSigningKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(util::ErrorString(result).original.find("does not match") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolve_invalid_descriptor_is_error)
{
    PSBTInput input = MWEBInput(TestHash(5));
    input.mweb_address_descriptor = "definitely-not-a-descriptor";

    const EmptyMWEBSigningKeyStore keystore;
    BOOST_CHECK(!ResolveMWEBInputKeys(input, keystore));

    input.mweb_address_descriptor = "wpkh(xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/0h)";
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(util::ErrorString(result).original.find("wrong output type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolve_is_noop_when_data_absent)
{
    PSBTInput input = MWEBInput(TestHash(6));

    const EmptyMWEBSigningKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);

    // Not knowing the input is not an error: another signer may hold the keys.
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->has_value());
    BOOST_CHECK(!input.mweb_address_descriptor.has_value());
    BOOST_CHECK(!input.mweb_shared_secret.has_value());
}

BOOST_AUTO_TEST_CASE(resolve_preserves_existing_shared_secret)
{
    const mw::Hash output_id = TestHash(8);
    const SecretKey input_secret = TestSecret('a');

    MockMWEBKeyStore keystore;
    mw::Coin coin;
    coin.output_id = output_id;
    coin.shared_secret = TestSecret('b');
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_shared_secret = input_secret;

    BOOST_REQUIRE(bool{ResolveMWEBInputKeys(input, keystore)});
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == input_secret);
}

BOOST_AUTO_TEST_CASE(descriptor_keystore)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    {
        FlatSigningProvider provider;
        const std::unique_ptr<Descriptor> account = ParseOne(keys.AccountDescriptor(/*spend_private=*/true), provider);
        DescriptorMWEBSigningKeyStore keystore;
        BOOST_REQUIRE(bool{keystore.AddDescriptor(*account, provider, {0, 10})});
        BOOST_CHECK(keystore.GetScanSecrets() == std::vector<SecretKey>{keys.scan_secret});
        BOOST_CHECK(keystore.IsMine(keys.Address(0)));
        BOOST_CHECK(keystore.IsMine(keys.Address(10)));
        BOOST_CHECK(!keystore.IsMine(keys.Address(11)));
        BOOST_CHECK(keystore.GetSubaddressSpendSecret(keys.Address(7)) == std::optional<SecretKey>{keys.SubaddressSpendSecret(7)});
    }

    {
        FlatSigningProvider provider;
        const std::unique_ptr<Descriptor> account = ParseOne(keys.AccountDescriptor(/*spend_private=*/false), provider);
        DescriptorMWEBSigningKeyStore keystore;
        BOOST_REQUIRE(bool{keystore.AddDescriptor(*account, provider, {0, 10})});
        BOOST_CHECK(keystore.IsMine(keys.Address(3)));
        BOOST_CHECK(!keystore.GetSubaddressSpendSecret(keys.Address(3)).has_value());
    }

    {
        FlatSigningProvider provider;
        const std::unique_ptr<Descriptor> indexed = ParseOne(keys.Descriptor(42), provider);
        DescriptorMWEBSigningKeyStore keystore;
        BOOST_REQUIRE(bool{keystore.AddDescriptor(*indexed, provider, {0, 0})});
        BOOST_CHECK(keystore.IsMine(keys.Address(42)));
        BOOST_CHECK(!keystore.IsMine(keys.Address(0)));
        BOOST_CHECK(keystore.GetSubaddressSpendSecret(keys.Address(42)) == std::optional<SecretKey>{keys.SubaddressSpendSecret(42)});
    }

    {
        // A public scan key cannot recover anything, so it adds nothing.
        const StealthAddress address = keys.Address(1);
        const std::string public_address = strprintf("mweb(%s,%s)", HexStr(address.GetScanPubKey().vec()), HexStr(address.GetSpendPubKey().vec()));
        FlatSigningProvider provider;
        const std::unique_ptr<Descriptor> desc = ParseOne(public_address, provider);
        DescriptorMWEBSigningKeyStore keystore;
        BOOST_REQUIRE(bool{keystore.AddDescriptor(*desc, provider, {0, 0})});
        BOOST_CHECK(keystore.GetScanSecrets().empty());
        BOOST_CHECK(!keystore.IsMine(address));
    }
}

BOOST_AUTO_TEST_CASE(sign_mweb_end_to_end)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = TestHash(1);
    const SecretKey spend_key = TestSecret('a');

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, TestSecret('b'), keys.Address(0));
    psbt.m_tx_modifiable = std::bitset<8>{0x03};

    const std::map<mw::Hash, SecretKey> spend_keys{{output_id, spend_key}};
    util::Result<std::map<mw::Hash, mw::Coin>> coins = SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{coins});

    BOOST_REQUIRE(psbt.inputs[0].mweb_sig.has_value());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));

    BOOST_CHECK(psbt.outputs[0].mweb_commit.has_value());
    BOOST_CHECK(psbt.outputs[0].mweb_rangeproof.has_value());
    BOOST_CHECK(psbt.outputs[0].mweb_sig.has_value());

    BOOST_CHECK(psbt.kernels[0].commit.has_value());
    BOOST_CHECK(psbt.kernels[0].sig.has_value());
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});

    BOOST_CHECK(psbt.mweb_tx_offset.has_value());
    BOOST_CHECK(psbt.mweb_stealth_offset.has_value());
    BOOST_REQUIRE(psbt.m_tx_modifiable.has_value());
    BOOST_CHECK(psbt.m_tx_modifiable->none());

    BOOST_REQUIRE_EQUAL(coins->size(), 1U);
    BOOST_CHECK(coins->begin()->second.address == keys.Address(0));

    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(sign_mweb_missing_spend_key_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    const std::vector<unsigned char> before = Ser(psbt);

    util::Result<std::map<mw::Hash, mw::Coin>> coins = SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(!coins);
    BOOST_CHECK(util::ErrorString(coins).original.find("spend key") != std::string::npos);
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_CASE(sign_mweb_already_final_is_noop)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = TestHash(1);

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, TestSecret('b'), keys.Address(0));
    const std::map<mw::Hash, SecretKey> spend_keys{{output_id, TestSecret('a')}};
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator())});

    const std::vector<unsigned char> before = Ser(psbt);
    util::Result<std::map<mw::Hash, mw::Coin>> again = SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('d'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{again});
    BOOST_CHECK(again->empty());
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_CASE(sign_mweb_rewrites_pegin_placeholder)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    PartiallySignedTransaction psbt(PeginTx(keys.Address(0)), 2);
    BOOST_CHECK(HasPeginPlaceholder(psbt));
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});
    BOOST_CHECK(!HasPeginPlaceholder(psbt));

    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script.IsMWEBPegin(&script_kernel_id));
    BOOST_CHECK(!script_kernel_id.IsZero());

    const std::optional<CMutableTransaction> signed_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(signed_tx);
    BOOST_REQUIRE(signed_tx->mweb_tx.kernels[0].GetKernelID().has_value());
    BOOST_CHECK(script_kernel_id == *signed_tx->mweb_tx.kernels[0].GetKernelID());
}

BOOST_AUTO_TEST_CASE(sign_mweb_pegin_mismatch_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    {
        PartiallySignedTransaction psbt(PeginTx(keys.Address(0), /*pegin_vout_amount=*/90'000), 2);
        util::Result<std::map<mw::Hash, mw::Coin>> coins = SignPSBTMWEBComponents(psbt, {}, TestSecret('c'), TestSenderKeyGenerator());
        BOOST_REQUIRE(!coins);
        BOOST_CHECK(util::ErrorString(coins).original.find("amount does not match") != std::string::npos);
    }

    {
        CMutableTransaction mtx = PeginTx(keys.Address(0));
        mtx.vout.clear();
        PartiallySignedTransaction psbt(mtx, 2);
        util::Result<std::map<mw::Hash, mw::Coin>> coins = SignPSBTMWEBComponents(psbt, {}, TestSecret('c'), TestSenderKeyGenerator());
        BOOST_REQUIRE(!coins);
        BOOST_CHECK(util::ErrorString(coins).original.find("count does not match") != std::string::npos);
    }
}

//! Sighash data built before MWEB signing is invalidated by the peg-in script rewrite, so transparent inputs
//! must be signed against data built afterwards.
BOOST_AUTO_TEST_CASE(pegin_rewrite_invalidates_sighash)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    CKey key;
    key.MakeNewKey(true);
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    CMutableTransaction mtx = PeginTx(keys.Address(0));
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].witness_utxo = CTxOut(110'000, wpkh_script);

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());

    const std::optional<PrecomputedTransactionData> stale_txdata = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(stale_txdata);

    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});

    const std::optional<PrecomputedTransactionData> fresh_txdata = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(fresh_txdata);
    BOOST_CHECK(stale_txdata->m_outputs_single_hash != fresh_txdata->m_outputs_single_hash);

    BOOST_CHECK(SignPSBTInput(provider, psbt, 0, &*fresh_txdata, {.sighash_type = SIGHASH_ALL, .finalize = true}).has_value());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &*fresh_txdata));
}

BOOST_AUTO_TEST_CASE(fill_signs_keyless_from_private_address_descriptor)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, TestSecret('b'));

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(result->transparent_signing_allowed);
    BOOST_CHECK_EQUAL(result->n_signed, 1U);
    BOOST_CHECK_EQUAL(result->coins.size(), 1U);
    BOOST_CHECK(psbt.IsComplete());

    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted));
    BOOST_CHECK(!CTransaction(extracted).mweb_tx.IsNull());
}

BOOST_AUTO_TEST_CASE(fill_infers_fee_before_signing)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, TestSecret('b'));
    psbt.kernels[0].fee.reset();

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});
    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(fill_without_signing_only_updates)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const SecretKey shared_secret = mw::RecoverSharedSecret(PublicKey::From(TestSecret('e')), keys.scan_secret);
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, shared_secret);
    psbt.inputs[0].mweb_shared_secret.reset();
    psbt.inputs[0].mweb_key_exchange_pubkey = PublicKey::From(TestSecret('e'));

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/false, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK_EQUAL(result->n_signed, 0U);
    BOOST_CHECK(psbt.inputs[0].mweb_shared_secret == std::optional<SecretKey>{shared_secret});
    BOOST_CHECK(!psbt.inputs[0].mweb_sig.has_value());
}

BOOST_AUTO_TEST_CASE(fill_missing_signing_data_blocks_transparent_signing)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    const std::vector<unsigned char> before = Ser(psbt);

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->transparent_signing_allowed);
    BOOST_CHECK_EQUAL(result->n_signed, 0U);
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_CASE(fill_pegin_placeholder_blocks_transparent_signing_until_signed)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    CMutableTransaction mtx = PeginTx(keys.Address(0));
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));

    PartiallySignedTransaction unsigned_psbt(mtx, 2);
    util::Result<MWEBFillResult> not_signed = FillMWEBPSBT(unsigned_psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/false, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{not_signed});
    BOOST_CHECK(!not_signed->transparent_signing_allowed);
    BOOST_CHECK(HasPeginPlaceholder(unsigned_psbt));

    PartiallySignedTransaction psbt(mtx, 2);
    util::Result<MWEBFillResult> signed_result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{signed_result});
    BOOST_CHECK(signed_result->transparent_signing_allowed);
    BOOST_CHECK(!HasPeginPlaceholder(psbt));
}

BOOST_AUTO_TEST_CASE(infer_mweb_kernel_fee)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    // MWEB-only draft without a fee: the fee is inputs minus outputs minus peg-outs.
    PartiallySignedTransaction psbt = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    psbt.kernels[0].fee.reset();
    psbt.kernels[0].pegouts = {PegOutCoin{3'000, CScript() << OP_TRUE}};
    BOOST_REQUIRE(bool{InferMWEBKernelFee(psbt)});
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{7'000});
    BOOST_CHECK(psbt.kernels[0].features == std::optional<uint8_t>{Kernel::FEE_FEATURE_BIT | Kernel::PEGOUT_FEATURE_BIT});

    // An existing fee is kept.
    psbt.kernels[0].fee = 1;
    BOOST_REQUIRE(bool{InferMWEBKernelFee(psbt)});
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{1});

    // Outputs exceeding inputs.
    PartiallySignedTransaction overspend = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    overspend.kernels[0].fee.reset();
    overspend.outputs[0].amount = 100'001;
    util::Result<void> error = InferMWEBKernelFee(overspend);
    BOOST_REQUIRE(!error);
    BOOST_CHECK(util::ErrorString(error).original.find("exceed") != std::string::npos);

    // Unknown input amount: nothing to infer yet.
    PartiallySignedTransaction unknown = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    unknown.kernels[0].fee.reset();
    unknown.inputs[0].mweb_amount.reset();
    BOOST_REQUIRE(bool{InferMWEBKernelFee(unknown)});
    BOOST_CHECK(!unknown.kernels[0].fee.has_value());

    // A transparent output makes the balance ambiguous.
    PartiallySignedTransaction mixed = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    mixed.kernels[0].fee.reset();
    mixed.outputs.insert(mixed.outputs.begin(), CanonicalOutput(1'000));
    BOOST_REQUIRE(bool{InferMWEBKernelFee(mixed)});
    BOOST_CHECK(!mixed.kernels[0].fee.has_value());

    // The balance cannot be split across several kernels.
    PartiallySignedTransaction multi = SignableMWEBPSBT(TestHash(1), TestSecret('b'), keys.Address(0));
    multi.kernels[0].fee.reset();
    multi.kernels.emplace_back();
    util::Result<void> multi_error = InferMWEBKernelFee(multi);
    BOOST_REQUIRE(!multi_error);
    BOOST_CHECK(util::ErrorString(multi_error).original.find("multiple kernels") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fill_without_mweb_components_is_noop)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    psbt.m_tx_modifiable = std::bitset<8>{0x03};
    psbt.inputs.push_back(CanonicalInput(Txid::FromUint256(uint256::ONE), 0, 0xfffffffe));
    psbt.outputs.push_back(CanonicalOutput());
    const std::vector<unsigned char> before = Ser(psbt);

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(result->transparent_signing_allowed);
    BOOST_CHECK_EQUAL(result->n_signed, 0U);
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_CASE(fill_skips_signed_inputs)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, TestSecret('b'));
    BOOST_REQUIRE(bool{FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator())});
    BOOST_REQUIRE(psbt.IsComplete());

    // Key material of an already signed input is not re-checked, even if it no longer matches.
    psbt.inputs[0].mweb_address_descriptor = keys.Descriptor(8);
    const std::vector<unsigned char> before = Ser(psbt);
    util::Result<MWEBFillResult> again = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('d'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{again});
    BOOST_CHECK(again->transparent_signing_allowed);
    BOOST_CHECK_EQUAL(again->n_signed, 0U);
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_CASE(fill_missing_amount_is_missing_signing_data)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, TestSecret('b'));
    psbt.inputs[0].mweb_amount.reset();

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->transparent_signing_allowed);
    BOOST_CHECK_EQUAL(result->n_signed, 0U);
    BOOST_CHECK(!psbt.inputs[0].mweb_sig.has_value());
}

BOOST_AUTO_TEST_CASE(fill_error_leaves_psbt_unchanged)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = KeylessSignablePSBT(keys, /*index=*/9, TestSecret('b'));
    psbt.kernels[0].fee.reset();
    psbt.outputs[0].amount = 100'001;
    const std::vector<unsigned char> before = Ser(psbt);

    util::Result<MWEBFillResult> result = FillMWEBPSBT(psbt, EmptyMWEBSigningKeyStore{}, /*sign=*/true, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(!result);
    BOOST_CHECK(Ser(psbt) == before);
}

BOOST_AUTO_TEST_SUITE_END()
