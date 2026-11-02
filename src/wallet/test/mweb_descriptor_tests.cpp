// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bech32.h>
#include <chainparams.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_types.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/wallet/stealth_address.h>
#include <wallet/imweb_keystore.h>
#include <wallet/mweb_keychain_util.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <array>
#include <boost/test/unit_test.hpp>

namespace wallet {
namespace {

class TestMWEBKeyStore final : public IMWEBKeyStore
{
public:
    std::unique_ptr<CKeyMetadata> GetMetadata(const StealthAddress&) const override { return nullptr; }
    bool GetKey(const CKeyID&, CKey&) const override { return false; }
    bool HaveKey(const CKeyID&) const override { return false; }
};

static std::unique_ptr<Descriptor> ParseMWEBDesc(const std::string& desc_str, FlatSigningProvider& keys)
{
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    return std::move(descs.at(0));
}

static bool DeriveMastersFromSeedKey(const CKey& seed, SecretKey& scan_secret, SecretKey& spend_secret)
{
    CExtKey master;
    master.SetSeed(seed);
    return DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret);
}

//! A descriptor SPKM that is not registered with its wallet.
class StandaloneDescriptorSPKM final : public DescriptorScriptPubKeyMan
{
public:
    StandaloneDescriptorSPKM(WalletStorage& storage, WalletDescriptor& descriptor)
        : DescriptorScriptPubKeyMan(storage, descriptor, /*keypool_size=*/10) {}
};

BOOST_AUTO_TEST_SUITE(mweb_descriptor_tests)

BOOST_FIXTURE_TEST_CASE(mweb_account_descriptor_parse, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master_key;
    master_key.SetSeed(seed);

    const WalletDescriptor w_desc = GenerateWalletDescriptor(master_key.Neuter(), OutputType::MWEB, false);
    BOOST_REQUIRE(w_desc.descriptor);
    BOOST_CHECK(w_desc.descriptor->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
    BOOST_CHECK(!w_desc.descriptor->IsRange());
    const std::optional<OutputType> out_type = w_desc.descriptor->GetOutputType();
    BOOST_REQUIRE(out_type.has_value());
    BOOST_CHECK(*out_type == OutputType::MWEB);

    const std::string desc_body = w_desc.descriptor->ToString().substr(0, w_desc.descriptor->ToString().find('#'));
    BOOST_CHECK(desc_body.find("/100h/240079435h/0h,") != std::string::npos || desc_body.find("/100'/240079435'/0',") != std::string::npos);
    BOOST_CHECK(desc_body.find("/100h/240079435h/1h,*") != std::string::npos || desc_body.find("/100'/240079435'/1',*") != std::string::npos);
    BOOST_CHECK(desc_body.starts_with("mweb("));

    FlatSigningProvider keys;
    const std::string legacy = "mweb(" + EncodeExtPubKey(master_key.Neuter()) + "/0h/100h)";
    std::string error;
    BOOST_CHECK(Parse(legacy, keys, error, false).empty());
}

BOOST_FIXTURE_TEST_CASE(mweb_internal_external_parse_and_expand, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(seed, scan_secret, spend_secret));

    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(2);

    CPubKey spend(addr.GetSpendPubKey().vec());
    CPubKey scan(addr.GetScanPubKey().vec());

    FlatSigningProvider keys;
    const std::string internal_str = strprintf("mweb(%s,%s,2,qj8x4s2a)", HexStr(scan), HexStr(spend));
    auto internal = ParseMWEBDesc(internal_str, keys);
    BOOST_CHECK(internal->GetMWEBForm() == MWEBDescriptorForm::INTERNAL);
    BOOST_REQUIRE(internal->GetMWEBAccountChecksum());
    BOOST_CHECK_EQUAL(*internal->GetMWEBAccountChecksum(), "qj8x4s2a");
    BOOST_REQUIRE(internal->GetMWEBIndex());
    BOOST_CHECK_EQUAL(*internal->GetMWEBIndex(), 2u);

    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_REQUIRE(internal->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr));
    BOOST_REQUIRE_EQUAL(dests.size(), 1);
    const StealthAddress* expanded = std::get_if<StealthAddress>(&dests[0]);
    BOOST_REQUIRE(expanded);
    BOOST_CHECK(*expanded == addr);

    // Two public keys are the single-subaddress form with a public scan key a*G, not an address.
    const CPubKey scan_master(PublicKey::From(scan_secret).vec());
    const std::string single_str = strprintf("mweb(%s,%s)", HexStr(scan_master), HexStr(spend));
    auto single = ParseMWEBDesc(single_str, keys);
    BOOST_CHECK(single->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
    BOOST_CHECK(!single->GetMWEBAccountChecksum());
    BOOST_CHECK(!single->GetMWEBIndex());
    BOOST_REQUIRE(single->GetMWEBScanPubKey(keys));
    BOOST_CHECK(*single->GetMWEBScanPubKey(keys) == scan_master);

    dests.clear();
    BOOST_CHECK(!single->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr));

    FlatSigningProvider with_scan;
    CKey scan_key;
    scan_key.Set(scan_secret.data(), scan_secret.data() + SecretKey::SIZE, /*fCompressedIn=*/true);
    with_scan.keys.emplace(scan_master.GetID(), scan_key);
    BOOST_REQUIRE(single->ExpandDestinations(0, with_scan, dests, out, nullptr, nullptr));
    BOOST_REQUIRE_EQUAL(dests.size(), 1);
    expanded = std::get_if<StealthAddress>(&dests[0]);
    BOOST_REQUIRE(expanded);
    BOOST_CHECK(*expanded == addr);

    const std::string roundtrip_body = single->ToString().substr(0, single->ToString().find('#'));
    BOOST_CHECK_EQUAL(roundtrip_body, single_str);
}

BOOST_FIXTURE_TEST_CASE(mweb_account_does_not_expand_destinations, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master_key;
    master_key.SetSeed(seed);
    const WalletDescriptor w_desc = GenerateWalletDescriptor(master_key.Neuter(), OutputType::MWEB, false);

    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_CHECK(!w_desc.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr));
}

BOOST_FIXTURE_TEST_CASE(output_type_from_stealth_address, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(seed, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(2);
    const std::optional<OutputType> type = OutputTypeFromDestination(CTxDestination{addr});
    BOOST_REQUIRE(type.has_value());
    BOOST_CHECK(*type == OutputType::MWEB);
}

BOOST_FIXTURE_TEST_CASE(mweb_getnewdestination_ismine, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "recv");
    BOOST_REQUIRE(dest);
    BOOST_CHECK(m_wallet.IsMine(*dest));

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);
    LOCK(mweb_spk->cs_desc_man);
    BOOST_CHECK(mweb_spk->GetWalletDescriptor().descriptor->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
    BOOST_CHECK_EQUAL(mweb_spk->GetMWEBInternalWalletDescriptors().size(), 3u);
}

BOOST_FIXTURE_TEST_CASE(mweb_pegin_address, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    StealthAddress pegin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetStealthAddress(mw::PEGIN_INDEX, pegin));
    BOOST_CHECK(m_wallet.IsMine(pegin));
}

//! Decodes a Litecoin "ltcmweb1..." address; the payload layout is the same on every chain.
static StealthAddress DecodeLitecoinStealthAddress(const std::string& str)
{
    const auto dec = bech32::Decode(str, bech32::CharLimit::MWEB);
    BOOST_REQUIRE(dec.encoding == bech32::Encoding::BECH32);
    BOOST_REQUIRE_EQUAL(dec.hrp, "ltcmweb");
    BOOST_REQUIRE(!dec.data.empty() && dec.data[0] == 0);
    std::vector<uint8_t> payload;
    const bool converted = ConvertBits<5, 8, false>([&](unsigned char c) { payload.push_back(c); }, dec.data.begin() + 1, dec.data.end());
    BOOST_REQUIRE(converted);
    BOOST_REQUIRE_EQUAL(payload.size(), 66U);
    return StealthAddress(PublicKey(BigInt<33>(payload.data())), PublicKey(BigInt<33>(payload.data() + 33)));
}

// Known-answer vectors from Litecoin Core v0.21.5.8 (scriptpubkeyman_tests StealthAddresses)
// along m/0'/100' plus Zorkcoin's default MWEB account path (m/100'/240079435' on mainnet).
BOOST_FIXTURE_TEST_CASE(mweb_seed_known_answer, WalletTestingSetup)
{
    // The key of Litecoin WIF 6usgJoGKXW12i7Ruxy8Z1C5hrRMVGfLmi9NU9uDQJMPXDJ6tQAH.
    const std::vector<unsigned char> seed_bytes = ParseHex("63227045132b2c5c3c992f427b646fd7fb2532fb1a4d6f5758bcfdbd3fea3ca3");
    CKey seed;
    seed.Set(seed_bytes.begin(), seed_bytes.end(), /*fCompressedIn=*/false);
    BOOST_REQUIRE(seed.IsValid());

    CExtKey master;
    master.SetSeed(seed);

    // 1. Litecoin Core v0.21.5.8 known-answer vectors along m/0'/100'/{0',1'}.
    CExtKey ltc_acct, ltc_scan_ext, ltc_spend_ext;
    BOOST_REQUIRE(master.Derive(ltc_acct, BIP32_HARDENED_FLAG | 0));
    BOOST_REQUIRE(ltc_acct.Derive(ltc_acct, BIP32_HARDENED_FLAG | 100));
    BOOST_REQUIRE(ltc_acct.Derive(ltc_scan_ext, BIP32_HARDENED_FLAG | 0));
    BOOST_REQUIRE(ltc_acct.Derive(ltc_spend_ext, BIP32_HARDENED_FLAG | 1));
    const SecretKey ltc_scan = KeyToSecretKey(ltc_scan_ext.key);
    const SecretKey ltc_spend = KeyToSecretKey(ltc_spend_ext.key);
    BOOST_CHECK_EQUAL(ltc_spend.ToHex(), "2396e5c33b07dfa2d9e70da1dcbdad0ad2399e5672ff2d4afbe3b20bccf3ba1b");
    BOOST_CHECK_EQUAL(ltc_scan.ToHex(), "918271168655385e387907612ee09d755be50c4685528f9f53eabae380ecba97");

    TestMWEBKeyStore keystore;
    const auto ltc_keychain = MakeMWEBKeychain(keystore, ltc_scan, ltc_spend);
    const StealthAddress ltc_change_address = DecodeLitecoinStealthAddress(
        "ltcmweb1qq20e2arnhvxw97katjkmsd35agw3capxjkrkh7dk8d30rczm8ypxuq329nwh2twmchhqn3jqh7ua4ps539f6aazh79jy76urqht4qa59ts3at6gf");
    const StealthAddress ltc_pegin_address = DecodeLitecoinStealthAddress(
        "ltcmweb1qqg5hddkl4uhspjwg9tkmatxa4s6gswdaq9swl8vsg5xxznmye7phcqatzc62mzkg788tsrfcuegxe9q3agf5cplw7ztqdusqf7x3n2tl55x4gvyt");
    const StealthAddress ltc_receive_address = DecodeLitecoinStealthAddress(
        "ltcmweb1qq0yq03ewm830ugmkkvrvjmyyeslcpwk8ayd7k27qx63sryy6kx3ksqm3k6jd24ld3r5dp5lzx7rm7uyxfujf8sn7v4nlxeqwrcq6k6xxwqdc6tl3");
    BOOST_CHECK(ltc_keychain->GetStealthAddress(mw::CHANGE_INDEX) == ltc_change_address);
    BOOST_CHECK(ltc_keychain->GetStealthAddress(mw::PEGIN_INDEX) == ltc_pegin_address);
    BOOST_CHECK(ltc_keychain->GetStealthAddress(2) == ltc_receive_address);

    // 2. Zorkcoin default mainnet account path (m/100'/240079435'/{0',1'}).
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(seed, scan_secret, spend_secret));
    BOOST_CHECK_EQUAL(spend_secret.ToHex(), "ffce40d58fe05935b1b3cbf984f25401242635799b048caee9dde5ecd593d16c");
    BOOST_CHECK_EQUAL(scan_secret.ToHex(), "372bd9106da610fbe7a6412207ebf7ff0d00048a20505e12112bd5de05ab0c35");

    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress change_address = keychain->GetStealthAddress(mw::CHANGE_INDEX);
    const StealthAddress pegin_address = keychain->GetStealthAddress(mw::PEGIN_INDEX);
    const StealthAddress receive_address = keychain->GetStealthAddress(2);

    // A wallet built from that seed owns the change and peg-in addresses, and hands out
    // index 2 as its first receive address.
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    WalletBatch batch(m_wallet.GetDatabase());
    m_wallet.SetupDescriptorScriptPubKeyMans(batch, master);

    BOOST_CHECK(m_wallet.IsMine(CTxDestination{change_address}));
    BOOST_CHECK(m_wallet.IsMine(CTxDestination{pegin_address}));
    const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "");
    BOOST_REQUIRE(dest);
    const StealthAddress* first = std::get_if<StealthAddress>(&*dest);
    BOOST_REQUIRE(first);
    BOOST_CHECK(*first == receive_address);
}

static CTransactionRef MWEBOnlyTransaction(Output output)
{
    const Kernel kernel = Kernel::Create(BlindingFactor::Random(), std::nullopt, 0, std::nullopt, {}, std::nullopt);
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mw::Transaction::Create(
        BlindingFactor::Random(), BlindingFactor::Random(), {}, {std::move(output)}, {kernel}));
    return MakeTransactionRef(std::move(tx));
}

// A mempool transaction whose output to us carries a malformed Ke or Ko must not throw
// out of the wallet callback or be stored; the well-formed original is stored.
BOOST_FIXTURE_TEST_CASE(mweb_mempool_callback_ignores_malformed_output_keys, WalletTestingSetup)
{
    StealthAddress receive_address;
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();
        const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "");
        BOOST_REQUIRE(dest);
        receive_address = std::get<StealthAddress>(*dest);
    }

    constexpr CAmount amount = 1'234'567;
    const Output valid_output = Output::Create(nullptr, SecretKey::Random(), SecretKey::Random(), receive_address, amount, {});

    std::array<uint8_t, 33> malformed_bytes{};
    malformed_bytes[0] = 0x04;
    const PublicKey malformed_key(malformed_bytes.data());
    BOOST_REQUIRE(!malformed_key.IsValid());
    const auto with_keys = [&](const PublicKey& key_exchange, const PublicKey& receiver) {
        return Output(
            valid_output.GetCommitment(),
            valid_output.GetSenderPubKey(),
            receiver,
            OutputMessage(valid_output.GetFeatures(),
                          OutputStandardFields(key_exchange, valid_output.GetViewTag(), valid_output.GetMaskedValue(), valid_output.GetMaskedNonce())),
            valid_output.GetRangeProof(),
            valid_output.GetSignature());
    };

    for (const Output& malformed : {with_keys(malformed_key, valid_output.Ko()), with_keys(valid_output.Ke(), malformed_key)}) {
        const CTransactionRef tx = MWEBOnlyTransaction(malformed);
        const size_t wallet_size = WITH_LOCK(m_wallet.cs_wallet, return m_wallet.mapWallet.size());
        BOOST_CHECK_NO_THROW(m_wallet.transactionAddedToMempool(tx));
        BOOST_CHECK_EQUAL(WITH_LOCK(m_wallet.cs_wallet, return m_wallet.mapWallet.size()), wallet_size);
        mw::Coin stored_coin;
        BOOST_CHECK(!m_wallet.GetMWWallet()->GetCoin(malformed.GetOutputID(), stored_coin));
    }

    const CTransactionRef valid_tx = MWEBOnlyTransaction(valid_output);
    BOOST_CHECK_NO_THROW(m_wallet.transactionAddedToMempool(valid_tx));
    BOOST_CHECK_EQUAL(WITH_LOCK(m_wallet.cs_wallet, return m_wallet.mapWallet.count(valid_tx->GetHash())), 1U);
    mw::Coin stored_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(valid_output.GetOutputID(), stored_coin));
    BOOST_CHECK_EQUAL(stored_coin.address_index, 2U);
    BOOST_CHECK_EQUAL(stored_coin.amount, amount);
}

BOOST_FIXTURE_TEST_CASE(mweb_parser_index_and_key_rules, BasicTestingSetup)
{
    CKey scan_key = GenerateRandomKey();
    CKey spend_key = GenerateRandomKey();
    const std::string scan_wif = EncodeSecret(scan_key);
    const std::string spend_hex = HexStr(spend_key.GetPubKey());
    const std::string scan_hex = HexStr(scan_key.GetPubKey());

    const auto parses = [](const std::string& desc_str) {
        FlatSigningProvider keys;
        std::string error;
        return !Parse(desc_str, keys, error, /*require_checksum=*/false).empty();
    };

    // Indexed and wallet-internal indices: decimal, no sign, no leading zeros, below 2^31.
    static const std::string VALID_INDICES[] = {"0", "7", "2147483647"};
    for (const std::string& index : VALID_INDICES) {
        BOOST_CHECK_MESSAGE(parses(strprintf("mweb(%s,%s,%s)", scan_wif, spend_hex, index)), index);
        BOOST_CHECK_MESSAGE(parses(strprintf("mweb(%s,%s,%s,qj8x4s2a)", scan_hex, spend_hex, index)), index);
    }
    static const std::string INVALID_INDICES[] = {
        "2147483648", "4294967294", "4294967295", "4294967296",
        "+5", "-1", "05", "00", "", " 5", "0x5",
    };
    for (const std::string& index : INVALID_INDICES) {
        BOOST_CHECK_MESSAGE(!parses(strprintf("mweb(%s,%s,%s)", scan_wif, spend_hex, index)), index);
        BOOST_CHECK_MESSAGE(!parses(strprintf("mweb(%s,%s,%s,qj8x4s2a)", scan_hex, spend_hex, index)), index);
    }
    FlatSigningProvider index_keys;
    std::string index_error;
    const auto max_indexed = Parse(strprintf("mweb(%s,%s,2147483647)", scan_wif, spend_hex), index_keys, index_error, false);
    BOOST_REQUIRE(!max_indexed.empty());
    BOOST_CHECK_EQUAL(*max_indexed.at(0)->GetMWEBIndex(), MWEB_MAX_DESCRIPTOR_INDEX);

    // Uncompressed keys are rejected in every argument.
    CKey uncompressed;
    uncompressed.Set(scan_key.begin(), scan_key.end(), /*fCompressedIn=*/false);
    const std::string uncompressed_wif = EncodeSecret(uncompressed);
    const std::string uncompressed_hex = HexStr(uncompressed.GetPubKey());
    BOOST_CHECK(!parses(strprintf("mweb(%s,%s,*)", uncompressed_wif, spend_hex)));
    BOOST_CHECK(!parses(strprintf("mweb(%s,%s)", scan_wif, uncompressed_hex)));
    BOOST_CHECK(!parses(strprintf("mweb(%s,%s)", uncompressed_hex, spend_hex)));
    BOOST_CHECK(!parses(strprintf("mweb(%s,%s,3)", scan_wif, uncompressed_wif)));
    BOOST_CHECK(!parses(strprintf("mweb(%s,%s,3,qj8x4s2a)", uncompressed_hex, spend_hex)));

    // A public scan key may be paired with a private spend key.
    FlatSigningProvider keys;
    std::string error;
    const auto pub_priv = Parse(strprintf("mweb(%s,%s)", scan_hex, EncodeSecret(spend_key)), keys, error, false);
    BOOST_REQUIRE_MESSAGE(!pub_priv.empty(), error);
    BOOST_CHECK(pub_priv.at(0)->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
    std::optional<CKey> scan_out;
    std::optional<CKey> spend_out;
    BOOST_CHECK(!pub_priv.at(0)->GetMWEBScanSpendKeys(keys, scan_out, spend_out));
    BOOST_CHECK(spend_out.has_value());
}

BOOST_FIXTURE_TEST_CASE(mweb_descriptor_string_is_not_a_destination, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(seed, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(2);
    CPubKey spend(addr.GetSpendPubKey().vec());
    CPubKey scan(addr.GetScanPubKey().vec());

    const std::string pubkey_pair = strprintf("mweb(%s,%s)", HexStr(scan), HexStr(spend));
    std::string error;
    BOOST_CHECK(!IsValidDestination(DecodeDestination(pubkey_pair, error)));
    BOOST_CHECK(IsValidDestination(DecodeDestination(EncodeDestination(addr), error)));
}

BOOST_FIXTURE_TEST_CASE(mweb_multi_account_internal_linkage, BasicTestingSetup)
{
    CKey seed_a = GenerateRandomKey();
    CKey seed_b = GenerateRandomKey();
    CExtKey master_a;
    CExtKey master_b;
    master_a.SetSeed(seed_a);
    master_b.SetSeed(seed_b);

    const WalletDescriptor account_a = GenerateWalletDescriptor(master_a.Neuter(), OutputType::MWEB, false);
    const WalletDescriptor account_b = GenerateWalletDescriptor(master_b.Neuter(), OutputType::MWEB, false);
    const std::string cksum_a = account_a.descriptor->ToString().substr(account_a.descriptor->ToString().find('#') + 1, 8);
    const std::string cksum_b = account_b.descriptor->ToString().substr(account_b.descriptor->ToString().find('#') + 1, 8);
    BOOST_CHECK_NE(cksum_a, cksum_b);

    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(seed_a, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(4);
    CPubKey spend(addr.GetSpendPubKey().vec());
    CPubKey scan(addr.GetScanPubKey().vec());

    FlatSigningProvider keys;
    const std::string internal_a = strprintf("mweb(%s,%s,4,%s)", HexStr(scan), HexStr(spend), cksum_a);
    const std::string internal_b = strprintf("mweb(%s,%s,4,%s)", HexStr(scan), HexStr(spend), cksum_b);
    auto desc_a = ParseMWEBDesc(internal_a, keys);
    auto desc_b = ParseMWEBDesc(internal_b, keys);
    BOOST_CHECK_EQUAL(*desc_a->GetMWEBAccountChecksum(), cksum_a);
    BOOST_CHECK_EQUAL(*desc_b->GetMWEBAccountChecksum(), cksum_b);
    BOOST_CHECK_EQUAL(*desc_a->GetMWEBIndex(), 4u);
    BOOST_CHECK_EQUAL(*desc_b->GetMWEBIndex(), 4u);
}

BOOST_FIXTURE_TEST_CASE(mweb_lookahead_window_bounds, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "recv");
    BOOST_REQUIRE(dest);

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);
    LOCK(mweb_spk->cs_desc_man);
    const mw::Keychain::Ptr keychain = mweb_spk->GetMWEBKeychain();
    BOOST_REQUIRE(keychain);

    const int64_t window = m_wallet.GetMWEBKeypoolSize();
    const uint32_t next = mweb_spk->GetWalletDescriptor().GetNext();
    BOOST_REQUIRE_GT(next + window, 500);

    const StealthAddress in_window = keychain->GetStealthAddress(500);
    BOOST_CHECK(m_wallet.IsMine(in_window));
    BOOST_CHECK_EQUAL(keychain->LookupAddressIndex(in_window).value_or(0), 500u);

    const StealthAddress past_window = keychain->GetStealthAddress(next + window);
    BOOST_CHECK(!m_wallet.IsMine(past_window));
    BOOST_CHECK(!mweb_spk->GetMetadata(past_window));
}

// An MWEB account without its own keychain (here a fully public descriptor, so no scan
// secret) must not borrow the wallet's default keychain, which belongs to another account.
BOOST_FIXTURE_TEST_CASE(mweb_account_without_keychain_derives_nothing, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const mw::Keychain::Ptr& wallet_default = m_wallet.GetWalletMWEBKeychain();
    BOOST_REQUIRE(wallet_default && wallet_default->HasSpendPubKey());

    CExtKey master;
    master.SetSeed(GenerateRandomKey());
    const std::string xpub = EncodeExtPubKey(master.Neuter());
    FlatSigningProvider keys;
    WalletDescriptor w_desc(ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,*)", xpub, xpub), keys),
                            /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    StandaloneDescriptorSPKM account(m_wallet, w_desc);
    BOOST_REQUIRE(!account.GetMWEBKeychain());

    BOOST_CHECK(!account.CanGetAddresses());
    BOOST_CHECK(!account.GetNewDestination(OutputType::MWEB));
}

BOOST_FIXTURE_TEST_CASE(mweb_ischange_per_account, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);

    StealthAddress change_addr;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*mweb_spk, change_addr));
    BOOST_CHECK(m_wallet.GetMWWallet()->IsChange(change_addr));

    const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "recv");
    BOOST_REQUIRE(dest);
    const StealthAddress* recv = std::get_if<StealthAddress>(&*dest);
    BOOST_REQUIRE(recv);
    BOOST_CHECK(!m_wallet.GetMWWallet()->IsChange(*recv));

    StealthAddress repeated_change;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*mweb_spk, repeated_change));
    BOOST_CHECK(repeated_change == change_addr);

    // Changing the active receive account preserves the old account's fixed
    // change address and its classification.
    CExtKey second_master;
    second_master.SetSeed(GenerateRandomKey());
    WalletBatch batch(m_wallet.GetDatabase());
    auto& second_account = m_wallet.SetupDescriptorScriptPubKeyMan(batch, second_master, OutputType::MWEB, false);
    BOOST_REQUIRE(m_wallet.GetExternalMWEBScriptPubKeyMan() == &second_account);
    BOOST_REQUIRE(m_wallet.GetExternalMWEBScriptPubKeyMan() != mweb_spk);
    StealthAddress second_change;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(second_account, second_change));
    BOOST_CHECK(second_change != change_addr);
    BOOST_CHECK(m_wallet.GetMWWallet()->IsChange(second_change));
    BOOST_CHECK(m_wallet.GetMWWallet()->IsChange(change_addr));
    BOOST_CHECK(!m_wallet.GetMWWallet()->IsChange(*recv));
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*mweb_spk, repeated_change));
    BOOST_CHECK(repeated_change == change_addr);
}

BOOST_FIXTURE_TEST_CASE(mweb_get_mweb_account_for_coin, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    const util::Result<CTxDestination> dest = m_wallet.GetNewDestination(OutputType::MWEB, "recv");
    BOOST_REQUIRE(dest);
    const StealthAddress* addr = std::get_if<StealthAddress>(&*dest);
    BOOST_REQUIRE(addr);

    DescriptorScriptPubKeyMan* account_spk = m_wallet.GetMWEBAccountForStealthAddress(*addr);
    BOOST_REQUIRE(account_spk);

    mw::Coin coin;
    coin.address = *addr;
    coin.address_index = 2;
    coin.amount = 1 * COIN;
    BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(coin) == account_spk);
}

BOOST_FIXTURE_TEST_CASE(mweb_rewind_known_coin_uses_owner_account, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account_a = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account_a);

    CKey seed_b = GenerateRandomKey();
    CExtKey master_b;
    master_b.SetSeed(seed_b);
    WalletBatch batch(m_wallet.GetDatabase());
    DescriptorScriptPubKeyMan& account_b = m_wallet.SetupDescriptorScriptPubKeyMan(batch, master_b, OutputType::MWEB, false);
    BOOST_REQUIRE(m_wallet.GetMWEBAccountScriptPubKeyMans().size() >= 2);
    BOOST_REQUIRE(account_a != &account_b);

    StealthAddress addr_b;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(account_b, 2, addr_b));
    {
        LOCK(account_b.cs_desc_man);
        account_b.PersistMWEBInternalIndex(batch, 2, addr_b);
    }

    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), addr_b, 1 * COIN);

    mw::Coin coin;
    coin.address = addr_b;
    coin.address_index = 2;
    coin.amount = 1 * COIN;
    coin.output_id = output.GetOutputID();
    coin.spend_key = SecretKey::Random();
    m_wallet.GetMWWallet()->LoadToWallet(coin);

    const int64_t before_a = WITH_LOCK(account_a->cs_desc_man, return account_a->GetMWEBInternalLastActive(2));
    const int64_t before_b = WITH_LOCK(account_b.cs_desc_man, return account_b.GetMWEBInternalLastActive(2));

    mw::Coin rewound;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, rewound));
    BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(rewound) == &account_b);

    const int64_t after_a = WITH_LOCK(account_a->cs_desc_man, return account_a->GetMWEBInternalLastActive(2));
    const int64_t after_b = WITH_LOCK(account_b.cs_desc_man, return account_b.GetMWEBInternalLastActive(2));
    BOOST_CHECK_EQUAL(after_a, before_a);
    BOOST_CHECK(after_b >= before_b);
    BOOST_CHECK(after_b > 0);
}

BOOST_FIXTURE_TEST_CASE(mweb_upgrade_coins_multi_account, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    CKey seed_b = GenerateRandomKey();
    CExtKey master_b;
    master_b.SetSeed(seed_b);
    WalletBatch batch(m_wallet.GetDatabase());
    DescriptorScriptPubKeyMan& account_b = m_wallet.SetupDescriptorScriptPubKeyMan(batch, master_b, OutputType::MWEB, false);

    StealthAddress addr_b;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(account_b, 2, addr_b));
    {
        LOCK(account_b.cs_desc_man);
        account_b.PersistMWEBInternalIndex(batch, 2, addr_b);
        account_b.LoadMWEBKeychain();
    }
    const mw::Keychain::Ptr keychain_b = WITH_LOCK(account_b.cs_desc_man, return account_b.GetMWEBKeychain());
    BOOST_REQUIRE(keychain_b);
    BOOST_REQUIRE(keychain_b->HasSpendSecret());

    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), addr_b, 2 * COIN);
    mw::Coin coin;
    BOOST_REQUIRE(keychain_b->RewindOutput(output, coin));
    BOOST_REQUIRE(coin.HasSpendKey());
    BOOST_REQUIRE(coin.HasSharedSecret());
    coin.spend_key = std::nullopt;
    BOOST_REQUIRE(!coin.HasSpendKey());

    CMutableTransaction mtx;
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const Txid wtx_hash = tx->GetHash();
    auto ret = m_wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(wtx_hash), std::forward_as_tuple(tx, TxStateInactive{}));
    BOOST_REQUIRE(ret.second);
    ret.first->second.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    m_wallet.GetMWWallet()->LoadToWallet(coin);

    BOOST_REQUIRE(m_wallet.GetMWWallet()->UpgradeCoins());

    mw::Coin upgraded;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(coin.output_id, upgraded));
    BOOST_CHECK(upgraded.HasSpendKey());
    BOOST_CHECK(upgraded.HasSpendMaterial());
    BOOST_CHECK(m_wallet.mapWallet.at(wtx_hash).mweb_wtx_info->received_coin->HasSpendKey());

    // Disk form must never retain spend material.
    const mw::Coin disk_form = upgraded.SanitizeForDisk();
    BOOST_CHECK(!disk_form.HasSpendMaterial());
    BOOST_CHECK(disk_form.HasSharedSecret());
}


BOOST_FIXTURE_TEST_CASE(mweb_select_master_secrets_bip32_only, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const CExtPubKey xpub = master.Neuter();

    SecretKey bip32_scan;
    SecretKey bip32_spend;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, bip32_scan, bip32_spend));

    SecretKey selected_scan;
    SecretKey selected_spend;
    BOOST_REQUIRE(SelectMWEBAccountMasterSecrets(xpub, master.key, SecretKey::Null(),
                                                 selected_scan, selected_spend));
    BOOST_CHECK(selected_scan == bip32_scan);
    BOOST_CHECK(selected_spend == bip32_spend);

    BOOST_REQUIRE(SelectMWEBAccountMasterSecrets(xpub, master.key, bip32_scan,
                                                 selected_scan, selected_spend));
    BOOST_CHECK(selected_scan == bip32_scan);

    // Wrong preferred scan must fail (no SetSeed fallback).
    SecretKey other_scan;
    SecretKey other_spend;
    CKey other_seed = GenerateRandomKey();
    BOOST_REQUIRE(DeriveMastersFromSeedKey(other_seed, other_scan, other_spend));
    BOOST_CHECK(!SelectMWEBAccountMasterSecrets(xpub, master.key, other_scan,
                                                selected_scan, selected_spend));
}

BOOST_FIXTURE_TEST_CASE(mweb_default_account_path, BasicTestingSetup)
{
    const std::vector<uint32_t> expected_main{100 | BIP32_HARDENED_FLAG, 240079435 | BIP32_HARDENED_FLAG};
    const std::vector<uint32_t> expected_test{100 | BIP32_HARDENED_FLAG, 1 | BIP32_HARDENED_FLAG};
    BOOST_CHECK(CreateChainParams(*m_node.args, ChainType::MAIN)->MWEBAccountPath() == expected_main);
    for (const ChainType chain : {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        BOOST_CHECK(CreateChainParams(*m_node.args, chain)->MWEBAccountPath() == expected_test);
    }

    const CExtKey master = DecodeExtKey("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    BOOST_CHECK(!scan_secret.IsNull());
    BOOST_CHECK(!spend_secret.IsNull());

    const std::string xpub = EncodeExtPubKey(master.Neuter());
    const std::string desc = GenerateWalletDescriptor(master.Neuter(), OutputType::MWEB, false).descriptor->ToString();
    BOOST_CHECK_EQUAL(desc.substr(0, desc.find('#')), "mweb(" + xpub + "/100h/240079435h/0h," + xpub + "/100h/240079435h/1h,*)");
}

BOOST_FIXTURE_TEST_CASE(mweb_wallet_keychain_matches_exported_account_xprv, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);
    LOCK(mweb_spk->cs_desc_man);
    mweb_spk->LoadMWEBKeychain();
    const SecretKey wallet_scan = mweb_spk->GetMWEBScanSecret();
    BOOST_REQUIRE(!wallet_scan.IsNull());

    std::string priv_desc;
    BOOST_REQUIRE(mweb_spk->GetDescriptorString(priv_desc, /*priv=*/true));
    // mweb(xprv/100h/240079435h/0h,xprv/100h/240079435h/1h,*)#checksum
    const auto body_end = priv_desc.find('#');
    BOOST_REQUIRE(body_end != std::string::npos);
    const std::string body = priv_desc.substr(0, body_end);
    BOOST_REQUIRE(body.starts_with("mweb("));
    BOOST_CHECK(body.find("/100h/240079435h/0h,") != std::string::npos);
    BOOST_CHECK(body.find("/100h/240079435h/1h,*") != std::string::npos);

    // Extract the shared root xprv from the first KEY expression.
    const std::string after_mweb = body.substr(5);
    const auto first_comma = after_mweb.find(',');
    BOOST_REQUIRE(first_comma != std::string::npos);
    const std::string scan_key_expr = after_mweb.substr(0, first_comma);
    const auto path_pos = scan_key_expr.find("/100h/240079435h/0h");
    BOOST_REQUIRE(path_pos != std::string::npos);
    const CExtKey master_root = DecodeExtKey(scan_key_expr.substr(0, path_pos));
    BOOST_REQUIRE(master_root.key.IsValid());

    SecretKey bip32_scan;
    SecretKey bip32_spend;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master_root, bip32_scan, bip32_spend));
    BOOST_CHECK(wallet_scan == bip32_scan);
}

BOOST_FIXTURE_TEST_CASE(mweb_internal_import_rejects_wrong_keys, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);
    LOCK(mweb_spk->cs_desc_man);
    mweb_spk->LoadMWEBKeychain();
    const mw::Keychain::Ptr keychain = mweb_spk->GetMWEBKeychain();
    BOOST_REQUIRE(keychain);
    BOOST_REQUIRE(keychain->HasSpendSecret());

    const std::string acct_cksum = mweb_spk->GetMWEBAccountChecksum();
    BOOST_REQUIRE(!acct_cksum.empty());

    // Honest keys at a non-reserved index must load.
    {
        const StealthAddress addr = keychain->GetStealthAddress(5);
        const CPubKey spend(addr.GetSpendPubKey().vec());
        const CPubKey scan(addr.GetScanPubKey().vec());
        FlatSigningProvider keys;
        auto parsed = ParseMWEBDesc(strprintf("mweb(%s,%s,5,%s)", HexStr(scan), HexStr(spend), acct_cksum), keys);
        WalletDescriptor w_desc(std::shared_ptr<Descriptor>(std::move(parsed)), GetTime(), 0, 0, 0);
        BOOST_REQUIRE(mweb_spk->LoadMWEBInternalDescriptorRecord(w_desc));
    }

    // Wrong (Ai,Bi) for a valid checksum/index must be rejected (would poison spend key maps).
    {
        CKey other_seed = GenerateRandomKey();
        SecretKey other_scan;
        SecretKey other_spend;
        BOOST_REQUIRE(DeriveMastersFromSeedKey(other_seed, other_scan, other_spend));
        TestMWEBKeyStore other_store;
        const auto other_keychain = MakeMWEBKeychain(other_store, other_scan, other_spend);
        const StealthAddress wrong_addr = other_keychain->GetStealthAddress(5);
        const CPubKey spend(wrong_addr.GetSpendPubKey().vec());
        const CPubKey scan(wrong_addr.GetScanPubKey().vec());
        FlatSigningProvider keys;
        auto parsed = ParseMWEBDesc(strprintf("mweb(%s,%s,5,%s)", HexStr(scan), HexStr(spend), acct_cksum), keys);
        WalletDescriptor w_desc(std::shared_ptr<Descriptor>(std::move(parsed)), GetTime(), 0, 0, 0);
        const auto loaded = mweb_spk->LoadMWEBInternalDescriptorRecord(w_desc);
        BOOST_CHECK(!loaded);
        BOOST_CHECK(util::ErrorString(loaded).original.find("do not match account derivation") != std::string::npos);
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_internal_record_bookkeeping, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* mweb_spk = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(mweb_spk);
    LOCK(mweb_spk->cs_desc_man);
    mweb_spk->LoadMWEBKeychain();
    const mw::Keychain::Ptr keychain = mweb_spk->GetMWEBKeychain();
    BOOST_REQUIRE(keychain && keychain->HasSpendSecret());
    const std::string acct_cksum = mweb_spk->GetMWEBAccountChecksum();

    // A loaded record is prunable until a saved tag says otherwise.
    const StealthAddress addr5 = keychain->GetStealthAddress(5);
    {
        FlatSigningProvider keys;
        auto parsed = ParseMWEBDesc(strprintf("mweb(%s,%s,5,%s)", HexStr(CPubKey(addr5.GetScanPubKey().vec())),
                                              HexStr(CPubKey(addr5.GetSpendPubKey().vec())), acct_cksum), keys);
        WalletDescriptor w_desc(std::shared_ptr<Descriptor>(std::move(parsed)), GetTime(), 0, 0, 0);
        BOOST_REQUIRE(mweb_spk->LoadMWEBInternalDescriptorRecord(w_desc));
    }
    BOOST_CHECK(mweb_spk->GetMWEBInternalProtect(5) == DescriptorScriptPubKeyMan::MWEBInternalProtect::NONE);

    // An occupied index accepts only its own address.
    WalletBatch batch(m_wallet.GetDatabase());
    BOOST_CHECK(mweb_spk->PersistMWEBInternalIndex(batch, 5, addr5));
    BOOST_CHECK(!mweb_spk->PersistMWEBInternalIndex(batch, 5, keychain->GetStealthAddress(6)));
    // A new index refuses an address the account does not derive there.
    BOOST_CHECK(!mweb_spk->PersistMWEBInternalIndex(batch, 7, keychain->GetStealthAddress(8)));

    // The account finds its own addresses, including recorded ones, and not others.
    BOOST_CHECK_EQUAL(mweb_spk->FindMWEBAccountAddressIndex(addr5).value_or(0), 5u);
    BOOST_CHECK_EQUAL(mweb_spk->FindMWEBAccountAddressIndex(keychain->GetStealthAddress(900)).value_or(0), 900u);
    BOOST_CHECK(!mweb_spk->FindMWEBAccountAddressIndex(StealthAddress::Random()));

    // The master spend secret is recovered from a subaddress spend key and accepted only when it is the account's.
    const SecretKey b = keychain->GetSpendSecret();
    const SecretKey a = keychain->GetScanSecret();
    const SecretKey recovered = mw::RecoverMasterSpendSecret(mw::DeriveSubaddressSpendKey(b, a, 42), a, 42);
    BOOST_CHECK(recovered == b);
    BOOST_CHECK(PublicKey::From(recovered) == *keychain->GetSpendPubKey());
    BOOST_CHECK(mweb_spk->AddMWEBAccountSpendSecret(batch, b));
    BOOST_CHECK(!mweb_spk->AddMWEBAccountSpendSecret(batch, SecretKey::Random()));
}

BOOST_FIXTURE_TEST_CASE(mweb_account_spend_key_slot, BasicTestingSetup)
{
    // An account takes a stored master spend key only when its spend argument is that plain key;
    // an xpub with a path would need the BIP32 parent.
    CKey scan = GenerateRandomKey();
    CKey spend = GenerateRandomKey();
    const CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    FlatSigningProvider probe;
    probe.keys.emplace(spend.GetPubKey().GetID(), spend);

    FlatSigningProvider keys;
    auto plain = ParseMWEBDesc(strprintf("mweb(%s,%s,*)", EncodeSecret(scan), HexStr(spend.GetPubKey())), keys);
    std::optional<CKey> scan_out;
    std::optional<CKey> spend_out;
    plain->GetMWEBScanSpendKeys(probe, scan_out, spend_out);
    BOOST_CHECK(spend_out && spend_out->GetPubKey() == spend.GetPubKey());

    keys = {};
    auto xpub_path = ParseMWEBDesc(strprintf("mweb(%s,%s/1,*)", EncodeSecret(scan), EncodeExtPubKey(master.Neuter())), keys);
    CExtKey child;
    BOOST_REQUIRE(master.Derive(child, 1));
    FlatSigningProvider child_probe;
    child_probe.keys.emplace(child.key.GetPubKey().GetID(), child.key);
    xpub_path->GetMWEBScanSpendKeys(child_probe, scan_out, spend_out);
    BOOST_CHECK(!spend_out);
}

BOOST_FIXTURE_TEST_CASE(mweb_lip_forms_parse_roundtrip, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());

    FlatSigningProvider keys;
    auto ranged = ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,*)", xprv, xprv), keys);
    BOOST_CHECK(ranged->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);

    keys = {};
    auto indexed = ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,7)", xprv, xpub), keys);
    BOOST_CHECK(indexed->GetMWEBForm() == MWEBDescriptorForm::INDEXED);
    BOOST_REQUIRE(indexed->GetMWEBIndex());
    BOOST_CHECK_EQUAL(*indexed->GetMWEBIndex(), 7u);

    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(3);
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);
    const CPubKey spend_pub(addr.GetSpendPubKey().vec());

    keys = {};
    auto single = ParseMWEBDesc(strprintf("mweb(%s,%s)", EncodeSecret(scan_key), HexStr(spend_pub)), keys);
    BOOST_CHECK(single->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_REQUIRE(single->ExpandDestinations(0, keys, dests, out, nullptr, nullptr));
    BOOST_REQUIRE_EQUAL(dests.size(), 1);
    BOOST_CHECK(*std::get_if<StealthAddress>(&dests[0]) == addr);

    // A public scan key with a private spend key parses; it expands only once the scan secret is known.
    keys = {};
    auto swapped = ParseMWEBDesc(strprintf("mweb(%s,%s)", HexStr(spend_pub), EncodeSecret(scan_key)), keys);
    BOOST_CHECK(swapped->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
    dests.clear();
    BOOST_CHECK(!swapped->ExpandDestinations(0, keys, dests, out, nullptr, nullptr));
}

BOOST_FIXTURE_TEST_CASE(mweb_two_arg_extended_spend_is_ranged, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);

    const std::string spend_paths[] = {
        strprintf("%s/0h/100h/1h", xprv),
        strprintf("[d34db33f/0h]%s/0h/100h/1h", xprv),
        strprintf("%s/1", xpub),
    };
    for (const std::string& spend : spend_paths) {
        FlatSigningProvider keys;
        auto desc = ParseMWEBDesc(strprintf("mweb(%s,%s)", EncodeSecret(scan_key), spend), keys);
        BOOST_CHECK(desc->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
        BOOST_CHECK(desc->ToString().ends_with(",*)") || desc->ToString().find(",*)#") != std::string::npos);
    }

    // A plain spend pubkey keeps the single-subaddress meaning.
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    FlatSigningProvider keys;
    auto single = ParseMWEBDesc(strprintf("mweb(%s,%s)", EncodeSecret(scan_key), HexStr(keychain->GetStealthAddress(2).GetSpendPubKey().vec())), keys);
    BOOST_CHECK(single->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
}

BOOST_FIXTURE_TEST_CASE(mweb_normalization_preserves_keys_origins_and_implicit_wildcard, BasicTestingSetup)
{
    CExtKey master;
    master.SetSeed(GenerateRandomKey());
    const auto derive = [&](uint32_t branch) {
        CExtKey key = master, child;
        for (const uint32_t index : {0x80000000U, 0x80000064U, 0x80000000U | branch}) {
            BOOST_REQUIRE(key.Derive(child, index));
            key = child;
        }
        return key;
    };
    const CExtKey scan = derive(0), spend = derive(1);
    const std::string scan_expr = strprintf("[11223344/5h]%s/0h/100h/0h", EncodeExtKey(master));
    const std::string spend_expr = strprintf("[11223344/5h]%s/0h/100h/1h", EncodeExtKey(master));
    const auto checksum = [](const std::string& text) { return text + "#" + GetDescriptorChecksum(text); };
    for (const std::string suffix : {"", ",*", ",7"}) {
        BOOST_TEST_CONTEXT("suffix " << suffix) {
            FlatSigningProvider keys;
            auto descriptor = ParseMWEBDesc(strprintf("mweb(%s,%s%s)", scan_expr, spend_expr, suffix), keys);
            std::string normalized;
            BOOST_REQUIRE(descriptor->ToNormalizedString(keys, normalized));
            const std::string normalized_suffix = suffix == ",7" ? ",7" : ",*";
            const std::string expected = checksum(strprintf(
                "mweb([11223344/5h/0h/100h/0h]%s,[11223344/5h/0h/100h/1h]%s%s)",
                EncodeExtPubKey(scan.Neuter()), EncodeExtPubKey(spend.Neuter()), normalized_suffix));
            BOOST_CHECK_EQUAL(normalized, expected);
            std::string private_string;
            BOOST_REQUIRE(descriptor->ToPrivateString(keys, private_string));
            BOOST_CHECK_EQUAL(private_string, checksum(strprintf("mweb(%s,%s%s)", scan_expr, spend_expr, normalized_suffix)));
            FlatSigningProvider expanded;
            descriptor->ExpandPrivate(0, keys, expanded);
            BOOST_REQUIRE_EQUAL(expanded.keys.size(), 2U);
            BOOST_CHECK(expanded.keys.at(scan.key.GetPubKey().GetID()) == scan.key);
            BOOST_CHECK(expanded.keys.at(spend.key.GetPubKey().GetID()) == spend.key);
            if (suffix == ",7") {
                std::vector<CTxDestination> destinations;
                FlatSigningProvider output;
                BOOST_REQUIRE(descriptor->ExpandDestinations(0, keys, destinations, output, nullptr, nullptr));
                BOOST_REQUIRE_EQUAL(destinations.size(), 1U);
                const SecretKey a{reinterpret_cast<const uint8_t*>(scan.key.data())};
                BOOST_CHECK(std::get<StealthAddress>(destinations.front()) ==
                    mw::DeriveSubaddress(PublicKey{spend.key.GetPubKey().data()}, a, 7));
                const auto& origin = output.origins.at(spend.key.GetPubKey().GetID()).second;
                BOOST_CHECK(origin.path == std::vector<uint32_t>({0x80000005U, 0x80000000U, 0x80000064U, 0x80000001U}));
                BOOST_CHECK(HexStr(origin.fingerprint) == "11223344");
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_lip_reject_and_public_account_parse, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());

    FlatSigningProvider keys;
    std::string error;

    // Bad third argument fails at parse.
    BOOST_CHECK(Parse(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,bogus)", xprv, xpub), keys, error, false).empty());
    BOOST_CHECK(error.find("third argument") != std::string::npos || error.find("uint32") != std::string::npos ||
                error.find("'*'") != std::string::npos);

    // A public scan key with a private spend key parses (pub,priv); import needs the wallet's scan secret.
    keys = {};
    error.clear();
    CKey scan_seed = GenerateRandomKey();
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(scan_seed, scan_secret, spend_secret));
    CKey spend_ckey;
    spend_ckey.Set(spend_secret.vec().begin(), spend_secret.vec().end(), true);
    const CPubKey scan_pub(PublicKey::From(scan_secret).vec());
    auto pub_priv = Parse(strprintf("mweb(%s,%s)", HexStr(scan_pub), EncodeSecret(spend_ckey)), keys, error, false);
    BOOST_REQUIRE_MESSAGE(!pub_priv.empty(), error);
    BOOST_CHECK(pub_priv.at(0)->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);

    // Fully public ranged account string parses (scan privacy enforced at import/use).
    keys = {};
    error.clear();
    auto public_account = Parse(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,*)", xpub, xpub), keys, error, false);
    BOOST_REQUIRE_MESSAGE(!public_account.empty(), error);
    BOOST_CHECK(public_account.at(0)->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
}

BOOST_FIXTURE_TEST_CASE(mweb_account_tostring_shapes, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());

    FlatSigningProvider keys;
    auto watch = ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,*)", xprv, xpub), keys);
    BOOST_CHECK(watch->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);

    const std::string pub_str = watch->ToString();
    // Spend side remains the public KEY expression in the parsed watch form.
    BOOST_CHECK(pub_str.find("/0h/100h/1h,*") != std::string::npos || pub_str.find("/0'/100'/1',*") != std::string::npos);

    std::string priv_str;
    BOOST_REQUIRE(watch->ToPrivateString(keys, priv_str));
    BOOST_CHECK(priv_str.find("mweb(") == 0);

    keys = {};
    auto both_priv = ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s/0h/100h/1h,*)", xprv, xprv), keys);
    std::string both_priv_str;
    BOOST_REQUIRE(both_priv->ToPrivateString(keys, both_priv_str));
    BOOST_CHECK(both_priv_str.find(xprv) != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(mweb_single_subaddr_expand_requires_scan_priv, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(4);
    const CPubKey spend_pub(addr.GetSpendPubKey().vec());
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);

    FlatSigningProvider keys;
    auto single = ParseMWEBDesc(strprintf("mweb(%s,%s)", EncodeSecret(scan_key), HexStr(spend_pub)), keys);
    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_REQUIRE(single->ExpandDestinations(0, keys, dests, out, nullptr, nullptr));
    BOOST_CHECK(*std::get_if<StealthAddress>(&dests[0]) == addr);

    // Without the scan private key in the provider, Expand fails unless keychain supplies it.
    dests.clear();
    FlatSigningProvider empty;
    BOOST_CHECK(!single->ExpandDestinations(0, empty, dests, out, nullptr, nullptr));
    BOOST_REQUIRE(single->ExpandDestinations(0, empty, dests, out, nullptr, keychain.get()));
    BOOST_CHECK(*std::get_if<StealthAddress>(&dests[0]) == addr);

    // Public listing form mweb(xpub/path, B_i) must parse as SINGLE for wallet DB round-trip.
    const std::string xpub = EncodeExtPubKey(master.Neuter());
    FlatSigningProvider pub_keys;
    auto pub_single = ParseMWEBDesc(strprintf("mweb(%s/0h/100h/0h,%s)", xpub, HexStr(spend_pub)), pub_keys);
    BOOST_CHECK(pub_single->GetMWEBForm() == MWEBDescriptorForm::SINGLE_SUBADDR);
}

BOOST_FIXTURE_TEST_CASE(mweb_single_subaddr_survives_scan_map_reload, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMastersFromSeedKey(GenerateRandomKey(), scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const StealthAddress addr = MakeMWEBKeychain(keystore, scan_secret, spend_secret)->GetStealthAddress(3);
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);

    FlatSigningProvider keys;
    auto desc = ParseMWEBDesc(strprintf("mweb(%s,%s)", EncodeSecret(scan_key), HexStr(addr.GetSpendPubKey().vec())), keys);
    WalletDescriptor w_desc(std::move(desc), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    auto added = m_wallet.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
    BOOST_REQUIRE_MESSAGE(added, util::ErrorString(added).original);
    DescriptorScriptPubKeyMan& single = added->get();
    BOOST_REQUIRE(single.IsMine(addr));

    // A UTXO scan, rescan or import scan ends by clearing its ephemeral indices.
    WITH_LOCK(single.cs_desc_man, single.ClearEphemeralMWEBIndices());
    BOOST_CHECK(single.IsMine(addr));
    BlindingFactor blind;
    mw::Coin coin;
    BOOST_CHECK(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), addr, COIN), coin));

    WITH_LOCK(single.cs_desc_man, single.ReloadMWEBScanMapsFromInternalDescriptors());
    BOOST_CHECK(single.IsMine(addr));
}

BOOST_FIXTURE_TEST_CASE(mweb_indexed_expands_to_keychain_address, BasicTestingSetup)
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());

    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);
    const StealthAddress addr = keychain->GetStealthAddress(7);

    FlatSigningProvider keys;
    auto indexed = ParseMWEBDesc(strprintf("mweb(%s/100h/240079435h/0h,%s/100h/240079435h/1h,7)", xprv, xpub), keys);
    BOOST_CHECK(indexed->GetMWEBForm() == MWEBDescriptorForm::INDEXED);

    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_REQUIRE(indexed->ExpandDestinations(0, keys, dests, out, nullptr, nullptr));
    BOOST_REQUIRE_EQUAL(dests.size(), 1);
    BOOST_CHECK(*std::get_if<StealthAddress>(&dests[0]) == addr);
}

static uint32_t MWEBNextIndex(DescriptorScriptPubKeyMan& spk)
{
    LOCK(spk.cs_desc_man);
    return static_cast<uint32_t>(spk.GetWalletDescriptor().GetNext());
}

BOOST_FIXTURE_TEST_CASE(mweb_lookahead_moves_with_payments, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.m_mweb_keypool_size = 20;
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    const uint32_t next = MWEBNextIndex(*account);
    BOOST_CHECK_EQUAL(WITH_LOCK(account->cs_desc_man, return account->GetMWEBLookaheadCount()), 20u);

    const uint32_t paid_index = next + 19;
    const StealthAddress paid = keychain->GetStealthAddress(paid_index);
    BOOST_REQUIRE(m_wallet.IsMine(paid));
    BOOST_CHECK(!m_wallet.IsMine(keychain->GetStealthAddress(next + 20)));
    BOOST_CHECK(!m_wallet.FindAddressBookEntry(CTxDestination{paid}));

    BlindingFactor blind;
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), paid, COIN), coin));
    BOOST_CHECK_EQUAL(coin.address_index, paid_index);

    BOOST_CHECK_EQUAL(MWEBNextIndex(*account), paid_index + 1);
    BOOST_CHECK(m_wallet.IsMine(keychain->GetStealthAddress(paid_index + 20)));
    BOOST_CHECK(!m_wallet.IsMine(keychain->GetStealthAddress(paid_index + 21)));
    const CAddressBookData* entry = m_wallet.FindAddressBookEntry(CTxDestination{paid});
    BOOST_REQUIRE(entry);
    BOOST_CHECK(entry->purpose == AddressPurpose::RECEIVE);

    // A payment below the next index leaves it where it is.
    const StealthAddress earlier = keychain->GetStealthAddress(next + 2);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), earlier, COIN), coin));
    BOOST_CHECK_EQUAL(MWEBNextIndex(*account), paid_index + 1);
}

BOOST_FIXTURE_TEST_CASE(mweb_lookahead_survives_scan_map_reload, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.m_mweb_keypool_size = 10;
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    const StealthAddress last_watched = keychain->GetStealthAddress(MWEBNextIndex(*account) + 9);
    BOOST_REQUIRE(m_wallet.IsMine(last_watched));
    const size_t internal_before = m_wallet.CountMWEBInternalDescriptors();

    WITH_LOCK(account->cs_desc_man, account->ClearEphemeralMWEBIndices());
    BOOST_CHECK(m_wallet.IsMine(last_watched));
    WITH_LOCK(account->cs_desc_man, account->ReloadMWEBScanMapsFromInternalDescriptors());
    BOOST_CHECK(m_wallet.IsMine(last_watched));

    // The window is never written: only used indices get internal descriptors.
    BOOST_CHECK_EQUAL(m_wallet.CountMWEBInternalDescriptors(), internal_before);
}

BOOST_FIXTURE_TEST_CASE(mweb_lookahead_watch_only_account, WalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    m_wallet.m_mweb_keypool_size = 15;

    CExtKey master;
    master.SetSeed(GenerateRandomKey());
    SecretKey scan_secret;
    SecretKey spend_secret;
    BOOST_REQUIRE(DeriveMWEBMasterSecretsFromAccountKey(master, scan_secret, spend_secret));
    TestMWEBKeyStore keystore;
    const auto device_keychain = MakeMWEBKeychain(keystore, scan_secret, spend_secret);

    // The account export a signing device gives a watch-only wallet: scan secret and spend pubkey.
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);
    CKey spend_key;
    spend_key.Set(spend_secret.vec().begin(), spend_secret.vec().end(), true);
    FlatSigningProvider keys;
    auto desc = ParseMWEBDesc(strprintf("mweb(%s,%s,*)", EncodeSecret(scan_key), HexStr(spend_key.GetPubKey())), keys);
    WalletDescriptor w_desc(std::move(desc), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    auto added = m_wallet.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
    BOOST_REQUIRE_MESSAGE(added, util::ErrorString(added).original);
    DescriptorScriptPubKeyMan& account = added->get();
    const mw::Keychain::Ptr keychain = WITH_LOCK(account.cs_desc_man, return account.GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    BOOST_REQUIRE(keychain->HasSpendPubKey());
    BOOST_REQUIRE(!keychain->HasSpendSecret());

    // Addresses the device handed out, never by this wallet.
    const StealthAddress paid = device_keychain->GetStealthAddress(14);
    BOOST_REQUIRE(m_wallet.IsMine(paid));
    BOOST_CHECK(!m_wallet.IsMine(device_keychain->GetStealthAddress(15)));

    BlindingFactor blind;
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), paid, COIN), coin));
    BOOST_CHECK(!coin.HasSpendKey());
    BOOST_CHECK_EQUAL(MWEBNextIndex(account), 15u);
    BOOST_CHECK(m_wallet.IsMine(device_keychain->GetStealthAddress(29)));
    BOOST_CHECK(!m_wallet.IsMine(device_keychain->GetStealthAddress(30)));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
