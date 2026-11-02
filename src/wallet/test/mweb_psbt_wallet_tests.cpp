// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/keychain.h>
#include <mweb/mweb_wallet.h>
#include <outputtype.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/psbt.h>
#include <wallet/mweb_psbt.h>
#include <wallet/scriptpubkeyman.h>
#include <util/strencodings.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace wallet {
namespace {

StealthAddress NewMWEBAddress(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const util::Result<CTxDestination> dest = wallet.GetNewDestination(OutputType::MWEB, "");
    BOOST_REQUIRE(dest);
    const StealthAddress* addr = std::get_if<StealthAddress>(&*dest);
    BOOST_REQUIRE(addr);
    return *addr;
}

//! Spend a real 100,000-satoshi output and verify the extracted transaction.
void CheckReceivedOutputSigning(CWallet& wallet, const Output& received,
    std::optional<CAmount> input_amount = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
    mw::MutableOutput output;
    output.address = StealthAddress::Random();
    output.amount = 90'000;
    tx.mweb_tx.outputs.push_back(output);
    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    tx.mweb_tx.kernels.push_back(kernel);
    PartiallySignedTransaction psbt(tx, 2);
    // The Updater supplies the key exchange point absent from this draft.
    psbt.inputs[0].mweb_key_exchange_pubkey = received.GetKeyExchangePubKey();
    if (input_amount) psbt.inputs[0].mweb_amount = *input_amount;

    bool complete = false;
    BOOST_REQUIRE(!wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete));
    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.inputs[0].mweb_output_pubkey == received.GetReceiverPubKey());
    CMutableTransaction final_tx;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, final_tx));
    const CTransaction final{final_tx};
    BOOST_REQUIRE(final.mweb_tx.m_transaction);
    BOOST_REQUIRE_EQUAL(final.mweb_tx.m_transaction->GetInputs().size(), 1U);
    BOOST_CHECK(final.mweb_tx.m_transaction->GetInputs().front().GetOutputID() == received.GetOutputID());
    BOOST_CHECK(final.mweb_tx.m_transaction->GetInputs().front().GetOutputPubKey() == received.GetReceiverPubKey());
    BOOST_CHECK_NO_THROW(final.mweb_tx.m_transaction->Validate());
}

//! In receipt mode, sender recovery and recipient ownership coexist for one real output.
void CheckCrossAccountSelfPayments(CWallet& wallet, uint32_t recipient_index) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetMWEBDeterministicSenders(true);
    wallet.SetupDescriptorScriptPubKeyMans();
    auto* first = wallet.GetExternalMWEBScriptPubKeyMan();
    auto* second = CreateDescriptor(wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('4'))),
            EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('5')))), true);
    BOOST_REQUIRE(first && second && first != second);
    const std::array<DescriptorScriptPubKeyMan*, 2> accounts{first, second};
    std::array<mw::Keychain::Ptr, 2> keychains;
    WalletBatch batch(wallet.GetDatabase());
    for (size_t i = 0; i < accounts.size(); ++i) {
        LOCK(accounts[i]->cs_desc_man);
        accounts[i]->LoadMWEBKeychain();
        const auto keys = accounts[i]->GetMWEBKeychain();
        BOOST_REQUIRE(keys && keys->HasSpendSecret());
        BOOST_REQUIRE(accounts[i]->PersistMWEBInternalIndex(batch, recipient_index, keys->GetStealthAddress(recipient_index)));
        accounts[i]->LoadMWEBKeychain();
        keychains[i] = accounts[i]->GetMWEBKeychain();
    }
    BOOST_REQUIRE(keychains[0]->GetMasterScanKeyID() != keychains[1]->GetMasterScanKeyID());
    BOOST_REQUIRE(keychains[0]->GetSpendPubKey() != keychains[1]->GetSpendPubKey());
    BOOST_CHECK(wallet.GetExternalMWEBScriptPubKeyMan() == first);

    std::array<uint64_t, 2> expected_sender_indices{0, 0};
    const auto check_sender_indices = [&] {
        for (size_t i = 0; i < accounts.size(); ++i) {
            uint64_t index{0};
            const bool found = wallet.GetDatabase().MakeBatch()->Read(
                std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, keychains[i]->GetMasterScanKeyID()), index);
            // A fresh account need not have written its initial zero counter.
            BOOST_REQUIRE(found || expected_sender_indices[i] == 0);
            BOOST_CHECK_EQUAL(index, expected_sender_indices[i]);
        }
    };
    check_sender_indices();
    std::vector<Output> received_outputs;
    for (size_t sender = 0; sender < accounts.size(); ++sender) {
        const size_t recipient = 1 - sender;
        BOOST_TEST_CONTEXT("sender " << sender << ", recipient " << recipient << ", index " << recipient_index) {
            const StealthAddress address = keychains[recipient]->GetStealthAddress(recipient_index);
            const SecretKey sender_key = keychains[sender]->GetSenderSigningKey(0);
            const Output output = Output::Create(nullptr, sender_key, keychains[sender]->GetRewindKey(), address, 100'000, {});
            mw::Coin recipient_coin;
            BOOST_REQUIRE(keychains[recipient]->RewindOutput(output, recipient_coin));
            mw::Coin coin;
            BOOST_REQUIRE(wallet.GetMWWallet()->RewindOutput(output, coin));
            ++expected_sender_indices[sender];
            check_sender_indices();

            BOOST_CHECK(coin.output_id == output.GetOutputID());
            BOOST_CHECK_EQUAL(coin.amount, 100'000);
            BOOST_CHECK_EQUAL(coin.address_index, recipient_index);
            BOOST_CHECK(coin.IsMine());
            BOOST_CHECK_EQUAL(coin.IsChange(), recipient_index == mw::CHANGE_INDEX);
            BOOST_REQUIRE(coin.address);
            BOOST_CHECK(*coin.address == address);
            BOOST_CHECK(coin.address == recipient_coin.address);
            BOOST_CHECK(coin.shared_secret == recipient_coin.shared_secret);
            BOOST_REQUIRE(coin.shared_secret);
            BOOST_REQUIRE(coin.HasSpendMaterial());
            BOOST_CHECK(PublicKey::From(*coin.spend_key) == output.GetReceiverPubKey());
            BOOST_REQUIRE(coin.sender_key);
            BOOST_CHECK(*coin.sender_key == sender_key);
            BOOST_CHECK(wallet.GetMWEBAccountForCoin(coin) == accounts[recipient]);
            BOOST_CHECK_EQUAL(wallet.GetMWWallet()->IsChange(*coin.address), recipient_index == mw::CHANGE_INDEX);
            // This field may identify either the owner or the sender. The
            // recipient address and matching output key establish ownership.
            BOOST_REQUIRE(coin.master_scan_key_id);
            BOOST_CHECK(*coin.master_scan_key_id == keychains[sender]->GetMasterScanKeyID() ||
                *coin.master_scan_key_id == keychains[recipient]->GetMasterScanKeyID());
            mw::Coin live;
            BOOST_REQUIRE(wallet.GetMWWallet()->GetCoin(output.GetOutputID(), live));
            BOOST_CHECK(live.Serialized() == coin.Serialized());
            mw::Coin persisted;
            BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(
                std::make_pair(DBKeys::MWEB_COIN, output.GetOutputID()), persisted));
            BOOST_CHECK(!persisted.spend_key && !persisted.blind && !persisted.sender_key);
            BOOST_CHECK(persisted.Serialized() == coin.SanitizeForDisk().Serialized());
            const auto recovered_spend_key = keychains[recipient]->CalculateOutputSpendKey(persisted);
            BOOST_REQUIRE(recovered_spend_key);
            BOOST_CHECK(PublicKey::From(*recovered_spend_key) == output.GetReceiverPubKey());

            mw::Coin repeated;
            BOOST_REQUIRE(wallet.GetMWWallet()->RewindOutput(output, repeated));
            BOOST_CHECK(repeated.Serialized() == coin.Serialized());
            mw::Coin persisted_again;
            BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(
                std::make_pair(DBKeys::MWEB_COIN, output.GetOutputID()), persisted_again));
            BOOST_CHECK(persisted_again.Serialized() == persisted.Serialized());
            check_sender_indices();
            received_outputs.push_back(output);
        }
    }

    // Recovery, independent counters and durable ownership were checked before
    // FillPSBT can derive input metadata or allocate sender keys for these spends.
    for (const Output& output : received_outputs) CheckReceivedOutputSigning(wallet, output);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(signing_key_store_resolves_owned_subaddresses)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const StealthAddress addr = NewMWEBAddress(m_wallet);
    DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForStealthAddress(addr);
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr& keychain = account->GetMWEBKeychain();
    BOOST_REQUIRE(keychain);

    const WalletMWEBSigningKeyStore keystore(m_wallet);
    BOOST_CHECK(keystore.IsMine(addr));
    BOOST_CHECK(!keystore.IsMine(StealthAddress::Random()));
    BOOST_CHECK(m_wallet.MakeMWEBSigningKeyStore()->IsMine(addr));

    const std::optional<SecretKey> spend = keystore.GetSubaddressSpendSecret(addr);
    BOOST_REQUIRE(spend);
    BOOST_CHECK(PublicKey::From(*spend) == addr.B());
    BOOST_CHECK(!keystore.GetSubaddressSpendSecret(StealthAddress::Random()));

    // A lookahead index has no separately stored subaddress key. The indexed
    // derivation fallback must keep working after adding direct-key lookup.
    constexpr uint32_t lookahead_index{7};
    const StealthAddress lookahead = keychain->GetStealthAddress(lookahead_index);
    WITH_LOCK(account->cs_desc_man, BOOST_REQUIRE(account->RegisterEphemeralMWEBIndex(lookahead_index)));
    BOOST_CHECK(!account->HaveKey(lookahead.B().GetID()));
    BOOST_CHECK(keystore.IsMine(lookahead));
    const auto lookahead_spend = keystore.GetSubaddressSpendSecret(lookahead);
    BOOST_REQUIRE(lookahead_spend);
    BOOST_CHECK(*lookahead_spend == keychain->GetSpendKey(lookahead_index));
    BOOST_CHECK(PublicKey::From(*lookahead_spend) == lookahead.B());

    const std::vector<SecretKey> scan_secrets = keystore.GetScanSecrets();
    BOOST_REQUIRE_EQUAL(scan_secrets.size(), 1U);
    BOOST_CHECK(scan_secrets.front() == keychain->GetScanSecret());
    BOOST_CHECK(addr.B().Mul(scan_secrets.front()) == addr.A());

    mw::Coin coin;
    coin.address = addr;
    coin.amount = COIN;
    const std::optional<SecretKey> coin_scan = keystore.GetScanSecret(coin);
    BOOST_REQUIRE(coin_scan);
    BOOST_CHECK(*coin_scan == keychain->GetScanSecret());

    mw::Coin foreign;
    foreign.address = StealthAddress::Random();
    foreign.amount = COIN;
    BOOST_CHECK(!keystore.GetScanSecret(foreign));
    BOOST_CHECK(!keystore.InferAddressDescriptor(foreign));
    BOOST_CHECK(!keystore.GetCoin(SecretKey::Random().GetBigInt()));

    BOOST_CHECK(m_wallet.GetMWEBRewindKeyForSigning() == keychain->GetRewindKey());
}

BOOST_AUTO_TEST_CASE(address_descriptor_records_origins_and_expands_to_the_coin_address)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const StealthAddress addr = NewMWEBAddress(m_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForStealthAddress(addr);
    BOOST_REQUIRE(account);
    const std::optional<uint32_t> index = account->GetMWEBKeychain()->LookupAddressIndex(addr);
    BOOST_REQUIRE(index);

    const WalletMWEBSigningKeyStore keystore(m_wallet);
    mw::Coin coin;
    coin.address = addr;
    coin.amount = COIN;
    const std::optional<std::string> by_address = keystore.InferAddressDescriptor(coin);
    BOOST_REQUIRE(by_address);
    coin.address_index = *index;
    BOOST_CHECK_EQUAL(keystore.InferAddressDescriptor(coin).value_or(""), *by_address);
    BOOST_CHECK_EQUAL(account->GetMWEBAddressDescriptor(*index).value_or(""), *by_address);

    const std::string body = by_address->substr(0, by_address->find('#'));
    BOOST_CHECK(body.starts_with("mweb(["));
    BOOST_CHECK(body.find("/100h/240079435h/0h]") != std::string::npos);
    BOOST_CHECK(body.find("/100h/240079435h/1h]") != std::string::npos);
    BOOST_CHECK(body.ends_with(strprintf(",%u)", *index)));

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(*by_address, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    BOOST_CHECK(descs.front()->GetMWEBForm() == MWEBDescriptorForm::INDEXED);
    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    BOOST_REQUIRE(descs.front()->ExpandDestinations(0, keys, dests, out, nullptr, nullptr));
    BOOST_REQUIRE_EQUAL(dests.size(), 1U);
    BOOST_CHECK(*std::get_if<StealthAddress>(&dests.front()) == addr);

    BOOST_CHECK(!account->GetMWEBAddressDescriptor(mw::CUSTOM_KEY));
    BOOST_CHECK(!account->GetMWEBAddressDescriptor(mw::UNKNOWN_INDEX));
    const auto* l1_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
    BOOST_REQUIRE(l1_spkm);
    BOOST_CHECK(!l1_spkm->GetMWEBAddressDescriptor(0));
}

BOOST_AUTO_TEST_CASE(watch_only_account_export_mints_the_same_addresses)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const StealthAddress addr = NewMWEBAddress(m_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForStealthAddress(addr);
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr& keychain = account->GetMWEBKeychain();
    BOOST_REQUIRE(keychain && keychain->HasSpendSecret());
    const PublicKey spend_pubkey = PublicKey::From(keychain->GetSpendSecret());

    const std::optional<std::string> exported = account->GetMWEBAccountWatchOnlyDescriptor();
    BOOST_REQUIRE(exported);
    const std::string body = exported->substr(0, exported->find('#'));
    BOOST_CHECK(body.starts_with("mweb(["));
    BOOST_CHECK(body.find("/100h/240079435h/0h]") != std::string::npos);
    BOOST_CHECK(body.ends_with("/100h/240079435h/1h]" + HexStr(spend_pubkey.vec()) + ",*)"));
    BOOST_CHECK(body.find("tpub") == std::string::npos);
    BOOST_CHECK(body.find("tprv") == std::string::npos);

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(*exported, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    BOOST_CHECK(descs.front()->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
    const std::optional<CPubKey> parsed_spend = descs.front()->GetMWEBAccountSpendPubKey(keys);
    BOOST_REQUIRE(parsed_spend);
    BOOST_CHECK(PublicKey{parsed_spend->data()} == spend_pubkey);

    CWallet watch(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(watch.cs_wallet);
    watch.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    watch.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    // Indices 0 and 1 are the reserved change and peg-in addresses.
    WalletDescriptor w_desc(std::move(descs.front()), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/2);
    auto added = watch.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
    BOOST_REQUIRE_MESSAGE(added, util::ErrorString(added).original);
    DescriptorScriptPubKeyMan& watch_account = added->get();
    watch.AddActiveScriptPubKeyMan(watch_account.GetID(), OutputType::MWEB, /*internal=*/false);

    const mw::Keychain::Ptr& watch_keychain = watch_account.GetMWEBKeychain();
    BOOST_REQUIRE(watch_keychain);
    BOOST_CHECK(watch_keychain->HasSpendPubKey());
    BOOST_CHECK(!watch_keychain->HasSpendSecret());
    BOOST_CHECK(watch_keychain->GetScanSecret() == keychain->GetScanSecret());
    BOOST_CHECK(watch_keychain->GetStealthAddress(mw::CHANGE_INDEX) == keychain->GetStealthAddress(mw::CHANGE_INDEX));

    const StealthAddress watch_addr = NewMWEBAddress(watch);
    const std::optional<uint32_t> watch_index = watch_keychain->LookupAddressIndex(watch_addr);
    BOOST_REQUIRE(watch_index);
    BOOST_CHECK(*watch_index != mw::CHANGE_INDEX && *watch_index != mw::PEGIN_INDEX);
    BOOST_CHECK(keychain->GetStealthAddress(*watch_index) == watch_addr);
    BOOST_CHECK_EQUAL(watch_account.GetMWEBAccountWatchOnlyDescriptor().value_or(""), *exported);

    // A hardened spend path under an xpub hides the spend pubkey.
    std::string old_public;
    BOOST_REQUIRE(account->GetDescriptorString(old_public, /*priv=*/false));
    FlatSigningProvider old_keys;
    auto old_descs = Parse(old_public, old_keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(old_descs.size() == 1, error);
    BOOST_CHECK(old_descs.front()->GetMWEBForm() == MWEBDescriptorForm::ACCOUNT);
    BOOST_CHECK(!old_descs.front()->GetMWEBAccountSpendPubKey(old_keys));
    // The account's descriptor cache holds the hardened spend xpub.
    const DescriptorCache account_cache = WITH_LOCK(account->cs_desc_man, return account->GetWalletDescriptor().cache);
    const std::optional<CPubKey> cached_spend = old_descs.front()->GetMWEBAccountSpendPubKey(old_keys, &account_cache);
    BOOST_REQUIRE(cached_spend);
    BOOST_CHECK(PublicKey{cached_spend->data()} == spend_pubkey);
    const DescriptorCache empty_cache;
    BOOST_CHECK(!old_descs.front()->GetMWEBAccountSpendPubKey(old_keys, &empty_cache));

    const std::optional<std::string> indexed = account->GetMWEBAddressDescriptor(*watch_index);
    BOOST_REQUIRE(indexed);
    FlatSigningProvider indexed_keys;
    auto indexed_descs = Parse(*indexed, indexed_keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(indexed_descs.size() == 1, error);
    BOOST_CHECK(!indexed_descs.front()->GetMWEBAccountSpendPubKey(indexed_keys));
}

BOOST_AUTO_TEST_CASE(signing_key_store_lists_a_shared_scan_secret_once)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const StealthAddress addr = NewMWEBAddress(m_wallet);
    const DescriptorScriptPubKeyMan* account = m_wallet.GetMWEBAccountForStealthAddress(addr);
    BOOST_REQUIRE(account);
    const std::optional<std::string> exported = account->GetMWEBAccountWatchOnlyDescriptor();
    BOOST_REQUIRE(exported);

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(*exported, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    WalletDescriptor w_desc(std::move(descs.front()), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    auto added = m_wallet.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
    BOOST_REQUIRE_MESSAGE(added, util::ErrorString(added).original);
    BOOST_REQUIRE(added->get().GetMWEBKeychain());

    size_t sharing_scan{0};
    for (const DescriptorScriptPubKeyMan* spkm : m_wallet.GetMWEBAccountScriptPubKeyMans()) {
        if (spkm->GetMWEBKeychain() && spkm->GetMWEBKeychain()->GetScanSecret() == account->GetMWEBKeychain()->GetScanSecret()) ++sharing_scan;
    }
    BOOST_CHECK_EQUAL(sharing_scan, 2U);

    const std::vector<SecretKey> scan_secrets = WalletMWEBSigningKeyStore(m_wallet).GetScanSecrets();
    BOOST_REQUIRE_EQUAL(scan_secrets.size(), 1U);
    BOOST_CHECK(scan_secrets.front() == account->GetMWEBKeychain()->GetScanSecret());
}

BOOST_AUTO_TEST_CASE(shared_scan_accounts_rewind_and_sign_their_own_outputs)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* first = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(first);
    const auto first_keys = WITH_LOCK(first->cs_desc_man, return first->GetMWEBKeychain());
    BOOST_REQUIRE(first_keys);
    const std::string scan = EncodeSecret(psbt_test::ToCKey(first_keys->GetScanSecret()));
    auto* second = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", scan, EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('3')))), true);
    auto* separate = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('4'))),
            EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('5')))), true);
    BOOST_REQUIRE(second);
    BOOST_REQUIRE(separate);
    const auto second_keys = WITH_LOCK(second->cs_desc_man, return second->GetMWEBKeychain());
    const auto separate_keys = WITH_LOCK(separate->cs_desc_man, return separate->GetMWEBKeychain());
    BOOST_REQUIRE(second_keys);
    BOOST_REQUIRE(separate_keys);
    BOOST_CHECK(first_keys->GetMasterScanKeyID() == second_keys->GetMasterScanKeyID());
    BOOST_CHECK(first_keys->GetMasterScanKeyID() != separate_keys->GetMasterScanKeyID());
    BOOST_REQUIRE(first_keys->GetSpendPubKey() != second_keys->GetSpendPubKey());

    const auto exported = first->GetMWEBAccountWatchOnlyDescriptor();
    BOOST_REQUIRE(exported);
    auto* watch = CreateDescriptor(m_wallet, *exported, true);
    BOOST_REQUIRE(watch && watch != first);
    const auto watch_keys = WITH_LOCK(watch->cs_desc_man, return watch->GetMWEBKeychain());
    BOOST_REQUIRE(watch_keys);
    BOOST_CHECK(!watch_keys->HasSpendSecret());
    WalletBatch batch(m_wallet.GetDatabase());
    for (auto* account : {first, second, separate, watch}) {
        LOCK(account->cs_desc_man);
        const auto keys = account->GetMWEBKeychain();
        BOOST_REQUIRE(keys);
        for (const uint32_t index : {7U, mw::CHANGE_INDEX}) {
            BOOST_REQUIRE(account->PersistMWEBInternalIndex(batch, index, keys->GetStealthAddress(index)));
        }
        account->LoadMWEBKeychain();
    }

    const WalletMWEBSigningKeyStore keystore(m_wallet);
    BOOST_CHECK_EQUAL(keystore.GetScanSecrets().size(), 2U);
    for (auto* account : {first, second, separate}) {
        BOOST_TEST_CONTEXT("account " << account->GetID().ToString()) {
            const auto keys = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
            BOOST_REQUIRE(keys && keys->HasSpendSecret());
            for (const uint32_t index : {7U, mw::CHANGE_INDEX}) {
                const StealthAddress address = keys->GetStealthAddress(index);
                if (account == first) BOOST_CHECK(watch->IsMine(CTxDestination{address}));
                const auto spend_key = keystore.GetSubaddressSpendSecret(address);
                BOOST_REQUIRE(spend_key);
                BOOST_CHECK(PublicKey::From(*spend_key) == address.GetSpendPubKey());
                const Output received = Output::Create(nullptr, SecretKey::Random(), SecretKey::Random(), address, 100'000, {});
                // No rewind or wallet coin may supply the owner implicitly.
                // A shared scan scalar alone cannot select a spend branch.
                BOOST_CHECK(!keystore.GetCoin(received.GetOutputID()));
                const SecretKey shared_secret = mw::RecoverSharedSecret(received.Ke(), keys->GetScanSecret());
                PSBTInput unresolved = psbt_test::MWEBInput(received.GetOutputID());
                unresolved.mweb_shared_secret = shared_secret;
                auto unresolved_key = ResolveMWEBInputKeys(unresolved, keystore);
                BOOST_REQUIRE(unresolved_key);
                BOOST_CHECK(!unresolved_key->has_value());
                BOOST_CHECK(unresolved.mweb_shared_secret == shared_secret);
                BOOST_CHECK(!unresolved.mweb_address_descriptor);
                unresolved.mweb_output_pubkey = received.Ko();
                auto resolved_key = ResolveMWEBInputKeys(unresolved, keystore);
                BOOST_REQUIRE(resolved_key && resolved_key->has_value());
                BOOST_CHECK(PublicKey::From(**resolved_key) == received.Ko());
                BOOST_CHECK(**resolved_key == mw::DeriveOutputSpendKey(*spend_key, shared_secret));

                PSBTInput recovered = psbt_test::MWEBInput(received.GetOutputID());
                recovered.mweb_key_exchange_pubkey = received.Ke();
                recovered.mweb_output_pubkey = received.Ko();
                const auto recovered_key = ResolveMWEBInputKeys(recovered, keystore);
                BOOST_REQUIRE(recovered_key && recovered_key->has_value());
                BOOST_CHECK(PublicKey::From(**recovered_key) == received.Ko());
                BOOST_CHECK(recovered.mweb_shared_secret == shared_secret);
                BOOST_CHECK(!recovered.mweb_amount);
                CheckReceivedOutputSigning(m_wallet, received, /*input_amount=*/100'000);
                BOOST_CHECK(!keystore.GetCoin(received.GetOutputID()));
                mw::Coin coin;
                BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, coin));
                BOOST_CHECK(coin.IsMine());
                BOOST_REQUIRE(coin.address);
                BOOST_CHECK(*coin.address == address);
                BOOST_CHECK_EQUAL(coin.address_index, index);
                BOOST_CHECK(coin.master_scan_key_id == keys->GetMasterScanKeyID());
                BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(coin) == account);
                BOOST_CHECK_EQUAL(coin.IsChange(), index == mw::CHANGE_INDEX);
                BOOST_CHECK_EQUAL(m_wallet.GetMWWallet()->IsChange(*coin.address), index == mw::CHANGE_INDEX);
                BOOST_REQUIRE(coin.spend_key);
                BOOST_CHECK(PublicKey::From(*coin.spend_key) == received.GetReceiverPubKey());
                CheckReceivedOutputSigning(m_wallet, received);
                BOOST_CHECK(m_wallet.GetExternalMWEBScriptPubKeyMan() == first);
            }
        }
    }
    // A shared scan scalar alone does not make an unknown spend branch ours,
    // nor does it extend another account's discovery window.
    const StealthAddress foreign = mw::DeriveSubaddress(PublicKey::From(psbt_test::TestSecret('9')),
        first_keys->GetScanSecret(), 7);
    const Output unrelated = Output::Create(nullptr, SecretKey::Random(), foreign, 100'000);
    const uint32_t outside_index = WITH_LOCK(second->cs_desc_man, return second->GetWalletDescriptor().GetEnd());
    const StealthAddress outside_address = second_keys->GetStealthAddress(outside_index);
    BOOST_CHECK(!second_keys->LookupAddressIndex(outside_address));
    const Output outside_range = Output::Create(nullptr, SecretKey::Random(), outside_address, 100'000);
    mw::Coin coin;
    for (const auto& output : {unrelated, outside_range}) {
        BOOST_CHECK(!m_wallet.GetMWWallet()->RewindOutput(output, coin));
        BOOST_CHECK(!m_wallet.GetMWWallet()->GetCoin(output.GetOutputID(), coin));
    }

    // Importing the missing account makes the very same output ours.
    auto* imported = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", scan, EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('9')))), true);
    BOOST_REQUIRE(imported);
    // Match importdescriptors' keychain refresh after installing private keys.
    WITH_LOCK(imported->cs_desc_man, imported->LoadMWEBKeychain());
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(unrelated, coin));
    BOOST_REQUIRE(coin.address);
    BOOST_CHECK(*coin.address == foreign);
    BOOST_CHECK_EQUAL(coin.address_index, 7U);
    BOOST_CHECK(coin.master_scan_key_id == first_keys->GetMasterScanKeyID());
    BOOST_REQUIRE(coin.spend_key);
    BOOST_CHECK(PublicKey::From(*coin.spend_key) == unrelated.GetReceiverPubKey());
    const auto* owner = m_wallet.GetMWEBAccountForStealthAddress(foreign);
    BOOST_REQUIRE(owner);
    BOOST_CHECK(owner == imported);
    BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(coin) == owner);
    const auto owner_keys = WITH_LOCK(owner->cs_desc_man, return owner->GetMWEBKeychain());
    BOOST_REQUIRE(owner_keys);
    BOOST_CHECK(owner_keys->GetSpendPubKey() == PublicKey::From(psbt_test::TestSecret('9')));
    BOOST_CHECK(!m_wallet.GetMWWallet()->IsChange(foreign));
    CheckReceivedOutputSigning(m_wallet, unrelated);
    BOOST_CHECK(m_wallet.GetExternalMWEBScriptPubKeyMan() == first);
}

BOOST_AUTO_TEST_CASE(stored_addressless_coin_requires_spend_branch_evidence)
{
    LOCK(m_wallet.cs_wallet);
    const SecretKey scan = psbt_test::TestSecret('1');
    std::vector<DescriptorScriptPubKeyMan*> accounts;
    WalletBatch batch(m_wallet.GetDatabase());
    for (const char spend : {'2', '3'}) {
        auto* account = CreateDescriptor(m_wallet,
            strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(scan)),
                EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret(spend)))), true);
        BOOST_REQUIRE(account);
        LOCK(account->cs_desc_man);
        account->LoadMWEBKeychain();
        const auto keys = account->GetMWEBKeychain();
        BOOST_REQUIRE(keys);
        BOOST_REQUIRE(account->PersistMWEBInternalIndex(batch, 7, keys->GetStealthAddress(7)));
        account->LoadMWEBKeychain();
        accounts.push_back(account);
    }
    auto* separate = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('4'))),
            EncodeSecret(psbt_test::ToCKey(psbt_test::TestSecret('5')))), true);
    BOOST_REQUIRE(separate);
    {
        LOCK(separate->cs_desc_man);
        separate->LoadMWEBKeychain();
        const auto keys = separate->GetMWEBKeychain();
        BOOST_REQUIRE(keys);
        BOOST_REQUIRE(separate->PersistMWEBInternalIndex(batch, 7, keys->GetStealthAddress(7)));
        separate->LoadMWEBKeychain();
    }
    accounts.push_back(separate);
    const WalletMWEBSigningKeyStore keystore(m_wallet);
    BOOST_REQUIRE_EQUAL(keystore.GetScanSecrets().size(), 2U);
    for (auto* account : accounts) {
        BOOST_TEST_CONTEXT("account " << account->GetID().ToString()) {
            const auto keys = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
            const Output output = Output::Create(nullptr, SecretKey::Random(), keys->GetStealthAddress(7), 100'000);
            mw::Coin original;
            BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, original));
            mw::Coin addressless = original;
            addressless.address.reset();
            addressless.spend_key.reset();
            addressless.blind.reset();
            m_wallet.GetMWWallet()->LoadToWallet(addressless);
            BOOST_REQUIRE(keystore.GetCoin(output.GetOutputID()));
            const bool ambiguous = account != separate;
            BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(addressless) == (ambiguous ? nullptr : account));
            // Newly recovered address data must beat an older addressless record.
            BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(original) == account);
            StealthAddress display;
            BOOST_CHECK_EQUAL(m_wallet.GetMWWallet()->GetStealthAddress(addressless, display), !ambiguous);
            BOOST_CHECK_EQUAL(keystore.InferAddressDescriptor(addressless).has_value(), !ambiguous);

            PSBTInput input = psbt_test::MWEBInput(output.GetOutputID());
            const auto unresolved = ResolveMWEBInputKeys(input, keystore);
            BOOST_REQUIRE(unresolved);
            BOOST_CHECK_EQUAL(unresolved->has_value(), !ambiguous);
            if (!ambiguous) BOOST_CHECK(PublicKey::From(**unresolved) == output.Ko());
            BOOST_CHECK(input.mweb_shared_secret == original.shared_secret);
            BOOST_CHECK_EQUAL(input.mweb_address_descriptor.has_value(), !ambiguous);

            PSBTInput identified = psbt_test::MWEBInput(output.GetOutputID());
            identified.mweb_output_pubkey = output.Ko();
            const auto resolved = ResolveMWEBInputKeys(identified, keystore);
            BOOST_CHECK_MESSAGE(resolved && resolved->has_value(), "genuine output pubkey must select its spend branch");
            if (resolved && resolved->has_value()) BOOST_CHECK(PublicKey::From(**resolved) == output.Ko());

            // Restoring the full native record is an independent positive control.
            m_wallet.GetMWWallet()->LoadToWallet(original);
            BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(original) == account);
            BOOST_REQUIRE(m_wallet.GetMWWallet()->GetStealthAddress(original, display));
            BOOST_CHECK(display == *original.address);
            CheckReceivedOutputSigning(m_wallet, output);
        }
    }
}

BOOST_AUTO_TEST_CASE(rewind_key_without_mweb_keychain_is_random)
{
    LOCK(m_wallet.cs_wallet);
    BOOST_REQUIRE(!m_wallet.GetMWEBKeychain());
    const SecretKey first = m_wallet.GetMWEBRewindKeyForSigning();
    BOOST_CHECK(!first.IsNull());
    BOOST_CHECK(first != m_wallet.GetMWEBRewindKeyForSigning());
}

BOOST_AUTO_TEST_CASE(watch_only_input_without_wallet_coin_recovers_metadata_but_cannot_sign)
{
    LOCK(m_wallet.cs_wallet);
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey spend = psbt_test::TestSecret('2');
    auto* watch = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(scan)),
            HexStr(PublicKey::From(spend).vec())), true);
    BOOST_REQUIRE(watch);
    const auto keys = WITH_LOCK(watch->cs_desc_man, return watch->GetMWEBKeychain());
    BOOST_REQUIRE(keys && keys->HasSpendPubKey());
    BOOST_CHECK(!keys->HasSpendSecret());
    const StealthAddress address = keys->GetStealthAddress(7);
    WalletBatch batch(m_wallet.GetDatabase());
    {
        LOCK(watch->cs_desc_man);
        BOOST_REQUIRE(watch->PersistMWEBInternalIndex(batch, 7, address));
        watch->LoadMWEBKeychain();
    }
    const Output received = Output::Create(nullptr, SecretKey::Random(), address, 100'000);
    const WalletMWEBSigningKeyStore keystore(m_wallet);
    BOOST_REQUIRE(keystore.IsMine(address));
    BOOST_CHECK(!keystore.GetCoin(received.GetOutputID()));
    BOOST_CHECK(!keystore.GetSubaddressSpendSecret(address));
    PSBTInput input = psbt_test::MWEBInput(received.GetOutputID());
    input.mweb_key_exchange_pubkey = received.Ke();
    input.mweb_output_pubkey = received.Ko();
    const auto key = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(key);
    BOOST_CHECK(!key->has_value());
    BOOST_CHECK(input.mweb_shared_secret == mw::RecoverSharedSecret(received.Ke(), scan));
    BOOST_CHECK(!input.mweb_amount);

    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
    tx.mweb_tx.outputs.emplace_back().address = StealthAddress::Random();
    tx.mweb_tx.outputs.back().amount = 90'000;
    tx.mweb_tx.kernels.emplace_back().fee = 10'000;
    PartiallySignedTransaction psbt(tx, 2);
    psbt.inputs[0].mweb_amount = 100'000;
    psbt.inputs[0].mweb_key_exchange_pubkey = received.Ke();
    bool complete = true;
    size_t signed_count{99};
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true}, complete, &signed_count));
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(signed_count, 0U);
    BOOST_CHECK(!psbt.inputs[0].mweb_sig);
    BOOST_CHECK(psbt.inputs[0].mweb_shared_secret == input.mweb_shared_secret);
    CMutableTransaction extracted;
    BOOST_CHECK(!FinalizeAndExtractPSBT(psbt, extracted));
    BOOST_CHECK(!keystore.GetCoin(received.GetOutputID()));
}

BOOST_AUTO_TEST_CASE(private_single_subaddress_wallet_signing)
{
    LOCK(m_wallet.cs_wallet);
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey master_spend = psbt_test::TestSecret('2');
    const SecretKey subaddress_spend = mw::DeriveSubaddressSpendKey(master_spend, scan, 7);
    const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(master_spend), scan, 7);
    // The watch-only account is installed first. Only the later direct
    // subaddress descriptor supplies this output's private spending key.
    auto* watch = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(psbt_test::ToCKey(scan)),
            HexStr(PublicKey::From(master_spend).vec())), true);
    const std::string private_descriptor = strprintf("mweb(%s,%s)",
        EncodeSecret(psbt_test::ToCKey(scan)), EncodeSecret(psbt_test::ToCKey(subaddress_spend)));
    auto* direct = CreateDescriptor(m_wallet, private_descriptor, true);
    BOOST_REQUIRE(watch && direct && watch != direct);
    WITH_LOCK(direct->cs_desc_man, direct->LoadMWEBKeychain());
    const auto direct_keys = WITH_LOCK(direct->cs_desc_man, return direct->GetMWEBKeychain());
    BOOST_REQUIRE(direct_keys);
    BOOST_REQUIRE(direct->IsMine(CTxDestination{address}));
    WITH_LOCK(direct->cs_desc_man, BOOST_CHECK(!direct->IsMWEBAccountDescriptor()));
    CKey stored_key;
    BOOST_REQUIRE(direct->GetKey(address.B().GetID(), stored_key));
    BOOST_CHECK(SecretKey{reinterpret_cast<const uint8_t*>(stored_key.data())} == subaddress_spend);

    const Output received = Output::Create(nullptr, SecretKey::Random(), address, 100'000);
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
    tx.mweb_tx.outputs.emplace_back().address = StealthAddress::Random();
    tx.mweb_tx.outputs.back().amount = 90'000;
    tx.mweb_tx.kernels.emplace_back().fee = 10'000;
    PartiallySignedTransaction original(tx, 2);
    original.inputs[0].mweb_amount = 100'000;
    original.inputs[0].mweb_key_exchange_pubkey = received.Ke();
    original.inputs[0].mweb_address_descriptor = strprintf("mweb(%s,%s)",
        EncodeSecret(psbt_test::ToCKey(scan)), HexStr(address.B().vec()));

    // The descriptor signer can already spend the same genuine output with
    // the exact private descriptor that the wallet has imported.
    FlatSigningProvider descriptor_keys;
    std::string error;
    const auto parsed = Parse(private_descriptor, descriptor_keys, error, false);
    BOOST_REQUIRE_MESSAGE(parsed.size() == 1, error);
    DescriptorMWEBSigningKeyStore descriptor_store;
    BOOST_REQUIRE(descriptor_store.AddDescriptor(*parsed.front(), descriptor_keys, {0, 1}));
    PartiallySignedTransaction control = original;
    BOOST_REQUIRE(FillMWEBPSBT(control, descriptor_store, true, SecretKey::Random(), []() -> util::Result<SecretKey> {
        return SecretKey::Random();
    }));
    CMutableTransaction control_tx;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(control, control_tx));
    const CTransaction signed_control{control_tx};
    BOOST_REQUIRE(signed_control.mweb_tx.m_transaction);
    BOOST_CHECK_NO_THROW(signed_control.mweb_tx.m_transaction->Validate());
    BOOST_CHECK(signed_control.mweb_tx.m_transaction->GetInputs().front().GetOutputPubKey() == received.Ko());

    const WalletMWEBSigningKeyStore wallet_store(m_wallet);
    for (const bool with_coin : {false, true}) {
        BOOST_TEST_CONTEXT("stored coin " << with_coin) {
            if (with_coin) {
                mw::Coin coin;
                BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, coin));
                BOOST_REQUIRE(coin.address);
                BOOST_CHECK(*coin.address == address);
                BOOST_CHECK_EQUAL(coin.address_index, mw::CUSTOM_KEY);
                const auto low_level_key = direct_keys->CalculateOutputSpendKey(coin);
                BOOST_REQUIRE(low_level_key);
                BOOST_CHECK(PublicKey::From(*low_level_key) == received.Ko());
                const auto inferred = wallet_store.InferAddressDescriptor(coin);
                BOOST_REQUIRE(inferred);
                const auto data = ParseMWEBAddressDescriptor(*inferred);
                BOOST_REQUIRE(data);
                BOOST_CHECK(data->address == address);
                BOOST_CHECK(data->scan_secret == scan);
                BOOST_CHECK(!data->subaddress_spend_secret);
            }
            BOOST_CHECK_EQUAL(wallet_store.GetCoin(received.GetOutputID()).has_value(), with_coin);
            for (const bool supplied_descriptor : {true, false}) {
                BOOST_TEST_CONTEXT("supplied descriptor " << supplied_descriptor) {
                    PartiallySignedTransaction funded = original;
                    if (!supplied_descriptor) funded.inputs[0].mweb_address_descriptor.reset();
                    auto input = funded.inputs[0];
                    const auto resolved = ResolveMWEBInputKeys(input, wallet_store);
                    BOOST_REQUIRE(resolved);
                    BOOST_REQUIRE(resolved->has_value());
                    BOOST_CHECK(PublicKey::From(**resolved) == received.Ko());
                    if (with_coin) BOOST_CHECK(input.mweb_address_descriptor.has_value());
                    bool complete = false;
                    BOOST_REQUIRE(!m_wallet.FillPSBT(funded, {.sign = true, .finalize = true}, complete));
                    BOOST_REQUIRE(complete);
                    CMutableTransaction extracted;
                    BOOST_REQUIRE(FinalizeAndExtractPSBT(funded, extracted));
                    const CTransaction final_tx{extracted};
                    BOOST_CHECK_NO_THROW(final_tx.mweb_tx.m_transaction->Validate());
                    BOOST_CHECK(final_tx.mweb_tx.m_transaction->GetInputs().front().GetOutputPubKey() == received.Ko());
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(direct_subaddress_signing_respects_encryption_and_watch_only)
{
    LOCK(m_wallet.cs_wallet);
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey spend = psbt_test::TestSecret('2');
    const StealthAddress address{PublicKey::From(spend).Mul(scan), PublicKey::From(spend)};
    const std::string private_descriptor = strprintf("mweb(%s,%s)",
        EncodeSecret(psbt_test::ToCKey(scan)), EncodeSecret(psbt_test::ToCKey(spend)));
    auto* direct = CreateDescriptor(m_wallet, private_descriptor, true);
    BOOST_REQUIRE(direct);
    WITH_LOCK(direct->cs_desc_man, direct->LoadMWEBKeychain());
    const Output received = Output::Create(nullptr, SecretKey::Random(), address, 100'000);
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
    tx.mweb_tx.outputs.emplace_back().address = StealthAddress::Random();
    tx.mweb_tx.outputs.back().amount = 90'000;
    tx.mweb_tx.kernels.emplace_back().fee = 10'000;
    PartiallySignedTransaction original(tx, 2);
    original.inputs[0].mweb_amount = 100'000;
    original.inputs[0].mweb_key_exchange_pubkey = received.Ke();

    const auto check = [&](CWallet& wallet, bool can_sign) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        const WalletMWEBSigningKeyStore store(wallet);
        BOOST_REQUIRE(store.IsMine(address));
        const auto key = store.GetSubaddressSpendSecret(address);
        BOOST_CHECK_EQUAL(key.has_value(), can_sign);
        if (key) BOOST_CHECK(PublicKey::From(*key) == address.B());
        mw::Coin coin;
        coin.output_id = received.GetOutputID();
        coin.address = address;
        coin.address_index = mw::CUSTOM_KEY;
        const auto inferred = store.InferAddressDescriptor(coin);
        BOOST_REQUIRE(inferred);
        const auto data = ParseMWEBAddressDescriptor(*inferred);
        BOOST_REQUIRE(data);
        BOOST_CHECK(data->address == address);
        BOOST_CHECK(data->scan_secret == scan);
        BOOST_CHECK(!data->subaddress_spend_secret);
        PartiallySignedTransaction psbt = original;
        bool complete = !can_sign;
        size_t signed_count{99};
        BOOST_REQUIRE(!wallet.FillPSBT(psbt, {.sign = true, .finalize = true}, complete, &signed_count));
        BOOST_CHECK_EQUAL(complete, can_sign);
        BOOST_CHECK_EQUAL(signed_count, can_sign ? 1U : 0U);
        BOOST_CHECK_EQUAL(psbt.inputs[0].mweb_sig.has_value(), can_sign);
        CMutableTransaction extracted;
        const bool finalized = FinalizeAndExtractPSBT(psbt, extracted);
        BOOST_CHECK_EQUAL(finalized, can_sign);
        if (finalized) {
            const CTransaction final_tx{extracted};
            BOOST_CHECK_NO_THROW(final_tx.mweb_tx.m_transaction->Validate());
            BOOST_CHECK(final_tx.mweb_tx.m_transaction->GetInputs().front().GetOutputPubKey() == received.Ko());
        }
    };
    check(m_wallet, true);
    SecureString passphrase;
    passphrase.assign("direct-subaddress-lock-test");
    BOOST_REQUIRE(m_wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(m_wallet.IsLocked());
    check(m_wallet, false);
    BOOST_REQUIRE(m_wallet.Unlock(passphrase));
    check(m_wallet, true);
    BOOST_REQUIRE(m_wallet.Lock());
    check(m_wallet, false);

    CWallet watch(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(watch.cs_wallet);
    watch.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    auto* watching = CreateDescriptor(watch,
        strprintf("mweb(%s,%s)", EncodeSecret(psbt_test::ToCKey(scan)), HexStr(address.B().vec())), true);
    BOOST_REQUIRE(watching);
    WITH_LOCK(watching->cs_desc_man, watching->LoadMWEBKeychain());
    check(watch, false);
}

BOOST_AUTO_TEST_CASE(imported_subaddress_signing_preserves_native_change_classification)
{
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey spend = psbt_test::TestSecret('2');
    for (const std::string form : {"indexed", "direct", "reserved_change"}) {
        BOOST_TEST_CONTEXT(form) {
            CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
            LOCK(wallet.cs_wallet);
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
            const uint32_t index = form == "reserved_change" ? mw::CHANGE_INDEX : 7;
            const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(spend), scan, index);
            const std::string descriptor = strprintf("mweb(%s,%s%s)",
                EncodeSecret(psbt_test::ToCKey(scan)),
                EncodeSecret(psbt_test::ToCKey(form == "direct" ? mw::DeriveSubaddressSpendKey(spend, scan, index) : spend)),
                form == "direct" ? "" : ",*");
            FlatSigningProvider provider;
            std::string error;
            auto parsed = Parse(descriptor, provider, error, false);
            BOOST_REQUIRE_MESSAGE(parsed.size() == 1, error);
            WalletDescriptor imported(std::move(parsed.front()), 0, 0, 1, 0);
            DescriptorScriptPubKeyMan* owner;
            if (form == "indexed") {
                // Native indexed imports use a limited supporting account and
                // explicitly register only the requested address.
                owner = &wallet.AddMWEBSupportingAccount(imported, provider);
                LOCK(owner->cs_desc_man);
                WalletBatch batch(wallet.GetDatabase());
                BOOST_REQUIRE(owner->PersistMWEBInternalIndex(batch, index, address));
                owner->EnsureMWEBNextIndexAtLeast(index + 1);
                BOOST_REQUIRE(batch.WriteDescriptor(owner->GetID(), owner->GetWalletDescriptor()));
                BOOST_CHECK(owner->IsMWEBLimitedAccount());
            } else {
                const auto added = wallet.AddWalletDescriptor(imported, provider, "", /*internal=*/true);
                BOOST_REQUIRE(added);
                owner = &added->get();
            }
            BOOST_REQUIRE(owner);
            WITH_LOCK(owner->cs_desc_man, owner->LoadMWEBKeychain());
            if (form == "reserved_change") {
                // Public internal records are bound to their imported account;
                // index 0 remains change without a rotating internal manager.
                const std::string checksum = WITH_LOCK(owner->cs_desc_man, return owner->GetMWEBAccountChecksum());
                FlatSigningProvider internal_provider;
                auto internal = Parse(strprintf("mweb(%s,%s,0,%s)", HexStr(address.A().vec()),
                    HexStr(address.B().vec()), checksum), internal_provider, error, false);
                BOOST_REQUIRE_MESSAGE(internal.size() == 1, error);
                WalletDescriptor record(std::move(internal.front()), 0, 0, 0, 0);
                LOCK(owner->cs_desc_man);
                BOOST_REQUIRE(owner->LoadMWEBInternalDescriptorRecord(record));
                BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).WriteMWEBInternalDescriptor(owner->GetID(), index, record));
            }
            BOOST_CHECK(wallet.GetMWEBAccountForStealthAddress(address) == owner);
            const Output received = Output::Create(nullptr, SecretKey::Random(), address, 100'000);
            mw::Coin coin;
            BOOST_REQUIRE(wallet.GetMWWallet()->RewindOutput(received, coin));
            BOOST_CHECK_EQUAL(coin.amount, 100'000);
            BOOST_CHECK(coin.address == address);
            BOOST_CHECK_EQUAL(coin.address_index, form == "direct" ? mw::CUSTOM_KEY : index);
            BOOST_CHECK(coin.IsMine());
            BOOST_CHECK_EQUAL(coin.IsChange(), index == mw::CHANGE_INDEX);
            BOOST_CHECK_EQUAL(wallet.GetMWWallet()->IsChange(address), index == mw::CHANGE_INDEX);
            BOOST_REQUIRE(coin.spend_key);
            BOOST_CHECK(PublicKey::From(*coin.spend_key) == received.Ko());
            mw::Coin persisted;
            BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(
                std::make_pair(DBKeys::MWEB_COIN, received.GetOutputID()), persisted));
            BOOST_CHECK(persisted.Serialized() == coin.SanitizeForDisk().Serialized());
            CheckReceivedOutputSigning(wallet, received);
        }
    }
}

BOOST_AUTO_TEST_CASE(watch_only_scan_key_alias_cannot_supply_a_spending_key)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    const SecretKey scan = psbt_test::TestSecret('1');
    const PublicKey public_key = PublicKey::From(scan);
    const StealthAddress address{public_key.Mul(scan), public_key};
    auto* direct = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s)", EncodeSecret(psbt_test::ToCKey(scan)), HexStr(public_key.vec())), true);
    BOOST_REQUIRE(direct);
    WITH_LOCK(direct->cs_desc_man, direct->LoadMWEBKeychain());
    // Watch-only scan material lives outside the descriptor's spending-key map,
    // including when its scalar happens to equal the subaddress spending key.
    BOOST_REQUIRE(direct->GetMWEBKeychain());
    BOOST_CHECK(direct->GetMWEBKeychain()->GetScanSecret() == scan);
    CKey available_scan_key;
    BOOST_CHECK(!direct->GetKey(address.B().GetID(), available_scan_key));
    const WalletMWEBSigningKeyStore store(m_wallet);
    BOOST_REQUIRE(store.IsMine(address));
    BOOST_CHECK(!store.GetSubaddressSpendSecret(address));
    const Output received = Output::Create(nullptr, SecretKey::Random(), address, 100'000);
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
    tx.mweb_tx.outputs.emplace_back().address = StealthAddress::Random();
    tx.mweb_tx.outputs.back().amount = 90'000;
    tx.mweb_tx.kernels.emplace_back().fee = 10'000;
    PartiallySignedTransaction psbt(tx, 2);
    psbt.inputs[0].mweb_amount = 100'000;
    psbt.inputs[0].mweb_key_exchange_pubkey = received.Ke();
    bool complete = true;
    size_t signed_count{99};
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true}, complete, &signed_count));
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(signed_count, 0U);
    BOOST_CHECK(!psbt.inputs[0].mweb_sig);
    BOOST_CHECK(psbt.inputs[0].mweb_shared_secret == mw::RecoverSharedSecret(received.Ke(), scan));
}

BOOST_AUTO_TEST_CASE(unsigned_sign_save_and_rewind_output_metadata_lifecycle)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetMWEBDeterministicSenders(true);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const auto keys = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keys && keys->HasSpendSecret());
    const StealthAddress owned = NewMWEBAddress(m_wallet);
    StealthAddress change;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*account, change));
    const StealthAddress external = StealthAddress::Random();
    const Output funding = Output::Create(nullptr, SecretKey::Random(), owned, 100'000);
    mw::Coin funding_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(funding, funding_coin));
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(funding));
    const std::map<StealthAddress, CAmount> payments{{owned, 20'000}, {change, 30'000}, {external, 40'000}};
    for (const auto& [address, amount] : payments) {
        mw::MutableOutput output;
        output.address = address;
        output.amount = amount;
        tx.mweb_tx.outputs.push_back(output);
    }
    tx.mweb_tx.kernels.emplace_back().fee = 10'000;
    const PartiallySignedTransaction original(tx, 2);
    PartiallySignedTransaction psbt = original;
    psbt.inputs[0].mweb_key_exchange_pubkey = funding.Ke();
    bool complete = true;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = false}, complete));
    BOOST_CHECK(!complete);
    BOOST_CHECK(m_wallet.mapWallet.empty());
    const WalletMWEBSigningKeyStore keystore(m_wallet);
    const auto serialize = [](const PartiallySignedTransaction& value) {
        DataStream stream;
        stream << value;
        return HexStr(stream);
    };

    // A failed signer publishes neither a partially signed draft nor coins.
    const std::string before = serialize(psbt);
    unsigned generated{0};
    auto failed = FillMWEBPSBT(psbt, keystore, true, keys->GetRewindKey(), [&]() -> util::Result<SecretKey> {
        if (generated++ == 1) return util::Error{Untranslated("injected sender key failure")};
        return keys->GetSenderSigningKey(0);
    });
    BOOST_CHECK(!failed);
    BOOST_CHECK_EQUAL(generated, 2U);
    BOOST_CHECK_EQUAL(serialize(psbt), before);

    // The low-level signer returns unpublished output coins. Their exact IDs
    // can then be checked against the wallet before an explicit save.
    uint64_t sender_index{0};
    auto signed_result = FillMWEBPSBT(psbt, keystore, true, keys->GetRewindKey(), [&]() -> util::Result<SecretKey> {
        return keys->GetSenderSigningKey(sender_index++);
    });
    BOOST_REQUIRE(signed_result);
    BOOST_REQUIRE_EQUAL(signed_result->coins.size(), 3U);
    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted));
    const CTransaction final_tx{extracted};
    BOOST_REQUIRE(final_tx.mweb_tx.m_transaction);
    BOOST_CHECK_NO_THROW(final_tx.mweb_tx.m_transaction->Validate());
    std::vector<mw::Coin> own_coins;
    std::optional<mw::Coin> external_coin;
    for (const auto& [id, coin] : signed_result->coins) {
        mw::Coin absent;
        BOOST_CHECK(!m_wallet.GetCoin(id, absent));
        BOOST_CHECK(!m_wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, id)));
        BOOST_REQUIRE(coin.address);
        BOOST_CHECK_EQUAL(coin.amount, payments.at(*coin.address));
        BOOST_REQUIRE(coin.sender_key);
        BOOST_CHECK(!coin.shared_secret);
        if (*coin.address == external) external_coin = coin;
        else own_coins.push_back(coin);
    }
    BOOST_REQUIRE(external_coin);
    BOOST_REQUIRE_EQUAL(own_coins.size(), 2U);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet(own_coins));
    mw::Coin absent;
    BOOST_CHECK(!m_wallet.GetCoin(external_coin->output_id, absent));
    BOOST_CHECK(!m_wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, external_coin->output_id)));

    const auto check_rewind = [&](const mw::Coin& saved, bool mine) {
        Output output;
        BOOST_REQUIRE(final_tx.mweb_tx.GetOutput(saved.output_id, output));
        mw::Coin coin;
        BOOST_REQUIRE(m_wallet.GetCoin(saved.output_id, coin));
        BOOST_CHECK(coin.address == saved.address);
        BOOST_CHECK(!coin.shared_secret);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, coin));
        BOOST_CHECK_EQUAL(coin.IsMine(), mine);
        BOOST_CHECK_EQUAL(coin.IsChange(), saved.address == change);
        if (mine) {
            BOOST_REQUIRE(coin.spend_key);
            BOOST_CHECK(PublicKey::From(*coin.spend_key) == output.Ko());
        }
        BOOST_CHECK(coin.address == saved.address);
        BOOST_REQUIRE(coin.shared_secret);
        BOOST_CHECK(*coin.shared_secret == mw::DeriveSharedSecret(*saved.sender_key, *saved.address, saved.amount));
        mw::Coin persisted;
        BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::MWEB_COIN, saved.output_id), persisted));
        BOOST_CHECK(persisted.Serialized() == coin.SanitizeForDisk().Serialized());
        BOOST_CHECK(!persisted.spend_key && !persisted.blind && !persisted.sender_key);
        mw::Coin repeated;
        BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, repeated));
        BOOST_CHECK(repeated.Serialized() == coin.Serialized());
    };
    for (const auto& coin : own_coins) check_rewind(coin, true);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({*external_coin}));
    check_rewind(*external_coin, false);
    BOOST_CHECK(m_wallet.mapWallet.empty());

    // The public wallet path saves every successfully signed output coin,
    // before a transaction is committed to history; it has no staging API.
    PartiallySignedTransaction automatic = original;
    automatic.inputs[0].mweb_key_exchange_pubkey = funding.Ke();
    BOOST_REQUIRE(!m_wallet.FillPSBT(automatic, {.sign = true, .finalize = true}, complete));
    BOOST_REQUIRE(complete);
    CMutableTransaction automatic_tx;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(automatic, automatic_tx));
    const CTransaction automatic_final{automatic_tx};
    BOOST_REQUIRE_EQUAL(automatic_final.mweb_tx.GetOutputIDs().size(), 3U);
    for (const auto& id : automatic_final.mweb_tx.GetOutputIDs()) {
        mw::Coin saved;
        BOOST_REQUIRE(m_wallet.GetCoin(id, saved));
        BOOST_REQUIRE(saved.address);
        BOOST_CHECK_EQUAL(saved.amount, payments.at(*saved.address));
        BOOST_CHECK(m_wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, id)));
    }
    BOOST_CHECK(m_wallet.mapWallet.empty());
}

//! Without signing, FillPSBT still adds the shared secret a keyless signer needs.
BOOST_AUTO_TEST_CASE(fill_without_signing_adds_the_shared_secret)
{
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey spend = psbt_test::TestSecret('2');
    const PublicKey key_exchange_pubkey = PublicKey::From(psbt_test::TestSecret('e'));
    const SecretKey shared_secret = mw::RecoverSharedSecret(key_exchange_pubkey, scan);

    PartiallySignedTransaction psbt = psbt_test::EmptyPSBT();
    PSBTInput input = psbt_test::MWEBInput(mw::Hash::ValueOf(1));
    input.mweb_address_descriptor = strprintf("mweb(%s,%s,0)", EncodeSecret(psbt_test::ToCKey(scan)), EncodeSecret(psbt_test::ToCKey(spend)));
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = mw::DeriveOutputPubKey(mw::DeriveSubaddress(PublicKey::From(spend), scan, 0), shared_secret);
    psbt.inputs.push_back(input);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = false}, complete));
    BOOST_CHECK(psbt.inputs[0].mweb_shared_secret == std::optional<SecretKey>{shared_secret});
    BOOST_CHECK(!psbt.inputs[0].mweb_sig);
    BOOST_CHECK(!complete);

    psbt.inputs[0].mweb_address_descriptor = "definitely-not-a-descriptor";
    BOOST_CHECK(m_wallet.FillPSBT(psbt, {.sign = false}, complete) == common::PSBTError::INVALID_TX);
}

//! A keyless MWEB draft spending subaddress `paid_index` of a private account
//! descriptor that names subaddress 0.
static PartiallySignedTransaction KeylessDraft(uint32_t paid_index, CAmount input_amount, CAmount output_amount)
{
    const SecretKey scan = psbt_test::TestSecret('1');
    const SecretKey spend = psbt_test::TestSecret('2');
    const PublicKey key_exchange_pubkey = PublicKey::From(psbt_test::TestSecret('e'));
    const SecretKey shared_secret = mw::RecoverSharedSecret(key_exchange_pubkey, scan);

    PartiallySignedTransaction psbt = psbt_test::EmptyPSBT();
    PSBTInput input = psbt_test::MWEBInput(mw::Hash::ValueOf(1));
    input.mweb_address_descriptor = strprintf("mweb(%s,%s,0)", EncodeSecret(psbt_test::ToCKey(scan)), EncodeSecret(psbt_test::ToCKey(spend)));
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = mw::DeriveOutputPubKey(mw::DeriveSubaddress(PublicKey::From(spend), scan, paid_index), shared_secret);
    input.mweb_amount = input_amount;
    psbt.inputs.push_back(input);
    psbt.outputs.push_back(psbt_test::MWEBOutput(output_amount));
    return psbt;
}

//! An input that does not pay the subaddress its descriptor names is an error, and nothing is signed.
BOOST_AUTO_TEST_CASE(fill_refuses_a_descriptor_that_does_not_match_the_input)
{
    PartiallySignedTransaction psbt = KeylessDraft(/*paid_index=*/5, /*input_amount=*/100'000, /*output_amount=*/90'000);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    size_t n_signed = 7;
    BOOST_CHECK(m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete, &n_signed) == common::PSBTError::INVALID_TX);
    BOOST_CHECK_EQUAL(n_signed, 0U);
    BOOST_CHECK(!psbt.inputs[0].mweb_sig);
}

//! An unknown canonical prevout does not prevent the valid MWEB stage from signing.
BOOST_AUTO_TEST_CASE(fill_with_an_unknown_canonical_prevout_stays_incomplete)
{
    PartiallySignedTransaction psbt = KeylessDraft(/*paid_index=*/0, /*input_amount=*/100'000, /*output_amount=*/90'000);
    // A mixed draft needs an explicit fee: its canonical input amount is unknown.
    psbt.kernels.emplace_back().fee = 10'000;
    const Txid unknown_txid = Txid::FromUint256(uint256::ONE);
    psbt.inputs.insert(psbt.inputs.begin(), psbt_test::CanonicalInput(unknown_txid));

    LOCK(m_wallet.cs_wallet);
    BOOST_REQUIRE(!m_wallet.mapWallet.contains(unknown_txid));
    bool complete = true;
    size_t n_signed = 0;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete, &n_signed));
    BOOST_CHECK(!complete);
    BOOST_CHECK(!psbt.IsComplete());
    BOOST_CHECK_EQUAL(n_signed, 1U);
    BOOST_CHECK(!PSBTInputSigned(psbt.inputs[0]));
    BOOST_CHECK(psbt.inputs[0].partial_sigs.empty());
    BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());
    BOOST_CHECK(!psbt.inputs[0].non_witness_utxo);
    BOOST_CHECK(psbt.inputs[0].witness_utxo.IsNull());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 1, nullptr));
}

//! A draft whose MWEB outputs exceed its inputs has no valid kernel fee.
BOOST_AUTO_TEST_CASE(fill_refuses_mweb_outputs_above_inputs)
{
    PartiallySignedTransaction psbt = KeylessDraft(/*paid_index=*/0, /*input_amount=*/80'000, /*output_amount=*/90'000);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_CHECK(m_wallet.FillPSBT(psbt, {.sign = false}, complete) == common::PSBTError::INVALID_TX);
    BOOST_CHECK(psbt.kernels.empty());
}

//! Signing MWEB rewrites the peg-in script, so the wallet signs the transparent input afterwards.
BOOST_AUTO_TEST_CASE(fill_signs_transparent_inputs_after_the_pegin_rewrite)
{
    const CKey key = psbt_test::ToCKey(psbt_test::TestSecret('7'));
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    BOOST_REQUIRE(CreateDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)), /*success=*/true));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(100'000, GetScriptForPegin(mw::Hash{}));
    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = psbt_test::TestStealthAddress('1', '2');
    mtx.mweb_tx.outputs.push_back(std::move(output));
    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.pegin = 100'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    PartiallySignedTransaction draft(mtx, 2);
    draft.inputs[0].witness_utxo = CTxOut(110'000, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));

    const auto check_signing = [&](bool finalize, int sighash) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        BOOST_TEST_CONTEXT("finalize=" << finalize << ", sighash=" << sighash) {
            PartiallySignedTransaction psbt = draft;
            bool complete = !finalize;
            size_t n_signed = 0;
            BOOST_REQUIRE(!m_wallet.FillPSBT(psbt,
                {.sign = true, .sighash_type = sighash, .finalize = finalize, .bip32_derivs = false},
                complete, finalize ? &n_signed : nullptr));
            BOOST_CHECK_EQUAL(complete, finalize);

            mw::Hash script_kernel_id;
            BOOST_REQUIRE(psbt.outputs[0].script.IsMWEBPegin(&script_kernel_id));
            BOOST_CHECK(!script_kernel_id.IsZero());
            if (finalize) {
                BOOST_CHECK_EQUAL(n_signed, 1U);
                BOOST_CHECK(!psbt.inputs[0].final_script_witness.IsNull());
            } else {
                BOOST_CHECK_EQUAL(psbt.inputs[0].partial_sigs.size(), 1U);
                BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());
                BOOST_CHECK(!psbt.IsComplete());
                BOOST_REQUIRE(FinalizePSBT(psbt));
            }
            BOOST_CHECK(psbt.IsComplete());
            BOOST_REQUIRE(!psbt.inputs[0].final_script_witness.IsNull());
            const auto& signature = psbt.inputs[0].final_script_witness.stack.at(0);
            BOOST_REQUIRE(!signature.empty());
            BOOST_CHECK_EQUAL(signature.back(), static_cast<unsigned char>(sighash));

            const std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(psbt);
            BOOST_REQUIRE(txdata);
            BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &*txdata));

            CMutableTransaction final_tx;
            BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, final_tx));
            BOOST_CHECK(!final_tx.vin[0].scriptWitness.IsNull());
            BOOST_CHECK(!final_tx.mweb_tx.IsNull());

            // A completed canonical signature commits to the final bridge
            // script. Restoring its unsigned placeholder invalidates it.
            PartiallySignedTransaction changed_after_signing = psbt;
            changed_after_signing.outputs[0].script = GetScriptForPegin(mw::Hash{});
            const auto changed_txdata = PrecomputePSBTData(changed_after_signing);
            BOOST_REQUIRE(changed_txdata);
            BOOST_CHECK(!PSBTInputSignedAndVerified(changed_after_signing, 0, &*changed_txdata));
        }
    };
    check_signing(/*finalize=*/false, SIGHASH_ALL);
    check_signing(/*finalize=*/true, SIGHASH_ALL);
    check_signing(/*finalize=*/true, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
}

//! An Updater pass infers the creator draft's kernel fee and signs nothing; a Signer
//! pass then signs it with the descriptor-carried keys and finalizes it.
BOOST_AUTO_TEST_CASE(fill_infers_the_kernel_fee_then_signs_with_descriptor_keys)
{
    PartiallySignedTransaction psbt = KeylessDraft(/*paid_index=*/0, /*input_amount=*/100'000, /*output_amount=*/90'000);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = false}, complete));
    BOOST_CHECK(!complete);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});
    BOOST_REQUIRE(psbt.kernels[0].features);
    BOOST_CHECK(*psbt.kernels[0].features & Kernel::FEE_FEATURE_BIT);
    BOOST_CHECK(!psbt.inputs[0].mweb_sig);
    BOOST_CHECK(!psbt.outputs[0].mweb_sig);
    BOOST_CHECK(!psbt.kernels[0].sig);
    BOOST_CHECK(!psbt.mweb_tx_offset);

    size_t n_signed = 0;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete, &n_signed));
    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.IsComplete());
    BOOST_CHECK_EQUAL(n_signed, 1U);
    BOOST_CHECK(psbt.inputs[0].mweb_sig);
    BOOST_CHECK(psbt.outputs[0].mweb_rangeproof);
    BOOST_CHECK(psbt.outputs[0].mweb_sig);
    BOOST_CHECK(psbt.kernels[0].sig);
    BOOST_CHECK(psbt.mweb_tx_offset);
    BOOST_CHECK(psbt.mweb_stealth_offset);

    CMutableTransaction final_tx;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, final_tx));
    const CTransaction final{final_tx};
    BOOST_REQUIRE(final.mweb_tx.m_transaction);
    BOOST_CHECK_NO_THROW(final.mweb_tx.m_transaction->Validate());
}

//! A creator draft encodes its canonical recipient as a kernel pegout before filling.
BOOST_AUTO_TEST_CASE(fill_infers_the_pegout_creator_fee_then_signs_with_descriptor_keys)
{
    const CKey recipient_key = psbt_test::ToCKey(psbt_test::TestSecret('7'));
    const CScript recipient_script = GetScriptForDestination(WitnessV0KeyHash(recipient_key.GetPubKey()));
    PartiallySignedTransaction psbt = KeylessDraft(/*paid_index=*/0, /*input_amount=*/100'000, /*output_amount=*/90'000);
    psbt.outputs.clear();
    psbt.kernels.emplace_back().pegouts.emplace_back(90'000, recipient_script);
    BOOST_CHECK(!psbt.kernels[0].fee);

    LOCK(m_wallet.cs_wallet);
    bool complete = false;
    size_t n_signed = 0;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete, &n_signed));
    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.IsComplete());
    BOOST_CHECK_EQUAL(n_signed, 1U);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});
    BOOST_REQUIRE(psbt.kernels[0].features);
    BOOST_CHECK(*psbt.kernels[0].features & Kernel::FEE_FEATURE_BIT);
    BOOST_CHECK(*psbt.kernels[0].features & Kernel::PEGOUT_FEATURE_BIT);
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));

    CMutableTransaction final_tx;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, final_tx));
    BOOST_CHECK(final_tx.vin.empty());
    BOOST_CHECK(final_tx.vout.empty());
    const CTransaction final{final_tx};
    BOOST_REQUIRE(final.mweb_tx.m_transaction);
    BOOST_REQUIRE_EQUAL(final.mweb_tx.m_transaction->GetInputs().size(), 1U);
    BOOST_CHECK(final.mweb_tx.m_transaction->GetOutputs().empty());
    BOOST_REQUIRE_EQUAL(final.mweb_tx.m_transaction->GetKernels().size(), 1U);
    BOOST_CHECK_EQUAL(final.mweb_tx.m_transaction->GetKernels()[0].GetFee(), 10'000);
    const auto pegouts = final.mweb_tx.m_transaction->GetPegOuts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK_EQUAL(pegouts[0].GetAmount(), 90'000);
    BOOST_CHECK(pegouts[0].GetScriptPubKey() == recipient_script);
    BOOST_CHECK_NO_THROW(final.mweb_tx.m_transaction->Validate());
}

//! A Signer-less pass over a mixed peg-in leaves every signature, the offsets and the
//! placeholder peg-in script alone.
BOOST_AUTO_TEST_CASE(fill_without_signing_produces_no_signatures)
{
    const CKey key = psbt_test::ToCKey(psbt_test::TestSecret('7'));
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    BOOST_REQUIRE(CreateDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)), /*success=*/true));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(100'000, GetScriptForPegin(mw::Hash{}));
    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = psbt_test::TestStealthAddress('1', '2');
    mtx.mweb_tx.outputs.push_back(std::move(output));
    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.pegin = 100'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].witness_utxo = CTxOut(110'000, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));

    bool complete = true;
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbt, {.sign = false, .finalize = true, .bip32_derivs = false}, complete));
    BOOST_CHECK(!complete);
    BOOST_CHECK(psbt.inputs[0].partial_sigs.empty());
    BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());
    BOOST_CHECK(!psbt.outputs[1].mweb_sig);
    BOOST_CHECK(!psbt.kernels[0].sig);
    BOOST_CHECK(!psbt.mweb_tx_offset);

    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script.IsMWEBPegin(&script_kernel_id));
    BOOST_CHECK(script_kernel_id.IsZero());
}

//! A coin the wallet received signs through FillPSBT, whether its stored record keeps
//! the address and shared secret or they must be recovered.
BOOST_AUTO_TEST_CASE(wallet_coin_signs_with_stored_or_recovered_metadata)
{
    StealthAddress address;
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();
        address = NewMWEBAddress(m_wallet);
    }
    const Output received = Output::Create(nullptr, SecretKey::Random(), SecretKey::Random(), address, 100'000, {});
    mw::Coin original;
    {
        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, original));
    }

    for (int metadata = 0; metadata < 3; ++metadata) {
        BOOST_TEST_CONTEXT("metadata variant " << metadata) {
            mw::Coin coin = original;
            if (metadata > 0) coin.address.reset();
            if (metadata > 1) coin.shared_secret.reset();
            LOCK(m_wallet.cs_wallet);
            m_wallet.GetMWWallet()->LoadToWallet(coin);

            CheckReceivedOutputSigning(m_wallet, received);
        }
    }
}

// Fixed account change keeps index 0 when recipient metadata must be recovered.
BOOST_AUTO_TEST_CASE(change_coin_rewind_restores_metadata_and_psbt_spendability)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const auto keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain && keychain->HasSpendSecret());
    StealthAddress address;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*account, address));
    BOOST_CHECK(address == keychain->GetStealthAddress(mw::CHANGE_INDEX));
    const Output received = Output::Create(nullptr, SecretKey::Random(), SecretKey::Random(), address, 100'000, {});
    mw::Coin original;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, original));
    BOOST_CHECK(original.IsMine());
    BOOST_CHECK(original.IsChange());
    BOOST_REQUIRE(original.HasSpendMaterial());

    // Keep the known change index and amount, but leave neither recipient
    // metadata nor cached spend material to satisfy the recovery assertions.
    mw::Coin sparse = original.SanitizeForDisk();
    sparse.address.reset();
    sparse.shared_secret.reset();
    sparse.master_scan_key_id.reset();
    WalletBatch batch(m_wallet.GetDatabase());
    BOOST_REQUIRE(batch.WriteMWEBCoin(sparse));
    m_wallet.GetMWWallet()->LoadToWallet(sparse);
    const auto read_persisted = [&] {
        mw::Coin persisted;
        BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(
            std::make_pair(DBKeys::MWEB_COIN, received.GetOutputID()), persisted));
        return persisted;
    };
    BOOST_CHECK(read_persisted().Serialized() == sparse.Serialized());
    mw::Coin before;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(received.GetOutputID(), before));
    BOOST_CHECK(before.Serialized() == sparse.Serialized());
    BOOST_CHECK(!before.HasAddress() && !before.HasSharedSecret());
    BOOST_CHECK(!before.HasSpendMaterial());

    mw::Coin repaired;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, repaired));
    BOOST_CHECK(repaired.output_id == received.GetOutputID());
    BOOST_CHECK_EQUAL(repaired.amount, 100'000);
    BOOST_CHECK_EQUAL(repaired.address_index, mw::CHANGE_INDEX);
    BOOST_CHECK(repaired.IsMine() && repaired.IsChange());
    BOOST_REQUIRE(repaired.address);
    BOOST_CHECK(*repaired.address == address);
    BOOST_CHECK(m_wallet.GetMWWallet()->IsChange(*repaired.address));
    BOOST_CHECK(m_wallet.GetMWEBAccountForCoin(repaired) == account);
    BOOST_REQUIRE(repaired.shared_secret);
    BOOST_CHECK(repaired.shared_secret == original.shared_secret);
    BOOST_CHECK(repaired.master_scan_key_id == keychain->GetMasterScanKeyID());
    BOOST_REQUIRE(repaired.HasSpendMaterial());
    BOOST_CHECK(PublicKey::From(*repaired.spend_key) == received.GetReceiverPubKey());
    mw::Coin live;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(received.GetOutputID(), live));
    BOOST_CHECK(live.Serialized() == repaired.Serialized());

    const mw::Coin persisted = read_persisted();
    BOOST_CHECK(!persisted.spend_key && !persisted.blind && !persisted.sender_key);
    BOOST_CHECK(persisted.Serialized() == repaired.SanitizeForDisk().Serialized());
    BOOST_CHECK(persisted.Serialized() == original.SanitizeForDisk().Serialized());
    const auto restored_key = keychain->CalculateOutputSpendKey(persisted);
    BOOST_REQUIRE(restored_key);
    BOOST_CHECK(PublicKey::From(*restored_key) == received.GetReceiverPubKey());

    // Check recovery and durability before FillPSBT can derive any input data.
    mw::Coin repeated;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, repeated));
    BOOST_CHECK(repeated.Serialized() == repaired.Serialized());
    BOOST_CHECK(read_persisted().Serialized() == persisted.Serialized());
    CheckReceivedOutputSigning(m_wallet, received);
    BOOST_CHECK(read_persisted().Serialized() == persisted.Serialized());
}

BOOST_AUTO_TEST_CASE(self_payment_between_accounts_rewinds_and_spends)
{
    LOCK(m_wallet.cs_wallet);
    CheckCrossAccountSelfPayments(m_wallet, /*recipient_index=*/7);
}

BOOST_AUTO_TEST_CASE(self_payment_to_other_account_change_rewinds_and_spends)
{
    LOCK(m_wallet.cs_wallet);
    CheckCrossAccountSelfPayments(m_wallet, mw::CHANGE_INDEX);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
