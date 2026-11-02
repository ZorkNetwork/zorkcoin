// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <key.h>
#include <key_io.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/keychain.h>
#include <mweb/mweb_wallet.h>
#include <outputtype.h>
#include <test_framework/tx_builder.h>
#include <univalue.h>
#include <util/translation.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wallet {
namespace {

class KeypoolArgGuard
{
    const std::optional<std::string> m_previous{gArgs.GetArg("-keypool")};

public:
    explicit KeypoolArgGuard(int size) { gArgs.ForceSetArg("-keypool", std::to_string(size)); }
    ~KeypoolArgGuard()
    {
        if (m_previous) {
            gArgs.ForceSetArg("-keypool", *m_previous);
        } else {
            gArgs.LockSettings([](common::Settings& settings) { settings.forced_settings.erase("keypool"); });
        }
    }
};

class SenderIndexFailureDatabase : public MockableSQLiteDatabase
{
    class Batch : public MockableSQLiteBatch
    {
        SenderIndexFailureDatabase& m_database;

        bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override
        {
            ++m_database.write_attempts;
            if (m_database.reject_index && key.str() == m_database.index_key) {
                ++m_database.rejected_writes;
                return false;
            }
            return MockableSQLiteBatch::WriteKey(std::move(key), std::move(value), overwrite);
        }

    public:
        explicit Batch(SenderIndexFailureDatabase& database)
            : MockableSQLiteBatch(database), m_database(database) {}
    };

public:
    bool reject_index{false};
    std::string index_key;
    size_t rejected_writes{0};
    size_t write_attempts{0};

    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<Batch>(*this); }
};

mw::Keychain::Ptr ActiveKeychain(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    DescriptorScriptPubKeyMan* account = wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    return keychain;
}

CKeyID MasterScanKeyId(const mw::Keychain::Ptr& keychain)
{
    return keychain->GetMasterScanKeyID();
}

util::Result<SecretKey> GenerateSenderKey(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    return wallet.GetMWWallet()->GenerateSenderKey();
}

uint64_t ReadSenderIndex(CWallet& wallet, const CKeyID& master_scan_keyid)
{
    uint64_t next_index{0};
    BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(
        std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid), next_index));
    return next_index;
}

Output SentOutput(const mw::Keychain::Ptr& keychain, uint64_t sender_index, CAmount amount)
{
    return Output::Create(
        /*blind_out=*/nullptr,
        keychain->GetSenderSigningKey(sender_index),
        keychain->GetRewindKey(),
        StealthAddress::Random(),
        amount,
        /*extra_data=*/{});
}

void SetupMWEBWallet(CWallet& wallet, std::optional<bool> deterministic_senders = true) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetMWEBDeterministicSenders(deterministic_senders);
    wallet.SetupDescriptorScriptPubKeyMans();
}

BOOST_FIXTURE_TEST_SUITE(mweb_sender_key_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(sender_keys_match_derivation_and_advance)
{
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);

    const util::Result<SecretKey> first = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first);
    BOOST_CHECK(*first == keychain->GetSenderSigningKey(0));
    BOOST_CHECK(*first == mw::DeriveSenderSigningKey(keychain->GetScanSecret(), 0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 1U);

    const util::Result<SecretKey> second = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(second);
    BOOST_CHECK(*second == keychain->GetSenderSigningKey(1));
    BOOST_CHECK(*second != *first);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 2U);
}

BOOST_AUTO_TEST_CASE(persisted_sender_index_restores_sequence)
{
    const fs::path path = m_path_root / "sender_index_wallet";
    const auto open_database = [&](bool create) {
        DatabaseStatus status;
        bilingual_str error;
        auto database = MakeDatabase(path, {.require_existing = !create, .require_create = create,
            .require_format = DatabaseFormat::SQLITE}, status, error);
        BOOST_REQUIRE_MESSAGE(database, error.original);
        return database;
    };
    CKeyID master_scan_keyid;
    SecretKey scan_secret;
    {
        CWallet original{m_node.chain.get(), "sender_index", open_database(/*create=*/true)};
        LOCK(original.cs_wallet);
        SetupMWEBWallet(original);
        const auto keychain = ActiveKeychain(original);
        master_scan_keyid = MasterScanKeyId(keychain);
        scan_secret = keychain->GetScanSecret();
        BOOST_REQUIRE(GenerateSenderKey(original));
        BOOST_REQUIRE(GenerateSenderKey(original));
        BOOST_REQUIRE_EQUAL(ReadSenderIndex(original, master_scan_keyid), 2U);
    }

    CWallet reloaded{m_node.chain.get(), "sender_index", open_database(/*create=*/false)};
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    BOOST_REQUIRE_MESSAGE(reloaded.PopulateWalletFromDB(error, warnings) == DBErrors::LOAD_OK, error.original);
    LOCK(reloaded.cs_wallet);
    const auto keychain = ActiveKeychain(reloaded);
    BOOST_CHECK(MasterScanKeyId(keychain) == master_scan_keyid);
    BOOST_CHECK(keychain->GetScanSecret() == scan_secret);
    BOOST_CHECK_EQUAL(ReadSenderIndex(reloaded, master_scan_keyid), 2U);

    const util::Result<SecretKey> restored = GenerateSenderKey(reloaded);
    BOOST_REQUIRE(restored);
    BOOST_CHECK(*restored == mw::DeriveSenderSigningKey(scan_secret, 2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(reloaded, master_scan_keyid), 3U);
}

BOOST_AUTO_TEST_CASE(account_activation_keeps_sender_sequences_independent)
{
    const KeypoolArgGuard keypool_size{3};
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    auto* first_account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(first_account);
    const auto first_keychain = ActiveKeychain(m_wallet);
    const auto first_id = MasterScanKeyId(first_keychain);
    const auto first_destination = m_wallet.GetNewDestination(OutputType::MWEB, "inactive receive");
    BOOST_REQUIRE(first_destination);
    const auto* first_address = std::get_if<StealthAddress>(&*first_destination);
    BOOST_REQUIRE(first_address);
    for (uint64_t index = 0; index < 2; ++index) {
        const auto key = GenerateSenderKey(m_wallet);
        BOOST_REQUIRE(key);
        BOOST_CHECK(*key == first_keychain->GetSenderSigningKey(index));
    }
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_id), 2U);

    CExtKey second_master;
    second_master.SetSeed(GenerateRandomKey());
    WalletBatch batch(m_wallet.GetDatabase());
    auto& second_account = m_wallet.SetupDescriptorScriptPubKeyMan(batch, second_master, OutputType::MWEB, false);
    const auto second_keychain = ActiveKeychain(m_wallet);
    const auto second_id = MasterScanKeyId(second_keychain);
    BOOST_REQUIRE(second_id != first_id);
    const auto second_first = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(second_first);
    BOOST_CHECK(*second_first == second_keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_id), 1U);

    m_wallet.AddActiveScriptPubKeyMan(first_account->GetID(), OutputType::MWEB, false);
    BOOST_CHECK(MasterScanKeyId(ActiveKeychain(m_wallet)) == first_id);
    const auto first_resumed = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_resumed);
    BOOST_CHECK(*first_resumed == first_keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_id), 3U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_id), 1U);

    m_wallet.AddActiveScriptPubKeyMan(second_account.GetID(), OutputType::MWEB, false);
    const auto second_resumed = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(second_resumed);
    BOOST_CHECK(*second_resumed == second_keychain->GetSenderSigningKey(1));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_id), 3U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_id), 2U);

    // Both receive and sender recovery remain available on the inactive
    // account, while generating keys still uses the current active account.
    BOOST_REQUIRE(m_wallet.GetExternalMWEBScriptPubKeyMan() != first_account);
    const Output received = Output::Create(nullptr, SecretKey::Random(), *first_address, COIN);
    mw::Coin received_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(received, received_coin));
    BOOST_CHECK(received_coin.IsMine());
    BOOST_REQUIRE(received_coin.master_scan_key_id);
    BOOST_CHECK(*received_coin.master_scan_key_id == first_id);
    BOOST_REQUIRE(received_coin.address);
    BOOST_CHECK(*received_coin.address == *first_address);
    BOOST_REQUIRE(received_coin.spend_key);
    BOOST_CHECK(PublicKey::From(*received_coin.spend_key) == received.GetReceiverPubKey());

    const Output sent = SentOutput(first_keychain, /*sender_index=*/3, 2 * COIN);
    const auto candidates = m_wallet.GetMWWallet()->OutputsToRewind(std::vector<Output>{sent});
    BOOST_REQUIRE_EQUAL(candidates.size(), 1U);
    BOOST_CHECK_EQUAL(candidates.front(), 0U);
    mw::Coin sent_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(sent, sent_coin));
    BOOST_CHECK(!sent_coin.IsMine());
    BOOST_REQUIRE(sent_coin.master_scan_key_id);
    BOOST_CHECK(*sent_coin.master_scan_key_id == first_id);
    BOOST_REQUIRE(sent_coin.sender_key);
    BOOST_CHECK(*sent_coin.sender_key == first_keychain->GetSenderSigningKey(3));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_id), 4U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_id), 2U);
    BOOST_CHECK(m_wallet.GetExternalMWEBScriptPubKeyMan() == &second_account);
    const auto active_next = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(active_next);
    BOOST_CHECK(*active_next == second_keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_id), 3U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_id), 4U);
}

BOOST_AUTO_TEST_CASE(lock_and_unlock_preserve_post_encryption_sender_sequence)
{
    WITH_LOCK(m_wallet.cs_wallet, SetupMWEBWallet(m_wallet));
    const SecureString passphrase{"mweb-sender-sequence"};
    BOOST_REQUIRE(m_wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(m_wallet.IsLocked());
    BOOST_REQUIRE(m_wallet.Unlock(passphrase));

    // Encryption rotates the active account. Establish this sequence only on
    // the new account, then keep its identity across lock and unlock.
    mw::Keychain::Ptr initial_keychain;
    uint256 account_id;
    {
        LOCK(m_wallet.cs_wallet);
        initial_keychain = ActiveKeychain(m_wallet);
        BOOST_REQUIRE(initial_keychain->HasSpendSecret());
        BOOST_REQUIRE(initial_keychain->HasSpendPubKey());
        account_id = m_wallet.GetExternalMWEBScriptPubKeyMan()->GetID();
    }
    const auto scan_id = MasterScanKeyId(initial_keychain);
    const SecretKey scan_secret = initial_keychain->GetScanSecret();
    const SecretKey rewind_key = initial_keychain->GetRewindKey();
    const PublicKey spend_pubkey = *initial_keychain->GetSpendPubKey();
    const auto check_sequence = [&](uint64_t index, bool spendable) {
        LOCK(m_wallet.cs_wallet);
        const auto keychain = ActiveKeychain(m_wallet);
        BOOST_CHECK(m_wallet.GetExternalMWEBScriptPubKeyMan()->GetID() == account_id);
        BOOST_CHECK(MasterScanKeyId(keychain) == scan_id);
        BOOST_CHECK(keychain->GetScanSecret() == scan_secret);
        BOOST_CHECK(keychain->GetRewindKey() == rewind_key);
        BOOST_REQUIRE(keychain->HasSpendPubKey());
        BOOST_CHECK(*keychain->GetSpendPubKey() == spend_pubkey);
        BOOST_CHECK_EQUAL(m_wallet.IsLocked(), !spendable);
        BOOST_REQUIRE_EQUAL(keychain->HasSpendSecret(), spendable);
        if (spendable) {
            BOOST_CHECK(PublicKey::From(keychain->GetSpendKey(mw::CHANGE_INDEX)) ==
                        keychain->GetStealthAddress(mw::CHANGE_INDEX).GetSpendPubKey());
        }
        const auto sender_key = GenerateSenderKey(m_wallet);
        BOOST_REQUIRE(sender_key);
        BOOST_CHECK(*sender_key == mw::DeriveSenderSigningKey(scan_secret, index));
        BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), index + 1);
    };

    check_sequence(0, /*spendable=*/true);
    BOOST_REQUIRE(m_wallet.Lock());
    check_sequence(1, /*spendable=*/false);
    BOOST_REQUIRE(m_wallet.Unlock(passphrase));
    check_sequence(2, /*spendable=*/true);
}

BOOST_AUTO_TEST_CASE(sender_index_write_failure_retries_without_consuming_key)
{
    auto database = std::make_unique<SenderIndexFailureDatabase>();
    auto& failures = *database;
    CWallet wallet{m_node.chain.get(), "sender_index_failure", std::move(database)};
    LOCK(wallet.cs_wallet);
    SetupMWEBWallet(wallet);
    const auto keychain = ActiveKeychain(wallet);
    const auto master_scan_keyid = MasterScanKeyId(keychain);
    DataStream index_key;
    index_key << std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid);
    failures.index_key = index_key.str();

    failures.reject_index = true;
    const auto failed_initial = GenerateSenderKey(wallet);
    BOOST_REQUIRE(!failed_initial);
    BOOST_CHECK(util::ErrorString(failed_initial).original.find("Failed to write MWEB sender key index") != std::string::npos);
    BOOST_CHECK_EQUAL(failures.rejected_writes, 1U);
    BOOST_CHECK(!wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid)));
    failures.reject_index = false;
    const auto first = GenerateSenderKey(wallet);
    BOOST_REQUIRE(first);
    BOOST_CHECK(*first == keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, master_scan_keyid), 1U);

    failures.reject_index = true;
    const auto failed = GenerateSenderKey(wallet);
    BOOST_REQUIRE(!failed);
    BOOST_CHECK(util::ErrorString(failed).original.find("Failed to write MWEB sender key index") != std::string::npos);
    BOOST_CHECK_EQUAL(failures.rejected_writes, 2U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, master_scan_keyid), 1U);

    failures.reject_index = false;
    const auto retry = GenerateSenderKey(wallet);
    BOOST_REQUIRE(retry);
    BOOST_CHECK(*retry == keychain->GetSenderSigningKey(1));
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, master_scan_keyid), 2U);
    const auto next = GenerateSenderKey(wallet);
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, master_scan_keyid), 3U);
    BOOST_CHECK_EQUAL(failures.rejected_writes, 2U);
}

BOOST_AUTO_TEST_CASE(sender_index_exhaustion_does_not_wrap)
{
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);
    const uint64_t last_index = std::numeric_limits<uint64_t>::max() - 1;
    m_wallet.GetMWWallet()->LoadNextSenderKeyIndex(master_scan_keyid, last_index);

    const util::Result<SecretKey> last_key = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(last_key);
    BOOST_CHECK(*last_key == keychain->GetSenderSigningKey(last_index));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), std::numeric_limits<uint64_t>::max());

    const util::Result<SecretKey> exhausted = GenerateSenderKey(m_wallet);
    BOOST_CHECK(!exhausted);
    BOOST_CHECK(util::ErrorString(exhausted).original.find("exhausted") != std::string::npos);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(missing_keychain_uses_ephemeral_sender_keys)
{
    auto database = std::make_unique<SenderIndexFailureDatabase>();
    const auto& observed = *database;
    CWallet wallet{m_node.chain.get(), "ephemeral_sender", std::move(database)};
    LOCK(wallet.cs_wallet);
    // Descriptor flag without SetupDescriptorScriptPubKeyMans: no MWEB keychain.
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    BOOST_REQUIRE(!wallet.GetExternalMWEBScriptPubKeyMan());
    const auto writes_before = observed.write_attempts;

    const util::Result<SecretKey> first = GenerateSenderKey(wallet);
    const util::Result<SecretKey> second = GenerateSenderKey(wallet);
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);
    BOOST_CHECK(!first->IsNull());
    BOOST_CHECK(!second->IsNull());
    BOOST_CHECK(*first != *second);
    // No sender-index or wallet-version write occurs on the random fallback.
    BOOST_CHECK_EQUAL(observed.write_attempts, writes_before);
}

BOOST_AUTO_TEST_CASE(sender_rewind_recovers_amount_with_proof_nonce)
{
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);
    constexpr CAmount AMOUNT{1'234'567};
    const Output output = SentOutput(keychain, /*sender_index=*/0, AMOUNT);

    // Foreign recipient: not ours by receive path, but sent-by-me via K_s.
    mw::Coin receive_only;
    BOOST_CHECK(!keychain->RewindOutput(output, receive_only));

    const std::vector<Output> outputs{output};
    const std::vector<size_t> to_rewind = m_wallet.GetMWWallet()->OutputsToRewind(outputs);
    BOOST_REQUIRE_EQUAL(to_rewind.size(), 1U);
    BOOST_CHECK_EQUAL(to_rewind[0], 0U);

    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, coin));
    BOOST_CHECK_EQUAL(coin.amount, AMOUNT);
    BOOST_REQUIRE(coin.shared_secret);
    BOOST_REQUIRE(coin.sender_key);
    BOOST_CHECK(*coin.sender_key == keychain->GetSenderSigningKey(0));

    // Persist sanitize strips spend material; amount + shared_secret remain.
    const mw::Coin sanitized = coin.SanitizeForDisk();
    BOOST_CHECK(!sanitized.sender_key);
    BOOST_CHECK(!sanitized.blind);
    BOOST_CHECK_EQUAL(sanitized.amount, AMOUNT);
    BOOST_CHECK(sanitized.shared_secret);

    // Raw-hash proof nonce must not rewind the bulletproof message.
    const SecretKey wrong_nonce = SecretKey::FromHash(Hashed(output.GetCommitment()));
    const BigInt<32> wrong_msg = Bulletproofs::RewindMessage(
        output.GetCommitment(),
        *output.GetRangeProof(),
        output.GetOutputMessage().Serialized(),
        wrong_nonce);
    BOOST_CHECK(wrong_msg.IsZero() || SecretKey(wrong_msg.data()) != *coin.shared_secret);
}

BOOST_AUTO_TEST_CASE(sender_lookahead_includes_sent_outputs)
{
    gArgs.ForceSetArg("-keypool", "3");
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);

    const Output in_range = SentOutput(keychain, /*sender_index=*/2, 2'000'000);
    const Output beyond = SentOutput(keychain, /*sender_index=*/3, 3'000'000);

    BOOST_CHECK(m_wallet.GetMWWallet()->OutputsToRewind(std::vector<Output>{beyond}).empty());
    mw::Coin boundary_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(in_range, boundary_coin));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, MasterScanKeyId(keychain)), 3U);

    const std::vector<size_t> after = m_wallet.GetMWWallet()->OutputsToRewind(std::vector<Output>{beyond});
    BOOST_REQUIRE_EQUAL(after.size(), 1U);

    mw::Coin beyond_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(beyond, beyond_coin));
    BOOST_REQUIRE(beyond_coin.sender_key);
    BOOST_CHECK(*beyond_coin.sender_key == keychain->GetSenderSigningKey(3));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, MasterScanKeyId(keychain)), 4U);
    const auto next = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == keychain->GetSenderSigningKey(4));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, MasterScanKeyId(keychain)), 5U);

    // Older history cannot rewind the sequence after a newer match and generation.
    mw::Coin older;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(in_range, older));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, MasterScanKeyId(keychain)), 5U);
    const auto continued = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(continued);
    BOOST_CHECK(*continued == keychain->GetSenderSigningKey(5));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, MasterScanKeyId(keychain)), 6U);
    gArgs.ForceSetArg("-keypool", "");
}

BOOST_AUTO_TEST_CASE(shared_scan_sender_lookahead_survives_account_reload)
{
    const KeypoolArgGuard keypool_size{3};
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet);
    auto* first_account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(first_account);
    const auto first_keychain = ActiveKeychain(m_wallet);
    const auto scan_id = MasterScanKeyId(first_keychain);
    CKey scan;
    scan.Set(first_keychain->GetScanSecret().data(), first_keychain->GetScanSecret().data() + SecretKey::SIZE, true);
    const auto second_spend = GenerateRandomKey();
    auto* second_account = CreateDescriptor(m_wallet,
        strprintf("mweb(%s,%s,*)", EncodeSecret(scan), EncodeSecret(second_spend)), /*success=*/true);
    BOOST_REQUIRE(second_account);
    const auto second_keychain = WITH_LOCK(second_account->cs_desc_man, return second_account->GetMWEBKeychain());
    BOOST_REQUIRE(second_keychain);
    BOOST_REQUIRE(first_keychain->GetSpendPubKey() != second_keychain->GetSpendPubKey());
    BOOST_REQUIRE(MasterScanKeyId(second_keychain) == scan_id);
    const auto boundary = SentOutput(first_keychain, 2, 100'000);
    const auto beyond = SentOutput(second_keychain, 3, 200'000);
    BOOST_CHECK(m_wallet.GetMWWallet()->OutputsToRewind(std::vector<Output>{beyond}).empty());
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(boundary, coin));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), 3U);

    // One account owns reserved receive/change indices in this wallet format.
    // Reload two supported accounts sharing its scan secret instead of creating
    // Litecoin's separate legacy receive/change managers.
    for (auto* account : {first_account, second_account}) {
        account->LoadMWEBKeychain();
        WITH_LOCK(account->cs_desc_man, account->ReloadMWEBScanMapsFromInternalDescriptors());
    }
    m_wallet.AddActiveScriptPubKeyMan(second_account->GetID(), OutputType::MWEB, false);
    BOOST_CHECK(MasterScanKeyId(ActiveKeychain(m_wallet)) == scan_id);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), 3U);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(beyond, coin));
    BOOST_CHECK_EQUAL(coin.amount, 200'000);
    BOOST_REQUIRE(coin.sender_key);
    BOOST_CHECK(*coin.sender_key == second_keychain->GetSenderSigningKey(3));
    BOOST_CHECK(coin.master_scan_key_id == scan_id);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), 4U);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(boundary, coin));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), 4U);
    const auto next = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == second_keychain->GetSenderSigningKey(4));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, scan_id), 5U);
}

BOOST_AUTO_TEST_CASE(default_sender_key_policy_uses_random_ephemeral_keys_until_opted_in)
{
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet, /*deterministic_senders=*/std::nullopt);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);

    BOOST_CHECK(!m_wallet.GetMWWallet()->UseDeterministicSenderKeys());
    const util::Result<SecretKey> first_random = GenerateSenderKey(m_wallet);
    const util::Result<SecretKey> second_random = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_random);
    BOOST_REQUIRE(second_random);
    BOOST_CHECK(*first_random != *second_random);
    BOOST_CHECK(*first_random != keychain->GetSenderSigningKey(0));
    BOOST_CHECK(*second_random != keychain->GetSenderSigningKey(0));
    BOOST_CHECK(!m_wallet.GetDatabase().MakeBatch()->Exists(
        std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid)));

    // Opting in via runtime argument or wallet setting starts the deterministic sequence at 0.
    gArgs.ForceSetArg("-mwebdeterministicsenders", "1");
    BOOST_CHECK(m_wallet.GetMWWallet()->UseDeterministicSenderKeys());
    const util::Result<SecretKey> first_det = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_det);
    BOOST_CHECK(*first_det == keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 1U);
    gArgs.LockSettings([](common::Settings& settings) { settings.forced_settings.erase("mwebdeterministicsenders"); });

    // Once a wallet has advanced its persisted sender index, migration keeps deterministic mode
    // unless -mwebdeterministicsenders=0 explicitly disables it.
    BOOST_CHECK(m_wallet.GetMWWallet()->UseDeterministicSenderKeys());
    gArgs.ForceSetArg("-mwebdeterministicsenders", "0");
    BOOST_CHECK(!m_wallet.GetMWWallet()->UseDeterministicSenderKeys());
    const util::Result<SecretKey> random_override = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(random_override);
    BOOST_CHECK(*random_override != keychain->GetSenderSigningKey(1));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 1U);
    gArgs.LockSettings([](common::Settings& settings) { settings.forced_settings.erase("mwebdeterministicsenders"); });
}

BOOST_AUTO_TEST_CASE(deterministic_sender_mode_tolerates_opaque_21x_spend_history)
{
    LOCK(m_wallet.cs_wallet);
    SetupMWEBWallet(m_wallet, /*deterministic_senders=*/true);
    const mw::Keychain::Ptr keychain = ActiveKeychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);

    StealthAddress receive_addr;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, receive_addr));
    StealthAddress change_addr;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*account, change_addr));

    // Fund with 5 COIN, then spend into a 21.x-style external output (4-arg Output::Create
    // with random sender key and random rangeproof nonces) plus 21.x-style change output.
    constexpr CAmount input_amount{5 * COIN};
    constexpr CAmount sent_amount{2 * COIN};
    constexpr CAmount fee_amount{10'000};
    constexpr CAmount change_amount{input_amount - sent_amount - fee_amount};

    const Output funding_out = Output::Create(nullptr, SecretKey::Random(), receive_addr, input_amount);
    mw::Coin funding_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(funding_out, funding_coin));
    BOOST_REQUIRE(funding_coin.IsMine());
    BOOST_REQUIRE(funding_coin.HasSpendMaterial());

    const auto legacy_21x_spend = test::TxBuilder()
        .AddInput(funding_coin.amount, *funding_coin.spend_key, *funding_coin.blind, funding_coin.output_id)
        .AddOutput(sent_amount, SecretKey::Random(), StealthAddress::Random())
        .AddOutput(change_amount, SecretKey::Random(), change_addr)
        .AddPlainKernel(fee_amount)
        .Build();
    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*legacy_21x_spend.GetTransaction());
    const CTransactionRef spend_tx = MakeTransactionRef(std::move(mtx));

    const auto rewound = m_wallet.GetMWWallet()->RewindOutputs(*spend_tx);
    BOOST_REQUIRE_EQUAL(rewound.size(), 1U);
    BOOST_CHECK(rewound.front().IsMine());
    BOOST_CHECK(rewound.front().IsChange());
    BOOST_CHECK_EQUAL(rewound.front().amount, change_amount);
    BOOST_CHECK(!m_wallet.GetDatabase().MakeBatch()->Exists(
        std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid)));

    const CWalletTx* wtx = m_wallet.AddToWallet(spend_tx, TxStateInMempool{});
    BOOST_REQUIRE(wtx);
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, *wtx, /*avoid_reuse=*/false), input_amount);
    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, *wtx, /*avoid_reuse=*/false), change_amount);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, *wtx), fee_amount);
    BOOST_CHECK_EQUAL(CachedTxGetAmount(m_wallet, *wtx), -sent_amount);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
