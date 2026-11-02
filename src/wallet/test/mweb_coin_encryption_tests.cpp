// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_types.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/stealth_address.h>
#include <support/allocators/secure.h>
#include <test/util/setup_common.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <span>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(mweb_coin_encryption_tests, WalletTestingSetup)

static mw::Coin MakeFullCoin(const StealthAddress& addr, uint32_t index, CAmount amount)
{
    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, amount);
    mw::Coin coin;
    coin.address_index = index;
    coin.address = addr;
    coin.amount = amount;
    coin.output_id = output.GetOutputID();
    coin.spend_key = SecretKey::Random();
    coin.blind = blind;
    coin.sender_key = SecretKey::Random();
    coin.shared_secret = SecretKey::Random();
    return coin;
}

BOOST_AUTO_TEST_CASE(write_mweb_coin_sanitizes_spend_material)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress addr;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, addr));

    mw::Coin full = MakeFullCoin(addr, 2, COIN);
    BOOST_REQUIRE(full.HasSpendMaterial());
    BOOST_REQUIRE(!!full.sender_key);

    WalletBatch batch(m_wallet.GetDatabase());
    BOOST_REQUIRE(batch.WriteMWEBCoin(full));

    mw::Coin loaded;
    auto db_batch = m_wallet.GetDatabase().MakeBatch();
    BOOST_REQUIRE(db_batch->Read(std::make_pair(DBKeys::MWEB_COIN, full.output_id), loaded));
    BOOST_CHECK(!loaded.spend_key);
    BOOST_CHECK(!loaded.blind);
    BOOST_CHECK(!loaded.sender_key);
    BOOST_CHECK(loaded.HasSharedSecret());
    BOOST_CHECK(loaded.address == full.address);
    BOOST_CHECK_EQUAL(loaded.amount, full.amount);
    BOOST_CHECK(loaded.output_id == full.output_id);
    BOOST_CHECK_EQUAL(loaded.address_index, full.address_index);
}

BOOST_AUTO_TEST_CASE(wallet_tx_info_roundtrip_sanitizes)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress addr;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 3, addr));

    mw::Coin full = MakeFullCoin(addr, 3, 2 * COIN);
    MWEB::WalletTxInfo info{full};

    const std::string hex = info.ToHex();
    MWEB::WalletTxInfo roundtrip = MWEB::WalletTxInfo::FromHex(hex);
    BOOST_REQUIRE(roundtrip.received_coin);
    BOOST_CHECK(!roundtrip.received_coin->spend_key);
    BOOST_CHECK(!roundtrip.received_coin->blind);
    BOOST_CHECK(!roundtrip.received_coin->sender_key);
    BOOST_CHECK(roundtrip.received_coin->HasSharedSecret());
    BOOST_CHECK_EQUAL(roundtrip.received_coin->amount, full.amount);
}

BOOST_AUTO_TEST_CASE(upgrade_and_lock_spend_material)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress addr;
    WalletBatch batch(m_wallet.GetDatabase());
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, addr));
    {
        LOCK(account->cs_desc_man);
        account->PersistMWEBInternalIndex(batch, 2, addr);
        account->LoadMWEBKeychain();
    }
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    BOOST_REQUIRE(keychain->HasSpendSecret());

    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, COIN);
    mw::Coin coin;
    BOOST_REQUIRE(keychain->RewindOutput(output, coin));
    BOOST_REQUIRE(coin.HasSpendMaterial());
    BOOST_REQUIRE(coin.HasSharedSecret());

    // Simulate disk/memory form after locked receive: shared_secret only.
    coin.ClearSpendMaterial();
    BOOST_REQUIRE(!coin.HasSpendMaterial());

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
    BOOST_CHECK(upgraded.HasSpendMaterial());
    BOOST_CHECK(m_wallet.mapWallet.at(wtx_hash).mweb_wtx_info->received_coin->HasSpendMaterial());

    // Disk must remain sanitized.
    BOOST_REQUIRE(batch.WriteMWEBCoin(upgraded));
    mw::Coin on_disk;
    auto db_batch = m_wallet.GetDatabase().MakeBatch();
    BOOST_REQUIRE(db_batch->Read(std::make_pair(DBKeys::MWEB_COIN, upgraded.output_id), on_disk));
    BOOST_CHECK(!on_disk.HasSpendMaterial());
    BOOST_CHECK(on_disk.HasSharedSecret());

    m_wallet.GetMWWallet()->LockSpendMaterial();
    mw::Coin locked_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(coin.output_id, locked_coin));
    BOOST_CHECK(!locked_coin.HasSpendMaterial());
    BOOST_CHECK(!m_wallet.mapWallet.at(wtx_hash).mweb_wtx_info->received_coin->HasSpendMaterial());
}

BOOST_AUTO_TEST_CASE(rewind_output_across_lock_and_unlock)
{
    WITH_LOCK(m_wallet.cs_wallet, m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS); m_wallet.SetupDescriptorScriptPubKeyMans());
    const SecureString passphrase{"mweb"};
    BOOST_REQUIRE(m_wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(m_wallet.IsLocked());

    // Encryption rotates the seed, so take the address from the new account.
    StealthAddress addr;
    {
        LOCK(m_wallet.cs_wallet);
        DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
        BOOST_REQUIRE(account);
        BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, addr));
        WalletBatch batch(m_wallet.GetDatabase());
        LOCK(account->cs_desc_man);
        account->PersistMWEBInternalIndex(batch, 2, addr);
    }

    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, COIN);

    const auto read_persisted = [&] {
        mw::Coin persisted;
        BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(
            std::make_pair(DBKeys::MWEB_COIN, output.GetOutputID()), persisted));
        return persisted;
    };
    mw::Coin locked;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, locked));
    BOOST_CHECK(locked.HasSharedSecret());
    BOOST_CHECK(!locked.HasSpendMaterial());
    const auto durable_metadata = read_persisted().Serialized();
    BOOST_CHECK(durable_metadata == locked.SanitizeForDisk().Serialized());

    // Each state checks both the known coin and a new output, which is matched
    // through the account keychains rather than the coin cache.
    BOOST_REQUIRE(m_wallet.Unlock(passphrase));
    mw::Coin unlocked;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, unlocked));
    BOOST_CHECK(unlocked.HasSpendMaterial());
    BOOST_REQUIRE(unlocked.spend_key);
    BOOST_CHECK(PublicKey::From(*unlocked.spend_key) == output.GetReceiverPubKey());
    BOOST_CHECK(read_persisted().Serialized() == durable_metadata);
    mw::Coin unlocked_new;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), addr, COIN), unlocked_new));
    BOOST_CHECK(unlocked_new.HasSpendMaterial());

    BOOST_REQUIRE(m_wallet.Lock());
    mw::Coin relocked;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, relocked));
    BOOST_CHECK(!relocked.HasSpendMaterial());
    BOOST_CHECK(relocked.SanitizeForDisk().Serialized() == durable_metadata);
    BOOST_CHECK(read_persisted().Serialized() == durable_metadata);
    mw::Coin relocked_new;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), addr, COIN), relocked_new));
    BOOST_CHECK(relocked_new.HasSharedSecret());
    BOOST_CHECK(!relocked_new.HasSpendMaterial());

    mw::Coin stranger;
    BOOST_CHECK(!m_wallet.GetMWWallet()->RewindOutput(Output::Create(&blind, SecretKey::Random(), StealthAddress::Random(), COIN), stranger));
}

BOOST_AUTO_TEST_CASE(sparse_owned_coin_rewind_repairs_persisted_metadata_idempotently)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress address;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, address));
    WalletBatch batch(m_wallet.GetDatabase());
    {
        LOCK(account->cs_desc_man);
        account->PersistMWEBInternalIndex(batch, 2, address);
        account->LoadMWEBKeychain();
    }
    const auto keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    const Output output = Output::Create(nullptr, SecretKey::Random(), address, COIN);
    mw::Coin sparse;
    sparse.address_index = 2;
    sparse.amount = COIN;
    sparse.output_id = output.GetOutputID();
    BOOST_REQUIRE(batch.WriteMWEBCoin(sparse));
    m_wallet.GetMWWallet()->LoadToWallet(sparse);

    const auto read_persisted = [&] {
        mw::Coin persisted;
        BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(
            std::make_pair(DBKeys::MWEB_COIN, output.GetOutputID()), persisted));
        return persisted;
    };
    BOOST_CHECK(read_persisted().Serialized() == sparse.Serialized());
    mw::Coin repaired;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, repaired));
    BOOST_REQUIRE(repaired.spend_key);
    BOOST_CHECK(PublicKey::From(*repaired.spend_key) == output.GetReceiverPubKey());
    const auto persisted = read_persisted();
    BOOST_CHECK_EQUAL(persisted.address_index, 2U);
    BOOST_CHECK_EQUAL(persisted.amount, COIN);
    BOOST_CHECK(persisted.output_id == output.GetOutputID());
    BOOST_REQUIRE(persisted.address);
    BOOST_CHECK(*persisted.address == address);
    BOOST_REQUIRE(persisted.master_scan_key_id);
    BOOST_CHECK(*persisted.master_scan_key_id == keychain->GetMasterScanKeyID());
    BOOST_REQUIRE(persisted.shared_secret);
    BOOST_CHECK(persisted.shared_secret == repaired.shared_secret);
    BOOST_CHECK(!persisted.spend_key && !persisted.blind && !persisted.sender_key);
    BOOST_CHECK(persisted.Serialized() == repaired.SanitizeForDisk().Serialized());
    const auto restored_key = keychain->CalculateOutputKey(persisted);
    BOOST_REQUIRE(restored_key);
    BOOST_CHECK(PublicKey::From(*restored_key) == output.GetReceiverPubKey());

    mw::Coin repeated;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, repeated));
    BOOST_CHECK(repeated.SanitizeForDisk().Serialized() == persisted.Serialized());
    BOOST_CHECK(read_persisted().Serialized() == persisted.Serialized());
    DataStream prefix;
    prefix << DBKeys::MWEB_COIN;
    auto db_batch = m_wallet.GetDatabase().MakeBatch();
    auto cursor = db_batch->GetNewPrefixCursor(std::span{prefix.data(), prefix.size()});
    DataStream key, value;
    BOOST_REQUIRE(cursor->Next(key, value) == DatabaseCursor::Status::MORE);
    BOOST_CHECK(cursor->Next(key, value) == DatabaseCursor::Status::DONE);
}

BOOST_AUTO_TEST_CASE(rewind_classifies_outputs_and_preserves_late_recipient_metadata)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetMWEBDeterministicSenders(true);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress address;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, address));
    WalletBatch batch(m_wallet.GetDatabase());
    {
        LOCK(account->cs_desc_man);
        BOOST_REQUIRE(account->PersistMWEBInternalIndex(batch, 2, address));
        account->LoadMWEBKeychain();
    }
    const auto keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    const auto sender_key = m_wallet.GetMWWallet()->GenerateSenderKey();
    BOOST_REQUIRE(sender_key);
    const StealthAddress recipient = StealthAddress::Random();
    const Output owned = Output::Create(nullptr, SecretKey::Random(), address, COIN);
    BlindingFactor sent_blind;
    const Output sent = Output::Create(&sent_blind, *sender_key, keychain->GetRewindKey(), recipient, 2 * COIN, {});
    const Output unrelated = Output::Create(nullptr, SecretKey::Random(), StealthAddress::Random(), 3 * COIN);
    const auto read_persisted = [&](const mw::Hash& output_id) {
        mw::Coin persisted;
        BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(
            std::make_pair(DBKeys::MWEB_COIN, output_id), persisted));
        return persisted;
    };

    mw::Coin owned_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(owned, owned_coin));
    BOOST_CHECK(owned_coin.IsMine());
    BOOST_CHECK_EQUAL(owned_coin.address_index, 2U);
    BOOST_CHECK_EQUAL(owned_coin.amount, COIN);
    BOOST_CHECK(owned_coin.output_id == owned.GetOutputID());
    BOOST_REQUIRE(owned_coin.address);
    BOOST_CHECK(*owned_coin.address == address);
    BOOST_REQUIRE(owned_coin.shared_secret);
    BOOST_REQUIRE(owned_coin.HasSpendMaterial());
    BOOST_CHECK(PublicKey::From(*owned_coin.spend_key) == owned.GetReceiverPubKey());
    BOOST_CHECK(owned_coin.master_scan_key_id == std::make_optional(keychain->GetMasterScanKeyID()));
    BOOST_CHECK(read_persisted(owned.GetOutputID()).Serialized() == owned_coin.SanitizeForDisk().Serialized());

    // A recovered send is relevant to history without becoming an owned coin.
    mw::Coin sent_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(sent, sent_coin));
    BOOST_CHECK(!sent_coin.IsMine());
    BOOST_CHECK_EQUAL(sent_coin.address_index, mw::UNKNOWN_INDEX);
    BOOST_CHECK_EQUAL(sent_coin.amount, 2 * COIN);
    BOOST_CHECK(sent_coin.output_id == sent.GetOutputID());
    BOOST_CHECK(!sent_coin.address);
    BOOST_CHECK(!sent_coin.spend_key);
    BOOST_CHECK(sent_coin.sender_key == std::make_optional(*sender_key));
    BOOST_CHECK(sent_coin.blind == std::make_optional(sent_blind));
    BOOST_CHECK(sent_coin.shared_secret == std::make_optional(mw::DeriveSharedSecret(*sender_key, recipient, 2 * COIN)));
    BOOST_CHECK(sent_coin.master_scan_key_id == std::make_optional(keychain->GetMasterScanKeyID()));
    BOOST_CHECK(read_persisted(sent.GetOutputID()).Serialized() == sent_coin.SanitizeForDisk().Serialized());

    mw::Coin foreign;
    BOOST_CHECK(!m_wallet.GetMWWallet()->RewindOutput(unrelated, foreign));
    BOOST_CHECK(!m_wallet.GetMWWallet()->GetCoin(unrelated.GetOutputID(), foreign));
    BOOST_CHECK(!m_wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, unrelated.GetOutputID())));

    // Public coin saving can add a recipient after sender rewind. A subsequent
    // rewind keeps that address and the live secrets; disk remains sanitized.
    mw::Coin enriched = sent_coin;
    enriched.address = recipient;
    const auto enriched_live = enriched.Serialized();
    BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({enriched}));
    mw::Coin saved;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetCoin(sent.GetOutputID(), saved));
    BOOST_CHECK(saved.Serialized() == enriched_live);
    BOOST_CHECK(!saved.IsMine());
    BOOST_CHECK(read_persisted(sent.GetOutputID()).Serialized() == enriched.SanitizeForDisk().Serialized());
    mw::Coin repeated;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(sent, repeated));
    BOOST_CHECK(repeated.Serialized() == enriched_live);
    BOOST_CHECK(!repeated.IsMine());
    BOOST_CHECK(read_persisted(sent.GetOutputID()).Serialized() == enriched.SanitizeForDisk().Serialized());
}

BOOST_AUTO_TEST_CASE(sanitize_legacy_coins_on_disk)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress addr;
    BOOST_REQUIRE(m_wallet.GetMWEBStealthAddress(*account, 2, addr));

    mw::Coin full = MakeFullCoin(addr, 2, COIN);
    // Bypass WriteMWEBCoin sanitization to simulate a legacy plaintext record.
    auto db_batch = m_wallet.GetDatabase().MakeBatch();
    BOOST_REQUIRE(db_batch->Write(std::make_pair(DBKeys::MWEB_COIN, full.output_id), full, true));

    mw::Coin legacy;
    BOOST_REQUIRE(db_batch->Read(std::make_pair(DBKeys::MWEB_COIN, full.output_id), legacy));
    BOOST_REQUIRE(legacy.HasSpendMaterial());

    m_wallet.GetMWWallet()->LoadToWallet(legacy);
    BOOST_CHECK(m_wallet.GetMWWallet()->SanitizeLegacyCoinsOnDisk());

    mw::Coin sanitized;
    BOOST_REQUIRE(db_batch->Read(std::make_pair(DBKeys::MWEB_COIN, full.output_id), sanitized));
    BOOST_CHECK(!sanitized.HasSpendMaterial());
    BOOST_CHECK(!sanitized.sender_key);
    BOOST_CHECK(sanitized.HasSharedSecret());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
