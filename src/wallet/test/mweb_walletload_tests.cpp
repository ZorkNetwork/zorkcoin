// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_types.h>
#include <mweb/mweb_transact.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/models/block/block.h>
#include <mw/models/block/header.h>
#include <mw/wallet/keychain.h>
#include <primitives/block.h>
#include <psbt.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test_framework/models/tx.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <utility>

namespace wallet {
namespace {

struct RawMWEBRecord {
    std::vector<uint8_t> bytes;
    template <typename Stream> void Serialize(Stream& stream) const { stream.write(std::as_bytes(std::span{bytes})); }
};

std::map<std::string, std::string> RecordSnapshot(WalletDatabase& database)
{
    auto batch = database.MakeBatch();
    auto cursor = batch->GetNewCursor();
    BOOST_REQUIRE(cursor);
    std::map<std::string, std::string> records;
    DataStream key, value;
    while (true) {
        const auto status = cursor->Next(key, value);
        if (status == DatabaseCursor::Status::DONE) break;
        BOOST_REQUIRE(status == DatabaseCursor::Status::MORE);
        records.emplace(key.str(), value.str());
    }
    return records;
}

class TxKeyFailureDatabase : public SQLiteDatabase
{
    class Batch : public SQLiteBatch
    {
        TxKeyFailureDatabase& m_database;

        bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override
        {
            DataStream coin_prefix;
            coin_prefix << DBKeys::MWEB_COIN;
            if ((m_database.reject_replacement && key.str() == m_database.replacement_key) ||
                (m_database.reject_coin_writes && key.str().starts_with(coin_prefix.str()))) {
                ++m_database.rejected_writes;
                return false;
            }
            return SQLiteBatch::WriteKey(std::move(key), std::move(value), overwrite);
        }

    public:
        explicit Batch(TxKeyFailureDatabase& database)
            : SQLiteBatch(database), m_database(database) {}
    };

public:
    explicit TxKeyFailureDatabase(const fs::path& path)
        : SQLiteDatabase(path, path / "wallet.dat", DatabaseOptions{}) {}

    bool reject_replacement{false};
    bool reject_coin_writes{false};
    std::string replacement_key;
    size_t rejected_writes{0};

    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<Batch>(*this); }
};

} // namespace

BOOST_AUTO_TEST_SUITE(mweb_walletload_tests)

BOOST_FIXTURE_TEST_CASE(current_mweb_coin_load_rejects_corruption_without_rewriting, TestingSetup)
{
    mw::Coin coin;
    coin.output_id = mw::Hash{SecretKey::Random().GetBigInt()};
    coin.address_index = 7;
    coin.amount = COIN;
    DataStream encoded;
    encoded << coin;
    const auto valid = ParseHex(HexStr(encoded));
    for (const std::string scenario : {"valid", "truncated", "wrong_id", "trailing_value", "trailing_key", "bad_version"}) {
        BOOST_TEST_CONTEXT(scenario) {
            auto database = CreateMockableWalletDatabase();
            DataStream key;
            key << std::make_pair(DBKeys::MWEB_COIN,
                scenario == "wrong_id" ? mw::Hash{SecretKey::Random().GetBigInt()} : coin.output_id);
            auto key_bytes = ParseHex(HexStr(key));
            auto value = valid;
            if (scenario == "truncated") value.pop_back();
            if (scenario == "trailing_value") value.push_back(0);
            if (scenario == "trailing_key") key_bytes.push_back(0);
            if (scenario == "bad_version") value[0] = 0xff;
            BOOST_REQUIRE(database->MakeBatch()->Write(RawMWEBRecord{key_bytes}, RawMWEBRecord{value}));
            const auto before = RecordSnapshot(*database);
            CWallet wallet{m_node.chain.get(), scenario, std::move(database)};
            bilingual_str error;
            std::vector<bilingual_str> warnings;
            const auto result = wallet.PopulateWalletFromDB(error, warnings);
            LOCK(wallet.cs_wallet);
            if (scenario == "valid") {
                BOOST_CHECK_EQUAL(result, DBErrors::LOAD_OK);
                mw::Coin loaded;
                BOOST_REQUIRE(wallet.GetCoin(coin.output_id, loaded));
                BOOST_CHECK_EQUAL(loaded.amount, coin.amount);
            } else {
                BOOST_CHECK_EQUAL(result, DBErrors::CORRUPT);
                mw::Coin rejected;
                BOOST_CHECK(!wallet.GetCoin(coin.output_id, rejected));
                BOOST_CHECK(RecordSnapshot(wallet.GetDatabase()) == before);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(current_embedded_mweb_info_corruption_preserves_records, TestingSetup)
{
    mw::Coin coin;
    coin.output_id = mw::Hash{SecretKey::Random().GetBigInt()};
    coin.address_index = 7;
    coin.amount = COIN;
    CWalletTx placeholder{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
    placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    placeholder.nOrderPos = 0;
    DataStream encoded, field;
    encoded << placeholder;
    field << placeholder.mweb_wtx_info->ToHex();
    const auto original = ParseHex(HexStr(encoded));
    const auto original_field = ParseHex(HexStr(field));
    for (const std::string scenario : {"valid", "truncated_record", "truncated_info", "trailing_info", "bad_tag"}) {
        BOOST_TEST_CONTEXT(scenario) {
            auto value = original;
            if (scenario == "truncated_record") {
                value.pop_back();
            } else if (scenario != "valid") {
                std::string hex = placeholder.mweb_wtx_info->ToHex();
                if (scenario == "truncated_info") hex.resize(hex.size() - 2);
                if (scenario == "trailing_info") hex += "00";
                if (scenario == "bad_tag") hex.replace(0, 2, "04");
                DataStream replacement;
                replacement << hex;
                const auto bytes = ParseHex(HexStr(replacement));
                const auto at = std::search(value.begin(), value.end(), original_field.begin(), original_field.end());
                BOOST_REQUIRE(at != value.end());
                const auto offset = at - value.begin();
                value.erase(at, at + original_field.size());
                value.insert(value.begin() + offset, bytes.begin(), bytes.end());
            }
            auto database = CreateMockableWalletDatabase();
            BOOST_REQUIRE(database->MakeBatch()->Write(std::make_pair(DBKeys::TX, placeholder.GetHash()), RawMWEBRecord{value}));
            const auto before = RecordSnapshot(*database);
            CWallet wallet{m_node.chain.get(), scenario, std::move(database)};
            bilingual_str error;
            std::vector<bilingual_str> warnings;
            const auto result = wallet.PopulateWalletFromDB(error, warnings);
            if (scenario == "valid") {
                BOOST_CHECK_EQUAL(result, DBErrors::LOAD_OK);
                BOOST_CHECK_EQUAL(WITH_LOCK(wallet.cs_wallet, return wallet.mapWallet.size()), 1U);
            } else {
                BOOST_CHECK_EQUAL(result, DBErrors::CORRUPT);
                BOOST_CHECK(WITH_LOCK(wallet.cs_wallet, return wallet.mapWallet.empty()));
                BOOST_CHECK(RecordSnapshot(wallet.GetDatabase()) == before);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_coin_write_failure_does_not_publish_unpersisted_coins, TestingSetup)
{
    auto database = std::make_unique<TxKeyFailureDatabase>(m_path_root / "coin_write_failure");
    auto& failures = *database;
    CWallet wallet{m_node.chain.get(), "coin_write_failure", std::move(database)};
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = wallet.GetNewDestination(OutputType::MWEB, "write failure");
    BOOST_REQUIRE(destination);
    const auto address = std::get<StealthAddress>(*destination);
    const auto keys = wallet.GetMWEBKeychain();
    BOOST_REQUIRE(keys);
    mw::Coin first, second;
    BOOST_REQUIRE(keys->RewindOutput(Output::Create(nullptr, SecretKey::Random(), address, COIN), first));
    BOOST_REQUIRE(keys->RewindOutput(Output::Create(nullptr, SecretKey::Random(), address, COIN), second));
    DataStream rejected_key;
    rejected_key << std::make_pair(DBKeys::MWEB_COIN, second.output_id);
    failures.replacement_key = rejected_key.str();
    failures.reject_replacement = true;
    BOOST_CHECK(!wallet.GetMWWallet()->SaveToWallet({first, second}));
    BOOST_CHECK_EQUAL(failures.rejected_writes, 1U);
    mw::Coin loaded;
    BOOST_CHECK(!wallet.GetCoin(first.output_id, loaded));
    BOOST_CHECK(!wallet.GetCoin(second.output_id, loaded));
    BOOST_CHECK(!wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, first.output_id)));
    BOOST_CHECK(!wallet.GetDatabase().MakeBatch()->Exists(std::make_pair(DBKeys::MWEB_COIN, second.output_id)));
    failures.reject_replacement = false;
    BOOST_REQUIRE(wallet.GetMWWallet()->SaveToWallet({first, second}));
    for (const auto& coin : {first, second}) {
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::MWEB_COIN, coin.output_id), loaded));
        BOOST_CHECK_EQUAL(loaded.amount, coin.amount);
        BOOST_CHECK(loaded.output_id == coin.output_id);
        BOOST_CHECK(!loaded.HasSpendMaterial());
        BOOST_CHECK(loaded.shared_secret == coin.shared_secret);
    }

    const Output owned = Output::Create(nullptr, SecretKey::Random(), address, COIN);
    DataStream owned_key;
    owned_key << std::make_pair(DBKeys::MWEB_COIN, owned.GetOutputID());
    failures.replacement_key = owned_key.str();
    failures.reject_replacement = true;
    mw::Coin rewound;
    BOOST_CHECK(!wallet.GetMWWallet()->RewindOutput(owned, rewound));
    BOOST_CHECK(!wallet.GetCoin(owned.GetOutputID(), loaded));
    CBlock block;
    const auto header = std::make_shared<mw::Header>(10, mw::Hash{}, mw::Hash{}, mw::Hash{},
        BlindingFactor{}, BlindingFactor{}, 1, 0);
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header, TxBody{{}, {owned}, {}})};
    wallet.SetLastBlockProcessed(10, block.GetHash());
    wallet.ScanMWEBExtensionBlock(block, 10, block.GetHash());
    BOOST_CHECK(wallet.mapWallet.empty());
    BOOST_CHECK(!wallet.GetCoin(owned.GetOutputID(), loaded));
    failures.reject_replacement = false;
    wallet.ScanMWEBExtensionBlock(block, 10, block.GetHash());
    BOOST_REQUIRE(wallet.GetCoin(owned.GetOutputID(), loaded));
    BOOST_CHECK_EQUAL(wallet.mapWallet.size(), 1U);

    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromCoin(first));
    tx.mweb_tx.outputs.emplace_back().address = StealthAddress::Random();
    tx.mweb_tx.outputs.back().amount = COIN - 1000;
    tx.mweb_tx.kernels.emplace_back().fee = 1000;
    const PartiallySignedTransaction original_psbt{tx, 2};
    auto failed_psbt = original_psbt;
    const auto before = RecordSnapshot(wallet.GetDatabase());
    failures.reject_coin_writes = true;
    bool complete{false};
    BOOST_CHECK(wallet.FillPSBT(failed_psbt, {.sign = true}, complete) == PSBTError::INVALID_TX);
    BOOST_CHECK(RecordSnapshot(wallet.GetDatabase()) == before);
    BOOST_CHECK_EQUAL(wallet.mapWallet.size(), 1U);
    failures.reject_coin_writes = false;
    auto retry_psbt = original_psbt;
    BOOST_REQUIRE(!wallet.FillPSBT(retry_psbt, {.sign = true}, complete));
    BOOST_CHECK(complete);

    // The direct signed builder also has to surface the failed output write.
    BOOST_REQUIRE(keys->PopulateSpendMaterial(first));
    auto prepare = [&](MWEB::InProcessTx& draft) {
        CRecipient recipient;
        recipient.dest = StealthAddress::Random();
        recipient.nAmount = COIN - 1000;
        recipient.fSubtractFeeFromAmount = false;
        draft.recipients = {recipient};
        draft.selected_coins.emplace(first);
        draft.mweb_type = MWEB::TxType::MWEB_TO_MWEB;
        draft.total_fee = draft.mweb_fee = 1000;
    };
    MWEB::InProcessTx failed_draft;
    prepare(failed_draft);
    const auto before_builder = RecordSnapshot(wallet.GetDatabase());
    failures.reject_coin_writes = true;
    BOOST_CHECK_EXCEPTION(MWEB::Transact(wallet).AddMWEBTx(failed_draft), MWEB::CreateTxError,
        [](const MWEB::CreateTxError& error) {
            BOOST_TEST_MESSAGE("Direct builder failure: " << error.what());
            return error.GetError().original == "Failed to persist MWEB output metadata";
        });
    BOOST_CHECK(RecordSnapshot(wallet.GetDatabase()) == before_builder);
    BOOST_CHECK_EQUAL(wallet.mapWallet.size(), 1U);
    const auto failed_ids = CTransaction(failed_draft.tx).mweb_tx.GetOutputIDs();
    BOOST_REQUIRE_EQUAL(failed_ids.size(), 1U);
    for (const auto& id : failed_ids) {
        BOOST_CHECK(!wallet.GetCoin(id, loaded));
    }
    failures.reject_coin_writes = false;
    MWEB::InProcessTx retry_draft;
    prepare(retry_draft);
    BOOST_CHECK_NO_THROW(MWEB::Transact(wallet).AddMWEBTx(retry_draft));
    const auto retry_ids = CTransaction(retry_draft.tx).mweb_tx.GetOutputIDs();
    BOOST_REQUIRE_EQUAL(retry_ids.size(), 1U);
    for (const auto& id : retry_ids) {
        BOOST_CHECK(wallet.GetCoin(id, loaded));
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_sanitization_write_failure_aborts_load, TestingSetup)
{
    auto database = std::make_unique<TxKeyFailureDatabase>(m_path_root / "sanitize_write_failure");
    auto& failures = *database;
    mw::Coin coin;
    coin.output_id = mw::Hash{SecretKey::Random().GetBigInt()};
    coin.address_index = 7;
    coin.amount = COIN;
    coin.spend_key = SecretKey::Random();
    coin.shared_secret = SecretKey::Random();
    BOOST_REQUIRE(database->MakeBatch()->Write(std::make_pair(DBKeys::MWEB_COIN, coin.output_id), coin));
    DataStream rejected_key;
    rejected_key << std::make_pair(DBKeys::MWEB_COIN, coin.output_id);
    failures.replacement_key = rejected_key.str();
    failures.reject_replacement = true;
    CWallet wallet{m_node.chain.get(), "sanitize_write_failure", std::move(database)};
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    BOOST_CHECK_EQUAL(wallet.PopulateWalletFromDB(error, warnings), DBErrors::LOAD_FAIL);
    BOOST_CHECK_EQUAL(failures.rejected_writes, 1U);
    // The failed load must leave the original coin recoverable. Version records
    // may be updated by the loader before sanitization, so compare the coin itself.
    mw::Coin retained;
    BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::MWEB_COIN, coin.output_id), retained));
    BOOST_CHECK(retained.Serialized() == coin.Serialized());
}

BOOST_FIXTURE_TEST_CASE(mweb_encryption_sanitization_failure_locks_and_recovers_on_reopen, TestingSetup)
{
    const fs::path path = m_path_root / "encrypt_sanitize_failure";
    SecureString passphrase;
    passphrase.assign("sanitize-failure");
    mw::Coin original;
    {
        auto database = std::make_unique<TxKeyFailureDatabase>(path);
        auto& failures = *database;
        CWallet wallet{m_node.chain.get(), "encrypt_sanitize_failure", std::move(database)};
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
        const auto destination = wallet.GetNewDestination(OutputType::MWEB, "legacy receive");
        BOOST_REQUIRE(destination);
        const auto keys = wallet.GetMWEBKeychain();
        BOOST_REQUIRE(keys);
        BOOST_REQUIRE(keys->RewindOutput(Output::Create(nullptr, SecretKey::Random(),
            std::get<StealthAddress>(*destination), COIN), original));
        // A native historical plaintext record, not a Litecoin scrub marker.
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Write(std::make_pair(DBKeys::MWEB_COIN, original.output_id), original));
        wallet.GetMWWallet()->LoadToWallet(original);
        DataStream key;
        key << std::make_pair(DBKeys::MWEB_COIN, original.output_id);
        failures.replacement_key = key.str();
        failures.reject_replacement = true;
        BOOST_CHECK_THROW(wallet.EncryptWallet(passphrase), std::runtime_error);
        BOOST_CHECK(wallet.IsLocked());
        BOOST_CHECK(wallet.HasEncryptionKeys());
        mw::Coin retained;
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::MWEB_COIN, original.output_id), retained));
        BOOST_CHECK(retained.Serialized() == original.Serialized());
    }
    DatabaseStatus status;
    bilingual_str error;
    auto database = MakeDatabase(path, {.require_existing = true, .require_format = DatabaseFormat::SQLITE}, status, error);
    BOOST_REQUIRE_MESSAGE(database, error.original);
    CWallet retry{m_node.chain.get(), "encrypt_sanitize_failure", std::move(database)};
    std::vector<bilingual_str> warnings;
    BOOST_REQUIRE(retry.PopulateWalletFromDB(error, warnings) == DBErrors::LOAD_OK);
    BOOST_CHECK(retry.IsLocked());
    mw::Coin persisted;
    BOOST_REQUIRE(retry.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::MWEB_COIN, original.output_id), persisted));
    BOOST_CHECK(!persisted.HasSpendMaterial());
    BOOST_CHECK(persisted.address == original.address);
    BOOST_CHECK(persisted.shared_secret == original.shared_secret);
    BOOST_REQUIRE(retry.Unlock(passphrase));
    mw::Coin recovered;
    BOOST_REQUIRE(retry.GetCoin(original.output_id, recovered));
    BOOST_REQUIRE(recovered.spend_key);
    BOOST_CHECK(PublicKey::From(*recovered.spend_key) == PublicKey::From(*original.spend_key));
}

BOOST_FIXTURE_TEST_CASE(mweb_tx_key_mismatch_heals, TestingSetup)
{
    BlindingFactor blind;
    const StealthAddress addr = StealthAddress::Random();
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, COIN);
    mw::Coin coin;
    coin.address_index = 1;
    coin.address = addr;
    coin.amount = COIN;
    coin.output_id = output.GetOutputID();
    // Pre-R/S wallets keyed receive placeholders by raw output_id; current keys use CalcHash('R').
    const Txid legacy_raw_key = Txid::FromUint256(uint256(coin.output_id.vec()));
    const Txid receive_key = Txid::FromUint256(MWEB::WalletTxInfo{coin}.GetHash());
    BOOST_REQUIRE(receive_key != legacy_raw_key);

    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    CTransactionRef mweb_tx = MakeTransactionRef(std::move(mtx));
    BOOST_REQUIRE(mweb_tx->HasMWEBTx());
    BOOST_REQUIRE(mweb_tx->IsNull());

    CWalletTx full{mweb_tx, TxStateConfirmed{uint256::ONE, /*height=*/10, /*index=*/0}};
    full.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    full.nOrderPos = 0;
    const Txid kernel_key = full.GetHash();
    BOOST_REQUIRE(kernel_key == mweb_tx->GetHash());
    BOOST_REQUIRE(kernel_key != receive_key);
    BOOST_REQUIRE(kernel_key != legacy_raw_key);

    // New placeholder writes under the R-domain hash and load unchanged.
    {
        auto database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            CWalletTx placeholder{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
            placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
            placeholder.nOrderPos = 0;
            BOOST_CHECK(placeholder.GetHash() == receive_key);
            BOOST_CHECK(batch.WriteFullTx(placeholder));
        }
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
        BOOST_CHECK(warnings.empty());
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE_EQUAL(wallet->mapWallet.size(), 1);
        BOOST_CHECK(wallet->mapWallet.contains(receive_key));
        BOOST_CHECK(!wallet->mapWallet.contains(legacy_raw_key));
        (void)wallet->GetTxDepthInMainChain(wallet->mapWallet.at(receive_key));
    }

    // Legacy DB row keyed by raw output_id heals to the R-domain receive key on load.
    {
        auto database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            CWalletTx placeholder{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
            placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
            placeholder.nOrderPos = 0;
            BOOST_CHECK(batch.WriteTxWithKey(legacy_raw_key, placeholder));
        }
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE_EQUAL(wallet->mapWallet.size(), 1);
        BOOST_CHECK(wallet->mapWallet.contains(receive_key));
        BOOST_CHECK(!wallet->mapWallet.contains(legacy_raw_key));
    }

    // Full tx under kernel_key plus a stale raw-key duplicate heals to a single kernel entry.
    {
        auto database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            BOOST_CHECK(batch.WriteFullTx(full));
            BOOST_CHECK(batch.WriteTxWithKey(legacy_raw_key, full));
        }
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
        BOOST_CHECK(warnings.empty());
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 1);
        BOOST_CHECK(wallet->mapWallet.contains(kernel_key));
        BOOST_CHECK(!wallet->mapWallet.contains(legacy_raw_key));
        (void)wallet->GetTxDepthInMainChain(wallet->mapWallet.at(kernel_key));
    }

    // Replacing a full-tx row with a receive placeholder stores under receive_key.
    {
        auto database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            BOOST_CHECK(batch.WriteFullTx(full));
            CWalletTx placeholder{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
            placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
            placeholder.nOrderPos = 0;
            BOOST_CHECK(batch.WriteFullTx(placeholder, /*previous_key=*/kernel_key));
        }
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 1);
        BOOST_CHECK(wallet->mapWallet.contains(receive_key));
        BOOST_CHECK(!wallet->mapWallet.contains(kernel_key));
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_tx_key_healing_preserves_old_row_when_replacement_write_fails, TestingSetup)
{
    const auto funding = test::Tx::CreatePegIn(COIN);
    mw::Coin coin;
    coin.address_index = 2;
    coin.amount = COIN;
    coin.output_id = funding.GetOutputs().front().GetOutputID();
    const Txid old_key = Txid::FromUint256(MWEB::WalletTxInfo{coin}.GetHash());
    CMutableTransaction mutable_tx;
    mutable_tx.mweb_tx = mw::MutableTx::From(*funding.GetTransaction());
    const auto full_tx = MakeTransactionRef(std::move(mutable_tx));
    BOOST_REQUIRE(full_tx->HasMWEBTx());
    BOOST_REQUIRE(full_tx->IsNull());
    const Txid new_key = full_tx->GetHash();
    BOOST_REQUIRE(old_key != new_key);

    const fs::path path = m_path_root / "tx_key_write_failure";
    auto database = std::make_unique<TxKeyFailureDatabase>(path);
    auto& failures = *database;
    CWalletTx stored_tx{full_tx, TxStateInactive{}};
    stored_tx.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    stored_tx.nOrderPos = 0;
    stored_tx.m_comment = "retained if key repair fails";
    {
        WalletBatch batch(*database);
        // Seed a current-format mismatch accepted by the loader's repair path.
        // Current writers use the computed key; no crash provenance is assumed.
        BOOST_REQUIRE(batch.WriteTxWithKey(old_key, stored_tx));
    }
    DataStream replacement_key;
    replacement_key << std::make_pair(DBKeys::TX, new_key);
    failures.replacement_key = replacement_key.str();
    failures.reject_replacement = true;

    {
        CWallet wallet{m_node.chain.get(), "tx_key_write_failure", std::move(database)};
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        BOOST_CHECK_EQUAL(wallet.PopulateWalletFromDB(error, warnings), DBErrors::LOAD_FAIL);
        BOOST_CHECK_EQUAL(failures.rejected_writes, 1U);
        auto batch = wallet.GetDatabase().MakeBatch();
        BOOST_TEST_MESSAGE("MWEB TX key repair old=" << old_key.ToString() << " replacement=" << new_key.ToString());
        CWalletTx retained{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
        BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::TX, old_key), retained));
        DataStream expected, actual;
        expected << stored_tx;
        actual << retained;
        BOOST_CHECK(actual.str() == expected.str());
        BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, new_key)));
    }

    // Reopen the same SQLite file without fault injection. The retained source
    // must still be sufficient to repair the record and remove its stale key.
    DatabaseStatus status;
    bilingual_str error;
    auto retry_database = MakeDatabase(path, {.require_existing = true,
        .require_format = DatabaseFormat::SQLITE}, status, error);
    BOOST_REQUIRE_MESSAGE(retry_database, error.original);
    CWallet retried{m_node.chain.get(), "tx_key_write_failure", std::move(retry_database)};
    std::vector<bilingual_str> warnings;
    BOOST_REQUIRE_MESSAGE(retried.PopulateWalletFromDB(error, warnings) == DBErrors::LOAD_OK, error.original);
    auto batch = retried.GetDatabase().MakeBatch();
    BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, old_key)));
    CWalletTx repaired{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
    BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::TX, new_key), repaired));
    DataStream expected, actual;
    expected << stored_tx;
    actual << repaired;
    BOOST_CHECK(actual.str() == expected.str());
    BOOST_CHECK(batch->Exists(std::make_pair(DBKeys::WTX_VARIANT, std::make_pair(new_key, full_tx->GetWitnessHash()))));
    LOCK(retried.cs_wallet);
    BOOST_REQUIRE_EQUAL(retried.mapWallet.size(), 1U);
    BOOST_REQUIRE(retried.mapWallet.contains(new_key));
    BOOST_CHECK(retried.mapWallet.at(new_key).GetTx()->GetWitnessHash() == full_tx->GetWitnessHash());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
