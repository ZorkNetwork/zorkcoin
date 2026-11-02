// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/receive.h>
#include <wallet/wallet.h>

#include <mweb/mweb_psbt.h> // MWEB hooks
#include <mweb/mweb_wallet.h> // MWEB hooks
#include <mweb/mweb_wallet_scan.h> // MWEB hooks
#include <mw/models/tx/kernel.h> // MWEB hooks
#include <mw/models/tx/output.h> // MWEB hooks
#include <mw/models/tx/peg_out_coin.h> // MWEB hooks

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <addresstype.h>
#include <blockfilter.h>
#include <chain.h>
#include <coins.h>
#include <common/args.h>
#include <common/messages.h>
#include <common/settings.h>
#include <common/signmessage.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <external_signer.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <kernel/mempool_removal_reason.h>
#include <kernel/types.h>
#include <key.h>
#include <key_io.h>
#include <node/types.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/truc_policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/mweb_descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/allocators/zeroafterfree.h>
#include <support/cleanse.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/log.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <limits>
#include <optional>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>

struct KeyOriginInfo;

using common::AmountErrMsg;
using common::AmountHighWarn;
using common::PSBTError;
using interfaces::FoundBlock;
using kernel::ChainstateRole;
using util::ReplaceAll;
using util::ToString;

namespace MWEB {
UTXOScanStats ScanWalletUTXOSet(wallet::CWallet& wallet, const wallet::CWallet::MWEBIndexScanParams* index_params);
} // namespace MWEB

namespace wallet {

CWallet::CWallet(interfaces::Chain* chain, const std::string& name, std::unique_ptr<WalletDatabase> database)
    : m_chain(chain),
      m_name(name),
      m_database(std::move(database))
{
    mweb_wallet = std::make_shared<MWEB::Wallet>(this);
}

bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) setting_value.setArray();
        for (const auto& value : setting_value.getValues()) {
            if (value.isStr() && value.get_str() == wallet_name) return interfaces::SettingsAction::SKIP_WRITE;
        }
        setting_value.push_back(wallet_name);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) {
            if (wallet_name.empty() && setting_value.isNull()) {
                // Empty setting suppresses backwards-compatible default wallet autoload.
                setting_value.setArray();
                return interfaces::SettingsAction::WRITE;
            }
            return interfaces::SettingsAction::SKIP_WRITE;
        }
        common::SettingsValue new_value(common::SettingsValue::VARR);
        for (const auto& value : setting_value.getValues()) {
            if (!value.isStr() || value.get_str() != wallet_name) new_value.push_back(value);
        }
        if (new_value.size() == setting_value.size()) return interfaces::SettingsAction::SKIP_WRITE;
        setting_value = std::move(new_value);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

static void UpdateWalletSetting(interfaces::Chain& chain,
                                const std::string& wallet_name,
                                std::optional<bool> load_on_startup,
                                std::vector<bilingual_str>& warnings)
{
    if (!load_on_startup) return;
    if (load_on_startup.value() && !AddWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
    } else if (!load_on_startup.value() && !RemoveWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
    }
}

/**
 * Refresh mempool status so the wallet is in an internally consistent state and
 * immediately knows the transaction's status: Whether it can be considered
 * trusted and is eligible to be abandoned ...
 */
static void RefreshMempoolStatus(CWalletTx& tx, interfaces::Chain& chain)
{
    if (chain.isInMempool(tx.GetHash())) {
        tx.m_state = TxStateInMempool();
    } else if (tx.state<TxStateInMempool>()) {
        tx.m_state = TxStateInactive();
    }
}

bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::const_iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i != context.wallets.end()) return false;
    context.wallets.push_back(wallet);
    wallet->ConnectScriptPubKeyManNotifiers();
    wallet->NotifyCanGetAddressesChanged();
    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start, std::vector<bilingual_str>& warnings)
{
    assert(wallet);

    interfaces::Chain& chain = wallet->chain();
    std::string name = wallet->GetName();
    WITH_LOCK(wallet->cs_wallet, wallet->WriteBestBlock());

    // Unregister with the validation interface which also drops shared pointers.
    wallet->DisconnectChainNotifications();
    {
        LOCK(context.wallets_mutex);
        std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
        if (i == context.wallets.end()) return false;
        context.wallets.erase(i);
    }
    // Notify unload so that upper layers release the shared pointer.
    wallet->NotifyUnload();

    // Write the wallet setting
    UpdateWalletSetting(chain, name, load_on_start, warnings);

    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start)
{
    std::vector<bilingual_str> warnings;
    return RemoveWallet(context, wallet, load_on_start, warnings);
}

std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context)
{
    LOCK(context.wallets_mutex);
    return context.wallets;
}

std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count)
{
    LOCK(context.wallets_mutex);
    count = context.wallets.size();
    return count == 1 ? context.wallets[0] : nullptr;
}

std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name)
{
    LOCK(context.wallets_mutex);
    for (const std::shared_ptr<CWallet>& wallet : context.wallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

std::unique_ptr<interfaces::Handler> HandleLoadWallet(WalletContext& context, LoadWalletFn load_wallet)
{
    LOCK(context.wallets_mutex);
    auto it = context.wallet_load_fns.emplace(context.wallet_load_fns.end(), std::move(load_wallet));
    return interfaces::MakeCleanupHandler([&context, it] { LOCK(context.wallets_mutex); context.wallet_load_fns.erase(it); });
}

void NotifyWalletLoaded(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    for (auto& load_wallet : context.wallet_load_fns) {
        load_wallet(interfaces::MakeWallet(context, wallet));
    }
}

static GlobalMutex g_loading_wallet_mutex;
static GlobalMutex g_wallet_release_mutex;
static std::condition_variable g_wallet_release_cv;
static std::set<std::string> g_loading_wallet_set GUARDED_BY(g_loading_wallet_mutex);
static std::set<std::string> g_unloading_wallet_set GUARDED_BY(g_wallet_release_mutex);

// Custom deleter for shared_ptr<CWallet>.
static void FlushAndDeleteWallet(CWallet* wallet)
{
    const std::string name = wallet->GetName();
    wallet->WalletLogPrintf("Releasing wallet %s..\n", name);
    delete wallet;
    // Wallet is now released, notify WaitForDeleteWallet, if any.
    {
        LOCK(g_wallet_release_mutex);
        if (g_unloading_wallet_set.erase(name) == 0) {
            // WaitForDeleteWallet was not called for this wallet, all done.
            return;
        }
    }
    g_wallet_release_cv.notify_all();
}

void WaitForDeleteWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Mark wallet for unloading.
    const std::string name = wallet->GetName();
    {
        LOCK(g_wallet_release_mutex);
        g_unloading_wallet_set.insert(name);
        // Do not expect to be the only one removing this wallet.
        // Multiple threads could simultaneously be waiting for deletion.
    }

    // Time to ditch our shared_ptr and wait for FlushAndDeleteWallet call.
    wallet.reset();
    {
        WAIT_LOCK(g_wallet_release_mutex, lock);
        while (g_unloading_wallet_set.contains(name)) {
            g_wallet_release_cv.wait(lock);
        }
    }
}

namespace {
std::shared_ptr<CWallet> LoadWalletInternal(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    try {
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
        if (!database) {
            error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
            return nullptr;
        }

        context.chain->initMessage(_("Loading wallet…"));
        std::shared_ptr<CWallet> wallet = CWallet::LoadExisting(context, name, std::move(database), error, warnings);
        if (!wallet) {
            error = Untranslated("Wallet loading failed.") + Untranslated(" ") + error;
            status = DatabaseStatus::FAILED_LOAD;
            return nullptr;
        }

        NotifyWalletLoaded(context, wallet);
        AddWallet(context, wallet);
        wallet->postInitProcess();

        // Write the wallet setting
        UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

        return wallet;
    } catch (const std::runtime_error& e) {
        error = Untranslated(e.what());
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
}

class FastWalletRescanFilter
{
public:
    FastWalletRescanFilter(const CWallet& wallet) : m_wallet(wallet)
    {
        // create initial filter with scripts from all ScriptPubKeyMans
        for (auto spkm : m_wallet.GetAllScriptPubKeyMans()) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
            assert(desc_spkm != nullptr);
            AddScriptPubKeys(desc_spkm);
            // save each range descriptor's end for possible future filter updates
            if (desc_spkm->IsHDEnabled()) {
                m_last_range_ends.emplace(desc_spkm->GetID(), desc_spkm->GetEndRange());
            }
        }
    }

    void UpdateIfNeeded()
    {
        // repopulate filter with new scripts if top-up has happened since last iteration
        for (const auto& [desc_spkm_id, last_range_end] : m_last_range_ends) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(desc_spkm_id))};
            assert(desc_spkm != nullptr);
            int32_t current_range_end{desc_spkm->GetEndRange()};
            if (current_range_end > last_range_end) {
                AddScriptPubKeys(desc_spkm, last_range_end);
                m_last_range_ends.at(desc_spkm->GetID()) = current_range_end;
            }
        }
    }

    std::optional<bool> MatchesBlock(const uint256& block_hash) const
    {
        return m_wallet.chain().blockFilterMatchesAny(BlockFilterType::BASIC, block_hash, m_filter_set);
    }

private:
    const CWallet& m_wallet;
    /** Map for keeping track of each range descriptor's last seen end range.
      * This information is used to detect whether new addresses were derived
      * (that is, if the current end range is larger than the saved end range)
      * after processing a block and hence a filter set update is needed to
      * take possible keypool top-ups into account.
      */
    std::map<uint256, int32_t> m_last_range_ends;
    GCSFilter::ElementSet m_filter_set;

    void AddScriptPubKeys(const DescriptorScriptPubKeyMan* desc_spkm, int32_t last_range_end = 0)
    {
        for (const auto& script_pub_key : desc_spkm->GetScriptPubKeys(last_range_end)) {
            m_filter_set.emplace(script_pub_key.begin(), script_pub_key.end());
        }
    }
};
} // namespace

std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    auto result = WITH_LOCK(g_loading_wallet_mutex, return g_loading_wallet_set.insert(name));
    if (!result.second) {
        error = Untranslated("Wallet already loading.");
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
    auto wallet = LoadWalletInternal(context, name, load_on_start, options, status, error, warnings);
    WITH_LOCK(g_loading_wallet_mutex, g_loading_wallet_set.erase(result.first));
    return wallet;
}

std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    // Wallet must have a non-empty name
    if (name.empty()) {
        error = Untranslated("Wallet name cannot be empty");
        status = DatabaseStatus::FAILED_NEW_UNNAMED;
        return nullptr;
    }

    uint64_t wallet_creation_flags = options.create_flags;
    const SecureString& passphrase = options.create_passphrase;
    bool born_encrypted = !passphrase.empty();

    // Only descriptor wallets can be created
    Assert(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS);
    options.require_format = DatabaseFormat::SQLITE;


    // Private keys must be disabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Private keys must be disabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Do not allow a passphrase when private keys are disabled
    if (born_encrypted && (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Wallet::Verify will check if we're trying to create a wallet with a duplicate name.
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
    if (!database) {
        error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_VERIFY;
        return nullptr;
    }

    // Make the wallet
    context.chain->initMessage(_("Creating wallet…"));
    std::shared_ptr<CWallet> wallet = CWallet::CreateNew(context, name, std::move(database), wallet_creation_flags, born_encrypted, error, warnings);
    if (!wallet) {
        error = Untranslated("Wallet creation failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Encrypt the wallet
    if (born_encrypted) {
        if (!wallet->EncryptWallet(passphrase)) {
            error = Untranslated("Error: Wallet created but failed to encrypt.");
            status = DatabaseStatus::FAILED_ENCRYPT;
            return nullptr;
        }
    }

    WITH_LOCK(wallet->cs_wallet, wallet->LogStats());
    NotifyWalletLoaded(context, wallet);
    AddWallet(context, wallet);
    wallet->postInitProcess();

    // Write the wallet settings
    UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

    status = DatabaseStatus::SUCCESS;
    return wallet;
}

// Re-creates wallet from the backup file by renaming and moving it into the wallet's directory.
// If 'load_after_restore=true', the wallet object will be fully initialized and appended to the context.
std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings, bool load_after_restore, bool allow_unnamed)
{
    // Error if the wallet name is empty and allow_unnamed == false
    // allow_unnamed == true is only used by migration to migrate an unnamed wallet
    if (!allow_unnamed && wallet_name.empty()) {
        error = Untranslated("Wallet name cannot be empty");
        status = DatabaseStatus::FAILED_NEW_UNNAMED;
        return nullptr;
    }

    DatabaseOptions options;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;

    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::u8path(wallet_name));
    auto wallet_file = wallet_path / "wallet.dat";
    std::shared_ptr<CWallet> wallet;
    bool wallet_file_copied = false;
    bool created_parent_dir = false;

    try {
        if (!fs::exists(backup_file)) {
            error = Untranslated("Backup file does not exist");
            status = DatabaseStatus::FAILED_INVALID_BACKUP_FILE;
            return nullptr;
        }

        // Wallet directories are allowed to exist, but must not contain a .dat file.
        // Any existing wallet database is treated as a hard failure to prevent overwriting.
        if (fs::exists(wallet_path)) {
            // If this is a file, it is the db and we don't want to overwrite it.
            if (!fs::is_directory(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }

            // Check we are not going to overwrite an existing db file
            if (fs::exists(wallet_file)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists in '%s'.", fs::PathToString(wallet_file)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
        } else {
            // The directory doesn't exist, create it
            if (!TryCreateDirectories(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore database path '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
            created_parent_dir = true;
        }

        fs::copy_file(backup_file, wallet_file, fs::copy_options::none);
        wallet_file_copied = true;

        if (load_after_restore) {
            wallet = LoadWallet(context, wallet_name, load_on_start, options, status, error, warnings);
        }
    } catch (const std::exception& e) {
        assert(!wallet);
        if (!error.empty()) error += Untranslated("\n");
        error += Untranslated(strprintf("Unexpected exception: %s", e.what()));
    }

    // Remove created wallet path only when loading fails
    if (load_after_restore && !wallet) {
        if (wallet_file_copied) fs::remove(wallet_file);
        // Clean up the parent directory if we created it during restoration.
        // As we have created it, it must be empty after deleting the wallet file.
        if (created_parent_dir) {
            Assume(fs::is_empty(wallet_path));
            fs::remove(wallet_path);
        }
    }

    return wallet;
}

/** @defgroup mapWallet
 *
 * @{
 */

const CWalletTx* CWallet::GetWalletTx(const Txid& hash) const
{
    AssertLockHeld(cs_wallet);
    const auto it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

void CWallet::UpgradeDescriptorCache()
{
    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) || IsLocked() || IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    for (ScriptPubKeyMan* spkm : GetAllScriptPubKeyMans()) {
        DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        desc_spkm->UpgradeDescriptorCache();
    }
    SetWalletFlag(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
}

/* Given a wallet passphrase string and an unencrypted master key, determine the proper key
 * derivation parameters (should take at least 100ms) and encrypt the master key. */
static bool EncryptMasterKey(const SecureString& wallet_passphrase, const CKeyingMaterial& plain_master_key, CMasterKey& master_key)
{
    constexpr MillisecondsDouble target_time{100};
    CCrypter crypter;
    CMasterKey updated_master_key{master_key};

    // Get the weighted average of iterations we can do in 100ms over 2 runs.
    for (int i = 0; i < 2; i++){
        auto start_time{NodeClock::now()};
        const bool key_set{crypter.SetKeyFromPassphrase(wallet_passphrase, updated_master_key.vchSalt, updated_master_key.nDeriveIterations, updated_master_key.nDerivationMethod)};
        auto elapsed_time{NodeClock::now() - start_time};
        if (!key_set) {
            return false;
        }

        if (elapsed_time <= 0s) {
            // We are probably in a test with a mocked clock.
            updated_master_key.nDeriveIterations = CMasterKey::DEFAULT_DERIVE_ITERATIONS;
            break;
        }

        // target_iterations : elapsed_iterations :: target_time : elapsed_time
        const double target_iterations{updated_master_key.nDeriveIterations * target_time / elapsed_time};
        if (target_iterations < 1 || target_iterations > std::numeric_limits<unsigned int>::max()) {
            return false;
        }
        // Get the weighted average with previous runs. Use 64-bit math so the
        // sum cannot wrap; the average of two unsigned int values fits in one.
        updated_master_key.nDeriveIterations = (uint64_t{updated_master_key.nDeriveIterations} * i + static_cast<unsigned int>(target_iterations)) / (i + 1);
    }

    if (updated_master_key.nDeriveIterations < CMasterKey::DEFAULT_DERIVE_ITERATIONS) {
        updated_master_key.nDeriveIterations = CMasterKey::DEFAULT_DERIVE_ITERATIONS;
    }

    if (!crypter.SetKeyFromPassphrase(wallet_passphrase, updated_master_key.vchSalt, updated_master_key.nDeriveIterations, updated_master_key.nDerivationMethod)) {
        return false;
    }
    if (!crypter.Encrypt(plain_master_key, updated_master_key.vchCryptedKey)) {
        return false;
    }

    master_key = std::move(updated_master_key);
    return true;
}

static bool DecryptMasterKey(const SecureString& wallet_passphrase, const CMasterKey& master_key, CKeyingMaterial& plain_master_key)
{
    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(wallet_passphrase, master_key.vchSalt, master_key.nDeriveIterations, master_key.nDerivationMethod)) {
        return false;
    }
    if (!crypter.Decrypt(master_key.vchCryptedKey, plain_master_key)) {
        return false;
    }

    return true;
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CKeyingMaterial plain_master_key;

    {
        LOCK(cs_wallet);
        m_mweb_unlock_error.reset();
        for (const auto& [_, master_key] : mapMasterKeys)
        {
            if (!DecryptMasterKey(strWalletPassphrase, master_key, plain_master_key)) {
                continue; // try another master key
            }
            if (Unlock(plain_master_key)) {
                // Now that we've unlocked, upgrade the descriptor cache
                UpgradeDescriptorCache();
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK2(m_relock_mutex, cs_wallet);
        Lock();
        m_mweb_unlock_error.reset();

        CKeyingMaterial plain_master_key;
        for (auto& [master_key_id, master_key] : mapMasterKeys)
        {
            if (!DecryptMasterKey(strOldWalletPassphrase, master_key, plain_master_key)) {
                return false;
            }
            if (Unlock(plain_master_key))
            {
                if (!EncryptMasterKey(strNewWalletPassphrase, plain_master_key, master_key)) {
                    return false;
                }
                WalletLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", master_key.nDeriveIterations);

                WalletBatch(GetDatabase()).WriteMasterKey(master_key_id, master_key);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetLastBlockProcessedInMem(int block_height, uint256 block_hash)
{
    AssertLockHeld(cs_wallet);

    m_last_block_processed = block_hash;
    m_last_block_processed_height = block_height;
}

void CWallet::SetLastBlockProcessed(int block_height, uint256 block_hash)
{
    AssertLockHeld(cs_wallet);

    SetLastBlockProcessedInMem(block_height, block_hash);
    WriteBestBlock();
}

std::set<Txid> CWallet::GetConflicts(const Txid& txid) const
{
    std::set<Txid> result;
    AssertLockHeld(cs_wallet);

    const auto it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.GetTx()->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    // MWEB spends can be known from a full body or an extension-only placeholder.
    auto mweb_inputs = wtx.GetTx()->mweb_tx.GetSpentIDs();
    if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input) {
        mweb_inputs.insert(*wtx.mweb_wtx_info->spent_input);
    }
    for (const mw::Hash& output_id : mweb_inputs) {
        if (mapMWEBSpends.count(output_id) <= 1) continue;
        const int target_epoch = GetMWEBOutputOccurrenceHeight(output_id, wtx);
        std::set<Txid> matching_spends;
        const auto [begin, end] = mapMWEBSpends.equal_range(output_id);
        for (auto spend = begin; spend != end; ++spend) {
            const auto spend_it = mapWallet.find(spend->second);
            if (spend_it == mapWallet.end()) continue;
            if (GetMWEBOutputOccurrenceHeight(output_id, spend_it->second) == target_epoch) {
                matching_spends.insert(spend->second);
            }
        }
        if (matching_spends.size() > 1) {
            result.insert(matching_spends.begin(), matching_spends.end());
        }
    }
    return result;
}

bool CWallet::HasWalletSpend(const CTransactionRef& tx) const
{
    AssertLockHeld(cs_wallet);
    const Txid& txid = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); ++i) {
        if (IsSpent(COutPoint(txid, i))) {
            return true;
        }
    }
    return false;
}

void CWallet::Close()
{
    GetDatabase().Close();
}

std::set<CWalletTx*, WalletTxOrderComparator> CWallet::GetMalleatedVariants(const CWalletTx& wtx)
{
    AssertLockHeld(cs_wallet);
    std::set<CWalletTx*, WalletTxOrderComparator> txs;

    // Coinbases cannot be malleated
    if (wtx.IsCoinBase()) return txs;

    // Only transactions that have non-witness inputs can be malleated
    if (std::ranges::none_of(wtx.GetTx()->vin, [](const CTxIn& in) { return in.scriptWitness.IsNull(); })) {
        return txs;
    }

    // All variants spend wtx's first input, so a single lookup finds every candidate
    bool found_self = false;
    const auto [begin, end] = mapTxSpends.equal_range(wtx.GetTx()->vin.front().prevout);
    for (auto it = begin; it != end; ++it) {
        auto entry = mapWallet.find(it->second);
        if (!Assume(entry != mapWallet.end())) continue; // sanity-check: mapTxSpends has txs that are in mapWallet
        const bool is_self = &entry->second == &wtx;
        found_self |= is_self;
        if (is_self || wtx.IsMalleation(entry->second)) {
            Assume(txs.insert(&entry->second).second);
        }
    }
    // wtx should always be found as this function is always called after AddToSpends
    Assert(found_self);
    return txs;
}

void CWallet::SyncMalleatedTxMetadata(WalletBatch& batch, const CWalletTx& wtx)
{
    const auto txs = GetMalleatedVariants(wtx);
    if (txs.size() <= 1) return; // no variants, nothing to do

    // First tx is the oldest one (smallest nOrderPos)
    const CWalletTx* copyFrom = *txs.begin();

    // The metadata that is kept in sync between malleated variants.
    // nTimeReceived, nOrderPos and cached members are not copied on purpose.
    const auto metadata = [](auto& tx) {
        return std::tie(tx.m_from, tx.m_message, tx.m_comment, tx.m_comment_to,
                        tx.m_replaces_txid, tx.m_replaced_by_txid,
                        tx.m_messages, tx.m_payment_requests, tx.nTimeSmart);
    };

    // Now copy data from copyFrom to rest:
    for (CWalletTx* copyTo : txs) {
        if (copyTo == copyFrom) continue;
        metadata(*copyTo) = metadata(*copyFrom);
        (void)batch.WriteTxMetadata(*copyTo);
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const COutPoint& outpoint) const
{
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const Txid& txid = it->second;
        const auto mit = mapWallet.find(txid);
        if (mit != mapWallet.end()) {
            const auto& wtx = mit->second;
            if (!wtx.isAbandoned() && !wtx.isBlockConflicted() && !wtx.isMempoolConflicted())
                return true; // Spent
        }
    }
    return false;
}

CWallet::SpendType CWallet::HowSpent(const COutPoint& outpoint) const
{
    SpendType st{SpendType::UNSPENT};

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const Txid& txid = it->second;
        const auto mit = mapWallet.find(txid);
        if (mit != mapWallet.end()) {
            const auto& wtx = mit->second;
            if (wtx.isConfirmed()) return SpendType::CONFIRMED;
            if (wtx.InMempool()) {
                st = SpendType::MEMPOOL;
            } else if (!wtx.isAbandoned() && !wtx.isBlockConflicted() && !wtx.isMempoolConflicted()) {
                if (st == SpendType::UNSPENT) st = SpendType::NONMEMPOOL;
            }
        }
    }
    return st;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const Txid& txid)
{
    mapTxSpends.insert(std::make_pair(outpoint, txid));

    UnlockCoin(outpoint);
}


void CWallet::AddToSpends(const CWalletTx& wtx)
{
    if (wtx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : wtx.GetTx()->vin)
        AddToSpends(txin.prevout, wtx.GetHash());

    // MWEB hooks
    for (const mw::Hash& spent_id : wtx.GetTx()->mweb_tx.GetSpentIDs()) {
        AddToSpends(spent_id, wtx.GetHash());
    }
    if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input) {
        AddToSpends(*wtx.mweb_wtx_info->spent_input, wtx.GetHash());
    }
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    // Only descriptor wallets can be encrypted
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    if (HasEncryptionKeys())
        return false;

    {
        // MWEB: the Unlock below would fail after the keys are encrypted on disk.
        LOCK(cs_wallet);
        m_mweb_unlock_error = LoadMWEBKeychains();
        if (m_mweb_unlock_error) return false;
    }

    CKeyingMaterial plain_master_key;

    plain_master_key.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(plain_master_key);

    CMasterKey master_key;

    master_key.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(master_key.vchSalt);

    if (!EncryptMasterKey(strWalletPassphrase, plain_master_key, master_key)) {
        return false;
    }
    WalletLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", master_key.nDeriveIterations);

    {
        LOCK2(m_relock_mutex, cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = master_key;
        WalletBatch* encrypted_batch = new WalletBatch(GetDatabase());
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, master_key);

        for (const auto& spk_man_pair : m_spk_managers) {
            auto spk_man = spk_man_pair.second.get();
            if (!spk_man->Encrypt(plain_master_key, encrypted_batch)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                // We now probably have half of our keys encrypted in memory, and half not...
                // die and let the user reload the unencrypted wallet.
                assert(false);
            }
        }

        if (!encrypted_batch->TxnCommit()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete encrypted_batch;
        encrypted_batch = nullptr;

        Lock();
        if (!Unlock(strWalletPassphrase)) {
            return false;
        }

        SetupWalletGeneration();

        // Sanitize MWEB coin / mweb_info records while unlocked (spend material still
        // in memory) so Rewrite cannot leave plaintext spend material in slack.
        try {
            GetMWWallet()->SanitizeLegacyCoinsOnDisk();
        } catch (...) {
            // Encryption keys are already committed. Keep spend secrets locked
            // if the final MWEB sanitization cannot be persisted.
            Lock();
            throw;
        }

        Lock();

        // Need to completely rewrite the wallet file; if we don't, the database might keep
        // bits of the unencrypted private key in slack space in the database file.
        GetDatabase().Rewrite();
    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx into a sorted-by-time multimap.
    typedef std::multimap<int64_t, CWalletTx*> TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, wtx));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second;
        int64_t& nOrderPos = pwtx->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (!batch.WriteTxMetadata(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (!batch.WriteTxMetadata(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
    }
    batch.WriteOrderPosNext(nOrderPosNext);

    return DBErrors::LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    int64_t nRet = nOrderPosNext++;
    if (batch) {
        batch->WriteOrderPosNext(nOrderPosNext);
    } else {
        WalletBatch(GetDatabase()).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

namespace {
template <typename Map>
void RemapTxidValues(Map& index, const Txid& old_key, const Txid& new_key)
{
    for (auto it = index.begin(); it != index.end();) {
        if (it->second != old_key) {
            ++it;
            continue;
        }
        bool duplicate{false};
        const auto [begin, end] = index.equal_range(it->first);
        for (auto other = begin; other != end; ++other) {
            if (other != it && other->second == new_key) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            it = index.erase(it);
        } else {
            it->second = new_key;
            ++it;
        }
    }
}

std::optional<uint64_t> GetMWEBBlockOutputLeafIndex(const CBlock& block_data, size_t output_index)
{
    if (block_data.mweb_block.IsNull() || !block_data.mweb_block.m_block) {
        return std::nullopt;
    }
    const auto& header = block_data.mweb_block.GetMWEBHeader();
    const auto& outputs = block_data.mweb_block.m_block->GetOutputs();
    if (!header || output_index >= outputs.size() || header->GetNumTXOs() < outputs.size()) {
        return std::nullopt;
    }
    return header->GetNumTXOs() - outputs.size() + output_index;
}
} // namespace

CWalletTx* CWallet::RekeyWalletTx(const Txid& map_key)
{
    AssertLockHeld(cs_wallet);
    auto it = mapWallet.find(map_key);
    if (it == mapWallet.end()) return nullptr;
    const Txid new_key = it->second.GetHash();
    if (new_key == map_key) return &it->second;

    WalletLogPrintf("RekeyWalletTx: map key %s != GetHash %s; moving wallet tx to computed hash\n",
                    map_key.ToString(), new_key.ToString());

    RemapTxidValues(mapTxSpends, map_key, new_key);
    RemapTxidValues(mapOutputsMWEB, map_key, new_key);
    RemapTxidValues(mapKernelsMWEB, map_key, new_key);
    RemapTxidValues(mapMWEBSpends, map_key, new_key);

    if (mapWallet.contains(new_key)) {
        for (auto oit = wtxOrdered.begin(); oit != wtxOrdered.end(); ++oit) {
            if (oit->second == &it->second) {
                wtxOrdered.erase(oit);
                break;
            }
        }
        mapWallet.erase(it);
        return &mapWallet.at(new_key);
    }

    auto node = mapWallet.extract(it);
    node.key() = new_key;
    auto inserted = mapWallet.insert(std::move(node));
    CHECK_NONFATAL(inserted.inserted);
    return &inserted.position->second;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (auto& [_, wtx] : mapWallet)
            wtx.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const Txid& originalHash, const Txid& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    Assert(!wtx.m_replaced_by_txid);

    wtx.m_replaced_by_txid = newHash;

    // Refresh mempool status without waiting for transactionRemovedFromMempool or transactionAddedToMempool
    RefreshMempoolStatus(wtx, chain());

    WalletBatch batch(GetDatabase());

    bool success = true;
    if (!batch.WriteTxMetadata(wtx)) {
        WalletLogPrintf("%s: Updating batch tx %s failed\n", __func__, wtx.GetHash().ToString());
        success = false;
    }

    // The new transaction also replaces any malleated variants of wtx,
    // so bumpfee refuses to bump them afterwards
    for (CWalletTx* variant : GetMalleatedVariants(wtx)) {
        if (variant == &wtx) continue;
        variant->m_replaced_by_txid = newHash;
        if (!batch.WriteTxMetadata(*variant)) {
            WalletLogPrintf("%s: Updating variant tx %s failed\n", __func__, variant->GetHash().ToString());
            success = false;
        }
    }

    NotifyTransactionChanged(originalHash, CT_UPDATED);

    return success;
}

void CWallet::SetSpentKeyState(WalletBatch& batch, const Txid& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    AssertLockHeld(cs_wallet);
    const CWalletTx* srctx = GetWalletTx(hash);
    if (!srctx) return;

    CTxDestination dst;
    if (ExtractDestination(srctx->GetTx()->vout[n].scriptPubKey, dst)) {
        if (IsMine(dst)) {
            if (used != IsAddressPreviouslySpent(dst)) {
                if (used) {
                    tx_destinations.insert(dst);
                }
                SetAddressPreviouslySpent(batch, dst, used);
            }
        }
    }
}

bool CWallet::IsSpentKey(const CScript& scriptPubKey) const
{
    AssertLockHeld(cs_wallet);
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest)) {
        return false;
    }
    if (IsAddressPreviouslySpent(dest)) {
        return true;
    }
    return false;
}

CWalletTx* CWallet::AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx, bool rescanning_old_block, const std::optional<MWEB::WalletTxInfo>& mweb_wtx_info)
{
    LOCK(cs_wallet);

    WalletBatch batch(GetDatabase());

    Txid hash = tx->GetHash();
    // Placeholder-only keying (Litecoin IsPartialMWEB): null body without extension tx.
    if (mweb_wtx_info && tx->IsNull() && !tx->HasMWEBTx()) {
        hash = Txid::FromUint256(mweb_wtx_info->GetHash());
    }

    // An extension-only rescan learns individual received/spent outputs before
    // their full transaction. Collapse those rows when its body becomes known.
    // Derive their domain-separated keys directly so this does not scan the wallet.
    std::vector<Txid> partial_mweb_keys;
    bool promoted_mweb_placeholder{false};
    if (tx->HasMWEBTx()) {
        const auto can_coalesce_placeholder = [&](const CWalletTx& partial) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
            if (!partial.IsMWEBPlaceholder() || !partial.mweb_wtx_info) return false;
            if (partial.mweb_wtx_info->spent_input) {
                if (const auto* confirmed = partial.state<TxStateConfirmed>()) {
                    const auto* incoming = std::get_if<TxStateConfirmed>(&state);
                    if (!incoming || incoming->confirmed_block_hash != confirmed->confirmed_block_hash) return false;
                }
            }
            if (partial.mweb_wtx_info->received_coin) {
                if (const auto* confirmed = partial.state<TxStateConfirmed>()) {
                    if (const auto* incoming = std::get_if<TxStateConfirmed>(&state)) {
                        if (incoming->confirmed_block_hash != confirmed->confirmed_block_hash) return false;
                    } else if (GetTxDepthInMainChain(partial) > 0 &&
                               IsOutputSpentMWEBInChainOrMempool(partial.mweb_wtx_info->received_coin->output_id, partial)) {
                        return false;
                    }
                }
            }
            return true;
        };
        const auto add_partial = [&](const MWEB::WalletTxInfo& info) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
            const Txid key = Txid::FromUint256(info.GetHash());
            const auto it = mapWallet.find(key);
            if (it == mapWallet.end() || !can_coalesce_placeholder(it->second)) return;
            partial_mweb_keys.push_back(key);
        };
        for (const auto& output_id : tx->mweb_tx.GetOutputIDs()) {
            mw::Coin coin;
            coin.output_id = output_id;
            add_partial(MWEB::WalletTxInfo{std::move(coin)});
            const auto [begin, end] = mapOutputsMWEB.equal_range(output_id);
            for (auto it = begin; it != end; ++it) {
                const auto wtx_it = mapWallet.find(it->second);
                if (wtx_it != mapWallet.end() && can_coalesce_placeholder(wtx_it->second)) {
                    partial_mweb_keys.push_back(it->second);
                }
            }
        }
        for (const auto& spent_id : tx->mweb_tx.GetSpentIDs()) {
            add_partial(MWEB::WalletTxInfo{spent_id});
            const auto [begin, end] = mapMWEBSpends.equal_range(spent_id);
            for (auto it = begin; it != end; ++it) {
                const auto wtx_it = mapWallet.find(it->second);
                if (wtx_it != mapWallet.end() && can_coalesce_placeholder(wtx_it->second)) {
                    partial_mweb_keys.push_back(it->second);
                }
            }
        }
        std::sort(partial_mweb_keys.begin(), partial_mweb_keys.end(), [&](const Txid& lhs, const Txid& rhs) {
            return std::tie(mapWallet.at(lhs).nOrderPos, lhs) < std::tie(mapWallet.at(rhs).nOrderPos, rhs);
        });
        partial_mweb_keys.erase(std::unique(partial_mweb_keys.begin(), partial_mweb_keys.end()), partial_mweb_keys.end());

        for (const auto& key : partial_mweb_keys) {
            CWalletTx& partial = mapWallet.at(key);
            if (partial.mweb_wtx_info->spent_input) {
                const auto [begin, end] = mapMWEBSpends.equal_range(*partial.mweb_wtx_info->spent_input);
                for (auto it = begin; it != end;) {
                    if (it->second == key) it = mapMWEBSpends.erase(it);
                    else ++it;
                }
            }
            if (const auto full = mapWallet.find(hash); full != mapWallet.end()) {
                // Keep existing full/earliest-row metadata; fill otherwise missing
                // user metadata from the other rows before discarding them.
                CWalletTx& target = full->second;
                const auto fill = [](auto& dest, const auto& source) { if (!dest) dest = source; };
                fill(target.m_from, partial.m_from);
                fill(target.m_message, partial.m_message);
                fill(target.m_comment, partial.m_comment);
                fill(target.m_comment_to, partial.m_comment_to);
                fill(target.m_replaces_txid, partial.m_replaces_txid);
                fill(target.m_replaced_by_txid, partial.m_replaced_by_txid);
                const auto append_unique = [](auto& dest, const auto& source) {
                    for (const auto& value : source) {
                        if (std::ranges::find(dest, value) == dest.end()) dest.push_back(value);
                    }
                };
                append_unique(target.m_messages, partial.m_messages);
                append_unique(target.m_payment_requests, partial.m_payment_requests);
            } else {
                promoted_mweb_placeholder = true;
            }
            partial.ReplaceMWEBPlaceholder(tx);
            partial.mweb_wtx_info = mweb_wtx_info;
            // Rekeying also redirects output/kernel indexes and removes an extra
            // row if the canonical transaction already exists.
            if (!RekeyWalletTx(key)) return nullptr;
        }
    }

    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        // Mark used destinations
        std::set<CTxDestination> tx_destinations;

        for (const CTxIn& txin : tx->vin) {
            const COutPoint& op = txin.prevout;
            SetSpentKeyState(batch, op.hash, op.n, true, tx_destinations);
        }

        MarkDestinationsDirty(tx_destinations);
    }

    // Inserts only if not already there, returns tx inserted or tx found
    auto ret = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(tx, state));
    CWalletTx& wtx = (*ret.first).second;
    bool fInsertedNew = ret.second;
    bool fUpdated = update_wtx && update_wtx(wtx, fInsertedNew);
    fUpdated |= !partial_mweb_keys.empty();
    if (promoted_mweb_placeholder) {
        AddToSpends(wtx);
        SyncMalleatedTxMetadata(batch, wtx);
        AddMWEBOrigins(wtx);
        if (!wtx.GetTx()->mweb_tx.GetSpentIDs().empty()) PruneMWEBDescriptors();
    }
    if (fInsertedNew) {
        wtx.nTimeReceived = GetTime<std::chrono::milliseconds>().count();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        wtx.nTimeSmart = ComputeTimeSmart(wtx, rescanning_old_block);
        if (mweb_wtx_info) {
            wtx.mweb_wtx_info = *mweb_wtx_info;
        }
        AddToSpends(wtx);
        SyncMalleatedTxMetadata(batch, wtx);
        AddMWEBOrigins(wtx); // MWEB hooks
        if ((wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input) || !wtx.GetTx()->mweb_tx.GetSpentIDs().empty()) {
            PruneMWEBDescriptors();
        }

        // Update birth time when tx time is older than it.
        MaybeUpdateBirthTime(wtx.GetTxTime());

        if (!batch.WriteFullTx(wtx)) {
            return nullptr;
        }
    }

    if (!fInsertedNew)
    {
        if (wtx.IsMWEBPlaceholder()) {
            // MWEB hooks: placeholders are keyed by an MWEB hash, not the L1 txid, so
            // they cannot go through CWalletTx::Update().
            if (tx->HasMWEBTx() || !tx->IsNull()) {
                // Replace partial MWEB placeholder with full transaction
                wtx.ReplaceMWEBPlaceholder(tx);
                if (mweb_wtx_info) {
                    wtx.mweb_wtx_info = *mweb_wtx_info;
                }
                fUpdated = true;
                if ((wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input) || !wtx.GetTx()->mweb_tx.GetSpentIDs().empty()) {
                    PruneMWEBDescriptors();
                }
            }
            if (state.index() != wtx.m_state.index() ||
                TxStateSerializedBlockHash(wtx.m_state) != TxStateSerializedBlockHash(state) ||
                TxStateSerializedIndex(wtx.m_state) != TxStateSerializedIndex(state)) {
                wtx.m_state = state;
                fUpdated = true;
            }
            if (fUpdated && wtx.GetHash() == hash && !batch.WriteTxMetadata(wtx)) {
                return nullptr;
            }
        } else {
            // MWEB hooks: rescans of old blocks and MWEB-only txs may legitimately move
            // a tx to a different block without a state type change.
            if (state.index() == wtx.m_state.index() &&
                (rescanning_old_block || (wtx.GetTx()->IsNull() && mweb_wtx_info)) &&
                (TxStateSerializedBlockHash(wtx.m_state) != TxStateSerializedBlockHash(state) ||
                 TxStateSerializedIndex(wtx.m_state) != TxStateSerializedIndex(state))) {
                wtx.m_state = state;
                fUpdated = true;
            }
            try {
                fUpdated |= wtx.Update(tx, state, batch, fUpdated);
            } catch (const std::ios_base::failure& e) {
                WalletLogPrintf("Error: Unable to write tx update, %s", e.what());
                return nullptr;
            }
        }
    }

    // Mark inactive coinbase transactions and their descendants as abandoned
    if (wtx.IsCoinBase() && wtx.isInactive()) {
        std::vector<CWalletTx*> txs{&wtx};

        TxStateInactive inactive_state = TxStateInactive{/*abandoned=*/true};

        while (!txs.empty()) {
            CWalletTx* desc_tx = txs.back();
            txs.pop_back();
            desc_tx->m_state = inactive_state;
            // Break caches since we have changed the state
            desc_tx->MarkDirty();
            batch.WriteTxMetadata(*desc_tx);
            MarkInputsDirty(desc_tx->GetTx());
            for (unsigned int i = 0; i < desc_tx->GetTx()->vout.size(); ++i) {
                COutPoint outpoint(desc_tx->GetHash(), i);
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(outpoint);
                for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
                    const auto wit = mapWallet.find(it->second);
                    if (wit != mapWallet.end()) {
                        txs.push_back(&wit->second);
                    }
                }
            }
        }
    }

    //// debug print
    std::string status{"no-change"};
    if (fInsertedNew || fUpdated) {
        status = fInsertedNew ? (fUpdated ? "new, update" : "new") : "update";
    }

    CWalletTx* pwtx = &wtx;
    if (wtx.GetHash() != hash) {
        // MWEB hooks: placeholder replaced by the full tx; move it to the computed hash.
        pwtx = RekeyWalletTx(hash);
        if (!pwtx) return nullptr;
        if (!batch.WriteFullTx(*pwtx, /*previous_key=*/hash)) {
            return nullptr;
        }
    }
    if (!partial_mweb_keys.empty()) {
        if (!batch.WriteFullTx(*pwtx)) return nullptr;
        for (const auto& key : partial_mweb_keys) {
            if (!batch.EraseTx(key)) return nullptr;
            NotifyTransactionChanged(key, CT_DELETED);
        }
    }
    WalletLogPrintf("AddToWallet %s %s %s", pwtx->GetHash().ToString(), status, TxStateString(state));

    // Break debit/credit balance caches:
    pwtx->MarkDirty();

    // Cache the outputs that belong to the wallet
    RefreshTXOsFromTx(*pwtx);

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(pwtx->GetHash(), (fInsertedNew || promoted_mweb_placeholder) ? CT_NEW : CT_UPDATED);

#if HAVE_SYSTEM
    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = m_notify_tx_changed_script;

    if (!strCmd.empty())
    {
        ReplaceAll(strCmd, "%s", pwtx->GetHash().GetHex());
        if (auto* conf = pwtx->state<TxStateConfirmed>())
        {
            ReplaceAll(strCmd, "%b", conf->confirmed_block_hash.GetHex());
            ReplaceAll(strCmd, "%h", ToString(conf->confirmed_block_height));
        } else {
            ReplaceAll(strCmd, "%b", "unconfirmed");
            ReplaceAll(strCmd, "%h", "-1");
        }
#ifndef WIN32
        // Substituting the wallet name isn't currently supported on windows
        // because windows shell escaping has not been implemented yet:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-537384875
        // A few ways it could be implemented in the future are described in:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-461288094
        ReplaceAll(strCmd, "%w", ShellEscape(GetName()));
#endif
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }
#endif

    return pwtx;
}

bool CWallet::LoadToWallet(CWalletTx&& wtx_in)
{
    const auto& ins = mapWallet.emplace(wtx_in.GetHash(), std::move(wtx_in));
    CWalletTx& wtx = ins.first->second;
    if (!ins.second) {
        return false;
    }
    // If wallet doesn't have a chain (e.g when using bitcoin-wallet tool),
    // don't bother to update txn.
    if (HaveChain()) {
      wtx.updateState(chain());
    }
    wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
    AddMWEBOrigins(wtx); // MWEB hooks: rebuild output index on wallet reload
    AddToSpends(wtx);
    for (const CTxIn& txin : wtx.GetTx()->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (auto* prev = prevtx.state<TxStateBlockConflicted>()) {
                MarkConflicted(prev->conflicting_block_hash, prev->conflicting_block_height, wtx.GetHash());
            }
        }
    }

    // Update birth time when tx time is older than it.
    MaybeUpdateBirthTime(wtx.GetTxTime());

    // Make sure the tx outputs are known by the wallet
    RefreshTXOsFromTx(wtx);
    return true;
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const SyncTxState& state, bool rescanning_old_block)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (auto* conf = std::get_if<TxStateConfirmed>(&state)) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), conf->confirmed_block_hash.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(conf->confirmed_block_hash, conf->confirmed_block_height, range.first->second);
                    }
                    range.first++;
                }
            }
            // MWEB inputs have no canonical prevout, including in mixed bodies.
            for (const mw::Hash& spent_id : tx.mweb_tx.GetSpentIDs()) {
                const int target_epoch = GetMWEBOutputOccurrenceHeightForSpendAt(spent_id, conf->confirmed_block_height);
                const auto [begin, end] = mapMWEBSpends.equal_range(spent_id);
                for (auto spend = begin; spend != end; ++spend) {
                    if (spend->second != tx.GetHash()) {
                        const auto spend_it = mapWallet.find(spend->second);
                        if (spend_it != mapWallet.end() &&
                            GetMWEBOutputOccurrenceHeight(spent_id, spend_it->second) == target_epoch) {
                            MarkConflicted(conf->confirmed_block_hash, conf->confirmed_block_height, spend->second);
                        }
                    }
                }
            }
        }

        bool fExisted = mapWallet.contains(tx.GetHash());
        std::vector<mw::Coin> mweb_coins;
        if (tx.HasMWEBTx() && !std::holds_alternative<TxStateConfirmed>(state)) {
            // MWEB outputs are indexed from the extension block in blockConnected once confirmed.
            mweb_coins = GetMWWallet()->RewindOutputs(tx);
        }
        const bool involves_mweb = !mweb_coins.empty();
        if (fExisted || IsMine(tx) || IsFromMe(tx) || involves_mweb)
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                for (const auto& spk_man : GetScriptPubKeyMans(txout.scriptPubKey)) {
                    for (auto &dest : spk_man->MarkUnusedAddresses(txout.scriptPubKey)) {
                        // If internal flag is not defined try to infer it from the ScriptPubKeyMan
                        if (!dest.internal.has_value()) {
                            dest.internal = IsInternalScriptPubKeyMan(spk_man);
                        }

                        // skip if can't determine whether it's a receiving address or not
                        if (!dest.internal.has_value()) continue;

                        // If this is a receiving address and it's not in the address book yet
                        // (e.g. it wasn't generated on this node or we're restoring from backup)
                        // add it to the address book for proper transaction accounting
                        if (!*dest.internal && !FindAddressBookEntry(dest.dest, /* allow_change= */ false)) {
                            SetAddressBook(dest.dest, "", AddressPurpose::RECEIVE);
                        }
                    }
                }
            }

            // Block disconnection override an abandoned tx as unconfirmed
            // which means user may have to call abandontransaction again
            TxState tx_state = std::visit([](auto&& s) -> TxState { return s; }, state);
            CWalletTx* wtx = AddToWallet(MakeTransactionRef(tx), tx_state, /*update_wtx=*/nullptr, rescanning_old_block);
            if (!wtx) {
                // Can only be nullptr if there was a db write error (missing db, read-only db or a db engine internal writing error).
                // As we only store arriving transaction in this process, and we don't want an inconsistent state, let's throw an error.
                throw std::runtime_error("DB error adding transaction to wallet, write failed");
            }
            return true;
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const Txid& hashTx) const
{
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && GetTxDepthInMainChain(*wtx) == 0 && !wtx->InMempool();
}

void CWallet::UpdateTrucSiblingConflicts(const CWalletTx& parent_wtx, const Txid& child_txid, bool add_conflict) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    // Find all other txs in our wallet that spend utxos from this parent
    // so that we can mark them as mempool-conflicted by this new tx.
    for (long unsigned int i = 0; i < parent_wtx.GetTx()->vout.size(); i++) {
        for (auto range = mapTxSpends.equal_range(COutPoint(parent_wtx.GetTx()->GetHash(), i)); range.first != range.second; range.first++) {
            const Txid& sibling_txid = range.first->second;
            // Skip the child_tx itself
            if (sibling_txid == child_txid) continue;
            RecursiveUpdateTxState(/*batch=*/nullptr, sibling_txid, [&child_txid, add_conflict](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return add_conflict ? (wtx.mempool_conflicts.insert(child_txid).second ? TxUpdate::CHANGED : TxUpdate::UNCHANGED)
                                    : (wtx.mempool_conflicts.erase(child_txid) ? TxUpdate::CHANGED : TxUpdate::UNCHANGED);
            });
        }
    }
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    for (const CTxIn& txin : tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

bool CWallet::AbandonTransaction(const Txid& hashTx)
{
    LOCK(cs_wallet);
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    return AbandonTransaction(it->second);
}

bool CWallet::AbandonTransaction(CWalletTx& tx)
{
    // Can't mark abandoned if confirmed or in mempool
    if (GetTxDepthInMainChain(tx) != 0 || tx.InMempool()) {
        return false;
    }

    auto try_updating_state = [](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // If the orig tx was not in block/mempool, none of its spends can be.
        assert(!wtx.isConfirmed());
        assert(!wtx.InMempool());
        // If already conflicted or abandoned, no need to set abandoned
        if (!wtx.isBlockConflicted() && !wtx.isAbandoned()) {
            wtx.m_state = TxStateInactive{/*abandoned=*/true};
            return TxUpdate::NOTIFY_CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too.
    // States are not permanent, so these transactions can become unabandoned if they are re-added to the
    // mempool, or confirmed in a block, or conflicted.
    // Note: If the reorged coinbase is re-added to the main chain, the descendants that have not had their
    // states change will remain abandoned and will require manual broadcast if the user wants them.

    RecursiveUpdateTxState(tx.GetHash(), try_updating_state);

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, int conflicting_height, const Txid& hashTx)
{
    LOCK(cs_wallet);

    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (m_last_block_processed_height < 0 || conflicting_height < 0) {
        return;
    }
    int conflictconfirms = (m_last_block_processed_height - conflicting_height + 1) * -1;
    if (conflictconfirms >= 0)
        return;

    auto try_updating_state = [&](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        if (conflictconfirms < GetTxDepthInMainChain(wtx)) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.m_state = TxStateBlockConflicted{hashBlock, conflicting_height};
            // An extension-only winner may have no canonical transaction callback
            // to notify observers about its losing MWEB transactions.
            if (wtx.GetTx()->HasMWEBTx() || wtx.IsMWEBPlaceholder()) return TxUpdate::NOTIFY_CHANGED;
            return TxUpdate::CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too.
    RecursiveUpdateTxState(hashTx, try_updating_state);

}

void CWallet::RecursiveUpdateTxState(const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state) {
    WalletBatch batch(GetDatabase());
    RecursiveUpdateTxState(&batch, tx_hash, try_updating_state);
}

void CWallet::RecursiveUpdateTxState(WalletBatch* batch, const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state) {
    std::set<Txid> todo;
    std::set<Txid> done;

    todo.insert(tx_hash);

    while (!todo.empty()) {
        Txid now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;

        TxUpdate update_state = try_updating_state(wtx);
        if (update_state != TxUpdate::UNCHANGED) {
            wtx.MarkDirty();
            if (batch) batch->WriteTxMetadata(wtx, /*previous_key=*/now);
            // Iterate over all its outputs, and update those tx states as well (if applicable)
            for (unsigned int i = 0; i < wtx.GetTx()->vout.size(); ++i) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(COutPoint(now, i));
                for (TxSpends::const_iterator iter = range.first; iter != range.second; ++iter) {
                    if (!done.contains(iter->second)) {
                        todo.insert(iter->second);
                    }
                }
            }
            // MWEB descendants spend output identities rather than COutPoints.
            auto mweb_outputs = wtx.GetTx()->mweb_tx.GetOutputIDs();
            if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
                mweb_outputs.insert(wtx.mweb_wtx_info->received_coin->output_id);
            }
            for (const mw::Hash& output_id : mweb_outputs) {
                const auto [begin, end] = mapMWEBSpends.equal_range(output_id);
                for (auto spend = begin; spend != end; ++spend) {
                    if (!done.contains(spend->second)) todo.insert(spend->second);
                }
            }

            if (update_state == TxUpdate::NOTIFY_CHANGED) {
                NotifyTransactionChanged(wtx.GetHash(), CT_UPDATED);
            }

            // If a transaction changes its tx state, that usually changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.GetTx());
        }
    }
}

bool CWallet::SyncTransaction(const CTransactionRef& ptx, const SyncTxState& state, bool rescanning_old_block)
{
    if (!AddToWalletIfInvolvingMe(ptx, state, rescanning_old_block))
        return false; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    MarkInputsDirty(ptx);
    return true;
}

void CWallet::transactionAddedToMempool(const CTransactionRef& tx) {
    LOCK(cs_wallet);
    SyncTransaction(tx, TxStateInMempool{});

    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }

    const Txid& txid = tx->GetHash();

    for (const CTxIn& tx_in : tx->vin) {
        // For each wallet transaction spending this prevout..
        for (auto range = mapTxSpends.equal_range(tx_in.prevout); range.first != range.second; range.first++) {
            const Txid& spent_id = range.first->second;
            // Skip the recently added tx
            if (spent_id == txid) continue;
            RecursiveUpdateTxState(/*batch=*/nullptr, spent_id, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.insert(txid).second ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }

    }

    // Mirror the canonical mempool-conflict lifecycle for MWEB spend identities.
    for (const mw::Hash& output_id : tx->mweb_tx.GetSpentIDs()) {
        const int target_epoch = GetMWEBOutputOccurrenceHeightForSpendAt(output_id, std::numeric_limits<int>::max());
        const auto [begin, end] = mapMWEBSpends.equal_range(output_id);
        for (auto spend = begin; spend != end; ++spend) {
            if (spend->second == txid) continue;
            const auto spend_it = mapWallet.find(spend->second);
            if (spend_it == mapWallet.end() ||
                GetMWEBOutputOccurrenceHeight(output_id, spend_it->second) != target_epoch) {
                continue;
            }
            RecursiveUpdateTxState(/*batch=*/nullptr, spend->second, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.insert(txid).second ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }
    }

    if (tx->version == TRUC_VERSION) {
        // Unconfirmed TRUC transactions are only allowed a 1-parent-1-child topology.
        // For any unconfirmed v3 parents (there should be a maximum of 1 except in reorgs),
        // record this child so the wallet doesn't try to spend any other outputs
        for (const CTxIn& tx_in : tx->vin) {
            auto parent_it = mapWallet.find(tx_in.prevout.hash);
            if (parent_it != mapWallet.end()) {
                CWalletTx& parent_wtx = parent_it->second;
                if (parent_wtx.isUnconfirmed()) {
                    parent_wtx.truc_child_in_mempool = tx->GetHash();
                    // Even though these siblings do not spend the same utxos, they can't
                    // be present in the mempool at the same time because of TRUC policy rules
                    UpdateTrucSiblingConflicts(parent_wtx, txid, /*add_conflict=*/true);
                }
            }
        }
    }
}

void CWallet::transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }
    // Handle transactions that were removed from the mempool because they
    // conflict with transactions in a newly connected block.
    if (reason == MemPoolRemovalReason::CONFLICT) {
        // Trigger external -walletnotify notifications for these transactions.
        // Set Status::UNCONFIRMED instead of Status::CONFLICTED for a few reasons:
        //
        // 1. The transactionRemovedFromMempool callback does not currently
        //    provide the conflicting block's hash and height, and for backwards
        //    compatibility reasons it may not be not safe to store conflicted
        //    wallet transactions with a null block hash. See
        //    https://github.com/bitcoin/bitcoin/pull/18600#discussion_r420195993.
        // 2. For most of these transactions, the wallet's internal conflict
        //    detection in the blockConnected handler will subsequently call
        //    MarkConflicted and update them with CONFLICTED status anyway. This
        //    applies to any wallet transaction that has inputs spent in the
        //    block, or that has ancestors in the wallet with inputs spent by
        //    the block.
        // 3. Longstanding behavior since the sync implementation in
        //    https://github.com/bitcoin/bitcoin/pull/9371 and the prior sync
        //    implementation before that was to mark these transactions
        //    unconfirmed rather than conflicted.
        //
        // Nothing described above should be seen as an unchangeable requirement
        // when improving this code in the future. The wallet's heuristics for
        // distinguishing between conflicted and unconfirmed transactions are
        // imperfect, and could be improved in general, see
        // https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Wallet-Transaction-Conflict-Tracking
        SyncTransaction(tx, TxStateInactive{});
    }

    const Txid& txid = tx->GetHash();

    for (const CTxIn& tx_in : tx->vin) {
        // Iterate over all wallet transactions spending txin.prev
        // and recursively mark them as no longer conflicting with
        // txid
        for (auto range = mapTxSpends.equal_range(tx_in.prevout); range.first != range.second; range.first++) {
            const Txid& spent_id = range.first->second;

            RecursiveUpdateTxState(/*batch=*/nullptr, spent_id, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.erase(txid) ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }
    }

    // MWEB conflicts disappear with the conflicting mempool transaction too.
    for (const mw::Hash& output_id : tx->mweb_tx.GetSpentIDs()) {
        const auto [begin, end] = mapMWEBSpends.equal_range(output_id);
        for (auto spend = begin; spend != end; ++spend) {
            RecursiveUpdateTxState(/*batch=*/nullptr, spend->second, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.erase(txid) ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }
    }

    if (tx->version == TRUC_VERSION) {
        // If this tx has a parent, unset its truc_child_in_mempool to make it possible
        // to spend from the parent again. If this tx was replaced by another
        // child of the same parent, transactionAddedToMempool
        // will update truc_child_in_mempool
        for (const CTxIn& tx_in : tx->vin) {
            auto parent_it = mapWallet.find(tx_in.prevout.hash);
            if (parent_it != mapWallet.end()) {
                CWalletTx& parent_wtx = parent_it->second;
                if (parent_wtx.truc_child_in_mempool == tx->GetHash()) {
                    parent_wtx.truc_child_in_mempool = std::nullopt;
                    UpdateTrucSiblingConflicts(parent_wtx, txid, /*add_conflict=*/false);
                }
            }
        }
    }
}

void CWallet::blockConnected(const ChainstateRole& role, const interfaces::BlockInfo& block)
{
    if (role.historical) {
        return;
    }
    assert(block.data);

    // MWEB: block.data from validation notifications may carry only a stub mweb_block
    // (header without outputs/kernels); read the full block from disk when HogEx is present.
    // The read and the view tag matching need no wallet lock.
    const bool scan_mweb = block.chain_time_max >= m_birth_time.load() - (TIMESTAMP_WINDOW * 2);
    const CBlock* scan_block = block.data;
    CBlock disk_block;
    if (scan_mweb && scan_block->GetHogEx() != nullptr) {
        if (chain().findBlock(block.hash, FoundBlock().data(disk_block)) && !disk_block.mweb_block.IsNull()) {
            scan_block = &disk_block;
        }
    }
    std::optional<MWEB::OutputCandidates> mweb_candidates;
    if (scan_mweb && !scan_block->mweb_block.IsNull()) {
        mweb_candidates = GetMWWallet()->FindCandidateOutputs(scan_block->mweb_block.m_block->GetOutputs());
    }

    LOCK(cs_wallet);

    // Update the best block in memory first. This will set the best block's height, which is
    // needed by MarkConflicted.
    SetLastBlockProcessedInMem(block.height, block.hash);

    // No need to scan block if it was created before the wallet birthday.
    // Uses chain max time and twice the grace period to adjust time for block time variability.
    if (block.chain_time_max < m_birth_time.load() - (TIMESTAMP_WINDOW * 2)) return;

    // Scan block
    bool wallet_updated = false;
    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        wallet_updated |= SyncTransaction(block.data->vtx[index], TxStateConfirmed{block.hash, block.height, static_cast<int>(index)});
        transactionRemovedFromMempool(block.data->vtx[index], MemPoolRemovalReason::BLOCK);
    }

    // Update on disk if this block resulted in us updating a tx, or periodically every 144 blocks (~1 day)
    if (wallet_updated || block.height % 144 == 0) {
        WriteBestBlock();
    }

    // MWEB hooks: scan extension block for wallet-relevant outputs and spends.
    if (!scan_mweb && scan_block->GetHogEx() != nullptr) {
        if (chain().findBlock(block.hash, FoundBlock().data(disk_block)) && !disk_block.mweb_block.IsNull()) {
            scan_block = &disk_block;
        }
    }
    if (!scan_block->mweb_block.IsNull()) {
        for (DescriptorScriptPubKeyMan* spk_man : GetMWEBAccountScriptPubKeyMans()) {
            spk_man->LoadMWEBKeychain();
        }
        ScanMWEBExtensionBlock(*scan_block, block.height, block.hash, /*rescanning_old_block=*/false,
                               mweb_candidates ? &*mweb_candidates : nullptr);
    }
}

void CWallet::blockDisconnected(const interfaces::BlockInfo& block)
{
    assert(block.data);
    // MWEB notifications may contain only the extension header, as on connect.
    const CBlock* disconnected_block = block.data;
    CBlock disk_block;
    if (block.data->GetHogEx() != nullptr && chain().findBlock(block.hash, FoundBlock().data(disk_block)) && !disk_block.mweb_block.IsNull()) {
        disconnected_block = &disk_block;
    }
    LOCK(cs_wallet);

    // At block disconnection, this will change an abandoned transaction to
    // be unconfirmed, whether or not the transaction is added back to the mempool.
    // User may have to call abandontransaction again. It may be addressed in the
    // future with a stickier abandoned state or even removing abandontransaction call.
    int disconnect_height = block.height;

    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        const CTransactionRef& ptx = block.data->vtx[index];
        // Coinbase transactions are not only inactive but also abandoned,
        // meaning they should never be relayed standalone via the p2p protocol.
        SyncTransaction(ptx, TxStateInactive{/*abandoned=*/index == 0});

        for (const CTxIn& tx_in : ptx->vin) {
            // No other wallet transactions conflicted with this transaction
            if (!mapTxSpends.contains(tx_in.prevout)) continue;

            std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(tx_in.prevout);

            // For all of the spends that conflict with this transaction
            for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it) {
                CWalletTx& wtx = mapWallet.find(_it->second)->second;

                if (!wtx.isBlockConflicted()) continue;

                auto try_updating_state = [&](CWalletTx& tx) {
                    if (!tx.isBlockConflicted()) return TxUpdate::UNCHANGED;
                    if (tx.state<TxStateBlockConflicted>()->conflicting_block_height >= disconnect_height) {
                        tx.m_state = TxStateInactive{};
                        return TxUpdate::CHANGED;
                    }
                    return TxUpdate::UNCHANGED;
                };

                RecursiveUpdateTxState(wtx.GetTx()->GetHash(), try_updating_state);
            }
        }
    }

    // Update the best block
    SetLastBlockProcessed(block.height - 1, *Assert(block.prev_hash));

    // MWEB hooks: disconnect extension block wallet effects
    const CBlock& block_data = *disconnected_block;
    if (!block_data.mweb_block.IsNull()) {
        for (const mw::Hash& spent_id : block_data.mweb_block.GetSpentIDs()) {
            const auto [begin, end] = mapMWEBSpends.equal_range(spent_id);
            for (auto spend = begin; spend != end; ++spend) {
                // Use the wallet key: an S(input) placeholder has an empty body.
                RecursiveUpdateTxState(spend->second, [&](CWalletTx& wtx) {
                    const auto* conflict = wtx.state<TxStateBlockConflicted>();
                    const auto* confirmed = wtx.state<TxStateConfirmed>();
                    if ((conflict && conflict->conflicting_block_height >= disconnect_height) ||
                        (confirmed && confirmed->confirmed_block_hash == block.hash)) {
                        wtx.m_state = TxStateInactive{};
                        return TxUpdate::CHANGED;
                    }
                    return TxUpdate::UNCHANGED;
                });
            }
        }

        for (const mw::Hash& kernel_id : block_data.mweb_block.GetKernelIDs()) {
            if (CWalletTx* wtx = FindWalletTxByKernelId(kernel_id)) {
                SyncTransaction(wtx->GetTx(), TxStateInactive{});
            }
        }

        const std::vector<Output>& outputs = block_data.mweb_block.m_block->GetOutputs();
        for (const size_t output_index : GetMWWallet()->OutputsToRewind(outputs)) {
            const Output& output = outputs[output_index];
            const std::optional<uint64_t> leaf_index = GetMWEBBlockOutputLeafIndex(block_data, output_index);
            mw::Coin received_coin;
            if (GetMWWallet()->RewindOutput(output, received_coin)) {
                if (CWalletTx* wtx = FindWalletTxForBlockOutput(output.GetOutputID(), block_data, block.hash, leaf_index)) {
                    if (wtx->IsMWEBPlaceholder()) {
                        AddToWallet(wtx->GetTx(), TxStateInactive{}, nullptr, false, wtx->mweb_wtx_info);
                    } else {
                        SyncTransaction(wtx->GetTx(), TxStateInactive{});
                    }
                }
            }
        }
    }
}

void CWallet::updatedBlockTip()
{
    m_best_block_time = GetTime<std::chrono::milliseconds>().count();
}

void CWallet::BlockUntilSyncedToCurrentChain() const {
    AssertLockNotHeld(cs_wallet);
    // Skip the queue-draining stuff if we know we're caught up with
    // chain().Tip(), otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    uint256 last_block_hash = WITH_LOCK(cs_wallet, return m_last_block_processed);
    chain().waitForNotificationsIfTipChanged(last_block_hash);
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" input.
CAmount CWallet::GetDebit(const CTxIn &txin) const
{
    LOCK(cs_wallet);
    auto txo = GetTXO(txin.prevout);
    if (txo) {
        return txo->GetTxOut().nValue;
    }
    return 0;
}

bool CWallet::IsMine(const CTxOut& txout) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(txout.scriptPubKey);
}

bool CWallet::IsMine(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    if (const StealthAddress* addr = std::get_if<StealthAddress>(&dest)) {
        for (DescriptorScriptPubKeyMan* spk_man : GetMWEBAccountScriptPubKeyMans()) {
            if (spk_man->IsMine(CTxDestination{*addr})) {
                return true;
            }
        }
        return false;
    }
    return IsMine(GetScriptForDestination(dest));
}

bool CWallet::IsMine(const CScript& script) const
{
    AssertLockHeld(cs_wallet);

    // Search the cache so that IsMine is called only on the relevant SPKMs instead of on everything in m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        bool res = false;
        for (const auto& spkm : it->second) {
            res = res || spkm->IsMine(script);
        }
        Assume(res);
        return res;
    }

    return false;
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    AssertLockHeld(cs_wallet);
    for (const CTxOut& txout : tx.vout) {
        if (IsMine(txout)) {
            return true;
        }
    }
    if (tx.HasMWEBTx()) {
        for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
            if (IsMine(pegout.GetScriptPubKey())) {
                return true;
            }
        }
    }
    return false;
}

bool CWallet::IsMine(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    auto wtx = GetWalletTx(outpoint.hash);
    if (!wtx) {
        return false;
    }
    if (outpoint.n >= wtx->GetTx()->vout.size()) {
        return false;
    }
    return IsMine(wtx->GetTx()->vout[outpoint.n]);
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    LOCK(cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (GetTXO(txin.prevout)) return true;
    }
    return false;
}

CAmount CWallet::GetDebit(const CTransaction& tx) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsHDEnabled() const
{
    // All Active ScriptPubKeyMans must be HD for this to be true
    bool result = false;
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->IsHDEnabled()) return false;
        result = true;
    }
    return result;
}

bool CWallet::CanGetAddresses(bool internal) const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) return false;
    for (OutputType t : OUTPUT_TYPES) {
        auto spk_man = GetScriptPubKeyMan(t, internal);
        if (spk_man && spk_man->CanGetAddresses(internal)) {
            return true;
        }
    }
    // MWEB hooks: external MWEB SPKM only (internal is inert by design)
    if (!internal) {
        if (auto* mweb_spk = GetScriptPubKeyMan(OutputType::MWEB, /*internal=*/false)) {
            if (mweb_spk->CanGetAddresses(false)) {
                return true;
            }
        }
    }
    return false;
}

void CWallet::SetWalletFlag(uint64_t flags)
{
    WalletBatch batch(GetDatabase());
    return SetWalletFlagWithDB(batch, flags);
}

void CWallet::SetWalletFlagWithDB(WalletBatch& batch, uint64_t flags)
{
    LOCK(cs_wallet);
    m_wallet_flags |= flags;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    WalletBatch batch(GetDatabase());
    UnsetWalletFlagWithDB(batch, flag);
}

void CWallet::UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag)
{
    LOCK(cs_wallet);
    m_wallet_flags &= ~flag;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetBlankWalletFlag(WalletBatch& batch)
{
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
}

bool CWallet::IsWalletFlagSet(uint64_t flag) const
{
    return (m_wallet_flags & flag);
}

bool CWallet::LoadWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);
    if (((flags & KNOWN_WALLET_FLAGS) >> 32) ^ (flags >> 32)) {
        // contains unknown non-tolerable wallet flags
        return false;
    }
    m_wallet_flags = flags;

    return true;
}

void CWallet::InitWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);

    // We should never be writing unknown non-tolerable wallet flags
    assert(((flags & KNOWN_WALLET_FLAGS) >> 32) == (flags >> 32));
    // This should only be used once, when creating a new wallet - so current flags are expected to be blank
    assert(m_wallet_flags == 0);

    if (!WalletBatch(GetDatabase()).WriteWalletFlags(flags)) {
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }

    if (!LoadWalletFlags(flags)) assert(false);
}

uint64_t CWallet::GetWalletFlags() const
{
    return m_wallet_flags;
}

void CWallet::MaybeUpdateBirthTime(int64_t time)
{
    int64_t birthtime = m_birth_time.load();
    if (time < birthtime) {
        m_birth_time = time;
    }
}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    int start_height = 0;
    uint256 start_block;
    bool start = chain().findFirstBlockWithTimeAndHeight(startTime - TIMESTAMP_WINDOW, 0, FoundBlock().hash(start_block).height(start_height));
    WalletLogPrintf("%s: Rescanning last %i blocks\n", __func__, start ? WITH_LOCK(cs_wallet, return GetLastBlockHeight()) - start_height + 1 : 0);

    if (start) {
        // TODO: this should take into account failure by ScanResult::USER_ABORT
        ScanResult result = ScanForWalletTransactions(start_block, start_height, /*max_height=*/{}, reserver, /*save_progress=*/false);
        if (result.status == ScanResult::FAILURE) {
            int64_t time_max;
            CHECK_NONFATAL(chain().findBlock(result.last_failed_block, FoundBlock().maxTime(time_max)));
            return time_max + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in start_block) for transactions
 * from or to us. If max_height is not set, the
 * mempool will be scanned as well.
 *
 * @param[in] start_block Scan starting block. If block is not on the active
 *                        chain, the scan will return SUCCESS immediately.
 * @param[in] start_height Height of start_block
 * @param[in] max_height  Optional max scanning height. If unset there is
 *                        no maximum and scanning can continue to the tip
 *
 * @return ScanResult returning scan information and indicating success or
 *         failure. Return status will be set to SUCCESS if scan was
 *         successful. FAILURE if a complete rescan was not possible (due to
 *         pruning or corruption). USER_ABORT if the rescan was aborted before
 *         it could complete.
 *
 * @pre Caller needs to make sure start_block (and the optional stop_block) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, const bool save_progress)
{
    constexpr auto INTERVAL_TIME{60s};
    auto current_time{reserver.now()};
    auto start_time{reserver.now()};

    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    std::unique_ptr<FastWalletRescanFilter> fast_rescan_filter;
    if (chain().hasBlockFilterIndex(BlockFilterType::BASIC)) fast_rescan_filter = std::make_unique<FastWalletRescanFilter>(*this);

    WalletLogPrintf("Rescan started from block %s... (%s)\n", start_block.ToString(),
                    fast_rescan_filter ? "fast variant using block filters" : "slow variant inspecting all blocks");

    ShowProgress(strprintf("[%s] %s", DisplayName(), _("Rescanning…")), 0); // show rescan progress in GUI as dialog or on splashscreen, if rescan required on startup (e.g. due to corruption)
    uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = tip_hash;
    if (max_height) chain().findAncestorByHeight(tip_hash, *max_height, FoundBlock().hash(end_hash));
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    int block_height = start_height;
    while (!fAbortRescan && !chain().shutdownRequested()) {
        if (progress_end - progress_begin > 0.0) {
            m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        } else { // avoid divide-by-zero for single block scan range (i.e. start and stop hashes are equal)
            m_scanning_progress = 0;
        }
        if (block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
            ShowProgress(strprintf("[%s] %s", DisplayName(), _("Rescanning…")), std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
        }

        bool next_interval = reserver.now() >= current_time + INTERVAL_TIME;
        if (next_interval) {
            current_time = reserver.now();
            WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", block_height, progress_current);
        }

        bool fetch_block{true};
        if (fast_rescan_filter) {
            fast_rescan_filter->UpdateIfNeeded();
            auto matches_block{fast_rescan_filter->MatchesBlock(block_hash)};
            if (matches_block.has_value()) {
                if (*matches_block) {
                    LogDebug(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (filter matched)\n", block_height, block_hash.ToString());
                } else {
                    result.last_scanned_block = block_hash;
                    result.last_scanned_height = block_height;
                    fetch_block = false;
                }
            } else {
                LogDebug(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (WARNING: block filter not found!)\n", block_height, block_hash.ToString());
            }
        }

        // Find next block separately from reading data above, because reading
        // is slow and there might be a reorg while it is read.
        bool block_still_active = false;
        bool next_block = false;
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));

        if (fetch_block) {
            // Read block data and locator if needed (the locator is usually null unless we need to save progress)
            CBlock block;
            CBlockLocator loc;
            // Find block
            FoundBlock found_block{FoundBlock().data(block)};
            if (save_progress && next_interval) found_block.locator(loc);
            chain().findBlock(block_hash, found_block);

            if (!block.IsNull()) {
                std::optional<MWEB::OutputCandidates> mweb_candidates;
                if (!block.mweb_block.IsNull()) {
                    mweb_candidates = GetMWWallet()->FindCandidateOutputs(block.mweb_block.m_block->GetOutputs());
                }
                LOCK(cs_wallet);
                if (!block_still_active) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{block_hash, block_height, static_cast<int>(posInBlock)}, /*rescanning_old_block=*/true);
                }
                // MWEB extension outputs are not present as L1 vtx entries; scan them
                // the same way blockConnected does so import/rescan discovers coins.
                if (!block.mweb_block.IsNull()) {
                    for (DescriptorScriptPubKeyMan* spk_man : GetMWEBAccountScriptPubKeyMans()) {
                        spk_man->LoadMWEBKeychain();
                    }
                    ScanMWEBExtensionBlock(block, block_height, block_hash, /*rescanning_old_block=*/true,
                                           mweb_candidates ? &*mweb_candidates : nullptr);
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = block_height;

                if (!loc.IsNull()) {
                    WalletLogPrintf("Saving scan progress %d.\n", block_height);
                    WalletBatch batch(GetDatabase());
                    batch.WriteBestBlock(loc);
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
        }
        if (max_height && block_height >= *max_height) {
            break;
        }
        // If rescanning was triggered with cs_wallet permanently locked (AttachChain), additional blocks that were connected during the rescan
        // aren't processed here but will be processed with the pending blockConnected notifications after the lock is released.
        // If rescanning without a permanent cs_wallet lock, additional blocks that were added during the rescan will be re-processed if
        // the notification was processed and the last block height was updated.
        if (block_height >= WITH_LOCK(cs_wallet, return GetLastBlockHeight())) {
            break;
        }

        {
            if (!next_block) {
                // break successfully when rescan has reached the tip, or
                // previous block is no longer on the chain due to a reorg
                break;
            }

            // increment block and verification progress
            block_hash = next_block_hash;
            ++block_height;
            progress_current = chain().guessVerificationProgress(block_hash);

            // handle updated tip hash
            const uint256 prev_tip_hash = tip_hash;
            tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
            if (!max_height && prev_tip_hash != tip_hash) {
                // in case the tip has changed, update progress max
                progress_end = chain().guessVerificationProgress(tip_hash);
            }
        }
    }
    if (!max_height) {
        WalletLogPrintf("Scanning current mempool transactions.\n");
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    }
    ShowProgress(strprintf("[%s] %s", DisplayName(), _("Rescanning…")), 100); // hide progress dialog in GUI
    if (fAbortRescan) {
        WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else if (chain().shutdownRequested()) {
        WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else {
        WalletLogPrintf("Rescan completed in %15dms\n", Ticks<std::chrono::milliseconds>(reserver.now() - start_time));
    }
    return result;
}

bool CWallet::SubmitTxMemoryPoolAndRelay(CWalletTx& wtx,
                                         std::string& err_string,
                                         node::TxBroadcast broadcast_method) const
{
    AssertLockHeld(cs_wallet);

    // Can't relay if wallet is not broadcasting
    if (!GetBroadcastTransactions()) return false;
    // Don't relay abandoned transactions
    if (wtx.isAbandoned()) return false;
    // Don't try to submit coinbase transactions. These would fail anyway but would
    // cause log spam.
    if (wtx.IsCoinBase()) return false;
    // Don't try to submit conflicted or confirmed transactions.
    if (GetTxDepthInMainChain(wtx) != 0) return false;

    const char* what{""};
    switch (broadcast_method) {
    case node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL:
        what = "to mempool and for broadcast to peers";
        break;
    case node::TxBroadcast::MEMPOOL_NO_BROADCAST:
        what = "to mempool without broadcast";
        break;
    case node::TxBroadcast::NO_MEMPOOL_PRIVATE_BROADCAST:
        what = "for private broadcast without adding to the mempool";
        break;
    }
    WalletLogPrintf("Submitting wtx %s %s\n", wtx.GetHash().ToString(), what);
    // We must set TxStateInMempool here. Even though it will also be set later by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that this newly generated transaction's change is
    // unavailable as we're not yet aware that it is in the mempool.
    //
    // If broadcast fails for any reason, trying to set wtx.m_state here would be incorrect.
    // If transaction was previously in the mempool, it should be updated when
    // TransactionRemovedFromMempool fires.
    bool ret = chain().broadcastTransaction(wtx.GetTx(), m_default_max_tx_fee, broadcast_method, err_string);
    if (ret) wtx.m_state = TxStateInMempool{};
    return ret;
}

std::set<Txid> CWallet::GetTxConflicts(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    const Txid myHash{wtx.GetHash()};
    std::set<Txid> result{GetConflicts(myHash)};
    result.erase(myHash);
    return result;
}

bool CWallet::ShouldResend() const
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast
    if (!fBroadcastTransactions) return false;

    // During reindex, importing and IBD, old wallet transactions become
    // unconfirmed. Don't resend them as that would spam other nodes.
    // We only allow forcing mempool submission when not relaying to avoid this spam.
    if (!chain().isReadyToBroadcast()) return false;

    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (NodeClock::now() < m_next_resend) return false;

    return true;
}

NodeClock::time_point CWallet::GetDefaultNextResend() { return FastRandomContext{}.rand_uniform_delay(NodeClock::now() + 12h, 24h); }

// Resubmit transactions from the wallet to the mempool, optionally asking the
// mempool to relay them. On startup, we will do this for all unconfirmed
// transactions but will not ask the mempool to relay them. We do this on startup
// to ensure that our own mempool is aware of our transactions. There
// is a privacy side effect here as not broadcasting on startup also means that we won't
// inform the world of our wallet's state, particularly if the wallet (or node) is not
// yet synced.
//
// Otherwise this function is called periodically in order to relay our unconfirmed txs.
// We do this on a random timer to slightly obfuscate which transactions
// come from our wallet.
//
// TODO: Ideally, we'd only resend transactions that we think should have been
// mined in the most recent block. Any transaction that wasn't in the top
// blockweight of transactions in the mempool shouldn't have been mined,
// and so is probably just sitting in the mempool waiting to be confirmed.
// Rebroadcasting does nothing to speed up confirmation and only damages
// privacy.
//
// The `force` option results in all unconfirmed transactions being submitted to
// the mempool. This does not necessarily result in those transactions being relayed,
// that depends on the `broadcast_method` option. Periodic rebroadcast uses the pattern
// broadcast_method=TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL force=false, while loading into
// the mempool (on start, or after import) uses
// broadcast_method=TxBroadcast::MEMPOOL_NO_BROADCAST force=true.
void CWallet::ResubmitWalletTransactions(node::TxBroadcast broadcast_method, bool force)
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast,
    // even if forcing.
    if (!fBroadcastTransactions) return;

    int submitted_tx_count = 0;

    { // cs_wallet scope
        LOCK(cs_wallet);

        // First filter for the transactions we want to rebroadcast.
        // We use a set with WalletTxOrderComparator so that rebroadcasting occurs in insertion order
        std::set<CWalletTx*, WalletTxOrderComparator> to_submit;
        for (auto& [txid, wtx] : mapWallet) {
            // Only rebroadcast unconfirmed txs
            if (!wtx.isUnconfirmed()) continue;

            // Attempt to rebroadcast all txes more than 5 minutes older than
            // the last block, or all txs if forcing.
            if (!force && wtx.nTimeReceived > m_best_block_time - 5 * 60 * 1000) continue;
            to_submit.insert(&wtx);
        }
        // Now try submitting the transactions to the memory pool and (optionally) relay them.
        for (auto wtx : to_submit) {
            std::string unused_err_string;
            if (SubmitTxMemoryPoolAndRelay(*wtx, unused_err_string, broadcast_method)) ++submitted_tx_count;
        }
    } // cs_wallet

    if (submitted_tx_count > 0) {
        WalletLogPrintf("%s: resubmit %u unconfirmed transactions\n", __func__, submitted_tx_count);
    }
}

/** @} */ // end of mapWallet

void MaybeResendWalletTxs(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        if (!pwallet->ShouldResend()) continue;
        pwallet->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL, /*force=*/false);
        pwallet->SetNextResend();
    }
}

void MaybePruneMWEBDescriptors(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        LOCK(pwallet->cs_wallet);
        if (pwallet->CountMWEBInternalDescriptors() <= static_cast<size_t>(pwallet->m_mweb_descriptor_threshold)) {
            continue;
        }
        pwallet->PruneMWEBDescriptors();
    }
}


bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    AssertLockHeld(cs_wallet);

    // Build coins map
    std::map<COutPoint, Coin> coins;
    for (auto& input : tx.vin) {
        const auto mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.GetTx()->vout.size()) {
            return false;
        }
        const CWalletTx& wtx = mi->second;
        int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
        coins[input.prevout] = Coin(wtx.GetTx()->vout[input.prevout.n], prev_height, wtx.IsCoinBase());
    }
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
}

bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    // Try to sign with all ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        // spk_man->SignTransaction will return true if the transaction is complete,
        // so we can exit early and return true if that happens
        if (spk_man->SignTransaction(tx, coins, sighash, input_errors)) {
            return true;
        }
    }

    // At this point, one input was not fully signed otherwise we would have exited already
    return false;
}

std::optional<PSBTError> CWallet::FillPSBT(PartiallySignedTransaction& psbtx, const common::PSBTFillOptions& options, bool& complete, size_t* n_signed) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    LOCK(cs_wallet);
    // Get all of the previous transactions
    for (PSBTInput& input : psbtx.inputs) {
        if (PSBTInputSigned(input) || input.IsMWEB()) {
            continue;
        }

        // If we have no utxo, grab it from the wallet.
        if (!input.non_witness_utxo) {
            const Txid& txhash = input.prev_txid;
            const auto it = mapWallet.find(txhash);
            if (it != mapWallet.end()) {
                const CWalletTx& wtx = it->second;
                // We only need the non_witness_utxo, which is a superset of the witness_utxo.
                //   The signing code will switch to the smaller witness_utxo if this is ok.
                input.non_witness_utxo = wtx.GetTx();
            }
        }
    }

    // MWEB components are signed first: transparent signatures commit to the peg-in scripts that MWEB
    // signing rewrites, so transparent inputs are not signed while MWEB signing is incomplete.
    common::PSBTFillOptions transparent_options{options};
    const bool has_mweb{psbtx.ContainsMWEBComponents()};
    if (has_mweb) {
        const std::unique_ptr<MWEBSigningKeyStore> keystore{MakeMWEBSigningKeyStore()};
        const mw::SenderKeyGenerator generate_sender_key = [this]() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) -> util::Result<SecretKey> {
            AssertLockHeld(cs_wallet);
            return GetMWWallet()->GenerateSenderKey();
        };
        util::Result<MWEBFillResult> mweb_fill = FillMWEBPSBT(psbtx, *keystore, options.sign, GetMWEBRewindKeyForSigning(), generate_sender_key);
        if (!mweb_fill) {
            WalletLogPrintf("FillPSBT: %s\n", util::ErrorString(mweb_fill).original);
            return PSBTError::INVALID_TX;
        }
        if (!mweb_fill->transparent_signing_allowed && options.sign && IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            if (const auto error{FillMWEBWithExternalSigner(psbtx, n_signed)}) return error;
            const util::Result<MWEBFillResult> refill = FillMWEBPSBT(psbtx, *keystore, /*sign=*/false, GetMWEBRewindKeyForSigning(), generate_sender_key);
            if (!refill) {
                WalletLogPrintf("FillPSBT: %s\n", util::ErrorString(refill).original);
                return PSBTError::INVALID_TX;
            }
            mweb_fill->transparent_signing_allowed = refill->transparent_signing_allowed;
        }
        if (!mweb_fill->transparent_signing_allowed) {
            transparent_options.sign = false;
        }
        if (n_signed) {
            (*n_signed) += mweb_fill->n_signed;
        }
        if (!mweb_fill->coins.empty() && GetMWWallet()) {
            std::vector<mw::Coin> coins;
            for (const auto& [output_id, coin] : mweb_fill->coins) {
                coins.push_back(coin);
            }
            if (!GetMWWallet()->SaveToWallet(coins)) {
                WalletLogPrintf("FillPSBT: failed to persist MWEB output metadata\n");
                return PSBTError::INVALID_TX;
            }
        }
    }

    std::optional<PrecomputedTransactionData> txdata_res = PrecomputePSBTData(psbtx);
    if (!txdata_res) {
        return PSBTError::INVALID_TX;
    }
    const PrecomputedTransactionData& txdata = *txdata_res;

    // Fill in information from ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        int n_signed_this_spkm = 0;
        const auto error{spk_man->FillPSBT(psbtx, txdata, transparent_options, &n_signed_this_spkm)};
        if (error) {
            return error;
        }

        if (n_signed) {
            (*n_signed) += n_signed_this_spkm;
        }
    }

    RemoveUnnecessaryTransactions(psbtx);

    // Complete if every input is now signed
    complete = true;
    for (size_t i = 0; i < psbtx.inputs.size(); ++i) {
        complete &= PSBTInputSignedAndVerified(psbtx, i, &txdata);
    }
    if (has_mweb) {
        complete &= psbtx.IsComplete();
    }

    return {};
}

std::optional<PSBTError> CWallet::FillMWEBWithExternalSigner(PartiallySignedTransaction& psbtx, size_t* n_signed) const
{
    AssertLockHeld(cs_wallet);
    const auto unsigned_mweb = [](const PSBTInput& input) { return input.IsMWEB() && !input.mweb_sig; };
    const auto ours = [&](const PSBTInput& input) {
        mw::Coin coin;
        // Require IsMine: sender-rewound coins for external recipients are in the
        // coin map for history but must not be offered to an external signer.
        return unsigned_mweb(input) && input.mweb_amount && input.mweb_address_descriptor && input.mweb_output_id &&
               GetCoin(*input.mweb_output_id, coin) && coin.IsMine();
    };
    // Checked before running the signer, so foreign PSBTs need no device.
    if (std::ranges::none_of(psbtx.inputs, ours)) return {};

    auto signer{ExternalSignerScriptPubKeyMan::GetExternalSigner()};
    if (!signer) {
        LogWarning("%s", util::ErrorString(signer).original);
        return PSBTError::EXTERNAL_SIGNER_NOT_FOUND;
    }
    if (std::ranges::none_of(psbtx.inputs, [&](const PSBTInput& input) { return ours(input) && signer->MatchesMWEBInput(input); })) {
        return {};
    }

    const auto unsigned_before{std::ranges::count_if(psbtx.inputs, unsigned_mweb)};
    if (const auto error{ExternalSignerScriptPubKeyMan::SignMWEBPSBT(*signer, psbtx)}) return error;
    if (n_signed) {
        *n_signed += static_cast<size_t>(unsigned_before - std::ranges::count_if(psbtx.inputs, unsigned_mweb));
    }
    return {};
}

SigningResult CWallet::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    SignatureData sigdata;
    CScript script_pub_key = GetScriptForDestination(pkhash);
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script_pub_key, sigdata)) {
            LOCK(cs_wallet);  // DescriptorScriptPubKeyMan calls IsLocked which can lock cs_wallet in a deadlocking order
            return spk_man_pair.second->SignMessage(message, pkhash, str_sig);
        }
    }
    return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
}

OutputType CWallet::TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& vecSend) const
{
    // If -changetype is specified, always use that change type.
    if (change_type) {
        return *change_type;
    }

    // if m_default_address_type is legacy, use legacy address as change.
    if (m_default_address_type == OutputType::LEGACY) {
        return OutputType::LEGACY;
    }

    bool any_tr{false};
    bool any_wpkh{false};
    bool any_sh{false};
    bool any_pkh{false};

    for (const auto& recipient : vecSend) {
        if (std::get_if<WitnessV1Taproot>(&recipient.dest)) {
            any_tr = true;
        } else if (std::get_if<WitnessV0KeyHash>(&recipient.dest)) {
            any_wpkh = true;
        } else if (std::get_if<ScriptHash>(&recipient.dest)) {
            any_sh = true;
        } else if (std::get_if<PKHash>(&recipient.dest)) {
            any_pkh = true;
        }
    }

    const bool has_bech32m_spkman(GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
    if (has_bech32m_spkman && any_tr) {
        // Currently tr is the only type supported by the BECH32M spkman
        return OutputType::BECH32M;
    }
    const bool has_bech32_spkman(GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
    if (has_bech32_spkman && any_wpkh) {
        // Currently wpkh is the only type supported by the BECH32 spkman
        return OutputType::BECH32;
    }
    const bool has_p2sh_segwit_spkman(GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
    if (has_p2sh_segwit_spkman && any_sh) {
        // Currently sh_wpkh is the only type supported by the P2SH_SEGWIT spkman
        // As of 2021 about 80% of all SH are wrapping WPKH, so use that
        return OutputType::P2SH_SEGWIT;
    }
    const bool has_legacy_spkman(GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
    if (has_legacy_spkman && any_pkh) {
        // Currently pkh is the only type supported by the LEGACY spkman
        return OutputType::LEGACY;
    }

    if (has_bech32m_spkman) {
        return OutputType::BECH32M;
    }
    if (has_bech32_spkman) {
        return OutputType::BECH32;
    }
    // else use m_default_address_type for change
    return m_default_address_type;
}

void CWallet::CommitTransaction(
    CTransactionRef tx,
    std::optional<Txid> replaces_txid,
    std::optional<std::string> comment,
    std::optional<std::string> comment_to,
    const std::vector<std::string>& messages,
    const std::vector<std::string>& payment_requests
)
{
    LOCK(cs_wallet);
    WalletLogPrintf("CommitTransaction:\n%s\n", util::RemoveSuffixView(tx->ToString(), "\n"));

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    CWalletTx* wtx = AddToWallet(tx, TxStateInactive{}, [&](CWalletTx& wtx, bool new_tx) {
        if (replaces_txid) wtx.m_replaces_txid = replaces_txid;
        if (comment) wtx.m_comment = comment;
        if (comment_to) wtx.m_comment_to = comment_to;
        if (!messages.empty()) wtx.m_messages = messages;
        if (!payment_requests.empty()) wtx.m_payment_requests = payment_requests;
        return true;
    });

    // wtx can only be null if the db write failed.
    if (!wtx) {
        throw std::runtime_error(std::string(__func__) + ": Wallet db error, transaction commit failed");
    }

    // Notify that old coins are spent
    for (const CTxIn& txin : tx->vin) {
        CWalletTx &coin = mapWallet.at(txin.prevout.hash);
        coin.MarkDirty();
        NotifyTransactionChanged(coin.GetHash(), CT_UPDATED);
    }

    if (!fBroadcastTransactions) {
        // Don't submit tx to the mempool
        return;
    }

    std::string err_string;
    if (!SubmitTxMemoryPoolAndRelay(*wtx, err_string, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL)) {
        WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
        // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
    }
}

DBErrors CWallet::PopulateWalletFromDB(bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    LOCK(cs_wallet);

    Assert(m_spk_managers.empty());
    Assert(m_wallet_flags == 0);
    DBErrors nLoadWalletRet = WalletBatch(GetDatabase()).LoadWallet(this);

    if (m_spk_managers.empty()) {
        assert(m_external_spk_managers.empty());
        assert(m_internal_spk_managers.empty());
    }

    const auto wallet_file = m_database->Filename();
    switch (nLoadWalletRet) {
    case DBErrors::LOAD_OK:
        break;
    case DBErrors::NONCRITICAL_ERROR:
        warnings.push_back(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                       " or address metadata may be missing or incorrect."),
            wallet_file));
        break;
    case DBErrors::NEED_RESCAN:
        warnings.push_back(strprintf(_("Error reading %s! Transaction data may be missing or incorrect."
                                       " Rescanning wallet."), wallet_file));
        break;
    case DBErrors::CORRUPT:
        error = strprintf(_("Error loading %s: Wallet corrupted"), wallet_file);
        break;
    case DBErrors::TOO_NEW:
        error = strprintf(_("Error loading %s: Wallet requires newer version of %s"), wallet_file, CLIENT_NAME);
        break;
    case DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED:
        error = strprintf(_("Error loading %s: External signer wallet being loaded without external signer support compiled"), wallet_file);
        break;
    case DBErrors::UNKNOWN_DESCRIPTOR:
        error = strprintf(_("Unrecognized descriptor found. Loading wallet %s\n\n"
                            "The wallet might have been created on a newer version.\n"
                            "Please try running the latest software version.\n"), wallet_file);
        break;
    case DBErrors::UNEXPECTED_LEGACY_ENTRY:
        error = strprintf(_("Unexpected legacy entry in descriptor wallet found. Loading wallet %s\n\n"
                            "The wallet might have been tampered with or created with malicious intent.\n"), wallet_file);
        break;
    case DBErrors::LEGACY_WALLET:
        error = strprintf(_("Error loading %s: Wallet is a legacy wallet. Please migrate to a descriptor wallet using the migration tool (migratewallet RPC)."), wallet_file);
        break;
    case DBErrors::LOAD_FAIL:
        error = strprintf(_("Error loading %s"), wallet_file);
        break;
    } // no default case, so the compiler can warn about missing cases
    return nLoadWalletRet;
}

util::Result<void> CWallet::RemoveTxs(std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    bilingual_str str_err;  // future: make RunWithinTxn return a util::Result
    bool was_txn_committed = RunWithinTxn(GetDatabase(), /*process_desc=*/"remove transactions", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        util::Result<void> result{RemoveTxs(batch, txs_to_remove)};
        if (!result) str_err = util::ErrorString(result);
        return result.has_value();
    });
    if (!str_err.empty()) return util::Error{str_err};
    if (!was_txn_committed) return util::Error{_("Error starting/committing db txn for wallet transactions removal process")};
    return {}; // all good
}

util::Result<void> CWallet::RemoveTxs(WalletBatch& batch, std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    if (!batch.HasActiveTxn()) return util::Error{strprintf(_("The transactions removal process can only be executed within a db txn"))};

    // Check for transaction existence and remove entries from disk
    std::vector<decltype(mapWallet)::const_iterator> erased_txs;
    bilingual_str str_err;
    for (const Txid& hash : txs_to_remove) {
        auto it_wtx = mapWallet.find(hash);
        if (it_wtx == mapWallet.end()) {
            return util::Error{strprintf(_("Transaction %s does not belong to this wallet"), hash.GetHex())};
        }
        if (!batch.EraseTx(hash)) {
            return util::Error{strprintf(_("Failure removing transaction: %s"), hash.GetHex())};
        }
        erased_txs.emplace_back(it_wtx);
    }

    // Register callback to update the memory state only when the db txn is actually dumped to disk
    batch.RegisterTxnListener({.on_commit=[&, erased_txs]() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // Update the in-memory state and notify upper layers about the removals
        for (const auto& it : erased_txs) {
            const Txid hash{it->first};
            wtxOrdered.erase(it->second.m_it_wtxOrdered);
            for (const auto& txin : it->second.GetTx()->vin) {
                auto range = mapTxSpends.equal_range(txin.prevout);
                for (auto iter = range.first; iter != range.second; ++iter) {
                    if (iter->second == hash) {
                        mapTxSpends.erase(iter);
                        break;
                    }
                }
            }
            for (unsigned int i = 0; i < it->second.GetTx()->vout.size(); ++i) {
                m_txos.erase(COutPoint(hash, i));
            }
            mapWallet.erase(it);
            NotifyTransactionChanged(hash, CT_DELETED);
        }

        MarkDirty();
    }, .on_abort={}});

    return {};
}

bool CWallet::SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& new_purpose)
{
    bool fUpdated = false;
    bool is_mine;
    std::optional<AddressPurpose> purpose;
    {
        LOCK(cs_wallet);
        std::map<CTxDestination, CAddressBookData>::iterator mi = m_address_book.find(address);
        fUpdated = mi != m_address_book.end() && !mi->second.IsChange();

        CAddressBookData& record = mi != m_address_book.end() ? mi->second : m_address_book[address];
        record.SetLabel(strName);
        is_mine = IsMine(address);
        if (new_purpose) { /* update purpose only if requested */
            record.purpose = new_purpose;
        }
        purpose = record.purpose;
    }

    const std::string& encoded_dest = EncodeDestination(address);
    if (new_purpose && !batch.WritePurpose(encoded_dest, PurposeToString(*new_purpose))) {
        WalletLogPrintf("Error: fail to write address book 'purpose' entry\n");
        return false;
    }
    if (!batch.WriteName(encoded_dest, strName)) {
        WalletLogPrintf("Error: fail to write address book 'name' entry\n");
        return false;
    }

    // In very old wallets, address purpose may not be recorded so we derive it from IsMine
    NotifyAddressBookChanged(address, strName, is_mine,
                             purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND),
                             (fUpdated ? CT_UPDATED : CT_NEW));
    return true;
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose)
{
    WalletBatch batch(GetDatabase());
    return SetAddressBookWithDB(batch, address, strName, purpose);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    return RunWithinTxn(GetDatabase(), /*process_desc=*/"address book entry removal", [&](WalletBatch& batch){
        return DelAddressBookWithDB(batch, address);
    });
}

bool CWallet::DelAddressBookWithDB(WalletBatch& batch, const CTxDestination& address)
{
    const std::string& dest = EncodeDestination(address);
    {
        LOCK(cs_wallet);
        // If we want to delete receiving addresses, we should avoid calling EraseAddressData because it will delete the previously_spent value. Could instead just erase the label so it becomes a change address, and keep the data.
        // NOTE: This isn't a problem for sending addresses because they don't have any data that needs to be kept.
        // When adding new address data, it should be considered here whether to retain or delete it.
        if (IsMine(address)) {
            WalletLogPrintf("%s called with IsMine address, NOT SUPPORTED. Please report this bug! %s\n", __func__, CLIENT_BUGREPORT);
            return false;
        }
        // Delete data rows associated with this address
        if (!batch.EraseAddressData(address)) {
            WalletLogPrintf("Error: cannot erase address book entry data\n");
            return false;
        }

        // Delete purpose entry
        if (!batch.ErasePurpose(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry purpose\n");
            return false;
        }

        // Delete name entry
        if (!batch.EraseName(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry name\n");
            return false;
        }

        // finally, remove it from the map
        m_address_book.erase(address);
    }

    // All good, signal changes
    NotifyAddressBookChanged(address, "", /*is_mine=*/false, AddressPurpose::SEND, CT_DELETED);
    return true;
}

size_t CWallet::KeypoolCountExternalKeys() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : m_external_spk_managers) {
        count += spk_man.second->GetKeyPoolSize();
    }

    return count;
}

unsigned int CWallet::GetKeyPoolSize() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        count += spk_man->GetKeyPoolSize();
    }
    return count;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    LOCK(cs_wallet);
    bool res = true;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        res &= spk_man->TopUp(kpSize);
    }
    return res;
}

util::Result<CTxDestination> CWallet::GetNewDestination(const OutputType type, const std::string& label)
{
    LOCK(cs_wallet);
    auto spk_man = GetScriptPubKeyMan(type, /*internal=*/false);
    if (!spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    auto op_dest = spk_man->GetNewDestination(type);
    if (op_dest) {
        SetAddressBook(*op_dest, label, AddressPurpose::RECEIVE);
    }

    return op_dest;
}

util::Result<CTxDestination> CWallet::PeekNewDestination(const OutputType type) const // MWEB
{
    LOCK(cs_wallet);
    const ScriptPubKeyMan* spk_man = GetScriptPubKeyMan(type, /*internal=*/false);
    if (!spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }
    return spk_man->PeekNewDestination(type);
}

util::Result<CTxDestination> CWallet::GetNewChangeDestination(const OutputType type)
{
    LOCK(cs_wallet);

    // MWEB: MWEB change goes to the active account's change subaddress
    if (type == OutputType::MWEB) {
        StealthAddress change_address;
        const DescriptorScriptPubKeyMan* account_spk{GetExternalMWEBScriptPubKeyMan()};
        if (!account_spk || !GetMWEBChangeAddress(*account_spk, change_address)) {
            return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
        }
        return CTxDestination{change_address};
    }

    ReserveDestination reservedest(this, type);
    auto op_dest = reservedest.GetReservedDestination(true);
    if (op_dest) reservedest.KeepDestination();

    return op_dest;
}

void CWallet::MarkDestinationsDirty(const std::set<CTxDestination>& destinations) {
    for (auto& entry : mapWallet) {
        CWalletTx& wtx = entry.second;
        if (wtx.m_is_cache_empty) continue;
        for (unsigned int i = 0; i < wtx.GetTx()->vout.size(); i++) {
            CTxDestination dst;
            if (ExtractDestination(wtx.GetTx()->vout[i].scriptPubKey, dst) && destinations.contains(dst)) {
                wtx.MarkDirty();
                break;
            }
        }
    }
}

void CWallet::ForEachAddrBookEntry(const ListAddrBookFunc& func) const
{
    AssertLockHeld(cs_wallet);
    for (const std::pair<const CTxDestination, CAddressBookData>& item : m_address_book) {
        const auto& entry = item.second;
        func(item.first, entry.GetLabel(), entry.IsChange(), entry.purpose);
    }
}

std::vector<CTxDestination> CWallet::ListAddrBookAddresses(const std::optional<AddrBookFilter>& _filter) const
{
    AssertLockHeld(cs_wallet);
    std::vector<CTxDestination> result;
    AddrBookFilter filter = _filter ? *_filter : AddrBookFilter();
    ForEachAddrBookEntry([&result, &filter](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        // Filter by change
        if (filter.ignore_change && is_change) return;
        // Filter by label
        if (filter.m_op_label && *filter.m_op_label != label) return;
        // All good
        result.emplace_back(dest);
    });
    return result;
}

std::set<std::string> CWallet::ListAddrBookLabels(const std::optional<AddressPurpose> purpose) const
{
    AssertLockHeld(cs_wallet);
    std::set<std::string> label_set;
    ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label,
                             bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (!purpose || purpose == _purpose) {
            label_set.insert(_label);
        }
    });
    return label_set;
}

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    m_spk_man = pwallet->GetScriptPubKeyMan(type, internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        int64_t index;
        auto op_address = m_spk_man->GetReservedDestination(type, internal, index);
        if (!op_address) return op_address;
        nIndex = index;
        address = *op_address;
    }
    return address;
}

void ReserveDestination::KeepDestination()
{
    if (nIndex != -1) {
        m_spk_man->KeepDestination(nIndex, type);
    }
    nIndex = -1;
    address = CNoDestination();
}

void ReserveDestination::ReturnDestination()
{
    if (nIndex != -1) {
        m_spk_man->ReturnDestination(nIndex, fInternal, address);
    }
    nIndex = -1;
    address = CNoDestination();
}

util::Result<void> CWallet::DisplayAddress(const CTxDestination& dest)
{
    if (const StealthAddress* stealth = std::get_if<StealthAddress>(&dest); stealth && IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        const DescriptorScriptPubKeyMan* mweb_spk = GetMWEBAccountForStealthAddress(*stealth);
        if (!mweb_spk) return util::Error{_("There is no ScriptPubKeyManager for this address")};
        auto signer{ExternalSignerScriptPubKeyMan::GetExternalSigner()};
        if (!signer) throw std::runtime_error(util::ErrorString(signer).original);
        return ExternalSignerScriptPubKeyMan::DisplayMWEBAddress(*mweb_spk, *stealth, *signer);
    }
    CScript scriptPubKey = GetScriptForDestination(dest);
    for (const auto& spk_man : GetScriptPubKeyMans(scriptPubKey)) {
        auto signer_spk_man = dynamic_cast<ExternalSignerScriptPubKeyMan *>(spk_man);
        if (signer_spk_man == nullptr) {
            continue;
        }
        auto signer{ExternalSignerScriptPubKeyMan::GetExternalSigner()};
        if (!signer) throw std::runtime_error(util::ErrorString(signer).original);
        return signer_spk_man->DisplayAddress(dest, *signer);
    }
    return util::Error{_("There is no ScriptPubKeyManager for this address")};
}

void CWallet::LoadLockedCoin(const COutPoint& coin, bool persistent)
{
    AssertLockHeld(cs_wallet);
    m_locked_coins.emplace(coin, persistent);
}

bool CWallet::LockCoin(const COutPoint& output, bool persist)
{
    AssertLockHeld(cs_wallet);
    LoadLockedCoin(output, persist);
    if (persist) {
        WalletBatch batch(GetDatabase());
        return batch.WriteLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet);
    auto locked_coin_it = m_locked_coins.find(output);
    if (locked_coin_it != m_locked_coins.end()) {
        bool persisted = locked_coin_it->second;
        m_locked_coins.erase(locked_coin_it);
        if (persisted) {
            WalletBatch batch(GetDatabase());
            return batch.EraseLockedUTXO(output);
        }
    }
    return true;
}

bool CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet);
    bool success = true;
    WalletBatch batch(GetDatabase());
    for (const auto& [coin, persistent] : m_locked_coins) {
        if (persistent) success = success && batch.EraseLockedUTXO(coin);
    }
    m_locked_coins.clear();
    for (const auto& [output_id, persistent] : m_locked_mweb_coins) {
        if (persistent) success = success && batch.EraseLockedUTXO(output_id);
    }
    m_locked_mweb_coins.clear();
    return success;
}

bool CWallet::IsLockedCoin(const COutPoint& output) const
{
    AssertLockHeld(cs_wallet);
    return m_locked_coins.contains(output);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [coin, _] : m_locked_coins) {
        vOutpts.push_back(coin);
    }
}

void CWallet::LoadLockedCoin(const mw::Hash& output_id, bool persistent)
{
    AssertLockHeld(cs_wallet);
    m_locked_mweb_coins.emplace(output_id, persistent);
}

bool CWallet::LockCoin(const mw::Hash& output_id, bool persist)
{
    AssertLockHeld(cs_wallet);
    LoadLockedCoin(output_id, persist);
    if (persist) {
        WalletBatch batch(GetDatabase());
        return batch.WriteLockedUTXO(output_id);
    }
    return true;
}

bool CWallet::UnlockCoin(const mw::Hash& output_id)
{
    AssertLockHeld(cs_wallet);
    auto locked_coin_it = m_locked_mweb_coins.find(output_id);
    if (locked_coin_it != m_locked_mweb_coins.end()) {
        bool persisted = locked_coin_it->second;
        m_locked_mweb_coins.erase(locked_coin_it);
        if (persisted) {
            WalletBatch batch(GetDatabase());
            return batch.EraseLockedUTXO(output_id);
        }
    }
    return true;
}

bool CWallet::IsLockedCoin(const mw::Hash& output_id) const
{
    AssertLockHeld(cs_wallet);
    return m_locked_mweb_coins.contains(output_id);
}

void CWallet::ListLockedCoins(std::vector<mw::Hash>& output_ids) const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [output_id, _] : m_locked_mweb_coins) {
        output_ids.push_back(output_id);
    }
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a transaction during a rescanning process, assign all its
 *   (not already known) transactions' timestamps to the block time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
uint64_t CWallet::ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const
{
    std::optional<uint256> block_hash;
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        block_hash = conf->confirmed_block_hash;
    } else if (auto* conf = wtx.state<TxStateBlockConflicted>()) {
        block_hash = conf->conflicting_block_hash;
    }

    uint64_t nTimeSmart = wtx.nTimeReceived;
    if (block_hash) {
        int64_t blocktime;
        int64_t block_max_time;
        if (chain().findBlock(*block_hash, FoundBlock().time(blocktime).maxTime(block_max_time))) {
            if (rescanning_old_block) {
                nTimeSmart = block_max_time;
            } else {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;

                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300 * 1000;
                const TxItems& txOrdered = wtxOrdered;
                for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                    CWalletTx* const pwtx = it->second;
                    if (pwtx == &wtx) {
                        continue;
                    }
                    int64_t nSmartTime;
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow) {
                            latestNow = nSmartTime;
                        }
                        break;
                    }
                }

                nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), block_hash->ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used)
{
    if (std::get_if<CNoDestination>(&dest))
        return false;

    if (!used) {
        if (auto* data{common::FindKey(m_address_book, dest)}) data->previously_spent = false;
        return batch.WriteAddressPreviouslySpent(dest, false);
    }

    LoadAddressPreviouslySpent(dest);
    return batch.WriteAddressPreviouslySpent(dest, true);
}

void CWallet::LoadAddressPreviouslySpent(const CTxDestination& dest)
{
    m_address_book[dest].previously_spent = true;
}

void CWallet::LoadAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& request)
{
    m_address_book[dest].receive_requests[id] = request;
}

bool CWallet::IsAddressPreviouslySpent(const CTxDestination& dest) const
{
    if (auto* data{common::FindKey(m_address_book, dest)}) return data->previously_spent;
    return false;
}

std::vector<std::string> CWallet::GetAddressReceiveRequests() const
{
    std::vector<std::string> values;
    for (const auto& [dest, entry] : m_address_book) {
        for (const auto& [id, request] : entry.receive_requests) {
            values.emplace_back(request);
        }
    }
    return values;
}

bool CWallet::SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value)
{
    if (!batch.WriteAddressReceiveRequest(dest, id, value)) return false;
    m_address_book[dest].receive_requests[id] = value;
    return true;
}

bool CWallet::EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id)
{
    if (!batch.EraseAddressReceiveRequest(dest, id)) return false;
    m_address_book[dest].receive_requests.erase(id);
    return true;
}

util::Result<fs::path> GetWalletPath(const std::string& name)
{
    const fs::path name_path = fs::PathFromString(name);

    // 'name' must be a normalized path, i.e. no . or .. except at the root
    if (name_path != name_path.lexically_normal()) {
        return util::Error{Untranslated("Wallet name given as a path must be normalized")};
    }

    // 'name' cannot begin with ./ or ../
    if (!name_path.empty() && (*name_path.begin() == fs::PathFromString(".") || *name_path.begin() == fs::PathFromString(".."))) {
        return util::Error{Untranslated("Wallet name given as a relative path cannot begin with ./ or ../, for wallets not in the walletdir, please use an absolute path.")};
    }

    // Disallow path at root
    if (name_path.has_root_path() && name_path.root_path() == name_path) {
        return util::Error{Untranslated("Wallet name cannot be the root path")};
    }

    // Do some checking on wallet path. It should be either a:
    //
    // 1. Path where a directory can be created.
    // 2. Path to an existing directory.
    // 3. Path to a symlink to a directory.
    // 4. For backwards compatibility, the name of a data file in -walletdir.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), name_path);
    fs::file_type path_type = fs::symlink_status(wallet_path).type();
    if (!(path_type == fs::file_type::not_found || path_type == fs::file_type::directory ||
          (path_type == fs::file_type::symlink && fs::is_directory(wallet_path)) ||
          (path_type == fs::file_type::regular && name_path.filename() == name_path))) {
        return util::Error{Untranslated(strprintf(
              "Invalid -wallet path '%s'. -wallet path should point to a directory where wallet.dat and "
              "database/log.?????????? files can be stored, a location where such a directory could be created, "
              "or (for backwards compatibility) the name of an existing data file in -walletdir (%s)",
              name, fs::quoted(fs::PathToString(GetWalletDir()))))};
    }
    return wallet_path;
}

std::unique_ptr<WalletDatabase> MakeWalletDatabase(const std::string& name, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error_string)
{
    const auto& wallet_path = GetWalletPath(name);
    if (!wallet_path) {
        error_string = util::ErrorString(wallet_path);
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    return MakeDatabase(*wallet_path, options, status, error_string);
}

bool CWallet::LoadWalletArgs(std::shared_ptr<CWallet> wallet, const WalletContext& context, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    const ArgsManager& args = *Assert(context.args);

    if (!args.GetArg("-addresstype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-addresstype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown address type '%s'"), args.GetArg("-addresstype", ""));
            return false;
        }
        wallet->m_default_address_type = parsed.value();
    }

    if (!args.GetArg("-changetype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-changetype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown change type '%s'"), args.GetArg("-changetype", ""));
            return false;
        }
        wallet->m_default_change_type = parsed.value();
    }

    if (const auto arg{args.GetArg("-mintxfee")}) {
        std::optional<CAmount> min_tx_fee = ParseMoney(*arg);
        if (!min_tx_fee) {
            error = AmountErrMsg("mintxfee", *arg);
            return false;
        } else if (min_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-mintxfee") + Untranslated(" ") +
                               _("This is the minimum transaction fee you pay on every transaction."));
        }

        wallet->m_min_fee = CFeeRate{min_tx_fee.value()};
    }

    if (const auto arg{args.GetArg("-maxapsfee")}) {
        const std::string& max_aps_fee{*arg};
        if (max_aps_fee == "-1") {
            wallet->m_max_aps_fee = -1;
        } else if (std::optional<CAmount> max_fee = ParseMoney(max_aps_fee)) {
            if (max_fee.value() > HIGH_APS_FEE) {
                warnings.push_back(AmountHighWarn("-maxapsfee") + Untranslated(" ") +
                                  _("This is the maximum transaction fee you pay (in addition to the normal fee) to prioritize partial spend avoidance over regular coin selection."));
            }
            wallet->m_max_aps_fee = max_fee.value();
        } else {
            error = AmountErrMsg("maxapsfee", max_aps_fee);
            return false;
        }
    }

    if (const auto arg{args.GetArg("-fallbackfee")}) {
        std::optional<CAmount> fallback_fee = ParseMoney(*arg);
        if (!fallback_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-fallbackfee", *arg);
            return false;
        } else if (fallback_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-fallbackfee") + Untranslated(" ") +
                               _("This is the transaction fee you may pay when fee estimates are not available."));
        }
        wallet->m_fallback_fee = CFeeRate{fallback_fee.value()};
    }

    // Disable fallback fee in case value was set to 0, enable if non-null value
    wallet->m_allow_fallback_fee = wallet->m_fallback_fee.GetFeePerK() != 0;

    if (const auto arg{args.GetArg("-discardfee")}) {
        std::optional<CAmount> discard_fee = ParseMoney(*arg);
        if (!discard_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-discardfee", *arg);
            return false;
        } else if (discard_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-discardfee") + Untranslated(" ") +
                               _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        wallet->m_discard_rate = CFeeRate{discard_fee.value()};
    }

    if (const auto arg{args.GetArg("-maxtxfee")}) {
        std::optional<CAmount> max_fee = ParseMoney(*arg);
        if (!max_fee) {
            error = AmountErrMsg("maxtxfee", *arg);
            return false;
        } else if (max_fee.value() > HIGH_MAX_TX_FEE) {
            warnings.push_back(strprintf(_("%s is set very high! Fees this large could be paid on a single transaction."), "-maxtxfee"));
        }

        if (chain && CFeeRate{max_fee.value(), 1000} < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                "-maxtxfee", *arg, chain->relayMinFee().ToString());
            return false;
        }

        wallet->m_default_max_tx_fee = max_fee.value();
    }

    if (const auto arg{args.GetArg("-consolidatefeerate")}) {
        if (std::optional<CAmount> consolidate_feerate = ParseMoney(*arg)) {
            wallet->m_consolidate_feerate = CFeeRate(*consolidate_feerate);
        } else {
            error = AmountErrMsg("consolidatefeerate", *arg);
            return false;
        }
    }

    if (chain && chain->relayMinFee().GetFeePerK() > HIGH_TX_FEE_PER_KB) {
        warnings.push_back(AmountHighWarn("-minrelaytxfee") + Untranslated(" ") +
                           _("The wallet will avoid paying less than the minimum relay fee."));
    }

    wallet->m_confirm_target = args.GetIntArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    wallet->m_spend_zero_conf_change = args.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    wallet->m_signal_rbf = DEFAULT_WALLET_RBF;
    if (auto value{args.GetBoolArg("-walletrbf")}) {
        warnings.push_back(_("-walletrbf is deprecated and will be fully removed in the next release."));
        wallet->m_signal_rbf = *value;
    }

    wallet->m_keypool_size = std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{1});
    wallet->m_mweb_keypool_size = std::max(args.GetIntArg("-mwebkeypool", wallet->m_keypool_size), int64_t{1});
    wallet->m_mweb_descriptor_threshold = std::max(args.GetIntArg("-mwebdescriptorthreshold", DEFAULT_KEYPOOL_SIZE), int64_t{0});
    wallet->m_mweb_descriptor_inactivity = std::max(args.GetIntArg("-mwebdescriptorinactivity", 90 * 24 * 60 * 60), int64_t{0});
    if (args.IsArgSet("-mwebdeterministicsenders")) {
        wallet->SetMWEBDeterministicSenders(args.GetBoolArg("-mwebdeterministicsenders", DEFAULT_MWEB_DETERMINISTIC_SENDERS));
    }
    wallet->m_notify_tx_changed_script = args.GetArg("-walletnotify", "");
    wallet->SetBroadcastTransactions(args.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    return true;
}

std::shared_ptr<CWallet> CWallet::CreateNew(WalletContext& context, const std::string& name, std::unique_ptr<WalletDatabase> database, uint64_t wallet_creation_flags, bool born_encrypted, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    const std::string& walletFile = database->Filename();

    const auto start{SteadyClock::now()};
    // TODO: Can't use std::make_shared because we need a custom deleter but
    // should be possible to use std::allocate_shared.
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, name, std::move(database)), FlushAndDeleteWallet);

    if (!LoadWalletArgs(walletInstance, context, error, warnings)) {
        return nullptr;
    }

    // Initialize version key.
    if(!WalletBatch(walletInstance->GetDatabase()).WriteVersion(CLIENT_VERSION)) {
        error = strprintf(_("Error creating %s: Could not write version metadata."), walletFile);
        return nullptr;
    }
    {
        LOCK(walletInstance->cs_wallet);

        // Init with passed flags.
        // Always set the cache upgrade flag as this feature is supported from the beginning.
        walletInstance->InitWalletFlags(wallet_creation_flags | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);

        // Only descriptor wallets can be created
        assert(walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

        // Born encrypted wallets will have their keys generated later
        if (!born_encrypted) {
            walletInstance->SetupWalletGeneration();
        }

        if (chain) {
            std::optional<int> tip_height = chain->getHeight();
            if (tip_height) {
                walletInstance->SetLastBlockProcessed(*tip_height, chain->getBlockHash(*tip_height));
            }
        }
    }

    walletInstance->WalletLogPrintf("Wallet completed creation in %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    if (chain && !AttachChain(walletInstance, *chain, /*rescan_required=*/false, error, warnings)) {
        walletInstance->DisconnectChainNotifications();
        return nullptr;
    }

    return walletInstance;
}

std::shared_ptr<CWallet> CWallet::LoadExisting(WalletContext& context, const std::string& name, std::unique_ptr<WalletDatabase> database, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    const std::string& walletFile = database->Filename();

    const auto start{SteadyClock::now()};
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, name, std::move(database)), FlushAndDeleteWallet);

    if (!LoadWalletArgs(walletInstance, context, error, warnings)) {
        return nullptr;
    }

    // Load wallet
    auto nLoadWalletRet = walletInstance->PopulateWalletFromDB(error, warnings);
    bool rescan_required = nLoadWalletRet == DBErrors::NEED_RESCAN;
    if (nLoadWalletRet != DBErrors::LOAD_OK && nLoadWalletRet != DBErrors::NONCRITICAL_ERROR && !rescan_required) {
        return nullptr;
    }

    if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
            if (spk_man->HavePrivateKeys()) {
                warnings.push_back(strprintf(_("Warning: Private keys detected in wallet {%s} with disabled private keys"), walletFile));
                break;
            }
        }
    }

    walletInstance->WalletLogPrintf("Wallet completed loading in %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    if (chain && !AttachChain(walletInstance, *chain, rescan_required, error, warnings)) {
        walletInstance->DisconnectChainNotifications();
        return nullptr;
    }

    WITH_LOCK(walletInstance->cs_wallet, walletInstance->LogStats());

    return walletInstance;
}


bool CWallet::AttachChain(const std::shared_ptr<CWallet>& walletInstance, interfaces::Chain& chain, const bool rescan_required, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    LOCK(walletInstance->cs_wallet);
    // allow setting the chain if it hasn't been set already but prevent changing it
    assert(!walletInstance->m_chain || walletInstance->m_chain == &chain);
    walletInstance->m_chain = &chain;

    // Unless allowed, ensure wallet files are not reused across chains:
    if (!gArgs.GetBoolArg("-walletcrosschain", DEFAULT_WALLETCROSSCHAIN)) {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator) && locator.vHave.size() > 0 && chain.getHeight()) {
            // Wallet is assumed to be from another chain, if genesis block in the active
            // chain differs from the genesis block known to the wallet.
            if (chain.getBlockHash(0) != locator.vHave.back()) {
                error = Untranslated("Wallet files should not be reused across chains. Restart bitcoind with -walletcrosschain to override.");
                return false;
            }
        }
    }

    // Register wallet with validationinterface. It's done before rescan to avoid
    // missing block connections during the rescan.
    // Because of the wallet lock being held, block connection notifications are going to
    // be pending on the validation-side until lock release. Blocks that are connected while the
    // rescan is ongoing will not be processed in the rescan but with the block connected notifications,
    // so the wallet will only be completeley synced after the notifications delivery.
    walletInstance->m_chain_notifications_handler = walletInstance->chain().handleNotifications(walletInstance);

    // If rescan_required = true, rescan_height remains equal to 0
    int rescan_height = 0;
    if (!rescan_required)
    {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator)) {
            if (const std::optional<int> fork_height = chain.findLocatorFork(locator)) {
                rescan_height = *fork_height;
            }
        }
    }

    const std::optional<int> tip_height = chain.getHeight();
    if (tip_height) {
        walletInstance->SetLastBlockProcessedInMem(*tip_height, chain.getBlockHash(*tip_height));
    } else {
        walletInstance->SetLastBlockProcessedInMem(-1, uint256());
    }

    if (tip_height && *tip_height != rescan_height)
    {
        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        std::optional<int64_t> time_first_key = walletInstance->m_birth_time.load();
        if (time_first_key) {
            FoundBlock found = FoundBlock().height(rescan_height);
            chain.findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height, found);
            if (!found.found) {
                // We were unable to find a block that had a time more recent than our earliest timestamp
                // or a height higher than the wallet was synced to, indicating that the wallet is newer than the
                // current chain tip. Skip rescanning in this case.
                rescan_height = *tip_height;
            }
        }

        // Technically we could execute the code below in any case, but performing the
        // `while` loop below can make startup very slow, so only check blocks on disk
        // if necessary.
        if (chain.havePruned() || chain.hasAssumedValidChain()) {
            int block_height = *tip_height;
            while (block_height > 0 && chain.haveBlockOnDisk(block_height - 1) && rescan_height != block_height) {
                --block_height;
            }

            if (rescan_height != block_height) {
                // Do not short-circuit on HasMWEBAccounts(): default descriptor wallets
                // always have MWEB accounts, and AttachChain has already set last-block
                // to tip in memory. Pre-snapshot L1 wallets must wait for background sync.
                // After a successful load, recover MWEB balance with mwebscanutxoset
                // (bare call uses the default import stealth-index window; or pass
                // acct_cksum + start/end indices for a wider range).
                error = chain.havePruned() ?
                     _("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of a pruned node)") :
                     strprintf(_(
                        "Error loading wallet. Wallet requires blocks to be downloaded, "
                        "and software does not currently support loading wallets while "
                        "blocks are being downloaded out of order when using assumeutxo "
                        "snapshots. Wallet should be able to load successfully after "
                        "node sync reaches height %s"), block_height);
                return false;
            }
        }

        chain.initMessage(_("Rescanning…"));
        walletInstance->WalletLogPrintf("Rescanning last %i blocks (from block %i)...\n", *tip_height - rescan_height, rescan_height);

        {
            WalletRescanReserver reserver(*walletInstance);
            if (!reserver.reserve()) {
                error = _("Failed to acquire rescan reserver during wallet initialization");
                return false;
            }
            ScanResult scan_res = walletInstance->ScanForWalletTransactions(chain.getBlockHash(rescan_height), rescan_height, /*max_height=*/{}, reserver, /*save_progress=*/true);
            if (ScanResult::SUCCESS != scan_res.status) {
                error = _("Failed to rescan the wallet during initialization");
                return false;
            }
            // Set and update the best block record
            // Set last block scanned as the last block processed as it may be different in case of a reorg.
            // Also save the best block locator because rescanning only updates it intermittently.
            walletInstance->SetLastBlockProcessed(*scan_res.last_scanned_height, scan_res.last_scanned_block);
        }
    }

    return true;
}

const CAddressBookData* CWallet::FindAddressBookEntry(const CTxDestination& dest, bool allow_change) const
{
    const auto& address_book_it = m_address_book.find(dest);
    if (address_book_it == m_address_book.end()) return nullptr;
    if ((!allow_change) && address_book_it->second.IsChange()) {
        return nullptr;
    }
    return &address_book_it->second;
}

void CWallet::postInitProcess()
{
    {
        // Hold cs_wallet before TopUp() opens a database transaction. Every
        // other TopUp() caller acquires cs_wallet first; taking the database
        // write semaphore before cs_wallet here can deadlock against wallet
        // notifications (e.g. mempool transactions loaded during startup).
        LOCK(cs_wallet);
        for (DescriptorScriptPubKeyMan* spk_man : GetMWEBAccountScriptPubKeyMans()) {
            spk_man->LoadMWEBKeychain();
            spk_man->TopUp();
        }
    }
    GetMWWallet()->UpgradeCoins();

    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_NO_BROADCAST, /*force=*/true);

    // Update wallet transactions with current mempool transactions.
    WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
}

bool CWallet::BackupWallet(const std::string& strDest) const
{
    WITH_LOCK(cs_wallet, WriteBestBlock());
    return GetDatabase().Backup(strDest);
}

int CWallet::GetTxDepthInMainChain(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        assert(conf->confirmed_block_height >= 0);
        return GetLastBlockHeight() - conf->confirmed_block_height + 1;
    } else if (auto* conf = wtx.state<TxStateBlockConflicted>()) {
        assert(conf->conflicting_block_height >= 0);
        return -1 * (GetLastBlockHeight() - conf->conflicting_block_height + 1);
    } else {
        return 0;
    }
}

int CWallet::GetTxBlocksToMaturity(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    if (!wtx.IsCoinBase() && !wtx.GetTx()->IsHogEx()) {
        return 0;
    }
    int chain_depth = GetTxDepthInMainChain(wtx);
    assert(chain_depth >= 0);
    if (wtx.IsCoinBase()) {
        return std::max(0, (COINBASE_MATURITY + 1) - chain_depth);
    }
    return std::max(0, PEGOUT_MATURITY - chain_depth); // MWEB: spendable in the next block, as in Litecoin
}

bool CWallet::IsTxImmatureCoinBase(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    // note GetBlocksToMaturity is 0 for non-coinbase tx
    return GetTxBlocksToMaturity(wtx) > 0;
}

bool CWallet::IsLocked() const
{
    if (!HasEncryptionKeys()) {
        return false;
    }
    LOCK(cs_wallet);
    return vMasterKey.empty();
}

bool CWallet::Lock()
{
    if (!HasEncryptionKeys())
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size() * sizeof(decltype(vMasterKey)::value_type));
            vMasterKey.clear();
        }

        // MWEB: Keychains are read under cs_wallet by block scans
        for (DescriptorScriptPubKeyMan* mweb_spk : GetMWEBAccountScriptPubKeyMans()) {
            const mw::Keychain::Ptr& keychain = mweb_spk->GetMWEBKeychain();
            if (keychain) {
                keychain->Lock();
            }
        }
        GetMWWallet()->LockSpendMaterial();
    }

    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_wallet);
        for (const auto& spk_man_pair : m_spk_managers) {
            if (!spk_man_pair.second->CheckDecryptionKey(vMasterKeyIn)) {
                return false;
            }
        }
        vMasterKey = vMasterKeyIn;
        // MWEB: Keychains are read under cs_wallet by block scans. Every entry is checked before any writes.
        m_mweb_unlock_error = LoadMWEBKeychains();
        if (m_mweb_unlock_error) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size() * sizeof(decltype(vMasterKey)::value_type));
            vMasterKey.clear();
            for (DescriptorScriptPubKeyMan* mweb_spk : GetMWEBAccountScriptPubKeyMans()) {
                if (const mw::Keychain::Ptr& keychain = mweb_spk->GetMWEBKeychain()) {
                    keychain->Lock();
                }
            }
            GetMWWallet()->LockSpendMaterial();
            return false;
        }
        for (DescriptorScriptPubKeyMan* mweb_spk : GetMWEBAccountScriptPubKeyMans()) {
            mweb_spk->RestoreMWEBSpendKeysAfterUnlock();
            LOCK(mweb_spk->cs_desc_man);
            WalletBatch batch(GetDatabase());
            if (!mweb_spk->PersistMWEBLockedMaterial(batch)) {
                WalletLogPrintf("Warning: could not write the MWEB scan key record or descriptor cache of entry %s\n", mweb_spk->GetMWEBAccountChecksum());
            }
        }
        GetMWWallet()->UpgradeCoins();
    }
    NotifyStatusChanged(this);
    return true;
}

std::set<ScriptPubKeyMan*> CWallet::GetActiveScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            auto spk_man = GetScriptPubKeyMan(t, internal);
            if (spk_man) {
                spk_mans.insert(spk_man);
            }
        }
        if (auto spk_man = GetScriptPubKeyMan(OutputType::MWEB, internal)) {
            spk_mans.insert(spk_man);
        }
    }
    return spk_mans;
}

bool CWallet::IsActiveScriptPubKeyMan(const ScriptPubKeyMan& spkm) const
{
    for (const auto& [_, ext_spkm] : m_external_spk_managers) {
        if (ext_spkm == &spkm) return true;
    }
    for (const auto& [_, int_spkm] : m_internal_spk_managers) {
        if (int_spkm == &spkm) return true;
    }
    return false;
}

std::set<ScriptPubKeyMan*> CWallet::GetAllScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (const auto& spk_man_pair : m_spk_managers) {
        spk_mans.insert(spk_man_pair.second.get());
    }
    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const OutputType& type, bool internal) const
{
    const std::map<OutputType, ScriptPubKeyMan*>& spk_managers = internal ? m_internal_spk_managers : m_external_spk_managers;
    std::map<OutputType, ScriptPubKeyMan*>::const_iterator it = spk_managers.find(type);
    if (it == spk_managers.end()) {
        return nullptr;
    }
    return it->second;
}

std::set<ScriptPubKeyMan*> CWallet::GetScriptPubKeyMans(const CScript& script) const
{
    std::set<ScriptPubKeyMan*> spk_mans;

    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        spk_mans.insert(it->second.begin(), it->second.end());
    }
    SignatureData sigdata;
    Assume(std::all_of(spk_mans.begin(), spk_mans.end(), [&script, &sigdata](ScriptPubKeyMan* spkm) { return spkm->CanProvide(script, sigdata); }));

    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const uint256& id) const
{
    if (m_spk_managers.contains(id)) {
        return m_spk_managers.at(id).get();
    }
    return nullptr;
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script) const
{
    SignatureData sigdata;
    return GetSolvingProvider(script, sigdata);
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script, SignatureData& sigdata) const
{
    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        // All spkms for a given script must already be able to make a SigningProvider for the script, so just return the first one.
        Assume(it->second.at(0)->CanProvide(script, sigdata));
        return it->second.at(0)->GetSolvingProvider(script);
    }

    return nullptr;
}

std::vector<WalletDescriptor> CWallet::GetWalletDescriptors(const CScript& script) const
{
    std::vector<WalletDescriptor> descs;
    for (const auto spk_man: GetScriptPubKeyMans(script)) {
        if (const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
            LOCK(desc_spk_man->cs_desc_man);
            descs.push_back(desc_spk_man->GetWalletDescriptor());
        }
    }
    return descs;
}

LegacyDataSPKM* CWallet::GetLegacyDataSPKM() const
{
    if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return nullptr;
    }
    auto it = m_internal_spk_managers.find(OutputType::LEGACY);
    if (it == m_internal_spk_managers.end()) return nullptr;
    return dynamic_cast<LegacyDataSPKM*>(it->second);
}

void CWallet::AddScriptPubKeyMan(const uint256& id, std::unique_ptr<ScriptPubKeyMan> spkm_man)
{
    // Add spkm_man to m_spk_managers before calling any method
    // that might access it.
    const auto& spkm = m_spk_managers[id] = std::move(spkm_man);

    // Update birth time if needed
    MaybeUpdateBirthTime(spkm->GetTimeFirstKey());
}

LegacyDataSPKM* CWallet::GetOrCreateLegacyDataSPKM()
{
    SetupLegacyDataSPKM();
    return GetLegacyDataSPKM();
}

void CWallet::SetupLegacyDataSPKM()
{
    if (!m_internal_spk_managers.empty() || !m_external_spk_managers.empty() || !m_spk_managers.empty() || IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return;
    }

    Assert(m_database->Format() == "bdb_ro" || m_database->Format() == "sqlite-mock");
    std::unique_ptr<ScriptPubKeyMan> spk_manager = std::make_unique<LegacyDataSPKM>(*this);

    for (const auto& type : LEGACY_OUTPUT_TYPES) {
        m_internal_spk_managers[type] = spk_manager.get();
        m_external_spk_managers[type] = spk_manager.get();
    }
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
}

bool CWallet::WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const
{
    LOCK(cs_wallet);
    return cb(vMasterKey);
}

bool CWallet::HasEncryptionKeys() const
{
    return !mapMasterKeys.empty();
}

bool CWallet::HaveCryptedKeys() const
{
    for (const auto& spkm : GetAllScriptPubKeyMans()) {
        if (spkm->HaveCryptedKeys()) return true;
    }
    return false;
}

void CWallet::ConnectScriptPubKeyManNotifiers()
{
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        spk_man->NotifyCanGetAddressesChanged.connect([this] {
            NotifyCanGetAddressesChanged();
        });
        spk_man->NotifyFirstKeyTimeChanged.connect([this](const ScriptPubKeyMan*, int64_t time) {
            MaybeUpdateBirthTime(time);
        });
    }
}

void CWallet::LoadDescriptorScriptPubKeyMan(uint256 id, WalletDescriptor& desc, const KeyMap& keys, const CryptedKeyMap& ckeys)
{
    std::unique_ptr<DescriptorScriptPubKeyMan> spk_manager;
    if (IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        spk_manager = ExternalSignerScriptPubKeyMan::LoadFromStorage(*this, id, desc, m_keypool_size, keys, ckeys);
    } else {
        spk_manager = DescriptorScriptPubKeyMan::LoadFromStorage(*this, id, desc, m_keypool_size, keys, ckeys);
    }
    AddScriptPubKeyMan(id, std::move(spk_manager));
}

DescriptorScriptPubKeyMan& CWallet::SetupDescriptorScriptPubKeyMan(WalletBatch& batch, const CExtKey& master_key, const OutputType& output_type, bool internal)
{
    AssertLockHeld(cs_wallet);
    if (IsLocked()) {
        throw std::runtime_error(std::string(__func__) + ": Wallet is locked, cannot setup new descriptors");
    }
    auto spk_manager = DescriptorScriptPubKeyMan::GenerateNewSingleSig(*this, batch, m_keypool_size, master_key, output_type, internal);
    DescriptorScriptPubKeyMan* out = spk_manager.get();
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
    AddActiveScriptPubKeyManWithDb(batch, id, output_type, internal);
    return *out;
}

void CWallet::SetupDescriptorScriptPubKeyMans(WalletBatch& batch, const CExtKey& master_key)
{
    AssertLockHeld(cs_wallet);
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            SetupDescriptorScriptPubKeyMan(batch, master_key, t, internal);
        }
        if (!internal) {
            SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::MWEB, false);
        }
    }
}

void CWallet::SetupOwnDescriptorScriptPubKeyMans(WalletBatch& batch)
{
    AssertLockHeld(cs_wallet);
    assert(!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    // Make a seed
    CKey seed_key = GenerateRandomKey();
    CPubKey seed = seed_key.GetPubKey();
    assert(seed_key.VerifyPubKey(seed));

    // Get the extended key
    CExtKey master_key;
    master_key.SetSeed(seed_key);

    SetupDescriptorScriptPubKeyMans(batch, master_key);
}

void CWallet::SetupDescriptorScriptPubKeyMans()
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        if (!RunWithinTxn(GetDatabase(), /*process_desc=*/"setup descriptors", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet){
            SetupOwnDescriptorScriptPubKeyMans(batch);
            return true;
        })) throw std::runtime_error("Error: cannot process db transaction for descriptors setup");
    } else {
        auto signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();
        if (!signer) throw std::runtime_error(util::ErrorString(signer).original);

        // TODO: add account parameter
        int account = 0;
        UniValue signer_res = signer->GetDescriptors(account);

        if (!signer_res.isObject()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) throw std::runtime_error("Error: cannot create db transaction for descriptors import");

        for (bool internal : {false, true}) {
            const UniValue& descriptor_vals = signer_res.find_value(internal ? "internal" : "receive");
            if (!descriptor_vals.isArray()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");
            for (const UniValue& desc_val : descriptor_vals.get_array().getValues()) {
                const std::string& desc_str = desc_val.getValStr();
                FlatSigningProvider keys;
                std::string desc_error;
                auto descs = Parse(desc_str, keys, desc_error, false);
                if (descs.empty()) {
                    throw std::runtime_error(std::string(__func__) + ": Invalid descriptor \"" + desc_str + "\" (" + desc_error + ")");
                }
                auto& desc = descs.at(0);
                if (!desc->GetOutputType()) {
                    continue;
                }
                OutputType t =  *desc->GetOutputType();
                if (t == OutputType::MWEB && (internal || desc->GetMWEBForm() != MWEBDescriptorForm::ACCOUNT)) {
                    // MWEB change goes to the active account; other MWEB forms make no addresses.
                    WalletLogPrintf("Skipping an external signer MWEB descriptor that is not a receive account\n");
                    continue;
                }
                auto spk_manager = ExternalSignerScriptPubKeyMan::CreateNew(*this, batch, m_keypool_size, std::move(desc), keys);
                uint256 id = spk_manager->GetID();
                AddScriptPubKeyMan(id, std::move(spk_manager));
                AddActiveScriptPubKeyManWithDb(batch, id, t, internal);
            }
        }

        // Ensure imported descriptors are committed to disk
        if (!batch.TxnCommit()) throw std::runtime_error("Error: cannot commit db transaction for descriptors import");
    }
}

void CWallet::SetupWalletGeneration()
{
    AssertLockHeld(cs_wallet);
    // Skip setup for non-external-signer wallets that are either blank
    // or have private keys disabled (not having private keys implies blank).
    if (!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER) &&
        (IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET) || IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS))) {
        return;
    }
    SetupDescriptorScriptPubKeyMans();
}

void CWallet::AddActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    WalletBatch batch(GetDatabase());
    return AddActiveScriptPubKeyManWithDb(batch, id, type, internal);
}

void CWallet::AddActiveScriptPubKeyManWithDb(WalletBatch& batch, uint256 id, OutputType type, bool internal)
{
    if (!batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(type), id, internal)) {
        throw std::runtime_error(std::string(__func__) + ": writing active ScriptPubKeyMan id failed");
    }
    LoadActiveScriptPubKeyMan(id, type, internal);
}

void CWallet::LoadActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    // Activating ScriptPubKeyManager for a given output and change type is incompatible with legacy wallets.
    // Legacy wallets have only one ScriptPubKeyManager and it's active for all output and change types.
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    WalletLogPrintf("Setting spkMan to active: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
    auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
    auto& spk_mans_other = internal ? m_external_spk_managers : m_internal_spk_managers;
    auto spk_man = m_spk_managers.at(id).get();
    if (auto* desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
        desc_spk->SetInternal(internal);
    }
    spk_mans[type] = spk_man;

    const auto it = spk_mans_other.find(type);
    if (it != spk_mans_other.end() && it->second == spk_man) {
        spk_mans_other.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

void CWallet::DeactivateScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    auto spk_man = GetScriptPubKeyMan(type, internal);
    if (spk_man != nullptr && spk_man->GetID() == id) {
        WalletLogPrintf("Deactivate spkMan: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
        WalletBatch batch(GetDatabase());
        if (!batch.EraseActiveScriptPubKeyMan(static_cast<uint8_t>(type), internal)) {
            throw std::runtime_error(std::string(__func__) + ": erasing active ScriptPubKeyMan id failed");
        }

        auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
        spk_mans.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

DescriptorScriptPubKeyMan* CWallet::GetDescriptorScriptPubKeyMan(const WalletDescriptor& desc) const
{
    auto spk_man_pair = std::find_if(m_spk_managers.begin(), m_spk_managers.end(), [&desc](const auto& item) {
        DescriptorScriptPubKeyMan* spk_manager = dynamic_cast<DescriptorScriptPubKeyMan*>(item.second.get());
        return spk_manager != nullptr && spk_manager->HasWalletDescriptor(desc);
    });

    if (spk_man_pair != m_spk_managers.end()) {
        return dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man_pair->second.get());
    }

    return nullptr;
}

std::optional<bool> CWallet::IsInternalScriptPubKeyMan(ScriptPubKeyMan* spk_man) const
{
    // only active ScriptPubKeyMan can be internal
    if (!GetActiveScriptPubKeyMans().contains(spk_man)) {
        return std::nullopt;
    }

    const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (!desc_spk_man) {
        throw std::runtime_error(std::string(__func__) + ": unexpected ScriptPubKeyMan type.");
    }

    LOCK(desc_spk_man->cs_desc_man);
    const auto& type = desc_spk_man->GetWalletDescriptor().descriptor->GetOutputType();
    assert(type.has_value());

    return GetScriptPubKeyMan(*type, /* internal= */ true) == desc_spk_man;
}

util::Result<std::reference_wrapper<DescriptorScriptPubKeyMan>> CWallet::AddWalletDescriptor(WalletDescriptor& desc, const FlatSigningProvider& signing_provider, const std::string& label, bool internal)
{
    AssertLockHeld(cs_wallet);

    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    auto spk_man = GetDescriptorScriptPubKeyMan(desc);
    if (spk_man) {
        WalletLogPrintf("Update existing descriptor: %s\n", desc.descriptor->ToString());
        if (auto spkm_res = spk_man->UpdateWalletDescriptor(desc, signing_provider); !spkm_res) {
            return util::Error{util::ErrorString(spkm_res)};
        }
    } else {
        auto new_spk_man = DescriptorScriptPubKeyMan::CreateFromImport(*this, desc, m_keypool_size, signing_provider, internal);
        spk_man = new_spk_man.get();

        // Save the descriptor to memory
        uint256 id = new_spk_man->GetID();
        AddScriptPubKeyMan(id, std::move(new_spk_man));

        // Write the existing cache to disk
        WalletBatch batch(GetDatabase());
        if (!batch.WriteDescriptorCacheItems(id, desc.cache)) {
            return util::Error{_("Unable to write descriptor cache")};
        }
    }

    // Apply the label if necessary
    // Note: we disable labels for descriptors that are ranged or that don't produce output scripts (i.e. unused())
    if (!desc.descriptor->IsRange() && desc.descriptor->HasScripts()) {
        auto script_pub_keys = spk_man->GetScriptPubKeys();
        if (script_pub_keys.empty()) {
            return util::Error{_("Could not generate scriptPubKeys (cache is empty)")};
        }

        if (!internal) {
            for (const auto& script : script_pub_keys) {
                CTxDestination dest;
                if (ExtractDestination(script, dest)) {
                    SetAddressBook(dest, label, AddressPurpose::RECEIVE);
                }
            }
        }
    }

    // Save the descriptor to DB
    spk_man->WriteDescriptor();

    // Break balance caches so that outputs that are now IsMine in already known txs will be included in the balance
    MarkDirty();

    return std::reference_wrapper(*spk_man);
}

bool CWallet::MigrateToSQLite(bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    WalletLogPrintf("Migrating wallet storage database from BerkeleyDB to SQLite.\n");

    if (m_database->Format() == "sqlite") {
        error = _("Error: This wallet already uses SQLite");
        return false;
    }

    // Get all of the records for DB type migration
    std::unique_ptr<DatabaseBatch> batch = m_database->MakeBatch();
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    std::vector<std::pair<SerializeData, SerializeData>> records;
    if (!cursor) {
        error = _("Error: Unable to begin reading all records in the database");
        return false;
    }
    DatabaseCursor::Status status = DatabaseCursor::Status::FAIL;
    while (true) {
        DataStream ss_key{};
        DataStream ss_value{};
        status = cursor->Next(ss_key, ss_value);
        if (status != DatabaseCursor::Status::MORE) {
            break;
        }
        SerializeData key(ss_key.begin(), ss_key.end());
        SerializeData value(ss_value.begin(), ss_value.end());
        records.emplace_back(key, value);
    }
    cursor.reset();
    batch.reset();
    if (status != DatabaseCursor::Status::DONE) {
        error = _("Error: Unable to read all records in the database");
        return false;
    }

    // Close this database and delete the file
    fs::path db_path = fs::PathFromString(m_database->Filename());
    m_database->Close();
    fs::remove(db_path);

    // Generate the path for the location of the migrated wallet
    // Wallets that are plain files rather than wallet directories will be migrated to be wallet directories.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(m_name));

    // Make new DB
    DatabaseOptions opts;
    opts.require_create = true;
    opts.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus db_status;
    std::unique_ptr<WalletDatabase> new_db = MakeDatabase(wallet_path, opts, db_status, error);
    assert(new_db); // This is to prevent doing anything further with this wallet. The original file was deleted, but a backup exists.
    m_database.reset();
    m_database = std::move(new_db);

    // Write existing records into the new DB
    batch = m_database->MakeBatch();
    bool began = batch->TxnBegin();
    assert(began); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    for (const auto& [key, value] : records) {
        if (!batch->Write(std::span{key}, std::span{value})) {
            batch->TxnAbort();
            m_database->Close();
            fs::remove(m_database->Filename());
            assert(false); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
        }
    }
    bool committed = batch->TxnCommit();
    assert(committed); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    return true;
}

std::optional<MigrationData> CWallet::GetDescriptorsForLegacy(bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);

    LegacyDataSPKM* legacy_spkm = GetLegacyDataSPKM();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        error = Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"));
        return std::nullopt;
    }

    std::optional<MigrationData> res = legacy_spkm->MigrateToDescriptor();
    if (res == std::nullopt) {
        error = _("Error: Unable to produce descriptors for this legacy wallet. Make sure to provide the wallet's passphrase if it is encrypted.");
        return std::nullopt;
    }
    return res;
}

util::Result<void> CWallet::ApplyMigrationData(WalletBatch& local_wallet_batch, MigrationData& data)
{
    AssertLockHeld(cs_wallet);

    LegacyDataSPKM* legacy_spkm = GetLegacyDataSPKM();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        return util::Error{Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"))};
    }

    // Note: when the legacy wallet has no spendable scripts, it must be empty at the end of the process.
    bool has_spendable_material = !data.desc_spkms.empty() || data.master_key.key.IsValid();

    // Get all invalid or non-watched scripts that will not be migrated
    std::set<CTxDestination> not_migrated_dests;
    for (const auto& script : legacy_spkm->GetNotMineScriptPubKeys()) {
        CTxDestination dest;
        if (ExtractDestination(script, dest)) not_migrated_dests.emplace(dest);
    }

    // When the legacy wallet has no spendable scripts, the main wallet will be empty, leaving its script cache empty as well.
    // The watch-only and/or solvable wallet(s) will contain the scripts in their respective caches.
    if (!data.desc_spkms.empty()) Assume(!m_cached_spks.empty());
    if (!data.watch_descs.empty()) Assume(!data.watchonly_wallet->m_cached_spks.empty());
    if (!data.solvable_descs.empty()) Assume(!data.solvable_wallet->m_cached_spks.empty());

    for (auto& desc_spkm : data.desc_spkms) {
        if (m_spk_managers.contains(desc_spkm->GetID())) {
            return util::Error{_("Error: Duplicate descriptors created during migration. Your wallet may be corrupted.")};
        }
        uint256 id = desc_spkm->GetID();
        AddScriptPubKeyMan(id, std::move(desc_spkm));
    }

    // Remove the LegacyDataSPKM's records from disk
    if (!legacy_spkm->DeleteRecordsWithDB(local_wallet_batch)) {
        return util::Error{_("Error: cannot remove legacy wallet records")};
    }

    // Remove the LegacyDataSPKM from memory
    m_spk_managers.erase(legacy_spkm->GetID());
    m_external_spk_managers.clear();
    m_internal_spk_managers.clear();

    // Setup new descriptors (only if we are migrating any key material)
    SetWalletFlagWithDB(local_wallet_batch, WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    if (has_spendable_material && !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Use the existing master key if we have it
        if (data.master_key.key.IsValid()) {
            SetupDescriptorScriptPubKeyMans(local_wallet_batch, data.master_key);
        } else {
            // Setup with a new seed if we don't.
            SetupOwnDescriptorScriptPubKeyMans(local_wallet_batch);
        }
    }

    // Get best block locator so that we can copy it to the watchonly and solvables
    // Note: The best block locator was introduced in #152 so ancient wallets do not have it
    CBlockLocator best_block_locator;
    (void)local_wallet_batch.ReadBestBlock(best_block_locator);

    // Update m_txos to match the descriptors remaining in this wallet
    m_txos.clear();
    RefreshAllTXOs();

    // Check if the transactions in the wallet are still ours. Either they belong here, or they belong in the watchonly wallet.
    // We need to go through these in the tx insertion order so that lookups to spends works.
    std::vector<Txid> txids_to_delete;
    std::unique_ptr<WalletBatch> watchonly_batch;
    if (data.watchonly_wallet) {
        watchonly_batch = std::make_unique<WalletBatch>(data.watchonly_wallet->GetDatabase());
        if (!watchonly_batch->TxnBegin()) return util::Error{strprintf(_("Error: database transaction cannot be executed for wallet %s"), data.watchonly_wallet->GetName())};
        // Copy the next tx order pos to the watchonly wallet
        LOCK(data.watchonly_wallet->cs_wallet);
        data.watchonly_wallet->nOrderPosNext = nOrderPosNext;
        watchonly_batch->WriteOrderPosNext(data.watchonly_wallet->nOrderPosNext);
        // Write the locator record. An empty locator is valid and triggers rescan on load.
        if (!watchonly_batch->WriteBestBlock(best_block_locator)) {
            return util::Error{_("Error: Unable to write watchonly wallet best block locator record")};
        }
    }
    std::unique_ptr<WalletBatch> solvables_batch;
    if (data.solvable_wallet) {
        solvables_batch = std::make_unique<WalletBatch>(data.solvable_wallet->GetDatabase());
        if (!solvables_batch->TxnBegin()) return util::Error{strprintf(_("Error: database transaction cannot be executed for wallet %s"), data.solvable_wallet->GetName())};
        // Write the locator record. An empty locator is valid and triggers rescan on load.
        if (!solvables_batch->WriteBestBlock(best_block_locator)) {
            return util::Error{_("Error: Unable to write solvable wallet best block locator record")};
        }
    }
    for (const auto& [_pos, wtx] : wtxOrdered) {
        // Check it is the watchonly wallet's
        // solvable_wallet doesn't need to be checked because transactions for those scripts weren't being watched for
        bool is_mine = IsMine(*wtx->GetTx()) || IsFromMe(*wtx->GetTx());
        if (data.watchonly_wallet) {
            LOCK(data.watchonly_wallet->cs_wallet);
            if (data.watchonly_wallet->IsMine(*wtx->GetTx()) || data.watchonly_wallet->IsFromMe(*wtx->GetTx())) {
                // Add to watchonly wallet
                const Txid& hash = wtx->GetHash();
                DataStream wtx_ser;
                wtx_ser << *wtx;
                CWalletTx copy_wtx(deserialize, wtx_ser, wtx->GetTxs());
                if (!data.watchonly_wallet->LoadToWallet(std::move(copy_wtx))) {
                    return util::Error{strprintf(_("Error: Could not add watchonly tx %s to watchonly wallet"), wtx->GetHash().GetHex())};
                }
                watchonly_batch->WriteFullTx(data.watchonly_wallet->mapWallet.at(hash));
                // Mark as to remove from the migrated wallet only if it does not also belong to it
                if (!is_mine) {
                    txids_to_delete.push_back(hash);
                    continue;
                }
            }
        }
        if (!is_mine) {
            // Both not ours and not in the watchonly wallet
            return util::Error{strprintf(_("Error: Transaction %s in wallet cannot be identified to belong to migrated wallets"), wtx->GetHash().GetHex())};
        }
        // Rewrite the transaction so that anything that may have changed about it in memory also persists to disk
        local_wallet_batch.WriteTxMetadata(*wtx);
    }

    // Do the removes
    if (txids_to_delete.size() > 0) {
        if (auto res = RemoveTxs(local_wallet_batch, txids_to_delete); !res) {
            return util::Error{_("Error: Could not delete watchonly transactions. ") + util::ErrorString(res)};
        }
    }

    // Pair external wallets with their corresponding db handler
    std::vector<std::pair<std::shared_ptr<CWallet>, std::unique_ptr<WalletBatch>>> wallets_vec;
    if (data.watchonly_wallet) wallets_vec.emplace_back(data.watchonly_wallet, std::move(watchonly_batch));
    if (data.solvable_wallet) wallets_vec.emplace_back(data.solvable_wallet, std::move(solvables_batch));

    // Write address book entry to disk
    auto func_store_addr = [](WalletBatch& batch, const CTxDestination& dest, const CAddressBookData& entry) {
        auto address{EncodeDestination(dest)};
        if (entry.purpose) batch.WritePurpose(address, PurposeToString(*entry.purpose));
        if (entry.label) batch.WriteName(address, *entry.label);
        for (const auto& [id, request] : entry.receive_requests) {
            batch.WriteAddressReceiveRequest(dest, id, request);
        }
        if (entry.previously_spent) batch.WriteAddressPreviouslySpent(dest, true);
    };

    // Check the address book data in the same way we did for transactions
    std::vector<CTxDestination> dests_to_delete;
    for (const auto& [dest, record] : m_address_book) {
        // Ensure "receive" entries that are no longer part of the original wallet are transferred to another wallet
        // Entries for everything else ("send") will be cloned to all wallets.
        bool require_transfer = record.purpose == AddressPurpose::RECEIVE && !IsMine(dest);
        bool copied = false;
        for (auto& [wallet, batch] : wallets_vec) {
            LOCK(wallet->cs_wallet);
            if (require_transfer && !wallet->IsMine(dest)) continue;

            // Copy the entire address book entry
            wallet->m_address_book[dest] = record;
            func_store_addr(*batch, dest, record);

            copied = true;
            // Only delete 'receive' records that are no longer part of the original wallet
            if (require_transfer) {
                dests_to_delete.push_back(dest);
                break;
            }
        }

        // Fail immediately if we ever found an entry that was ours and cannot be transferred
        // to any of the created wallets (watch-only, solvable).
        // Means that no inferred descriptor maps to the stored entry. Which mustn't happen.
        if (require_transfer && !copied) {

            // Skip invalid/non-watched scripts that will not be migrated
            if (not_migrated_dests.contains(dest)) {
                dests_to_delete.push_back(dest);
                continue;
            }

            return util::Error{_("Error: Address book data in wallet cannot be identified to belong to migrated wallets")};
        }
    }

    // Persist external wallets address book entries
    for (auto& [wallet, batch] : wallets_vec) {
        if (!batch->TxnCommit()) {
            return util::Error{strprintf(_("Error: Unable to write data to disk for wallet %s"), wallet->GetName())};
        }
    }

    // Remove the things to delete in this wallet
    if (dests_to_delete.size() > 0) {
        for (const auto& dest : dests_to_delete) {
            if (!DelAddressBookWithDB(local_wallet_batch, dest)) {
                return util::Error{_("Error: Unable to remove watchonly address book data")};
            }
        }
    }

    // If there was no key material in the main wallet, there should be no records on it anymore.
    // This wallet will be discarded at the end of the process. Only wallets that contain the
    // migrated records will be presented to the user.
    if (!has_spendable_material) {
        if (!m_address_book.empty()) return util::Error{_("Error: Not all address book records were migrated")};
        if (!mapWallet.empty()) return util::Error{_("Error: Not all transaction records were migrated")};
    }

    return {}; // all good
}

bool CWallet::CanGrindR() const
{
    return !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
}

// Returns wallet prefix for migration.
// Used to name the backup file and newly created wallets.
// E.g. a watch-only wallet is named "<prefix>_watchonly".
static std::string MigrationPrefixName(CWallet& wallet)
{
    const std::string& name{wallet.GetName()};
    return name.empty() ? "default_wallet" : name;
}

bool DoMigration(CWallet& wallet, WalletContext& context, bilingual_str& error, MigrationResult& res, const bool load_on_startup = true) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // Get all of the descriptors from the legacy wallet
    std::optional<MigrationData> data = wallet.GetDescriptorsForLegacy(error);
    if (data == std::nullopt) return false;

    // Create the watchonly and solvable wallets if necessary
    if (data->watch_descs.size() > 0 || data->solvable_descs.size() > 0) {
        DatabaseOptions options;
        options.require_existing = false;
        options.require_create = true;
        options.require_format = DatabaseFormat::SQLITE;

        WalletContext empty_context;
        empty_context.args = context.args;

        // Make the wallets
        options.create_flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET | WALLET_FLAG_DESCRIPTORS;
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            options.create_flags |= WALLET_FLAG_AVOID_REUSE;
        }
        if (wallet.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
            options.create_flags |= WALLET_FLAG_KEY_ORIGIN_METADATA;
        }
        if (data->watch_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the watched scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = MigrationPrefixName(wallet) + "_watchonly";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->watchonly_wallet = CWallet::CreateNew(empty_context, wallet_name, std::move(database), options.create_flags, /*born_encrypted=*/false, error, warnings);
            if (!data->watchonly_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.watchonly_wallet = data->watchonly_wallet;
            LOCK(data->watchonly_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->watch_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, parse_err, /*require_checksum=*/ true);
                // LegacyDataSPKM should not produce invalid, multipath, or ranged watch-only descriptors.
                assert(descs.size() == 1);
                assert(!descs.at(0)->IsRange());

                // Add to the wallet
                WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);
                if (auto spkm_res = data->watchonly_wallet->AddWalletDescriptor(w_desc, keys, "", false); !spkm_res) {
                    throw std::runtime_error(util::ErrorString(spkm_res).original);
                }
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, load_on_startup, warnings);
        }
        if (data->solvable_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the unwatched solvable scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = MigrationPrefixName(wallet) + "_solvables";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->solvable_wallet = CWallet::CreateNew(empty_context, wallet_name, std::move(database), options.create_flags, /*born_encrypted=*/false, error, warnings);
            if (!data->solvable_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.solvables_wallet = data->solvable_wallet;
            LOCK(data->solvable_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->solvable_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, parse_err, /*require_checksum=*/ true);
                // LegacyDataSPKM should not produce invalid, multipath, or ranged watch-only descriptors.
                assert(descs.size() == 1);
                assert(!descs.at(0)->IsRange());

                // Add to the wallet
                WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);
                if (auto spkm_res = data->solvable_wallet->AddWalletDescriptor(w_desc, keys, "", false); !spkm_res) {
                    throw std::runtime_error(util::ErrorString(spkm_res).original);
                }
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, load_on_startup, warnings);
        }
    }

    // Add the descriptors to the wallet, remove the LegacyDataSPKM, and clean up transactions and address book data
    return RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"apply migration process", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet){
        if (auto res_migration = wallet.ApplyMigrationData(batch, *data); !res_migration) {
            error = util::ErrorString(res_migration);
            return false;
        }
        wallet.WalletLogPrintf("Wallet migration complete.\n");
        return true;
    });
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(const std::string& wallet_name, const SecureString& passphrase, WalletContext& context, bool load_wallet)
{
    std::vector<bilingual_str> warnings;
    bilingual_str error;

    // The only kind of wallets that could be loaded are descriptor ones, which don't need to be migrated.
    if (auto wallet = GetWallet(context, wallet_name)) {
        assert(wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        return util::Error{_("Error: This wallet is already a descriptor wallet")};
    } else {
        // Check if the wallet is BDB
        const auto& wallet_path = GetWalletPath(wallet_name);
        if (!wallet_path) {
            return util::Error{util::ErrorString(wallet_path)};
        }
        if (!fs::exists(*wallet_path)) {
            return util::Error{_("Error: Wallet does not exist")};
        }
        if (!IsBDBFile(BDBDataFile(*wallet_path))) {
            return util::Error{_("Error: This wallet is already a descriptor wallet")};
        }
    }

    // Load the wallet but only in the context of this function.
    // No signals should be connected nor should anything else be aware of this wallet
    WalletContext empty_context;
    empty_context.args = context.args;
    DatabaseOptions options;
    options.require_existing = true;
    options.require_format = DatabaseFormat::BERKELEY_RO;
    DatabaseStatus status;
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
    if (!database) {
        return util::Error{Untranslated("Wallet file verification failed.") + Untranslated(" ") + error};
    }

    // Make the local wallet
    std::shared_ptr<CWallet> local_wallet = CWallet::LoadExisting(empty_context, wallet_name, std::move(database), error, warnings);
    if (!local_wallet) {
        return util::Error{Untranslated("Wallet loading failed.") + Untranslated(" ") + error};
    }

    return MigrateLegacyToDescriptor(std::move(local_wallet), passphrase, context, load_wallet);
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(std::shared_ptr<CWallet> local_wallet, const SecureString& passphrase, WalletContext& context, bool load_wallet)
{
    MigrationResult res;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    DatabaseOptions options;
    options.require_existing = true;
    DatabaseStatus status;

    const std::string wallet_name = local_wallet->GetName();

    // Before anything else, check if there is something to migrate.
    if (local_wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return util::Error{_("Error: This wallet is already a descriptor wallet")};
    }

    // Make a backup of the DB in the wallet's directory with a unique filename
    // using the wallet name and current timestamp. The backup filename is based
    // on the name of the parent directory containing the wallet data in most
    // cases, but in the case where the wallet name is a path to a data file,
    // the name of the data file is used, and in the case where the wallet name
    // is blank, "default_wallet" is used.
    const std::string backup_prefix = wallet_name.empty() ? MigrationPrefixName(*local_wallet) : [&] {
        // fs::weakly_canonical resolves relative specifiers and remove trailing slashes.
        const auto legacy_wallet_path = fs::weakly_canonical(GetWalletDir() / fs::PathFromString(wallet_name));
        return fs::PathToString(legacy_wallet_path.filename());
    }();

    fs::path backup_filename = fs::PathFromString(strprintf("%s_%d.legacy.bak", backup_prefix, GetTime()));
    fs::path backup_path = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
    if (!local_wallet->BackupWallet(fs::PathToString(backup_path))) {
        return util::Error{_("Error: Unable to make a backup of your wallet")};
    }
    res.backup_path = backup_path;

    bool success = false;

    // Unlock the wallet if needed
    if (local_wallet->IsLocked() && !local_wallet->Unlock(passphrase)) {
        if (passphrase.find('\0') == std::string::npos) {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase was not provided or was incorrect.")};
        } else {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase entered was incorrect. "
                                            "The passphrase contains a null character (ie - a zero byte). "
                                            "If this passphrase was set with a version of this software prior to 25.0, "
                                            "please try again with only the characters up to — but not including — "
                                            "the first null character.")};
        }
    }

    // Indicates whether the current wallet is empty after migration.
    // Notes:
    // When non-empty: the local wallet becomes the main spendable wallet.
    // When empty: The local wallet is excluded from the result, as the
    //             user does not expect an empty spendable wallet after
    //             migrating only watch-only scripts.
    bool empty_local_wallet = false;

    {
        LOCK(local_wallet->cs_wallet);
        // First change to using SQLite
        if (!local_wallet->MigrateToSQLite(error)) return util::Error{error};

        // Do the migration of keys and scripts for non-empty wallets, and cleanup if it fails
        if (HasLegacyRecords(*local_wallet)) {
            success = DoMigration(*local_wallet, context, error, res, load_wallet);
            // No scripts mean empty wallet after migration
            empty_local_wallet = local_wallet->GetAllScriptPubKeyMans().empty();
        } else {
            // Make sure that descriptors flag is actually set
            local_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            success = true;
        }
    }

    // In case of loading failure, we need to remember the wallet files we have created to remove.
    // A `set` is used as it may be populated with the same wallet directory paths multiple times,
    // both before and after loading. This ensures the set is complete even if one of the wallets
    // fails to load.
    std::set<fs::path> wallet_files_to_remove;
    std::set<fs::path> wallet_empty_dirs_to_remove;

    // Helper to track wallet files and directories for cleanup on failure.
    // Only directories of wallets created during migration (not the main wallet) are tracked.
    auto track_for_cleanup = [&](const CWallet& wallet) {
        const auto files = wallet.GetDatabase().Files();
        wallet_files_to_remove.insert(files.begin(), files.end());
        if (wallet.GetName() != wallet_name) {
            // If this isn’t the main wallet, mark its directory for removal.
            // This applies to the watch-only and solvable wallets.
            // Wallets stored directly as files in the top-level directory
            // (e.g. default unnamed wallets) don’t have a removable parent directory.
            wallet_empty_dirs_to_remove.insert(fs::PathFromString(wallet.GetDatabase().Filename()).parent_path());
        }
    };


    if (success) {
        Assume(!res.wallet); // We will set it here.
        // Check if the local wallet is empty after migration
        if (empty_local_wallet) {
            // This wallet has no records. We can safely remove it.
            std::vector<fs::path> paths_to_remove = local_wallet->GetDatabase().Files();
            local_wallet.reset();
            for (const auto& path_to_remove : paths_to_remove) fs::remove(path_to_remove);
        }

        if (load_wallet) {
            LogInfo("Loading new wallets after migration...\n");
            /** We only override the load_on_startup setting in case the user explicitly said
             * that he does not want to load the wallet, otherwise keep the old wallet configuration */
        } else {
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/false, warnings);
        }
        // Migration successful, if load_wallet is set load all the migrated wallets.
        bool main_wallet_set{false};
        for (std::shared_ptr<CWallet>* wallet_ptr : {&local_wallet, &res.watchonly_wallet, &res.solvables_wallet}) {
            if (success && *wallet_ptr) {
                std::shared_ptr<CWallet>& wallet = *wallet_ptr;
                // Track db path
                track_for_cleanup(*wallet);
                assert(wallet.use_count() == 1);
                std::string wallet_name = wallet->GetName();
                wallet.reset();
                if (load_wallet) {
                    wallet = LoadWallet(context, wallet_name, /*load_on_start=*/std::nullopt, options, status, error, warnings);
                    if (!wallet) {
                        LogError("Failed to load wallet '%s' after migration. Rolling back migration to preserve consistency. "
                                 "Error cause: %s\n", wallet_name, error.original);
                        success = false;
                        break;
                    }
                }
                // Set the first wallet as the main one.
                // The loop order is intentional and must always start with the local wallet.
                if (!main_wallet_set) {
                    res.wallet_name = wallet_name;
                    if (load_wallet) res.wallet = std::move(wallet);
                    main_wallet_set = true;
                }
                if (wallet_ptr == &res.watchonly_wallet) {
                    res.watchonly_wallet_name = wallet_name;
                } else if (wallet_ptr == &res.solvables_wallet) {
                    res.solvables_wallet_name = wallet_name;
                }
            }
        }
    }
    if (!success) {
        // Make list of wallets to cleanup
        std::vector<std::shared_ptr<CWallet>> created_wallets;
        if (local_wallet) created_wallets.push_back(std::move(local_wallet));
        if (res.watchonly_wallet) created_wallets.push_back(std::move(res.watchonly_wallet));
        if (res.solvables_wallet) created_wallets.push_back(std::move(res.solvables_wallet));

        // Get the directories to remove after unloading
        for (std::shared_ptr<CWallet>& wallet : created_wallets) {
            track_for_cleanup(*wallet);
        }

        // Unload the wallets
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            if (w->HaveChain()) {
                // Unloading for wallets that were loaded for normal use
                if (!RemoveWallet(context, w, /*load_on_start=*/false)) {
                    error += _("\nUnable to cleanup failed migration");
                    return util::Error{error};
                }
                WaitForDeleteWallet(std::move(w));
            } else {
                // Unloading for wallets in local context
                assert(w.use_count() == 1);
                w.reset();
            }
        }

        // First, delete the db files we have created throughout this process and nothing else
        for (const fs::path& file : wallet_files_to_remove) {
            fs::remove(file);
        }

        // Second, delete the created wallet directories and nothing else. They must be empty at this point.
        for (const fs::path& dir : wallet_empty_dirs_to_remove) {
            Assume(fs::is_empty(dir));
            fs::remove(dir);
        }

        // Restore the backup
        // Convert the backup file to the wallet db file by renaming it and moving it into the wallet's directory.
        bilingual_str restore_error;
        const auto& ptr_wallet = RestoreWallet(context, backup_path, wallet_name, /*load_on_start=*/std::nullopt, status, restore_error, warnings, /*load_after_restore=*/false, /*allow_unnamed=*/true);
        if (!restore_error.empty()) {
            error += restore_error + _("\nUnable to restore backup of wallet.");
            return util::Error{error};
        }
        // Verify that the legacy wallet is not loaded after restoring from the backup.
        assert(!ptr_wallet);

        return util::Error{error};
    }
    return res;
}

void CWallet::CacheNewScriptPubKeys(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    for (const auto& script : spks) {
        m_cached_spks[script].push_back(spkm);
    }
}

void CWallet::TopUpCallback(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    // Update scriptPubKey cache
    CacheNewScriptPubKeys(spks, spkm);
}

CWallet::HDPubKeyMap CWallet::GetHDPubKeys(HDKeyFilter filter) const
{
    AssertLockHeld(cs_wallet);

    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    HDPubKeyMap xpubs;
    for (const auto& spkm : filter == HDKeyFilter::Active ? GetActiveScriptPubKeyMans() : GetAllScriptPubKeyMans()) {
        auto* desc_spkm = Assert(dynamic_cast<DescriptorScriptPubKeyMan*>(spkm));
        LOCK(desc_spkm->cs_desc_man);
        WalletDescriptor w_desc = desc_spkm->GetWalletDescriptor();
        // mweb() descriptors also report !HasScripts() but are not unused(KEY) descriptors.
        if (filter == HDKeyFilter::UnusedKey &&
            (w_desc.descriptor->HasScripts() || w_desc.descriptor->GetOutputType() == OutputType::MWEB)) continue;

        std::set<CPubKey> desc_pubkeys;
        std::set<CExtPubKey> desc_xpubs;
        w_desc.descriptor->GetPubKeys(desc_pubkeys, desc_xpubs);
        for (const CExtPubKey& xpub : desc_xpubs) {
            xpubs[xpub].insert(desc_spkm);
        }
    }
    return xpubs;
}

std::optional<CKey> CWallet::GetKey(const CKeyID& keyid) const
{
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    for (const auto& spkm : GetAllScriptPubKeyMans()) {
        const DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        assert(desc_spkm);
        LOCK(desc_spkm->cs_desc_man);
        if (std::optional<CKey> key = desc_spkm->LookupPrivKey(keyid)) {
            return key;
        }
    }
    return std::nullopt;
}

std::optional<CExtKey> CWallet::GetExtKey(const CExtPubKey& xpub) const
{
    if (std::optional<CKey> key = GetKey(xpub.pubkey.GetID())) {
        return CExtKey{xpub, *key};
    }
    return std::nullopt;
}

void CWallet::WriteBestBlock() const
{
    AssertLockHeld(cs_wallet);

    if (!m_last_block_processed.IsNull()) {
        CBlockLocator loc;
        chain().findBlock(m_last_block_processed, FoundBlock().locator(loc));

        if (!loc.IsNull()) {
            WalletBatch batch(GetDatabase());
            batch.WriteBestBlock(loc);
        }
    }
}

void CWallet::RefreshTXOsFromTx(const CWalletTx& wtx)
{
    AssertLockHeld(cs_wallet);
    for (uint32_t i = 0; i < wtx.GetTx()->vout.size(); ++i) {
        const CTxOut& txout = wtx.GetTx()->vout.at(i);
        if (!IsMine(txout)) continue;
        COutPoint outpoint(wtx.GetHash(), i);
        if (m_txos.contains(outpoint)) {
        } else {
            m_txos.emplace(outpoint, WalletTXO{wtx, txout});
        }
    }
}

void CWallet::RefreshAllTXOs()
{
    AssertLockHeld(cs_wallet);
    for (const auto& [_, wtx] : mapWallet) {
        RefreshTXOsFromTx(wtx);
    }
}

std::optional<WalletTXO> CWallet::GetTXO(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    const auto& it = m_txos.find(outpoint);
    if (it == m_txos.end()) {
        return std::nullopt;
    }
    return it->second;
}

void CWallet::DisconnectChainNotifications()
{
    if (m_chain_notifications_handler) {
        m_chain_notifications_handler->disconnect();
        chain().waitForNotifications();
        m_chain_notifications_handler.reset();
    }
}

// MWEB hooks
DescriptorScriptPubKeyMan& CWallet::AddMWEBSupportingAccount(WalletDescriptor& descriptor, const FlatSigningProvider& provider)
{
    AssertLockHeld(cs_wallet);
    auto spkm = DescriptorScriptPubKeyMan::CreateMWEBSupportingAccount(*this, descriptor, m_keypool_size, provider);
    auto& result = *spkm;
    const uint256 id = spkm->GetID();
    AddScriptPubKeyMan(id, std::move(spkm));
    MarkDirty();
    return result;
}

void CWallet::AddToSpends(const mw::Hash& output_id, const Txid& txid)
{
    const auto [begin, end] = mapMWEBSpends.equal_range(output_id);
    for (auto it = begin; it != end; ++it) {
        if (it->second == txid) {
            UnlockCoin(output_id);
            return;
        }
    }
    mapMWEBSpends.insert(std::make_pair(output_id, txid));

    UnlockCoin(output_id);
}

void CWallet::AddMWEBOrigins(const CWalletTx& wtx)
{
    const auto insert_output_origin = [&](const mw::Hash& output_id) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        const auto [begin, end] = mapOutputsMWEB.equal_range(output_id);
        for (auto it = begin; it != end; ++it) {
            if (it->second == wtx.GetHash()) return;
        }
        mapOutputsMWEB.insert(std::make_pair(output_id, wtx.GetHash()));
    };
    for (const mw::Hash& output_id : wtx.GetTx()->mweb_tx.GetOutputIDs()) {
        insert_output_origin(output_id);
    }

    if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
        insert_output_origin(wtx.mweb_wtx_info->received_coin->output_id);
    }

    for (const mw::Hash& kernel_id : wtx.GetTx()->mweb_tx.GetKernelIDs()) {
        mapKernelsMWEB.insert(std::make_pair(kernel_id, wtx.GetHash()));
    }
}

bool CWallet::GetCoin(const mw::Hash& output_id, mw::Coin& coin) const
{
    return GetMWWallet()->GetCoin(output_id, coin);
}

bool CWallet::IsSpentMWEB(const mw::Hash& output_id) const
{
    return mapMWEBSpends.contains(output_id);
}

int CWallet::GetMWEBOutputOccurrenceHeightForSpendAt(const mw::Hash& output_id, int spend_height) const
{
    AssertLockHeld(cs_wallet);
    int best_height = -1;
    const auto [begin, end] = mapOutputsMWEB.equal_range(output_id);
    for (auto it = begin; it != end; ++it) {
        const auto wtx_it = mapWallet.find(it->second);
        if (wtx_it == mapWallet.end() || GetTxDepthInMainChain(wtx_it->second) <= 0) {
            continue;
        }
        if (const auto* conf = wtx_it->second.state<TxStateConfirmed>()) {
            if (conf->confirmed_block_height <= spend_height && conf->confirmed_block_height > best_height) {
                best_height = conf->confirmed_block_height;
            }
        }
    }
    return best_height;
}

int CWallet::GetMWEBOutputOccurrenceHeight(const mw::Hash& output_id, const CWalletTx& spend_wtx) const
{
    AssertLockHeld(cs_wallet);
    if (GetTxDepthInMainChain(spend_wtx) > 0) {
        if (const auto* conf = spend_wtx.state<TxStateConfirmed>()) {
            return GetMWEBOutputOccurrenceHeightForSpendAt(output_id, conf->confirmed_block_height);
        }
    }
    if (const auto* conflict = spend_wtx.state<TxStateBlockConflicted>()) {
        return GetMWEBOutputOccurrenceHeightForSpendAt(output_id, conflict->conflicting_block_height);
    }
    return GetMWEBOutputOccurrenceHeightForSpendAt(output_id, std::numeric_limits<int>::max());
}

bool CWallet::IsOutputSpentMWEB(const mw::Hash& output_id, const CWalletTx& create_wtx) const
{
    AssertLockHeld(cs_wallet);
    std::optional<int> create_height;
    if (GetTxDepthInMainChain(create_wtx) > 0) {
        if (const auto* conf = create_wtx.state<TxStateConfirmed>()) {
            create_height = conf->confirmed_block_height;
        }
    }
    if (create_height) {
        const auto [out_begin, out_end] = mapOutputsMWEB.equal_range(output_id);
        for (auto it = out_begin; it != out_end; ++it) {
            const auto wtx_it = mapWallet.find(it->second);
            if (wtx_it == mapWallet.end() || GetTxDepthInMainChain(wtx_it->second) <= 0) continue;
            if (const auto* other_conf = wtx_it->second.state<TxStateConfirmed>()) {
                if (other_conf->confirmed_block_height > *create_height) {
                    return true;
                }
            }
        }
    }
    if (!IsSpentMWEB(output_id)) {
        return false;
    }
    const int create_epoch = create_height.value_or(std::numeric_limits<int>::max());
    const int target_epoch = GetMWEBOutputOccurrenceHeightForSpendAt(output_id, create_epoch);
    for (auto range = mapMWEBSpends.equal_range(output_id); range.first != range.second; ++range.first) {
        const auto spend_it = mapWallet.find(range.first->second);
        if (spend_it == mapWallet.end() || spend_it->second.isAbandoned()) {
            continue;
        }
        const CWalletTx& spend_wtx = spend_it->second;
        if (!create_height && GetTxDepthInMainChain(spend_wtx) > 0) {
            continue;
        }
        if (GetMWEBOutputOccurrenceHeight(output_id, spend_wtx) == target_epoch) {
            return true;
        }
    }
    return false;
}

bool CWallet::IsOutputSpentMWEBInChainOrMempool(const mw::Hash& output_id, const CWalletTx& create_wtx) const
{
    AssertLockHeld(cs_wallet);
    std::optional<int> create_height;
    if (GetTxDepthInMainChain(create_wtx) > 0) {
        if (const auto* conf = create_wtx.state<TxStateConfirmed>()) {
            create_height = conf->confirmed_block_height;
        }
    }
    if (create_height) {
        const auto [out_begin, out_end] = mapOutputsMWEB.equal_range(output_id);
        for (auto it = out_begin; it != out_end; ++it) {
            const auto wtx_it = mapWallet.find(it->second);
            if (wtx_it == mapWallet.end() || GetTxDepthInMainChain(wtx_it->second) <= 0) continue;
            if (const auto* other_conf = wtx_it->second.state<TxStateConfirmed>()) {
                if (other_conf->confirmed_block_height > *create_height) {
                    return true;
                }
            }
        }
    }
    if (!IsSpentMWEB(output_id)) {
        return false;
    }
    const int create_epoch = create_height.value_or(std::numeric_limits<int>::max());
    const int target_epoch = GetMWEBOutputOccurrenceHeightForSpendAt(output_id, create_epoch);
    for (auto range = mapMWEBSpends.equal_range(output_id); range.first != range.second; ++range.first) {
        const auto wtx_it = mapWallet.find(range.first->second);
        if (wtx_it == mapWallet.end()) {
            continue;
        }
        const CWalletTx& spend_wtx = wtx_it->second;
        if (!spend_wtx.InMempool() && GetTxDepthInMainChain(spend_wtx) <= 0) {
            continue;
        }
        if (!create_height && GetTxDepthInMainChain(spend_wtx) > 0) {
            continue;
        }
        if (GetMWEBOutputOccurrenceHeight(output_id, spend_wtx) == target_epoch) {
            return true;
        }
    }
    return false;
}

bool CWallet::IsSpentMWEBInChainOrMempool(const mw::Hash& output_id) const
{
    AssertLockHeld(cs_wallet);
    if (!IsSpentMWEB(output_id)) {
        return false;
    }
    bool has_active_create{false};
    const auto [out_begin, out_end] = mapOutputsMWEB.equal_range(output_id);
    for (auto it = out_begin; it != out_end; ++it) {
        const auto wtx_it = mapWallet.find(it->second);
        if (wtx_it == mapWallet.end()) continue;
        const CWalletTx& create_wtx = wtx_it->second;
        if (create_wtx.InMempool() || GetTxDepthInMainChain(create_wtx) > 0) {
            has_active_create = true;
            if (!IsOutputSpentMWEBInChainOrMempool(output_id, create_wtx)) {
                return false;
            }
        }
    }
    if (has_active_create) {
        return true;
    }
    for (auto range = mapMWEBSpends.equal_range(output_id); range.first != range.second; ++range.first) {
        const auto wtx_it = mapWallet.find(range.first->second);
        if (wtx_it == mapWallet.end()) {
            continue;
        }
        const CWalletTx& spend_wtx = wtx_it->second;
        if (spend_wtx.InMempool() || GetTxDepthInMainChain(spend_wtx) > 0) {
            return true;
        }
    }
    return false;
}

std::vector<CWalletTx*> CWallet::FindWalletTxsByOutputId(const mw::Hash& output_id)
{
    std::vector<CWalletTx*> result;
    const auto [begin, end] = mapOutputsMWEB.equal_range(output_id);
    for (auto it = begin; it != end; ++it) {
        auto wtx_it = mapWallet.find(it->second);
        if (wtx_it != mapWallet.end()) {
            result.push_back(&wtx_it->second);
        }
    }
    return result;
}

CWalletTx* CWallet::FindWalletTxByOutputId(const mw::Hash& output_id, std::optional<uint64_t> leaf_index)
{
    const std::vector<CWalletTx*> matches = FindWalletTxsByOutputId(output_id);
    if (matches.empty()) {
        return nullptr;
    }
    if (leaf_index) {
        for (CWalletTx* wtx : matches) {
            if (wtx->mweb_wtx_info && wtx->mweb_wtx_info->leaf_index == leaf_index) {
                return wtx;
            }
        }
        if (matches.size() == 1 && (!matches.front()->mweb_wtx_info || !matches.front()->mweb_wtx_info->leaf_index)) {
            return matches.front();
        }
        return nullptr;
    }
    CWalletTx* best = matches.front();
    for (CWalletTx* wtx : matches) {
        if (wtx->nOrderPos > best->nOrderPos) {
            best = wtx;
        }
    }
    return best;
}

CWalletTx* CWallet::FindWalletTxForBlockOutput(const mw::Hash& output_id, const CBlock& block_data,
                                                const uint256& block_hash, std::optional<uint64_t> leaf_index)
{
    const std::vector<CWalletTx*> matches = FindWalletTxsByOutputId(output_id);
    if (matches.empty()) {
        return nullptr;
    }
    const std::set<mw::Hash> block_kernels = block_data.mweb_block.IsNull()
        ? std::set<mw::Hash>{}
        : block_data.mweb_block.GetKernelIDs();

    for (CWalletTx* wtx : matches) {
        if (const auto* conf = wtx->state<TxStateConfirmed>(); conf && conf->confirmed_block_hash == block_hash) {
            return wtx;
        }
        if (!wtx->IsMWEBPlaceholder() && wtx->GetTx()->HasMWEBTx()) {
            const auto tx_kernels = wtx->GetTx()->mweb_tx.GetKernelIDs();
            if (!tx_kernels.empty() &&
                std::all_of(tx_kernels.begin(), tx_kernels.end(),
                            [&](const mw::Hash& kernel_id) { return block_kernels.contains(kernel_id); })) {
                return wtx;
            }
        }
        if (wtx->IsMWEBPlaceholder() && wtx->mweb_wtx_info && wtx->mweb_wtx_info->leaf_index && leaf_index &&
            *wtx->mweb_wtx_info->leaf_index == *leaf_index) {
            return wtx;
        }
    }

    for (CWalletTx* wtx : matches) {
        if (!wtx->IsMWEBPlaceholder()) {
            continue;
        }
        if (wtx->mweb_wtx_info && wtx->mweb_wtx_info->leaf_index && leaf_index &&
            *wtx->mweb_wtx_info->leaf_index != *leaf_index) {
            continue;
        }
        if (wtx->state<TxStateConfirmed>() && GetTxDepthInMainChain(*wtx) > 0) {
            continue;
        }
        return wtx;
    }

    return nullptr;
}

CWalletTx* CWallet::FindWalletTxByKernelId(const mw::Hash& kernel_id)
{
    auto iter = mapKernelsMWEB.find(kernel_id);
    if (iter == mapKernelsMWEB.end()) {
        return nullptr;
    }
    auto wtx_iter = mapWallet.find(iter->second);
    return wtx_iter == mapWallet.end() ? nullptr : &wtx_iter->second;
}

std::vector<CWallet::MWEBUnspentEntry> CWallet::ListMWEBUnspent(
    int min_depth, int max_depth, bool include_unsafe,
    const std::set<CTxDestination>* filter_destinations,
    CAmount min_amount, CAmount max_amount) const
{
    AssertLockHeld(cs_wallet);
    std::vector<MWEBUnspentEntry> result;
    std::set<Txid> trusted_parents;
    std::set<mw::Hash> seen_outputs;
    for (const auto& [output_id, txid] : mapOutputsMWEB) {
        if (seen_outputs.contains(output_id)) {
            continue;
        }
        if (MWEB::IsFrozenOutput(output_id)) {
            continue;
        }
        mw::Coin coin;
        if (!GetCoin(output_id, coin) || !coin.IsMine()) {
            continue;
        }
        if (coin.amount < min_amount || coin.amount > max_amount) {
            continue;
        }

        const auto wtx_it = mapWallet.find(txid);
        if (wtx_it == mapWallet.end()) {
            continue;
        }
        const CWalletTx& wtx = wtx_it->second;

        const int depth = GetTxDepthInMainChain(wtx);
        if (depth < 0) {
            continue;
        }
        if (depth == 0 && !wtx.InMempool()) {
            continue;
        }
        if (IsOutputSpentMWEBInChainOrMempool(output_id, wtx)) {
            continue;
        }
        seen_outputs.insert(output_id);
        if (depth < min_depth || depth > max_depth) {
            continue;
        }

        const bool safe = CachedTxIsTrusted(*this, wtx, trusted_parents);
        if (!include_unsafe && !safe) {
            continue;
        }

        StealthAddress address;
        if (!GetMWWallet()->GetStealthAddress(coin, address)) {
            continue;
        }

        const CTxDestination dest = address;
        if (filter_destinations && !filter_destinations->contains(dest)) {
            continue;
        }

        // Emit mapWallet key (from mapOutputsMWEB), not wtx.GetHash(), so balance and
        // listunspent txids stay lookup-stable even if GetHash ever regresses.
        result.push_back({output_id, txid, coin.amount, depth, std::move(address), safe});
    }
    return result;
}

bool CWallet::IsMine(const CTransaction& tx, const std::optional<MWEB::WalletTxInfo>& mweb_wtx_info) const
{
    if (IsMine(tx)) {
        return true;
    }
    if (mweb_wtx_info) {
        if (mweb_wtx_info->received_coin && mweb_wtx_info->received_coin->IsMine()) {
            return true;
        }
        if (mweb_wtx_info->spent_input) {
            mw::Coin coin;
            if (GetCoin(*mweb_wtx_info->spent_input, coin) && coin.IsMine()) {
                return true;
            }
        }
    }
    if (tx.HasMWEBTx()) {
        for (const Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            if (GetCoin(output.GetOutputID(), coin) && coin.IsMine()) {
                return true;
            }
        }
    }
    return false;
}

DescriptorScriptPubKeyMan* CWallet::GetExternalMWEBScriptPubKeyMan() const
{
    return dynamic_cast<DescriptorScriptPubKeyMan*>(GetScriptPubKeyMan(OutputType::MWEB, false));
}

DescriptorScriptPubKeyMan* CWallet::GetInternalMWEBScriptPubKeyMan() const
{
    return dynamic_cast<DescriptorScriptPubKeyMan*>(GetScriptPubKeyMan(OutputType::MWEB, true));
}

std::optional<std::string> CWallet::LoadMWEBKeychains()
{
    AssertLockHeld(cs_wallet);
    for (DescriptorScriptPubKeyMan* mweb_spk : GetMWEBAccountScriptPubKeyMans()) {
        mweb_spk->LoadMWEBKeychain();
        LOCK(mweb_spk->cs_desc_man);
        if (std::optional<std::string> error = mweb_spk->CheckMWEBKeychain()) {
            WalletLogPrintf("Error: %s\n", *error);
            return error;
        }
    }
    return std::nullopt;
}

std::vector<DescriptorScriptPubKeyMan*> CWallet::GetMWEBAccountScriptPubKeyMans() const
{
    // Several entries can claim one address (a separate single-address entry and an account that
    // derives it). Callers take the first match, so order by spend capability, then accounts,
    // then id, rather than by pointer.
    struct Entry {
        DescriptorScriptPubKeyMan* spk;
        bool can_spend;
        bool is_account;
        uint256 id;
    };
    std::vector<Entry> entries;
    for (ScriptPubKeyMan* spk : GetAllScriptPubKeyMans()) {
        auto* desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk);
        if (!desc_spk) {
            continue;
        }
        LOCK(desc_spk->cs_desc_man);
        if (desc_spk->IsMWEBCapabilityDescriptor()) {
            const mw::Keychain::Ptr& keychain = desc_spk->GetMWEBKeychain();
            entries.push_back({desc_spk, keychain && keychain->HasSpendSecret(), desc_spk->IsMWEBAccountDescriptor(), desc_spk->GetID()});
        }
    }
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return std::tie(b.can_spend, b.is_account, a.id) < std::tie(a.can_spend, a.is_account, b.id);
    });
    std::vector<DescriptorScriptPubKeyMan*> result;
    result.reserve(entries.size());
    for (const Entry& entry : entries) {
        result.push_back(entry.spk);
    }
    return result;
}

DescriptorScriptPubKeyMan* CWallet::GetMWEBAccountScriptPubKeyMan(const std::string& acct_cksum) const
{
    if (acct_cksum.empty()) {
        return nullptr;
    }
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        if (spk->GetMWEBAccountChecksum() == acct_cksum) {
            return spk;
        }
    }
    return nullptr;
}

size_t CWallet::CountMWEBInternalDescriptors() const
{
    size_t count = 0;
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        count += spk->GetMWEBInternalDescriptorCount();
    }
    return count;
}

bool CWallet::HasUnspentMWEBAtIndex(const DescriptorScriptPubKeyMan& account_spk, uint32_t index) const
{
    AssertLockHeld(cs_wallet);
    // Align with ListMWEBUnspent for abandoned spends: a coin stays "unspent"
    // only when every recorded spend is abandoned. Non-abandoned spends
    // (including CommitTransaction's TxStateInactive window before broadcast
    // sets InMempool) must inhibit pruning.
    for (const auto& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        if (!wtx.mweb_wtx_info || !wtx.mweb_wtx_info->received_coin) {
            continue;
        }
        const mw::Coin& coin = *wtx.mweb_wtx_info->received_coin;
        if (coin.address_index != index || !coin.IsMine()) {
            continue;
        }
        if (IsOutputSpentMWEB(coin.output_id, wtx)) {
            continue;
        }
        if (!coin.HasAddress()) {
            continue;
        }
        if (GetMWEBAccountForStealthAddress(*coin.address) == &account_spk) {
            return true;
        }
    }
    return false;
}

void CWallet::OnMWEBCoinDetected(DescriptorScriptPubKeyMan& account_spk, const mw::Coin& coin)
{
    AssertLockHeld(cs_wallet);
    if (coin.address_index == mw::UNKNOWN_INDEX || coin.address_index == mw::CUSTOM_KEY ||
        coin.address_index > MWEB_MAX_DESCRIPTOR_INDEX) {
        return;
    }
    {
        LOCK(account_spk.cs_desc_man);
        if (!account_spk.IsMWEBAccountDescriptor()) {
            return;
        }
        account_spk.MarkMWEBIndexActive(coin.address_index);
        bool already_persisted = false;
        for (const WalletDescriptor* wdesc : account_spk.GetMWEBInternalWalletDescriptors()) {
            const std::optional<uint32_t> index = GetMWEBIndex(*wdesc->descriptor);
            if (index && *index == coin.address_index) {
                already_persisted = true;
                break;
            }
        }
        WalletBatch batch(GetDatabase());
        if (!already_persisted && coin.HasAddress()) {
            account_spk.PersistMWEBInternalIndex(batch, coin.address_index, *coin.address);
        }
        account_spk.UpdateMWEBInternalActivity(coin.address_index, GetTime());
        account_spk.AdvanceMWEBNextIndexPast(batch, coin.address_index);
    }

    if (coin.address_index != mw::CHANGE_INDEX && coin.address_index != mw::PEGIN_INDEX && coin.HasAddress() &&
        !FindAddressBookEntry(CTxDestination{*coin.address}, /*allow_change=*/false)) {
        SetAddressBook(CTxDestination{*coin.address}, "", AddressPurpose::RECEIVE);
    }
}

void CWallet::ScanMWEBExtensionBlock(const CBlock& block_data, int height, const uint256& block_hash, bool rescanning_old_block,
                                     const MWEB::OutputCandidates* candidates)
{
    AssertLockHeld(cs_wallet);
    // Establish known winners before checking spends. Marking a winner conflicted
    // first would incorrectly propagate that state to its own descendants.
    for (const Kernel& kernel : block_data.mweb_block.m_block->GetKernels()) {
        if (CWalletTx* wtx = FindWalletTxByKernelId(kernel.GetKernelID())) {
            int index = 0;
            if (auto* conf = wtx->state<TxStateConfirmed>()) {
                index = conf->position_in_block;
            }
            SyncTransaction(wtx->GetTx(), TxStateConfirmed{block_hash, height, index}, rescanning_old_block);
        }
    }

    for (const mw::Hash& spent_id : block_data.mweb_block.GetSpentIDs()) {
        bool known_winner{false};
        const int block_epoch = GetMWEBOutputOccurrenceHeightForSpendAt(spent_id, height);
        const auto [begin, end] = mapMWEBSpends.equal_range(spent_id);
        for (auto spend = begin; spend != end; ++spend) {
            CWalletTx& wtx = mapWallet.at(spend->second);
            if (const auto* confirmed = wtx.state<TxStateConfirmed>(); confirmed && confirmed->confirmed_block_hash == block_hash) {
                known_winner = true;
            } else if (GetMWEBOutputOccurrenceHeight(spent_id, wtx) == block_epoch) {
                MarkConflicted(block_hash, height, spend->second);
            }
        }
        mw::Coin coin;
        if (!known_winner && GetCoin(spent_id, coin) && coin.IsMine()) {
            if (DescriptorScriptPubKeyMan* account_spk = GetMWEBAccountForCoin(coin)) {
                LOCK(account_spk->cs_desc_man);
                account_spk->UpdateMWEBInternalActivity(coin.address_index, GetTime());
            }
            MWEB::WalletTxInfo spend_info{spent_id};
            if (const auto it = mapWallet.find(Txid::FromUint256(spend_info.GetHash()));
                it != mapWallet.end() && it->second.IsMWEBPlaceholder() &&
                GetMWEBOutputOccurrenceHeight(spent_id, it->second) != block_epoch) {
                spend_info = MWEB::WalletTxInfo{spent_id, static_cast<uint64_t>(height)};
            }
            AddToWallet(MakeTransactionRef(CMutableTransaction{}), TxStateConfirmed{block_hash, height, 0},
                /*update_wtx=*/nullptr, rescanning_old_block, std::move(spend_info));
        }
    }

    const std::vector<Output>& outputs = block_data.mweb_block.m_block->GetOutputs();
    std::vector<size_t> pending = GetMWWallet()->OutputsToRewind(outputs, candidates);
    // A coin found moves its account's lookahead, which can take in outputs of this block that
    // were checked before it; outputs are in no particular order, so check those again.
    bool found = true;
    while (found && !pending.empty()) {
        found = false;
        std::vector<size_t> unmatched;
        for (const size_t output_index : pending) {
            const Output& output = outputs[output_index];
            const std::optional<uint64_t> leaf_index = GetMWEBBlockOutputLeafIndex(block_data, output_index);
            mw::Coin mweb_coin;
            if (!GetMWWallet()->RewindOutput(output, mweb_coin)) {
                unmatched.push_back(output_index);
                continue;
            }
            found = true;
            if (CWalletTx* wtx = FindWalletTxForBlockOutput(output.GetOutputID(), block_data, block_hash, leaf_index)) {
                int index = 0;
                if (auto* conf = wtx->state<TxStateConfirmed>()) {
                    index = conf->position_in_block;
                }
                if (wtx->IsMWEBPlaceholder()) {
                    // Its empty body cannot identify the domain-separated receive record.
                    AddToWallet(wtx->GetTx(), TxStateConfirmed{block_hash, height, index},
                        nullptr, rescanning_old_block, wtx->mweb_wtx_info);
                } else {
                    // Keep full transactions keyed by their transaction ID.
                    SyncTransaction(wtx->GetTx(), TxStateConfirmed{block_hash, height, index}, rescanning_old_block);
                }
            } else {
                MWEB::WalletTxInfo info{std::move(mweb_coin)};
                if (leaf_index &&
                    (mapWallet.contains(Txid::FromUint256(info.GetHash())) || mapOutputsMWEB.contains(output.GetOutputID()))) {
                    info = MWEB::WalletTxInfo{std::move(*info.received_coin), leaf_index};
                }
                AddToWallet(MakeTransactionRef(CMutableTransaction{}), TxStateConfirmed{block_hash, height, 0},
                    /*update_wtx=*/nullptr, rescanning_old_block,
                    std::move(info));
            }
        }
        pending = std::move(unmatched);
    }
}

bool CWallet::ScanMWEBBlocksFromHeight(int start_height, std::optional<int> max_height)
{
    AssertLockHeld(cs_wallet);
    const int tip_height = GetLastBlockHeight();
    if (start_height < 0 || start_height > tip_height) {
        return true;
    }

    int block_height = start_height;
    uint256 block_hash;
    if (!chain().findAncestorByHeight(GetLastBlockHash(), start_height, FoundBlock().hash(block_hash))) {
        return false;
    }

    while (block_height <= tip_height) {
        if (max_height && block_height > *max_height) {
            break;
        }

        CBlock block;
        bool block_still_active = false;
        bool has_next = false;
        uint256 next_hash;
        if (!chain().findBlock(block_hash, FoundBlock().data(block).inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(has_next).hash(next_hash)))) {
            return false;
        }
        if (!block_still_active) {
            return false;
        }
        if (!block.mweb_block.IsNull()) {
            ScanMWEBExtensionBlock(block, block_height, block_hash, /*rescanning_old_block=*/true);
        }

        if (!has_next || block_height >= tip_height) {
            break;
        }
        block_hash = next_hash;
        ++block_height;
    }
    return true;
}

bool CWallet::HasMWEBAccounts() const
{
    return !GetMWEBAccountScriptPubKeyMans().empty();
}

MWEB::UTXOScanStats CWallet::ScanMWEBUTXOSet(const MWEBIndexScanParams* index_params)
{
    return MWEB::ScanWalletUTXOSet(*this, index_params);
}

bool CWallet::ScanMWEBAccountIndices(DescriptorScriptPubKeyMan& account_spk, const MWEBIndexScanParams& params, int start_height)
{
    AssertLockHeld(cs_wallet);

    uint32_t phase1_end = std::max(params.phase1_end, MWEB_DEFAULT_PHASE1_END);
    if (m_keypool_size > static_cast<int64_t>(phase1_end)) {
        phase1_end = static_cast<uint32_t>(m_keypool_size);
    }
    if (params.max_index) {
        phase1_end = std::max(phase1_end, *params.max_index);
    }

    bool is_account;
    {
        LOCK(account_spk.cs_desc_man);
        account_spk.LoadMWEBKeychain();
        is_account = account_spk.IsMWEBAccountDescriptor() && !account_spk.IsMWEBLimitedAccount();
    }
    if (!is_account) {
        return ScanMWEBBlocksFromHeight(start_height);
    }
    {
        LOCK(account_spk.cs_desc_man);
        account_spk.ResetMWEBScanState();
        if (!account_spk.RegisterEphemeralMWEBIndexRange(0, phase1_end)) {
            return false;
        }
    }

    if (!ScanMWEBBlocksFromHeight(start_height)) {
        LOCK(account_spk.cs_desc_man);
        account_spk.ClearEphemeralMWEBIndices();
        return false;
    }

    uint32_t max_active = 0;
    {
        LOCK(account_spk.cs_desc_man);
        WalletBatch batch(GetDatabase());
        max_active = account_spk.CommitActiveMWEBIndices(batch);
        account_spk.ClearEphemeralMWEBIndices();
    }

    const uint32_t window = std::max(MWEB_DEFAULT_PHASE1_END, static_cast<uint32_t>(std::clamp<int64_t>(m_keypool_size, 0, MWEB_MAX_DESCRIPTOR_INDEX)));
    uint32_t scanned_end = phase1_end;
    while (scanned_end < MWEB_MAX_DESCRIPTOR_INDEX && uint64_t{max_active} + params.gap_limit > scanned_end) {
        const uint32_t from = scanned_end + 1;
        const uint32_t to = static_cast<uint32_t>(std::min<uint64_t>(uint64_t{max_active} + window, MWEB_MAX_DESCRIPTOR_INDEX));
        {
            LOCK(account_spk.cs_desc_man);
            account_spk.ResetMWEBScanState();
            if (!account_spk.RegisterEphemeralMWEBIndexRange(from, to)) {
                account_spk.ClearEphemeralMWEBIndices();
                break;
            }
        }
        const bool scanned = ScanMWEBBlocksFromHeight(start_height);
        LOCK(account_spk.cs_desc_man);
        if (scanned) {
            WalletBatch batch(GetDatabase());
            max_active = std::max(max_active, account_spk.CommitActiveMWEBIndices(batch));
        }
        account_spk.ClearEphemeralMWEBIndices();
        if (!scanned) break;
        scanned_end = to;
    }

    LOCK(account_spk.cs_desc_man);
    WalletBatch batch(GetDatabase());
    account_spk.EnsureMWEBNextIndexAtLeast(std::max<uint32_t>(max_active + 1, 2));
    batch.WriteDescriptor(account_spk.GetID(), account_spk.GetWalletDescriptor());
    return true;
}

void CWallet::PruneMWEBDescriptors()
{
    AssertLockHeld(cs_wallet);
    size_t global_count = CountMWEBInternalDescriptors();
    const size_t threshold = static_cast<size_t>(m_mweb_descriptor_threshold);
    if (global_count <= threshold) {
        return;
    }

    WalletBatch batch(GetDatabase());
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        spk->PruneMWEBInternalDescriptors(batch, global_count, threshold, m_mweb_descriptor_inactivity,
            [this, spk](uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return HasUnspentMWEBAtIndex(*spk, index); });
        if (global_count <= threshold) {
            break;
        }
    }
}

const mw::Keychain::Ptr& CWallet::GetMWEBKeychain() const
{
    return GetWalletMWEBKeychain();
}

DescriptorScriptPubKeyMan* CWallet::GetMWEBAccountForStealthAddress(const StealthAddress& addr) const
{
    AssertLockHeld(cs_wallet);
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        if (spk->IsMine(CTxDestination{addr})) {
            return spk;
        }
    }
    return nullptr;
}

DescriptorScriptPubKeyMan* CWallet::GetMWEBAccountForCoin(const mw::Coin& coin) const
{
    AssertLockHeld(cs_wallet);
    mw::Coin lookup = coin;
    mw::Coin stored;
    if (GetCoin(coin.output_id, stored)) {
        if (stored.HasAddress() || !lookup.HasAddress()) lookup = stored;
    } else {
        const auto [begin, end] = mapOutputsMWEB.equal_range(coin.output_id);
        for (auto map_it = begin; map_it != end; ++map_it) {
            const auto wtx_it = mapWallet.find(map_it->second);
            if (wtx_it != mapWallet.end() && wtx_it->second.mweb_wtx_info && wtx_it->second.mweb_wtx_info->received_coin) {
                const auto& received = *wtx_it->second.mweb_wtx_info->received_coin;
                if (received.HasAddress() || !lookup.HasAddress()) lookup = received;
                break;
            }
        }
    }
    if (lookup.HasAddress()) {
        if (DescriptorScriptPubKeyMan* account = GetMWEBAccountForStealthAddress(*lookup.address)) {
            return account;
        }
        for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
            if (spk->GetMetadata(CTxDestination{*lookup.address})) {
                return spk;
            }
        }
    }
    if (lookup.address_index == mw::UNKNOWN_INDEX || lookup.address_index == mw::CUSTOM_KEY) {
        return nullptr;
    }
    DescriptorScriptPubKeyMan* match{nullptr};
    std::optional<StealthAddress> matched_address;
    bool match_has_spend_secret{false};
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        spk->LoadMWEBKeychain();
        const mw::Keychain::Ptr keychain = spk->GetMWEBKeychain();
        if (!keychain || !keychain->HasSpendPubKey() || (lookup.HasAddress() && !keychain->HasSpendSecret())) {
            continue;
        }
        if (!lookup.HasAddress() && lookup.master_scan_key_id &&
            keychain->GetMasterScanKeyID() != *lookup.master_scan_key_id) {
            continue;
        }
        const StealthAddress candidate = keychain->GetStealthAddress(lookup.address_index);
        if (lookup.HasAddress()) {
            if (candidate == *lookup.address) {
                return spk;
            }
            continue;
        }
        if (spk->IsMine(CTxDestination{candidate}) || spk->GetMetadata(CTxDestination{candidate})) {
            // A scan key and index do not distinguish spend branches. Watch
            // and private aliases of the same address are one branch; prefer
            // the private alias without inventing an owner for different ones.
            if (matched_address && *matched_address != candidate) return nullptr;
            matched_address = candidate;
            if (!match || (!match_has_spend_secret && keychain->HasSpendSecret())) {
                match = spk;
                match_has_spend_secret = keychain->HasSpendSecret();
            }
        }
    }
    return match;
}

bool CWallet::GetMWEBStealthAddress(const DescriptorScriptPubKeyMan& account_spk, uint32_t index, StealthAddress& address) const
{
    LOCK(account_spk.cs_desc_man);
    const mw::Keychain::Ptr& keychain = account_spk.GetMWEBKeychain();
    if (!keychain || !account_spk.IsMWEBAccountDescriptor() || index == mw::UNKNOWN_INDEX || index == mw::CUSTOM_KEY) {
        return false;
    }
    if (!keychain->HasSpendPubKey()) {
        return false;
    }
    address = keychain->GetStealthAddress(index);
    return true;
}

bool CWallet::GetMWEBChangeAddress(const DescriptorScriptPubKeyMan& account_spk, StealthAddress& address) const
{
    LOCK(account_spk.cs_desc_man);
    // Indexed imports do not opt into discovering reserved change addresses.
    // Use a full active/contributing account, or an explicit caller-supplied destination.
    if (account_spk.IsMWEBLimitedAccount()) return false;
    return GetMWEBStealthAddress(account_spk, mw::CHANGE_INDEX, address);
}

const mw::Keychain::Ptr& CWallet::GetWalletMWEBKeychain() const
{
    static const mw::Keychain::Ptr null;
    if (DescriptorScriptPubKeyMan* spk_man = GetExternalMWEBScriptPubKeyMan()) {
        const mw::Keychain::Ptr& keychain = spk_man->GetMWEBKeychain();
        if (keychain && keychain->HasSpendSecret()) {
            return keychain;
        }
    }
    for (DescriptorScriptPubKeyMan* spk : GetMWEBAccountScriptPubKeyMans()) {
        LOCK(spk->cs_desc_man);
        if (!spk->IsMWEBAccountDescriptor()) continue;
        const mw::Keychain::Ptr& keychain = spk->GetMWEBKeychain();
        if (keychain && keychain->HasSpendSecret()) {
            return keychain;
        }
    }
    if (DescriptorScriptPubKeyMan* spk_man = GetExternalMWEBScriptPubKeyMan()) {
        return spk_man->GetMWEBKeychain();
    }
    return null;
}

} // namespace wallet
