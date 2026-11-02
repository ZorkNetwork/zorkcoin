// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETDB_H
#define BITCOIN_WALLET_WALLETDB_H

#include <key.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <mw/models/wallet/coin.h> // MWEB hooks
#include <script/sign.h>
#include <wallet/db.h>
#include <wallet/walletutil.h>

#include <mw/models/crypto/secret_key.h> // MWEB hooks

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

class CScript;
class uint160;
class uint256;
struct CBlockLocator;

namespace wallet {
class CMasterKey;
class CWallet;
class CWalletTx;
struct WalletContext;

// Logs information about the database, including available engines, features, and other capabilities
void LogDBInfo();

/**
 * Overview of wallet database classes:
 *
 * - WalletBatch is an abstract modifier object for the wallet database, and encapsulates a database
 *   batch update as well as methods to act on the database. It should be agnostic to the database implementation.
 */

/** Error statuses for the wallet database.
 * Values are in order of severity. When multiple errors occur, the most severe (highest value) will be returned.
 */
enum class DBErrors : int
{
    LOAD_OK = 0,
    NEED_RESCAN = 1,
    EXTERNAL_SIGNER_SUPPORT_REQUIRED = 3,
    NONCRITICAL_ERROR = 4,
    TOO_NEW = 5,
    UNKNOWN_DESCRIPTOR = 6,
    LOAD_FAIL = 7,
    UNEXPECTED_LEGACY_ENTRY = 8,
    LEGACY_WALLET = 9,
    CORRUPT = 10,
};

namespace DBKeys {
extern const std::string ACENTRY;
extern const std::string ACTIVEEXTERNALSPK;
extern const std::string ACTIVEINTERNALSPK;
extern const std::string BESTBLOCK;
extern const std::string BESTBLOCK_NOMERKLE;
extern const std::string CRYPTED_KEY;
extern const std::string CSCRIPT;
extern const std::string DEFAULTKEY;
extern const std::string DESTDATA;
extern const std::string FLAGS;
extern const std::string HDCHAIN;
extern const std::string KEY;
extern const std::string KEYMETA;
extern const std::string LOCKED_UTXO;
extern const std::string MASTER_KEY;
extern const std::string MINVERSION;
extern const std::string NAME;
extern const std::string OLD_KEY;
extern const std::string ORDERPOSNEXT;
extern const std::string POOL;
extern const std::string PURPOSE;
extern const std::string SETTINGS;
extern const std::string TX;
extern const std::string WTX_VARIANT;
extern const std::string VERSION;
extern const std::string WALLETDESCRIPTOR;
extern const std::string WALLETDESCRIPTORCKEY;
extern const std::string WALLETDESCRIPTORKEY;
extern const std::string WATCHMETA;
extern const std::string WATCHS;
extern const std::string MWEB_COIN; // MWEB hooks
extern const std::string MWEB_SENDER_KEY_INDEX; // Next deterministic MWEB sender-key index per scan key
extern const std::string MWEBINTERNALDESC; // MWEB per-index scan descriptors
extern const std::string MWEBSCANK; // MWEB entry scan secret, readable without the passphrase
extern const std::string MWEBINTERNALPROT; // MWEB internal descriptor protect flags
extern const std::string MWEBLIMITEDACCOUNT; // Supporting account: scan registered indices only
extern const std::string LOCKED_MWEB_UTXO; // Persistently locked MWEB output id

// Keys in this set pertain only to legacy wallets and are removed during migration to descriptors.
extern const std::unordered_set<std::string> LEGACY_TYPES;
} // namespace DBKeys

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter;
    uint32_t nInternalChainCounter;
    uint32_t nMWEBIndexCounter{0}; // MWEB hooks
    CKeyID seed_id; //!< seed hash160
    std::optional<SecretKey> mweb_scan_key; // MWEB hooks

    static constexpr int VERSION_HD_BASE{1};
    static constexpr int VERSION_HD_CHAIN_SPLIT{2};
    static constexpr int VERSION_HD_MWEB{3}; // MWEB hooks
    static constexpr int VERSION_HD_MWEB_WATCH{4}; // MWEB hooks
    static constexpr int CURRENT_VERSION{VERSION_HD_MWEB_WATCH};
    int nVersion;

    CHDChain() { SetNull(); }

    SERIALIZE_METHODS(CHDChain, obj)
    {
        READWRITE(obj.nVersion, obj.nExternalChainCounter, obj.seed_id);
        if (obj.nVersion >= VERSION_HD_CHAIN_SPLIT) {
            READWRITE(obj.nInternalChainCounter);
        }
        if (obj.nVersion >= VERSION_HD_MWEB) { // MWEB hooks
            READWRITE(obj.nMWEBIndexCounter);
        }
        if (obj.nVersion >= VERSION_HD_MWEB_WATCH) { // MWEB hooks
            READWRITE(obj.mweb_scan_key);
        }
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nExternalChainCounter = 0;
        nInternalChainCounter = 0;
        nMWEBIndexCounter = 0; // MWEB hooks
        seed_id.SetNull();
        mweb_scan_key = std::nullopt; // MWEB hooks
    }

    bool operator==(const CHDChain& chain) const
    {
        return seed_id == chain.seed_id;
    }
    bool operator<(const CHDChain& chain) const
    {
        return seed_id < chain.seed_id;
    }
};

class CKeyMetadata
{
public:
    static constexpr int VERSION_BASIC{1};
    static constexpr int VERSION_WITH_HDDATA{10};
    static constexpr int VERSION_WITH_KEY_ORIGIN{12};
    static constexpr int VERSION_WITH_MWEB_INDEX{14}; // MWEB hooks
    static constexpr int CURRENT_VERSION{VERSION_WITH_MWEB_INDEX};
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    std::string hdKeypath; //optional HD/bip32 keypath. Still used to determine whether a key is a seed. Also kept for backwards compatibility
    CKeyID hd_seed_id; //id of the HD seed used to derive this key
    KeyOriginInfo key_origin; // Key origin info with path and fingerprint
    bool has_key_origin = false; //!< Whether the key_origin is useful
    std::optional<uint32_t> mweb_index = std::nullopt; // MWEB hooks

    CKeyMetadata()
    {
        SetNull();
    }
    explicit CKeyMetadata(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    SERIALIZE_METHODS(CKeyMetadata, obj)
    {
        READWRITE(obj.nVersion, obj.nCreateTime);
        if (obj.nVersion >= VERSION_WITH_HDDATA) {
            READWRITE(obj.hdKeypath, obj.hd_seed_id);
        }
        if (obj.nVersion >= VERSION_WITH_KEY_ORIGIN)
        {
            READWRITE(obj.key_origin);
            READWRITE(obj.has_key_origin);
        }
        if (obj.nVersion >= VERSION_WITH_MWEB_INDEX) { // MWEB hooks
            READWRITE(obj.mweb_index);
        }
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        hdKeypath.clear();
        hd_seed_id.SetNull();
        key_origin.clear();
        has_key_origin = false;
        mweb_index = std::nullopt; // MWEB hooks
    }
};

struct DbTxnListener
{
    std::function<void()> on_commit, on_abort;
};

/** Access to the wallet database.
 * Opens the database and provides read and write access to it. Each read and write is its own transaction.
 * Multiple operation transactions can be started using TxnBegin() and committed using TxnCommit()
 * Otherwise the transaction will be committed when the object goes out of scope.
 * Optionally (on by default) it will flush to disk on close.
 * Every 1000 writes will automatically trigger a flush to disk.
 */
class WalletBatch
{
private:
    template <typename K, typename T>
    bool WriteIC(const K& key, const T& value, bool fOverwrite = true)
    {
        if (!m_batch->Write(key, value, fOverwrite)) {
            return false;
        }
        return true;
    }

    template <typename K>
    bool EraseIC(const K& key)
    {
        if (!m_batch->Erase(key)) {
            return false;
        }
        return true;
    }

public:
    explicit WalletBatch(WalletDatabase &database) :
        m_batch(database.MakeBatch())
    {
    }
    WalletBatch(const WalletBatch&) = delete;
    WalletBatch& operator=(const WalletBatch&) = delete;

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    // Write a CWalletTx and all variant witness txs (single tx record and multiple wtxvariant records).
    // If previous_key differs from GetHash(), that TX row (and its variants) is erased first.
    bool WriteFullTx(const CWalletTx& wtx, std::optional<Txid> previous_key = std::nullopt);
    /** Write wtx under an explicit TX key (may differ from GetHash()). Tests use this to simulate legacy mismatched rows. */
    bool WriteTxWithKey(const Txid& key, const CWalletTx& wtx);
    bool EraseTx(Txid hash);
    // Write a single witness variant of CWalletTx (single wtxvariant record)
    bool WriteWtxVariant(const Txid& txid, const CTransactionRef& tx);
    // Write only the canonical witness tx and all of the tx metadata (single tx record)
    // Write only the tx record. Falls back to WriteFullTx if previous_key differs from GetHash().
    bool WriteTxMetadata(const CWalletTx& wtx, std::optional<Txid> previous_key = std::nullopt);

    bool WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, bool overwrite);
    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);
    bool EraseMasterKey(unsigned int id);

    bool WriteWatchOnly(const CScript &script, const CKeyMetadata &keymeta);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    // Returns true if wallet stores encryption keys
    bool IsEncrypted();

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const CPrivKey& privkey);
    bool WriteCryptedDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const std::vector<unsigned char>& secret);
    bool WriteDescriptor(const uint256& desc_id, const WalletDescriptor& descriptor);
    bool WriteDescriptorDerivedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index, uint32_t der_index);
    bool WriteDescriptorParentCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index);
    bool WriteDescriptorLastHardenedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index);
    bool WriteDescriptorCacheItems(const uint256& desc_id, const DescriptorCache& cache);

    bool WriteLockedUTXO(const COutPoint& output);
    bool EraseLockedUTXO(const COutPoint& output);
    bool WriteLockedUTXO(const mw::Hash& output_id);
    bool EraseLockedUTXO(const mw::Hash& output_id);

    bool WriteAddressPreviouslySpent(const CTxDestination& dest, bool previously_spent);
    bool WriteAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& receive_request);
    bool EraseAddressReceiveRequest(const CTxDestination& dest, const std::string& id);
    bool EraseAddressData(const CTxDestination& dest);

    bool WriteActiveScriptPubKeyMan(uint8_t type, const uint256& id, bool internal);
    bool EraseActiveScriptPubKeyMan(uint8_t type, bool internal);

    // MWEB hooks
    bool WriteMWEBCoin(const mw::Coin& coin);
    bool WriteMWEBNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index);
    bool WriteMWEBInternalDescriptor(const uint256& account_id, uint32_t index, const WalletDescriptor& descriptor);
    bool EraseMWEBInternalDescriptor(const uint256& account_id, uint32_t index);
    bool WriteMWEBScanKey(const uint256& account_id, const SecretKey& scan_key);
    bool EraseMWEBScanKey(const uint256& account_id);
    bool WriteMWEBInternalProtect(const uint256& account_id, uint32_t index, uint8_t protect);
    bool EraseMWEBInternalProtect(const uint256& account_id, uint32_t index);
    bool WriteMWEBLimitedAccount(const uint256& account_id);
    bool EraseMWEBLimitedAccount(const uint256& account_id);
    bool WriteHDChain(const CHDChain& chain);
    template<typename KeyPool>
    bool ReadPool(int64_t nPool, KeyPool& keypool)
    {
        return m_batch->Read(std::make_pair(DBKeys::POOL, nPool), keypool);
    }
    template<typename KeyPool>
    bool WritePool(int64_t nPool, const KeyPool& keypool)
    {
        return WriteIC(std::make_pair(DBKeys::POOL, nPool), keypool);
    }

    DBErrors LoadWallet(CWallet* pwallet);

    /**
     * Write the given `client_version` to m_batch, indicating the last version
     * of client software to load this wallet.
     *
     * @param[in]   client_version  `CLIENT_VERSION` outside of test code.
     * @return      A bool indicating whether or not the write succeeded.
     */
    bool WriteVersion(int client_version) { return m_batch->Write(DBKeys::VERSION, client_version); }

    //! Delete records of the given types
    bool EraseRecords(const std::unordered_set<std::string>& types);

    bool WriteWalletFlags(uint64_t flags);
    //! Begin a new transaction
    bool TxnBegin();
    //! Commit current transaction
    bool TxnCommit();
    //! Abort current transaction
    bool TxnAbort();
    bool HasActiveTxn() { return m_batch->HasActiveTxn(); }

    //! Registers db txn callback functions
    void RegisterTxnListener(const DbTxnListener& l);

private:
    std::unique_ptr<DatabaseBatch> m_batch;

    // External functions listening to the current db txn outcome.
    // Listeners are cleared at the end of the transaction.
    std::vector<DbTxnListener> m_txn_listeners;
};

/**
 * Executes the provided function 'func' within a database transaction context.
 *
 * This function ensures that all db modifications performed within 'func()' are
 * atomically committed to the db at the end of the process. And, in case of a
 * failure during execution, all performed changes are rolled back.
 *
 * @param database The db connection instance to perform the transaction on.
 * @param process_desc A description of the process being executed, used for logging purposes in the event of a failure.
 * @param func The function to be executed within the db txn context. It returns a boolean indicating whether to commit or roll back the txn.
 * @return true if the db txn executed successfully, false otherwise.
 */
bool RunWithinTxn(WalletDatabase& database, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func);

bool LoadKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr);
bool LoadCryptedKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr);
bool LoadEncryptionKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr);
bool LoadHDChain(CWallet* pwallet, DataStream& ssValue, std::string& strErr);

//! Returns true if there are any DBKeys::LEGACY_TYPES record in the wallet db
bool HasLegacyRecords(CWallet& wallet);
bool HasLegacyRecords(CWallet& wallet, DatabaseBatch& batch);
} // namespace wallet

#endif // BITCOIN_WALLET_WALLETDB_H
