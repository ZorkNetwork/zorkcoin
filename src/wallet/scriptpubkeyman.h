// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_SCRIPTPUBKEYMAN_H

#include <addresstype.h>
#include <common/messages.h>
#include <common/signmessage.h>
#include <common/types.h>
#include <musig.h>
#include <node/types.h>
#include <mw/wallet/keychain.h> // MWEB hooks
#include <psbt.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <util/btcsignals.h>
#include <util/hasher.h>
#include <util/log.h>
#include <util/result.h>
#include <util/time.h>
#include <wallet/crypter.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/imweb_keystore.h>

#include <functional>
#include <optional>
#include <unordered_map>
#include <unordered_set>

enum class OutputType;

namespace wallet {
struct MigrationData;
class ScriptPubKeyMan;

// Wallet storage things that ScriptPubKeyMans need in order to be able to store things to the wallet database.
// It provides access to things that are part of the entire wallet and not specific to a ScriptPubKeyMan such as
// wallet flags, wallet version, encryption keys, encryption status, and the database itself. This allows a
// ScriptPubKeyMan to have callbacks into CWallet without causing a circular dependency.
// WalletStorage should be the same for all ScriptPubKeyMans of a wallet.
class WalletStorage
{
public:
    virtual ~WalletStorage() = default;
    virtual std::string LogName() const = 0;
    virtual WalletDatabase& GetDatabase() const = 0;
    virtual bool IsWalletFlagSet(uint64_t) const = 0;
    virtual void UnsetBlankWalletFlag(WalletBatch&) = 0;
    //! Pass the encryption key to cb().
    virtual bool WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const = 0;
    virtual bool HasEncryptionKeys() const = 0;
    virtual bool IsLocked() const = 0;
    //! Callback function for after TopUp completes containing any scripts that were added by a SPKMan
    virtual void TopUpCallback(const std::set<CScript>&, ScriptPubKeyMan*) = 0;
    //! Number of unused MWEB addresses an MWEB account watches past its next index (-mwebkeypool)
    virtual int64_t GetMWEBKeypoolSize() const;
};

//! Constant representing an unknown spkm creation time
inline constexpr int64_t UNKNOWN_TIME = std::numeric_limits<int64_t>::max();

//! Default for -keypool
inline constexpr unsigned int DEFAULT_KEYPOOL_SIZE = 1000;

inline int64_t WalletStorage::GetMWEBKeypoolSize() const { return DEFAULT_KEYPOOL_SIZE; }

struct WalletDestination
{
    CTxDestination dest;
    std::optional<bool> internal;
};

/*
 * A class implementing ScriptPubKeyMan manages some (or all) scriptPubKeys used in a wallet.
 * It contains the scripts and keys related to the scriptPubKeys it manages.
 * A ScriptPubKeyMan will be able to give out scriptPubKeys to be used, as well as marking
 * when a scriptPubKey has been used. It also handles when and how to store a scriptPubKey
 * and its related scripts and keys, including encryption.
 */
class ScriptPubKeyMan
{
protected:
    WalletStorage& m_storage;
    mw::Keychain::Ptr m_mwebKeychain; // MWEB hooks

public:
    explicit ScriptPubKeyMan(WalletStorage& storage) : m_storage(storage), m_mwebKeychain(nullptr) {}
    virtual ~ScriptPubKeyMan() = default;
    virtual util::Result<CTxDestination> GetNewDestination(const OutputType type) { return util::Error{Untranslated("Not supported")}; }
    //! MWEB: The destination GetNewDestination would return next, without taking it.
    virtual util::Result<CTxDestination> PeekNewDestination(const OutputType type) const { return util::Error{Untranslated("Not supported")}; }
    virtual bool IsMine(const CScript& script) const { return false; }
    virtual bool IsMine(const CTxDestination& dest) const { return false; }

    //! Check that the given decryption key is valid for this ScriptPubKeyMan, i.e. it decrypts all of the keys handled by it.
    virtual bool CheckDecryptionKey(const CKeyingMaterial& master_key) { return false; }
    virtual bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) { return false; }

    virtual util::Result<CTxDestination> GetReservedDestination(const OutputType type, bool internal, int64_t& index) { return util::Error{Untranslated("Not supported")}; }
    virtual void KeepDestination(int64_t index, const OutputType& type) {}
    virtual void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) {}

    /** Fills internal address pool. Use within ScriptPubKeyMan implementations should be used sparingly and only
      * when something from the address pool is removed, excluding GetNewDestination and GetReservedDestination.
      * External wallet code is primarily responsible for topping up prior to fetching new addresses
      */
    virtual bool TopUp(unsigned int size = 0) { return false; }

    /** Mark unused addresses as being used
     * Affects all keys up to and including the one determined by provided script.
     *
     * @param script determines the last key to mark as used
     *
     * @return All of the addresses affected
     */
    virtual std::vector<WalletDestination> MarkUnusedAddresses(const CScript& script) { return {}; }

    /* Returns true if HD is enabled */
    virtual bool IsHDEnabled() const { return false; }

    /* Returns true if the wallet can give out new addresses. This means it has keys in the keypool or can generate new keys */
    virtual bool CanGetAddresses(bool internal = false) const { return false; }

    virtual bool HavePrivateKeys() const { return false; }
    virtual bool HaveCryptedKeys() const { return false; }

    virtual unsigned int GetKeyPoolSize() const { return 0; }

    virtual int64_t GetTimeFirstKey() const { return 0; }

    virtual std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const { return nullptr; }

    // MWEB hooks
    virtual void LoadMWEBKeychain() { }
    virtual const mw::Keychain::Ptr& GetMWEBKeychain() const noexcept { return m_mwebKeychain; }

    virtual std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const { return nullptr; }

    /** Whether this ScriptPubKeyMan can provide a SigningProvider (via GetSolvingProvider) that, combined with
      * sigdata, can produce solving data.
      */
    virtual bool CanProvide(const CScript& script, SignatureData& sigdata) { return false; }

    /** Creates new signatures and adds them to the transaction. Returns whether all inputs were signed */
    virtual bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const { return false; }
    /** Sign a message with the given script */
    virtual SigningResult SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const { return SigningResult::SIGNING_FAILED; };
    /** Adds script and derivation path information to a PSBT, and optionally signs it. */
    virtual std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed = nullptr) const { return common::PSBTError::UNSUPPORTED; }

    virtual uint256 GetID() const { return uint256(); }

    /** Returns a set of all the scriptPubKeys that this ScriptPubKeyMan watches */
    virtual std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const { return {}; };

    /** Prepends the wallet name in logging output to ease debugging in multi-wallet use cases */
    template <typename... Params>
    void WalletLogPrintf(util::ConstevalFormatString<sizeof...(Params)> wallet_fmt, const Params&... params) const
    {
        LogInfo("[%s] %s", m_storage.LogName(), tfm::format(wallet_fmt, params...));
    };

    /** Keypool has new keys */
    btcsignals::signal<void ()> NotifyCanGetAddressesChanged;

    /** Birth time changed */
    btcsignals::signal<void (const ScriptPubKeyMan* spkm, int64_t new_birth_time)> NotifyFirstKeyTimeChanged;
};

/** Output types associated with LegacyDataSPKM. */
inline const std::unordered_set<OutputType> LEGACY_OUTPUT_TYPES {
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
};

using KeyMap = std::map<CKeyID, CKey>;
using CryptedKeyMap = std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>;

// Manages the minimum data needed to load and migrate a legacy wallet.
class LegacyDataSPKM : public ScriptPubKeyMan, public FillableSigningProvider
{
private:
    using WatchOnlySet = std::set<CScript>;
    using WatchKeyMap = std::map<CKeyID, CPubKey>;

    CryptedKeyMap mapCryptedKeys GUARDED_BY(cs_KeyStore);
    WatchOnlySet setWatchOnly GUARDED_BY(cs_KeyStore);
    WatchKeyMap mapWatchKeys GUARDED_BY(cs_KeyStore);

    /* the HD chain data model (external chain counters) */
    CHDChain m_hd_chain;
    std::unordered_map<CKeyID, CHDChain, SaltedSipHasher> m_inactive_hd_chains;

    //! keeps track of whether Unlock has run a thorough check before
    bool fDecryptionThoroughlyChecked = true;

    bool AddWatchOnlyInMem(const CScript &dest);
    virtual bool AddKeyPubKeyInner(const CKey& key, const CPubKey &pubkey);
    bool AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

    // Helper function to retrieve a conservative superset of all output scripts that may be relevant to this LegacyDataSPKM.
    // It may include scripts that are invalid or not actually watched by this LegacyDataSPKM.
    // Used only in migration.
    std::unordered_set<CScript, SaltedSipHasher> GetCandidateScriptPubKeys() const;

    // Keep the base destination overload visible. Legacy wallets do not own
    // Stealth destinations; CWallet::IsMine routes those to MWEB descriptors.
    using ScriptPubKeyMan::IsMine;
    bool IsMine(const CScript& script) const override;
    bool CanProvide(const CScript& script, SignatureData& sigdata) override;
public:
    using ScriptPubKeyMan::ScriptPubKeyMan;

    // Map from Key ID to key metadata.
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata GUARDED_BY(cs_KeyStore);

    // Map from Script ID to key metadata (for watch-only keys).
    std::map<CScriptID, CKeyMetadata> m_script_metadata GUARDED_BY(cs_KeyStore);

    // ScriptPubKeyMan overrides
    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;
    uint256 GetID() const override { return uint256::ONE; }

    // FillableSigningProvider overrides
    bool HaveKey(const CKeyID &address) const override;
    bool GetKey(const CKeyID &address, CKey& keyOut) const override;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override;

    //! Load metadata (used by LoadWallet)
    virtual void LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &metadata);
    virtual void LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &metadata);

    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);
    //! Returns whether the watch-only script is in the wallet
    bool HaveWatchOnly(const CScript &dest) const;
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid);
    //! Adds a CScript to the store
    bool LoadCScript(const CScript& redeemScript);
    //! Load a HD chain model (used by LoadWallet)
    void LoadHDChain(const CHDChain& chain);
    void AddInactiveHDChain(const CHDChain& chain);
    const CHDChain& GetHDChain() const { return m_hd_chain; }

    //! Fetches a pubkey from mapWatchKeys if it exists there
    bool GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const;

    /**
     * Retrieves scripts that were imported by bugs into the legacy spkm and are
     * simply invalid, such as a sh(sh(pkh())) script, or not watched.
     */
    std::unordered_set<CScript, SaltedSipHasher> GetNotMineScriptPubKeys() const;

    /** Get the DescriptorScriptPubKeyMans (with private keys) that have the same scriptPubKeys as this LegacyDataSPKM.
     * Does not modify this LegacyDataSPKM. */
    std::optional<MigrationData> MigrateToDescriptor();
    /** Delete the legacy wallet records from disk. */
    bool DeleteRecordsWithDB(WalletBatch& batch);
};

/** SigningProvider wrapper for LegacyDataSPKM that does not provide private keys. */
class LegacySigningProvider : public SigningProvider
{
private:
    const LegacyDataSPKM& m_spk_man;
public:
    explicit LegacySigningProvider(const LegacyDataSPKM& spk_man) : m_spk_man(spk_man) {}

    bool GetCScript(const CScriptID &scriptid, CScript& script) const override { return m_spk_man.GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID &scriptid) const override { return m_spk_man.HaveCScript(scriptid); }
    bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const override { return m_spk_man.GetPubKey(address, pubkey); }
    bool GetKey(const CKeyID &address, CKey& key) const override { return false; }
    bool HaveKey(const CKeyID &address) const override { return false; }
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return m_spk_man.GetKeyOrigin(keyid, info); }
};

class DescriptorScriptPubKeyMan : public ScriptPubKeyMan
{
public:
    enum class MWEBInternalProtect : uint8_t { NONE, MANUAL, KEEP };

private:
    using ScriptPubKeyMap = std::map<CScript, int32_t>; // Map of scripts to descriptor range index
    using PubKeyMap = std::map<CPubKey, int32_t>; // Map of pubkeys involved in scripts to descriptor range index
    using MWEBAddressMap = std::map<StealthAddress, int32_t>;

    ScriptPubKeyMap m_map_script_pub_keys GUARDED_BY(cs_desc_man);
    PubKeyMap m_map_pubkeys GUARDED_BY(cs_desc_man);
    MWEBAddressMap m_map_mweb_addresses GUARDED_BY(cs_desc_man);
    std::map<CKeyID, CKeyMetadata> m_map_mweb_metadata GUARDED_BY(cs_desc_man);
    std::map<uint32_t, WalletDescriptor> m_mweb_internal_descriptors GUARDED_BY(cs_desc_man);
    std::set<uint32_t> m_ephemeral_mweb_indices GUARDED_BY(cs_desc_man);
    //! Unused account indices watched for payments, with their derived addresses. Never persisted.
    std::map<uint32_t, StealthAddress> m_mweb_lookahead GUARDED_BY(cs_desc_man);
    //! Supporting account of indexed imports: discover only explicitly registered addresses.
    bool m_mweb_limited_account GUARDED_BY(cs_desc_man){false};
    std::set<uint32_t> m_mweb_scan_active_indices GUARDED_BY(cs_desc_man);
    std::map<uint32_t, int64_t> m_mweb_internal_last_active GUARDED_BY(cs_desc_man);
    std::map<uint32_t, MWEBInternalProtect> m_mweb_internal_protect GUARDED_BY(cs_desc_man);
    int32_t m_max_cached_index = -1;

    bool m_internal{false};
    SecretKey m_mweb_scan_secret;
    //! The scan secret in the mwebscank record, as last read or written.
    SecretKey m_mweb_scan_secret_on_disk;
    std::optional<std::string> m_mweb_keychain_error;

    //! Composed IMWEBKeyStore for mw::Keychain (avoids MI into DescriptorScriptPubKeyMan).
    class MWEBKeyStoreAdapter final : public IMWEBKeyStore
    {
        DescriptorScriptPubKeyMan& m_parent;
    public:
        explicit MWEBKeyStoreAdapter(DescriptorScriptPubKeyMan& parent) : m_parent(parent) {}
        std::unique_ptr<CKeyMetadata> GetMetadata(const StealthAddress& addr) const override
        {
            return m_parent.GetMetadata(addr);
        }
        bool GetKey(const CKeyID& id, CKey& keyOut) const override { return m_parent.GetKey(id, keyOut); }
        bool HaveKey(const CKeyID& id) const override { return m_parent.HaveKey(id); }
    };
    MWEBKeyStoreAdapter m_mweb_keystore{*this};

    KeyMap m_map_keys GUARDED_BY(cs_desc_man);
    CryptedKeyMap m_map_crypted_keys GUARDED_BY(cs_desc_man);

    //! keeps track of whether Unlock has run a thorough check before
    bool m_decryption_thoroughly_checked = false;

    //! Number of pre-generated keys/scripts (part of the look-ahead process, used to detect payments)
    int64_t m_keypool_size GUARDED_BY(cs_desc_man){DEFAULT_KEYPOOL_SIZE};

    /** Map of a session id to MuSig2 secnonce
     *
     * Stores MuSig2 secnonces while the MuSig2 signing session is still ongoing.
     * Note that these secnonces must not be reused. In order to avoid being tricked into
     * reusing a nonce, this map is held only in memory and must not be written to disk.
     * The side effect is that signing sessions cannot persist across restarts, but this
     * must be done in order to prevent nonce reuse.
     *
     * The session id is an arbitrary value set by the signer in order for the signing logic
     * to find ongoing signing sessions, see MuSig2SessionID.
     */
    mutable std::map<uint256, MuSig2SecNonce> m_musig2_secnonces;

    const uint256 m_id;

    KeyMap GetKeys() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    // Cached FlatSigningProviders to avoid regenerating them each time they are needed.
    mutable std::map<int32_t, FlatSigningProvider> m_map_signing_providers;
    // Fetch the SigningProvider for the given script and optionally include private keys
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CScript& script, bool include_private = false) const;
    // Fetch the SigningProvider for a given index and optionally include private keys. Called by the above functions.
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(int32_t index, bool include_private = false) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    void Load();

    void UpdateWithSigningProvider(WalletBatch& batch, const FlatSigningProvider& signing_provider) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    bool KeyIsMWEBSeed(const KeyMap& keys, const CKey& key) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::optional<CKey> FindMWEBWalletSeed(const KeyMap& keys) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! Origins of keys of this MWEB entry's descriptor; nullopt for a key without an origin of its own.
    std::vector<std::optional<KeyOriginInfo>> GetMWEBKeyOrigins(const std::vector<CPubKey>& pubkeys) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::string FormatMWEBKeyOrigin(const std::optional<KeyOriginInfo>& origin) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::optional<CKey> GetMWEBScanKey() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! "[origin]<scan WIF>" of any MWEB entry that holds the scan secret.
    std::optional<std::string> GetMWEBScanKeyExpression() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! "[origin]<scan WIF>" and "[origin]<spend pubkey hex>" of an MWEB account.
    std::optional<std::pair<std::string, std::string>> GetMWEBAccountKeyExpressions() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! The account's spend pubkey from its descriptor or, for a hardened spend path, the descriptor cache.
    std::optional<PublicKey> GetMWEBAccountSpendPubKey() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! Why the account's internal records do not match keychain, if they do not.
    std::optional<std::string> VerifyMWEBInternalRecords(const mw::Keychain& keychain) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void RefuseMWEBKeychain(std::string error) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void ClearMWEBLookahead() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

protected:
    //! Create a DescriptorScriptPubKeyMan from existing data (i.e. during loading)
    DescriptorScriptPubKeyMan(WalletStorage& storage, const uint256& id, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys);

    //! Create a new DescriptorScriptPubKeyMan from a descriptor (e.g. from an import, newly generated)
    DescriptorScriptPubKeyMan(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size)
        : ScriptPubKeyMan(storage),
        m_keypool_size(keypool_size),
        m_id(CompatDescriptorHash(*descriptor.descriptor)),
        m_wallet_descriptor(descriptor)
    {}

    WalletDescriptor m_wallet_descriptor GUARDED_BY(cs_desc_man);
    void IncIndex() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void DecIndex() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void SetRangeEnd(int32_t end) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    //! Same as 'TopUp' but designed for use within a batch transaction context
    bool TopUpWithDB(WalletBatch& batch, unsigned int size = 0);

public:
    static std::unique_ptr<DescriptorScriptPubKeyMan> LoadFromStorage(WalletStorage& storage, const uint256& id, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys);
    static std::unique_ptr<DescriptorScriptPubKeyMan> CreateFromImport(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider, bool internal);
    static std::unique_ptr<DescriptorScriptPubKeyMan> CreateMWEBSupportingAccount(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider);
    static std::unique_ptr<DescriptorScriptPubKeyMan> CreateFromMigration(WalletStorage& storage, WalletBatch& batch, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider);
    static std::unique_ptr<DescriptorScriptPubKeyMan> GenerateNewSingleSig(WalletStorage& storage, WalletBatch& batch, int64_t keypool_size, const CExtKey& master_key, OutputType addr_type, bool internal);

    mutable RecursiveMutex cs_desc_man;

    util::Result<CTxDestination> GetNewDestination(OutputType type) override;
    util::Result<CTxDestination> PeekNewDestination(OutputType type) const override; // MWEB
    bool IsMine(const CScript& script) const override;
    bool IsMine(const CTxDestination& dest) const override;

    void LoadMWEBKeychain() override;
    void RestoreMWEBSpendKeysAfterUnlock();
    /** Validate and load a wallet-internal mweb(A_i,B_i,i,acct_cksum) record.
     *  Rejects keys that do not match account derivation (or DKSAP self-check
     *  when watch-only). Reserved change/pegin index rejection is enforced at
     *  the importdescriptors RPC boundary so wallet DB reload of indices 0/1
     *  still succeeds. */
    util::Result<void> LoadMWEBInternalDescriptorRecord(const WalletDescriptor& descriptor) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::vector<const WalletDescriptor*> GetMWEBInternalWalletDescriptors() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    bool IsMWEBDescriptor() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool IsMWEBAccountDescriptor() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool IsMWEBLimitedAccount() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) { return m_mweb_limited_account; }
    void LoadMWEBLimitedAccountRecord() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool EnableMWEBAccountDiscovery(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** ACCOUNT, INDEXED, or SINGLE_SUBADDR — can identify/scan (not INTERNAL). */
    bool IsMWEBCapabilityDescriptor() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::string GetMWEBAccountChecksum() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    const mw::Keychain* GetMWEBKeychainForExpansion() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void InitMWEBReservedIndices(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool PersistMWEBInternalIndex(WalletBatch& batch, uint32_t index, const StealthAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** The index at which this account derives addr: its recorded index, else a search of indices
     *  below max(1024, keypool size) and of a keypool-sized band around the next index. */
    std::optional<uint32_t> FindMWEBAccountAddressIndex(const StealthAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** Store the master spend secret of an account that holds only B, so the account can spend.
     *  Fails unless spend_secret*G == B and the account's spend key expression resolves to it. */
    util::Result<void> AddMWEBAccountSpendSecret(WalletBatch& batch, const SecretKey& spend_secret) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void ReloadMWEBScanMapsFromInternalDescriptors() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void RegisterMWEBSingleSubaddress(const SigningProvider& provider) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool TopUpMWEBWithDB(WalletBatch& batch, unsigned int size) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool RegisterEphemeralMWEBIndex(uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool RegisterEphemeralMWEBIndexRange(uint32_t from, uint32_t to_inclusive) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void UnregisterEphemeralMWEBIndex(uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void ClearEphemeralMWEBIndices() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void ResetMWEBScanState() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void MarkMWEBIndexActive(uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    uint32_t CommitActiveMWEBIndices(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void EnsureMWEBNextIndexAtLeast(uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** Watch the account's unused indices from one lookahead window below the next index up to
     *  max(range end, next index + lookahead size), in memory only. */
    void RegisterMWEBLookahead() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** When a payment reaches index or beyond the next index, move the next index past it and
     *  top up the lookahead. Returns whether the next index moved. */
    bool AdvanceMWEBNextIndexPast(WalletBatch& batch, uint32_t index) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    size_t GetMWEBLookaheadCount() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void SetMWEBInternalProtect(uint32_t index, MWEBInternalProtect flag) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void SetMWEBInternalProtectMemory(uint32_t index, MWEBInternalProtect flag) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    MWEBInternalProtect GetMWEBInternalProtect(uint32_t index) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void UpdateMWEBInternalActivity(uint32_t index, int64_t activity_time) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    int64_t GetMWEBInternalLastActive(uint32_t index) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    size_t GetMWEBInternalDescriptorCount() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    size_t PruneMWEBInternalDescriptors(WalletBatch& batch, size_t& global_count, size_t global_threshold, int64_t inactivity_secs,
        const std::function<bool(uint32_t)>& has_unspent) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** getaddressinfo's desc for one of this entry's addresses: mweb([origin]<scan WIF>,[origin]<spend pubkey>,index)
     *  when an account derives it, otherwise mweb([origin]<scan WIF>,<address spend pubkey>). */
    std::optional<std::string> GetMWEBAddressInfoDescriptor(const StealthAddress& addr) const;
    /** getaddressinfo's parent_desc: the account's watch-only form, or a separate entry's own address descriptor. */
    std::optional<std::string> GetMWEBParentDescriptor(const StealthAddress& addr) const;
    std::optional<KeyOriginInfo> GetMWEBScanKeyOrigin() const;
    /** The single-address mweb([origin]<scan WIF>,[origin]<spend pubkey>,index) descriptor of an account's subaddress. */
    std::optional<std::string> GetMWEBAddressDescriptor(uint32_t index) const;
    /** The account as mweb([origin]<scan WIF>,[origin]<spend pubkey>,*), importable into a watch-only wallet. */
    std::optional<std::string> GetMWEBAccountWatchOnlyDescriptor() const;
    bool HasMWEBScanCapability() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    SecretKey GetMWEBScanSecret() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    void LoadMWEBScanSecretRecord(const SecretKey& scan_secret) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** Write what the entry needs to scan and describe its addresses while locked: the descriptor cache
     *  of its hardened keys, then the mwebscank record when the wallet has none. */
    bool PersistMWEBLockedMaterial(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    /** Why the keys contradict the wallet's records, if they do: the scan secret derived from the keys
     *  differs from the mwebscank record, the decrypted spend key does not match the spend pubkey the
     *  keychain already used, or an internal record does not match the account's keychain. The entry
     *  then has no keychain until the wallet is reloaded. */
    std::optional<std::string> CheckMWEBKeychain() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool SetMWEBScanSecret(WalletBatch& batch, const SecretKey& scan_secret) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool TryExtractMWEBScanSecretFromProvider(WalletBatch& batch, const FlatSigningProvider& signing_provider) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);

    //! MWEB keystore surface used by mw::Keychain (composed; not MI into ScriptPubKeyMan).
    std::unique_ptr<CKeyMetadata> GetMetadata(const StealthAddress& addr) const;
    bool GetKey(const CKeyID& id, CKey& keyOut) const;
    bool HaveKey(const CKeyID& id) const;

    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) override;

    util::Result<CTxDestination> GetReservedDestination(OutputType type, bool internal, int64_t& index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;

    // Tops up the descriptor cache and m_map_script_pub_keys. The cache is stored in the wallet file
    // and is used to expand the descriptor in GetNewDestination. Descriptor wallets rely more on
    // ephemeral data than legacy wallets. For wallets using unhardened derivation
    // (with or without private keys), the "keypool" is a single xpub.
    bool TopUp(unsigned int size = 0) override;

    std::vector<WalletDestination> MarkUnusedAddresses(const CScript& script) override;

    bool IsHDEnabled() const override;

    bool HavePrivateKeys() const override;
    bool HasPrivKey(const CKeyID& keyid) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! Retrieve the particular key if it is available. Returns nullopt if the key is not in the wallet, or if the wallet is locked.
    std::optional<CKey> LookupPrivKey(const CKeyID& keyid) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool HaveCryptedKeys() const override;

    unsigned int GetKeyPoolSize() const override;

    int64_t GetTimeFirstKey() const override;

    std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const override;

    bool CanGetAddresses(bool internal = false) const override;

    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;

    // Fetch the SigningProvider for the given pubkey and always include private keys. This should only be called by signing code.
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CPubKey& pubkey) const;

    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const override;
    SigningResult SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const override;
    std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed = nullptr) const override;

    uint256 GetID() const override;

    bool HasWalletDescriptor(const WalletDescriptor& desc) const;
    util::Result<void> UpdateWalletDescriptor(WalletDescriptor& descriptor, const FlatSigningProvider& provider);
    bool CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error);
    void WriteDescriptor();

    WalletDescriptor GetWalletDescriptor() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys(int32_t minimum_index) const;
    int32_t GetEndRange() const;

    [[nodiscard]] bool GetDescriptorString(std::string& out, bool priv) const;

    void UpgradeDescriptorCache();

    void SetInternal(bool internal) { LOCK(cs_desc_man); m_internal = internal; }
};

/** struct containing information needed for migrating legacy wallets to descriptor wallets */
struct MigrationData
{
    CExtKey master_key;
    std::vector<std::pair<std::string, int64_t>> watch_descs;
    std::vector<std::pair<std::string, int64_t>> solvable_descs;
    std::vector<std::unique_ptr<DescriptorScriptPubKeyMan>> desc_spkms;
    std::shared_ptr<CWallet> watchonly_wallet{nullptr};
    std::shared_ptr<CWallet> solvable_wallet{nullptr};
};

} // namespace wallet

#endif // BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
