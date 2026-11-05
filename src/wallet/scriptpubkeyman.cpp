// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scriptpubkeyman.h>

#include <coins.h>
#include <hash.h>
#include <key_io.h>
#include <node/types.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/mweb_descriptor.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/log.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/mweb_keychain_util.h>

#include <mw/models/wallet/coin.h>

using common::PSBTError;
using util::ToString;

namespace wallet {

typedef std::vector<unsigned char> valtype;

// Legacy wallet IsMine(). Used only in migration
// DO NOT USE ANYTHING IN THIS NAMESPACE OUTSIDE OF MIGRATION
namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
};

bool PermitsUncompressed(IsMineSigVersion sigversion)
{
    return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
}

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyDataSPKM& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

//! Recursively solve script and return spendable/watchonly/invalid status.
//!
//! @param keystore            legacy key and script store
//! @param scriptPubKey        script to solve
//! @param sigversion          script type (top-level / redeemscript / witnessscript)
//! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
//!                            scripts or simply treat any script that has been
//!                            stored in the keystore as spendable
// NOLINTNEXTLINE(misc-no-recursion)
IsMineResult LegacyWalletIsMineInnerDONOTUSE(const LegacyDataSPKM& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash=true)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
    case TxoutType::WITNESS_MWEB_PEGIN:
    case TxoutType::WITNESS_MWEB_HOGADDR:
    case TxoutType::ANCHOR:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
            return IsMineResult::INVALID;
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, LegacyWalletIsMineInnerDONOTUSE(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TxoutType::PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!PermitsUncompressed(sigversion)) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                return IsMineResult::INVALID;
            }
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        CScriptID scriptID{RIPEMD160(vSolutions[0])};
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
        }
        break;
    }

    case TxoutType::MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (!PermitsUncompressed(sigversion)) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    return IsMineResult::INVALID;
                }
            }
        }
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    } // no default case, so the compiler can warn about missing cases

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

bool LegacyDataSPKM::IsMine(const CScript& script) const
{
    switch (LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return false;
    case IsMineResult::WATCH_ONLY:
    case IsMineResult::SPENDABLE:
        return true;
    }
    assert(false);
}

bool LegacyDataSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(master_key, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail)
        {
            LogWarning("The wallet is probably corrupted: Some keys decrypt but not all.");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || !keyPass)
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

std::unique_ptr<SigningProvider> LegacyDataSPKM::GetSolvingProvider(const CScript& script) const
{
    return std::make_unique<LegacySigningProvider>(*this);
}

bool LegacyDataSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    IsMineResult ismine = LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP, /* recurse_scripthash= */ false);
    if (ismine == IsMineResult::SPENDABLE || ismine == IsMineResult::WATCH_ONLY) {
        // If ismine, it means we recognize keys or script ids in the script, or
        // are watching the script itself, and we can at least provide metadata
        // or solving information, even if not able to sign fully.
        return true;
    } else {
        // If, given the stuff in sigdata, we could make a valid signature, then we can provide for this script
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, script, sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have a private key to actually make a signature
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

bool LegacyDataSPKM::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyDataSPKM::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyDataSPKM::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    mapKeyMetadata[keyID] = meta;
}

void LegacyDataSPKM::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    m_script_metadata[script_id] = meta;
}

bool LegacyDataSPKM::AddKeyPubKeyInner(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    return FillableSigningProvider::AddKeyPubKey(key, pubkey);
}

bool LegacyDataSPKM::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyDataSPKM::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyDataSPKM::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.contains(dest);
}

bool LegacyDataSPKM::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return Solver(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}

bool LegacyDataSPKM::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

void LegacyDataSPKM::LoadHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    m_hd_chain = chain;
}

void LegacyDataSPKM::AddInactiveHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    assert(!chain.seed_id.IsNull());
    m_inactive_hd_chains[chain.seed_id] = chain;
}

bool LegacyDataSPKM::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.contains(address);
}

bool LegacyDataSPKM::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, vchCryptedSecret, vchPubKey, keyOut);
        });
    }
    return false;
}

bool LegacyDataSPKM::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_KeyStore);
        auto it = mapKeyMetadata.find(keyID);
        if (it == mapKeyMetadata.end()) {
            return false;
        }
        meta = it->second;
    }
    if (meta.has_key_origin) {
        info.fingerprint = meta.key_origin.fingerprint;
        info.path = meta.key_origin.path;
    } else { // Single pubkeys get the master fingerprint of themselves
        info.fingerprint = keyID.fingerprint();
    }
    return true;
}

bool LegacyDataSPKM::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyDataSPKM::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetCandidateScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> candidate_spks;

    // For every private key in the wallet, there should be a P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH
    const auto& add_pubkey = [&candidate_spks](const CPubKey& pub) -> void {
        candidate_spks.insert(GetScriptForRawPubKey(pub));
        candidate_spks.insert(GetScriptForDestination(PKHash(pub)));

        CScript wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
        candidate_spks.insert(wpkh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wpkh)));
    };
    for (const auto& [_, key] : mapKeys) {
        add_pubkey(key.GetPubKey());
    }
    for (const auto& [_, ckeypair] : mapCryptedKeys) {
        add_pubkey(ckeypair.first);
    }

    // mapScripts contains all redeemScripts and witnessScripts. Therefore each script in it has
    // itself, P2SH, P2WSH, and P2SH-P2WSH as a candidate.
    // Invalid scripts such as P2SH-P2SH and P2WSH-P2SH, among others, will be added as candidates.
    // Callers of this function will need to remove such scripts.
    const auto& add_script = [&candidate_spks](const CScript& script) -> void {
        candidate_spks.insert(script);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(script)));

        CScript wsh = GetScriptForDestination(WitnessV0ScriptHash(script));
        candidate_spks.insert(wsh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wsh)));
    };
    for (const auto& [_, script] : mapScripts) {
        add_script(script);
    }

    // Although setWatchOnly should only contain output scripts, we will also include each script's
    // P2SH, P2WSH, and P2SH-P2WSH as a precaution.
    for (const auto& script : setWatchOnly) {
        add_script(script);
    }

    return candidate_spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetScriptPubKeys() const
{
    // Run IsMine() on each candidate output script. Any script that IsMine is an output
    // script to return.
    // This both filters out things that are not watched by the wallet, and things that are invalid.
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        if (IsMine(script)) {
            spks.insert(script);
        }
    }

    return spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetNotMineScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : setWatchOnly) {
        if (!IsMine(script)) spks.insert(script);
    }
    return spks;
}

std::optional<MigrationData> LegacyDataSPKM::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<CScript, SaltedSipHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    // Get key metadata and figure out which keys don't have a seed
    // Note that we do not ignore the seeds themselves because they are considered IsMine!
    for (auto keyid_it = keyids.begin(); keyid_it != keyids.end();) {
        const CKeyID& keyid = *keyid_it;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            const CKeyMetadata& meta = it->second;
            if (meta.hdKeypath == "s" || meta.hdKeypath == "m") {
                keyid_it++;
                continue;
            }
            if (!meta.hd_seed_id.IsNull() && (m_hd_chain.seed_id == meta.hd_seed_id || m_inactive_hd_chains.contains(meta.hd_seed_id))) {
                keyid_it = keyids.erase(keyid_it);
                continue;
            }
        }
        keyid_it++;
    }

    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) {
        LogWarning("Error generating descriptors for migration, cannot initialize db transaction");
        return std::nullopt;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Get the key origin
        // Maybe this doesn't matter because floating keys here shouldn't have origins
        KeyOriginInfo info;
        bool has_info = GetKeyOrigin(keyid, info);
        std::string origin_str = has_info ? "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.path) + "]" : "";

        // Construct the combo descriptor
        std::string desc_str = "combo(" + origin_str + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider provider;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, provider, error, false);
        CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
        WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        provider.keys.emplace(key.GetPubKey().GetID(), key);
        auto desc_spk_man = DescriptorScriptPubKeyMan::CreateFromMigration(m_storage, batch, w_desc, /*keypool_size=*/0, provider);
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const CScript& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk));
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle HD keys by using the CHDChains
    std::set<CHDChain> chains;
    chains.insert(m_hd_chain);
    for (const auto& chain_pair : m_inactive_hd_chains) {
        chains.insert(chain_pair.second);
    }

    bool can_support_hd_split_feature = m_hd_chain.nVersion >= CHDChain::VERSION_HD_CHAIN_SPLIT;

    std::set<CExtPubKey> master_xpubs;
    for (const CHDChain& chain : chains) {
        if (chain.seed_id.IsNull()) continue;

        // Get the master xprv
        CKey seed_key;
        if (!GetKey(chain.seed_id, seed_key)) {
            assert(false);
        }
        CExtKey master_key;
        master_key.SetSeed(seed_key);

        // Get the xpub and verify that we haven't already seen this xpub before
        CExtPubKey master_xpub = master_key.Neuter();
        const auto& [_, inserted] = master_xpubs.insert(master_xpub);
        if (!inserted) continue;

        for (int i = 0; i < 2; ++i) {
            // Skip if doing internal chain and split chain is not supported
            if (i == 1 && !can_support_hd_split_feature) {
                continue;
            }

            // Make the combo descriptor
            std::string xpub = EncodeExtPubKey(master_key.Neuter());
            std::string desc_str = "combo(" + xpub + "/0h/" + ToString(i) + "h/*h)";
            FlatSigningProvider provider;
            std::string error;
            std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, provider, error, false);
            CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
            uint32_t chain_counter = std::max((i == 1 ? chain.nInternalChainCounter : chain.nExternalChainCounter), (uint32_t)0);
            WalletDescriptor w_desc(std::move(descs.at(0)), 0, 0, chain_counter, 0);

            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            provider.keys.emplace(master_key.key.GetPubKey().GetID(), master_key.key);
            auto desc_spk_man = DescriptorScriptPubKeyMan::CreateFromMigration(m_storage, batch, w_desc, /*keypool_size=*/0, provider);
            auto desc_spks = desc_spk_man->GetScriptPubKeys();

            // Remove the scriptPubKeys from our current set
            for (const CScript& spk : desc_spks) {
                size_t erased = spks.erase(spk);
                assert(erased == 1);
                assert(IsMine(spk));
            }

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }
    }
    // Add the current master seed to the migration data
    if (!m_hd_chain.seed_id.IsNull()) {
        CKey seed_key;
        if (!GetKey(m_hd_chain.seed_id, seed_key)) {
            assert(false);
        }
        out.master_key.SetSeed(seed_key);
    }

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const CScript& spk = *it;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk));
        if (mit != m_script_metadata.end()) {
            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed.
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error);
            if (parsed_descs.empty()) {
                // Remove this scriptPubKey from the set
                it = spks.erase(it);
                continue;
            }
        }

        // Get the private keys for this descriptor
        std::vector<CScript> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_orig_pair : keys.origins) {
            privkeyids.insert(key_orig_pair.first);
        }

        std::vector<CScript> desc_spks;

        // If we can't provide all private keys for this inferred descriptor,
        // but this wallet is not watch-only, migrate it to the watch-only wallet.
        if (!desc->HavePrivateKeys(*this) && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.emplace_back(desc->ToString(), creation_time);

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                keys.keys.emplace(key.GetPubKey().GetID(), key);
            }
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = DescriptorScriptPubKeyMan::CreateFromMigration(m_storage, batch, w_desc, /*keypool_size=*/0, keys);
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const CScript& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk));
            it = spks.erase(del_it);
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    if (!Assume(spks.empty())) {
        LogError("%s", STR_INTERNAL_BUG("Error: Some output scripts were not migrated."));
        return std::nullopt;
    }

    // Legacy wallets can also contain scripts whose P2SH, P2WSH, or P2SH-P2WSH it is not watching for
    // but can provide script data to a PSBT spending them. These "solvable" output scripts will need to
    // be put into the separate "solvables" wallet.
    // These can be detected by going through the entire candidate output scripts, finding the not IsMine scripts,
    // and checking CanProvide() which will dummy sign.
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        // Since we only care about P2SH, P2WSH, and P2SH-P2WSH, filter out any scripts that are not those
        if (!script.IsPayToScriptHash() && !script.IsPayToWitnessScriptHash()) {
            continue;
        }
        if (IsMine(script)) {
            continue;
        }
        SignatureData dummy_sigdata;
        if (!CanProvide(script, dummy_sigdata)) {
            continue;
        }

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(script, *GetSolvingProvider(script));
        if (!desc->IsSolvable()) {
            // The wallet was able to provide some information, but not enough to make a descriptor that actually
            // contains anything useful. This is probably because the script itself is actually unsignable (e.g. P2WSH-P2WSH).
            continue;
        }

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error, false);
            if (parsed_descs.empty()) {
                continue;
            }
        }

        out.solvable_descs.emplace_back(desc->ToString(), creation_time);
    }

    // Finalize transaction
    if (!batch.TxnCommit()) {
        LogWarning("Error generating descriptors for migration, cannot commit db transaction");
        return std::nullopt;
    }

    return out;
}

bool LegacyDataSPKM::DeleteRecordsWithDB(WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    return batch.EraseRecords(DBKeys::LEGACY_TYPES);
}

std::unique_ptr<DescriptorScriptPubKeyMan> DescriptorScriptPubKeyMan::CreateFromImport(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider, bool internal)
{
    auto spkm = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(storage, descriptor, keypool_size));
    LOCK(spkm->cs_desc_man);
    spkm->m_internal = internal;
    WalletBatch batch(storage.GetDatabase());
    spkm->UpdateWithSigningProvider(batch, provider);
    return spkm;
}

std::unique_ptr<DescriptorScriptPubKeyMan> DescriptorScriptPubKeyMan::CreateFromMigration(WalletStorage& storage, WalletBatch& batch, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider)
{
    auto spkm = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(storage, descriptor, keypool_size));
    LOCK(spkm->cs_desc_man);
    spkm->UpdateWithSigningProvider(batch, provider);
    return spkm;
}

std::unique_ptr<DescriptorScriptPubKeyMan> DescriptorScriptPubKeyMan::CreateMWEBSupportingAccount(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider)
{
    auto spkm = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(storage, descriptor, keypool_size));
    LOCK(spkm->cs_desc_man);
    CHECK_NONFATAL(spkm->IsMWEBAccountDescriptor());
    spkm->m_mweb_limited_account = true;
    // Commit the discovery restriction with its descriptor and keys. A restart
    // must never load an implicitly created supporting account as a full account.
    if (!RunWithinTxn(storage.GetDatabase(), "create MWEB supporting account", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(spkm->cs_desc_man) {
        spkm->UpdateWithSigningProvider(batch, provider);
        storage.UnsetBlankWalletFlag(batch);
        return batch.WriteDescriptor(spkm->GetID(), spkm->m_wallet_descriptor)
            && batch.WriteDescriptorCacheItems(spkm->GetID(), spkm->m_wallet_descriptor.cache)
            && batch.WriteMWEBLimitedAccount(spkm->GetID());
    })) {
        throw std::runtime_error("Could not write MWEB supporting account");
    }
    return spkm;
}

DescriptorScriptPubKeyMan::DescriptorScriptPubKeyMan(WalletStorage& storage, const uint256& id, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys)
    : ScriptPubKeyMan(storage),
    m_map_keys(keys),
    m_map_crypted_keys(ckeys),
    m_keypool_size(keypool_size),
    m_id(id),
    m_wallet_descriptor(descriptor)
{
    if (!keys.empty() && !ckeys.empty()) {
        throw std::runtime_error("Wallet contains both unencrypted and encrypted keys");
    }
    Load();
}

std::unique_ptr<DescriptorScriptPubKeyMan> DescriptorScriptPubKeyMan::LoadFromStorage(WalletStorage& storage, const uint256& id, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys)
{
    return std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(storage, id, descriptor, keypool_size, keys, ckeys));
}

std::unique_ptr<DescriptorScriptPubKeyMan> DescriptorScriptPubKeyMan::GenerateNewSingleSig(WalletStorage& storage, WalletBatch& batch, int64_t keypool_size, const CExtKey& master_key, OutputType addr_type, bool internal)
{
    WalletDescriptor desc = GenerateWalletDescriptor(master_key.Neuter(), addr_type, internal);

    auto spkm = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(storage, desc, keypool_size));

    LOCK(spkm->cs_desc_man);
    Assert(spkm->m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    spkm->m_internal = internal;

    // Store the master private key, and descriptor
    if (!spkm->AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey())) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor master private key failed");
    }
    if (!batch.WriteDescriptor(spkm->GetID(), spkm->m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // Set m_decryption_thoroughly_checked for encrypted wallets
    if (spkm->m_storage.HasEncryptionKeys()) {
        spkm->m_decryption_thoroughly_checked = true;
    }

    if (addr_type == OutputType::MWEB) {
        spkm->LoadMWEBKeychain();
        if (!spkm->PersistMWEBLockedMaterial(batch)) {
            throw std::runtime_error(std::string(__func__) + ": writing MWEB scan key failed");
        }
        spkm->InitMWEBReservedIndices(batch);
        spkm->m_wallet_descriptor.SetMWEBIndices(/*start=*/0, /*next=*/2, /*end=*/0);
        batch.WriteDescriptor(spkm->GetID(), spkm->m_wallet_descriptor);
    }

    // TopUp
    spkm->TopUpWithDB(batch);

    spkm->m_storage.UnsetBlankWalletFlag(batch);
    return spkm;
}

void DescriptorScriptPubKeyMan::IncIndex()
{
    AssertLockHeld(cs_desc_man);

    const auto old_can = CanGetAddresses();
    m_wallet_descriptor.IncNext();
    const auto new_can = CanGetAddresses();
    if (old_can != new_can) {
        NotifyCanGetAddressesChanged();
    }
}

void DescriptorScriptPubKeyMan::DecIndex()
{
    AssertLockHeld(cs_desc_man);

    const auto old_can = CanGetAddresses();
    m_wallet_descriptor.DecNext();
    const auto new_can = CanGetAddresses();
    if (old_can != new_can) {
        NotifyCanGetAddressesChanged();
    }
}

void DescriptorScriptPubKeyMan::SetRangeEnd(int32_t end)
{
    AssertLockHeld(cs_desc_man);

    const auto old_can = CanGetAddresses();
    m_wallet_descriptor.SetEnd(end);
    const auto new_can = CanGetAddresses();
    if (old_can != new_can) {
        NotifyCanGetAddressesChanged();
    }
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    // Returns true if this descriptor supports getting new addresses. Conditions where we may be unable to fetch them (e.g. locked) are caught later
    if (!CanGetAddresses()) {
        return util::Error{_("No addresses available")};
    }
    {
        LOCK(cs_desc_man);
        assert(m_wallet_descriptor.descriptor->IsSingleType()); // This is a combo descriptor which should not be an active descriptor
        std::optional<OutputType> desc_addr_type = m_wallet_descriptor.descriptor->GetOutputType();
        assert(desc_addr_type);
        if (type != *desc_addr_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
        }

        if (IsMWEBAccountDescriptor()) {
            TopUp(1);
            const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
            if (!keychain || !keychain->HasSpendPubKey()) {
                return util::Error{_("MWEB keychain not loaded")};
            }
            const uint32_t index = static_cast<uint32_t>(m_wallet_descriptor.GetNext());
            if (index > MWEB_MAX_DESCRIPTOR_INDEX || (index == MWEB_MAX_DESCRIPTOR_INDEX && m_mweb_internal_descriptors.contains(index))) {
                return util::Error{_("Error: MWEB address indices exhausted for this account")};
            }
            WalletBatch batch(m_storage.GetDatabase());
            const StealthAddress addr = keychain->GetStealthAddress(index);
            if (!PersistMWEBInternalIndex(batch, index, addr)) {
                return util::Error{_("Error: failed to record MWEB address index")};
            }
            if (index < MWEB_MAX_DESCRIPTOR_INDEX) IncIndex();
            RegisterMWEBLookahead();
            batch.WriteDescriptor(GetID(), m_wallet_descriptor);
            return CTxDestination{addr};
        }

        TopUp();

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (m_wallet_descriptor.GetEnd() <= m_max_cached_index && !TopUp(1)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.GetNext(), m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }

        CTxDestination dest;
        if (!ExtractDestination(scripts_temp[0], dest)) {
            return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")}; // shouldn't happen
        }
        IncIndex();
        WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
        return dest;
    }
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::PeekNewDestination(const OutputType type) const // MWEB
{
    if (!CanGetAddresses()) {
        return util::Error{_("No addresses available")};
    }
    LOCK(cs_desc_man);
    if (IsMWEBAccountDescriptor() || !m_wallet_descriptor.descriptor->IsSingleType() || m_wallet_descriptor.descriptor->GetOutputType() != type) {
        return util::Error{Untranslated("Not supported")};
    }
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts_temp;
    if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.GetNext(), m_wallet_descriptor.cache, scripts_temp, out_keys)) {
        return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
    }
    CTxDestination dest;
    if (!ExtractDestination(scripts_temp[0], dest)) {
        return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")};
    }
    return dest;
}

bool DescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_desc_man);
    return m_map_script_pub_keys.contains(script);
}

bool DescriptorScriptPubKeyMan::IsMine(const CTxDestination& dest) const
{
    const StealthAddress* address = std::get_if<StealthAddress>(&dest);
    if (!address) {
        return IsMine(GetScriptForDestination(dest));
    }
    LOCK(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return false;
    }
    if (!m_map_mweb_addresses.contains(*address)) {
        return false;
    }
    const mw::Keychain::Ptr& keychain = m_mwebKeychain;
    if (keychain && !keychain->GetScanSecret().IsNull()) {
        if (address->GetSpendPubKey().Mul(keychain->GetScanSecret()) != address->GetScanPubKey()) {
            return false;
        }
        // Identify-capable (scan) is enough for IsMine; spendability is separate.
        return true;
    }
    if (!m_mweb_scan_secret.IsNull()) {
        if (address->GetSpendPubKey().Mul(m_mweb_scan_secret) != address->GetScanPubKey()) {
            return false;
        }
        return true;
    }
    if (m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return true;
    }
    return HaveKey(address->GetSpendPubKey().GetID());
}

bool DescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    bool keyPass = m_map_crypted_keys.empty(); // Always pass when there are no encrypted keys
    bool keyFail = false;
    for (const auto& mi : m_map_crypted_keys) {
        const CPubKey &pubkey = mi.second.first;
        const std::vector<unsigned char> &crypted_secret = mi.second.second;
        CKey key;
        if (!DecryptKey(master_key, crypted_secret, pubkey, key)) {
            keyFail = true;
            break;
        }
        keyPass = true;
        if (m_decryption_thoroughly_checked)
            break;
    }
    if (keyPass && keyFail) {
        LogWarning("The wallet is probably corrupted: Some keys decrypt but not all.");
        throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
    }
    if (keyFail || !keyPass) {
        return false;
    }
    m_decryption_thoroughly_checked = true;
    return true;
}

bool DescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    if (!m_map_crypted_keys.empty()) {
        return false;
    }

    for (const KeyMap::value_type& key_in : m_map_keys)
    {
        const CKey &key = key_in.second;
        CPubKey pubkey = key.GetPubKey();
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        std::vector<unsigned char> crypted_secret;
        if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }
        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        batch->WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    }
    m_map_keys.clear();
    return true;
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, int64_t& index)
{
    LOCK(cs_desc_man);
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.GetNext() - 1;
    return op_dest;
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
    LOCK(cs_desc_man);
    // Only return when the index was the most recent
    if (m_wallet_descriptor.GetNext() - 1 == index) {
        DecIndex();
    }
    WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        KeyMap keys;
        for (const auto& key_pair : m_map_crypted_keys) {
            const CPubKey& pubkey = key_pair.second.first;
            const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
            CKey key;
            m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return DecryptKey(encryption_key, crypted_secret, pubkey, key);
            });
            keys[pubkey.GetID()] = key;
        }
        return keys;
    }
    return m_map_keys;
}

bool DescriptorScriptPubKeyMan::HasPrivKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    return m_map_keys.contains(keyid) || m_map_crypted_keys.contains(keyid);
}

std::optional<CKey> DescriptorScriptPubKeyMan::LookupPrivKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        const auto& it = m_map_crypted_keys.find(keyid);
        if (it == m_map_crypted_keys.end()) {
            return std::nullopt;
        }
        const std::vector<unsigned char>& crypted_secret = it->second.second;
        CKey key;
        if (!Assume(m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, crypted_secret, it->second.first, key);
        }))) {
            return std::nullopt;
        }
        return key;
    }
    const auto& it = m_map_keys.find(keyid);
    if (it == m_map_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) return false;
    bool res = TopUpWithDB(batch, size);
    if (!batch.TxnCommit()) throw std::runtime_error(strprintf("Error during descriptors keypool top up. Cannot commit changes for wallet [%s]", m_storage.LogName()));
    return res;
}

bool DescriptorScriptPubKeyMan::TopUpWithDB(WalletBatch& batch, unsigned int size)
{
    LOCK(cs_desc_man);
    if (IsMWEBAccountDescriptor()) {
        return TopUpMWEBWithDB(batch, size);
    }
    // Single-subaddress accounts are capability SPKMs without L1 scripts.
    if (IsMWEBCapabilityDescriptor() &&
        GetMWEBForm(*m_wallet_descriptor.descriptor) == MWEBDescriptorForm::SINGLE_SUBADDR) {
        LoadMWEBKeychain();
        return TopUpMWEBWithDB(batch, size);
    }
    std::set<CScript> new_spks;
    unsigned int target_size;
    if (size > 0) {
        target_size = size;
    } else {
        target_size = m_keypool_size;
    }

    // Calculate the new range_end
    int32_t new_range_end = std::max(m_wallet_descriptor.GetNext() + (int32_t)target_size, m_wallet_descriptor.GetEnd());

    // If the descriptor is not ranged, we actually just want to fill the first cache item
    if (!m_wallet_descriptor.descriptor->IsRange()) {
        new_range_end = 1;
    }

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    uint256 id = GetID();
    for (int32_t i = m_max_cached_index + 1; i < new_range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        DescriptorCache temp_cache;
        // Maybe we have a cached xpub and we can expand from the cache first
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            if (!m_wallet_descriptor.descriptor->Expand(i, provider, scripts_temp, out_keys, &temp_cache)) return false;
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.contains(pubkey)) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
        }
        m_max_cached_index++;
    }
    SetRangeEnd(new_range_end);
    batch.WriteDescriptor(GetID(), m_wallet_descriptor);

    // By this point, the cache size should be the size of the entire range
    assert(m_wallet_descriptor.GetEnd() - 1 == m_max_cached_index);

    m_storage.TopUpCallback(new_spks, this);
    return true;
}

std::vector<WalletDestination> DescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_desc_man);
    std::vector<WalletDestination> result;
    if (IsMine(script)) {
        int32_t index = m_map_script_pub_keys[script];
        if (index >= m_wallet_descriptor.GetNext()) {
            WalletLogPrintf("%s: Detected a used keypool item at index %d, mark all keypool items up to this item as used\n", __func__, index);
            auto out_keys = std::make_unique<FlatSigningProvider>();
            std::vector<CScript> scripts_temp;
            while (index >= m_wallet_descriptor.GetNext()) {
                if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.GetNext(), m_wallet_descriptor.cache, scripts_temp, *out_keys)) {
                    throw std::runtime_error(std::string(__func__) + ": Unable to expand descriptor from cache");
                }
                CTxDestination dest;
                ExtractDestination(scripts_temp[0], dest);
                result.push_back({dest, std::nullopt});
                IncIndex();
            }
        }
        if (!TopUp()) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    }

    return result;
}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // Check if provided key already exists
    if (m_map_keys.contains(pubkey.GetID()) ||
        m_map_crypted_keys.contains(pubkey.GetID())) {
        return true;
    }

    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return EncryptSecret(encryption_key, secret, pubkey.GetHash(), crypted_secret);
            })) {
            return false;
        }

        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        return batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    } else {
        m_map_keys[pubkey.GetID()] = key;
        return batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey());
    }
}

bool DescriptorScriptPubKeyMan::IsHDEnabled() const
{
    LOCK(cs_desc_man);
    if (IsMWEBCapabilityDescriptor()) {
        return true;
    }
    return m_wallet_descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(bool internal) const
{
    LOCK(cs_desc_man);
    if (IsMWEBAccountDescriptor()) {
        const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
        return !m_mweb_limited_account && keychain && keychain->HasSpendPubKey();
    }
    return m_wallet_descriptor.descriptor->IsSingleType() &&
           m_wallet_descriptor.descriptor->IsRange() &&
           (HavePrivateKeys() || m_wallet_descriptor.GetNext() < m_wallet_descriptor.GetEnd() || m_wallet_descriptor.descriptor->CanSelfExpand());
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    return m_map_keys.size() > 0 || m_map_crypted_keys.size() > 0;
}

bool DescriptorScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_desc_man);
    return !m_map_crypted_keys.empty();
}

unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_desc_man);
    if (m_wallet_descriptor.GetEnd() <= m_wallet_descriptor.GetNext()) {
        return 0;
    }
    return m_wallet_descriptor.GetEnd() - m_wallet_descriptor.GetNext();
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CScript& script, bool include_private) const
{
    LOCK(cs_desc_man);

    // Find the index of the script
    auto it = m_map_script_pub_keys.find(script);
    if (it == m_map_script_pub_keys.end()) {
        return nullptr;
    }
    int32_t index = it->second;

    return GetSigningProvider(index, include_private);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPubKey& pubkey) const
{
    LOCK(cs_desc_man);

    // Find index of the pubkey
    auto it = m_map_pubkeys.find(pubkey);
    if (it == m_map_pubkeys.end()) {
        return nullptr;
    }
    int32_t index = it->second;

    // Always try to get the signing provider with private keys. This function should only be called during signing anyways
    std::unique_ptr<FlatSigningProvider> out = GetSigningProvider(index, true);
    if (!out->HaveKey(pubkey.GetID())) {
        return nullptr;
    }
    return out;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(int32_t index, bool include_private) const
{
    AssertLockHeld(cs_desc_man);

    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();

    // Fetch SigningProvider from cache to avoid re-deriving
    auto it = m_map_signing_providers.find(index);
    if (it != m_map_signing_providers.end()) {
        out_keys->Merge(FlatSigningProvider{it->second});
    } else {
        // Get the scripts, keys, and key origins for this script
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) return nullptr;

        // Cache SigningProvider so we don't need to re-derive if we need this SigningProvider again
        m_map_signing_providers[index] = *out_keys;
    }

    if (HavePrivateKeys() && include_private) {
        FlatSigningProvider master_provider;
        master_provider.keys = GetKeys();
        m_wallet_descriptor.descriptor->ExpandPrivate(index, master_provider, *out_keys);

        // Always include musig_secnonces as this descriptor may have a participant private key
        // but not a musig() descriptor
        out_keys->musig2_secnonces = &m_musig2_secnonces;
    }

    return out_keys;
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    return GetSigningProvider(script, false);
}

bool DescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return IsMine(script);
}

bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair : coins) {
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.out.scriptPubKey, true);
        if (!coin_keys) {
            continue;
        }
        keys->Merge(std::move(*coin_keys));
    }

    return ::SignTransaction(tx, keys.get(), coins, {.sighash_type = sighash}, input_errors);
}

SigningResult DescriptorScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(GetScriptForDestination(pkhash), true);
    if (!keys) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    CKey key;
    if (!keys->GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (!MessageSign(key, message, str_sig)) {
        return SigningResult::SIGNING_FAILED;
    }
    return SigningResult::OK;
}

std::optional<PSBTError> DescriptorScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (!input.prev_out.has_value() || *input.prev_out >= input.non_witness_utxo->vout.size()) {
                return PSBTError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[*input.prev_out].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }

        std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
        std::unique_ptr<FlatSigningProvider> script_keys = GetSigningProvider(script, /*include_private=*/options.sign);
        if (script_keys) {
            keys->Merge(std::move(*script_keys));
        } else {
            // Maybe there are pubkeys listed that we can sign for
            std::vector<CPubKey> pubkeys;
            pubkeys.reserve(input.hd_keypaths.size() + 2);

            // ECDSA Pubkeys
            for (const auto& [pk, _] : input.hd_keypaths) {
                pubkeys.push_back(pk);
            }

            // Taproot output pubkey
            std::vector<std::vector<unsigned char>> sols;
            if (Solver(script, sols) == TxoutType::WITNESS_V1_TAPROOT) {
                sols[0].insert(sols[0].begin(), 0x02);
                pubkeys.emplace_back(sols[0]);
                sols[0][0] = 0x03;
                pubkeys.emplace_back(sols[0]);
            }

            // Taproot pubkeys
            for (const auto& pk_pair : input.m_tap_bip32_paths) {
                const XOnlyPubKey& pubkey = pk_pair.first;
                for (unsigned char prefix : {0x02, 0x03}) {
                    unsigned char b[33] = {prefix};
                    std::copy(pubkey.begin(), pubkey.end(), b + 1);
                    CPubKey fullpubkey;
                    fullpubkey.Set(b, b + 33);
                    pubkeys.push_back(fullpubkey);
                }
            }

            for (const auto& pubkey : pubkeys) {
                std::unique_ptr<FlatSigningProvider> pk_keys = GetSigningProvider(pubkey);
                if (pk_keys) {
                    keys->Merge(std::move(*pk_keys));
                }
            }
        }

        const auto sign_result = SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!options.sign, /*hide_origin=*/!options.bip32_derivs), psbtx, i, &txdata, options, /*out_sigdata=*/nullptr);
        if (!sign_result.has_value() && sign_result.error() != PSBTError::INCOMPLETE) {
            return sign_result.error();
        }

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !options.sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // Fill in the bip32 keypaths and redeemscripts for the outputs so that hardware wallets can identify change
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        std::unique_ptr<SigningProvider> keys = GetSolvingProvider(psbtx.outputs.at(i).script);
        if (!keys) {
            continue;
        }
        UpdatePSBTOutput(HidingSigningProvider(keys.get(), /*hide_secret=*/true, /*hide_origin=*/!options.bip32_derivs), psbtx, i);
    }

    return {};
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    if (const StealthAddress* addr = std::get_if<StealthAddress>(&dest)) {
        return GetMetadata(*addr);
    }
    std::unique_ptr<SigningProvider> provider = GetSigningProvider(GetScriptForDestination(dest));
    if (provider) {
        KeyOriginInfo orig;
        CKeyID key_id = GetKeyForDestination(*provider, dest);
        if (provider->GetKeyOrigin(key_id, orig)) {
            LOCK(cs_desc_man);
            std::unique_ptr<CKeyMetadata> meta = std::make_unique<CKeyMetadata>();
            meta->key_origin = orig;
            meta->has_key_origin = true;
            meta->nCreateTime = m_wallet_descriptor.creation_time;
            return meta;
        }
    }
    return nullptr;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    return m_id;
}

void DescriptorScriptPubKeyMan::Load()
{
    LOCK(cs_desc_man);
    if (IsMWEBCapabilityDescriptor()) {
        LoadMWEBKeychain();
        ReloadMWEBScanMapsFromInternalDescriptors();
        return;
    }
    std::set<CScript> new_spks;
    for (int32_t i = m_wallet_descriptor.GetStart(); i < m_wallet_descriptor.GetEnd(); ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            throw std::runtime_error("Error: Unable to expand wallet descriptor from cache");
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            if (m_map_script_pub_keys.contains(script)) {
                throw std::runtime_error(strprintf("Error: Already loaded script at index %d as being at index %d", i, m_map_script_pub_keys[script]));
            }
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.contains(pubkey)) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        m_max_cached_index++;
    }
    // Make sure the wallet knows about our new spks
    m_storage.TopUpCallback(new_spks, this);
}

bool DescriptorScriptPubKeyMan::HasWalletDescriptor(const WalletDescriptor& desc) const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.IsCanonicallyEquivalent(desc);
}

void DescriptorScriptPubKeyMan::WriteDescriptor()
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
}

WalletDescriptor DescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    return m_wallet_descriptor;
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    return GetScriptPubKeys(0);
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys(int32_t minimum_index) const
{
    LOCK(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> script_pub_keys;
    script_pub_keys.reserve(m_map_script_pub_keys.size());

    for (auto const& [script_pub_key, index] : m_map_script_pub_keys) {
        if (index >= minimum_index) script_pub_keys.insert(script_pub_key);
    }
    return script_pub_keys;
}

int32_t DescriptorScriptPubKeyMan::GetEndRange() const
{
    return m_max_cached_index + 1;
}

bool DescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    LOCK(cs_desc_man);

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    if (priv) {
        // For the private version, always return the master key to avoid
        // exposing child private keys. The risk implications of exposing child
        // private keys together with the parent xpub may be non-obvious for users.
        return m_wallet_descriptor.descriptor->ToPrivateString(provider, out);
    }

    // MWEB: export the exact stored public descriptor body so acct_cksum matches.
    if (IsMWEBCapabilityDescriptor()) {
        out = m_wallet_descriptor.descriptor->ToString();
        return true;
    }

    return m_wallet_descriptor.descriptor->ToNormalizedString(provider, out, &m_wallet_descriptor.cache);
}

void DescriptorScriptPubKeyMan::UpgradeDescriptorCache()
{
    LOCK(cs_desc_man);
    if (m_storage.IsLocked() || m_storage.IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    // Skip if we have the last hardened xpub cache
    if (m_wallet_descriptor.cache.GetCachedLastHardenedExtPubKeys().size() > 0) {
        return;
    }

    // Expand the descriptor
    FlatSigningProvider provider;
    provider.keys = GetKeys();
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts_temp;
    DescriptorCache temp_cache;
    if (!m_wallet_descriptor.descriptor->Expand(0, provider, scripts_temp, out_keys, &temp_cache)){
        throw std::runtime_error("Unable to expand descriptor");
    }

    // Cache the last hardened xpubs
    DescriptorCache diff = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
    if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptorCacheItems(GetID(), diff)) {
        throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
    }
}

util::Result<void> DescriptorScriptPubKeyMan::UpdateWalletDescriptor(WalletDescriptor& descriptor, const FlatSigningProvider& provider)
{
    LOCK(cs_desc_man);
    std::string error;
    if (!CanUpdateToWalletDescriptor(descriptor, error)) {
        return util::Error{Untranslated(std::move(error))};
    }

    m_map_pubkeys.clear();
    m_map_script_pub_keys.clear();
    m_map_mweb_addresses.clear();
    m_map_mweb_metadata.clear();
    m_mweb_internal_descriptors.clear();
    m_mweb_lookahead.clear();
    m_max_cached_index = -1;
    m_wallet_descriptor.UpdateFrom(descriptor);

    WalletBatch batch(m_storage.GetDatabase());
    UpdateWithSigningProvider(batch, provider);
    NotifyFirstKeyTimeChanged(this, m_wallet_descriptor.creation_time);
    return {};
}

void DescriptorScriptPubKeyMan::UpdateWithSigningProvider(WalletBatch& batch, const FlatSigningProvider& signing_provider)
{
    AssertLockHeld(cs_desc_man);
    // Watch-only wallets (DISABLE_PRIVATE_KEYS) must not receive map_keys entries.
    // MWEB viewing accounts may still carry a private scan KEY; that material is
    // extracted below and kept in MWEBSCANK.
    if (!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        for (const auto& entry : signing_provider.keys) {
            const CKey& key = entry.second;
            if (!AddDescriptorKeyWithDB(batch, key, key.GetPubKey())) {
                throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
            }
        }
    }
    // After the keys, so the descriptor cache is written before the MWEBSCANK record.
    if (IsMWEBCapabilityDescriptor()) {
        TryExtractMWEBScanSecretFromProvider(batch, signing_provider);
    }

    // Top up key pool, to generate scriptPubKeys
    if (!TopUpWithDB(batch)) {
        throw std::runtime_error("Could not top up scriptPubKeys");
    }
}

bool DescriptorScriptPubKeyMan::CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error)
{
    LOCK(cs_desc_man);
    if (!HasWalletDescriptor(descriptor)) {
        error = "can only update matching descriptor";
        return false;
    }

    if (!descriptor.descriptor->IsRange()) {
        // Skip range check for non-range descriptors
        return true;
    }

    if (descriptor.GetStart() > m_wallet_descriptor.GetStart() ||
        descriptor.GetEnd() < m_wallet_descriptor.GetEnd()) {
        // Use inclusive range for error
        error = strprintf("new range must include current range = [%d,%d]",
                          m_wallet_descriptor.GetStart(),
                          m_wallet_descriptor.GetEnd() - 1);
        return false;
    }

    return true;
}

bool DescriptorScriptPubKeyMan::IsMWEBDescriptor() const
{
    AssertLockHeld(cs_desc_man);
    const std::optional<OutputType> out_type = m_wallet_descriptor.descriptor->GetOutputType();
    return out_type && *out_type == OutputType::MWEB;
}

bool DescriptorScriptPubKeyMan::IsMWEBAccountDescriptor() const
{
    AssertLockHeld(cs_desc_man);
    return IsMWEBDescriptor() && GetMWEBForm(*m_wallet_descriptor.descriptor) == MWEBDescriptorForm::ACCOUNT;
}

bool DescriptorScriptPubKeyMan::IsMWEBCapabilityDescriptor() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBDescriptor()) return false;
    switch (GetMWEBForm(*m_wallet_descriptor.descriptor)) {
    case MWEBDescriptorForm::ACCOUNT:
    case MWEBDescriptorForm::INDEXED:
    case MWEBDescriptorForm::SINGLE_SUBADDR:
        return true;
    default:
        return false;
    }
}

std::string DescriptorScriptPubKeyMan::GetMWEBAccountChecksum() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return {};
    }
    // Checksum of the exact unchecksummed public account descriptor text as stored.
    std::string desc_str = m_wallet_descriptor.descriptor->ToString();
    const size_t hash_pos = desc_str.find('#');
    if (hash_pos != std::string::npos) {
        desc_str = desc_str.substr(0, hash_pos);
    }
    if (desc_str.empty()) {
        return {};
    }
    return GetDescriptorChecksum(desc_str);
}

const mw::Keychain* DescriptorScriptPubKeyMan::GetMWEBKeychainForExpansion() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return nullptr;
    }
    // A wallet can hold several MWEB accounts; only this account's own keychain derives
    // its addresses. Never fall back to the wallet default, which may belong to another
    // account and whose lookup locks other accounts' cs_desc_man while ours is held.
    return m_mwebKeychain.get();
}

bool DescriptorScriptPubKeyMan::KeyIsMWEBSeed(const KeyMap& keys, const CKey& key)
{
    AssertLockHeld(cs_desc_man);
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> extpubs;
    m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, extpubs);

    auto spend_key_known = [&](const SecretKey& scan_secret, const SecretKey& spend_secret) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        if (!m_mweb_scan_secret.IsNull() && scan_secret != m_mweb_scan_secret) {
            return false;
        }
        const mw::Keychain::Ptr keychain = MakeMWEBKeychain(m_mweb_keystore, scan_secret, spend_secret);
        const SecretKey spend_sk = keychain->GetSpendKey(mw::CHANGE_INDEX);
        CKey spend_key;
        spend_key.Set(spend_sk.vec().begin(), spend_sk.vec().end(), true);
        const CKeyID spend_id = spend_key.GetPubKey().GetID();
        return keys.contains(spend_id) || m_map_crypted_keys.contains(spend_id);
    };

    for (const CExtPubKey& xpub : extpubs) {
        if (xpub.pubkey.GetID() != key.GetPubKey().GetID()) {
            continue;
        }
        SecretKey scan_secret;
        SecretKey spend_secret;
        if (SelectMWEBAccountMasterSecrets(xpub, key, m_mweb_scan_secret, scan_secret, spend_secret) &&
            spend_key_known(scan_secret, spend_secret)) {
            return true;
        }
    }
    return false;
}

std::optional<CKey> DescriptorScriptPubKeyMan::FindMWEBWalletSeed(const KeyMap& keys)
{
    AssertLockHeld(cs_desc_man);
    if (keys.empty()) {
        return std::nullopt;
    }

    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> extpubs;
    m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, extpubs);
    for (const CExtPubKey& xpub : extpubs) {
        const auto it = keys.find(xpub.pubkey.GetID());
        if (it == keys.end()) {
            continue;
        }
        SecretKey scan_secret;
        SecretKey spend_secret;
        if (SelectMWEBAccountMasterSecrets(xpub, it->second, m_mweb_scan_secret, scan_secret, spend_secret)) {
            return it->second;
        }
    }

    for (const auto& [_, key] : keys) {
        if (KeyIsMWEBSeed(keys, key)) {
            return key;
        }
    }
    return std::nullopt;
}

void DescriptorScriptPubKeyMan::LoadMWEBKeychain()
{
    LOCK(cs_desc_man);
    // A refusal lasts until the wallet is reloaded: the records it refused are still loaded.
    if (!IsMWEBCapabilityDescriptor() || m_mweb_keychain_error) {
        return;
    }

    FlatSigningProvider provider;
    KeyMap keys = !m_map_keys.empty() ? m_map_keys : (!m_storage.IsLocked() ? GetKeys() : KeyMap{});
    provider.keys = keys;

    std::optional<CKey> scan_ckey;
    std::optional<CKey> spend_ckey;
    SecretKey scan_secret = SecretKey::Null();
    SecretKey spend_secret = SecretKey::Null();
    bool derived = false;

    // Prefer extracting scan/spend directly from the two KEY expressions.
    if (!derived && m_wallet_descriptor.descriptor->GetMWEBScanSpendKeys(provider, scan_ckey, spend_ckey) && scan_ckey) {
        scan_secret = KeyToSecretKey(*scan_ckey);
        if (spend_ckey) {
            spend_secret = KeyToSecretKey(*spend_ckey);
        }
        derived = !scan_secret.IsNull();
    }

    // Honor a preferred scan secret (the MWEBSCANK record) when the
    // wallet master can BIP32-derive it.
    if (!derived && !keys.empty() && !m_mweb_scan_secret.IsNull()) {
        std::set<CPubKey> pubkeys;
        std::set<CExtPubKey> extpubs;
        m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, extpubs);
        for (const CExtPubKey& xpub : extpubs) {
            const auto it = keys.find(xpub.pubkey.GetID());
            if (it == keys.end()) continue;
            if (SelectMWEBAccountMasterSecrets(xpub, it->second, m_mweb_scan_secret, scan_secret, spend_secret)) {
                derived = true;
                break;
            }
        }
    }

    // BIP32 wallet-master path: same root xpub as both KEY expressions; derive
    // along the chain's MWEB account path when the master privkey is present. No preferred
    // scan secret here: a master that derives another one must not fall through to the record.
    if (!derived && !keys.empty()) {
        std::set<CPubKey> pubkeys;
        std::set<CExtPubKey> extpubs;
        m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, extpubs);
        for (const CExtPubKey& xpub : extpubs) {
            const auto it = keys.find(xpub.pubkey.GetID());
            if (it == keys.end()) {
                continue;
            }
            if (SelectMWEBAccountMasterSecrets(xpub, it->second, SecretKey::Null(), scan_secret, spend_secret)) {
                derived = true;
                break;
            }
        }
    }
    const bool derived_from_keys = derived;

    // Watch-only or locked: the scan secret from the MWEBSCANK record.
    if (!derived) {
        if (!m_mweb_scan_secret.IsNull()) {
            scan_secret = m_mweb_scan_secret;
            derived = true;
        }
    }

    if (!derived) {
        return;
    }

    if (derived_from_keys && !m_mweb_scan_secret_on_disk.IsNull() && scan_secret != m_mweb_scan_secret_on_disk) {
        RefuseMWEBKeychain(strprintf("MWEB entry %s: the scan key derived from the wallet's keys does not match the wallet's "
                                     "scan key record; the wallet file may have been modified", GetMWEBAccountChecksum()));
        return;
    }

    if (!m_mwebKeychain || m_mwebKeychain->GetScanSecret() != scan_secret) {
        const std::optional<PublicKey> spend_pubkey = spend_secret.IsNull() ? GetMWEBAccountSpendPubKey() : std::nullopt;
        mw::Keychain::Ptr keychain = spend_pubkey ? MakeMWEBKeychain(m_mweb_keystore, scan_secret, *spend_pubkey)
                                                  : MakeMWEBKeychain(m_mweb_keystore, scan_secret, spend_secret);
        if (std::optional<std::string> error = VerifyMWEBInternalRecords(*keychain)) {
            RefuseMWEBKeychain(std::move(*error));
            return;
        }
        ClearMWEBLookahead();
        m_mwebKeychain = std::move(keychain);
        RegisterMWEBLookahead();
    } else if (!spend_secret.IsNull()) {
        if (m_mwebKeychain->HasSpendPubKey()) {
            if (PublicKey::From(spend_secret) != *m_mwebKeychain->GetSpendPubKey()) {
                RefuseMWEBKeychain(strprintf("MWEB entry %s: the decrypted spend key does not match the spend public key "
                                             "used while the wallet was locked; the wallet file may have been modified",
                                             GetMWEBAccountChecksum()));
                return;
            }
        } else if (std::optional<std::string> error = VerifyMWEBInternalRecords(*MakeMWEBKeychain(m_mweb_keystore, scan_secret, spend_secret))) {
            RefuseMWEBKeychain(std::move(*error));
            return;
        }
        m_mwebKeychain->Unlock(spend_secret);
    }
    m_mweb_scan_secret = scan_secret;

    RegisterMWEBSingleSubaddress(provider);
}

std::optional<std::string> DescriptorScriptPubKeyMan::CheckMWEBKeychain()
{
    AssertLockHeld(cs_desc_man);
    if (!m_mweb_keychain_error && m_mwebKeychain) {
        if (std::optional<std::string> error = VerifyMWEBInternalRecords(*m_mwebKeychain)) {
            RefuseMWEBKeychain(std::move(*error));
        }
    }
    return m_mweb_keychain_error;
}

void DescriptorScriptPubKeyMan::RefuseMWEBKeychain(std::string error)
{
    AssertLockHeld(cs_desc_man);
    m_mweb_keychain_error = std::move(error);
    m_mwebKeychain.reset();
    ClearMWEBLookahead();
}

std::optional<std::string> DescriptorScriptPubKeyMan::VerifyMWEBInternalRecords(const mw::Keychain& keychain) const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor() || !keychain.HasSpendPubKey()) {
        return std::nullopt;
    }
    for (const auto& [index, record] : m_mweb_internal_descriptors) {
        std::vector<CTxDestination> dests;
        FlatSigningProvider out;
        const StealthAddress* addr = nullptr;
        if (record.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr) && !dests.empty()) {
            addr = std::get_if<StealthAddress>(&dests[0]);
        }
        if (!addr || keychain.GetStealthAddress(index) != *addr) {
            return strprintf("MWEB account %s: the internal record at index %u does not match the account's keys", GetMWEBAccountChecksum(), index);
        }
    }
    return std::nullopt;
}

void DescriptorScriptPubKeyMan::RegisterMWEBSingleSubaddress(const SigningProvider& provider)
{
    AssertLockHeld(cs_desc_man);
    // SINGLE_SUBADDR: register the one stealth address for IsMine.
    if (GetMWEBForm(*m_wallet_descriptor.descriptor) == MWEBDescriptorForm::SINGLE_SUBADDR) {
        std::vector<CTxDestination> dests;
        FlatSigningProvider out;
        // Pass keychain so Expand can use MWEBSCANK when map_keys is empty (watch-only or locked).
        if (m_wallet_descriptor.descriptor->ExpandDestinations(0, provider, dests, out, nullptr, m_mwebKeychain.get()) && !dests.empty()) {
            if (const StealthAddress* addr = std::get_if<StealthAddress>(&dests[0])) {
                const CPubKey spend(addr->GetSpendPubKey().vec());
                CKeyMetadata metadata(m_wallet_descriptor.creation_time);
                m_map_mweb_metadata[spend.GetID()] = metadata;
                m_map_mweb_addresses[*addr] = 0;
                m_map_pubkeys[spend] = 0;
            }
        }
    }
}

void DescriptorScriptPubKeyMan::InitMWEBReservedIndices(WalletBatch& batch)
{
    AssertLockHeld(cs_desc_man);
    if (m_mweb_limited_account) return;
    for (const uint32_t index : {mw::CHANGE_INDEX, mw::PEGIN_INDEX}) {
        const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
        if (!keychain || !keychain->HasSpendPubKey()) {
            continue;
        }
        PersistMWEBInternalIndex(batch, index, keychain->GetStealthAddress(index));
    }
}

bool DescriptorScriptPubKeyMan::PersistMWEBInternalIndex(WalletBatch& batch, uint32_t index, const StealthAddress& addr)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor()) {
        return false;
    }
    if (const auto it = m_mweb_internal_descriptors.find(index); it != m_mweb_internal_descriptors.end()) {
        std::vector<CTxDestination> dests;
        FlatSigningProvider out;
        if (!it->second.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr) ||
            dests.empty() || dests[0] != CTxDestination{addr}) {
            return false;
        }
        m_max_cached_index = std::max(m_max_cached_index, static_cast<int32_t>(index));
        if (!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            const CPubKey spend(addr.GetSpendPubKey().vec());
            if (!m_map_keys.contains(spend.GetID()) && !m_map_crypted_keys.contains(spend.GetID())) {
                const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
                if (keychain && keychain->HasSpendSecret()) {
                    const SecretKey spend_sk = keychain->GetSpendKey(index);
                    if (PublicKey::From(spend_sk) != addr.GetSpendPubKey()) {
                        return false;
                    }
                    CKey key;
                    key.Set(spend_sk.vec().begin(), spend_sk.vec().end(), true);
                    if (!AddDescriptorKeyWithDB(batch, key, spend)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    const std::string acct_cksum = GetMWEBAccountChecksum();
    if (acct_cksum.empty()) {
        return false;
    }

    std::optional<SecretKey> derived_spend_sk;
    if (!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
        if (keychain && keychain->HasSpendSecret()) {
            derived_spend_sk = keychain->GetSpendKey(index);
            if (PublicKey::From(*derived_spend_sk) != addr.GetSpendPubKey()) {
                return false;
            }
        }
    }

    const CPubKey spend(addr.GetSpendPubKey().vec());
    const CPubKey scan(addr.GetScanPubKey().vec());
    const std::string body = strprintf("mweb(%s,%s,%u,%s)", HexStr(scan), HexStr(spend), index, acct_cksum);
    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse(body, keys, error, false);
    if (parsed.empty()) {
        return false;
    }

    WalletDescriptor w_desc(std::move(parsed.at(0)), GetTime(), 0, 0, 0);
    // WalletDescriptor is not assignable (const descriptor member).
    m_mweb_internal_descriptors.erase(index);
    m_mweb_internal_descriptors.emplace(index, std::move(w_desc));

    CKeyMetadata metadata(GetTime());
    metadata.mweb_index = index;
    m_map_mweb_metadata[spend.GetID()] = metadata;
    m_map_mweb_addresses[addr] = static_cast<int32_t>(index);
    m_map_pubkeys[spend] = static_cast<int32_t>(index);
    m_max_cached_index = std::max(m_max_cached_index, static_cast<int32_t>(index));
    m_mweb_internal_last_active[index] = GetTime();
    m_ephemeral_mweb_indices.erase(index);
    m_mweb_lookahead.erase(index);

    if (!batch.WriteMWEBInternalDescriptor(GetID(), index, w_desc)) {
        return false;
    }

    if (derived_spend_sk) {
        CKey key;
        key.Set(derived_spend_sk->vec().begin(), derived_spend_sk->vec().end(), true);
        if (!AddDescriptorKeyWithDB(batch, key, spend)) {
            return false;
        }
    }
    return true;
}

std::optional<uint32_t> DescriptorScriptPubKeyMan::FindMWEBAccountAddressIndex(const StealthAddress& addr) const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor()) {
        return std::nullopt;
    }
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!keychain || !keychain->HasSpendPubKey()) {
        return std::nullopt;
    }
    if (const std::optional<uint32_t> index = keychain->LookupAddressIndex(addr);
        index && *index <= MWEB_MAX_DESCRIPTOR_INDEX && keychain->GetStealthAddress(*index) == addr) {
        return index;
    }
    const uint32_t keypool = static_cast<uint32_t>(std::clamp<int64_t>(m_keypool_size, 0, MWEB_MAX_DESCRIPTOR_INDEX));
    const uint32_t low_end = std::max<uint32_t>(1024, keypool);
    for (uint32_t i = 0; i < low_end; ++i) {
        if (keychain->GetStealthAddress(i) == addr) return i;
    }
    const int64_t next = m_wallet_descriptor.GetNext();
    const uint32_t band_start = static_cast<uint32_t>(std::clamp<int64_t>(next - 1024, low_end, MWEB_MAX_DESCRIPTOR_INDEX));
    const uint32_t band_end = static_cast<uint32_t>(std::clamp<int64_t>(next + std::max<int64_t>(1024, keypool), low_end, MWEB_MAX_DESCRIPTOR_INDEX));
    for (uint32_t i = band_start; i < band_end; ++i) {
        if (keychain->GetStealthAddress(i) == addr) return i;
    }
    if (band_end == MWEB_MAX_DESCRIPTOR_INDEX && keychain->GetStealthAddress(band_end) == addr) {
        return band_end;
    }
    return std::nullopt;
}

util::Result<void> DescriptorScriptPubKeyMan::AddMWEBAccountSpendSecret(WalletBatch& batch, const SecretKey& spend_secret)
{
    AssertLockHeld(cs_desc_man);
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!IsMWEBAccountDescriptor() || !keychain || !keychain->HasSpendPubKey()) {
        return util::Error{Untranslated("Not an MWEB account with a spend public key")};
    }
    if (PublicKey::From(spend_secret) != *keychain->GetSpendPubKey()) {
        return util::Error{Untranslated("Spend key does not match the account's spend public key")};
    }
    if (keychain->HasSpendSecret()) {
        return {};
    }

    CKey key;
    key.Set(spend_secret.vec().begin(), spend_secret.vec().end(), /*fCompressedIn=*/true);
    const CPubKey pubkey = key.GetPubKey();
    FlatSigningProvider probe;
    probe.keys.emplace(pubkey.GetID(), key);
    std::optional<CKey> probe_scan;
    std::optional<CKey> probe_spend;
    m_wallet_descriptor.descriptor->GetMWEBScanSpendKeys(probe, probe_scan, probe_spend);
    if (!probe_spend || probe_spend->GetPubKey() != pubkey) {
        return util::Error{Untranslated("The account's spend key expression cannot hold a private spend key; import the account with its private spend key instead")};
    }
    if (!AddDescriptorKeyWithDB(batch, key, pubkey)) {
        return util::Error{Untranslated("Failed to store the account's spend key")};
    }
    LoadMWEBKeychain();
    const mw::Keychain* reloaded = GetMWEBKeychainForExpansion();
    if (!reloaded || !reloaded->HasSpendSecret()) {
        return util::Error{Untranslated("The account did not pick up the imported spend key")};
    }
    return {};
}

util::Result<void> DescriptorScriptPubKeyMan::LoadMWEBInternalDescriptorRecord(const WalletDescriptor& descriptor)
{
    AssertLockHeld(cs_desc_man);
    if (GetMWEBForm(*descriptor.descriptor) != MWEBDescriptorForm::INTERNAL) {
        return util::Error{Untranslated("Not an MWEB internal descriptor")};
    }
    const std::optional<uint32_t> index = GetMWEBIndex(*descriptor.descriptor);
    const std::optional<std::string> acct_cksum = ::GetMWEBAccountChecksum(*descriptor.descriptor);
    if (!index || !acct_cksum || *acct_cksum != GetMWEBAccountChecksum()) {
        return util::Error{Untranslated("MWEB internal descriptor does not match any account in this wallet")};
    }

    std::vector<CTxDestination> dests;
    FlatSigningProvider out;
    if (!descriptor.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr) || dests.empty()) {
        return util::Error{Untranslated("Invalid MWEB internal descriptor")};
    }
    const StealthAddress* addr = std::get_if<StealthAddress>(&dests[0]);
    if (!addr) {
        return util::Error{Untranslated("Invalid MWEB internal descriptor")};
    }

    // Caller should already have LoadMWEBKeychain(); re-check for defense in depth.
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (keychain) {
        if (keychain->HasSpendPubKey()) {
            if (keychain->GetStealthAddress(*index) != *addr) {
                return util::Error{Untranslated("MWEB internal descriptor keys do not match account derivation at the given index")};
            }
        } else if (!keychain->GetScanSecret().IsNull()) {
            if (addr->GetSpendPubKey().Mul(keychain->GetScanSecret()) != addr->GetScanPubKey()) {
                return util::Error{Untranslated("MWEB internal descriptor scan/spend keys are inconsistent")};
            }
        }
    }

    // WalletDescriptor is not assignable (const descriptor member).
    m_mweb_internal_descriptors.erase(*index);
    m_mweb_internal_descriptors.emplace(*index, descriptor);
    m_mweb_internal_last_active[*index] = descriptor.creation_time;

    const CPubKey spend(addr->GetSpendPubKey().vec());
    CKeyMetadata metadata(descriptor.creation_time);
    metadata.mweb_index = *index;
    m_map_mweb_metadata[spend.GetID()] = metadata;
    m_map_mweb_addresses[*addr] = static_cast<int32_t>(*index);
    m_map_pubkeys[spend] = static_cast<int32_t>(*index);
    m_max_cached_index = std::max(m_max_cached_index, static_cast<int32_t>(*index));
    return {};
}

void DescriptorScriptPubKeyMan::ReloadMWEBScanMapsFromInternalDescriptors()
{
    AssertLockHeld(cs_desc_man);
    m_map_mweb_addresses.clear();
    m_map_mweb_metadata.clear();
    for (const auto& [index, w_desc] : m_mweb_internal_descriptors) {
        std::vector<CTxDestination> dests;
        FlatSigningProvider out;
        if (!w_desc.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr) || dests.empty()) {
            continue;
        }
        const StealthAddress* addr = std::get_if<StealthAddress>(&dests[0]);
        if (!addr) {
            continue;
        }
        const CPubKey spend(addr->GetSpendPubKey().vec());
        CKeyMetadata metadata(w_desc.creation_time);
        metadata.mweb_index = index;
        m_map_mweb_metadata[spend.GetID()] = metadata;
        m_map_mweb_addresses[*addr] = static_cast<int32_t>(index);
        m_map_pubkeys[spend] = static_cast<int32_t>(index);
        m_max_cached_index = std::max(m_max_cached_index, static_cast<int32_t>(index));
    }
    RegisterMWEBSingleSubaddress(DUMMY_SIGNING_PROVIDER);
    for (const auto& [index, addr] : m_mweb_lookahead) {
        m_map_mweb_addresses.emplace(addr, static_cast<int32_t>(index));
    }
    RegisterMWEBLookahead();
}

std::vector<const WalletDescriptor*> DescriptorScriptPubKeyMan::GetMWEBInternalWalletDescriptors() const
{
    AssertLockHeld(cs_desc_man);
    std::vector<const WalletDescriptor*> ret;
    ret.reserve(m_mweb_internal_descriptors.size());
    for (const auto& entry : m_mweb_internal_descriptors) {
        ret.push_back(&entry.second);
    }
    return ret;
}

bool DescriptorScriptPubKeyMan::TopUpMWEBWithDB(WalletBatch& batch, unsigned int size)
{
    AssertLockHeld(cs_desc_man);
    if (m_mweb_limited_account) return true;
    const int64_t target_size = size > 0 ? int64_t{size} : std::max<int64_t>(m_storage.GetMWEBKeypoolSize(), 1);
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!keychain || !keychain->HasSpendPubKey()) {
        NotifyCanGetAddressesChanged();
        return true;
    }

    const int64_t wanted_end = std::min<int64_t>(int64_t{m_wallet_descriptor.GetNext()} + target_size, MWEB_MAX_DESCRIPTOR_INDEX);
    const int32_t new_range_end = std::max(m_wallet_descriptor.GetEnd(), static_cast<int32_t>(wanted_end));
    if (new_range_end != m_wallet_descriptor.GetEnd()) {
        m_wallet_descriptor.SetMWEBIndices(m_wallet_descriptor.GetStart(), m_wallet_descriptor.GetNext(), new_range_end);
        if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
            throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
        }
    }
    RegisterMWEBLookahead();

    NotifyCanGetAddressesChanged();
    return true;
}

void DescriptorScriptPubKeyMan::RegisterMWEBLookahead()
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor() || m_mweb_limited_account) {
        return;
    }
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!keychain || !keychain->HasSpendPubKey()) {
        return;
    }
    const int64_t size = std::max<int64_t>(m_storage.GetMWEBKeypoolSize(), 1);
    const int64_t next = std::clamp<int64_t>(m_wallet_descriptor.GetNext(), 0, MWEB_MAX_DESCRIPTOR_INDEX);
    const int64_t lowest = std::max<int64_t>({int64_t{m_wallet_descriptor.GetStart()}, next - size, 0});
    const int64_t end = std::min<int64_t>(std::max<int64_t>(m_wallet_descriptor.GetEnd(), next + size), int64_t{MWEB_MAX_DESCRIPTOR_INDEX} + 1);

    for (auto it = m_mweb_lookahead.begin(); it != m_mweb_lookahead.end() && it->first < lowest;) {
        const auto addr_it = m_map_mweb_addresses.find(it->second);
        if (addr_it != m_map_mweb_addresses.end() && addr_it->second == static_cast<int32_t>(it->first) &&
            !m_mweb_internal_descriptors.contains(it->first) && !m_ephemeral_mweb_indices.contains(it->first)) {
            m_map_mweb_addresses.erase(addr_it);
        }
        it = m_mweb_lookahead.erase(it);
    }
    for (int64_t i = lowest; i < end; ++i) {
        const uint32_t index = static_cast<uint32_t>(i);
        if (m_mweb_internal_descriptors.contains(index)) {
            continue;
        }
        auto it = m_mweb_lookahead.find(index);
        if (it == m_mweb_lookahead.end()) {
            it = m_mweb_lookahead.emplace(index, keychain->GetStealthAddress(index)).first;
        }
        m_map_mweb_addresses.emplace(it->second, static_cast<int32_t>(index));
    }
}

void DescriptorScriptPubKeyMan::ClearMWEBLookahead()
{
    AssertLockHeld(cs_desc_man);
    for (const auto& [index, addr] : m_mweb_lookahead) {
        const auto addr_it = m_map_mweb_addresses.find(addr);
        if (addr_it != m_map_mweb_addresses.end() && addr_it->second == static_cast<int32_t>(index) &&
            !m_mweb_internal_descriptors.contains(index) && !m_ephemeral_mweb_indices.contains(index)) {
            m_map_mweb_addresses.erase(addr_it);
        }
    }
    m_mweb_lookahead.clear();
}

bool DescriptorScriptPubKeyMan::AdvanceMWEBNextIndexPast(WalletBatch& batch, uint32_t index)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor() || index > MWEB_MAX_DESCRIPTOR_INDEX || int64_t{index} < m_wallet_descriptor.GetNext()) {
        return false;
    }
    const uint32_t next = index < MWEB_MAX_DESCRIPTOR_INDEX ? index + 1 : MWEB_MAX_DESCRIPTOR_INDEX;
    m_wallet_descriptor.SetMWEBIndices(m_wallet_descriptor.GetStart(), static_cast<int32_t>(next), m_wallet_descriptor.GetEnd());
    TopUpMWEBWithDB(batch, 0);
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
    return true;
}

size_t DescriptorScriptPubKeyMan::GetMWEBLookaheadCount() const
{
    AssertLockHeld(cs_desc_man);
    return m_mweb_lookahead.size();
}

void DescriptorScriptPubKeyMan::RestoreMWEBSpendKeysAfterUnlock()
{
    LOCK(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return;
    }
    LoadMWEBKeychain();
    WalletBatch batch(m_storage.GetDatabase());
    for (const auto& entry : m_mweb_internal_descriptors) {
        std::vector<CTxDestination> dests;
        FlatSigningProvider out;
        if (!entry.second.descriptor->ExpandDestinations(0, DUMMY_SIGNING_PROVIDER, dests, out, nullptr, nullptr) || dests.empty()) {
            continue;
        }
        const StealthAddress* addr = std::get_if<StealthAddress>(&dests[0]);
        if (!addr) {
            continue;
        }
        PersistMWEBInternalIndex(batch, entry.first, *addr);
    }
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const StealthAddress& addr) const
{
    LOCK(cs_desc_man);
    const auto it = m_map_mweb_addresses.find(addr);
    if (it == m_map_mweb_addresses.end()) {
        return nullptr;
    }
    const CKeyID key_id = addr.GetSpendPubKey().GetID();
    const auto meta_it = m_map_mweb_metadata.find(key_id);
    if (meta_it != m_map_mweb_metadata.end()) {
        return std::make_unique<CKeyMetadata>(meta_it->second);
    }
    auto meta = std::make_unique<CKeyMetadata>();
    meta->mweb_index = static_cast<uint32_t>(it->second);
    meta->nCreateTime = m_wallet_descriptor.creation_time;
    return meta;
}

bool DescriptorScriptPubKeyMan::GetKey(const CKeyID& id, CKey& keyOut) const
{
    LOCK(cs_desc_man);
    if (auto key = LookupPrivKey(id)) {
        keyOut = *key;
        return true;
    }
    return false;
}

bool DescriptorScriptPubKeyMan::HaveKey(const CKeyID& id) const
{
    LOCK(cs_desc_man);
    return HasPrivKey(id);
}

bool DescriptorScriptPubKeyMan::RegisterEphemeralMWEBIndex(uint32_t index)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor()) {
        return false;
    }
    if (m_mweb_internal_descriptors.contains(index)) {
        return true;
    }
    if (m_ephemeral_mweb_indices.contains(index)) {
        return true;
    }
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!keychain || !keychain->HasSpendPubKey()) {
        return false;
    }
    const StealthAddress addr = keychain->GetStealthAddress(index);
    m_ephemeral_mweb_indices.insert(index);
    m_map_mweb_addresses[addr] = static_cast<int32_t>(index);
    const CPubKey spend(addr.GetSpendPubKey().vec());
    CKeyMetadata metadata(GetTime());
    metadata.mweb_index = index;
    m_map_mweb_metadata[spend.GetID()] = metadata;
    m_map_pubkeys[spend] = static_cast<int32_t>(index);
    m_max_cached_index = std::max(m_max_cached_index, static_cast<int32_t>(index));
    return true;
}

bool DescriptorScriptPubKeyMan::RegisterEphemeralMWEBIndexRange(uint32_t from, uint32_t to_inclusive)
{
    AssertLockHeld(cs_desc_man);
    // Automatic account-wide scan passes keep indexed imports scoped. Explicit
    // account import enables discovery before asking for an expanded scan.
    if (m_mweb_limited_account) return true;
    for (uint32_t i = from; i <= to_inclusive; ++i) {
        if (!RegisterEphemeralMWEBIndex(i)) {
            return false;
        }
    }
    return true;
}

void DescriptorScriptPubKeyMan::UnregisterEphemeralMWEBIndex(uint32_t index)
{
    AssertLockHeld(cs_desc_man);
    if (m_mweb_internal_descriptors.contains(index)) {
        m_ephemeral_mweb_indices.erase(index);
        return;
    }
    if (!m_ephemeral_mweb_indices.erase(index)) {
        return;
    }
    if (m_mweb_lookahead.contains(index)) {
        return;
    }
    for (auto it = m_map_mweb_addresses.begin(); it != m_map_mweb_addresses.end();) {
        if (it->second == static_cast<int32_t>(index)) {
            const CKeyID key_id = it->first.GetSpendPubKey().GetID();
            m_map_mweb_metadata.erase(key_id);
            m_map_pubkeys.erase(CPubKey(it->first.GetSpendPubKey().vec()));
            it = m_map_mweb_addresses.erase(it);
        } else {
            ++it;
        }
    }
}

void DescriptorScriptPubKeyMan::ClearEphemeralMWEBIndices()
{
    AssertLockHeld(cs_desc_man);
    std::vector<uint32_t> ephemeral(m_ephemeral_mweb_indices.begin(), m_ephemeral_mweb_indices.end());
    for (const uint32_t index : ephemeral) {
        UnregisterEphemeralMWEBIndex(index);
    }
    m_ephemeral_mweb_indices.clear();
    m_mweb_scan_active_indices.clear();
    ReloadMWEBScanMapsFromInternalDescriptors();
}

void DescriptorScriptPubKeyMan::ResetMWEBScanState()
{
    AssertLockHeld(cs_desc_man);
    m_mweb_scan_active_indices.clear();
}

void DescriptorScriptPubKeyMan::MarkMWEBIndexActive(uint32_t index)
{
    AssertLockHeld(cs_desc_man);
    m_mweb_scan_active_indices.insert(index);
    UpdateMWEBInternalActivity(index, GetTime());
}

uint32_t DescriptorScriptPubKeyMan::CommitActiveMWEBIndices(WalletBatch& batch)
{
    AssertLockHeld(cs_desc_man);
    uint32_t max_active = 0;
    const mw::Keychain* keychain = GetMWEBKeychainForExpansion();
    if (!keychain) {
        m_mweb_scan_active_indices.clear();
        return 0;
    }
    for (const uint32_t index : m_mweb_scan_active_indices) {
        if (m_mweb_internal_descriptors.contains(index)) {
            max_active = std::max(max_active, index);
            continue;
        }
        if (!keychain->HasSpendSecret()) {
            continue;
        }
        const StealthAddress addr = keychain->GetStealthAddress(index);
        if (PersistMWEBInternalIndex(batch, index, addr)) {
            max_active = std::max(max_active, index);
        }
    }
    m_mweb_scan_active_indices.clear();
    return max_active;
}

void DescriptorScriptPubKeyMan::EnsureMWEBNextIndexAtLeast(uint32_t index)
{
    AssertLockHeld(cs_desc_man);
    const uint32_t next = std::min(index, MWEB_MAX_DESCRIPTOR_INDEX);
    if (m_wallet_descriptor.GetNext() < static_cast<int64_t>(next)) {
        m_wallet_descriptor.SetMWEBIndices(m_wallet_descriptor.GetStart(), static_cast<int32_t>(next), m_wallet_descriptor.GetEnd());
        RegisterMWEBLookahead();
    }
}

void DescriptorScriptPubKeyMan::LoadMWEBLimitedAccountRecord()
{
    AssertLockHeld(cs_desc_man);
    m_mweb_limited_account = true;
    ClearMWEBLookahead();
}

bool DescriptorScriptPubKeyMan::EnableMWEBAccountDiscovery(WalletBatch& batch)
{
    AssertLockHeld(cs_desc_man);
    if (!m_mweb_limited_account) return true;
    if (!batch.EraseMWEBLimitedAccount(GetID())) return false;
    m_mweb_limited_account = false;
    InitMWEBReservedIndices(batch);
    return TopUpMWEBWithDB(batch, 0);
}

void DescriptorScriptPubKeyMan::SetMWEBInternalProtectMemory(uint32_t index, MWEBInternalProtect flag)
{
    AssertLockHeld(cs_desc_man);
    if (flag == MWEBInternalProtect::NONE) {
        m_mweb_internal_protect.erase(index);
    } else {
        m_mweb_internal_protect[index] = flag;
    }
}

void DescriptorScriptPubKeyMan::SetMWEBInternalProtect(uint32_t index, MWEBInternalProtect flag)
{
    AssertLockHeld(cs_desc_man);
    SetMWEBInternalProtectMemory(index, flag);
    WalletBatch batch(m_storage.GetDatabase());
    if (flag == MWEBInternalProtect::NONE) {
        batch.EraseMWEBInternalProtect(GetID(), index);
    } else {
        batch.WriteMWEBInternalProtect(GetID(), index, static_cast<uint8_t>(flag));
    }
}

DescriptorScriptPubKeyMan::MWEBInternalProtect DescriptorScriptPubKeyMan::GetMWEBInternalProtect(uint32_t index) const
{
    AssertLockHeld(cs_desc_man);
    const auto it = m_mweb_internal_protect.find(index);
    if (it == m_mweb_internal_protect.end()) {
        return MWEBInternalProtect::NONE;
    }
    return it->second;
}

void DescriptorScriptPubKeyMan::UpdateMWEBInternalActivity(uint32_t index, int64_t activity_time)
{
    AssertLockHeld(cs_desc_man);
    m_mweb_internal_last_active[index] = activity_time;
    const auto it = m_mweb_internal_descriptors.find(index);
    if (it != m_mweb_internal_descriptors.end()) {
        it->second.creation_time = activity_time;
        WalletBatch batch(m_storage.GetDatabase());
        batch.WriteMWEBInternalDescriptor(GetID(), index, it->second);
    }
}

int64_t DescriptorScriptPubKeyMan::GetMWEBInternalLastActive(uint32_t index) const
{
    AssertLockHeld(cs_desc_man);
    const auto it = m_mweb_internal_last_active.find(index);
    if (it != m_mweb_internal_last_active.end()) {
        return it->second;
    }
    const auto desc_it = m_mweb_internal_descriptors.find(index);
    if (desc_it != m_mweb_internal_descriptors.end()) {
        return desc_it->second.creation_time;
    }
    return 0;
}

size_t DescriptorScriptPubKeyMan::GetMWEBInternalDescriptorCount() const
{
    AssertLockHeld(cs_desc_man);
    return m_mweb_internal_descriptors.size();
}

size_t DescriptorScriptPubKeyMan::PruneMWEBInternalDescriptors(WalletBatch& batch, size_t& global_count, size_t global_threshold, int64_t inactivity_secs,
    const std::function<bool(uint32_t)>& has_unspent)
{
    AssertLockHeld(cs_desc_man);
    if (global_count <= global_threshold) {
        return 0;
    }

    const int64_t now = GetTime();
    std::vector<uint32_t> candidates;
    for (const auto& [index, _] : m_mweb_internal_descriptors) {
        if (index == mw::CHANGE_INDEX || index == mw::PEGIN_INDEX) {
            continue;
        }
        const MWEBInternalProtect protect = GetMWEBInternalProtect(index);
        if (protect == MWEBInternalProtect::KEEP || protect == MWEBInternalProtect::MANUAL) {
            continue;
        }
        if (has_unspent(index)) {
            continue;
        }
        if (now - GetMWEBInternalLastActive(index) < inactivity_secs) {
            continue;
        }
        candidates.push_back(index);
    }

    std::sort(candidates.begin(), candidates.end(), [&](uint32_t a, uint32_t b) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        return GetMWEBInternalLastActive(a) < GetMWEBInternalLastActive(b);
    });

    size_t pruned = 0;
    for (const uint32_t index : candidates) {
        if (global_count <= global_threshold) {
            break;
        }
        if (!m_mweb_internal_descriptors.contains(index)) {
            continue;
        }
        // Keep receive-map metadata so reused addresses stay detectable via
        // Keychain::RewindOutput / IsMine. Only the internal descriptor record is pruned.
        m_mweb_internal_descriptors.erase(index);
        m_mweb_internal_last_active.erase(index);
        m_mweb_internal_protect.erase(index);
        batch.EraseMWEBInternalDescriptor(GetID(), index);
        batch.EraseMWEBInternalProtect(GetID(), index);
        WalletLogPrintf("Pruned inactive MWEB internal descriptor account=%s index=%u\n", GetMWEBAccountChecksum(), index);
        if (global_count > 0) {
            --global_count;
        }
        ++pruned;
    }
    return pruned;
}

std::optional<std::string> DescriptorScriptPubKeyMan::GetMWEBAddressInfoDescriptor(const StealthAddress& addr) const
{
    LOCK(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor() || !m_mwebKeychain) {
        return std::nullopt;
    }
    if (IsMWEBAccountDescriptor() && m_mwebKeychain->HasSpendPubKey()) {
        const std::optional<uint32_t> index = m_mwebKeychain->LookupAddressIndex(addr);
        if (index && *index <= MWEB_MAX_DESCRIPTOR_INDEX && m_mwebKeychain->GetStealthAddress(*index) == addr) {
            return GetMWEBAddressDescriptor(*index);
        }
    }
    const std::optional<std::string> scan = GetMWEBScanKeyExpression();
    if (!scan) {
        return std::nullopt;
    }
    const std::string body = strprintf("mweb(%s,%s)", *scan, HexStr(addr.GetSpendPubKey().vec()));
    return body + "#" + GetDescriptorChecksum(body);
}

std::optional<std::string> DescriptorScriptPubKeyMan::GetMWEBParentDescriptor(const StealthAddress& addr) const
{
    LOCK(cs_desc_man);
    if (IsMWEBAccountDescriptor()) {
        if (std::optional<std::string> watch_only = GetMWEBAccountWatchOnlyDescriptor()) {
            return watch_only;
        }
        // Without B (a hardened spend path under an xpub) only the stored public form exists.
        std::string desc;
        if (GetDescriptorString(desc, /*priv=*/false)) {
            return desc;
        }
        return std::nullopt;
    }
    return GetMWEBAddressInfoDescriptor(addr);
}

std::optional<std::string> DescriptorScriptPubKeyMan::GetMWEBAddressDescriptor(uint32_t index) const
{
    LOCK(cs_desc_man);
    if (index == mw::UNKNOWN_INDEX || index == mw::CUSTOM_KEY) {
        return std::nullopt;
    }
    const auto keys = GetMWEBAccountKeyExpressions();
    if (!keys) {
        return std::nullopt;
    }
    const std::string body = strprintf("mweb(%s,%s,%u)", keys->first, keys->second, index);
    return body + "#" + GetDescriptorChecksum(body);
}

std::optional<std::string> DescriptorScriptPubKeyMan::GetMWEBAccountWatchOnlyDescriptor() const
{
    LOCK(cs_desc_man);
    const auto keys = GetMWEBAccountKeyExpressions();
    if (!keys) {
        return std::nullopt;
    }
    const std::string body = strprintf("mweb(%s,%s,*)", keys->first, keys->second);
    return body + "#" + GetDescriptorChecksum(body);
}

std::vector<std::optional<KeyOriginInfo>> DescriptorScriptPubKeyMan::GetMWEBKeyOrigins(const std::vector<CPubKey>& pubkeys) const
{
    AssertLockHeld(cs_desc_man);
    // Expanding the descriptor records the origins of its keys. Hardened derivation needs the private keys.
    std::vector<CScript> scripts;
    FlatSigningProvider expanded;
    if (!m_wallet_descriptor.descriptor->ExpandFromCache(0, m_wallet_descriptor.cache, scripts, expanded)) {
        FlatSigningProvider keys;
        if (HavePrivateKeys() && !m_storage.IsLocked()) {
            keys.keys = GetKeys();
        }
        m_wallet_descriptor.descriptor->Expand(0, keys, scripts, expanded);
    }
    std::vector<std::optional<KeyOriginInfo>> origins;
    for (const CPubKey& pubkey : pubkeys) {
        const auto it = expanded.origins.find(pubkey.GetID());
        const CKeyID id = pubkey.GetID();
        // A key without origin info expands to its own fingerprint and an empty path; that is not an origin.
        if (it == expanded.origins.end() ||
            (it->second.second.path.empty() && std::equal(std::begin(it->second.second.fingerprint), std::end(it->second.second.fingerprint), id.begin()))) {
            origins.emplace_back(std::nullopt);
        } else {
            origins.emplace_back(it->second.second);
        }
    }
    return origins;
}

std::string DescriptorScriptPubKeyMan::FormatMWEBKeyOrigin(const std::optional<KeyOriginInfo>& origin) const
{
    AssertLockHeld(cs_desc_man);
    if (!origin) return "";
    const bool apostrophe = m_wallet_descriptor.descriptor->ToString().find('\'') != std::string::npos;
    return "[" + HexStr(origin->fingerprint) + FormatHDKeypath(origin->path, apostrophe) + "]";
}

std::optional<CKey> DescriptorScriptPubKeyMan::GetMWEBScanKey() const
{
    AssertLockHeld(cs_desc_man);
    if (!m_mwebKeychain || m_mwebKeychain->GetScanSecret().IsNull()) {
        return std::nullopt;
    }
    const SecretKey& scan_secret = m_mwebKeychain->GetScanSecret();
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);
    return scan_key;
}

std::optional<std::string> DescriptorScriptPubKeyMan::GetMWEBScanKeyExpression() const
{
    AssertLockHeld(cs_desc_man);
    const std::optional<CKey> scan_key = GetMWEBScanKey();
    if (!scan_key) {
        return std::nullopt;
    }
    return FormatMWEBKeyOrigin(GetMWEBKeyOrigins({scan_key->GetPubKey()}).at(0)) + EncodeSecret(*scan_key);
}

std::optional<KeyOriginInfo> DescriptorScriptPubKeyMan::GetMWEBScanKeyOrigin() const
{
    LOCK(cs_desc_man);
    const std::optional<CKey> scan_key = GetMWEBScanKey();
    if (!scan_key) {
        return std::nullopt;
    }
    return GetMWEBKeyOrigins({scan_key->GetPubKey()}).at(0);
}

std::optional<std::pair<std::string, std::string>> DescriptorScriptPubKeyMan::GetMWEBAccountKeyExpressions() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor() || !m_mwebKeychain) {
        return std::nullopt;
    }
    const std::optional<CKey> scan_key = GetMWEBScanKey();
    const std::optional<PublicKey>& spend_pubkey = m_mwebKeychain->GetSpendPubKey();
    if (!scan_key || !spend_pubkey) {
        return std::nullopt;
    }
    const CPubKey spend(spend_pubkey->vec());
    const auto origins = GetMWEBKeyOrigins({scan_key->GetPubKey(), spend});
    return std::make_pair(FormatMWEBKeyOrigin(origins.at(0)) + EncodeSecret(*scan_key), FormatMWEBKeyOrigin(origins.at(1)) + HexStr(spend));
}

bool DescriptorScriptPubKeyMan::HasMWEBScanCapability() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return false;
    }
    if (!m_mweb_scan_secret.IsNull()) {
        return true;
    }
    if (m_mwebKeychain && !m_mwebKeychain->GetScanSecret().IsNull()) {
        return true;
    }
    return false;
}

SecretKey DescriptorScriptPubKeyMan::GetMWEBScanSecret() const
{
    AssertLockHeld(cs_desc_man);
    if (!m_mweb_scan_secret.IsNull()) {
        return m_mweb_scan_secret;
    }
    if (m_mwebKeychain && !m_mwebKeychain->GetScanSecret().IsNull()) {
        return m_mwebKeychain->GetScanSecret();
    }
    return SecretKey::Null();
}

void DescriptorScriptPubKeyMan::LoadMWEBScanSecretRecord(const SecretKey& scan_secret)
{
    AssertLockHeld(cs_desc_man);
    m_mweb_scan_secret = scan_secret;
    m_mweb_scan_secret_on_disk = scan_secret;
}

bool DescriptorScriptPubKeyMan::PersistMWEBLockedMaterial(WalletBatch& batch)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor() || !m_mwebKeychain || m_mwebKeychain->GetScanSecret().IsNull()) {
        return true;
    }
    // Hardened key expressions (the default account's spend key among them) only expand with the
    // private keys; cache them first, so a scan key record never exists without the spend pubkey.
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!m_wallet_descriptor.descriptor->ExpandFromCache(0, m_wallet_descriptor.cache, scripts, out) &&
        HavePrivateKeys() && !m_storage.IsLocked()) {
        FlatSigningProvider keys;
        keys.keys = GetKeys();
        DescriptorCache temp_cache;
        if (m_wallet_descriptor.descriptor->Expand(0, keys, scripts, out, &temp_cache) &&
            !batch.WriteDescriptorCacheItems(GetID(), m_wallet_descriptor.cache.MergeAndDiff(temp_cache))) {
            return false;
        }
    }

    if (m_mweb_scan_secret_on_disk.IsNull()) {
        if (!batch.WriteMWEBScanKey(GetID(), m_mwebKeychain->GetScanSecret())) {
            return false;
        }
        m_mweb_scan_secret_on_disk = m_mwebKeychain->GetScanSecret();
    }
    return true;
}

bool DescriptorScriptPubKeyMan::SetMWEBScanSecret(WalletBatch& batch, const SecretKey& scan_secret)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor() || m_mweb_keychain_error) {
        return false;
    }
    if (!m_mweb_scan_secret_on_disk.IsNull() && scan_secret != m_mweb_scan_secret_on_disk) {
        RefuseMWEBKeychain(strprintf("MWEB entry %s: the imported scan key does not match the wallet's scan key record; "
                                     "the wallet file may have been modified", GetMWEBAccountChecksum()));
        return false;
    }
    m_mweb_scan_secret = scan_secret;
    SecretKey spend_secret = SecretKey::Null();
    if (m_mwebKeychain && m_mwebKeychain->HasSpendSecret()) {
        spend_secret = m_mwebKeychain->GetSpendSecret();
    }
    const std::optional<PublicKey> spend_pubkey = spend_secret.IsNull() ? GetMWEBAccountSpendPubKey() : std::nullopt;
    m_mwebKeychain = spend_pubkey ? MakeMWEBKeychain(m_mweb_keystore, scan_secret, *spend_pubkey)
                                  : MakeMWEBKeychain(m_mweb_keystore, scan_secret, spend_secret);
    // Every wallet kind keeps a readable copy, so an encrypted wallet scans and makes addresses while locked.
    return PersistMWEBLockedMaterial(batch);
}

std::optional<PublicKey> DescriptorScriptPubKeyMan::GetMWEBAccountSpendPubKey() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBAccountDescriptor()) {
        return std::nullopt;
    }
    FlatSigningProvider provider;
    const std::optional<CPubKey> spend = m_wallet_descriptor.descriptor->GetMWEBAccountSpendPubKey(provider, &m_wallet_descriptor.cache);
    if (!spend) {
        return std::nullopt;
    }
    return PublicKey{spend->data()};
}

bool DescriptorScriptPubKeyMan::TryExtractMWEBScanSecretFromProvider(WalletBatch& batch, const FlatSigningProvider& signing_provider)
{
    AssertLockHeld(cs_desc_man);
    if (!IsMWEBCapabilityDescriptor()) {
        return false;
    }

    std::optional<CKey> scan_ckey;
    std::optional<CKey> spend_ckey;
    if (m_wallet_descriptor.descriptor->GetMWEBScanSpendKeys(signing_provider, scan_ckey, spend_ckey) && scan_ckey) {
        const SecretKey scan_secret = KeyToSecretKey(*scan_ckey);
        if (!scan_secret.IsNull()) {
            return SetMWEBScanSecret(batch, scan_secret);
        }
    }

    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> extpubs;
    m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, extpubs);
    for (const CExtPubKey& xpub : extpubs) {
        CKey key;
        if (!signing_provider.GetKey(xpub.pubkey.GetID(), key)) {
            continue;
        }
        SecretKey scan_secret;
        SecretKey spend_secret;
        if (!SelectMWEBAccountMasterSecrets(xpub, key, m_mweb_scan_secret, scan_secret, spend_secret)) {
            continue;
        }
        return SetMWEBScanSecret(batch, scan_secret);
    }

    return false;
}

} // namespace wallet
