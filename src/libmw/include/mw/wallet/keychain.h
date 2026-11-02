
#ifndef BITCOIN_LIBMW_INCLUDE_MW_WALLET_KEYCHAIN_H
#define BITCOIN_LIBMW_INCLUDE_MW_WALLET_KEYCHAIN_H
#include <mw/models/crypto/secret_key.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <pubkey.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>

// Forward Declarations
namespace wallet { class IMWEBKeyStore; }

MW_NAMESPACE

class Keychain
{
public:
    using Ptr = std::shared_ptr<Keychain>;

    Keychain(const wallet::IMWEBKeyStore& keystore, const SecretKey& scan_secret, const SecretKey& spend_secret)
        : m_keystore(keystore),
        m_scanSecret(scan_secret),
        m_spendSecret(spend_secret)
    {
        if (!m_spendSecret.IsNull()) {
            m_spendPubkey = PublicKey::From(m_spendSecret);
        }
    }

    // Watch-only keychain from the master scan secret and master spend pubkey.
    // Derives and identifies addresses; cannot produce spend keys.
    Keychain(const wallet::IMWEBKeyStore& keystore, const SecretKey& scan_secret, PublicKey spend_pubkey)
        : m_keystore(keystore),
        m_scanSecret(scan_secret),
        m_spendSecret(SecretKey::Null()),
        m_spendPubkey(std::move(spend_pubkey)) { }

    // If keychain is locked or watch-only (m_spendSecret is null),
    // this will still identify outputs belonging to the wallet, but
    // will not be able to calculate the coin's output key.
    // It will still calculate the shared_secret though, which can be
    // used to calculate the spend key when the wallet becomes unlocked.
    bool RewindOutput(const Output& output, mw::Coin& coin) const;

    // Calculates the output secret key for the given coin.
    // If the address index is known, it calculates from the keychain's master spend key.
    // If not, it attempts to lookup the spend key in the database.
    // Returns nullopt when keychain is locked or watch-only.
    std::optional<SecretKey> CalculateOutputKey(const mw::Coin& coin) const;

    // As CalculateOutputKey, but refuses coins whose recorded address does not match
    // the address derived at the coin's index. Returns nullopt without the spend key.
    std::optional<SecretKey> CalculateOutputSpendKey(const mw::Coin& coin) const;

    // Derive spend_key and blind into memory from shared_secret when unlocked.
    // Returns true when the coin has full spend material afterwards.
    bool PopulateSpendMaterial(mw::Coin& coin) const;

    // Calculates the StealthAddress at the given index.
    // Requires the master spend pubkey (available to watch-only and locked keychains).
    StealthAddress GetStealthAddress(uint32_t index) const;
    StealthAddress DeriveAddress(const uint32_t index) const { return GetStealthAddress(index); }

    // Requires that keychain be unlocked and not watch-only.
    SecretKey GetSpendKey(uint32_t index) const;
    SecretKey GetSubaddressSpendKey(const uint32_t index) const { return GetSpendKey(index); }

    // The address's mweb_index, CUSTOM_KEY for known addresses without one,
    // or nullopt when the keystore does not know the address.
    std::optional<uint32_t> LookupAddressIndex(const StealthAddress& address) const;

    SecretKey GetRewindKey() const;
    SecretKey GetSenderSigningKey(uint64_t index) const;
    void TopUpSenderPubKeys(uint64_t range_end);
    std::optional<uint64_t> LookupSenderPubKeyIndex(const PublicKey& sender_pubkey) const;

    CKeyID GetMasterScanKeyID() const { return PublicKey::From(m_scanSecret).GetID(); }
    const SecretKey& GetScanSecret() const noexcept { return m_scanSecret; }
    const SecretKey& GetSpendSecret() const noexcept { return m_spendSecret; }
    const std::optional<PublicKey>& GetSpendPubKey() const noexcept { return m_spendPubkey; }

    bool HasSpendPubKey() const noexcept { return m_spendPubkey.has_value(); }
    bool HasSpendSecret() const noexcept { return !m_spendSecret.IsNull(); }

    // Clears the spend secret from memory, effectively making this a watch-only keychain.
    void Lock() { m_spendSecret = SecretKey::Null(); }

    // Reassigns the spend secret. To be used when unlocking the wallet.
    void Unlock(const SecretKey& spend_secret)
    {
        m_spendSecret = spend_secret;
        m_spendPubkey = PublicKey::From(spend_secret);
    }

private:
    const wallet::IMWEBKeyStore& m_keystore;
    SecretKey m_scanSecret;
    SecretKey m_spendSecret;
    std::optional<PublicKey> m_spendPubkey;
    std::map<PublicKey, uint64_t> m_sender_pubkeys;
    uint64_t m_sender_pubkey_range_end{0};
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_WALLET_KEYCHAIN_H
