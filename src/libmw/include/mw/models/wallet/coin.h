
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_COIN_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_COIN_H
#include <mw/common/macros.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/commitment.h>
#include <mw/models/wallet/stealth_address.h>

#include <consensus/amount.h>
#include <pubkey.h>
#include <optional>

MW_NAMESPACE

/// <summary>
/// Change outputs will use the stealth address generated using index 0
/// </summary>
static constexpr uint32_t CHANGE_INDEX{0};

/// <summary>
/// Peg-in outputs will use the stealth address generated using index 1.
/// </summary>
static constexpr uint32_t PEGIN_INDEX{1};

/// <summary>
/// Outputs sent to a stealth address whose spend key was not generated using the MWEB
/// keychain won't have an address index. We use 0xfffffffe to represent this.
/// In that case, we must lookup the secret key in the wallet DB, rather than the MWEB keychain.
/// </summary>
static constexpr uint32_t CUSTOM_KEY{std::numeric_limits<uint32_t>::max() - 1};

/// <summary>
/// Outputs sent to others will be marked with an address_index of 0xffffffff.
/// </summary>
static constexpr uint32_t UNKNOWN_INDEX{std::numeric_limits<uint32_t>::max()};

/// <summary>
/// Represents an output owned by the wallet, and the keys necessary to spend it.
/// </summary>
struct Coin : public Traits::ISerializable {
    static constexpr uint8_t LATEST_VERSION = 3;

    // Index of the subaddress this coin was received at.
    uint32_t address_index{UNKNOWN_INDEX};

    // The private key needed in order to spend the coin.
    // Will be empty for watch-only wallets.
    // May be empty for locked wallets. Upon unlock, spend_key will get populated.
    std::optional<SecretKey> spend_key;

    // The blinding factor of the coin's output.
    // May be empty for watch-only wallets.
    std::optional<BlindingFactor> blind;

    // The output amount in litoshis.
    // Typically positive, but could be 0 in the future when we start using decoys to improve privacy.
    CAmount amount;

    // The output's ID (hash).
    mw::Hash output_id;

    // The ephemeral private key used by the sender to create the output.
    // This will only be populated when the coin has flag HAS_SENDER_INFO.
    std::optional<SecretKey> sender_key;

    // The StealthAddress the coin was sent to.
    // This will only be populated when the coin has flag HAS_SENDER_INFO.
    std::optional<StealthAddress> address;

    // The shared secret used to generate the output key.
    // By storing this, we are able to postpone calculation of the spend key.
    // This allows us to scan for outputs while wallet is locked, and recalculate
    // the output key once the wallet becomes unlocked.
    std::optional<SecretKey> shared_secret;

    // Key ID of the master scan pubkey of the keychain that owns or sent the coin.
    // Identifies the account when a wallet holds several MWEB keychains.
    std::optional<CKeyID> master_scan_key_id;

    bool IsChange() const noexcept { return address_index == CHANGE_INDEX; }
    bool IsPegIn() const noexcept { return address_index == PEGIN_INDEX; }
    bool IsMine() const noexcept { return address_index != UNKNOWN_INDEX; }
    bool HasAddress() const noexcept { return !!address; }
    bool HasSpendKey() const noexcept { return !!spend_key; }
    bool HasSharedSecret() const noexcept { return !!shared_secret; }
    bool HasSpendMaterial() const noexcept { return !!spend_key && !!blind; }

    void ClearSpendMaterial()
    {
        spend_key = std::nullopt;
        blind = std::nullopt;
        sender_key = std::nullopt;
    }

    Coin SanitizeForDisk() const
    {
        Coin sanitized = *this;
        sanitized.ClearSpendMaterial();
        return sanitized;
    }

    void Reset()
    {
        address_index = UNKNOWN_INDEX;
        spend_key = std::nullopt;
        blind = std::nullopt;
        amount = 0;
        output_id = mw::Hash();
        sender_key = std::nullopt;
        address = std::nullopt;
        shared_secret = std::nullopt;
        master_scan_key_id = std::nullopt;
    }

    //
    // Basic serialization format (v0):
    //  - byte version
    //  - varint address_index
    //  - bool has_spend_key
    //    * byte[32] spend_key - skip if has_spend_key is false
    //  - bool has_blind
    //    * byte[32] blind - skip if has_blind is false
    //  - varint amount
    //  - byte[32] output_id
    //
    // If version >= 1, format extended to include:
    //  - bool has_sender_key
    //    * byte[32] sender_key - skip if has_sender_key is false
    //  - bool has_address
    //    * byte[33] address.scan_key - skip if has_address is false
    //    * byte[33] address.spend_key - skip if has_address is false
    //
    // If version >= 2, format extended to include:
    //  - bool has_shared_secret
    //    * byte[32] shared_secret - skip if has_shared_secret is false
    //
    // If version >= 3, format extended to include:
    //  - bool has_master_scan_key_id
    //    * byte[20] master_scan_key_id - skip if has_master_scan_key_id is false
    //
    IMPL_SERIALIZABLE(Coin, obj)
    {
        // Always serialize using the latest version
        uint8_t version = LATEST_VERSION;
        READWRITE(version);
        if (version > LATEST_VERSION) {
            throw std::ios_base::failure("Unsupported Coin version");
        }

        READWRITE(VARINT(obj.address_index));
        READWRITE(obj.spend_key);
        READWRITE(obj.blind);
        READWRITE(VARINT_MODE(obj.amount, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(obj.output_id);

        if (version >= 1) {
            READWRITE(obj.sender_key);
            READWRITE(obj.address);
        }

        if (version >= 2) {
            READWRITE(obj.shared_secret);
        }

        if (version >= 3) {
            READWRITE(obj.master_scan_key_id);
        }
    }
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_COIN_H
