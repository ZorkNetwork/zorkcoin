#include <mw/wallet/keychain.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/key_derivation.h>
#include <mw/crypto/secret_keys.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/models/tx/output_mask.h>
#include <wallet/imweb_keystore.h>
#include <key_io.h>

MW_NAMESPACE

bool Keychain::RewindOutput(const Output& output, mw::Coin& coin) const
{
    if (!output.HasStandardFields()) {
        return false;
    }
    if (!output.Ko().IsValid() || !output.Ke().IsValid()) {
        return false;
    }

    try {
        assert(!GetScanSecret().IsNull());
        if (RecoverViewTag(output.Ke(), GetScanSecret()) != output.GetViewTag()) {
            return false;
        }

        SecretKey t = RecoverSharedSecret(output.Ke(), GetScanSecret());

        // Check if B_i belongs to wallet
        const StealthAddress address = RecoverSubaddress(output.Ko(), t, m_scanSecret);
        const std::optional<uint32_t> address_index = LookupAddressIndex(address);
        if (!address_index) {
            return false;
        }

        // Calc blinding factor and unmask nonce and amount.
        OutputMask mask = OutputMask::FromShared(t);
        uint64_t value = mask.MaskValue(output.GetMaskedValue());
        BigInt<16> n = mask.MaskNonce(output.GetMaskedNonce());

        if (mask.SwitchCommit(value) != output.GetCommitment()) {
            return false;
        }

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        if (output.Ke() != DeriveOutputKeyExchangePubKey(address, DeriveOutputSendKey(address, value, n))) {
            return false;
        }

        mw::Coin rewound;
        rewound.address_index = *address_index;
        rewound.blind = std::make_optional(mask.GetRawBlind());
        rewound.amount = value;
        rewound.output_id = output.GetOutputID();
        rewound.address = address;
        rewound.shared_secret = std::make_optional(std::move(t));
        rewound.master_scan_key_id = GetMasterScanKeyID();
        rewound.spend_key = CalculateOutputKey(rewound);
        coin = std::move(rewound);
        return true;
    } catch (const CryptoException&) {
        return false;
    }
}

std::optional<SecretKey> Keychain::CalculateOutputKey(const mw::Coin& coin) const
{
    // If we already calculated the spend key, there's no need to calculate it again.
    if (coin.HasSpendKey()) {
        return coin.spend_key;
    }

    // Watch-only or locked wallets will not have the spend secret.
    if (!HasSpendSecret() || !coin.HasSharedSecret() || !coin.IsMine()) {
        return std::nullopt;
    }

    // An address_index of CUSTOM_KEY means the spend key was not generated from the MWEB keychain.
    // We should lookup the secret key in the wallet DB, instead of calculating by index.
    if (coin.address_index == CUSTOM_KEY) {
        if (!coin.HasAddress()) {
            return std::nullopt;
        }

        CKey key;
        if (!m_keystore.GetKey(coin.address->B().GetID(), key)) {
            return std::nullopt;
        }

        return DeriveOutputSpendKey(SecretKey(reinterpret_cast<const uint8_t*>(key.data())), *coin.shared_secret);
    }

    return DeriveOutputSpendKey(GetSpendKey(coin.address_index), *coin.shared_secret);
}

std::optional<SecretKey> Keychain::CalculateOutputSpendKey(const mw::Coin& coin) const
{
    if (!coin.HasSharedSecret() || !coin.IsMine()) {
        return std::nullopt;
    }

    if (coin.HasAddress() && coin.address_index != CUSTOM_KEY && HasSpendPubKey() &&
        GetStealthAddress(coin.address_index) != *coin.address) {
        return std::nullopt;
    }

    if (coin.HasAddress()) {
        CKey key;
        if (m_keystore.GetKey(coin.address->B().GetID(), key)) {
            return DeriveOutputSpendKey(SecretKey(reinterpret_cast<const uint8_t*>(key.data())), *coin.shared_secret);
        }
    }

    if (!HasSpendSecret() || coin.address_index == CUSTOM_KEY) {
        return std::nullopt;
    }

    return DeriveOutputSpendKey(GetSpendKey(coin.address_index), *coin.shared_secret);
}

bool Keychain::PopulateSpendMaterial(mw::Coin& coin) const
{
    if (!HasSpendSecret() || !coin.HasSharedSecret() || !coin.IsMine()) {
        return coin.HasSpendMaterial();
    }

    if (!coin.blind) {
        coin.blind = std::make_optional(OutputMask::FromShared(*coin.shared_secret).GetRawBlind());
    }

    if (!coin.HasSpendKey()) {
        if (auto spend_key = CalculateOutputKey(coin)) {
            coin.spend_key = *spend_key;
        }
    }

    return coin.HasSpendMaterial();
}

StealthAddress Keychain::GetStealthAddress(const uint32_t index) const
{
    assert(m_spendPubkey.has_value());
    return DeriveSubaddress(*m_spendPubkey, m_scanSecret, index);
}

SecretKey Keychain::GetSpendKey(const uint32_t index) const
{
    assert(!m_spendSecret.IsNull());
    return DeriveSubaddressSpendKey(m_spendSecret, m_scanSecret, index);
}

std::optional<uint32_t> Keychain::LookupAddressIndex(const StealthAddress& address) const
{
    const auto metadata = m_keystore.GetMetadata(address);
    if (!metadata) {
        return std::nullopt;
    }

    // v0.21.2 incorrectly generated MWEB keys from the pre-split keypool for upgraded wallets.
    // These keys will not have an mweb_index, so we set the address_index as CUSTOM_KEY.
    return metadata->mweb_index.value_or(CUSTOM_KEY);
}

SecretKey Keychain::GetRewindKey() const
{
    return DeriveRewindKey(m_scanSecret);
}

SecretKey Keychain::GetSenderSigningKey(const uint64_t index) const
{
    return DeriveSenderSigningKey(m_scanSecret, index);
}

void Keychain::TopUpSenderPubKeys(const uint64_t range_end)
{
    for (uint64_t index = m_sender_pubkey_range_end; index < range_end; ++index) {
        m_sender_pubkeys.emplace(PublicKey::From(GetSenderSigningKey(index)), index);
    }
    m_sender_pubkey_range_end = std::max(m_sender_pubkey_range_end, range_end);
}

std::optional<uint64_t> Keychain::LookupSenderPubKeyIndex(const PublicKey& sender_pubkey) const
{
    const auto it = m_sender_pubkeys.find(sender_pubkey);
    if (it == m_sender_pubkeys.end()) {
        return std::nullopt;
    }
    return it->second;
}

END_NAMESPACE
