// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_PSBT_H
#define BITCOIN_MWEB_MWEB_PSBT_H

#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/sign.h>
#include <psbt.h>
#include <util/result.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class Output;
struct Descriptor;
struct FlatSigningProvider;

//! Key material carried by a single-address mweb() descriptor.
struct MWEBAddressDescriptorData {
    StealthAddress address{};
    std::optional<SecretKey> scan_secret{};
    std::optional<SecretKey> subaddress_spend_secret{};
    std::optional<uint32_t> index{};
};

//! Parses a single-address mweb() descriptor (PSBT_IN_MWEB_ADDR_DESCRIPTOR), including any private keys it carries.
util::Result<MWEBAddressDescriptorData> ParseMWEBAddressDescriptor(const std::string& descriptor_str);

//! The key material an MWEB PSBT updater/signer can draw on besides the PSBT itself.
class MWEBSigningKeyStore
{
public:
    virtual ~MWEBSigningKeyStore() = default;

    //! A known coin for the output, carrying its amount, shared secret and address where known.
    virtual std::optional<mw::Coin> GetCoin(const mw::Hash& output_id) const = 0;

    //! The master scan secret of the account a known coin belongs to.
    virtual std::optional<SecretKey> GetScanSecret(const mw::Coin& coin) const = 0;

    //! Master scan secrets to try when recovering an input's shared secret and subaddress.
    virtual std::vector<SecretKey> GetScanSecrets() const = 0;

    //! Whether the subaddress belongs to this store.
    virtual bool IsMine(const StealthAddress& address) const = 0;

    //! The spend secret of an owned subaddress, if this store can spend from it.
    virtual std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress& address) const = 0;

    //! The single-address descriptor to record in PSBT_IN_MWEB_ADDR_DESCRIPTOR for a known coin.
    virtual std::optional<std::string> InferAddressDescriptor(const mw::Coin& coin) const = 0;
};

//! A key store with no keys: inputs can only be signed from the PSBT's own fields and a private 0x96.
class EmptyMWEBSigningKeyStore final : public MWEBSigningKeyStore
{
public:
    std::optional<mw::Coin> GetCoin(const mw::Hash&) const override { return std::nullopt; }
    std::optional<SecretKey> GetScanSecret(const mw::Coin&) const override { return std::nullopt; }
    std::vector<SecretKey> GetScanSecrets() const override { return {}; }
    bool IsMine(const StealthAddress&) const override { return false; }
    std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress&) const override { return std::nullopt; }
    std::optional<std::string> InferAddressDescriptor(const mw::Coin&) const override { return std::nullopt; }
};

//! A key store built from mweb() output descriptors, e.g. those passed to descriptorprocesspsbt.
class DescriptorMWEBSigningKeyStore final : public MWEBSigningKeyStore
{
public:
    /**
     * Adds the subaddresses of an mweb() descriptor. Ranged accounts contribute the indexes in range.
     * A descriptor without the private scan key can recover nothing and adds nothing, like any other
     * watch-only descriptor. Fails if the descriptor is not an MWEB descriptor.
     */
    util::Result<void> AddDescriptor(const Descriptor& descriptor, const FlatSigningProvider& keys, std::pair<int64_t, int64_t> range);

    std::optional<mw::Coin> GetCoin(const mw::Hash&) const override { return std::nullopt; }
    std::optional<SecretKey> GetScanSecret(const mw::Coin&) const override { return std::nullopt; }
    std::vector<SecretKey> GetScanSecrets() const override { return m_scan_secrets; }
    bool IsMine(const StealthAddress& address) const override { return m_subaddresses.contains(address); }
    std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress& address) const override;
    std::optional<std::string> InferAddressDescriptor(const mw::Coin&) const override { return std::nullopt; }

private:
    std::vector<SecretKey> m_scan_secrets;
    std::map<StealthAddress, std::optional<SecretKey>> m_subaddresses;
};

//! Adds known coins to another key store, e.g. outputs a caller without a wallet rewound from the chain.
class CoinOverlayMWEBSigningKeyStore final : public MWEBSigningKeyStore
{
public:
    CoinOverlayMWEBSigningKeyStore(const MWEBSigningKeyStore& base, std::map<mw::Hash, mw::Coin> coins)
        : m_base{base}, m_coins{std::move(coins)} {}

    std::optional<mw::Coin> GetCoin(const mw::Hash& output_id) const override;
    std::optional<SecretKey> GetScanSecret(const mw::Coin& coin) const override { return m_base.GetScanSecret(coin); }
    std::vector<SecretKey> GetScanSecrets() const override { return m_base.GetScanSecrets(); }
    bool IsMine(const StealthAddress& address) const override { return m_base.IsMine(address); }
    std::optional<SecretKey> GetSubaddressSpendSecret(const StealthAddress& address) const override { return m_base.GetSubaddressSpendSecret(address); }
    std::optional<std::string> InferAddressDescriptor(const mw::Coin& coin) const override { return m_base.InferAddressDescriptor(coin); }

private:
    const MWEBSigningKeyStore& m_base;
    const std::map<mw::Hash, mw::Coin> m_coins;
};

/**
 * Rewinds the output an MWEB PSBT input spends, recovering its amount, blind, shared secret and subaddress.
 * Tries the key store's scan secrets, then the scan secret of the input's address descriptor if it carries one.
 */
std::optional<mw::Coin> RewindMWEBInputOutput(const PSBTInput& input, const Output& output, const MWEBSigningKeyStore& keystore);

/**
 * Resolves the key material for one MWEB PSBT input (the Updater role).
 *
 * Fills the amount, public coin fields, address descriptor and shared secret where the key store or the
 * input's own fields determine them. Returns the input's output spend key if one could be resolved,
 * nullopt if not (another signer may hold it), or an error if the address descriptor is inconsistent.
 */
util::Result<std::optional<SecretKey>> ResolveMWEBInputKeys(PSBTInput& input, const MWEBSigningKeyStore& keystore);

/**
 * Sets the kernel fee of a draft whose inputs and outputs are all MWEB and whose amounts are all known,
 * where the fee is the only balance unknown. Does nothing for any other PSBT.
 */
util::Result<void> InferMWEBKernelFee(PartiallySignedTransaction& psbtx);

/**
 * Signs the MWEB inputs, outputs and kernels of the PSBT and writes the results back into its MWEB fields,
 * peg-in output scripts and offsets. Returns the coins created for the signed outputs.
 *
 * May rewrite peg-in output scripts, so sighash data precomputed before this call must be rebuilt.
 */
util::Result<std::map<mw::Hash, mw::Coin>> SignPSBTMWEBComponents(
    PartiallySignedTransaction& psbtx,
    const std::map<mw::Hash, SecretKey>& spend_keys,
    const SecretKey& rewind_key,
    const mw::SenderKeyGenerator& generate_sender_key);

//! Whether any output still has a peg-in placeholder script (OP_9 <zero kernel ID>).
bool HasPeginPlaceholder(const PartiallySignedTransaction& psbtx);

struct MWEBFillResult {
    //! False when MWEB inputs still lack signing data, or a peg-in placeholder remains, so transparent
    //! inputs must not be signed yet: their signatures would commit to scripts MWEB signing rewrites.
    bool transparent_signing_allowed{true};
    //! Number of MWEB inputs signed.
    size_t n_signed{0};
    //! Coins created for the signed MWEB outputs.
    std::map<mw::Hash, mw::Coin> coins;
};

/**
 * Runs the MWEB stages of filling a PSBT: resolves every unsigned MWEB input, infers the fee of MWEB-only
 * drafts and, when signing, signs all MWEB components once every MWEB input can be signed.
 * Leaves the PSBT unchanged on error.
 */
util::Result<MWEBFillResult> FillMWEBPSBT(
    PartiallySignedTransaction& psbtx,
    const MWEBSigningKeyStore& keystore,
    bool sign,
    const SecretKey& rewind_key,
    const mw::SenderKeyGenerator& generate_sender_key);

#endif // BITCOIN_MWEB_MWEB_PSBT_H
