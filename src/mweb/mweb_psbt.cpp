// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_psbt.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <mw/crypto/key_derivation.h>
#include <mw/exceptions/crypto_exception.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/output_mask.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <util/translation.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <variant>

namespace {

std::optional<SecretKey> ToSecretKey(const std::optional<CKey>& key)
{
    if (!key || !key->IsValid() || key->size() != SecretKey::SIZE) return std::nullopt;
    return SecretKey{reinterpret_cast<const uint8_t*>(key->data())};
}

//! Writes the signed MWEB transaction back into the PSBT's MWEB fields, peg-in output scripts and offsets.
void CommitMWEBTxToPSBT(PartiallySignedTransaction& psbtx, const CMutableTransaction& mtx)
{
    if (psbtx.m_tx_modifiable.has_value()) {
        psbtx.m_tx_modifiable->reset();
    }

    size_t idx = 0;
    for (PSBTInput& psbt_input : psbtx.inputs) {
        if (!psbt_input.IsMWEB()) continue;

        const mw::MutableInput& input = mtx.mweb_tx.inputs[idx++];
        if (!psbt_input.mweb_output_commit.has_value()) {
            psbt_input.mweb_output_commit = input.commitment;
        }
        if (!psbt_input.mweb_output_pubkey.has_value()) {
            psbt_input.mweb_output_pubkey = input.output_pubkey;
        }
        psbt_input.mweb_input_pubkey = input.input_pubkey;
        psbt_input.mweb_features = input.features;
        psbt_input.mweb_sig = input.signature;
        psbt_input.mweb_amount = input.amount;
        psbt_input.mweb_extra_data = input.extradata;
    }

    idx = 0;
    for (PSBTOutput& psbt_output : psbtx.outputs) {
        if (!psbt_output.IsMWEB()) continue;

        const mw::MutableOutput& output = mtx.mweb_tx.outputs[idx++];
        psbt_output.amount = output.amount.value_or(psbt_output.amount);
        psbt_output.mweb_stealth_address = output.address;
        psbt_output.mweb_commit = output.commitment;
        psbt_output.mweb_sender_pubkey = output.sender_pubkey;
        psbt_output.mweb_output_pubkey = output.receiver_pubkey;
        assert(output.message.has_value());
        psbt_output.mweb_features = output.message->features;
        psbt_output.mweb_standard_fields = output.message->GetStandardFields();
        psbt_output.mweb_extra_data = output.message->extra_data;
        psbt_output.mweb_rangeproof = (output.proof && *output.proof) ? std::make_optional(**output.proof) : std::nullopt;
        psbt_output.mweb_sig = output.signature;
    }

    if (psbtx.kernels.size() < mtx.mweb_tx.kernels.size()) {
        psbtx.kernels.resize(mtx.mweb_tx.kernels.size());
    }

    idx = 0;
    for (const mw::MutableKernel& kernel : mtx.mweb_tx.kernels) {
        PSBTKernel& psbt_kernel = psbtx.kernels[idx++];
        psbt_kernel.features = kernel.GetFeatureByte();
        psbt_kernel.commit = kernel.excess;
        psbt_kernel.stealth_commit = kernel.stealth_excess;
        psbt_kernel.fee = kernel.fee;
        psbt_kernel.pegin_amount = kernel.pegin;
        psbt_kernel.pegouts = kernel.GetPegOuts();
        psbt_kernel.lock_height = kernel.lock_height;
        psbt_kernel.extra_data = kernel.extradata;
        psbt_kernel.sig = kernel.signature;
    }

    // Transparent outputs map one-to-one, in order, to the non-MWEB PSBT outputs.
    size_t vout_idx = 0;
    for (PSBTOutput& psbt_output : psbtx.outputs) {
        if (psbt_output.IsMWEB()) continue;
        const CTxOut& out = mtx.vout[vout_idx++];
        if (out.scriptPubKey.IsMWEBPegin()) {
            psbt_output.amount = out.nValue;
            psbt_output.script = out.scriptPubKey;
            psbt_output.m_has_script = true;
        }
    }

    psbtx.mweb_tx_offset = mtx.mweb_tx.kernel_offset.IsNull() ? std::nullopt : std::make_optional(mtx.mweb_tx.kernel_offset);
    psbtx.mweb_stealth_offset = mtx.mweb_tx.stealth_offset.IsNull() ? std::nullopt : std::make_optional(mtx.mweb_tx.stealth_offset);
}

void PopulateInputFromCoin(PSBTInput& input, const mw::Coin& coin)
{
    const mw::MutableInput coin_input = mw::MutableInput::FromCoin(coin);

    if (!input.mweb_amount) {
        input.mweb_amount = coin.amount;
    }
    if (!input.mweb_output_commit && coin_input.commitment) {
        input.mweb_output_commit = coin_input.commitment;
    }
    if (!input.mweb_output_pubkey && coin_input.output_pubkey) {
        input.mweb_output_pubkey = coin_input.output_pubkey;
    }
}

//! Resolves the input's shared secret: from the input itself, the known coin, or by ECDH with the descriptor's
//! or the coin's account scan secret. Failing those, the key store's scan secrets are tried, and the first that
//! recovers one of the store's own subaddresses is used.
std::optional<SecretKey> ResolveSharedSecret(const PSBTInput& input, const std::optional<mw::Coin>& coin,
                                             const MWEBSigningKeyStore& keystore,
                                             const std::optional<MWEBAddressDescriptorData>& descriptor_data)
{
    if (input.mweb_shared_secret) return input.mweb_shared_secret;
    if (coin && coin->shared_secret) return *coin->shared_secret;
    if (!input.mweb_key_exchange_pubkey) return std::nullopt;

    if (descriptor_data && descriptor_data->scan_secret) {
        return mw::RecoverSharedSecret(*input.mweb_key_exchange_pubkey, *descriptor_data->scan_secret);
    }
    if (coin) {
        if (const std::optional<SecretKey> scan_secret = keystore.GetScanSecret(*coin)) {
            return mw::RecoverSharedSecret(*input.mweb_key_exchange_pubkey, *scan_secret);
        }
    }
    if (!input.mweb_output_pubkey) return std::nullopt;
    for (const SecretKey& scan_secret : keystore.GetScanSecrets()) {
        SecretKey shared_secret = mw::RecoverSharedSecret(*input.mweb_key_exchange_pubkey, scan_secret);
        if (keystore.IsMine(mw::RecoverSubaddress(*input.mweb_output_pubkey, shared_secret, scan_secret))) {
            return shared_secret;
        }
    }
    return std::nullopt;
}

//! The input's subaddress: from the known coin or the descriptor, else recovered from its output pubkey with
//! the coin's account scan secret or one of the key store's.
std::optional<StealthAddress> ResolveSubaddress(const PSBTInput& input, const std::optional<mw::Coin>& coin,
                                                const MWEBSigningKeyStore& keystore, const SecretKey& shared_secret,
                                                const std::optional<MWEBAddressDescriptorData>& descriptor_data)
{
    if (coin && coin->address) return *coin->address;
    if (descriptor_data) return descriptor_data->address;
    if (!input.mweb_output_pubkey) return std::nullopt;
    if (coin) {
        if (const std::optional<SecretKey> scan_secret = keystore.GetScanSecret(*coin)) {
            return mw::RecoverSubaddress(*input.mweb_output_pubkey, shared_secret, *scan_secret);
        }
    }
    for (const SecretKey& scan_secret : keystore.GetScanSecrets()) {
        StealthAddress address = mw::RecoverSubaddress(*input.mweb_output_pubkey, shared_secret, scan_secret);
        if (keystore.IsMine(address)) return address;
    }
    return std::nullopt;
}

std::optional<mw::Coin> RewindOutput(const Output& output, const SecretKey& scan_secret)
{
    try {
        if (mw::RecoverViewTag(output.Ke(), scan_secret) != output.GetViewTag()) return std::nullopt;

        const SecretKey shared_secret = mw::RecoverSharedSecret(output.Ke(), scan_secret);
        const StealthAddress address = mw::RecoverSubaddress(output.Ko(), shared_secret, scan_secret);
        const OutputMask mask = OutputMask::FromShared(shared_secret);
        const uint64_t value = mask.MaskValue(output.GetMaskedValue());
        const BigInt<16> nonce = mask.MaskNonce(output.GetMaskedNonce());
        if (mask.SwitchCommit(value) != output.GetCommitment()) return std::nullopt;
        if (output.Ke() != mw::DeriveOutputKeyExchangePubKey(address, mw::DeriveOutputSendKey(address, value, nonce))) return std::nullopt;

        mw::Coin coin;
        coin.output_id = output.GetOutputID();
        coin.amount = value;
        coin.blind = std::make_optional(mask.GetRawBlind());
        coin.address = address;
        coin.shared_secret = std::make_optional(shared_secret);
        return coin;
    } catch (const CryptoException&) {
        return std::nullopt;
    }
}

bool SpendKeyMatches(const PSBTInput& input, const SecretKey& spend_key)
{
    return !input.mweb_output_pubkey || PublicKey::From(spend_key) == *input.mweb_output_pubkey;
}

} // namespace

namespace {
util::Result<MWEBAddressDescriptorData> ExtractAddressDescriptorData(const Descriptor& descriptor, const SigningProvider& keys)
{
    if (descriptor.GetOutputType() != OutputType::MWEB) {
        return util::Error{Untranslated("MWEB address descriptor has wrong output type")};
    }
    const MWEBDescriptorForm form = descriptor.GetMWEBForm();
    if (form == MWEBDescriptorForm::ACCOUNT || form == MWEBDescriptorForm::NONE) {
        return util::Error{Untranslated("MWEB address descriptor must be single-address")};
    }

    std::optional<CKey> scan_key;
    std::optional<CKey> spend_key;
    if (!descriptor.GetMWEBScanSpendKeys(keys, scan_key, spend_key)) {
        return util::Error{Untranslated("MWEB address descriptor has no scan private key")};
    }

    std::vector<CTxDestination> destinations;
    FlatSigningProvider expanded;
    if (!descriptor.ExpandDestinations(0, keys, destinations, expanded, nullptr, nullptr) ||
        destinations.size() != 1 || !std::holds_alternative<StealthAddress>(destinations.front())) {
        return util::Error{Untranslated("MWEB address descriptor did not expand to one MWEB address")};
    }

    MWEBAddressDescriptorData data;
    data.address = std::get<StealthAddress>(destinations.front());
    data.index = descriptor.GetMWEBIndex();
    data.scan_secret = ToSecretKey(scan_key);

    std::optional<SecretKey> spend_secret = ToSecretKey(spend_key);
    if (spend_secret && form == MWEBDescriptorForm::INDEXED && data.scan_secret && data.index) {
        spend_secret = mw::DeriveSubaddressSpendKey(*spend_secret, *data.scan_secret, *data.index);
    }
    if (spend_secret && PublicKey::From(*spend_secret) == data.address.GetSpendPubKey()) {
        data.subaddress_spend_secret = spend_secret;
    }

    return data;
}
} // namespace

util::Result<MWEBAddressDescriptorData> ParseMWEBAddressDescriptor(const std::string& descriptor_str)
{
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> descriptors = Parse(descriptor_str, keys, error, /*require_checksum=*/false);
    if (descriptors.empty()) {
        return util::Error{Untranslated(strprintf("Invalid MWEB address descriptor: %s", error))};
    }
    if (descriptors.size() != 1) {
        return util::Error{Untranslated("MWEB address descriptor must be single-address")};
    }
    return ExtractAddressDescriptorData(*descriptors.front(), keys);
}

util::Result<void> DescriptorMWEBSigningKeyStore::AddDescriptor(const Descriptor& descriptor, const FlatSigningProvider& keys, std::pair<int64_t, int64_t> range)
{
    if (descriptor.GetOutputType() != OutputType::MWEB) {
        return util::Error{Untranslated("Not an MWEB descriptor")};
    }

    std::optional<CKey> scan_key;
    std::optional<CKey> spend_key;
    descriptor.GetMWEBScanSpendKeys(keys, scan_key, spend_key);
    const std::optional<SecretKey> scan_secret = ToSecretKey(scan_key);
    if (!scan_secret) {
        return {};
    }
    const std::optional<SecretKey> spend_secret = ToSecretKey(spend_key);

    const MWEBDescriptorForm form = descriptor.GetMWEBForm();
    if (form == MWEBDescriptorForm::ACCOUNT) {
        std::optional<PublicKey> spend_pubkey;
        if (spend_secret) {
            spend_pubkey = PublicKey::From(*spend_secret);
        } else {
            std::vector<CScript> scripts;
            FlatSigningProvider out;
            descriptor.Expand(0, keys, scripts, out);
            const PublicKey scan_pubkey = PublicKey::From(*scan_secret);
            for (const auto& [id, pubkey] : out.pubkeys) {
                if (pubkey.IsCompressed() && PublicKey(pubkey.data()) != scan_pubkey) {
                    spend_pubkey = PublicKey(pubkey.data());
                }
            }
        }
        if (!spend_pubkey) {
            return util::Error{Untranslated("MWEB descriptor spend key could not be determined")};
        }
        if (range.first < 0 || range.second < range.first || range.second > std::numeric_limits<uint32_t>::max()) {
            return util::Error{Untranslated("Invalid MWEB descriptor range")};
        }
        for (int64_t i = range.first; i <= range.second; ++i) {
            const uint32_t index = static_cast<uint32_t>(i);
            const StealthAddress address = mw::DeriveSubaddress(*spend_pubkey, *scan_secret, index);
            m_subaddresses[address] = spend_secret ? std::make_optional(mw::DeriveSubaddressSpendKey(*spend_secret, *scan_secret, index)) : std::nullopt;
        }
    } else {
        util::Result<MWEBAddressDescriptorData> data = ExtractAddressDescriptorData(descriptor, keys);
        if (!data) {
            return util::Error{util::ErrorString(data)};
        }
        m_subaddresses[data->address] = data->subaddress_spend_secret;
    }

    if (std::find(m_scan_secrets.begin(), m_scan_secrets.end(), *scan_secret) == m_scan_secrets.end()) {
        m_scan_secrets.push_back(*scan_secret);
    }
    return {};
}

std::optional<SecretKey> DescriptorMWEBSigningKeyStore::GetSubaddressSpendSecret(const StealthAddress& address) const
{
    const auto it = m_subaddresses.find(address);
    return it == m_subaddresses.end() ? std::nullopt : it->second;
}

std::optional<mw::Coin> CoinOverlayMWEBSigningKeyStore::GetCoin(const mw::Hash& output_id) const
{
    const auto it = m_coins.find(output_id);
    return it == m_coins.end() ? m_base.GetCoin(output_id) : std::make_optional(it->second);
}

std::optional<mw::Coin> RewindMWEBInputOutput(const PSBTInput& input, const Output& output, const MWEBSigningKeyStore& keystore)
{
    if (!output.HasStandardFields() || !output.Ko().IsValid() || !output.Ke().IsValid()) {
        return std::nullopt;
    }

    std::vector<SecretKey> scan_secrets = keystore.GetScanSecrets();
    if (input.mweb_address_descriptor) {
        if (util::Result<MWEBAddressDescriptorData> data = ParseMWEBAddressDescriptor(*input.mweb_address_descriptor); data && data->scan_secret) {
            scan_secrets.push_back(*data->scan_secret);
        }
    }
    for (const SecretKey& scan_secret : scan_secrets) {
        if (std::optional<mw::Coin> coin = RewindOutput(output, scan_secret)) return coin;
    }
    return std::nullopt;
}

util::Result<std::optional<SecretKey>> ResolveMWEBInputKeys(PSBTInput& input, const MWEBSigningKeyStore& keystore)
{
    assert(input.IsMWEB());

    try {
        const std::optional<mw::Coin> coin = keystore.GetCoin(*input.mweb_output_id);
        if (coin) {
            PopulateInputFromCoin(input, *coin);
            if (!input.mweb_address_descriptor) {
                input.mweb_address_descriptor = keystore.InferAddressDescriptor(*coin);
            }
        }

        std::optional<MWEBAddressDescriptorData> descriptor_data;
        if (input.mweb_address_descriptor) {
            util::Result<MWEBAddressDescriptorData> parsed = ParseMWEBAddressDescriptor(*input.mweb_address_descriptor);
            if (!parsed) {
                return util::Error{util::ErrorString(parsed)};
            }
            descriptor_data = std::move(*parsed);
        }

        const std::optional<SecretKey> shared_secret = ResolveSharedSecret(input, coin, keystore, descriptor_data);
        if (!shared_secret) {
            return std::optional<SecretKey>{};
        }

        if (descriptor_data && descriptor_data->scan_secret && input.mweb_output_pubkey &&
            mw::RecoverSubaddress(*input.mweb_output_pubkey, *shared_secret, *descriptor_data->scan_secret) != descriptor_data->address) {
            return util::Error{Untranslated("MWEB address descriptor does not match input's output pubkey")};
        }
        input.mweb_shared_secret = shared_secret;

        if (descriptor_data && descriptor_data->subaddress_spend_secret) {
            const SecretKey spend_key = mw::DeriveOutputSpendKey(*descriptor_data->subaddress_spend_secret, *shared_secret);
            if (SpendKeyMatches(input, spend_key)) {
                return std::optional<SecretKey>{spend_key};
            }
        }

        const std::optional<StealthAddress> address = ResolveSubaddress(input, coin, keystore, *shared_secret, descriptor_data);
        if (address) {
            if (const std::optional<SecretKey> subaddress_spend_secret = keystore.GetSubaddressSpendSecret(*address)) {
                const SecretKey spend_key = mw::DeriveOutputSpendKey(*subaddress_spend_secret, *shared_secret);
                if (SpendKeyMatches(input, spend_key)) {
                    return std::optional<SecretKey>{spend_key};
                }
            }
        }
        return std::optional<SecretKey>{};
    } catch (const std::exception& e) {
        return util::Error{Untranslated(strprintf("Invalid MWEB input key material: %s", e.what()))};
    }
}

util::Result<void> InferMWEBKernelFee(PartiallySignedTransaction& psbtx)
{
    const auto is_mweb_input = [](const PSBTInput& input) { return input.IsMWEB(); };
    if (std::none_of(psbtx.inputs.begin(), psbtx.inputs.end(), is_mweb_input)) {
        return {};
    }

    // A missing amount means this PSBT still needs an updater that knows the coin. Do not guess a fee until
    // every input is known.
    if (std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) { return input.IsMWEB() && !input.mweb_amount; })) {
        return {};
    }

    // A draft with only MWEB inputs and outputs has exactly one balance equation, so its fee is unambiguous.
    // Mixed transactions already carry explicit kernel metadata.
    const bool has_transparent_component =
        std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) { return !input.IsMWEB(); }) ||
        std::any_of(psbtx.outputs.begin(), psbtx.outputs.end(), [](const PSBTOutput& output) { return !output.IsMWEB(); });
    const bool missing_fee = psbtx.kernels.empty() ||
        std::any_of(psbtx.kernels.begin(), psbtx.kernels.end(), [](const PSBTKernel& kernel) { return !kernel.fee; });
    if (has_transparent_component || !missing_fee) {
        return {};
    }

    if (psbtx.kernels.size() > 1) {
        return util::Error{Untranslated("Cannot infer MWEB fee across multiple kernels")};
    }

    CAmount input_amount{0};
    for (const PSBTInput& input : psbtx.inputs) {
        if (!MoneyRange(*input.mweb_amount) || !MoneyRange(input_amount + *input.mweb_amount)) {
            return util::Error{Untranslated("Invalid MWEB input amount")};
        }
        input_amount += *input.mweb_amount;
    }

    CAmount output_amount{0};
    for (const PSBTOutput& output : psbtx.outputs) {
        if (!MoneyRange(output.amount) || !MoneyRange(output_amount + output.amount)) {
            return util::Error{Untranslated("Invalid MWEB output amount")};
        }
        output_amount += output.amount;
    }

    CAmount pegout_amount{0};
    if (!psbtx.kernels.empty()) {
        for (const PegOutCoin& pegout : psbtx.kernels.front().pegouts) {
            if (!MoneyRange(pegout.GetAmount()) || !MoneyRange(pegout_amount + pegout.GetAmount())) {
                return util::Error{Untranslated("Invalid MWEB pegout amount")};
            }
            pegout_amount += pegout.GetAmount();
        }
    }

    const CAmount fee = input_amount - output_amount - pegout_amount;
    if (fee < 0 || !MoneyRange(fee)) {
        return util::Error{Untranslated("MWEB outputs exceed inputs")};
    }

    if (psbtx.kernels.empty()) {
        psbtx.kernels.emplace_back();
    }
    PSBTKernel& kernel = psbtx.kernels.front();
    kernel.fee = fee;
    uint8_t features = Kernel::FEE_FEATURE_BIT;
    features |= kernel.pegin_amount.has_value() ? Kernel::PEGIN_FEATURE_BIT : 0;
    features |= !kernel.pegouts.empty() ? Kernel::PEGOUT_FEATURE_BIT : 0;
    features |= kernel.lock_height.has_value() ? Kernel::HEIGHT_LOCK_FEATURE_BIT : 0;
    features |= kernel.stealth_commit.has_value() ? Kernel::STEALTH_EXCESS_FEATURE_BIT : 0;
    features |= !kernel.extra_data.empty() ? Kernel::EXTRA_DATA_FEATURE_BIT : 0;
    kernel.features = features;
    return {};
}

util::Result<std::map<mw::Hash, mw::Coin>> SignPSBTMWEBComponents(
    PartiallySignedTransaction& psbtx,
    const std::map<mw::Hash, SecretKey>& spend_keys,
    const SecretKey& rewind_key,
    const mw::SenderKeyGenerator& generate_sender_key)
{
    std::optional<CMutableTransaction> mtx = psbtx.GetUnsignedTx();
    if (!mtx) {
        return util::Error{Untranslated("PSBT has no valid locktime")};
    }
    for (mw::MutableInput& input : mtx->mweb_tx.inputs) {
        const auto it = spend_keys.find(input.output_id);
        if (it != spend_keys.end()) {
            input.spend_key = it->second;
        }
    }

    util::Result<mw::SignTxResult> result = mw::SignTx(*mtx, rewind_key, generate_sender_key);
    if (!result) {
        return util::Error{util::ErrorString(result)};
    }

    CommitMWEBTxToPSBT(psbtx, *mtx);
    return std::move(result->coins_by_output_id);
}

bool HasPeginPlaceholder(const PartiallySignedTransaction& psbtx)
{
    return std::any_of(psbtx.outputs.begin(), psbtx.outputs.end(), [](const PSBTOutput& output) {
        mw::Hash kernel_id;
        return output.m_has_script && output.script.IsMWEBPegin(&kernel_id) && kernel_id.IsZero();
    });
}

util::Result<MWEBFillResult> FillMWEBPSBT(
    PartiallySignedTransaction& psbtx,
    const MWEBSigningKeyStore& keystore,
    bool sign,
    const SecretKey& rewind_key,
    const mw::SenderKeyGenerator& generate_sender_key)
{
    MWEBFillResult result;
    if (!psbtx.ContainsMWEBComponents()) {
        return result;
    }

    PartiallySignedTransaction filled{psbtx};
    std::map<mw::Hash, SecretKey> spend_keys;
    for (PSBTInput& input : filled.inputs) {
        if (!input.IsMWEB() || PSBTInputSigned(input)) continue;
        util::Result<std::optional<SecretKey>> spend_key = ResolveMWEBInputKeys(input, keystore);
        if (!spend_key) {
            return util::Error{util::ErrorString(spend_key)};
        }
        if (spend_key->has_value()) {
            spend_keys.emplace(*input.mweb_output_id, **spend_key);
        }
    }

    if (util::Result<void> fee = InferMWEBKernelFee(filled); !fee) {
        return util::Error{util::ErrorString(fee)};
    }

    // A resolved spend key implies a resolved shared secret.
    const auto needs_signature = [](const PSBTInput& input) { return input.IsMWEB() && !input.mweb_sig; };
    const bool missing_signing_data = std::any_of(filled.inputs.begin(), filled.inputs.end(), [&](const PSBTInput& input) {
        return needs_signature(input) && (!input.mweb_amount || !spend_keys.contains(*input.mweb_output_id));
    });

    if (sign && !missing_signing_data) {
        // Signing validates the whole transaction, so on success every MWEB input is signed.
        const size_t n_unsigned = std::count_if(filled.inputs.begin(), filled.inputs.end(), needs_signature);
        util::Result<std::map<mw::Hash, mw::Coin>> coins = SignPSBTMWEBComponents(filled, spend_keys, rewind_key, generate_sender_key);
        if (!coins) {
            return util::Error{util::ErrorString(coins)};
        }
        result.coins = std::move(*coins);
        result.n_signed = n_unsigned;
    }

    result.transparent_signing_allowed = !missing_signing_data && !HasPeginPlaceholder(filled);
    psbtx = std::move(filled);
    return result;
}
