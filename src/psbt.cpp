// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <common/types.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/schnorr.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/signingprovider.h>
#include <util/check.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <algorithm>
#include <set>

using common::PSBTError;

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx, uint32_t version) : m_version(version)
{
    assert(m_version == 0 || m_version == 2);

    tx_version = tx.version;
    fallback_locktime = tx.nLockTime;
    inputs.reserve(tx.vin.size());
    for (const CTxIn& input : tx.vin) {
        inputs.emplace_back(GetVersion(), input.prevout.hash, input.prevout.n, input.nSequence);
    }
    outputs.reserve(tx.vout.size());
    for (const CTxOut& output : tx.vout) {
        outputs.emplace_back(GetVersion(), output.nValue, output.scriptPubKey);
    }

    // PSBTv0 cannot carry MWEB data.
    if (GetVersion() < 2) {
        return;
    }

    const mw::MutableTx& mweb_tx = tx.mweb_tx;
    if (!mweb_tx.kernel_offset.IsNull()) mweb_tx_offset = mweb_tx.kernel_offset;
    if (!mweb_tx.stealth_offset.IsNull()) mweb_stealth_offset = mweb_tx.stealth_offset;

    for (const mw::MutableInput& mweb_input : mweb_tx.inputs) {
        PSBTInput& psbt_input = inputs.emplace_back(GetVersion(), mweb_input.output_id);
        psbt_input.mweb_output_commit = mweb_input.commitment;
        psbt_input.mweb_output_pubkey = mweb_input.output_pubkey;
        psbt_input.mweb_input_pubkey = mweb_input.input_pubkey;
        psbt_input.mweb_features = mweb_input.features;
        psbt_input.mweb_sig = mweb_input.signature;
        psbt_input.mweb_amount = mweb_input.amount;
        psbt_input.mweb_extra_data = mweb_input.extradata;
    }

    for (const mw::MutableOutput& mweb_output : mweb_tx.outputs) {
        PSBTOutput& psbt_output = outputs.emplace_back(GetVersion(), mweb_output.amount.value_or(0), CScript{});
        psbt_output.m_has_script = false;
        psbt_output.mweb_stealth_address = mweb_output.address;
        psbt_output.mweb_commit = mweb_output.commitment;
        psbt_output.mweb_sender_pubkey = mweb_output.sender_pubkey;
        psbt_output.mweb_output_pubkey = mweb_output.receiver_pubkey;
        if (mweb_output.message.has_value()) {
            psbt_output.mweb_features = mweb_output.message->features;
            psbt_output.mweb_standard_fields = mweb_output.message->GetStandardFields();
            psbt_output.mweb_extra_data = mweb_output.message->extra_data;
        }
        if (mweb_output.proof.has_value() && *mweb_output.proof) {
            psbt_output.mweb_rangeproof = **mweb_output.proof;
        }
        psbt_output.mweb_sig = mweb_output.signature;
    }

    for (const mw::MutableKernel& mweb_kernel : mweb_tx.kernels) {
        PSBTKernel& psbt_kernel = kernels.emplace_back();
        psbt_kernel.features = mweb_kernel.GetFeatureByte();
        psbt_kernel.commit = mweb_kernel.excess;
        psbt_kernel.stealth_commit = mweb_kernel.stealth_excess;
        psbt_kernel.fee = mweb_kernel.fee;
        psbt_kernel.pegin_amount = mweb_kernel.pegin;
        psbt_kernel.pegouts = mweb_kernel.GetPegOuts();
        psbt_kernel.lock_height = mweb_kernel.lock_height;
        psbt_kernel.extra_data = mweb_kernel.extradata;
        psbt_kernel.sig = mweb_kernel.signature;
    }
}

bool PartiallySignedTransaction::ContainsMWEBComponents() const noexcept
{
    if (mweb_tx_offset.has_value() || mweb_stealth_offset.has_value() || !kernels.empty()) {
        return true;
    }
    return std::any_of(inputs.begin(), inputs.end(), [](const PSBTInput& input) { return input.IsMWEB(); }) ||
           std::any_of(outputs.begin(), outputs.end(), [](const PSBTOutput& output) { return output.IsMWEB(); });
}

bool PartiallySignedTransaction::IsComplete() const noexcept
{
    const bool is_mweb = ContainsMWEBComponents();
    if (is_mweb && kernels.empty()) {
        return false;
    }

    for (const PSBTInput& input : inputs) {
        if (!PSBTInputSigned(input)) {
            return false;
        }

        if (input.IsMWEB()) {
            if (!input.mweb_features || !input.mweb_output_commit || !input.mweb_output_pubkey) {
                return false;
            }
            const uint8_t features = *input.mweb_features;
            if ((features & Input::STEALTH_KEY_FEATURE_BIT) && !input.mweb_input_pubkey) {
                return false;
            }
            if ((features & Input::EXTRA_DATA_FEATURE_BIT) && input.mweb_extra_data.empty()) {
                return false;
            }
        }
    }

    for (const PSBTKernel& kernel : kernels) {
        if (!kernel.commit || !kernel.features || !kernel.sig) {
            return false;
        }

        const uint8_t features = *kernel.features;
        if ((features & Kernel::FEE_FEATURE_BIT) && !kernel.fee) {
            return false;
        }
        if ((features & Kernel::PEGIN_FEATURE_BIT) && !kernel.pegin_amount) {
            return false;
        }
        if ((features & Kernel::PEGOUT_FEATURE_BIT) && kernel.pegouts.empty()) {
            return false;
        }
        if ((features & Kernel::HEIGHT_LOCK_FEATURE_BIT) && !kernel.lock_height) {
            return false;
        }
        if ((features & Kernel::STEALTH_EXCESS_FEATURE_BIT) && !kernel.stealth_commit) {
            return false;
        }
        if ((features & Kernel::EXTRA_DATA_FEATURE_BIT) && kernel.extra_data.empty()) {
            return false;
        }
        // MWEB: a field without its bit is serialized but not read back.
        if ((CalculateKernelFeatures(kernel) & ~features) != 0) {
            return false;
        }
    }

    for (const PSBTOutput& output : outputs) {
        if (!output.IsMWEB()) continue;
        if (!output.mweb_commit || !output.mweb_features || !output.mweb_sender_pubkey ||
            !output.mweb_output_pubkey || !output.mweb_rangeproof || !output.mweb_sig) {
            return false;
        }

        const uint8_t features = *output.mweb_features;
        if ((features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT) && !output.mweb_standard_fields) {
            return false;
        }
        if ((features & OutputMessage::EXTRA_DATA_FEATURE_BIT) && output.mweb_extra_data.empty()) {
            return false;
        }
    }

    if (is_mweb && (!mweb_tx_offset.has_value() || !mweb_stealth_offset.has_value())) {
        return false;
    }

    return true;
}

uint8_t CalculateKernelFeatures(const PSBTKernel& kernel)
{
    uint8_t features{0};
    features |= kernel.fee.has_value() ? Kernel::FEE_FEATURE_BIT : 0;
    features |= kernel.pegin_amount.has_value() ? Kernel::PEGIN_FEATURE_BIT : 0;
    features |= !kernel.pegouts.empty() ? Kernel::PEGOUT_FEATURE_BIT : 0;
    features |= kernel.lock_height.has_value() ? Kernel::HEIGHT_LOCK_FEATURE_BIT : 0;
    features |= kernel.stealth_commit.has_value() ? Kernel::STEALTH_EXCESS_FEATURE_BIT : 0;
    features |= !kernel.extra_data.empty() ? Kernel::EXTRA_DATA_FEATURE_BIT : 0;
    return features;
}

namespace {
template <typename T>
bool MergeOptionalStrict(std::optional<T>& dst, const std::optional<T>& src)
{
    if (!src.has_value()) {
        return true;
    }
    if (!dst.has_value()) {
        dst = src;
        return true;
    }
    return *dst == *src;
}

template <typename T>
bool MergeVectorStrict(std::vector<T>& dst, const std::vector<T>& src)
{
    if (src.empty()) {
        return true;
    }
    if (dst.empty()) {
        dst = src;
        return true;
    }
    return dst == src;
}

bool MergeUnknownStrict(std::map<std::vector<unsigned char>, std::vector<unsigned char>>& dst, const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& src)
{
    for (const auto& [key, value] : src) {
        const auto [it, inserted] = dst.emplace(key, value);
        if (!inserted && it->second != value) {
            return false;
        }
    }
    return true;
}

bool MergeProprietaryStrict(std::set<PSBTProprietary>& dst, const std::set<PSBTProprietary>& src)
{
    for (const PSBTProprietary& prop : src) {
        const auto [it, inserted] = dst.insert(prop);
        if (!inserted && (it->identifier != prop.identifier || it->subtype != prop.subtype || it->value != prop.value)) {
            return false;
        }
    }
    return true;
}

bool IsPeginPlaceholderScript(const CScript& script)
{
    mw::Hash kernel_id;
    return script.IsMWEBPegin(&kernel_id) && kernel_id.IsZero();
}

bool IsFinalPeginScript(const CScript& script)
{
    mw::Hash kernel_id;
    return script.IsMWEBPegin(&kernel_id) && !kernel_id.IsZero();
}

bool HasBaseSignatureData(const PartiallySignedTransaction& psbt)
{
    return std::any_of(psbt.inputs.begin(), psbt.inputs.end(), [](const PSBTInput& input) {
        return !input.IsMWEB() && input.HasSignatures();
    });
}

bool HasMWEBSignatureOrProof(const PartiallySignedTransaction& psbt)
{
    for (const PSBTInput& input : psbt.inputs) {
        if (input.mweb_sig.has_value()) return true;
    }
    for (const PSBTOutput& output : psbt.outputs) {
        if (output.mweb_rangeproof.has_value() || output.mweb_sig.has_value()) return true;
    }
    for (const PSBTKernel& kernel : psbt.kernels) {
        if (kernel.sig.has_value()) return true;
    }
    return false;
}

/**
 * Merges the output scripts. A peg-in placeholder script may be replaced by the final peg-in script, but only
 * while the PSBT holding the placeholder has no base-layer signatures, since those commit to the script.
 */
bool MergeScriptStrict(PSBTOutput& dst, const PSBTOutput& src, bool dst_has_base_sigs, bool src_has_base_sigs)
{
    if (!src.m_has_script) {
        return true;
    }
    if (!dst.m_has_script) {
        dst.script = src.script;
        dst.m_has_script = true;
        return true;
    }
    if (dst.script == src.script) {
        return true;
    }
    if (IsPeginPlaceholderScript(dst.script) && IsFinalPeginScript(src.script)) {
        if (dst_has_base_sigs) {
            return false;
        }
        dst.script = src.script;
        return true;
    }
    if (IsFinalPeginScript(dst.script) && IsPeginPlaceholderScript(src.script)) {
        return !src_has_base_sigs;
    }
    return false;
}

bool KernelFeaturesConsistent(const PSBTKernel& kernel)
{
    return !kernel.features.has_value() || *kernel.features == CalculateKernelFeatures(kernel);
}

std::optional<mw::Hash> GetKernelID(const PSBTKernel& kernel)
{
    if (!kernel.features.has_value() || !kernel.commit.has_value() || !kernel.sig.has_value()) {
        return std::nullopt;
    }
    return Kernel(
        *kernel.features,
        kernel.fee,
        kernel.pegin_amount,
        kernel.pegouts,
        kernel.lock_height,
        kernel.stealth_commit,
        kernel.extra_data,
        *kernel.commit,
        *kernel.sig).GetKernelID();
}

bool MergeInputStrict(PSBTInput& dst, const PSBTInput& src)
{
    if (dst.IsMWEB() != src.IsMWEB()) {
        return false;
    }

    if (!dst.IsMWEB()) {
        if (dst.prev_txid != src.prev_txid || dst.prev_out != src.prev_out) {
            return false;
        }
    } else {
        if (dst.mweb_output_id != src.mweb_output_id) {
            return false;
        }
        if (src.prev_txid != dst.prev_txid) {
            if (!dst.prev_txid.IsNull() && !src.prev_txid.IsNull()) return false;
            if (dst.prev_txid.IsNull()) dst.prev_txid = src.prev_txid;
        }
        if (!MergeOptionalStrict(dst.prev_out, src.prev_out) ||
            !MergeOptionalStrict(dst.mweb_output_commit, src.mweb_output_commit) ||
            !MergeOptionalStrict(dst.mweb_output_pubkey, src.mweb_output_pubkey) ||
            !MergeOptionalStrict(dst.mweb_input_pubkey, src.mweb_input_pubkey) ||
            !MergeOptionalStrict(dst.mweb_features, src.mweb_features) ||
            !MergeOptionalStrict(dst.mweb_sig, src.mweb_sig) ||
            !MergeOptionalStrict(dst.mweb_amount, src.mweb_amount) ||
            !MergeOptionalStrict(dst.mweb_shared_secret, src.mweb_shared_secret) ||
            !MergeOptionalStrict(dst.mweb_key_exchange_pubkey, src.mweb_key_exchange_pubkey) ||
            !MergeOptionalStrict(dst.mweb_address_descriptor, src.mweb_address_descriptor) ||
            !MergeVectorStrict(dst.mweb_extra_data, src.mweb_extra_data)) {
            return false;
        }
    }

    if (!MergeUnknownStrict(dst.unknown, src.unknown) || !MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary)) {
        return false;
    }
    // Base-layer fields (sequence, locktimes, signatures, UTXOs, key paths) do not apply to MWEB inputs, so
    // only their MWEB fields are merged.
    if (dst.IsMWEB()) {
        return true;
    }
    dst.Merge(src);
    return true;
}

bool MergeOutputStrict(PSBTOutput& dst, const PSBTOutput& src, bool dst_has_base_sigs, bool src_has_base_sigs)
{
    if (dst.IsMWEB() != src.IsMWEB() || dst.amount != src.amount) {
        return false;
    }
    if (!MergeScriptStrict(dst, src, dst_has_base_sigs, src_has_base_sigs)) {
        return false;
    }
    if (!MergeUnknownStrict(dst.unknown, src.unknown) || !MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary)) {
        return false;
    }
    if (dst.IsMWEB()) {
        if (!MergeOptionalStrict(dst.mweb_stealth_address, src.mweb_stealth_address) ||
            !MergeOptionalStrict(dst.mweb_commit, src.mweb_commit) ||
            !MergeOptionalStrict(dst.mweb_features, src.mweb_features) ||
            !MergeOptionalStrict(dst.mweb_sender_pubkey, src.mweb_sender_pubkey) ||
            !MergeOptionalStrict(dst.mweb_output_pubkey, src.mweb_output_pubkey) ||
            !MergeOptionalStrict(dst.mweb_standard_fields, src.mweb_standard_fields) ||
            !MergeOptionalStrict(dst.mweb_rangeproof, src.mweb_rangeproof) ||
            !MergeOptionalStrict(dst.mweb_sig, src.mweb_sig) ||
            !MergeVectorStrict(dst.mweb_extra_data, src.mweb_extra_data)) {
            return false;
        }
    }
    dst.Merge(src);
    return true;
}

bool MergeKernelStrict(PSBTKernel& dst, const PSBTKernel& src)
{
    if (!KernelFeaturesConsistent(dst) || !KernelFeaturesConsistent(src)) {
        return false;
    }
    if (!MergeOptionalStrict(dst.commit, src.commit) ||
        !MergeOptionalStrict(dst.stealth_commit, src.stealth_commit) ||
        !MergeOptionalStrict(dst.fee, src.fee) ||
        !MergeOptionalStrict(dst.pegin_amount, src.pegin_amount) ||
        !MergeVectorStrict(dst.pegouts, src.pegouts) ||
        !MergeOptionalStrict(dst.lock_height, src.lock_height) ||
        !MergeVectorStrict(dst.extra_data, src.extra_data) ||
        !MergeOptionalStrict(dst.sig, src.sig) ||
        !MergeUnknownStrict(dst.unknown, src.unknown)) {
        return false;
    }
    if (dst.features.has_value() || src.features.has_value()) {
        dst.features = CalculateKernelFeatures(dst);
    }
    return true;
}

/** Merges two PSBTs of which at least one has MWEB components. Leaves dst unchanged on failure. */
bool MergeMWEB(PartiallySignedTransaction& dst, const PartiallySignedTransaction& src)
{
    // The base txid does not cover MWEB data, and finalizing peg-in scripts changes it,
    // so compare the transaction structure explicitly.
    if (dst.GetVersion() != src.GetVersion() || dst.tx_version != src.tx_version) {
        return false;
    }
    if (dst.inputs.size() != src.inputs.size() ||
        dst.outputs.size() != src.outputs.size() ||
        dst.kernels.size() != src.kernels.size()) {
        return false;
    }
    const std::optional<uint32_t> dst_locktime = dst.ComputeTimeLock();
    const std::optional<uint32_t> src_locktime = src.ComputeTimeLock();
    if (!dst_locktime || !src_locktime || *dst_locktime != *src_locktime) {
        return false;
    }

    PartiallySignedTransaction merged{dst};
    const bool dst_has_base_sigs = HasBaseSignatureData(merged);
    const bool src_has_base_sigs = HasBaseSignatureData(src);

    for (size_t i = 0; i < merged.inputs.size(); ++i) {
        if (!MergeInputStrict(merged.inputs[i], src.inputs[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < merged.outputs.size(); ++i) {
        if (!MergeOutputStrict(merged.outputs[i], src.outputs[i], dst_has_base_sigs, src_has_base_sigs)) {
            return false;
        }
    }
    for (size_t i = 0; i < merged.kernels.size(); ++i) {
        if (!MergeKernelStrict(merged.kernels[i], src.kernels[i])) {
            return false;
        }
    }
    if (!MergeOptionalStrict(merged.mweb_tx_offset, src.mweb_tx_offset) ||
        !MergeOptionalStrict(merged.mweb_stealth_offset, src.mweb_stealth_offset) ||
        !VerifyPeginOutputs(merged, /*require_final=*/false)) {
        return false;
    }
    if (!MergeUnknownStrict(merged.unknown, src.unknown) || !MergeProprietaryStrict(merged.m_proprietary, src.m_proprietary)) {
        return false;
    }

    merged.MergeGlobalXPubs(src);
    if (!merged.fallback_locktime.has_value()) merged.fallback_locktime = src.fallback_locktime;

    // An absent field carries no information, so the flags are OR'd. Once anything MWEB is
    // signed or proven, the transaction can no longer be modified.
    if (merged.m_tx_modifiable.has_value() && src.m_tx_modifiable.has_value()) {
        *merged.m_tx_modifiable |= *src.m_tx_modifiable;
    } else if (!merged.m_tx_modifiable.has_value()) {
        merged.m_tx_modifiable = src.m_tx_modifiable;
    }
    if (merged.m_tx_modifiable.has_value() && HasMWEBSignatureOrProof(merged)) {
        merged.m_tx_modifiable->reset();
    }

    dst = std::move(merged);
    return true;
}
} // namespace

bool VerifyPeginOutputs(const PartiallySignedTransaction& psbt, bool require_final)
{
    std::vector<const PSBTKernel*> pegin_kernels;
    for (const PSBTKernel& kernel : psbt.kernels) {
        if (kernel.pegin_amount.has_value()) {
            pegin_kernels.push_back(&kernel);
        }
    }

    struct PeginOutput {
        const PSBTOutput* output;
        mw::Hash kernel_id;
    };
    std::vector<PeginOutput> pegin_outputs;
    bool has_final_pegin_script{false};
    for (const PSBTOutput& output : psbt.outputs) {
        mw::Hash kernel_id;
        if (!output.m_has_script || !output.script.IsMWEBPegin(&kernel_id)) {
            continue;
        }
        if (!kernel_id.IsZero()) {
            has_final_pegin_script = true;
        }
        pegin_outputs.push_back(PeginOutput{&output, std::move(kernel_id)});
    }

    // Check every pairing that can already be formed, even while a partial PSBT is still missing
    // peg-in outputs or kernels.
    for (size_t i = 0; i < pegin_outputs.size() && i < pegin_kernels.size(); ++i) {
        const PeginOutput& pegin_output = pegin_outputs[i];
        const PSBTKernel& pegin_kernel = *pegin_kernels[i];

        if (pegin_output.output->amount != *pegin_kernel.pegin_amount) {
            return false;
        }
        if (pegin_output.kernel_id.IsZero()) {
            if (require_final) {
                return false;
            }
            continue;
        }
        const std::optional<mw::Hash> kernel_id = GetKernelID(pegin_kernel);
        if (!kernel_id.has_value() || pegin_output.kernel_id != *kernel_id) {
            return false;
        }
    }

    // Once any peg-in script is final, or before extraction, every peg-in output needs its kernel.
    if (pegin_outputs.size() != pegin_kernels.size() && (require_final || has_final_pegin_script)) {
        return false;
    }

    return true;
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    if (ContainsMWEBComponents() || psbt.ContainsMWEBComponents()) {
        return MergeMWEB(*this, psbt);
    }

    // Prohibited to merge two PSBTs over different transactions
    std::optional<Txid> this_id = GetUniqueID();
    std::optional<Txid> psbt_id = psbt.GetUniqueID();
    if (!this_id || !psbt_id || this_id != psbt_id) {
        return false;
    }
    if (GetVersion() != psbt.GetVersion()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    MergeGlobalXPubs(psbt);
    if (fallback_locktime == std::nullopt && psbt.fallback_locktime != std::nullopt) fallback_locktime = psbt.fallback_locktime;

    // Set m_tx_modifiable only if either PSBT had it set
    if (m_tx_modifiable.has_value() || psbt.m_tx_modifiable.has_value()) {
        // In general, we AND the modifiable flags
        std::bitset<8> this_modifiable = m_tx_modifiable.value_or(0);
        std::bitset<8> psbt_modifiable = psbt.m_tx_modifiable.value_or(0);
        std::bitset<8> final_modifiable = this_modifiable & psbt_modifiable;
        // SIGHASH_SINGLE Modifiable (bit 2) needs to be bitwise OR'd
        final_modifiable.set(2, this_modifiable[2] || psbt_modifiable[2]);

        m_tx_modifiable = final_modifiable;
    }

    m_proprietary.insert(psbt.m_proprietary.begin(), psbt.m_proprietary.end());
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

void PartiallySignedTransaction::MergeGlobalXPubs(const PartiallySignedTransaction& psbt)
{
    for (const auto& [origin, xpubs] : psbt.m_xpubs) {
        for (const CExtPubKey& xpub : xpubs) {
            const bool known{std::ranges::any_of(m_xpubs, [&](const auto& entry) { return entry.second.contains(xpub); })};
            if (!known) m_xpubs[origin].insert(xpub);
        }
    }
}

std::optional<uint32_t> PartiallySignedTransaction::ComputeTimeLock() const
{
    if (GetVersion() >= 2) {
        std::optional<uint32_t> time_lock{0};
        std::optional<uint32_t> height_lock{0};
        for (const PSBTInput& input : inputs) {
            if (input.time_locktime.has_value() && !input.height_locktime.has_value()) {
                height_lock.reset(); // Transaction can no longer have a height locktime
                if (!time_lock.has_value()) {
                    return std::nullopt;
                }
            } else if (!input.time_locktime.has_value() && input.height_locktime.has_value()) {
                time_lock.reset(); // Transaction can no longer have a time locktime
                if (!height_lock.has_value()) {
                    return std::nullopt;
                }
            }
            if (input.time_locktime && time_lock.has_value()) {
                time_lock = std::max(time_lock, input.time_locktime);
            }
            if (input.height_locktime && height_lock.has_value()) {
                height_lock = std::max(height_lock, input.height_locktime);
            }
        }
        if (height_lock.has_value() && *height_lock > 0) {
            return *height_lock;
        }
        if (time_lock.has_value() && *time_lock > 0) {
            return *time_lock;
        }
    }
    return fallback_locktime.value_or(0);
}

std::optional<CMutableTransaction> PartiallySignedTransaction::GetUnsignedTx() const
{
    CMutableTransaction mtx;
    mtx.version = tx_version;
    std::optional<uint32_t> locktime = ComputeTimeLock();
    if (!locktime) {
        return std::nullopt;
    }
    mtx.nLockTime = *locktime;
    uint32_t max_sequence = CTxIn::SEQUENCE_FINAL;
    for (const PSBTInput& input : inputs) {
        if (input.IsMWEB()) {
            mw::MutableInput mweb_input(*input.mweb_output_id);
            mweb_input.commitment = input.mweb_output_commit;
            mweb_input.output_pubkey = input.mweb_output_pubkey;
            mweb_input.amount = input.mweb_amount;
            if (input.mweb_shared_secret.has_value()) {
                mweb_input.raw_blind = mw::DeriveOutputRawBlind(*input.mweb_shared_secret);
            }
            mweb_input.features = input.mweb_features;
            mweb_input.extradata = input.mweb_extra_data;
            mweb_input.input_pubkey = input.mweb_input_pubkey;
            mweb_input.signature = input.mweb_sig;
            mweb_input.key_exchange_pubkey = input.mweb_key_exchange_pubkey;
            mweb_input.shared_secret = input.mweb_shared_secret;
            mtx.mweb_tx.inputs.push_back(std::move(mweb_input));
            continue;
        }
        if (!input.prev_out.has_value()) {
            return std::nullopt;
        }
        CTxIn txin;
        txin.prevout.hash = input.prev_txid;
        txin.prevout.n = *input.prev_out;
        txin.nSequence = input.sequence.value_or(max_sequence);
        mtx.vin.push_back(txin);
    }
    for (const PSBTOutput& output : outputs) {
        if (output.IsMWEB()) {
            mw::MutableOutput mweb_output;
            mweb_output.commitment = output.mweb_commit;
            mweb_output.sender_pubkey = output.mweb_sender_pubkey;
            mweb_output.receiver_pubkey = output.mweb_output_pubkey;
            uint8_t features{0};
            if (output.mweb_features.has_value()) {
                features = *output.mweb_features;
            } else {
                features |= output.mweb_standard_fields.has_value() ? OutputMessage::STANDARD_FIELDS_FEATURE_BIT : 0;
                features |= !output.mweb_extra_data.empty() ? OutputMessage::EXTRA_DATA_FEATURE_BIT : 0;
            }
            mweb_output.message = OutputMessage(features, output.mweb_standard_fields, output.mweb_extra_data);
            if (output.mweb_rangeproof.has_value()) {
                mweb_output.proof = std::make_shared<const RangeProof>(*output.mweb_rangeproof);
            }
            mweb_output.signature = output.mweb_sig;
            mweb_output.amount = output.amount;
            mweb_output.address = output.mweb_stealth_address;
            mtx.mweb_tx.outputs.push_back(std::move(mweb_output));
            continue;
        }
        CTxOut txout;
        txout.nValue = output.amount;
        txout.scriptPubKey = output.script;
        mtx.vout.push_back(txout);
    }
    for (const PSBTKernel& kernel : kernels) {
        mw::MutableKernel mweb_kernel;
        mweb_kernel.fee = kernel.fee;
        mweb_kernel.pegin = kernel.pegin_amount;
        mweb_kernel.SetPegOuts(kernel.pegouts);
        mweb_kernel.lock_height = kernel.lock_height;
        mweb_kernel.excess = kernel.commit;
        mweb_kernel.stealth_excess = kernel.stealth_commit;
        mweb_kernel.extradata = kernel.extra_data;
        mweb_kernel.signature = kernel.sig;
        if (kernel.commit && kernel.sig && kernel.features) {
            // The signature covers the feature byte. Like a kernel read from the wire, it may
            // set the peg-out, extra-data and unassigned bits without their fields, but no
            // other bit whose field is absent.
            constexpr uint8_t read_back_bits{Kernel::FEE_FEATURE_BIT | Kernel::PEGIN_FEATURE_BIT |
                                             Kernel::HEIGHT_LOCK_FEATURE_BIT | Kernel::STEALTH_EXCESS_FEATURE_BIT};
            const uint8_t implied{CalculateKernelFeatures(kernel)};
            const uint8_t added = *kernel.features & ~implied;
            if ((*kernel.features & implied) == implied && (added & read_back_bits) == 0) {
                mweb_kernel.features = kernel.features;
            }
        }
        mtx.mweb_tx.kernels.push_back(std::move(mweb_kernel));
    }
    mtx.mweb_tx.kernel_offset = mweb_tx_offset.value_or(BlindingFactor{});
    mtx.mweb_tx.stealth_offset = mweb_stealth_offset.value_or(BlindingFactor{});
    return mtx;
}

std::optional<Txid> PartiallySignedTransaction::GetUniqueID() const
{
    // Get the unsigned transaction
    std::optional<CMutableTransaction> mtx = GetUnsignedTx();
    if (!mtx) {
        return std::nullopt;
    }
    if (GetVersion() >= 2) {
        for (CTxIn& txin : mtx->vin) {
            txin.nSequence = 0;
        }
    }
    return mtx->GetHash();
}

bool PartiallySignedTransaction::AddInput(const PSBTInput& psbtin)
{
    // The input being added must be for this PSBT's version
    if (psbtin.GetVersion() != GetVersion()) {
        return false;
    }

    // Prevent duplicate inputs
    if (std::find_if(inputs.begin(), inputs.end(),
        [&psbtin](const PSBTInput& psbt) {
            if (psbtin.IsMWEB() || psbt.IsMWEB()) {
                return psbt.mweb_output_id == psbtin.mweb_output_id;
            }
            return psbt.prev_txid == psbtin.prev_txid && psbt.prev_out == psbtin.prev_out;
        }
    ) != inputs.end()) {
        return false;
    }

    if (GetVersion() < 2) {
        // This is a v0 psbt, so do the v0 AddInput
        inputs.push_back(psbtin);
        inputs.back().partial_sigs.clear();
        inputs.back().final_script_sig.clear();
        inputs.back().final_script_witness.SetNull();
        return true;
    }

    // Check inputs modifiable flag
    if (!m_tx_modifiable.has_value() || !m_tx_modifiable->test(0)) {
        return false;
    }

    // Determine if we need to iterate the inputs.
    // For now, we only do this if the new input has a required time lock.
    // BIP 370 states that we should also do this if m_tx_modifiable's bit 2 is set
    // (Has SIGHASH_SINGLE flag) but since we are only adding inputs at the end of the vector,
    // we don't care about that.
    bool iterate_inputs = psbtin.time_locktime != std::nullopt || psbtin.height_locktime != std::nullopt;
    if (iterate_inputs) {
        std::optional<uint32_t> old_timelock = ComputeTimeLock();
        if (!old_timelock) {
            return false;
        }

        std::optional<uint32_t> time_lock = psbtin.time_locktime;
        std::optional<uint32_t> height_lock = psbtin.height_locktime;
        bool has_sigs = false;
        for (const PSBTInput& input : inputs) {
            if (input.time_locktime.has_value() && !input.height_locktime.has_value()) {
                height_lock.reset(); // Transaction can no longer have a height locktime
                if (time_lock == std::nullopt) {
                    return false;
                }
            } else if (!input.time_locktime.has_value() && input.height_locktime.has_value()) {
                time_lock.reset(); // Transaction can no longer have a time locktime
                if (height_lock == std::nullopt) {
                    return false;
                }
            }
            if (input.time_locktime && time_lock.has_value()) {
                time_lock = std::max(time_lock, input.time_locktime);
            }
            if (input.height_locktime && height_lock.has_value()) {
                height_lock = std::max(height_lock, input.height_locktime);
            }
            if (input.HasSignatures()) {
                has_sigs = true;
            }
        }
        uint32_t new_timelock = fallback_locktime.value_or(0);
        if (height_lock.has_value() && *height_lock > 0) {
            new_timelock = *height_lock;
        } else if (time_lock.has_value() && *time_lock > 0) {
            new_timelock = *time_lock;
        }
        if (has_sigs && *old_timelock != new_timelock) {
            return false;
        }
    }

    // Add the input to the end, keeping MWEB inputs last
    if (psbtin.IsMWEB()) {
        inputs.push_back(psbtin);
    } else {
        const auto first_mweb = std::find_if(inputs.begin(), inputs.end(), [](const PSBTInput& input) { return input.IsMWEB(); });
        inputs.insert(first_mweb, psbtin);
    }
    return true;
}

bool PartiallySignedTransaction::AddOutput(const PSBTOutput& psbtout)
{
    // The output being added must be for this PSBT's version
    if (psbtout.GetVersion() != GetVersion()) {
        return false;
    }

    if (GetVersion() < 2) {
        // This is a v0 psbt, do the v0 AddOutput
        outputs.push_back(psbtout);
        return true;
    }

    // No global tx, must be PSBTv2
    // Check outputs are modifiable
    if (!m_tx_modifiable.has_value() || !m_tx_modifiable->test(1)) {
        return false;
    }
    // Keep MWEB outputs last
    if (psbtout.IsMWEB()) {
        outputs.push_back(psbtout);
    } else {
        const auto first_mweb = std::find_if(outputs.begin(), outputs.end(), [](const PSBTOutput& output) { return output.IsMWEB(); });
        outputs.insert(first_mweb, psbtout);
    }

    return true;
}

bool PSBTInput::GetUTXO(CTxOut& utxo) const
{
    if (non_witness_utxo) {
        if (!prev_out.has_value() || *prev_out >= non_witness_utxo->vout.size()) {
            return false;
        }
        if (non_witness_utxo->GetHash() != prev_txid) {
            return false;
        }
        utxo = non_witness_utxo->vout[*prev_out];
    } else if (!witness_utxo.IsNull()) {
        utxo = witness_utxo;
    } else {
        return false;
    }
    return true;
}

COutPoint PSBTInput::GetOutPoint() const
{
    return COutPoint(prev_txid, prev_out.value_or(COutPoint::NULL_INDEX));
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_key_sig.empty()) {
        sigdata.taproot_key_path_sig = m_tap_key_sig;
    }
    for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
        sigdata.taproot_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!m_tap_internal_key.IsNull()) {
        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
    }
    if (!m_tap_merkle_root.IsNull()) {
        sigdata.tr_spenddata.merkle_root = m_tap_merkle_root;
    }
    for (const auto& [leaf_script, control_block] : m_tap_scripts) {
        sigdata.tr_spenddata.scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
    for (const auto& [hash, preimage] : ripemd160_preimages) {
        sigdata.ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sha256_preimages) {
        sigdata.sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash160_preimages) {
        sigdata.hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash256_preimages) {
        sigdata.hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    sigdata.musig2_pubkeys.insert(m_musig2_participants.begin(), m_musig2_participants.end());
    for (const auto& [agg_key_lh, pubnonces] : m_musig2_pubnonces) {
        sigdata.musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : m_musig2_partial_sigs) {
        sigdata.musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.taproot_key_path_sig.empty()) {
        m_tap_key_sig = sigdata.taproot_key_path_sig;
    }
    for (const auto& [pubkey_leaf, sig] : sigdata.taproot_script_sigs) {
        m_tap_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (!sigdata.tr_spenddata.merkle_root.IsNull()) {
        m_tap_merkle_root = sigdata.tr_spenddata.merkle_root;
    }
    for (const auto& [leaf_script, control_block] : sigdata.tr_spenddata.scripts) {
        m_tap_scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
    m_musig2_participants.insert(sigdata.musig2_pubkeys.begin(), sigdata.musig2_pubkeys.end());
    for (const auto& [agg_key_lh, pubnonces] : sigdata.musig2_pubnonces) {
        m_musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : sigdata.musig2_partial_sigs) {
        m_musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
    for (const auto& [hash, preimage] : sigdata.ripemd160_preimages) {
        ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.sha256_preimages) {
        sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.hash160_preimages) {
        hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.hash256_preimages) {
        hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    m_proprietary.insert(input.m_proprietary.begin(), input.m_proprietary.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    // Merge by control block, the serialized key (BIP 371), to avoid duplicate keys. Keep the
    // leaf script already present; BIP 174 lets the Combiner pick arbitrarily on conflict.
    std::set<std::vector<unsigned char>> seen_control_blocks;
    for (const auto& [_, control_blocks] : m_tap_scripts) {
        seen_control_blocks.insert(control_blocks.begin(), control_blocks.end());
    }
    for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
        for (const auto& control_block : control_blocks) {
            if (seen_control_blocks.insert(control_block).second) m_tap_scripts[leaf].insert(control_block);
        }
    }
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
    if (m_tap_key_sig.empty() && !input.m_tap_key_sig.empty()) m_tap_key_sig = input.m_tap_key_sig;
    if (m_tap_internal_key.IsNull() && !input.m_tap_internal_key.IsNull()) m_tap_internal_key = input.m_tap_internal_key;
    if (m_tap_merkle_root.IsNull() && !input.m_tap_merkle_root.IsNull()) m_tap_merkle_root = input.m_tap_merkle_root;
    m_musig2_participants.insert(input.m_musig2_participants.begin(), input.m_musig2_participants.end());
    for (const auto& [agg_key_lh, pubnonces] : input.m_musig2_pubnonces) {
        m_musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : input.m_musig2_partial_sigs) {
        m_musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
    if (sighash_type == std::nullopt && input.sighash_type != std::nullopt) sighash_type = input.sighash_type;
    if (sequence == std::nullopt && input.sequence != std::nullopt) sequence = input.sequence;
    if (time_locktime == std::nullopt && input.time_locktime != std::nullopt) time_locktime = input.time_locktime;
    if (height_locktime == std::nullopt && input.height_locktime != std::nullopt) height_locktime = input.height_locktime;
}

bool PSBTInput::HasSignatures() const
{
    return !final_script_sig.empty()
           || !final_script_witness.IsNull()
           || !partial_sigs.empty()
           || !m_tap_key_sig.empty()
           || !m_tap_script_sigs.empty()
           || !m_musig2_partial_sigs.empty();
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_tree.empty() && m_tap_internal_key.IsFullyValid()) {
        TaprootBuilder builder;
        for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
            builder.Add((int)depth, script, (int)leaf_ver, /*track=*/true);
        }
        assert(builder.IsComplete());
        builder.Finalize(m_tap_internal_key);
        TaprootSpendData spenddata = builder.GetSpendData();

        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
        sigdata.tr_spenddata.Merge(spenddata);
        sigdata.tr_builder = builder;
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
    sigdata.musig2_pubkeys.insert(m_musig2_participants.begin(), m_musig2_participants.end());
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (sigdata.tr_builder.has_value() && sigdata.tr_builder->HasScripts()) {
        m_tap_tree = sigdata.tr_builder->GetTreeTuples();
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
    m_musig2_participants.insert(sigdata.musig2_pubkeys.begin(), sigdata.musig2_pubkeys.end());
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    m_proprietary.insert(output.m_proprietary.begin(), output.m_proprietary.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
    if (m_tap_internal_key.IsNull() && !output.m_tap_internal_key.IsNull()) m_tap_internal_key = output.m_tap_internal_key;
    if (m_tap_tree.empty() && !output.m_tap_tree.empty()) m_tap_tree = output.m_tap_tree;
    m_musig2_participants.insert(output.m_musig2_participants.begin(), output.m_musig2_participants.end());
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull() || (input.IsMWEB() && input.mweb_sig.has_value());
}

static bool VerifyMWEBPSBTInputSignature(const PSBTInput& input)
{
    if (!input.mweb_sig.has_value() || !input.mweb_output_id.has_value() || !input.mweb_output_pubkey.has_value() || !input.mweb_features.has_value()) {
        return false;
    }

    const uint8_t features = *input.mweb_features;
    if ((features & Input::STEALTH_KEY_FEATURE_BIT) && !input.mweb_input_pubkey.has_value()) {
        return false;
    }
    if ((features & Input::EXTRA_DATA_FEATURE_BIT) && input.mweb_extra_data.empty()) {
        return false;
    }

    Hasher msg_hasher;
    msg_hasher << features << *input.mweb_output_id;
    if (features & Input::EXTRA_DATA_FEATURE_BIT) {
        msg_hasher << input.mweb_extra_data;
    }
    const mw::Hash msg_hash = msg_hasher.hash();

    // The keys come from untrusted PSBT data, and libmw throws if they are not valid points.
    try {
        PublicKey public_key = *input.mweb_output_pubkey;
        if (features & Input::STEALTH_KEY_FEATURE_BIT) {
            Hasher key_hasher;
            key_hasher << *input.mweb_input_pubkey << *input.mweb_output_pubkey;
            const SecretKey key_hash{key_hasher.hash()};
            public_key = public_key.Mul(key_hash).Add(*input.mweb_input_pubkey);
        }
        return Schnorr::Verify(*input.mweb_sig, public_key, msg_hash);
    } catch (const std::exception&) {
        return false;
    }
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction& psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(input_index < psbt.inputs.size());
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.IsMWEB()) {
        return VerifyMWEBPSBTInputSignature(input);
    }

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }

    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return false;
    }
    const CMutableTransaction& tx = *unsigned_tx;
    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    if (psbt.outputs.at(index).IsMWEB()) {
        return;
    }

    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return;
    }
    const CTxOut& out = unsigned_tx->vout.at(index);
    PSBTOutput& psbt_out = psbt.outputs.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    CMutableTransaction tx{};
    tx.vin.emplace_back();
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, {.sighash_type = SIGHASH_ALL});
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

std::optional<PrecomputedTransactionData> PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{
    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return std::nullopt;
    }
    const CMutableTransaction& tx = *unsigned_tx;
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos;
    for (const PSBTInput& input : psbt.inputs) {
        if (input.IsMWEB()) continue;
        if (!input.GetUTXO(utxos.emplace_back())) have_all_spent_outputs = false;
    }
    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

util::Expected<void, PSBTError> SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, const common::PSBTFillOptions& options,  SignatureData* out_sigdata)
{
    PSBTInput& input = psbt.inputs.at(index);
    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return util::Unexpected{PSBTError::INVALID_TX};
    }
    const CMutableTransaction& tx = *unsigned_tx;

    if (PSBTInputSignedAndVerified(psbt, index, txdata)) {
        return {};
    }

    // MWEB inputs are not signed by script signing.
    if (input.IsMWEB()) {
        return util::Unexpected{PSBTError::INCOMPLETE};
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return util::Unexpected{PSBTError::MISSING_INPUTS};
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return util::Unexpected{PSBTError::MISSING_INPUTS};
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return util::Unexpected{PSBTError::MISSING_INPUTS};
    }

    // Get the sighash type
    // If both the field and the parameter are provided, they must match
    // If only the parameter is provided, use it and add it to the PSBT if it is other than SIGHASH_DEFAULT
    // for all input types, and not SIGHASH_ALL for non-taproot input types.
    // If neither are provided, use SIGHASH_DEFAULT if it is taproot, and SIGHASH_ALL for everything else.
    int sighash{options.sighash_type.value_or(utxo.scriptPubKey.IsPayToTaproot() ? SIGHASH_DEFAULT : SIGHASH_ALL)};

    // For user safety, the desired sighash must be provided if the PSBT wants something other than the default set in the previous line.
    if (input.sighash_type && input.sighash_type != sighash) {
        return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
    }
    // Set the PSBT sighash field when sighash is not DEFAULT or ALL
    // DEFAULT is allowed for non-taproot inputs since DEFAULT may be passed for them (e.g. the psbt being signed also has taproot inputs)
    // Note that signing already aliases DEFAULT to ALL for non-taproot inputs.
    if (utxo.scriptPubKey.IsPayToTaproot() ? sighash != SIGHASH_DEFAULT :
                                            (sighash != SIGHASH_DEFAULT && sighash != SIGHASH_ALL)) {
        input.sighash_type = sighash;
    }

    // Check all existing signatures use the sighash type
    if (sighash == SIGHASH_DEFAULT) {
        if (!input.m_tap_key_sig.empty() && input.m_tap_key_sig.size() != 64) {
            return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.m_tap_script_sigs) {
            if (sig.size() != 64) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
    } else {
        if (!input.m_tap_key_sig.empty() && (input.m_tap_key_sig.size() != 65 || input.m_tap_key_sig.back() != sighash)) {
            return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.m_tap_script_sigs) {
            if (sig.size() != 65 || sig.back() != sighash) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.partial_sigs) {
            if (sig.second.back() != sighash) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
    }

    sigdata.witness = false;
    bool sig_complete;
    if (txdata == nullptr) {
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, {.sighash_type = sighash});
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return util::Unexpected{PSBTError::INCOMPLETE};

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!options.finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // We can remove the non_witness_utxo if and only if there are no non-segwit or segwit v0
        // inputs in this transaction. Since this requires inspecting the entire transaction, this
        // is something for the caller to deal with (i.e. FillPSBT).
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    if (!sig_complete) return util::Unexpected{PSBTError::INCOMPLETE};
    return {};
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx)
{
    // Figure out if any non_witness_utxos should be dropped
    std::vector<unsigned int> to_drop;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const auto& input = psbtx.inputs.at(i);
        int wit_ver;
        std::vector<unsigned char> wit_prog;
        if (input.witness_utxo.IsNull() || !input.witness_utxo.scriptPubKey.IsWitnessProgram(wit_ver, wit_prog)) {
            // There's a non-segwit input, so we cannot drop any non_witness_utxos
            to_drop.clear();
            break;
        }
        if (wit_ver == 0) {
            // Segwit v0, so we cannot drop any non_witness_utxos
            to_drop.clear();
            break;
        }
        // non_witness_utxos cannot be dropped if the sighash type includes SIGHASH_ANYONECANPAY
        // Since callers should have called SignPSBTInput which updates the sighash type in the PSBT, we only
        // need to look at that field. If it is not present, then we can assume SIGHASH_DEFAULT or SIGHASH_ALL.
        if (input.sighash_type != std::nullopt && (*input.sighash_type & 0x80) == SIGHASH_ANYONECANPAY) {
            to_drop.clear();
            break;
        }

        if (input.non_witness_utxo) {
            to_drop.push_back(i);
        }
    }

    // Drop the non_witness_utxos that we can drop
    for (unsigned int i : to_drop) {
        psbtx.inputs.at(i).non_witness_utxo = nullptr;
    }
}

/** Checks that a PSBT with MWEB components, whose inputs are all finalized, extracts to a valid transaction. */
static bool VerifyFinalMWEBPSBT(const PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata)
{
    if (!psbtx.IsComplete() || !VerifyPeginOutputs(psbtx, /*require_final=*/true)) {
        return false;
    }
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        if (!PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            return false;
        }
    }

    std::optional<CMutableTransaction> mtx = psbtx.GetUnsignedTx();
    if (!mtx) {
        return false;
    }
    for (unsigned int i = 0; i < mtx->vin.size(); ++i) {
        mtx->vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        mtx->vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }

    const CTransaction tx{*mtx};
    return !tx.mweb_tx.IsNull() && !tx.mweb_tx.m_transaction->GetValidationError().has_value();
}

bool FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    std::optional<PrecomputedTransactionData> txdata_res = PrecomputePSBTData(psbtx);
    if (!txdata_res) {
        return false;
    }
    const PrecomputedTransactionData& txdata = *txdata_res;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);
        const auto sign_result = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, {.sighash_type = input.sighash_type, .finalize = true}, /*out_sigdata=*/nullptr);
        complete &= sign_result.has_value();
    }

    if (complete && psbtx.ContainsMWEBComponents()) {
        complete = VerifyFinalMWEBPSBT(psbtx, txdata);
    }

    return complete;
}

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result)
{
    // It's not safe to extract a PSBT that isn't finalized, and there's no easy way to check
    //   whether a PSBT is finalized without finalizing it, so we just do this.
    if (!FinalizePSBT(psbtx)) {
        return false;
    }

    std::optional<CMutableTransaction> unsigned_tx = psbtx.GetUnsignedTx();
    if (!unsigned_tx) {
        return false;
    }
    result = *unsigned_tx;
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        result.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }
    return true;
}

std::optional<PartiallySignedTransaction> CombinePSBTs(const std::vector<PartiallySignedTransaction>& psbtxs)
{
    PartiallySignedTransaction out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return std::nullopt;
        }
    }
    return out;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

util::Result<PartiallySignedTransaction> DecodeBase64PSBT(const std::string& base64_tx)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        return util::Error{Untranslated("invalid base64")};
    }
    return DecodeRawPSBT(MakeByteSpan(*tx_data));
}

util::Result<PartiallySignedTransaction> DecodeRawPSBT(std::span<const std::byte> tx_data)
{
    SpanReader ss_data{tx_data};
    try {
        PartiallySignedTransaction psbt(deserialize, ss_data);
        if (!ss_data.empty()) {
            return util::Error{Untranslated("extra data after PSBT")};
        }
        return psbt;
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

uint32_t PartiallySignedTransaction::GetVersion() const
{
    if (m_version != std::nullopt) {
        return *m_version;
    }
    return 0;
}
