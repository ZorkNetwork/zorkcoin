// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/wallet/sign.h>

#include <mw/crypto/blinds.h>
#include <mw/crypto/key_derivation.h>
#include <mw/crypto/pedersen.h>
#include <mw/crypto/schnorr.h>
#include <mw/crypto/secret_keys.h>
#include <mw/exceptions/validation_exception.h>
#include <mw/models/tx/mutable_tx.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <util/translation.h>

#include <vector>

MW_NAMESPACE

namespace {

util::Result<Signature> InputSignature(
    const mw::Hash& output_id,
    const uint8_t features,
    const SecretKey& input_key,
    const SecretKey& output_key,
    const std::vector<uint8_t>& extra_data) noexcept
{
    try {
        const PublicKey input_pubkey = PublicKey::From(input_key);
        const PublicKey output_pubkey = PublicKey::From(output_key);

        // k_agg = k_i + HASH(K_i||K_o) * k_o
        Hasher key_hasher;
        key_hasher << input_pubkey << output_pubkey;
        const SecretKey key_hash = SecretKey::FromHash(key_hasher.hash());
        const SecretKey sig_key = SecretKeys::From(output_key)
                                      .Mul(key_hash)
                                      .Add(input_key)
                                      .Total();

        Hasher msg_hasher;
        msg_hasher << features << output_id;
        if (features & Input::EXTRA_DATA_FEATURE_BIT) {
            msg_hasher << extra_data;
        }

        return Schnorr::Sign(sig_key.data(), msg_hasher.hash());
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

struct SignInputResult {
    BlindingFactor input_blind{};
    SecretKey ephemeral_key{};
    SecretKey spend_key{};
};

util::Result<SignInputResult> SignInput(MutableInput& input) noexcept
{
    if (input.signature) {
        return util::Error{Untranslated("Input is already signed")};
    }

    if (!input.raw_blind) {
        if (!input.shared_secret) {
            return util::Error{Untranslated("Input blinding factor and shared secret missing")};
        }
        input.raw_blind = mw::DeriveOutputRawBlind(*input.shared_secret);
    }

    if (!input.spend_key) {
        return util::Error{Untranslated("Input spend key missing")};
    }

    if (!input.amount) {
        return util::Error{Untranslated("Input amount missing")};
    }

    try {
        const PublicKey output_pubkey = PublicKey::From(*input.spend_key);
        if (input.output_pubkey && *input.output_pubkey != output_pubkey) {
            return util::Error{Untranslated("Input spend key does not match output pubkey")};
        }
        input.output_pubkey = output_pubkey;

        if (!input.features) {
            input.features = static_cast<uint8_t>(
                Input::STEALTH_KEY_FEATURE_BIT |
                (input.extradata.empty() ? 0 : Input::EXTRA_DATA_FEATURE_BIT));
        } else if (!input.extradata.empty()) {
            input.features = static_cast<uint8_t>(*input.features | Input::EXTRA_DATA_FEATURE_BIT);
        }

        if ((*input.features & Input::EXTRA_DATA_FEATURE_BIT) && input.extradata.empty()) {
            return util::Error{Untranslated("Input extra data missing")};
        }

        if (!(*input.features & Input::STEALTH_KEY_FEATURE_BIT)) {
            return util::Error{Untranslated("Input does not have the stealth key feature")};
        }

        if (!input.ephemeral_key) {
            input.ephemeral_key = SecretKey::Random();
        }
        input.input_pubkey = PublicKey::From(*input.ephemeral_key);

        const BlindingFactor input_blind = Pedersen::BlindSwitch(*input.raw_blind, *input.amount);
        const Commitment commitment = Commitment::Blinded(input_blind, *input.amount);
        if (input.commitment && *input.commitment != commitment) {
            return util::Error{Untranslated("Input amount or blinding factor does not match commitment")};
        }
        input.commitment = commitment;

        util::Result<Signature> signature = InputSignature(
            input.output_id,
            *input.features,
            *input.ephemeral_key,
            *input.spend_key,
            input.extradata);
        if (!signature) {
            return util::Error{util::ErrorString(signature)};
        }
        input.signature = *signature;

        return SignInputResult{input_blind, *input.ephemeral_key, *input.spend_key};
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

struct SignOutputResult {
    BlindingFactor output_blind{};
    SecretKey ephemeral_key{};
    mw::Coin coin{};
};

util::Result<SignOutputResult> SignOutput(MutableOutput& output, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept
{
    if (output.signature) {
        return util::Error{Untranslated("Output is already signed")};
    }

    if (!output.amount || !output.address) {
        return util::Error{Untranslated("Output amount or address missing")};
    }

    const std::vector<uint8_t> extra_data = output.message ? output.message->extra_data : std::vector<uint8_t>{};
    if (output.message && (output.message->features & OutputMessage::EXTRA_DATA_FEATURE_BIT) && extra_data.empty()) {
        return util::Error{Untranslated("Output extra data missing")};
    }

    util::Result<SecretKey> sender_key = generate_sender_key();
    if (!sender_key) {
        return util::Error{util::ErrorString(sender_key)};
    }

    try {
        BlindingFactor raw_blind;
        const Output finalized = Output::Create(
            &raw_blind,
            *sender_key,
            rewind_key,
            *output.address,
            *output.amount,
            extra_data);
        output.Update(finalized);

        mw::Coin coin;
        coin.blind = raw_blind;
        coin.amount = *output.amount;
        coin.output_id = finalized.GetOutputID();
        coin.sender_key = *sender_key;
        coin.address = *output.address;

        return SignOutputResult{Pedersen::BlindSwitch(raw_blind, *output.amount), *sender_key, std::move(coin)};
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

//! Pairs peg-in kernels with peg-in outputs by relative order and writes the
//! final kernel IDs into the output scripts. Outputs may carry the all-zero
//! placeholder kernel ID or the matching kernel ID.
std::optional<bilingual_str> UpdatePegInScripts(CMutableTransaction& tx) noexcept
{
    std::vector<std::pair<CAmount, mw::Hash>> pegins;
    for (const MutableKernel& kernel : tx.mweb_tx.kernels) {
        if (!kernel.pegin) continue;

        const std::optional<mw::Hash> kernel_id = kernel.GetKernelID();
        if (!kernel_id) {
            return Untranslated("Kernel ID could not be calculated");
        }
        pegins.emplace_back(*kernel.pegin, *kernel_id);
    }

    std::vector<size_t> pegin_output_indices;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].scriptPubKey.IsMWEBPegin()) {
            pegin_output_indices.push_back(i);
        }
    }

    if (pegin_output_indices.size() != pegins.size()) {
        return Untranslated("Peg-in output count does not match MWEB pegin kernel count");
    }

    for (size_t i = 0; i < pegins.size(); ++i) {
        CTxOut& out = tx.vout[pegin_output_indices[i]];
        mw::Hash current_kernel_id;
        out.scriptPubKey.IsMWEBPegin(&current_kernel_id);

        if (out.nValue != pegins[i].first) {
            return Untranslated("Peg-in output amount does not match MWEB pegin kernel");
        }

        if (!current_kernel_id.IsZero() && current_kernel_id != pegins[i].second) {
            return Untranslated("Peg-in output kernel ID conflicts with MWEB pegin kernel order");
        }

        out.scriptPubKey = GetScriptForPegin(pegins[i].second);
    }

    return std::nullopt;
}

} // namespace

util::Result<SignTxResult> SignTx(CMutableTransaction& tx_in, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept
{
    SignTxResult result{};
    if (tx_in.mweb_tx.IsNull() || tx_in.mweb_tx.IsFinal()) {
        return result;
    }

    if (!generate_sender_key) {
        return util::Error{Untranslated("Sender key generator missing")};
    }

    try {
        CMutableTransaction tx{tx_in};
        Blinds kernel_offset{};
        Blinds stealth_offset{};

        if (tx.mweb_tx.kernels.empty()) {
            tx.mweb_tx.kernels.push_back(MutableKernel{});
        }

        for (MutableKernel& kernel : tx.mweb_tx.kernels) {
            if (kernel.IsFinal()) continue;

            const SecretKey kernel_blind = SecretKey::Random();
            const SecretKey stealth_blind = SecretKey::Random();
            const Kernel finalized = Kernel::Create(
                BlindingFactor(kernel_blind),
                std::make_optional(stealth_blind),
                kernel.fee,
                kernel.pegin,
                kernel.GetPegOuts(),
                kernel.lock_height,
                kernel.extradata);

            kernel.stealth_excess = finalized.GetStealthExcess();
            kernel.excess = finalized.GetExcess();
            kernel.signature = finalized.GetSignature();
            kernel.features = finalized.GetFeatures();

            kernel_offset.Sub(kernel_blind);
            stealth_offset.Sub(stealth_blind);
        }

        if (const auto error = UpdatePegInScripts(tx)) {
            return util::Error{*error};
        }

        for (MutableOutput& output : tx.mweb_tx.outputs) {
            if (output.IsFinal()) continue;

            util::Result<SignOutputResult> signed_output = SignOutput(output, rewind_key, generate_sender_key);
            if (!signed_output) {
                return util::Error{util::ErrorString(signed_output)};
            }

            kernel_offset.Add(signed_output->output_blind);
            stealth_offset.Add(signed_output->ephemeral_key);
            result.coins_by_output_id[*output.CalcOutputID()] = signed_output->coin;
        }

        for (MutableInput& input : tx.mweb_tx.inputs) {
            if (input.IsFinal()) continue;

            util::Result<SignInputResult> signed_input = SignInput(input);
            if (!signed_input) {
                return util::Error{util::ErrorString(signed_input)};
            }

            kernel_offset.Sub(signed_input->input_blind);
            stealth_offset.Add(signed_input->ephemeral_key);
            stealth_offset.Sub(signed_input->spend_key);
        }

        tx.mweb_tx.kernel_offset = kernel_offset.Total();
        tx.mweb_tx.stealth_offset = stealth_offset.Total();

        const MWEB::Tx finalized_tx{tx.mweb_tx};
        if (finalized_tx.IsNull()) {
            return util::Error{Untranslated("Failed to construct MWEB transaction")};
        }

        if (const auto tx_error = finalized_tx.m_transaction->GetValidationError()) {
            return util::Error{Untranslated(strprintf("Validate failed: %s", ConsensusErrorString(*tx_error)))};
        }

        tx_in = std::move(tx);
        return result;
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

END_NAMESPACE
