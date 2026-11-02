// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_MUTABLE_TX_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_MUTABLE_TX_H

#include <mw/common/macros.h>
#include <mw/common/optional_serialization.h>
#include <mw/consensus/weight.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>

#include <numeric>
#include <optional>
#include <vector>

MW_NAMESPACE

//! An MWEB input that may still be missing its signature, pubkeys or commitment.
struct MutableInput {
    // Coin: public info
    mw::Hash output_id;
    std::optional<Commitment> commitment;
    std::optional<PublicKey> output_pubkey;

    // Coin: secrets
    std::optional<CAmount> amount;               //! The amount being spent.
    std::optional<SecretKey> spend_key;          //! Secret key needed to spend the coin.
    std::optional<BlindingFactor> raw_blind;     //! Pre-switch blinding factor.
    std::optional<PublicKey> key_exchange_pubkey; //! Key exchange pubkey of the output being spent.
    std::optional<SecretKey> shared_secret;      //! Shared secret of the output being spent.

    // Input: public info
    std::optional<uint8_t> features;
    std::optional<PublicKey> input_pubkey;
    std::vector<uint8_t> extradata;
    std::optional<Signature> signature;

    // Input: secrets
    std::optional<SecretKey> ephemeral_key; //! Secret key of input_pubkey. Generated when signing.

    explicit MutableInput(mw::Hash output_id_) : output_id(std::move(output_id_)) {}

    //! Populates the public coin fields for spending the provided output.
    static MutableInput FromOutput(const Output& output)
    {
        MutableInput input(output.GetOutputID());
        input.commitment = output.GetCommitment();
        input.output_pubkey = output.GetReceiverPubKey();
        if (output.HasStandardFields()) {
            input.key_exchange_pubkey = output.GetKeyExchangePubKey();
        }
        return input;
    }

    //! Populates the coin fields known to the wallet. The spend key is left for the signer.
    static MutableInput FromCoin(const mw::Coin& coin)
    {
        MutableInput input(coin.output_id);
        input.amount = coin.amount;
        if (coin.blind) {
            input.raw_blind = *coin.blind;
        } else if (coin.shared_secret) {
            input.raw_blind = mw::DeriveOutputRawBlind(*coin.shared_secret);
        }
        if (input.raw_blind) {
            input.commitment = Commitment::Switch(*input.raw_blind, coin.amount);
        }
        if (coin.shared_secret) {
            input.shared_secret = *coin.shared_secret;
            if (coin.address) {
                input.output_pubkey = mw::DeriveOutputPubKey(*coin.address, *coin.shared_secret);
            }
        }
        return input;
    }

    bool operator==(const MutableInput& other) const noexcept
    {
        return output_id == other.output_id &&
               features == other.features &&
               commitment == other.commitment &&
               input_pubkey == other.input_pubkey &&
               output_pubkey == other.output_pubkey &&
               extradata == other.extradata &&
               signature == other.signature &&
               amount == other.amount &&
               spend_key == other.spend_key &&
               raw_blind == other.raw_blind &&
               key_exchange_pubkey == other.key_exchange_pubkey &&
               shared_secret == other.shared_secret &&
               ephemeral_key == other.ephemeral_key;
    }

    //! True when all public fields are populated.
    bool IsFinal() const noexcept
    {
        return commitment && output_pubkey && features && input_pubkey && signature;
    }

    //! The signed Input, or nullopt if not final.
    std::optional<Input> Finalized() const noexcept
    {
        if (!IsFinal()) return std::nullopt;
        return Input(*features, output_id, *commitment, *input_pubkey, *output_pubkey, extradata, *signature);
    }

    //! Sets the public fields to those of the finalized input.
    void Update(const Input& finalized) noexcept
    {
        features = finalized.GetFeatures();
        output_id = finalized.GetOutputID();
        commitment = finalized.GetCommitment();
        input_pubkey = finalized.GetInputPubKey();
        output_pubkey = finalized.GetOutputPubKey();
        extradata = finalized.GetExtraData();
        signature = finalized.GetSignature();
    }
};

//! An MWEB output that may still be missing its commitment, proof or signature.
struct MutableOutput {
    std::optional<Commitment> commitment{};
    std::optional<PublicKey> sender_pubkey{};
    std::optional<PublicKey> receiver_pubkey{};
    std::optional<OutputMessage> message{};
    std::optional<RangeProof::CPtr> proof{};
    std::optional<Signature> signature{};

    std::optional<CAmount> amount{};
    std::optional<StealthAddress> address{};
    std::optional<bool> subtract_fee_from_amount{};

    bool operator==(const MutableOutput& other) const noexcept
    {
        const bool proofs_equal = proof.has_value() == other.proof.has_value() &&
            (!proof || (*proof == nullptr) == (*other.proof == nullptr)) &&
            (!proof || !*proof || **proof == **other.proof);
        return commitment == other.commitment &&
               sender_pubkey == other.sender_pubkey &&
               receiver_pubkey == other.receiver_pubkey &&
               message == other.message &&
               proofs_equal &&
               signature == other.signature &&
               amount == other.amount &&
               address == other.address &&
               subtract_fee_from_amount == other.subtract_fee_from_amount;
    }

    //! True when all public fields are populated.
    bool IsFinal() const noexcept
    {
        return commitment && sender_pubkey && receiver_pubkey && message && proof && *proof && signature;
    }

    //! The signed Output, or nullopt if not final.
    std::optional<Output> Finalized() const noexcept
    {
        if (!IsFinal()) return std::nullopt;
        return Output(*commitment, *sender_pubkey, *receiver_pubkey, *message, *proof, *signature);
    }

    std::optional<mw::Hash> CalcOutputID() const noexcept
    {
        const std::optional<Output> output = Finalized();
        return output ? std::make_optional(output->GetOutputID()) : std::nullopt;
    }

    //! Sets the public fields to those of the finalized output.
    void Update(const Output& finalized) noexcept
    {
        commitment = finalized.GetCommitment();
        sender_pubkey = finalized.GetSenderPubKey();
        receiver_pubkey = finalized.GetReceiverPubKey();
        message = finalized.GetOutputMessage();
        proof = finalized.GetRangeProof();
        signature = finalized.GetSignature();
    }
};

struct PegOutRecipient {
    CScript script;
    CAmount nAmount{0};
    bool fSubtractFeeFromAmount{false};

    bool operator==(const PegOutRecipient& rhs) const noexcept
    {
        return script == rhs.script && nAmount == rhs.nAmount && fSubtractFeeFromAmount == rhs.fSubtractFeeFromAmount;
    }
};

//! An MWEB kernel that may still be missing its excess and signature.
struct MutableKernel {
    std::optional<CAmount> fee;
    std::optional<CAmount> pegin;
    std::vector<PegOutRecipient> pegouts;
    std::optional<int32_t> lock_height;
    std::optional<PublicKey> stealth_excess;
    std::vector<uint8_t> extradata;
    std::optional<Commitment> excess;
    std::optional<Signature> signature;
    //! The feature byte of a kernel read from a finalized transaction. Its signature
    //! covers this byte, which may carry bits the fields don't imply.
    std::optional<uint8_t> features;

    bool operator==(const MutableKernel& other) const noexcept
    {
        return GetFeatureByte() == other.GetFeatureByte() &&
               fee == other.fee &&
               pegin == other.pegin &&
               pegouts == other.pegouts &&
               lock_height == other.lock_height &&
               stealth_excess == other.stealth_excess &&
               extradata == other.extradata &&
               excess == other.excess &&
               signature == other.signature;
    }

    //! True when the excess and signature are populated.
    bool IsFinal() const noexcept { return excess && signature; }

    //! The feature byte implied by the populated fields.
    uint8_t CalcFeatureByte() const noexcept
    {
        uint8_t features = 0;
        features |= fee ? Kernel::FEE_FEATURE_BIT : 0;
        features |= pegin ? Kernel::PEGIN_FEATURE_BIT : 0;
        features |= !pegouts.empty() ? Kernel::PEGOUT_FEATURE_BIT : 0;
        features |= lock_height ? Kernel::HEIGHT_LOCK_FEATURE_BIT : 0;
        features |= stealth_excess ? Kernel::STEALTH_EXCESS_FEATURE_BIT : 0;
        features |= !extradata.empty() ? Kernel::EXTRA_DATA_FEATURE_BIT : 0;
        return features;
    }

    //! The stored feature byte, or the one implied by the populated fields.
    uint8_t GetFeatureByte() const noexcept { return features.value_or(CalcFeatureByte()); }

    //! The signed Kernel, or nullopt if not final.
    std::optional<Kernel> Finalized() const noexcept
    {
        if (!IsFinal()) return std::nullopt;
        return Kernel(
            GetFeatureByte(),
            fee,
            pegin,
            GetPegOuts(),
            lock_height,
            stealth_excess,
            extradata,
            *excess,
            *signature);
    }

    void SetPegOuts(const std::vector<PegOutCoin>& pegout_coins)
    {
        pegouts.clear();
        for (const PegOutCoin& pegout_coin : pegout_coins) {
            pegouts.push_back(PegOutRecipient{pegout_coin.GetScriptPubKey(), pegout_coin.GetAmount(), false});
        }
    }

    //! Sets the public fields to those of the finalized kernel.
    void Update(const Kernel& finalized) noexcept
    {
        features = finalized.GetFeatures();
        fee = finalized.GetOptionalFee();
        pegin = finalized.GetOptionalPegIn();
        SetPegOuts(finalized.GetPegOuts());
        lock_height = finalized.GetOptionalLockHeight();
        stealth_excess = finalized.GetOptionalStealthExcess();
        extradata = finalized.GetExtraData();
        excess = finalized.GetExcess();
        signature = finalized.GetSignature();
    }

    //! The kernel ID, or nullopt if not final.
    std::optional<mw::Hash> GetKernelID() const noexcept
    {
        const std::optional<Kernel> kernel = Finalized();
        return kernel ? std::make_optional(kernel->GetKernelID()) : std::nullopt;
    }

    std::vector<PegOutCoin> GetPegOuts() const noexcept
    {
        std::vector<PegOutCoin> coins;
        coins.reserve(pegouts.size());
        for (const PegOutRecipient& pegout : pegouts) {
            coins.emplace_back(pegout.nAmount, pegout.script);
        }
        return coins;
    }
};

//! The MWEB part of a CMutableTransaction. Components may be unsigned stubs.
//! Serializes as the finalized mw::Transaction, or as "no transaction" while
//! any component is unsigned.
struct MutableTx : public Traits::ISerializable {
    BlindingFactor kernel_offset;
    BlindingFactor stealth_offset;
    std::vector<MutableInput> inputs;
    std::vector<MutableOutput> outputs;
    std::vector<MutableKernel> kernels;

    static MutableTx From(const mw::Transaction& tx)
    {
        MutableTx mutable_tx{};
        mutable_tx.kernel_offset = tx.GetKernelOffset();
        mutable_tx.stealth_offset = tx.GetStealthOffset();

        for (const Input& input : tx.GetInputs()) {
            MutableInput mutable_input(input.GetOutputID());
            mutable_input.Update(input);
            mutable_tx.inputs.push_back(std::move(mutable_input));
        }

        for (const Output& output : tx.GetOutputs()) {
            MutableOutput mutable_output{};
            mutable_output.Update(output);
            mutable_tx.outputs.push_back(std::move(mutable_output));
        }

        for (const Kernel& kernel : tx.GetKernels()) {
            MutableKernel mutable_kernel{};
            mutable_kernel.Update(kernel);
            mutable_tx.kernels.push_back(std::move(mutable_kernel));
        }

        return mutable_tx;
    }

    void SetFee(const CAmount fee) noexcept
    {
        if (kernels.empty()) {
            kernels.push_back(MutableKernel{});
        }
        kernels.front().fee = fee;
    }

    std::optional<CAmount> GetPeginAmount() const noexcept
    {
        if (kernels.empty()) return std::nullopt;
        return kernels.front().pegin;
    }

    void SetPeginAmount(const CAmount pegin_amount)
    {
        if (kernels.empty()) {
            kernels.push_back(MutableKernel{});
        }
        kernels.front().pegin = pegin_amount;
    }

    void AddPegout(const PegOutRecipient& pegout_recipient)
    {
        if (kernels.empty()) {
            kernels.push_back(MutableKernel{});
        }
        kernels.front().pegouts.push_back(pegout_recipient);
    }

    void AddPegout(CScript script, const CAmount amount, bool subtract_fee_from_amount)
    {
        AddPegout(PegOutRecipient{std::move(script), amount, subtract_fee_from_amount});
    }

    std::vector<PegOutRecipient> GetPegouts() const noexcept
    {
        std::vector<PegOutRecipient> pegouts;
        for (const MutableKernel& kernel : kernels) {
            pegouts.insert(pegouts.end(), kernel.pegouts.begin(), kernel.pegouts.end());
        }
        return pegouts;
    }

    CAmount GetTotalPegoutAmount() const noexcept
    {
        CAmount pegout_amount = 0;
        for (const MutableKernel& kernel : kernels) {
            for (const PegOutRecipient& pegout : kernel.pegouts) {
                pegout_amount += pegout.nAmount;
            }
        }
        return pegout_amount;
    }

    bool operator==(const MutableTx& tx) const noexcept
    {
        return kernel_offset == tx.kernel_offset && stealth_offset == tx.stealth_offset &&
               inputs == tx.inputs && outputs == tx.outputs && kernels == tx.kernels;
    }

    bool IsNull() const noexcept
    {
        return kernel_offset.IsNull() && stealth_offset.IsNull() && inputs.empty() && outputs.empty() && kernels.empty();
    }

    void SetNull() noexcept
    {
        kernel_offset = BlindingFactor{};
        stealth_offset = BlindingFactor{};
        inputs.clear();
        outputs.clear();
        kernels.clear();
    }

    //! True when every component is signed. A null MutableTx is final.
    bool IsFinal() const noexcept
    {
        if (IsNull()) return true;
        if (kernels.empty()) return false;
        for (const MutableInput& input : inputs) {
            if (!input.IsFinal()) return false;
        }
        for (const MutableOutput& output : outputs) {
            if (!output.IsFinal()) return false;
        }
        for (const MutableKernel& kernel : kernels) {
            if (!kernel.IsFinal()) return false;
        }
        return true;
    }

    //! The finalized transaction, or nullopt if null or not final.
    std::optional<mw::Transaction::CPtr> Finalized() const noexcept
    {
        if (IsNull() || !IsFinal()) return std::nullopt;

        std::vector<Input> final_inputs;
        final_inputs.reserve(inputs.size());
        for (const MutableInput& input : inputs) {
            final_inputs.push_back(*input.Finalized());
        }

        std::vector<Output> final_outputs;
        final_outputs.reserve(outputs.size());
        for (const MutableOutput& output : outputs) {
            final_outputs.push_back(*output.Finalized());
        }

        std::vector<Kernel> final_kernels;
        final_kernels.reserve(kernels.size());
        for (const MutableKernel& kernel : kernels) {
            final_kernels.push_back(*kernel.Finalized());
        }

        return mw::Transaction::Create(
            kernel_offset,
            stealth_offset,
            std::move(final_inputs),
            std::move(final_outputs),
            std::move(final_kernels));
    }

    std::vector<PegInCoin> GetPegIns() const noexcept
    {
        std::vector<PegInCoin> pegins;
        for (const MutableKernel& kernel : kernels) {
            if (kernel.pegin) {
                pegins.emplace_back(*kernel.pegin, kernel.GetKernelID().value_or(mw::Hash{}));
            }
        }
        return pegins;
    }

    std::vector<PegOutCoin> GetPegOutCoins() const noexcept
    {
        std::vector<PegOutCoin> pegout_coins;
        for (const MutableKernel& kernel : kernels) {
            for (const PegOutRecipient& pegout : kernel.pegouts) {
                pegout_coins.emplace_back(pegout.nAmount, pegout.script);
            }
        }
        return pegout_coins;
    }

    //! Estimated MWEB weight for fee calculation. Every kernel is priced as a
    //! stealth kernel, and a transaction without kernels is priced as having one.
    uint64_t GetMWEBWeight() const noexcept
    {
        if (inputs.empty() && outputs.empty() && kernels.empty()) {
            return 0;
        }

        const size_t input_weight = std::accumulate(
            inputs.cbegin(), inputs.cend(), size_t{0},
            [](size_t sum, const MutableInput& input) {
                return sum + Weight::CalcInputWeight(input.extradata);
            });

        const size_t output_weight = std::accumulate(
            outputs.cbegin(), outputs.cend(), size_t{0},
            [](size_t sum, const MutableOutput& output) {
                const bool standard_fields = !output.message ||
                    (output.message->features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT);
                return sum + Weight::CalcOutputWeight(
                    standard_fields,
                    output.message ? output.message->extra_data : std::vector<uint8_t>{});
            });

        size_t kernel_weight = 0;
        if (kernels.empty()) {
            kernel_weight = Weight::CalcKernelWeight(true, std::vector<PegOutCoin>{});
        } else {
            kernel_weight = std::accumulate(
                kernels.cbegin(), kernels.cend(), size_t{0},
                [](size_t sum, const MutableKernel& kernel) {
                    return sum + Weight::CalcKernelWeight(true, kernel.GetPegOuts(), kernel.extradata);
                });
        }

        return input_weight + output_weight + kernel_weight;
    }

    IMPL_SERIALIZABLE(MutableTx, obj)
    {
        mw::Transaction::CPtr tx;
        SER_WRITE(obj, tx = obj.Finalized().value_or(nullptr));
        READWRITE(WrapOptionalPtr(tx));
        SER_READ(obj, obj = tx ? MutableTx::From(*tx) : MutableTx{});
    }
};

END_NAMESPACE

#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_MUTABLE_TX_H
