
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_OUTPUT_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_OUTPUT_H
#include <mw/common/traits.h>
#include <mw/crypto/hasher.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/proof_data.h>
#include <mw/models/crypto/range_proof.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/crypto/signed_message.h>

#include <optional>

// Forward Declarations
class StealthAddress;

////////////////////////////////////////
// OUTPUT STANDARD FIELDS
////////////////////////////////////////
class OutputStandardFields : public Traits::ISerializable
{
public:
    OutputStandardFields(PublicKey keyExchangePubKey, uint8_t viewTag, uint64_t maskedValue, BigInt<16> maskedNonce) :
        key_exchange_pubkey(std::move(keyExchangePubKey)), view_tag(viewTag), masked_value(maskedValue), masked_nonce(std::move(maskedNonce)) { }
    OutputStandardFields() = default;

    bool operator==(const OutputStandardFields& rhs) const noexcept
    {
        return key_exchange_pubkey == rhs.key_exchange_pubkey && view_tag == rhs.view_tag &&
               masked_value == rhs.masked_value && masked_nonce == rhs.masked_nonce;
    }

    PublicKey key_exchange_pubkey;
    uint8_t view_tag{0};
    uint64_t masked_value{0};
    BigInt<16> masked_nonce;

    IMPL_SERIALIZABLE(OutputStandardFields, obj)
    {
        READWRITE(obj.key_exchange_pubkey);
        READWRITE(obj.view_tag);
        READWRITE(obj.masked_value);
        READWRITE(obj.masked_nonce);
    }
};

////////////////////////////////////////
// OUTPUT MESSAGE
////////////////////////////////////////
class OutputMessage : public Traits::ISerializable, public Traits::IHashable
{
public:
    //
    // Constructors
    //
    OutputMessage(
        uint8_t features_,
        PublicKey keyExchangePubKey_,
        uint8_t viewTag_,
        uint64_t maskedValue_,
        BigInt<16> maskedNonce_
    ) :
        features(features_),
        key_exchange_pubkey(std::move(keyExchangePubKey_)),
        view_tag(viewTag_),
        masked_value(maskedValue_),
        masked_nonce(std::move(maskedNonce_))
    {
        m_hash = Hashed(*this);
    }
    OutputMessage(uint8_t features_, const OutputStandardFields& standard_fields)
        : OutputMessage(features_, std::optional<OutputStandardFields>{standard_fields}, std::vector<uint8_t>{}) { }
    OutputMessage(uint8_t features_, const std::optional<OutputStandardFields>& standard_fields, std::vector<uint8_t> extra_data_)
        : features(features_), extra_data(std::move(extra_data_))
    {
        if (standard_fields) {
            key_exchange_pubkey = standard_fields->key_exchange_pubkey;
            view_tag = standard_fields->view_tag;
            masked_value = standard_fields->masked_value;
            masked_nonce = standard_fields->masked_nonce;
        }
        m_hash = Hashed(*this);
    }
    OutputMessage(const OutputMessage& output_message) = default;
    OutputMessage(OutputMessage&& output_message) noexcept = default;
    OutputMessage() = default;

    enum FeatureBit {
        STANDARD_FIELDS_FEATURE_BIT = 0x01,
        EXTRA_DATA_FEATURE_BIT = 0x02
    };

    //
    // Operators
    //
    OutputMessage& operator=(const OutputMessage& output_message) = default;
    OutputMessage& operator=(OutputMessage&& output_message) noexcept = default;
    bool operator<(const OutputMessage& output_message) const noexcept { return m_hash < output_message.m_hash; }
    bool operator==(const OutputMessage& output_message) const noexcept { return m_hash == output_message.m_hash; }

    uint8_t features{0};
    PublicKey key_exchange_pubkey;
    uint8_t view_tag{0};
    uint64_t masked_value{0};
    BigInt<16> masked_nonce;
    std::vector<uint8_t> extra_data;

    IMPL_SERIALIZABLE(OutputMessage, obj)
    {
        READWRITE(obj.features);

        if (obj.features & STANDARD_FIELDS_FEATURE_BIT) {
            READWRITE(obj.key_exchange_pubkey);
            READWRITE(obj.view_tag);
            READWRITE(obj.masked_value);
            READWRITE(obj.masked_nonce);
        }

        if (obj.features & EXTRA_DATA_FEATURE_BIT) {
            READWRITE(obj.extra_data);
        }

        // Cast keeps the call non-dependent so IWYU charges Hashed to this header, not to every deserializing TU.
        SER_READ(obj, obj.m_hash = Hashed(static_cast<const Traits::ISerializable&>(obj)));
    }

    //! The standard fields, or nullopt when STANDARD_FIELDS_FEATURE_BIT is not set.
    std::optional<OutputStandardFields> GetStandardFields() const
    {
        if (!(features & STANDARD_FIELDS_FEATURE_BIT)) {
            return std::nullopt;
        }
        return OutputStandardFields(key_exchange_pubkey, view_tag, masked_value, masked_nonce);
    }

    //
    // Traits
    //
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    mw::Hash m_hash;
};

////////////////////////////////////////
// OUTPUT
////////////////////////////////////////
class Output :
    public Traits::ICommitted,
    public Traits::ISerializable,
    public Traits::IHashable,
    public Traits::IPrintable
{
public:
    //
    // Constructors
    //
    Output(
        Commitment commitment,
        PublicKey senderPubKey,
        PublicKey receiverPubKey,
        OutputMessage message,
        const RangeProof::CPtr& pProof,
        Signature signature
    ) :
        m_commitment(std::move(commitment)),
        m_senderPubKey(std::move(senderPubKey)),
        m_receiverPubKey(std::move(receiverPubKey)),
        m_message(std::move(message)),
        m_pProof(pProof),
        m_signature(std::move(signature))
    {
        m_hash = ComputeHash();
    }

    Output(const Output& Output) = default;
    Output(Output&& Output) noexcept = default;
    Output() = default;

    //
    // Factory
    //
    static Output Create(
        BlindingFactor* blind_out,
        const SecretKey& sender_privkey,
        const StealthAddress& receiver_addr,
        uint64_t value
    );

    //! Creates an output whose range proof embeds the shared secret, rewindable with
    //! the proof nonce derived from rewind_key and the commitment. Non-empty extra_data
    //! is committed to and sets EXTRA_DATA_FEATURE_BIT.
    static Output Create(
        BlindingFactor* blind_out,
        const SecretKey& sender_privkey,
        const SecretKey& rewind_key,
        const StealthAddress& receiver_addr,
        uint64_t value,
        const std::vector<uint8_t>& extra_data
    );

    //
    // Destructor
    //
    virtual ~Output() = default;

    //
    // Operators
    //
    Output& operator=(const Output& output) = default;
    Output& operator=(Output&& output) noexcept = default;
    bool operator<(const Output& output) const noexcept { return m_hash < output.m_hash; }
    bool operator==(const Output& output) const noexcept { return m_hash == output.m_hash; }

    //
    // Getters
    //
    const mw::Hash& GetOutputID() const noexcept { return m_hash; }
    const Commitment& GetCommitment() const noexcept final { return m_commitment; }
    const PublicKey& GetSenderPubKey() const noexcept { return m_senderPubKey; }
    const PublicKey& GetReceiverPubKey() const noexcept { return m_receiverPubKey; }
    const RangeProof::CPtr& GetRangeProof() const noexcept { return m_pProof; }
    const OutputMessage& GetOutputMessage() const noexcept { return m_message; }
    const Signature& GetSignature() const noexcept { return m_signature; }

    bool IsStandard() const noexcept
    {
        return m_message.features == OutputMessage::STANDARD_FIELDS_FEATURE_BIT
            && m_message.key_exchange_pubkey.IsValid()
            && m_receiverPubKey.IsValid();
    }
    const std::vector<uint8_t>& GetExtraData() const noexcept { return m_message.extra_data; }
    uint8_t GetFeatures() const noexcept { return m_message.features; }
    bool HasStandardFields() const noexcept { return m_message.features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT; }
    const PublicKey& GetKeyExchangePubKey() const noexcept { return m_message.key_exchange_pubkey; }
    uint8_t GetViewTag() const noexcept { return m_message.view_tag; }
    uint64_t GetMaskedValue() const noexcept { return m_message.masked_value; }
    const BigInt<16>& GetMaskedNonce() const noexcept { return m_message.masked_nonce; }

    const PublicKey& Ko() const noexcept { return m_receiverPubKey; }
    const PublicKey& Ke() const noexcept { return m_message.key_exchange_pubkey; }

    SignedMessage BuildSignedMsg() const noexcept;
    ProofData BuildProofData() const noexcept;

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(Output, obj)
    {
        READWRITE(obj.m_commitment);
        READWRITE(obj.m_senderPubKey);
        READWRITE(obj.m_receiverPubKey);
        READWRITE(obj.m_message);
        READWRITE(obj.m_pProof);
        READWRITE(obj.m_signature);
        SER_READ(obj, obj.m_hash = obj.ComputeHash());
    }

    //
    // Traits
    //
    std::string Format() const noexcept final { return "Output(ID=" + GetOutputID().Format() + ")"; }
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    //
    // Outputs use a special serialization when hashing that only includes
    // the hash of the rangeproof, instead of the full 675 byte rangeproof.
    //
    // This will make some light client use cases more efficient.
    //
    mw::Hash ComputeHash() const noexcept
    {
        return Hasher()
            .Append(m_commitment)
            .Append(m_senderPubKey)
            .Append(m_receiverPubKey)
            .Append(m_message.GetHash())
            .Append(m_pProof->GetHash())
            .Append(m_signature)
            .hash();
    }

    Commitment m_commitment;
    PublicKey m_senderPubKey;
    PublicKey m_receiverPubKey;
    OutputMessage m_message;
    RangeProof::CPtr m_pProof;
    Signature m_signature;

    mw::Hash m_hash;
};

// Sorts by output ID (hash)
struct OutputSort {
    bool operator()(const Output& a, const Output& b) const noexcept
    {
        return a.GetOutputID() < b.GetOutputID();
    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_OUTPUT_H
