
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SIGNED_MESSAGE_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SIGNED_MESSAGE_H
#include <mw/common/traits.h>
#include <mw/crypto/hasher.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/signature.h>
#include <boost/functional/hash.hpp>

/// <summary>
/// Contains a hashed message, a signature of that message, and the public key it was signed for.
/// </summary>
class SignedMessage : public Traits::ISerializable, public Traits::IHashable
{
public:
    SignedMessage() = default;
    SignedMessage(const SignedMessage&) = default;
    SignedMessage(SignedMessage&&) = default;
    SignedMessage(mw::Hash msgHash, PublicKey publicKey, Signature signature)
        : m_messageHash(std::move(msgHash)), m_publicKey(std::move(publicKey)), m_signature(std::move(signature))
    {
        m_hash = Hashed(*this);
    }

    //
    // Operators
    //
    SignedMessage& operator=(const SignedMessage& other) = default;
    SignedMessage& operator=(SignedMessage&& other) noexcept = default;
    bool operator==(const SignedMessage& rhs) const noexcept {
        return m_messageHash == rhs.m_messageHash
            && m_publicKey == rhs.m_publicKey
            && m_signature == rhs.m_signature;
    }
    bool operator!=(const SignedMessage& rhs) const noexcept { return !(*this == rhs); }

    //
    // Getters
    //
    const mw::Hash& GetMsgHash() const noexcept { return m_messageHash; }
    const PublicKey& GetPublicKey() const noexcept { return m_publicKey; }
    const Signature& GetSignature() const noexcept { return m_signature; }

    IMPL_SERIALIZABLE(SignedMessage, obj)
    {
        READWRITE(obj.m_messageHash);
        READWRITE(obj.m_publicKey);
        READWRITE(obj.m_signature);
        // Cast keeps the call non-dependent so IWYU charges Hashed to this header, not to every deserializing TU.
        SER_READ(obj, obj.m_hash = Hashed(static_cast<const Traits::ISerializable&>(obj)));
    }

    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    mw::Hash m_messageHash;
    PublicKey m_publicKey;
    Signature m_signature;

    mw::Hash m_hash;
};

namespace std
{
    template<>
    struct hash<SignedMessage>
    {
        size_t operator()(const SignedMessage& hash) const
        {
            return boost::hash_value(hash.Serialized());
        }
    };
}
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SIGNED_MESSAGE_H
