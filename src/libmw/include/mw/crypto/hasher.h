
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_HASHER_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_HASHER_H
#include <crypto/blake3/blake3.h>
#include <mw/models/crypto/hash.h>
#include <serialize.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Traits {
class ISerializable;
} // namespace Traits

enum class EHashTag : char
{
    ADDRESS = 'A',
    BLIND = 'B',
    DERIVE = 'D',
    NONCE = 'N',
    OUT_KEY = 'O',
    PROOF_NONCE = 'P',
    SENDER_ROOT = 'Q',
    REWIND_KEY = 'R',
    SEND_KEY = 'S',
    TAG = 'T',
    NONCE_MASK = 'X',
    VALUE_MASK = 'Y'
};

class Hasher
{
public:
    Hasher()
    {
        blake3_hasher_init(&m_hasher);
    }

    Hasher(const EHashTag tag)
    {
        blake3_hasher_init(&m_hasher);
        char c_tag = static_cast<char>(tag);
        write(&c_tag, 1);
    }

    int GetType() const { return 0; }
    int GetVersion() const { return 0; }

    void write(const char* pch, size_t size)
    {
        blake3_hasher_update(&m_hasher, pch, size);
    }

    void write(std::span<const std::byte> src)
    {
        blake3_hasher_update(&m_hasher, src.data(), src.size());
    }

    mw::Hash hash()
    {
        mw::Hash hashed;
        blake3_hasher_finalize(&m_hasher, hashed.data(), hashed.size());
        return hashed;
    }

    template <class T>
    Hasher& Append(const T& t)
    {
        ::Serialize(*this, t);
        return *this;
    }

    template <typename T>
    Hasher& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

private:
    blake3_hasher m_hasher;
};

extern mw::Hash Hashed(const std::vector<uint8_t>& serialized);
extern mw::Hash Hashed(const Traits::ISerializable& serializable);

template<class T>
mw::Hash Hashed(const EHashTag tag, const T& serializable)
{
    return Hasher(tag).Append(serializable).hash();
}
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_HASHER_H
