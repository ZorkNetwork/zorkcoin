
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SECRET_KEY_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SECRET_KEY_H
#include <mw/common/traits.h>
#include <mw/models/crypto/hash.h>
#include <crypto/blake3/blake3.h>
#include <random.h>
#include <support/allocators/secure.h>

#include <cassert>

class SecretKey : public Traits::ISerializable
{
public:
    static constexpr size_t SIZE = 32;
    using SecureBytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

    //
    // Constructor
    //
    SecretKey() = default;
    explicit SecretKey(const BigInt<SIZE>& value) : m_value(value.data()) { }
    explicit SecretKey(const std::vector<uint8_t>& bytes) : m_value(Checked(bytes).data()) { }
    explicit SecretKey(const SecureBytes& bytes) : m_value(Checked(bytes).data()) { }
    explicit SecretKey(const std::array<uint8_t, SIZE>& bytes) : m_value(bytes.data()) { }
    explicit SecretKey(const uint8_t* bytes) : m_value(bytes) { }

    static SecretKey Null() { return SecretKey(); }
    static SecretKey FromHex(const std::string& hex) { return SecretKey(BigInt<SIZE>::FromHex(hex)); }

    static SecretKey Random()
    {
        SecretKey key;
        do {
            GetStrongRandBytes(std::span{key.data(), SIZE});
        } while (!key.IsValid());

        return key;
    }

    static SecretKey FromHash(const mw::Hash& hash)
    {
        SecretKey key(hash);
        if (key.IsValid()) {
            return key;
        }

        uint32_t counter = 0;
        do {
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);

            static constexpr char tag[] = "MWEB hash-to-scalar";
            blake3_hasher_update(&hasher, tag, sizeof(tag) - 1);
            blake3_hasher_update(&hasher, hash.data(), hash.size());

            std::array<uint8_t, 4> counter_bytes{
                static_cast<uint8_t>(counter),
                static_cast<uint8_t>(counter >> 8),
                static_cast<uint8_t>(counter >> 16),
                static_cast<uint8_t>(counter >> 24)
            };
            blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
            blake3_hasher_finalize(&hasher, key.data(), key.size());
            counter++;
        } while (!key.IsValid());

        return key;
    }

    //
    // Destructor
    //
    virtual ~SecretKey() = default;

    //
    // Operators
    //
    bool operator==(const SecretKey& rhs) const noexcept { return m_value == rhs.m_value; }
    bool operator!=(const SecretKey& rhs) const noexcept { return !(*this == rhs); }

    //
    // Getters
    //
    //! A copy outside locked memory, for the libmw interfaces that take a BigInt.
    BigInt<SIZE> GetBigInt() const { return BigInt<SIZE>(data()); }
    std::string ToHex() const noexcept { return m_value.ToHex(); }
    bool IsNull() const noexcept { return m_value.IsZero(); }
    bool IsValid() const noexcept { return IsValidBytes(data()); }
    const SecureBytes& vec() const { return m_value.vec(); }
    std::array<uint8_t, SIZE> array() const noexcept { return m_value.ToArray(); }
    uint8_t* data() { return m_value.data(); }
    const uint8_t* data() const { return m_value.data(); }
    uint8_t& operator[] (const size_t x) { return m_value[x]; }
    const uint8_t& operator[] (const size_t x) const { return m_value[x]; }
    size_t size() const { return m_value.size(); }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(SecretKey, obj)
    {
        READWRITE(obj.m_value);
    }

private:
    template <typename Bytes>
    static const Bytes& Checked(const Bytes& bytes)
    {
        assert(bytes.size() == SIZE);
        return bytes;
    }

    static bool IsValidBytes(const uint8_t* bytes) noexcept
    {
        static constexpr std::array<uint8_t, SIZE> SECP256K1_ORDER{{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
        }};

        bool nonzero = false;
        for (size_t i = 0; i < SIZE; i++) {
            if (bytes[i] != 0) {
                nonzero = true;
                break;
            }
        }
        if (!nonzero) {
            return false;
        }

        for (size_t i = 0; i < SIZE; i++) {
            if (bytes[i] != SECP256K1_ORDER[i]) {
                return bytes[i] < SECP256K1_ORDER[i];
            }
        }

        return false;
    }

    BigInt<SIZE, secure_allocator<uint8_t>> m_value;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_SECRET_KEY_H
