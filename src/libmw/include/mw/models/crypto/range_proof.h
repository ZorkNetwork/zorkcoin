
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_RANGE_PROOF_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_RANGE_PROOF_H
#include <mw/common/traits.h>
#include <mw/common/stream_util.h>
#include <mw/crypto/hasher.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <cassert>

class RangeProof :
    public Traits::IPrintable,
    public Traits::ISerializable,
    public Traits::IHashable
{
public:
    using CPtr = std::shared_ptr<const RangeProof>;
    enum { SIZE = 675 };

    //
    // Constructors
    //
    RangeProof() noexcept : m_bytes(SIZE) {}
    RangeProof(std::vector<uint8_t>&& bytes) : m_bytes(std::move(bytes))
    {
        assert(m_bytes.size() == SIZE);
        m_hash = Hashed(*this);
    }
    template <typename Stream>
    RangeProof(deserialize_type, Stream& s) : m_bytes(SIZE)
    {
        Unserialize(s);
    }
    RangeProof(const RangeProof& other) = default;
    RangeProof(RangeProof&& other) noexcept = default;

    //
    // Destructor
    //
    virtual ~RangeProof() = default;

    //
    // Operators
    //
    RangeProof& operator=(const RangeProof& other) = default;
    RangeProof& operator=(RangeProof&& other) noexcept = default;
    bool operator==(const RangeProof& other) const noexcept { return m_bytes == other.m_bytes; }

    //
    // Getters
    //
    const std::vector<uint8_t>& vec() const { return m_bytes; }
    const uint8_t* data() const { return m_bytes.data(); }
    size_t size() const { return m_bytes.size(); }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZED(RangeProof);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        StreamWriteBytes(s, m_bytes.data(), SIZE);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        StreamReadBytes(s, m_bytes.data(), SIZE);

        m_hash = Hashed(*this);
    }

    //
    // Traits
    //
    std::string Format() const final { return HexStr(m_bytes); }
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    // The proof itself, at most 675 bytes long.
    std::vector<uint8_t> m_bytes;

    mw::Hash m_hash;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_RANGE_PROOF_H
