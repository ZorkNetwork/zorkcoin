
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_COMMON_TRAITS_H
#define BITCOIN_LIBMW_INCLUDE_MW_COMMON_TRAITS_H
#include <streams.h>
#include <span>

// Forward Declarations
template <size_t NUM_BYTES, class ALLOC>
class BigInt;

class Commitment;
namespace mw {
using Hash = BigInt<32, std::allocator<uint8_t>>;
}

#define IMPL_SERIALIZED(T)                                                  \
    std::vector<uint8_t> Serialized() const noexcept final                  \
    {                                                                       \
        DataStream stream;                                                  \
        ::Serialize(stream, *this);                                         \
        const auto* data = reinterpret_cast<const uint8_t*>(stream.data()); \
        return std::vector<uint8_t>(data, data + stream.size());            \
    }                                                                       \
    static T Deserialize(const std::vector<uint8_t>& serialized)            \
    {                                                                       \
        T obj;                                                              \
        SpanReader stream(std::span<const uint8_t>{serialized});          \
        ::Unserialize(stream, obj);                                         \
        return obj;                                                         \
    }

#define IMPL_SERIALIZABLE(T, obj) \
    IMPL_SERIALIZED(T)            \
    SERIALIZE_METHODS(T, obj)


namespace Traits
{
    class ISerializable
    {
    public:
        virtual ~ISerializable() = default;

        //
        // Serializes object into a byte vector.
        //
        virtual std::vector<uint8_t> Serialized() const noexcept = 0;
    };

    class IPrintable
    {
    public:
        virtual ~IPrintable() = default;

        virtual std::string Format() const = 0;
    };

    class ICommitted
    {
    public:
        virtual ~ICommitted() = default;

        virtual const Commitment& GetCommitment() const noexcept = 0;
    };

    class IHashable
    {
    public:
        virtual ~IHashable() = default;

        virtual const mw::Hash& GetHash() const noexcept = 0;
    };
}
#endif // BITCOIN_LIBMW_INCLUDE_MW_COMMON_TRAITS_H
