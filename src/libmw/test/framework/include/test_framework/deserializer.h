
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_DESERIALIZER_H
#define BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_DESERIALIZER_H
#include <mw/common/stream_util.h>
#include <mw/common/traits.h>
#include <streams.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

class Deserializer
{
public:
    Deserializer(std::vector<uint8_t> bytes)
        : m_bytes(std::move(bytes)), m_reader(std::span<const uint8_t>{m_bytes}) {}

    template <class T, typename SFINAE = std::enable_if_t<std::is_integral<T>::value || std::is_base_of<Traits::ISerializable, T>::value>>
    T Read()
    {
        T value;
        m_reader >> value;
        return value;
    }

    std::vector<uint8_t> ReadVector(const uint64_t numBytes)
    {
        std::vector<uint8_t> vec(numBytes);
        StreamReadBytes(m_reader, vec.data(), numBytes);
        return vec;
    }

private:
    std::vector<uint8_t> m_bytes;
    SpanReader m_reader;
};
#endif // BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_DESERIALIZER_H
