
#ifndef BITCOIN_LIBMW_INCLUDE_MW_COMMON_STREAM_UTIL_H
#define BITCOIN_LIBMW_INCLUDE_MW_COMMON_STREAM_UTIL_H
#include <cstddef>
#include <cstdint>
#include <span>

template <typename Stream>
void StreamWriteBytes(Stream& s, const uint8_t* data, size_t len)
{
    if constexpr (requires { s.write(std::span<const std::byte>{}); }) {
        s.write(std::as_bytes(std::span{data, len}));
    } else {
        s.write(reinterpret_cast<const char*>(data), len);
    }
}

template <typename Stream>
void StreamReadBytes(Stream& s, uint8_t* data, size_t len)
{
    if constexpr (requires { s.read(std::span<std::byte>{}); }) {
        s.read(std::as_writable_bytes(std::span{data, len}));
    } else {
        s.read(reinterpret_cast<char*>(data), len);
    }
}
#endif // BITCOIN_LIBMW_INCLUDE_MW_COMMON_STREAM_UTIL_H
