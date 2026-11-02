// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_KASPA_HASH_H
#define BITCOIN_AUXPOW_KASPA_HASH_H

extern "C" {
#include <crypto/blake2b/blake2.h>
}
#include <crypto/common.h>
#include <span>
#include <uint256.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace auxpow {

/** Load a Kaspa Hash Display hex string (raw byte order, not uint256S). */
inline uint256 KaspaHashFromHex(std::string_view hex)
{
    assert(hex.size() == 64);
    uint256 out;
    for (size_t i = 0; i < 32; ++i) {
        auto nib = [](char c) -> unsigned {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out.begin()[i] = static_cast<unsigned char>((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    }
    return out;
}

/** Kaspa Hash::from_u64_word: word in the last LE u64 slot (bytes 24..32). */
inline uint256 KaspaHashFromU64(uint64_t n)
{
    uint256 out;
    WriteLE64(out.begin() + 24, n);
    return out;
}

class KaspaBlake2b32
{
    blake2b_state m_state;

public:
    explicit KaspaBlake2b32(std::string_view key)
    {
        assert(key.size() <= BLAKE2B_KEYBYTES);
        int rc = blake2b_init_key(&m_state, 32, key.data(), key.size());
        assert(rc == 0);
    }

    KaspaBlake2b32& Write(std::span<const unsigned char> data)
    {
        if (!data.empty()) {
            int rc = blake2b_update(&m_state, data.data(), data.size());
            assert(rc == 0);
        }
        return *this;
    }

    KaspaBlake2b32& Write(const uint256& h)
    {
        return Write(std::span<const unsigned char>{h.begin(), h.size()});
    }

    KaspaBlake2b32& WriteU16(uint16_t v)
    {
        unsigned char buf[2];
        WriteLE16(buf, v);
        return Write(buf);
    }

    KaspaBlake2b32& WriteU32(uint32_t v)
    {
        unsigned char buf[4];
        WriteLE32(buf, v);
        return Write(buf);
    }

    KaspaBlake2b32& WriteU64(uint64_t v)
    {
        unsigned char buf[8];
        WriteLE64(buf, v);
        return Write(buf);
    }

    KaspaBlake2b32& WriteLen(uint64_t n) { return WriteU64(n); }

    KaspaBlake2b32& WriteVarBytes(std::span<const unsigned char> data)
    {
        WriteLen(data.size());
        return Write(data);
    }

    /** Uint192 blue_work: BE 24-byte strip leading zeros, then write_var_bytes. */
    KaspaBlake2b32& WriteBlueWork(const unsigned char be24[24])
    {
        size_t start = 0;
        while (start < 24 && be24[start] == 0) ++start;
        return WriteVarBytes(std::span<const unsigned char>{be24 + start, 24 - start});
    }

    KaspaBlake2b32& WriteBlueWorkU64(uint64_t v)
    {
        unsigned char be24[24]{};
        for (int i = 0; i < 8; ++i) {
            be24[23 - i] = static_cast<unsigned char>((v >> (8 * i)) & 0xff);
        }
        return WriteBlueWork(be24);
    }

    uint256 Finalize()
    {
        uint256 out;
        int rc = blake2b_final(&m_state, out.begin(), 32);
        assert(rc == 0);
        return out;
    }
};

inline KaspaBlake2b32 BlockHashHasher() { return KaspaBlake2b32("BlockHash"); }
inline KaspaBlake2b32 TransactionHashHasher() { return KaspaBlake2b32("TransactionHash"); }
inline KaspaBlake2b32 MerkleBranchHashHasher() { return KaspaBlake2b32("MerkleBranchHash"); }

} // namespace auxpow

#endif // BITCOIN_AUXPOW_KASPA_HASH_H
