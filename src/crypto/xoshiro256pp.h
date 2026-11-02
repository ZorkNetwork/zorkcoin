// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_XOSHIRO256PP_H
#define BITCOIN_CRYPTO_XOSHIRO256PP_H

#include <uint256.h>

#include <cstdint>

/** Pseudorandom number generator used by kHeavyHash matrix setup. */
class XoShiRo256PlusPlus
{
private:
    uint64_t s[4];

    static uint64_t RotateLeft64(uint64_t x, int k)
    {
        return (x << k) | (x >> (64 - k));
    }

    XoShiRo256PlusPlus(const XoShiRo256PlusPlus&) = default;
    XoShiRo256PlusPlus& operator=(const XoShiRo256PlusPlus&) = default;

public:
    explicit XoShiRo256PlusPlus(uint256 seed)
    {
        for (int i = 0; i < 4; ++i) {
            s[i] = seed.GetUint64(i);
        }
    }

    void Reset(uint256 seed)
    {
        for (int i = 0; i < 4; ++i) {
            s[i] = seed.GetUint64(i);
        }
    }

    uint64_t operator()()
    {
        const uint64_t result = RotateLeft64(s[0] + s[3], 23) + s[0];

        const uint64_t t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;

        s[3] = RotateLeft64(s[3], 45);

        return result;
    }
};

#endif // BITCOIN_CRYPTO_XOSHIRO256PP_H
