#ifndef OPOW_CRYPTO_HEAVYHASH_H
#define OPOW_CRYPTO_HEAVYHASH_H

#include <stdint.h>
#include <stdlib.h>
#include <crypto/sha3.h>
#include <uint256.h>
#include <memory>

class KHeavyHash
{
private:
    uint16_t matrix[64][64];
    SHA3_256 hasher;

    const char *powHashStr = "ProofOfWorkHash";
    const char *hashStr = "HeavyHash";

public:
    static const size_t OUTPUT_SIZE = 32;
    explicit KHeavyHash(uint256 seed);
    KHeavyHash& Reset(uint256 seed);
    KHeavyHash& Write(Span<const unsigned char> data);
    KHeavyHash& Finalize(Span<unsigned char> output);
};

#endif  // OPOW_CRYPTO_HEAVYHASH_H
