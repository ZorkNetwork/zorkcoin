#ifndef BITCOIN_CRYPTO_KHEAVYHASH_H
#define BITCOIN_CRYPTO_KHEAVYHASH_H

#include <cstdint>
#include <span>
#include <crypto/sha3.h>
#include <uint256.h>

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
    KHeavyHash& Write(std::span<const unsigned char> data);
    KHeavyHash& Finalize(std::span<unsigned char> output);
    KHeavyHash& Finalize(uint256& output);
    KHeavyHash& Write(const uint256& data);
};

#endif  // BITCOIN_CRYPTO_KHEAVYHASH_H
