// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_pow.h>

#include <crypto/common.h>
#include <crypto/kheavyhash.h>
#include <crypto/sha3.h>

#include <cstring>
#include <span>
#include <vector>

namespace auxpow {
namespace {

/** Domain-separated cSHAKE256 finalize matching KHeavyHash personalization setup. */
uint256 CShake256Domain(const char* domain, size_t domain_len, std::span<const unsigned char> data)
{
    SHA3_256 hasher;
    uint8_t tmpBuffer[136] = {0};
    tmpBuffer[0] = 1;
    tmpBuffer[1] = 136;
    tmpBuffer[2] = 1;
    tmpBuffer[3] = 0;
    tmpBuffer[4] = 1;
    tmpBuffer[5] = static_cast<uint8_t>(domain_len * 8);
    std::memcpy(tmpBuffer + 6, domain, domain_len);
    hasher.Write(std::span<const unsigned char>{tmpBuffer, sizeof(tmpBuffer)});
    hasher.Write(data);
    uint256 out;
    hasher.Finalize(std::span<unsigned char>{out.begin(), out.size()}, 0x04);
    return out;
}

} // namespace

uint256 KaspaPeerPoW(const KaspaHeader& header)
{
    const uint256 pre = KaspaPrePowHash(header);
    unsigned char time_buf[8];
    unsigned char nonce_buf[8];
    WriteLE64(time_buf, header.timestamp);
    WriteLE64(nonce_buf, header.nonce);

    KHeavyHash work{pre};
    uint256 out;
    work.Write(pre)
        .Write(std::span<const unsigned char>{time_buf, sizeof(time_buf)})
        .Write(uint256::ZERO)
        .Write(std::span<const unsigned char>{nonce_buf, sizeof(nonce_buf)})
        .Finalize(out);
    return out;
}

uint256 KaspaPowHashOnly(const uint256& pre_pow_hash, uint64_t timestamp, uint64_t nonce)
{
    std::vector<unsigned char> buf;
    buf.reserve(32 + 8 + 32 + 8);
    buf.insert(buf.end(), pre_pow_hash.begin(), pre_pow_hash.end());
    unsigned char time_buf[8];
    WriteLE64(time_buf, timestamp);
    buf.insert(buf.end(), time_buf, time_buf + 8);
    buf.insert(buf.end(), 32, 0);
    unsigned char nonce_buf[8];
    WriteLE64(nonce_buf, nonce);
    buf.insert(buf.end(), nonce_buf, nonce_buf + 8);
    return CShake256Domain("ProofOfWorkHash", 15, buf);
}

uint256 KaspaHeavyHashOnly(const uint256& input)
{
    return CShake256Domain("HeavyHash", 9, std::span<const unsigned char>{input.begin(), input.size()});
}

} // namespace auxpow
