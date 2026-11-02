// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_KASPA_HEADER_H
#define BITCOIN_AUXPOW_KASPA_HEADER_H

#include <span>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace auxpow {

/** One RLE run of parents_by_level (cum_count is exclusive end level). */
struct KaspaParentRun {
    uint8_t cum_count{0};
    std::vector<uint256> parents;
};

struct KaspaHeader {
    uint16_t version{0};
    std::vector<KaspaParentRun> parents_by_level;
    uint256 hash_merkle_root;
    uint256 accepted_id_merkle_root;
    uint256 utxo_commitment;
    uint64_t timestamp{0};
    uint32_t bits{0};
    uint64_t nonce{0};
    uint64_t daa_score{0};
    uint64_t blue_score{0};
    /** 24-byte big-endian Uint192 (leading zeros allowed). */
    unsigned char blue_work[24]{};
    uint256 pruning_point;

    size_t ExpandedLevelCount() const;
    std::vector<std::vector<uint256>> ExpandedParents() const;
    bool IsRleCanonical(std::string* err = nullptr) const;
};

bool SerializeKaspaHeader(const KaspaHeader& h, std::vector<unsigned char>& out, std::string* err = nullptr);
bool DeserializeKaspaHeader(std::span<const unsigned char> in, KaspaHeader& out, size_t& consumed, std::string* err = nullptr);

uint256 HashOverrideNonceTime(const KaspaHeader& h, uint64_t nonce, uint64_t timestamp);
inline uint256 KaspaHeaderHash(const KaspaHeader& h)
{
    return HashOverrideNonceTime(h, h.nonce, h.timestamp);
}
inline uint256 KaspaPrePowHash(const KaspaHeader& h)
{
    return HashOverrideNonceTime(h, 0, 0);
}

/** Decode Kaspa compact bits (sign bit ⇒ zero target). */
bool DecodeKaspaCompactBits(uint32_t bits, uint256& target, std::string* err = nullptr);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_KASPA_HEADER_H
