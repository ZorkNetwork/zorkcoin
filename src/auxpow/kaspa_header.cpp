// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_header.h>

#include <auxpow/kaspa_hash.h>
#include <crypto/common.h>

#include <cstring>

namespace auxpow {
namespace {

bool ReadBytes(std::span<const unsigned char>& in, unsigned char* dest, size_t n, std::string* err)
{
    if (in.size() < n) {
        if (err) *err = "kaspa header truncated";
        return false;
    }
    std::memcpy(dest, in.data(), n);
    in = in.subspan(n);
    return true;
}

bool ReadU16(std::span<const unsigned char>& in, uint16_t& v, std::string* err)
{
    unsigned char buf[2];
    if (!ReadBytes(in, buf, 2, err)) return false;
    v = ReadLE16(buf);
    return true;
}

bool ReadU32(std::span<const unsigned char>& in, uint32_t& v, std::string* err)
{
    unsigned char buf[4];
    if (!ReadBytes(in, buf, 4, err)) return false;
    v = ReadLE32(buf);
    return true;
}

bool ReadU64(std::span<const unsigned char>& in, uint64_t& v, std::string* err)
{
    unsigned char buf[8];
    if (!ReadBytes(in, buf, 8, err)) return false;
    v = ReadLE64(buf);
    return true;
}

bool ReadU8(std::span<const unsigned char>& in, uint8_t& v, std::string* err)
{
    if (in.empty()) {
        if (err) *err = "kaspa header truncated";
        return false;
    }
    v = in[0];
    in = in.subspan(1);
    return true;
}

bool ReadHash(std::span<const unsigned char>& in, uint256& h, std::string* err)
{
    return ReadBytes(in, h.begin(), 32, err);
}

void AppendU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char buf[2];
    WriteLE16(buf, v);
    out.insert(out.end(), buf, buf + 2);
}

void AppendU32(std::vector<unsigned char>& out, uint32_t v)
{
    unsigned char buf[4];
    WriteLE32(buf, v);
    out.insert(out.end(), buf, buf + 4);
}

void AppendU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char buf[8];
    WriteLE64(buf, v);
    out.insert(out.end(), buf, buf + 8);
}

void AppendBlueWorkWire(std::vector<unsigned char>& out, const unsigned char be24[24])
{
    size_t start = 0;
    while (start < 24 && be24[start] == 0) ++start;
    AppendU64(out, 24 - start);
    out.insert(out.end(), be24 + start, be24 + 24);
}

bool ReadBlueWorkWire(std::span<const unsigned char>& in, unsigned char be24[24], std::string* err)
{
    uint64_t len = 0;
    if (!ReadU64(in, len, err)) return false;
    if (len > 24) {
        if (err) *err = "blue_work length > 24";
        return false;
    }
    std::memset(be24, 0, 24);
    if (len == 0) return true;
    if (in.size() < len) {
        if (err) *err = "blue_work truncated";
        return false;
    }
    std::memcpy(be24 + (24 - len), in.data(), len);
    in = in.subspan(len);
    return true;
}

} // namespace

size_t KaspaHeader::ExpandedLevelCount() const
{
    if (parents_by_level.empty()) return 0;
    return parents_by_level.back().cum_count;
}

std::vector<std::vector<uint256>> KaspaHeader::ExpandedParents() const
{
    std::vector<std::vector<uint256>> expanded;
    uint8_t prev = 0;
    for (const auto& run : parents_by_level) {
        for (uint8_t level = prev; level < run.cum_count; ++level) {
            expanded.push_back(run.parents);
        }
        prev = run.cum_count;
    }
    return expanded;
}

bool KaspaHeader::IsRleCanonical(std::string* err) const
{
    if (parents_by_level.empty()) {
        if (err) *err = "empty parents_by_level";
        return false;
    }
    if (parents_by_level.front().cum_count == 0) {
        if (err) *err = "first cum_count is 0";
        return false;
    }
    for (size_t i = 0; i < parents_by_level.size(); ++i) {
        if (i > 0) {
            if (parents_by_level[i].cum_count <= parents_by_level[i - 1].cum_count) {
                if (err) *err = "cum_count not strictly increasing";
                return false;
            }
            if (parents_by_level[i].parents == parents_by_level[i - 1].parents) {
                if (err) *err = "adjacent RLE runs identical";
                return false;
            }
        }
    }
    return true;
}

bool SerializeKaspaHeader(const KaspaHeader& h, std::vector<unsigned char>& out, std::string* err)
{
    if (!h.IsRleCanonical(err)) return false;
    out.clear();
    AppendU16(out, h.version);
    AppendU64(out, h.parents_by_level.size());
    for (const auto& run : h.parents_by_level) {
        out.push_back(run.cum_count);
        AppendU64(out, run.parents.size());
        for (const auto& p : run.parents) {
            out.insert(out.end(), p.begin(), p.end());
        }
    }
    out.insert(out.end(), h.hash_merkle_root.begin(), h.hash_merkle_root.end());
    out.insert(out.end(), h.accepted_id_merkle_root.begin(), h.accepted_id_merkle_root.end());
    out.insert(out.end(), h.utxo_commitment.begin(), h.utxo_commitment.end());
    AppendU64(out, h.timestamp);
    AppendU32(out, h.bits);
    AppendU64(out, h.nonce);
    AppendU64(out, h.daa_score);
    AppendU64(out, h.blue_score);
    AppendBlueWorkWire(out, h.blue_work);
    out.insert(out.end(), h.pruning_point.begin(), h.pruning_point.end());
    return true;
}

bool DeserializeKaspaHeader(std::span<const unsigned char> in, KaspaHeader& out, size_t& consumed, std::string* err)
{
    const auto begin = in.data();
    KaspaHeader h;
    if (!ReadU16(in, h.version, err)) return false;
    uint64_t num_runs = 0;
    if (!ReadU64(in, num_runs, err)) return false;
    if (num_runs > 255) {
        if (err) *err = "too many parent runs";
        return false;
    }
    h.parents_by_level.resize(num_runs);
    for (uint64_t i = 0; i < num_runs; ++i) {
        if (!ReadU8(in, h.parents_by_level[i].cum_count, err)) return false;
        uint64_t np = 0;
        if (!ReadU64(in, np, err)) return false;
        if (np > 1024) {
            if (err) *err = "too many parents in run";
            return false;
        }
        h.parents_by_level[i].parents.resize(np);
        for (uint64_t j = 0; j < np; ++j) {
            if (!ReadHash(in, h.parents_by_level[i].parents[j], err)) return false;
        }
    }
    if (!ReadHash(in, h.hash_merkle_root, err)) return false;
    if (!ReadHash(in, h.accepted_id_merkle_root, err)) return false;
    if (!ReadHash(in, h.utxo_commitment, err)) return false;
    if (!ReadU64(in, h.timestamp, err)) return false;
    if (!ReadU32(in, h.bits, err)) return false;
    if (!ReadU64(in, h.nonce, err)) return false;
    if (!ReadU64(in, h.daa_score, err)) return false;
    if (!ReadU64(in, h.blue_score, err)) return false;
    if (!ReadBlueWorkWire(in, h.blue_work, err)) return false;
    if (!ReadHash(in, h.pruning_point, err)) return false;
    if (!h.IsRleCanonical(err)) return false;
    consumed = static_cast<size_t>(in.data() - begin);
    out = std::move(h);
    return true;
}

uint256 HashOverrideNonceTime(const KaspaHeader& h, uint64_t nonce, uint64_t timestamp)
{
    auto hasher = BlockHashHasher();
    hasher.WriteU16(h.version);
    const auto expanded = h.ExpandedParents();
    hasher.WriteLen(expanded.size());
    for (const auto& level : expanded) {
        hasher.WriteLen(level.size());
        for (const auto& p : level) {
            hasher.Write(p);
        }
    }
    hasher.Write(h.hash_merkle_root);
    hasher.Write(h.accepted_id_merkle_root);
    hasher.Write(h.utxo_commitment);
    hasher.WriteU64(timestamp);
    hasher.WriteU32(h.bits);
    hasher.WriteU64(nonce);
    hasher.WriteU64(h.daa_score);
    hasher.WriteU64(h.blue_score);
    hasher.WriteBlueWork(h.blue_work);
    hasher.Write(h.pruning_point);
    return hasher.Finalize();
}

bool DecodeKaspaCompactBits(uint32_t bits, uint256& target, std::string* err)
{
    const uint32_t mant = bits & 0xffffff;
    if (mant > 0x7fffff) {
        target.SetNull();
        if (err) *err = "kaspa compact bits negative";
        return false;
    }
    const uint32_t unshifted_expt = bits >> 24;
    uint64_t mant64;
    uint32_t shift_bits;
    if (unshifted_expt <= 3) {
        mant64 = mant >> (8 * (3 - unshifted_expt));
        shift_bits = 0;
    } else {
        mant64 = mant;
        shift_bits = 8 * (unshifted_expt - 3);
    }
    if (mant64 == 0) {
        target.SetNull();
        if (err) *err = "kaspa compact bits zero";
        return false;
    }
    // Build LE uint256: mant64 << shift_bits
    if (shift_bits >= 256) {
        target.SetNull();
        if (err) *err = "kaspa compact bits overflow";
        return false;
    }
    target.SetNull();
    const uint32_t byte_shift = shift_bits / 8;
    const uint32_t bit_shift = shift_bits % 8;
    unsigned char tmp[9]{};
    WriteLE64(tmp, mant64);
    for (size_t i = 0; i < 8; ++i) {
        const size_t dest = byte_shift + i;
        if (dest >= 32) {
            if (tmp[i] != 0 || (bit_shift && tmp[i + 1] != 0)) {
                target.SetNull();
                if (err) *err = "kaspa compact bits overflow";
                return false;
            }
            continue;
        }
        const uint16_t shifted = static_cast<uint16_t>(tmp[i]) << bit_shift;
        target.begin()[dest] |= static_cast<unsigned char>(shifted & 0xff);
        if (bit_shift && dest + 1 < 32) {
            target.begin()[dest + 1] |= static_cast<unsigned char>(shifted >> 8);
        } else if (bit_shift && (shifted >> 8) != 0) {
            target.SetNull();
            if (err) *err = "kaspa compact bits overflow";
            return false;
        }
    }
    return true;
}

} // namespace auxpow
