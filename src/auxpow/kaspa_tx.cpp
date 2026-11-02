// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_tx.h>

#include <auxpow/kaspa_hash.h>
#include <crypto/common.h>

#include <cstring>

namespace auxpow {
namespace {

bool ReadBytes(std::span<const unsigned char>& in, unsigned char* dest, size_t n, std::string* err)
{
    if (in.size() < n) {
        if (err) *err = "kaspa tx truncated";
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
        if (err) *err = "kaspa tx truncated";
        return false;
    }
    v = in[0];
    in = in.subspan(1);
    return true;
}

void AppendU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char buf[2];
    WriteLE16(buf, v);
    out.insert(out.end(), buf, buf + 2);
}

void AppendU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char buf[8];
    WriteLE64(buf, v);
    out.insert(out.end(), buf, buf + 8);
}

bool ReadVarBytes(std::span<const unsigned char>& in, std::vector<unsigned char>& out, uint64_t max_len, std::string* err)
{
    uint64_t len = 0;
    if (!ReadU64(in, len, err)) return false;
    if (len > max_len) {
        if (err) *err = "var bytes too long";
        return false;
    }
    if (in.size() < len) {
        if (err) *err = "var bytes truncated";
        return false;
    }
    out.assign(in.begin(), in.begin() + len);
    in = in.subspan(len);
    return true;
}

bool ReadOutput(std::span<const unsigned char>& in, uint16_t tx_version, KaspaTxOutput& out, std::string* err)
{
    if (!ReadU64(in, out.value, err)) return false;
    if (!ReadU16(in, out.script_version, err)) return false;
    if (!ReadVarBytes(in, out.script, 150000, err)) return false;
    out.covenant = {};
    if (tx_version >= 1) {
        uint8_t present = 0;
        if (!ReadU8(in, present, err)) return false;
        if (present > 1) {
            if (err) *err = "invalid covenant flag";
            return false;
        }
        out.covenant.present = present != 0;
        if (out.covenant.present) {
            if (!ReadU16(in, out.covenant.authorizing_input, err)) return false;
            if (!ReadBytes(in, out.covenant.covenant_id.begin(), 32, err)) return false;
        }
    }
    return true;
}

void WriteOutput(KaspaBlake2b32& hasher, uint16_t tx_version, const KaspaTxOutput& out)
{
    hasher.WriteU64(out.value);
    hasher.WriteU16(out.script_version);
    hasher.WriteVarBytes(out.script);
    if (tx_version >= 1) {
        unsigned char flag = out.covenant.present ? 1 : 0;
        hasher.Write(std::span<const unsigned char>{&flag, 1});
        if (out.covenant.present) {
            hasher.WriteU16(out.covenant.authorizing_input);
            hasher.Write(out.covenant.covenant_id);
        }
    }
}

void AppendOutput(std::vector<unsigned char>& out, uint16_t tx_version, const KaspaTxOutput& o)
{
    AppendU64(out, o.value);
    AppendU16(out, o.script_version);
    AppendU64(out, o.script.size());
    out.insert(out.end(), o.script.begin(), o.script.end());
    if (tx_version >= 1) {
        out.push_back(o.covenant.present ? 1 : 0);
        if (o.covenant.present) {
            AppendU16(out, o.covenant.authorizing_input);
            out.insert(out.end(), o.covenant.covenant_id.begin(), o.covenant.covenant_id.end());
        }
    }
}

} // namespace

bool SerializeKaspaTransaction(const KaspaTransaction& tx, std::vector<unsigned char>& out, std::string* err)
{
    (void)err;
    out.clear();
    AppendU16(out, tx.version);
    AppendU64(out, 0); // inputs
    AppendU64(out, tx.outputs.size());
    for (const auto& o : tx.outputs) {
        AppendOutput(out, tx.version, o);
    }
    AppendU64(out, tx.lock_time);
    out.insert(out.end(), tx.subnetwork_id, tx.subnetwork_id + KASPA_SUBNETWORK_ID_SIZE);
    AppendU64(out, tx.gas);
    AppendU64(out, tx.payload.size());
    out.insert(out.end(), tx.payload.begin(), tx.payload.end());
    AppendU64(out, tx.storage_mass);
    return true;
}

bool DeserializeKaspaTransaction(std::span<const unsigned char> in, KaspaTransaction& out, size_t& consumed, std::string* err)
{
    const auto begin = in.data();
    KaspaTransaction tx;
    if (!ReadU16(in, tx.version, err)) return false;
    uint64_t n_in = 0;
    if (!ReadU64(in, n_in, err)) return false;
    if (n_in != 0) {
        if (err) *err = "kaspa auxpow tx must have 0 inputs";
        return false;
    }
    uint64_t n_out = 0;
    if (!ReadU64(in, n_out, err)) return false;
    if (n_out > 64) {
        if (err) *err = "too many outputs";
        return false;
    }
    tx.outputs.resize(n_out);
    for (uint64_t i = 0; i < n_out; ++i) {
        if (!ReadOutput(in, tx.version, tx.outputs[i], err)) return false;
    }
    if (!ReadU64(in, tx.lock_time, err)) return false;
    if (!ReadBytes(in, tx.subnetwork_id, KASPA_SUBNETWORK_ID_SIZE, err)) return false;
    if (!ReadU64(in, tx.gas, err)) return false;
    if (!ReadVarBytes(in, tx.payload, 2048, err)) return false;
    if (!ReadU64(in, tx.storage_mass, err)) return false;
    consumed = static_cast<size_t>(in.data() - begin);
    out = std::move(tx);
    return true;
}

uint256 KaspaTransactionHash(const KaspaTransaction& tx)
{
    auto hasher = TransactionHashHasher();
    hasher.WriteU16(tx.version);
    hasher.WriteLen(0); // inputs
    hasher.WriteLen(tx.outputs.size());
    for (const auto& o : tx.outputs) {
        WriteOutput(hasher, tx.version, o);
    }
    hasher.WriteU64(tx.lock_time);
    hasher.Write(std::span<const unsigned char>{tx.subnetwork_id, KASPA_SUBNETWORK_ID_SIZE});
    hasher.WriteU64(tx.gas);
    hasher.WriteVarBytes(tx.payload);
    if (tx.version >= 1) {
        hasher.WriteU64(tx.storage_mass);
    }
    return hasher.Finalize();
}

bool IsKaspaCoinbaseShape(const KaspaTransaction& tx, std::string* err)
{
    if (tx.version != 1) {
        if (err) *err = "coinbase version must be 1";
        return false;
    }
    if (std::memcmp(tx.subnetwork_id, KASPA_SUBNETWORK_ID_COINBASE, KASPA_SUBNETWORK_ID_SIZE) != 0) {
        if (err) *err = "not coinbase subnetwork";
        return false;
    }
    if (tx.gas != 0) {
        if (err) *err = "coinbase gas must be 0";
        return false;
    }
    if (tx.storage_mass != 0) {
        if (err) *err = "coinbase storage_mass must be 0";
        return false;
    }
    if (tx.payload.size() < 19 || tx.payload.size() > 204) {
        if (err) *err = "coinbase payload length out of range";
        return false;
    }
    return true;
}

bool ParseKaspaCoinbasePayload(const std::vector<unsigned char>& payload,
                               uint64_t& blue_score,
                               uint64_t& subsidy,
                               uint16_t& spk_version,
                               std::vector<unsigned char>& spk,
                               std::vector<unsigned char>& extra_data,
                               std::string* err)
{
    if (payload.size() < 19) {
        if (err) *err = "payload too short";
        return false;
    }
    blue_score = ReadLE64(payload.data());
    subsidy = ReadLE64(payload.data() + 8);
    spk_version = ReadLE16(payload.data() + 16);
    const uint8_t spk_len = payload[18];
    if (payload.size() < 19u + spk_len) {
        if (err) *err = "payload script truncated";
        return false;
    }
    spk.assign(payload.begin() + 19, payload.begin() + 19 + spk_len);
    extra_data.assign(payload.begin() + 19 + spk_len, payload.end());
    return true;
}

} // namespace auxpow
