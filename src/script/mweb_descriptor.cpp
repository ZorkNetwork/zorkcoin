// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/mweb_descriptor.h>

#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <cstddef>
#include <string_view>
#include <vector>

namespace {

const std::string MWEB_ACCT_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

} // namespace

MWEBDescriptorForm GetMWEBForm(const Descriptor& desc)
{
    return desc.GetMWEBForm();
}

std::optional<std::string> GetMWEBAccountChecksum(const Descriptor& desc)
{
    return desc.GetMWEBAccountChecksum();
}

std::optional<uint32_t> GetMWEBIndex(const Descriptor& desc)
{
    return desc.GetMWEBIndex();
}

bool IsValidMWEBAccountChecksum(std::span<const char> checksum)
{
    if (checksum.size() != 8) return false;
    for (const char c : checksum) {
        if (MWEB_ACCT_CHECKSUM_CHARSET.find(c) == std::string::npos) return false;
    }
    return true;
}

bool IsMWEBExtKeyExpression(std::span<const char> key_expr)
{
    std::string key_str(key_expr.begin(), key_expr.end());
    if (!key_str.empty() && key_str.front() == '[') {
        const size_t close_bracket = key_str.find(']');
        if (close_bracket == std::string::npos) return false;
        key_str = key_str.substr(close_bracket + 1);
    }
    const std::string key_base = key_str.substr(0, key_str.find('/'));
    return DecodeExtPubKey(key_base).pubkey.IsValid() || DecodeExtKey(key_base).key.IsValid();
}

std::optional<uint32_t> ParseMWEBIndex(std::span<const char> index_expr)
{
    if (index_expr.empty() || (index_expr.size() > 1 && index_expr[0] == '0')) return std::nullopt;
    for (const char c : index_expr) {
        if (c < '0' || c > '9') return std::nullopt;
    }
    const std::optional<uint32_t> index = ToIntegral<uint32_t>(std::string_view{index_expr.data(), index_expr.size()});
    if (!index || *index > MWEB_MAX_DESCRIPTOR_INDEX) return std::nullopt;
    return index;
}

bool ParseMWEBCompressedPubkey(const std::span<const char>& sp, CPubKey& pubkey, std::string& error)
{
    const std::string str(sp.begin(), sp.end());
    if (!IsHex(str)) {
        error = strprintf("'%s' is not a valid pubkey", str);
        return false;
    }
    const std::vector<unsigned char> data = ParseHex(str);
    pubkey = CPubKey(data);
    if (!pubkey.IsFullyValid() || !pubkey.IsCompressed()) {
        error = strprintf("Pubkey '%s' is invalid", str);
        return false;
    }
    return true;
}
