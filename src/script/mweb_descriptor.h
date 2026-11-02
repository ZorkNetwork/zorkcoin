// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_MWEB_DESCRIPTOR_H
#define BITCOIN_SCRIPT_MWEB_DESCRIPTOR_H

//! Free helpers and parser utilities for mweb() descriptors (doc/mweb/descriptors.md).
//! The form, account checksum and index come from the Descriptor's own virtual methods.

#include <cstdint>
#include <optional>
#include <span>
#include <string>

class CPubKey;
struct Descriptor;

/** Form of an mweb() descriptor (see doc/mweb/descriptors.md / LIP-0008). */
enum class MWEBDescriptorForm {
    NONE,
    ACCOUNT,         //!< mweb(master_scan,master_spend,*)
    INDEXED,         //!< mweb(master_scan,master_spend,i)
    SINGLE_SUBADDR,  //!< mweb(a,b_i) or mweb(a,B_i)
    INTERNAL,        //!< mweb(A_i,B_i,i,acct_cksum)
};

//! Largest index an mweb() descriptor may name. libmw reserves 0xFFFFFFFE and 0xFFFFFFFF as markers,
//! and the wallet keeps indices in signed 32-bit fields.
static constexpr uint32_t MWEB_MAX_DESCRIPTOR_INDEX{0x7FFFFFFF};

MWEBDescriptorForm GetMWEBForm(const Descriptor& desc);
std::optional<std::string> GetMWEBAccountChecksum(const Descriptor& desc);
std::optional<uint32_t> GetMWEBIndex(const Descriptor& desc);

bool IsValidMWEBAccountChecksum(std::span<const char> checksum);

bool ParseMWEBCompressedPubkey(const std::span<const char>& sp, CPubKey& pubkey, std::string& error);

//! Whether a key expression, after any key origin, is an extended (BIP32) public or private key.
bool IsMWEBExtKeyExpression(std::span<const char> key_expr);

//! Parse an mweb() index: decimal digits, no sign, no leading zeros, at most MWEB_MAX_DESCRIPTOR_INDEX.
std::optional<uint32_t> ParseMWEBIndex(std::span<const char> index_expr);

#endif // BITCOIN_SCRIPT_MWEB_DESCRIPTOR_H
