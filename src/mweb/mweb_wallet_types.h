// Copyright (c) 2011 - 2020 The Litecoin Core developers
// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_WALLET_TYPES_H
#define BITCOIN_MWEB_MWEB_WALLET_TYPES_H

#include <serialize.h>
#include <streams.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <uint256.h>

#include <mw/crypto/hasher.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/wallet/coin.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace MWEB {

struct WalletTxInfo
{
    std::optional<mw::Coin> received_coin;
    std::optional<mw::Hash> spent_input;
    std::optional<uint64_t> leaf_index;

    mutable uint256 hash;

    WalletTxInfo()
        : received_coin(std::nullopt), spent_input(std::nullopt), leaf_index(std::nullopt), hash() { }
    explicit WalletTxInfo(mw::Coin received, std::optional<uint64_t> leaf_idx = std::nullopt)
        : received_coin(std::move(received)), spent_input(std::nullopt), leaf_index(leaf_idx), hash(CalcHash()) {}
    explicit WalletTxInfo(mw::Hash spent, std::optional<uint64_t> leaf_idx = std::nullopt)
        : received_coin(std::nullopt), spent_input(std::move(spent)), leaf_index(leaf_idx), hash(CalcHash()) {}

    SERIALIZE_METHODS(WalletTxInfo, obj)
    {
        uint8_t tag = (obj.received_coin ? 0x01 : 0x00) | (obj.leaf_index ? 0x02 : 0x00);
        READWRITE(tag);
        if (tag > 0x03) {
            throw std::ios_base::failure("Unsupported WalletTxInfo tag");
        }
        const bool received = (tag & 0x01) != 0;
        const bool has_leaf = (tag & 0x02) != 0;

        if (received) {
            mw::Coin coin;
            SER_WRITE(obj, coin = obj.received_coin->SanitizeForDisk());
            READWRITE(coin);
            SER_READ(obj, obj.received_coin = std::make_optional<mw::Coin>(std::move(coin)));
            SER_READ(obj, obj.spent_input = std::nullopt);
        } else {
            mw::Hash output_id;
            SER_WRITE(obj, output_id = *Assert(obj.spent_input));
            READWRITE(output_id);
            SER_READ(obj, obj.spent_input = std::make_optional<mw::Hash>(std::move(output_id)));
            SER_READ(obj, obj.received_coin = std::nullopt);
        }

        if (has_leaf) {
            uint64_t leaf{0};
            SER_WRITE(obj, leaf = *Assert(obj.leaf_index));
            READWRITE(VARINT(leaf));
            SER_READ(obj, obj.leaf_index = leaf);
        } else {
            SER_READ(obj, obj.leaf_index = std::nullopt);
        }
        SER_READ(obj, obj.hash = obj.CalcHash());
    }

    static WalletTxInfo FromHex(const std::string& str)
    {
        if (!IsHex(str)) throw std::ios_base::failure("Invalid WalletTxInfo hex");
        std::vector<uint8_t> bytes = ParseHex(str);
        DataStream stream(bytes);

        WalletTxInfo wtx_info;
        stream >> wtx_info;
        if (!stream.empty()) throw std::ios_base::failure("Trailing WalletTxInfo data");
        return wtx_info;
    }

    std::string ToHex() const
    {
        std::vector<uint8_t> vch;
        VectorWriter vw{vch, 0};
        vw << *this;
        return HexStr(vch);
    }

    const uint256& GetHash() const {
        return hash;
    }

private:
    // Domain-separate receive vs spend placeholders so they can coexist in
    // mapWallet for the same output_id (otherwise spend never records AddToSpends).
    // When an output_id recurs after a prior spend, leaf_index disambiguates occurrences.
    uint256 CalcHash() const
    {
        if (received_coin) {
            Hasher hasher;
            hasher.Append<int8_t>('R').Append(received_coin->output_id);
            if (leaf_index) hasher.Append<uint64_t>(*leaf_index);
            return uint256(hasher.hash().vec());
        }
        if (spent_input) {
            Hasher hasher;
            hasher.Append<int8_t>('S').Append(*spent_input);
            if (leaf_index) hasher.Append<uint64_t>(*leaf_index);
            return uint256(hasher.hash().vec());
        }
        return uint256();
    }
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_WALLET_TYPES_H
