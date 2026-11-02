// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/mmr_info.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mweb/mweb_wallet_types.h>
#include <pubkey.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Pins the bytes of every persisted object that holds optional fields: wallet DB records,
// MWEB wallet transaction info, and MMRInfo (node DB and UTXO snapshots). An optional is
// written as a flag byte (0x01 set, 0x00 unset) followed by the value when set.
namespace wallet {
namespace {

template <size_t N>
BigInt<N> Filled(uint8_t byte)
{
    return BigInt<N>(std::vector<uint8_t>(N, byte));
}

std::string Repeat(const std::string& hex_byte, size_t count)
{
    std::string out;
    for (size_t i = 0; i < count; ++i) out += hex_byte;
    return out;
}

template <typename T>
std::string SerializeHex(const T& obj)
{
    DataStream ss{};
    ss << obj;
    return HexStr(ss);
}

CKeyID FilledKeyID(uint8_t byte)
{
    return CKeyID{uint160{std::vector<unsigned char>(20, byte)}};
}

StealthAddress TestAddress()
{
    std::vector<uint8_t> scan(33, 0x55);
    scan[0] = 0x02;
    std::vector<uint8_t> spend(33, 0x66);
    spend[0] = 0x03;
    return StealthAddress(PublicKey(BigInt<33>(scan)), PublicKey(BigInt<33>(spend)));
}

const std::string ADDRESS_HEX{"02" + Repeat("55", 32) + "03" + Repeat("66", 32)};

mw::Coin TestCoinUnset()
{
    mw::Coin coin;
    coin.address_index = 5;
    coin.amount = 100;
    coin.output_id = Filled<32>(0x22);
    return coin;
}

mw::Coin TestCoinSet()
{
    mw::Coin coin = TestCoinUnset();
    coin.spend_key = SecretKey(Filled<32>(0x11));
    coin.blind = BlindingFactor(Filled<32>(0x33));
    coin.sender_key = SecretKey(Filled<32>(0x44));
    coin.address = TestAddress();
    coin.shared_secret = SecretKey(Filled<32>(0x77));
    coin.master_scan_key_id = FilledKeyID(0x88);
    return coin;
}

// Version 3, varint address_index 5, then spend_key and blind, varint amount 100, output_id,
// then sender_key, address, shared_secret and master_scan_key_id.
const std::string COIN_UNSET_HEX{"03" "05" "00" "00" "64" + Repeat("22", 32) + "00" "00" "00" "00"};
const std::string COIN_SET_HEX{"03" "05" "01" + Repeat("11", 32) + "01" + Repeat("33", 32) + "64" + Repeat("22", 32) +
                               "01" + Repeat("44", 32) + "01" + ADDRESS_HEX + "01" + Repeat("77", 32) + "01" + Repeat("88", 20)};
const std::string COIN_SANITIZED_HEX{"03" "05" "00" "00" "64" + Repeat("22", 32) +
                                     "00" "01" + ADDRESS_HEX + "01" + Repeat("77", 32) + "01" + Repeat("88", 20)};

// CKeyMetadata at version 14 from SetNull(): nVersion, nCreateTime, empty hdKeypath, null
// hd_seed_id, key_origin (fingerprint, empty path), has_key_origin, then mweb_index.
const std::string KEY_METADATA_PREFIX_HEX{"0e000000" + Repeat("00", 8) + "00" + Repeat("00", 20) + "00000000" "00" "00"};

// CHDChain at version 4: nVersion, nExternalChainCounter, seed_id, nInternalChainCounter,
// nMWEBIndexCounter, then mweb_scan_key.
const std::string HD_CHAIN_PREFIX_HEX{"04000000" "01000000" + Repeat("aa", 20) + "02000000" "03000000"};

CHDChain TestHDChain()
{
    CHDChain chain;
    chain.nVersion = CHDChain::VERSION_HD_MWEB_WATCH;
    chain.nExternalChainCounter = 1;
    chain.seed_id = FilledKeyID(0xaa);
    chain.nInternalChainCounter = 2;
    chain.nMWEBIndexCounter = 3;
    return chain;
}

// MMRInfo: version, index, pruned, compact_index, then compacted.
const std::string MMR_INFO_PREFIX_HEX{"01" "02000000" + Repeat("99", 32) + "03000000"};

MMRInfo TestMMRInfo()
{
    MMRInfo info;
    info.version = 1;
    info.index = 2;
    info.pruned = Filled<32>(0x99);
    info.compact_index = 3;
    return info;
}
} // namespace

BOOST_AUTO_TEST_SUITE(mweb_optional_serialization_tests)

BOOST_AUTO_TEST_CASE(key_metadata_mweb_index)
{
    CKeyMetadata meta;
    BOOST_CHECK_EQUAL(meta.nVersion, CKeyMetadata::VERSION_WITH_MWEB_INDEX);
    BOOST_CHECK_EQUAL(SerializeHex(meta), KEY_METADATA_PREFIX_HEX + "00");

    meta.mweb_index = uint32_t{0x01020304};
    BOOST_CHECK_EQUAL(SerializeHex(meta), KEY_METADATA_PREFIX_HEX + "01" "04030201");

    DataStream set_stream{ParseHex(KEY_METADATA_PREFIX_HEX + "01" "04030201")};
    CKeyMetadata read_set;
    set_stream >> read_set;
    BOOST_REQUIRE(read_set.mweb_index);
    BOOST_CHECK_EQUAL(*read_set.mweb_index, 0x01020304U);
    BOOST_CHECK(set_stream.empty());

    // Reading an unset field clears a value that was already there.
    DataStream unset_stream{ParseHex(KEY_METADATA_PREFIX_HEX + "00")};
    CKeyMetadata read_unset;
    read_unset.mweb_index = uint32_t{7};
    unset_stream >> read_unset;
    BOOST_CHECK(!read_unset.mweb_index);
    BOOST_CHECK(unset_stream.empty());

    // Any flag other than 0x01 reads as unset, and the value bytes are not consumed.
    DataStream flag2_stream{ParseHex(KEY_METADATA_PREFIX_HEX + "02" "04030201")};
    CKeyMetadata read_flag2;
    flag2_stream >> read_flag2;
    BOOST_CHECK(!read_flag2.mweb_index);
    BOOST_CHECK_EQUAL(flag2_stream.size(), 4U);
}

BOOST_AUTO_TEST_CASE(key_metadata_versions_preserve_full_origin_and_mweb_index)
{
    struct Vector {
        std::string hex;
        int version;
        int64_t created;
        std::string path;
        std::string seed_id;
        std::string fingerprint;
        std::vector<uint32_t> origin_path;
        bool has_origin;
        std::optional<uint32_t> mweb_index;
    };
    const std::vector<Vector> vectors{
        {"0100000083c1242200000000", CKeyMetadata::VERSION_BASIC, 572834179,
            "", Repeat("00", 20), "00000000", {}, false, std::nullopt},
        {"0a000000baef3e5300000000126d2f30272f31272f32313437303836303631e733eb9c0c2ffab4021dd5871ba164bc5b6f2cf2",
            CKeyMetadata::VERSION_WITH_HDDATA, 1396633530, "m/0'/1'/2147086061",
            "f22c6f5bbc64a11b87d51d02b4fa2f0c9ceb33e7", "00000000", {}, false, std::nullopt},
        {"0c000000bee5380100000000126d2f30272f31272f3130393535333237302751379303fdd14c2b412ba8e6d7dd141d1514d45f3d5476ed0300000080010000806d5de96301",
            CKeyMetadata::VERSION_WITH_KEY_ORIGIN, 20506046, "m/0'/1'/109553270'",
            "5fd414151d14ddd7e6a82b412b4cd1fd03933751", "3d5476ed", {2147483648U, 2147483649U, 1676238189U}, true, std::nullopt},
        {"0e0000004711db0600000000146d2f30272f313030272f37353534383535343927b42b9838177bfdd872e14e5a155164db2961b39cffe614810001011407ca6c",
            CKeyMetadata::VERSION_WITH_MWEB_INDEX, 115020103, "m/0'/100'/755485549'",
            "9cb36129db6451155a4ee172d8fd7b1738982bb4", "ffe61481", {}, true, 1825179412U},
    };
    for (const auto& vector : vectors) {
        BOOST_TEST_CONTEXT("metadata version " << vector.version) {
            DataStream stream{ParseHex(vector.hex)};
            CKeyMetadata metadata;
            stream >> metadata;
            BOOST_CHECK(stream.empty());
            BOOST_CHECK_EQUAL(metadata.nVersion, vector.version);
            BOOST_CHECK_EQUAL(metadata.nCreateTime, vector.created);
            BOOST_CHECK_EQUAL(metadata.hdKeypath, vector.path);
            BOOST_CHECK_EQUAL(metadata.hd_seed_id.GetHex(), vector.seed_id);
            BOOST_CHECK_EQUAL(HexStr(metadata.key_origin.fingerprint), vector.fingerprint);
            BOOST_CHECK(metadata.key_origin.path == vector.origin_path);
            BOOST_CHECK_EQUAL(metadata.has_key_origin, vector.has_origin);
            // Native metadata stores this separately from the BIP32 path.
            BOOST_CHECK(metadata.mweb_index == vector.mweb_index);
            BOOST_CHECK_EQUAL(SerializeHex(metadata), vector.hex);
            DataStream truncated{ParseHex(vector.hex.substr(0, vector.hex.size() - 2))};
            CKeyMetadata incomplete;
            BOOST_CHECK_THROW(truncated >> incomplete, std::ios_base::failure);
        }
    }
}

BOOST_AUTO_TEST_CASE(hd_chain_mweb_scan_key)
{
    CHDChain chain = TestHDChain();
    BOOST_CHECK_EQUAL(SerializeHex(chain), HD_CHAIN_PREFIX_HEX + "00");

    chain.mweb_scan_key = SecretKey(Filled<32>(0x11));
    BOOST_CHECK_EQUAL(SerializeHex(chain), HD_CHAIN_PREFIX_HEX + "01" + Repeat("11", 32));

    DataStream ss{ParseHex(HD_CHAIN_PREFIX_HEX + "01" + Repeat("11", 32))};
    CHDChain read;
    ss >> read;
    BOOST_REQUIRE(read.mweb_scan_key);
    BOOST_CHECK(*read.mweb_scan_key == SecretKey(Filled<32>(0x11)));
    BOOST_CHECK(ss.empty());
}

BOOST_AUTO_TEST_CASE(mweb_coin)
{
    BOOST_CHECK_EQUAL(SerializeHex(TestCoinUnset()), COIN_UNSET_HEX);
    BOOST_CHECK_EQUAL(SerializeHex(TestCoinSet()), COIN_SET_HEX);
    BOOST_CHECK_EQUAL(SerializeHex(TestCoinSet().SanitizeForDisk()), COIN_SANITIZED_HEX);

    DataStream set_stream{ParseHex(COIN_SET_HEX)};
    mw::Coin read_set;
    set_stream >> read_set;
    BOOST_CHECK(set_stream.empty());
    BOOST_CHECK_EQUAL(SerializeHex(read_set), COIN_SET_HEX);

    // Reading unset fields clears values that were already there.
    DataStream unset_stream{ParseHex(COIN_UNSET_HEX)};
    mw::Coin read_unset = TestCoinSet();
    unset_stream >> read_unset;
    BOOST_CHECK(unset_stream.empty());
    BOOST_CHECK(!read_unset.spend_key);
    BOOST_CHECK(!read_unset.blind);
    BOOST_CHECK(!read_unset.sender_key);
    BOOST_CHECK(!read_unset.address);
    BOOST_CHECK(!read_unset.shared_secret);
    BOOST_CHECK(!read_unset.master_scan_key_id);

    // A flag of 0x02 on the last field reads as unset and leaves its 20 bytes unread.
    const std::string flag2_hex{COIN_UNSET_HEX.substr(0, COIN_UNSET_HEX.size() - 2) + "02" + Repeat("88", 20)};
    DataStream flag2_stream{ParseHex(flag2_hex)};
    mw::Coin read_flag2;
    flag2_stream >> read_flag2;
    BOOST_CHECK(!read_flag2.master_scan_key_id);
    BOOST_CHECK_EQUAL(flag2_stream.size(), 20U);
}

BOOST_AUTO_TEST_CASE(mweb_wallet_tx_info)
{
    const MWEB::WalletTxInfo received{TestCoinSet()};
    BOOST_CHECK_EQUAL(received.ToHex(), "01" + COIN_SANITIZED_HEX);

    const MWEB::WalletTxInfo spent{mw::Hash{Filled<32>(0xcc)}};
    BOOST_CHECK_EQUAL(spent.ToHex(), "00" + Repeat("cc", 32));

    const MWEB::WalletTxInfo read_received = MWEB::WalletTxInfo::FromHex("01" + COIN_SANITIZED_HEX);
    BOOST_REQUIRE(read_received.received_coin);
    BOOST_CHECK(!read_received.spent_input);
    BOOST_CHECK_EQUAL(SerializeHex(*read_received.received_coin), COIN_SANITIZED_HEX);
    BOOST_CHECK(read_received.GetHash() == received.GetHash());

    const MWEB::WalletTxInfo read_spent = MWEB::WalletTxInfo::FromHex("00" + Repeat("cc", 32));
    BOOST_REQUIRE(read_spent.spent_input);
    BOOST_CHECK(!read_spent.received_coin);
    BOOST_CHECK(!read_spent.leaf_index);
    BOOST_CHECK(*read_spent.spent_input == Filled<32>(0xcc));
    BOOST_CHECK(read_spent.GetHash() == spent.GetHash());

    const MWEB::WalletTxInfo received_leaf{TestCoinSet(), 7};
    BOOST_CHECK_EQUAL(received_leaf.ToHex(), "03" + COIN_SANITIZED_HEX + "07");
    BOOST_CHECK(received_leaf.GetHash() != received.GetHash());
    const MWEB::WalletTxInfo read_received_leaf = MWEB::WalletTxInfo::FromHex(received_leaf.ToHex());
    BOOST_REQUIRE(read_received_leaf.received_coin);
    BOOST_REQUIRE(read_received_leaf.leaf_index);
    BOOST_CHECK_EQUAL(*read_received_leaf.leaf_index, 7U);
    BOOST_CHECK(read_received_leaf.GetHash() == received_leaf.GetHash());

    const MWEB::WalletTxInfo spent_leaf{mw::Hash{Filled<32>(0xcc)}, 9};
    BOOST_CHECK_EQUAL(spent_leaf.ToHex(), "02" + Repeat("cc", 32) + "09");
    BOOST_CHECK(spent_leaf.GetHash() != spent.GetHash());
    const MWEB::WalletTxInfo read_spent_leaf = MWEB::WalletTxInfo::FromHex(spent_leaf.ToHex());
    BOOST_REQUIRE(read_spent_leaf.spent_input);
    BOOST_REQUIRE(read_spent_leaf.leaf_index);
    BOOST_CHECK_EQUAL(*read_spent_leaf.leaf_index, 9U);
    BOOST_CHECK(read_spent_leaf.GetHash() == spent_leaf.GetHash());
    for (const auto& info : {received, spent, received_leaf, spent_leaf}) {
        BOOST_CHECK_THROW(MWEB::WalletTxInfo::FromHex(info.ToHex() + "00"), std::ios_base::failure);
        BOOST_CHECK_THROW(MWEB::WalletTxInfo::FromHex(info.ToHex() + "z"), std::ios_base::failure);
        BOOST_CHECK_THROW(MWEB::WalletTxInfo::FromHex(info.ToHex().substr(1)), std::ios_base::failure);
        BOOST_CHECK_THROW(MWEB::WalletTxInfo::FromHex(info.ToHex().substr(0, info.ToHex().size() - 2)), std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(mmr_info_compacted)
{
    MMRInfo info = TestMMRInfo();
    BOOST_CHECK_EQUAL(SerializeHex(info), MMR_INFO_PREFIX_HEX + "00");

    info.compacted = Filled<32>(0xab);
    BOOST_CHECK_EQUAL(SerializeHex(info), MMR_INFO_PREFIX_HEX + "01" + Repeat("ab", 32));

    DataStream set_stream{ParseHex(MMR_INFO_PREFIX_HEX + "01" + Repeat("ab", 32))};
    MMRInfo read_set{deserialize, set_stream};
    BOOST_REQUIRE(read_set.compacted);
    BOOST_CHECK(*read_set.compacted == Filled<32>(0xab));
    BOOST_CHECK(set_stream.empty());

    DataStream flag2_stream{ParseHex(MMR_INFO_PREFIX_HEX + "02" + Repeat("ab", 32))};
    MMRInfo read_flag2{deserialize, flag2_stream};
    BOOST_CHECK(!read_flag2.compacted);
    BOOST_CHECK_EQUAL(flag2_stream.size(), 32U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
