// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_snapshot.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <hash.h>
#include <kernel/cs_main.h>
#include <kernel/messagestartchars.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <mw/mmr/leaf.h>
#include <mw/mmr/leaf_index.h>
#include <mw/mmr/mmr_info.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/utxo.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using node::ComputeMWEBSnapshotHash;
using node::MaxMWEBSnapshotLeafDatBytes;
using node::MaxMWEBSnapshotODatBytes;
using node::ReadMWEBSnapshotBlob;
using node::ValidateMWEBSnapshotCoinLeafsetBinding;
using node::ValidateMWEBSnapshotLeafPMMRBinding;
using node::WriteMWEBSnapshotBlob;

namespace {

std::vector<uint8_t> MakeLeafDatFile(uint64_t next_leaf, const std::vector<uint64_t>& unspent)
{
    std::vector<uint8_t> dat{mmr::LeafIndex::At(next_leaf).Serialized()};
    dat.resize(8 + (next_leaf + 7) / 8, 0);
    for (uint64_t idx : unspent) {
        BOOST_REQUIRE(idx < next_leaf);
        dat[8 + idx / 8] |= static_cast<uint8_t>(1u << (7 - (idx % 8)));
    }
    return dat;
}

mw::Header MakeHeader(uint64_t num_txos)
{
    return mw::Header(
        /*height=*/1,
        mw::Hash{},
        mw::Hash{},
        mw::Hash{},
        BlindingFactor{},
        BlindingFactor{},
        num_txos,
        /*kernelMMRSize=*/0);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_snapshot_tests, BasicTestingSetup)

// AssumeUTXO MWEB PMMR blobs must load when larger than serialize.h MAX_SIZE (32 MiB).
BOOST_AUTO_TEST_CASE(snapshot_blob_roundtrip_above_max_size)
{
    constexpr size_t kOverMax{static_cast<size_t>(MAX_SIZE) + 4096};
    BOOST_REQUIRE(kOverMax > MAX_SIZE);

    // Default ReadCompactSize range-check rejects this size; our blob reader must not.
    {
        DataStream probe{};
        WriteCompactSize(probe, kOverMax);
        BOOST_CHECK_EXCEPTION(ReadCompactSize(probe, /*range_check=*/true), std::ios_base::failure,
                              [](const std::ios_base::failure& e) {
                                  return std::string(e.what()).find("size too large") != std::string::npos;
                              });
    }

    const fs::path path{m_args.GetDataDirBase() / "mweb_snapshot_f12.bin"};
    std::vector<uint8_t> payload(kOverMax);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i & 0xff);
    }

    {
        AutoFile out{fsbridge::fopen(path, "w+b")};
        BOOST_REQUIRE(out.IsNull() == false);
        WriteMWEBSnapshotBlob(out, payload);
        // Second blob under the leaf_dat floor (32 MiB) but still sequential.
        std::vector<uint8_t> leaf(MAX_SIZE, 0x5a);
        WriteMWEBSnapshotBlob(out, leaf);
        // AutoFile::~AutoFile requires an explicit successful close after writes.
        BOOST_REQUIRE_EQUAL(out.fclose(), 0);
    }

    {
        AutoFile in{fsbridge::fopen(path, "rb")};
        BOOST_REQUIRE(in.IsNull() == false);
        // Caps for num_txos=0 still floor at 64 MiB / 32 MiB — enough for this probe.
        const auto got_o = ReadMWEBSnapshotBlob(in, MaxMWEBSnapshotODatBytes(/*num_txos=*/0));
        BOOST_CHECK_EQUAL(got_o.size(), payload.size());
        BOOST_CHECK(got_o == payload);

        const auto got_leaf = ReadMWEBSnapshotBlob(in, MaxMWEBSnapshotLeafDatBytes(/*num_txos=*/0));
        BOOST_CHECK_EQUAL(got_leaf.size(), MAX_SIZE);
        BOOST_CHECK(got_leaf.front() == 0x5a);
        BOOST_CHECK(got_leaf.back() == 0x5a);
    }

    fs::remove(path);
}

BOOST_AUTO_TEST_CASE(snapshot_blob_respects_cap)
{
    const fs::path path{m_args.GetDataDirBase() / "mweb_snapshot_cap.bin"};
    {
        AutoFile out{fsbridge::fopen(path, "w+b")};
        std::vector<uint8_t> payload(1024, 0x11);
        WriteMWEBSnapshotBlob(out, payload);
        // AutoFile::~AutoFile requires an explicit successful close after writes.
        BOOST_REQUIRE_EQUAL(out.fclose(), 0);
    }
    {
        AutoFile in{fsbridge::fopen(path, "rb")};
        BOOST_CHECK_EXCEPTION(ReadMWEBSnapshotBlob(in, /*max_bytes=*/512), std::ios_base::failure,
                              [](const std::ios_base::failure& e) {
                                  return std::string(e.what()).find("exceeds limit") != std::string::npos;
                              });
    }
    fs::remove(path);
}

// CoinDB ↔ leafset binding must reject missing / mismatched entries.
BOOST_AUTO_TEST_CASE(coin_leafset_binding_happy_and_mutate)
{
    const mw::Header header{MakeHeader(/*num_txos=*/1)};
    UTXO utxo(/*blockHeight=*/1, mmr::LeafIndex::At(0), Output{});
    const mw::Hash output_id{utxo.GetOutputID()};
    const std::vector<std::pair<mw::Hash, UTXO>> utxos{{output_id, utxo}};
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries{{0, output_id.vec()}};
    const std::vector<uint8_t> leaf_dat{MakeLeafDatFile(/*next_leaf=*/1, /*unspent=*/{0})};

    BOOST_REQUIRE(ValidateMWEBSnapshotCoinLeafsetBinding(header, utxos, leaf_entries, leaf_dat));

    // Drop the UTXO → leafset still marks unspent.
    BOOST_CHECK(!ValidateMWEBSnapshotCoinLeafsetBinding(header, {}, leaf_entries, leaf_dat));

    // Clear the leafset bit → UTXO/LeafDB orphaned.
    const std::vector<uint8_t> empty_leaf{MakeLeafDatFile(/*next_leaf=*/1, /*unspent=*/{})};
    BOOST_CHECK(!ValidateMWEBSnapshotCoinLeafsetBinding(header, utxos, leaf_entries, empty_leaf));

    // Corrupt LeafDB payload so it no longer matches the UTXO output id.
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> bad_leaf{leaf_entries};
    bad_leaf[0].second[0] ^= 0xff;
    BOOST_CHECK(!ValidateMWEBSnapshotCoinLeafsetBinding(header, utxos, bad_leaf, leaf_dat));
}

// LeafDB payload must bind to the output PMMR leaf hash in o_dat (not just leafset bits).
BOOST_AUTO_TEST_CASE(leaf_pmmr_binding_happy_and_mutate)
{
    std::vector<uint8_t> leaf_data(32, 0x42);
    leaf_data[0] = 0x11;
    const mmr::LeafIndex idx = mmr::LeafIndex::At(0);
    const mw::Hash leaf_hash = mmr::Leaf::CalcHash(idx, leaf_data);
    const std::vector<uint8_t>& o_dat = leaf_hash.vec();
    // Parent/peak padding is irrelevant for binding; leaf 0 sits at file offset 0 with empty prune.
    const std::vector<uint8_t> prun_dat;
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries{{0, leaf_data}};

    BOOST_REQUIRE(ValidateMWEBSnapshotLeafPMMRBinding(leaf_entries, o_dat, prun_dat));

    // Tamper LeafDB payload while leaving o_dat honest → CalcHash mismatch.
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> bad_payload{leaf_entries};
    bad_payload[0].second[1] ^= 0xff;
    BOOST_CHECK(!ValidateMWEBSnapshotLeafPMMRBinding(bad_payload, o_dat, prun_dat));

    // Tamper o_dat leaf hash while leaving payload honest.
    std::vector<uint8_t> bad_o{o_dat};
    bad_o[0] ^= 0xff;
    BOOST_CHECK(!ValidateMWEBSnapshotLeafPMMRBinding(leaf_entries, bad_o, prun_dat));

    // Truncated o_dat cannot supply the leaf hash.
    BOOST_CHECK(!ValidateMWEBSnapshotLeafPMMRBinding(leaf_entries, {}, prun_dat));
}

// Content hash must ignore raw PMMR/leaf/prune blob layout drift when logical data is unchanged.
BOOST_AUTO_TEST_CASE(mweb_content_hash_ignores_blob_drift)
{
    const mw::Header header{MakeHeader(/*num_txos=*/0)};
    const MMRInfo mmr_info;
    const std::vector<std::pair<mw::Hash, UTXO>> utxos;
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries;
    std::vector<uint8_t> leaf_dat{MakeLeafDatFile(/*next_leaf=*/0, /*unspent=*/{})};
    std::vector<uint8_t> o_dat(32, 0xab);
    std::vector<uint8_t> prun_dat(8, 0xcd);

    const uint256 honest = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    o_dat[0] ^= 0xff;
    leaf_dat[0] ^= 0x0f;
    prun_dat[0] ^= 0xf0;
    const uint256 drifted = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    BOOST_CHECK_MESSAGE(
        honest == drifted,
        "blob drift changed canonical MWEB snapshot hash: "
            << honest.ToString() << " vs " << drifted.ToString());
}

// Content hash must change when the logical MWEB state changes.
BOOST_AUTO_TEST_CASE(mweb_content_hash_detects_logical_drift)
{
    const mw::Header header{MakeHeader(/*num_txos=*/1)};
    const MMRInfo mmr_info;
    const std::vector<std::pair<mw::Hash, UTXO>> utxos;
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries{{0, std::vector<uint8_t>(32, 0x42)}};
    const std::vector<uint8_t> o_dat(32, 0xab);
    const std::vector<uint8_t> leaf_dat{MakeLeafDatFile(/*next_leaf=*/1, /*unspent=*/{0})};
    const std::vector<uint8_t> prun_dat(8, 0xcd);

    const uint256 honest = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);

    auto bad_leaf_entries = leaf_entries;
    bad_leaf_entries[0].second[0] ^= 0xff;
    const uint256 leaf_drifted = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, bad_leaf_entries, o_dat, leaf_dat, prun_dat);
    BOOST_CHECK(honest != leaf_drifted);

    const mw::Header height_drifted_header = MakeHeader(/*num_txos=*/2);
    const uint256 header_drifted = ComputeMWEBSnapshotHash(
        height_drifted_header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    BOOST_CHECK(honest != header_drifted);

    auto bad_mmr_info = mmr_info;
    bad_mmr_info.index = 1;
    bad_mmr_info.compact_index = 99;
    const uint256 mmr_info_drifted = ComputeMWEBSnapshotHash(
        header, bad_mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    BOOST_CHECK_MESSAGE(
        honest == mmr_info_drifted,
        "MMRInfo file-index drift changed canonical MWEB snapshot hash: "
            << honest.ToString() << " vs " << mmr_info_drifted.ToString());
}

// Optional: recompute (and optionally rewrite) the MWEB hash field of a live
// dumptxoutset file after hasher changes. Skip unless ADGL_MWEB_SNAPSHOT_DUMP
// is set. Set ADGL_MWEB_SNAPSHOT_REWRITE=1 to write the new hash in place.
BOOST_AUTO_TEST_CASE(rehash_external_mweb_snapshot_dump)
{
    const char* dump_path_c = std::getenv("ADGL_MWEB_SNAPSHOT_DUMP");
    if (!dump_path_c || dump_path_c[0] == '\0') {
        return;
    }
    const bool rewrite = [] {
        const char* v = std::getenv("ADGL_MWEB_SNAPSHOT_REWRITE");
        return v && v[0] == '1' && v[1] == '\0';
    }();

    AutoFile file{fsbridge::fopen(fs::u8path(dump_path_c), rewrite ? "r+b" : "rb")};
    BOOST_REQUIRE_MESSAGE(!file.IsNull(), "failed to open ADGL_MWEB_SNAPSHOT_DUMP");

    std::array<uint8_t, 5> utxo_magic{};
    uint16_t version{0};
    MessageStartChars network_magic{};
    uint256 base_blockhash;
    uint64_t coins_count{0};
    file >> utxo_magic >> version >> network_magic >> base_blockhash >> coins_count;
    BOOST_REQUIRE(utxo_magic == SNAPSHOT_MAGIC_BYTES);
    (void)network_magic;

    uint64_t coins_left = coins_count;
    while (coins_left > 0) {
        Txid txid;
        file >> txid;
        const uint64_t coins_per_txid = ReadCompactSize(file);
        BOOST_REQUIRE(coins_per_txid > 0 && coins_per_txid <= coins_left);
        for (uint64_t i = 0; i < coins_per_txid; ++i) {
            ReadCompactSize(file);
            Coin coin;
            file >> coin;
            --coins_left;
        }
    }

    auto detected = node::DetectMWEBSnapshotSection(file, coins_count);
    BOOST_REQUIRE(detected);
    BOOST_REQUIRE(*detected);

    uint16_t section_version{0};
    mw::Header header;
    file >> section_version >> header;
    BOOST_REQUIRE_EQUAL(section_version, node::MWEB_SNAPSHOT_SECTION_VERSION);

    const int64_t hash_pos = file.tell();
    uint256 stored_hash;
    MMRInfo mmr_info;
    file >> stored_hash >> mmr_info;

    const uint64_t coin_count = ReadCompactSize(file);
    std::vector<std::pair<mw::Hash, UTXO>> utxos;
    utxos.reserve(coin_count);
    for (uint64_t i = 0; i < coin_count; ++i) {
        mw::Hash output_id;
        UTXO utxo;
        file >> output_id >> utxo;
        utxos.emplace_back(output_id, std::move(utxo));
    }

    const uint64_t leafdb_count = ReadCompactSize(file);
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries;
    leaf_entries.reserve(leafdb_count);
    for (uint64_t i = 0; i < leafdb_count; ++i) {
        uint64_t leaf_index{0};
        file >> leaf_index;
        const uint64_t size = ReadCompactSize(file);
        std::vector<uint8_t> leaf_data(size);
        if (size > 0) {
            file.read(std::as_writable_bytes(std::span{leaf_data}));
        }
        leaf_entries.emplace_back(leaf_index, std::move(leaf_data));
    }

    const uint256 canonical = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, leaf_entries, /*o_dat=*/{}, /*leaf_dat=*/{}, /*prun_dat=*/{});

    auto hash_with_mmr = [&](const MMRInfo& info) {
        HashWriter ss;
        ss << header;
        ss << info;
        WriteCompactSize(ss, utxos.size());
        for (const auto& [output_id, utxo] : utxos) {
            ss << output_id;
            ss << utxo;
        }
        WriteCompactSize(ss, leaf_entries.size());
        for (const auto& [leaf_index, leaf_data] : leaf_entries) {
            ss << leaf_index;
            WriteCompactSize(ss, leaf_data.size());
            if (!leaf_data.empty()) {
                ss.write(std::as_bytes(std::span{leaf_data}));
            }
        }
        return ss.GetHash();
    };

    const uint256 old_hasher = hash_with_mmr(mmr_info);
    const uint256 ibd_reported{uint256{"69f98c1fe9e12533d9ce38b09756790df27ef966e4c79539ef9748b46901c1aa"}};
    int matched_index = -1;
    for (uint32_t idx = 0; idx <= 30; ++idx) {
        MMRInfo probe = mmr_info;
        probe.index = idx;
        if (hash_with_mmr(probe) == ibd_reported) {
            matched_index = static_cast<int>(idx);
            break;
        }
    }

    std::cout << "dump " << dump_path_c << "\n"
              << "dump_version " << version << "\n"
              << "base_blockhash " << base_blockhash.ToString() << "\n"
              << "l1_coins " << coins_count << "\n"
              << "mweb_coins " << utxos.size() << "\n"
              << "leafdb " << leaf_entries.size() << "\n"
              << "mmr_info.version " << unsigned(mmr_info.version) << "\n"
              << "mmr_info.index " << mmr_info.index << "\n"
              << "mmr_info.compact_index " << mmr_info.compact_index << "\n"
              << "mmr_info.pruned " << mmr_info.pruned.ToHex() << "\n"
              << "mmr_info.compacted " << (mmr_info.compacted ? mmr_info.compacted->ToHex() : std::string("none")) << "\n"
              << "stored_mweb_hash " << stored_hash.ToString() << "\n"
              << "canonical_mweb_hash " << canonical.ToString() << "\n"
              << "old_hasher_with_dump_mmr_info " << old_hasher.ToString() << "\n"
              << "ibd_index_match " << matched_index << "\n";

    if (rewrite && stored_hash != canonical) {
        file.seek(hash_pos, SEEK_SET);
        file << canonical;
        BOOST_REQUIRE(file.Commit());
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
        std::cout << "rewrote dump mweb_hash field\n";
    }
}

// The MWEB snapshot load reads the base block from disk, so the base block is
// stored before activation. Background validation must still be able to write
// its undo data before any block above the base has been stored.
BOOST_AUTO_TEST_CASE(snapshot_base_block_undo_before_assumed_blocks)
{
    node::KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    node::BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    constexpr int BASE_HEIGHT{10};
    CBlock base_block;
    base_block.nVersion = 1;
    CBlock next_block;
    next_block.nVersion = 2;
    const uint256 parent_hash{uint256::ONE};
    CBlockIndex parent_index;
    parent_index.phashBlock = &parent_hash;
    parent_index.nHeight = BASE_HEIGHT - 1;

    LOCK(::cs_main);
    const FlatFilePos base_pos{blockman.WriteBlock(base_block, BASE_HEIGHT)};
    BOOST_REQUIRE(!base_pos.IsNull());
    blockman.m_snapshot_height = BASE_HEIGHT;

    CBlockIndex base_index;
    base_index.pprev = &parent_index;
    base_index.nHeight = BASE_HEIGHT;
    base_index.nFile = base_pos.nFile;
    base_index.nDataPos = base_pos.nPos;
    base_index.nStatus = BLOCK_HAVE_DATA;

    BlockValidationState state;
    BOOST_CHECK(blockman.WriteBlockUndo(CBlockUndo{}, state, base_index));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(base_index.nStatus & BLOCK_HAVE_UNDO);
    BOOST_CHECK_EQUAL(base_index.GetUndoPos().nFile, base_pos.nFile);

    // Blocks above the base still get their own block file.
    const FlatFilePos next_pos{blockman.WriteBlock(next_block, BASE_HEIGHT + 1)};
    BOOST_REQUIRE(!next_pos.IsNull());
    BOOST_CHECK_NE(next_pos.nFile, base_pos.nFile);
}

BOOST_AUTO_TEST_SUITE_END()
