// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_snapshot.h>

#include <dbwrapper.h>
#include <hash.h>
#include <mweb/mweb_db.h>
#include <mw/common/dynamic_bit_set.h>
#include <mw/db/coin_db.h>
#include <mw/db/leaf_db.h>
#include <mw/db/mmr_info_db.h>
#include <mw/file/file.h>
#include <mw/file/file_path.h>
#include <node/mweb_utxo_enumerate.h>
#include <mw/node/coins_view.h>
#include <mw/mmr/mmr.h>
#include <mw/mmr/prune_list.h>
#include <mw/util/string_util.h>
#include <serialize.h>
#include <streams.h>
#include <txdb.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <stdexcept>
#include <algorithm>
#include <unordered_map>
#include <vector>

namespace node {

namespace {

std::vector<uint8_t> ReadFileBytes(const FilePath& path)
{
    File file(path);
    if (!file.Exists()) {
        return {};
    }
    return file.ReadBytes();
}

void WriteFileBytes(const FilePath& path, const std::vector<uint8_t>& bytes)
{
    File file(path);
    if (bytes.empty()) {
        if (file.Exists()) {
            file.Truncate(0);
        } else {
            file.Create();
        }
        return;
    }
    // File::Write(bytes) appends. Snapshot load must replace any pre-created
    // empty index-0 PMMR/leafset files from chainstate init (ece6aad canonicalize).
    file.Write(/*startIndex=*/0, bytes, /*truncate=*/true);
}

void WriteBytes(AutoFile& file, const std::vector<uint8_t>& bytes)
{
    WriteCompactSize(file, bytes.size());
    if (!bytes.empty()) {
        file.write(std::as_bytes(std::span{bytes}));
    }
}

std::vector<uint8_t> ReadBytes(AutoFile& file)
{
    // LeafDB payloads and other small blobs stay under serialize.h MAX_SIZE.
    const uint64_t size = ReadCompactSize(file);
    std::vector<uint8_t> bytes(size);
    if (size > 0) {
        file.read(std::as_writable_bytes(std::span{bytes}));
    }
    return bytes;
}

} // namespace

void WriteMWEBSnapshotBlob(AutoFile& file, const std::vector<uint8_t>& bytes)
{
    WriteCompactSize(file, bytes.size());
    if (!bytes.empty()) {
        file.write(std::as_bytes(std::span{bytes}));
    }
}

std::vector<uint8_t> ReadMWEBSnapshotBlob(AutoFile& file, uint64_t max_bytes)
{
    // PMMR dumps exceed serialize.h MAX_SIZE (32 MiB) on realistic chains.
    const uint64_t size = ReadCompactSize(file, /*range_check=*/false);
    if (size > max_bytes) {
        throw std::ios_base::failure(strprintf(
            "MWEB snapshot blob size %u exceeds limit %u", size, max_bytes));
    }
    std::vector<uint8_t> bytes(size);
    if (size > 0) {
        file.read(std::as_writable_bytes(std::span{bytes}));
    }
    return bytes;
}

uint64_t MaxMWEBSnapshotODatBytes(uint64_t num_txos)
{
    // Peak MMR nodes is < 2 * num_txos; 32-byte hashes → budget 64 bytes/txo,
    // plus 1 MiB slack. Floor at 64 MiB so small headers still round-trip
    // oversized-but-legal dumps used in tests / headroom.
    const uint64_t expected{num_txos * 64 + (1ULL << 20)};
    return std::min(MAX_MWEB_SNAPSHOT_BLOB_BYTES, std::max(uint64_t{64} << 20, expected));
}

uint64_t MaxMWEBSnapshotLeafDatBytes(uint64_t num_txos)
{
    const uint64_t expected{(num_txos + 7) / 8 + 4096};
    return std::min(MAX_MWEB_SNAPSHOT_BLOB_BYTES, std::max(uint64_t{0x02000000}, expected));
}

uint64_t MaxMWEBSnapshotPrunDatBytes(uint64_t num_txos)
{
    // Prune lists are much smaller than o_dat; reuse the o_dat cap.
    return MaxMWEBSnapshotODatBytes(num_txos);
}

namespace {

void ApplyMWEBSnapshotHash(
    HashWriter& ss,
    const mw::Header& header,
    const MMRInfo& mmr_info,
    const std::vector<std::pair<mw::Hash, UTXO>>& utxos,
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& /*o_dat*/,
    const std::vector<uint8_t>& /*leaf_dat*/,
    const std::vector<uint8_t>& /*prun_dat*/)
{
    ss << header;
    // MMRInfo.index / compact_index are local PMMR file numbers (incremented
    // on every Flush). Hashing them makes dumptxoutset from a long-lived node
    // disagree with background IBD at the same height. Blobs are already
    // ignored; mmr_info is the same class of layout, not consensus state.
    (void)mmr_info;
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
}

} // namespace

uint256 ComputeMWEBSnapshotHash(
    const mw::Header& header,
    const MMRInfo& mmr_info,
    const std::vector<std::pair<mw::Hash, UTXO>>& utxos,
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& o_dat,
    const std::vector<uint8_t>& leaf_dat,
    const std::vector<uint8_t>& prun_dat)
{
    HashWriter ss;
    ApplyMWEBSnapshotHash(ss, header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    return ss.GetHash();
}

namespace {

/** leaf.dat on-disk format: 8-byte nextLeafIdx then bit-packed unspent flags. */
bool LeafDatContains(const std::vector<uint8_t>& leaf_dat, uint64_t leaf_idx)
{
    if (leaf_dat.size() < 8) return false;
    const uint64_t file_byte{8 + (leaf_idx / 8)};
    if (file_byte >= leaf_dat.size()) return false;
    const uint8_t mask{static_cast<uint8_t>(1u << (7 - (leaf_idx % 8)))};
    return (leaf_dat[file_byte] & mask) != 0;
}

} // namespace

util::Result<void> ValidateMWEBSnapshotCoinLeafsetBinding(
    const mw::Header& header,
    const std::vector<std::pair<mw::Hash, UTXO>>& utxos,
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& leaf_dat)
{
    if (leaf_dat.size() < 8) {
        return util::Error{Untranslated("MWEB snapshot leafset file is truncated")};
    }

    const mmr::LeafIndex next_leaf{mmr::LeafIndex::Deserialize(
        std::vector<uint8_t>(leaf_dat.begin(), leaf_dat.begin() + 8))};
    if (next_leaf.Get() != header.GetNumTXOs()) {
        return util::Error{Untranslated(strprintf(
            "MWEB snapshot leafset next index %u does not match header output MMR size %u",
            next_leaf.Get(), header.GetNumTXOs()))};
    }

    if (utxos.size() != leaf_entries.size()) {
        return util::Error{Untranslated(strprintf(
            "MWEB snapshot UTXO count %u does not match LeafDB entry count %u",
            utxos.size(), leaf_entries.size()))};
    }

    std::unordered_map<uint64_t, mw::Hash> leaf_to_id;
    leaf_to_id.reserve(leaf_entries.size());
    for (const auto& [leaf_index, leaf_data] : leaf_entries) {
        if (leaf_index >= next_leaf.Get()) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot LeafDB index %u is outside leafset range %u",
                leaf_index, next_leaf.Get()))};
        }
        if (!LeafDatContains(leaf_dat, leaf_index)) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot LeafDB index %u is not marked unspent in leafset", leaf_index))};
        }
        if (leaf_data.size() != 32) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot LeafDB entry at %u has unexpected size %u", leaf_index, leaf_data.size()))};
        }
        const mw::Hash output_id{leaf_data};
        if (!leaf_to_id.emplace(leaf_index, output_id).second) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot has duplicate LeafDB index %u", leaf_index))};
        }
    }

    std::unordered_map<uint64_t, mw::Hash> utxo_to_id;
    utxo_to_id.reserve(utxos.size());
    for (const auto& [output_id, utxo] : utxos) {
        if (output_id != utxo.GetOutputID()) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot UTXO key mismatch for output %s", output_id.ToHex()))};
        }
        const uint64_t leaf_index{utxo.GetLeafIndex().Get()};
        if (leaf_index >= next_leaf.Get() || !LeafDatContains(leaf_dat, leaf_index)) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot UTXO %s leaf index %u is not marked unspent in leafset",
                output_id.ToHex(), leaf_index))};
        }
        const auto leaf_it = leaf_to_id.find(leaf_index);
        if (leaf_it == leaf_to_id.end()) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot UTXO %s leaf index %u has no LeafDB entry",
                output_id.ToHex(), leaf_index))};
        }
        if (leaf_it->second != output_id) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot UTXO %s does not match LeafDB payload at leaf %u",
                output_id.ToHex(), leaf_index))};
        }
        if (!utxo_to_id.emplace(leaf_index, output_id).second) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot has duplicate UTXO leaf index %u", leaf_index))};
        }
    }

    // Every unspent leafset bit must appear in both maps.
    for (uint64_t i = 0; i < next_leaf.Get(); ++i) {
        if (!LeafDatContains(leaf_dat, i)) continue;
        if (!leaf_to_id.contains(i) || !utxo_to_id.contains(i)) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot leafset marks leaf %u unspent without matching UTXO/LeafDB entries", i))};
        }
    }

    return {};
}

util::Result<void> ValidateMWEBSnapshotLeafPMMRBinding(
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& o_dat,
    const std::vector<uint8_t>& prun_dat)
{
    const mw::DynamicBitSet compacted = mw::DynamicBitSet::From(prun_dat);
    for (const auto& [leaf_index, leaf_data] : leaf_entries) {
        const mmr::LeafIndex idx = mmr::LeafIndex::At(leaf_index);
        const uint64_t node_pos = idx.GetPosition();
        // Unspent LeafDB entries must not sit on compacted MMR positions.
        if (compacted.test(node_pos)) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot LeafDB index %u is marked compacted in the prune list", leaf_index))};
        }
        uint64_t file_pos = node_pos;
        if (compacted.size() > 0) {
            file_pos -= compacted.rank(node_pos);
        }
        const size_t offset = static_cast<size_t>(file_pos) * mw::Hash::size();
        if (offset + mw::Hash::size() > o_dat.size()) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot o_dat is truncated for leaf index %u (need offset %u)",
                leaf_index, offset))};
        }
        const mw::Hash expected = mmr::Leaf::CalcHash(idx, leaf_data);
        const mw::Hash stored{std::vector<uint8_t>(
            o_dat.begin() + static_cast<std::ptrdiff_t>(offset),
            o_dat.begin() + static_cast<std::ptrdiff_t>(offset + mw::Hash::size()))};
        if (expected != stored) {
            return util::Error{Untranslated(strprintf(
                "MWEB snapshot LeafDB payload at index %u does not match output PMMR leaf hash",
                leaf_index))};
        }
    }
    return {};
}

namespace {

struct MWEBSnapshotContent {
    MMRInfo mmr_info;
    std::vector<std::pair<mw::Hash, UTXO>> utxos;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries;
    std::vector<uint8_t> o_dat;
    std::vector<uint8_t> leaf_dat;
    std::vector<uint8_t> prun_dat;
};

util::Result<MWEBSnapshotContent> GatherMWEBSnapshotContent(
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const mw::ICoinsView* utxo_view,
    const std::function<void()>& interruption_point)
{
    CDBWrapper* db = coins_db.GetDB();
    if (!db) {
        return util::Error{Untranslated("MWEB snapshot requires a persistent chainstate database")};
    }

    MWEB::DBWrapper mweb_db(db);
    const auto mmr_info = MMRInfoDB(&mweb_db, nullptr).GetLatest();
    if (!mmr_info) {
        return util::Error{Untranslated("MWEB snapshot requires MMRInfo in chainstate")};
    }

    MWEBSnapshotContent content;
    content.mmr_info = *mmr_info;

    const mw::ICoinsView* scan_view = utxo_view;
    if (!scan_view) {
        scan_view = coins_db.GetMWEBView().get();
    }
    if (scan_view) {
        const auto gather_result = ForEachUnspentMWEBUTXO(
            *scan_view,
            [&](MWEBUnspentEntry&& entry) {
                content.leaf_entries.emplace_back(entry.leaf_index.Get(), std::move(entry.leaf_data));
                UTXO::CPtr pUTXO = scan_view->GetUTXO(entry.output_id);
                content.utxos.emplace_back(entry.output_id, *pUTXO);
                return true;
            },
            interruption_point);
        if (!gather_result) {
            return util::Error{util::ErrorString(gather_result)};
        }
    } else {
        auto iter = mweb_db.NewIterator();
        iter->Seek(std::string(1, 'U'));
        unsigned int count{0};
        while (iter->Valid()) {
            std::string key;
            if (!iter->GetKey(key) || key.empty() || key.front() != 'U') {
                break;
            }

            if (count++ % 5000 == 0) {
                interruption_point();
            }

            std::vector<uint8_t> value;
            if (!db->Read(key, value)) {
                return util::Error{Untranslated(strprintf("Failed to read MWEB UTXO key %s", key))};
            }

            DataStream stream(value);
            UTXO utxo;
            stream >> utxo;
            content.utxos.emplace_back(utxo.GetOutputID(), std::move(utxo));
            iter->Next();
        }

        iter = mweb_db.NewIterator();
        iter->Seek(std::string(1, 'O'));
        count = 0;
        while (iter->Valid()) {
            std::string key;
            if (!iter->GetKey(key) || key.empty() || key.front() != 'O') {
                break;
            }

            if (count++ % 5000 == 0) {
                interruption_point();
            }

            std::vector<uint8_t> value;
            if (!db->Read(key, value)) {
                return util::Error{Untranslated(strprintf("Failed to read MWEB LeafDB key %s", key))};
            }

            const std::string leaf_idx_str = key.substr(1);
            const auto leaf_index_opt = ToIntegral<uint64_t>(leaf_idx_str);
            if (!leaf_index_opt) {
                return util::Error{Untranslated(strprintf("Invalid MWEB LeafDB key index %s", leaf_idx_str))};
            }
            content.leaf_entries.emplace_back(*leaf_index_opt, std::move(value));
            iter->Next();
        }
    }

    const uint32_t file_index = content.mmr_info.index;
    const uint32_t compact_index = content.mmr_info.compact_index;
    content.o_dat = ReadFileBytes(PMMR::GetPath(chainstate_dir, 'O', file_index));
    content.leaf_dat = ReadFileBytes(LeafSet::GetPath(chainstate_dir, file_index));
    content.prun_dat = ReadFileBytes(PruneList::GetPath(chainstate_dir, compact_index));
    return content;
}

} // namespace

util::Result<uint256> ComputeMWEBSnapshotHashFromChainstate(
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const mw::Header& header,
    const mw::ICoinsView* utxo_view,
    const std::function<void()>& interruption_point)
{
    auto content = GatherMWEBSnapshotContent(coins_db, chainstate_dir, utxo_view, interruption_point);
    if (!content) {
        return util::Error{util::ErrorString(content)};
    }
    return ComputeMWEBSnapshotHash(
        header, content->mmr_info, content->utxos, content->leaf_entries,
        content->o_dat, content->leaf_dat, content->prun_dat);
}

MWEBSnapshotWriteStats WriteMWEBSnapshotSection(
    AutoFile& file,
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const mw::Header::CPtr& header,
    const mw::ICoinsView* utxo_view,
    const std::function<void()>& interruption_point)
{
    if (!header) {
        throw std::runtime_error("MWEB snapshot write requires a non-null extension block header");
    }

    auto content = GatherMWEBSnapshotContent(coins_db, chainstate_dir, utxo_view, interruption_point);
    if (!content) {
        throw std::runtime_error(util::ErrorString(content).original);
    }

    const uint256 mweb_hash = ComputeMWEBSnapshotHash(
        *header, content->mmr_info, content->utxos, content->leaf_entries,
        content->o_dat, content->leaf_dat, content->prun_dat);

    file << MWEB_SNAPSHOT_MAGIC_BYTES;
    file << MWEB_SNAPSHOT_SECTION_VERSION;
    file << *header;
    file << mweb_hash;
    // PMMR file numbers are local flush layout. Canonicalize so snapshot bytes
    // do not depend on how many MWEB flushes the dumping node has performed.
    MMRInfo snapshot_mmr_info = content->mmr_info;
    snapshot_mmr_info.index = 0;
    snapshot_mmr_info.compact_index = 0;
    file << snapshot_mmr_info;

    WriteCompactSize(file, content->utxos.size());
    for (const auto& [output_id, utxo] : content->utxos) {
        file << output_id;
        file << utxo;
    }

    WriteCompactSize(file, content->leaf_entries.size());
    for (const auto& [leaf_index, leaf_data] : content->leaf_entries) {
        file << leaf_index;
        WriteBytes(file, leaf_data);
    }

    WriteMWEBSnapshotBlob(file, content->o_dat);
    WriteMWEBSnapshotBlob(file, content->leaf_dat);
    WriteMWEBSnapshotBlob(file, content->prun_dat);

    return {
        .coins_written = content->utxos.size(),
        .leafdb_entries_written = content->leaf_entries.size(),
        .o_dat_bytes = content->o_dat.size(),
        .leaf_dat_bytes = content->leaf_dat.size(),
        .prun_dat_bytes = content->prun_dat.size(),
        .mweb_hash = mweb_hash,
    };
}

util::Result<MWEBSnapshotLoadStats> LoadMWEBSnapshotSection(
    AutoFile& file,
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const std::function<void()>& interruption_point)
{
    uint16_t section_version{0};
    try {
        file >> section_version;
    } catch (const std::ios_base::failure&) {
        return util::Error{Untranslated("Missing MWEB snapshot section version")};
    }
    if (section_version != MWEB_SNAPSHOT_SECTION_VERSION) {
        return util::Error{Untranslated(strprintf("Unsupported MWEB snapshot section version: %u", section_version))};
    }

    mw::Header header;
    uint256 mweb_hash_expected;
    MMRInfo mmr_info;
    try {
        file >> header;
        file >> mweb_hash_expected;
        file >> mmr_info;
    } catch (const std::ios_base::failure&) {
        return util::Error{Untranslated("Truncated MWEB snapshot section header")};
    }

    CDBWrapper* db = coins_db.GetDB();
    if (!db) {
        return util::Error{Untranslated("MWEB snapshot load requires a persistent chainstate database")};
    }

    MWEB::DBWrapper mweb_db(db);
    std::vector<std::pair<mw::Hash, UTXO>> utxos;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> leaf_entries;

    try {
        const uint64_t coin_count = ReadCompactSize(file);
        utxos.reserve(coin_count);
        for (uint64_t i = 0; i < coin_count; ++i) {
            if (i % 5000 == 0) {
                interruption_point();
            }
            mw::Hash output_id;
            UTXO utxo;
            file >> output_id;
            file >> utxo;
            utxos.emplace_back(output_id, std::move(utxo));
        }

        const uint64_t leafdb_count = ReadCompactSize(file);
        leaf_entries.reserve(leafdb_count);
        for (uint64_t i = 0; i < leafdb_count; ++i) {
            if (i % 5000 == 0) {
                interruption_point();
            }
            uint64_t leaf_index{0};
            file >> leaf_index;
            leaf_entries.emplace_back(leaf_index, ReadBytes(file));
        }
    } catch (const std::ios_base::failure&) {
        return util::Error{Untranslated("Truncated MWEB snapshot UTXO or LeafDB data")};
    }

    std::vector<uint8_t> o_dat;
    std::vector<uint8_t> leaf_dat;
    std::vector<uint8_t> prun_dat;
    try {
        const uint64_t num_txos{header.GetNumTXOs()};
        o_dat = ReadMWEBSnapshotBlob(file, MaxMWEBSnapshotODatBytes(num_txos));
        leaf_dat = ReadMWEBSnapshotBlob(file, MaxMWEBSnapshotLeafDatBytes(num_txos));
        prun_dat = ReadMWEBSnapshotBlob(file, MaxMWEBSnapshotPrunDatBytes(num_txos));
    } catch (const std::ios_base::failure&) {
        return util::Error{Untranslated("Truncated MWEB snapshot PMMR file data")};
    }

    const uint256 mweb_hash = ComputeMWEBSnapshotHash(
        header, mmr_info, utxos, leaf_entries, o_dat, leaf_dat, prun_dat);
    // Embedded content hash is mandatory (null would skip integrity checks).
    if (mweb_hash_expected.IsNull()) {
        return util::Error{Untranslated("MWEB snapshot section is missing a required content hash")};
    }
    if (mweb_hash != mweb_hash_expected) {
        return util::Error{Untranslated(strprintf(
            "Bad MWEB snapshot content hash: expected %s, got %s",
            mweb_hash_expected.ToString(), mweb_hash.ToString()))};
    }

    if (auto binding = ValidateMWEBSnapshotCoinLeafsetBinding(header, utxos, leaf_entries, leaf_dat); !binding) {
        return util::Error{util::ErrorString(binding)};
    }
    if (auto pmmr_bind = ValidateMWEBSnapshotLeafPMMRBinding(leaf_entries, o_dat, prun_dat); !pmmr_bind) {
        return util::Error{util::ErrorString(pmmr_bind)};
    }

    {
        CoinDB coin_db(&mweb_db, nullptr);
        std::vector<UTXO::CPtr> utxo_ptrs;
        utxo_ptrs.reserve(utxos.size());
        for (const auto& [output_id, utxo] : utxos) {
            if (output_id != utxo.GetOutputID()) {
                return util::Error{Untranslated(strprintf(
                    "MWEB snapshot UTXO key mismatch for output %s", output_id.ToHex()))};
            }
            utxo_ptrs.push_back(std::make_shared<UTXO>(utxo));
        }
        if (!utxo_ptrs.empty()) {
            coin_db.AddUTXOs(utxo_ptrs);
        }
    }

    {
        auto batch = mweb_db.CreateBatch();
        LeafDB leaf_db('O', &mweb_db, batch.get());
        if (!leaf_entries.empty()) {
            std::vector<mmr::Leaf> leaves;
            leaves.reserve(leaf_entries.size());
            for (const auto& [leaf_index, leaf_data] : leaf_entries) {
                leaves.push_back(mmr::Leaf::Create(mmr::LeafIndex::At(leaf_index), leaf_data));
            }
            leaf_db.Add(leaves);
        }
        batch->Commit();
    }

    MMRInfoDB(&mweb_db, nullptr).Save(mmr_info);

    const uint32_t file_index = mmr_info.index;
    const uint32_t compact_index = mmr_info.compact_index;
    WriteFileBytes(PMMR::GetPath(chainstate_dir, 'O', file_index), o_dat);
    WriteFileBytes(LeafSet::GetPath(chainstate_dir, file_index), leaf_dat);
    WriteFileBytes(PruneList::GetPath(chainstate_dir, compact_index), prun_dat);

    return MWEBSnapshotLoadStats{
        .header = header,
        .coins_loaded = utxos.size(),
        .leafdb_entries_loaded = leaf_entries.size(),
        .mweb_hash = mweb_hash,
    };
}

util::Result<bool> DetectMWEBSnapshotSection(AutoFile& coins_file, uint64_t coins_count)
{
    try {
        std::array<uint8_t, 5> magic;
        coins_file >> magic;
        if (magic != MWEB_SNAPSHOT_MAGIC_BYTES) {
            return util::Error{Untranslated(strprintf(
                "Bad snapshot - unexpected trailing data after deserializing %d coins",
                coins_count))};
        }
        return true;
    } catch (const std::ios_base::failure&) {
        // EOF after coins — no MWEB section.
        return false;
    }
}

util::Result<void> CheckMWEBSnapshotSectionExpected(bool mweb_active_at_base, bool has_mweb_section, int base_height)
{
    if (mweb_active_at_base && !has_mweb_section) {
        return util::Error{Untranslated(strprintf(
            "MWEB is active at height %d but snapshot file contains no MWEB chainstate section",
            base_height))};
    }
    if (!mweb_active_at_base && has_mweb_section) {
        return util::Error{Untranslated("Snapshot contains an MWEB section but MWEB is not active at the base height")};
    }
    return {};
}

util::Result<void> CheckMWEBSnapshotLoadPin(
    bool mweb_active_at_base,
    const std::optional<MWEBSnapshotLoadStats>& load_stats,
    const std::optional<AssumeutxoHash>& mweb_hash_serialized,
    int base_height)
{
    if (mweb_active_at_base) {
        if (!load_stats) {
            return util::Error{Untranslated(strprintf(
                "MWEB is active at height %d but no MWEB chainstate was loaded from the snapshot",
                base_height))};
        }
        if (!mweb_hash_serialized.has_value() ||
            *mweb_hash_serialized == AssumeutxoHash{uint256{}}) {
            return util::Error{Untranslated(strprintf(
                "MWEB is active at height %d but assumeutxo parameters lack a required mweb_hash_serialized",
                base_height))};
        }
        if (AssumeutxoHash{load_stats->mweb_hash} != *mweb_hash_serialized) {
            return util::Error{Untranslated(strprintf(
                "Bad MWEB snapshot content hash: expected %s, got %s",
                mweb_hash_serialized->ToString(), load_stats->mweb_hash.ToString()))};
        }
    } else if (load_stats) {
        return util::Error{Untranslated("Snapshot contains MWEB chainstate but MWEB is not active at the base height")};
    }
    return {};
}

} // namespace node
