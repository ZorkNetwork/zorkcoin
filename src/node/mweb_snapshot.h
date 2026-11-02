// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SNAPSHOT_H
#define BITCOIN_NODE_MWEB_SNAPSHOT_H

#include <mw/mmr/mmr_info.h>
#include <mw/models/block/header.h>
#include <mw/models/tx/utxo.h>
#include <mw/node/coins_view.h>
#include <kernel/chainparams.h>
#include <uint256.h>
#include <util/result.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

class AutoFile;
class CCoinsViewDB;
class FilePath;

namespace node {

//! Magic bytes marking the start of an MWEB section in an AssumeUTXO snapshot file.
static constexpr std::array<uint8_t, 5> MWEB_SNAPSHOT_MAGIC_BYTES = {'m', 'w', 'e', 'b', 0xff};

//! Version of the MWEB snapshot section payload (after magic).
static constexpr uint16_t MWEB_SNAPSHOT_SECTION_VERSION{1};

struct MWEBSnapshotWriteStats {
    uint64_t coins_written{0};
    uint64_t leafdb_entries_written{0};
    uint64_t o_dat_bytes{0};
    uint64_t leaf_dat_bytes{0};
    uint64_t prun_dat_bytes{0};
    uint256 mweb_hash{};
};

struct MWEBSnapshotLoadStats {
    mw::Header header;
    uint64_t coins_loaded{0};
    uint64_t leafdb_entries_loaded{0};
    uint256 mweb_hash{};
};

//! Absolute DoS ceiling for a single MWEB snapshot length-prefixed blob (o_dat / leaf_dat / prun_dat).
static constexpr uint64_t MAX_MWEB_SNAPSHOT_BLOB_BYTES{16ULL << 30}; // 16 GiB

/**
 * Length-prefixed blob I/O for PMMR file dumps in AssumeUTXO MWEB sections.
 * Unlike VectorSerializer / default ReadCompactSize, these allow sizes above
 * serialize.h MAX_SIZE (32 MiB) so realistic output PMMRs can load.
 */
void WriteMWEBSnapshotBlob(AutoFile& file, const std::vector<uint8_t>& bytes);
std::vector<uint8_t> ReadMWEBSnapshotBlob(AutoFile& file, uint64_t max_bytes);

/** Caps for o_dat / leaf_dat / prun_dat derived from header output MMR size. */
uint64_t MaxMWEBSnapshotODatBytes(uint64_t num_txos);
uint64_t MaxMWEBSnapshotLeafDatBytes(uint64_t num_txos);
uint64_t MaxMWEBSnapshotPrunDatBytes(uint64_t num_txos);

/**
 * Compute the MWEB snapshot content hash over canonical MWEB state:
 * header, UTXOs, and LeafDB entries. MMRInfo file numbers and raw PMMR
 * blobs (o_dat / leaf_dat / prun_dat) are local layout and are not hashed.
 * mmr_info and the blob arguments remain so dump/load can pass the full
 * section through one function.
 */
uint256 ComputeMWEBSnapshotHash(
    const mw::Header& header,
    const MMRInfo& mmr_info,
    const std::vector<std::pair<mw::Hash, UTXO>>& utxos,
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& o_dat,
    const std::vector<uint8_t>& leaf_dat,
    const std::vector<uint8_t>& prun_dat);

/**
 * Every unspent leafset bit must have a matching UTXO and LeafDB entry
 * (and vice versa). leaf_dat is the on-disk leafset file (8-byte next-index header).
 */
util::Result<void> ValidateMWEBSnapshotCoinLeafsetBinding(
    const mw::Header& header,
    const std::vector<std::pair<mw::Hash, UTXO>>& utxos,
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& leaf_dat);

/**
 * Bind each LeafDB payload to the output PMMR leaf hash in o_dat.
 * For every (leaf_index, leaf_data), require Leaf::CalcHash == hash stored at the
 * prune-adjusted MMR position. Root checks alone do not catch payload/hash drift.
 */
util::Result<void> ValidateMWEBSnapshotLeafPMMRBinding(
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& leaf_entries,
    const std::vector<uint8_t>& o_dat,
    const std::vector<uint8_t>& prun_dat);

/**
 * Recompute the MWEB snapshot content hash from a live chainstate (same
 * enumeration as dumptxoutset). Used by background AssumeUTXO completion.
 */
util::Result<uint256> ComputeMWEBSnapshotHashFromChainstate(
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const mw::Header& header,
    const mw::ICoinsView* utxo_view,
    const std::function<void()>& interruption_point);

/**
 * Append the MWEB chainstate section to an AssumeUTXO snapshot file.
 * Must be called after all main-chain coins have been written and before the file is closed.
 *
 * MMRInfo.index / compact_index in the written section are always 0 (canonical file
 * layout). Blobs are read from the live chainstate file numbers; load writes O000000.dat.
 *
 * @pre MWEB is active at the snapshot base and the coins DB has an initialized MWEB view.
 */
MWEBSnapshotWriteStats WriteMWEBSnapshotSection(
    AutoFile& file,
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const mw::Header::CPtr& header,
    const mw::ICoinsView* utxo_view,
    const std::function<void()>& interruption_point);

/**
 * Load the MWEB chainstate section from an AssumeUTXO snapshot file.
 * @param file  File positioned immediately after the MWEB section magic bytes.
 */
util::Result<MWEBSnapshotLoadStats> LoadMWEBSnapshotSection(
    AutoFile& file,
    CCoinsViewDB& coins_db,
    const FilePath& chainstate_dir,
    const std::function<void()>& interruption_point);

/**
 * Probe for MWEB section magic after L1 coins. On success, file is positioned
 * after the magic (ready for LoadMWEBSnapshotSection). On absent, file may be at EOF.
 * Returns error on unexpected non-magic trailing bytes.
 * @param coins_count Used only in the unexpected-trailing-data error string.
 */
util::Result<bool> DetectMWEBSnapshotSection(AutoFile& coins_file, uint64_t coins_count);

/** Section presence must match MWEB activation at the snapshot base height. */
util::Result<void> CheckMWEBSnapshotSectionExpected(bool mweb_active_at_base, bool has_mweb_section, int base_height);

/**
 * Require and compare mweb_hash_serialized pin when MWEB is active at base
 * (load-time belt check against loaded content hash).
 */
util::Result<void> CheckMWEBSnapshotLoadPin(
    bool mweb_active_at_base,
    const std::optional<MWEBSnapshotLoadStats>& load_stats,
    const std::optional<AssumeutxoHash>& mweb_hash_serialized,
    int base_height);

} // namespace node

#endif // BITCOIN_NODE_MWEB_SNAPSHOT_H
