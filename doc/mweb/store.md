# Data Storage

In addition to extending the existing `CBlock` and `CTransaction` objects already used in Litecoin, the following data stores are created or modified for MWEB.

### CBlockUndo

After a new block is connected, a `rev<index>.dat` file is created that describes how to remove or "undo" the block from the chain state.
When performing a reorg, the undo file can be processed, which will revert the UTXO set back to the way it was just before the block.

Each spent L1 coin's undo record (`TxInUndoFormatter`) stores `VARINT(nHeight * 2 + fCoinBase + (fPegout ? 2^31 : 0))`, so the peg-out flag survives disconnect. Without it, a peg-out spend returned to the mempool by a reorg would lose its 6-block maturity check. Heights stay below 2^30, so the top bit does not collide with `nHeight * 2`.

To support undo-ing MWEB blocks, we've added a new `mw::BlockUndo` object to `CBlockUndo`, which gets serialized at the end.
This contains the following fields:

* `prev_header` - the MWEB header in the previous block
* `utxos_spent` - vector of `UTXO`s that were spent in the block
* `utxos_added` - vector of coin IDs (hashes) that were added in the block

To revert the block from the chain state, the node adds back the `UTXO`s in `utxos_spent`, removes the matching `UTXO`s in `utxos_added`, and sets `prev_header` as the MWEB chain tip.

NOTE: For backward compatibility, when deserializing a `CBlockUndo`, we first must look up the size of the `CBlockUndo` object.
After deserializing vtxundo (the vector of `CTxUndo`s), if more data remains, assume it's the `mw::BlockUndo` object.
If no more data remains, assume the `CBlockUndo` does not have MWEB data.
An `UnserializeBlockUndo` function was added to handle this.

### UTXOs
##### CoinDB (leveldb)

Litecoin's leveldb instance is used to maintain a UTXO table (prefix: 'U') with `UTXO` objects, consisting of the following data fields:

* output_hash (key) - The hash of the output.
* block_height - The block height the UTXO was included.
* leaf_index - The index of the leaf in the output PMMR.
* output - The full `Output` object, including the rangeproof and owner data.

### PMMRs
##### MMR Info (leveldb)
The node's leveldb instance maintains an MMR Info table (prefix: "M") with `MMRInfo` objects consisting of the following data fields:

* version - A version byte that allows for future schema upgrades.
* index (key) - File number of the PMMR files.
* pruned - Schema field for the hash of the latest header this PMMR represents. This node never updates it on flush (it remains the default null hash).
* compact_index - File number of the PruneList bitset file opened for the PMMR.
* compacted - Optional schema field for a compaction-horizon header hash. This node never sets it (`std::nullopt`); there is no spent-history compaction rewind floor.

Each time the PMMRs are flushed to disk, a new MMRInfo object is written with an incremented `index` and marked as the latest. Litecoin Core 24.x spent-history compaction (which would advance `pruned` / `compacted`) is not implemented here.

##### Leaves (leveldb)
The node's leveldb instance maintains MMR leaf tables (prefix: 'O' for outputs) to store PMMR leaf payloads consisting of the following data fields:

* leaf_index (key) - The zero-based leaf position.
* leaf - The raw leaf data committed to by the PMMR.

Spent leaf payloads are pruned from LeafDB when their creating block falls below the retained-block floor (`node::PruneSpentLeafPayloadsToBlockFloor` in `src/node/mweb_leafdb_sync.cpp`, called from chainstate pruning in `validation.cpp`). Unspent leaves and payloads still needed for retained history are kept. This is LeafDB payload pruning, not PMMR hash-file compaction.

##### MMR Hashes (file)

Stored in file `<prefix><index>.dat` where `<prefix>` refers to 'O' for the output PMMR, and `<index>` is a 6-digit number that matches the `index` value of the latest `MMRInfo` object.
Example: If the latest `MMRInfo` object has an `index` of 123, the matching output PMMR hash file will be named `O000123.dat`.

The hash file stores leaf hashes and parent hashes. Positions may be shifted by the prune list when reading.

##### Leafset (file)

Stored in file `leaf<index>.dat`.

The leafset file consists of a bitset indicating which leaf indices of the output PMMR are unspent.
Example: If the PMMR contains 5 leaves where leaf indices 0, 1, and 2 are spent, but 3 and 4 are unspent, the file will contain a single byte of 00011000 = 0x18.

##### PruneList (file)

Stored in file `prun<index>.dat`, selected by `MMRInfo::compact_index`.

The prunelist file is a bitset used to shift PMMR hash-file positions for nodes omitted from the hash file. Without spent-history compaction, this node keeps an empty or unadvanced prune list in normal operation; the file format remains part of the on-disk layout (including AssumeUTXO snapshots).

## AssumeUTXO MWEB section

When MWEB is active at the snapshot base, `dumptxoutset` appends an MWEB section after the main-chain coins (`WriteMWEBSnapshotSection` in `src/node/mweb_snapshot.cpp`). Load path is `LoadMWEBSnapshotSection`.

### On-disk layout

1. Magic `mweb\xff` (`MWEB_SNAPSHOT_MAGIC_BYTES`) and section version (`MWEB_SNAPSHOT_SECTION_VERSION` = 1).
2. MWEB header, MMR info, content hash, UTXO map, LeafDB entries.
3. Length-prefixed blobs for `o_dat` (output PMMR hashes), `leaf_dat` (leafset), and `prun_dat` (prune list), via `WriteMWEBSnapshotBlob` / `ReadMWEBSnapshotBlob`.

Blob reads use size caps derived from the header’s output MMR size (`MaxMWEBSnapshotODatBytes` / `LeafDat` / `PrunDat`), with an absolute ceiling of `MAX_MWEB_SNAPSHOT_BLOB_BYTES` (16 GiB) so realistic PMMRs can exceed the usual 32 MiB `serialize.h` `MAX_SIZE`.

### Integrity pins

- **Content hash** — `ComputeMWEBSnapshotHash` covers the section payload (excluding magic, version, and the embedded hash field). Load rejects hash mismatch; background AssumeUTXO completion recomputes the same hash from the live chainstate (`ComputeMWEBSnapshotHashFromChainstate`).
- **Coin ↔ leafset binding** — `ValidateMWEBSnapshotCoinLeafsetBinding`: every unspent leafset bit must have a matching UTXO and LeafDB entry (and vice versa).
- **Leaf ↔ PMMR binding** — `ValidateMWEBSnapshotLeafPMMRBinding`: each LeafDB payload’s `Leaf::CalcHash` must match the prune-adjusted hash in `o_dat`. Root checks alone do not catch payload/hash drift.

### Background warm

After snapshot activation, `ScheduleAssumeUTXOWarm` freezes a durable MWEB view and queues stepped materialization into the historical serve cache (`ProcessOneAssumeUTXOWarmStep`). When MWEB is active, `MaybeValidateSnapshot` also recomputes the MWEB content hash as part of background validation.
