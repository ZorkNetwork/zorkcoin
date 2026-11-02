# MWEB - Mining Changes

Starting with Litecoin Core release v0.21.2, changes have been made to `getblocktemplate` to support mining blocks with MWEB data. `getblocktemplate` does not yet provide consumers control over which MWEB transactions can be included in a block, and instead builds the MWEB and integrating transactions for you. Though changes do need to be made to pool software, those changes should be very minimal.

### Required Pool Software Changes

1. The "mweb" rule must be supplied to the `getblocktemplate` "rules" array to signal to the node that MWEB is supported.
```
getblocktemplate '{"rules": ["segwit", "mweb"]}'
```

2. In the response, there will be an "mweb" field for all blocks after MWEB activation. If that field exists, then before calling `submitblock` with your solved block, append a byte with value `1` followed by the data from the "mweb" field, to the very end of the serialized block. NOTE: This `<0x01>` is just an  indicator that tells the node that MWEB data follows.

```
<Block><0x01><MWEB>
```

3. If your pool software modifies, reorders, or reprioritizes transactions that it receives from `getblocktemplate`, it must be updated to ensure it never alters the final transaction, known as the HogEx or "Integrating Transaction." The pool also must be careful to not modify or remove any transaction the HogEx depends on (txs with outputs it spends).

The reason for (3) is that the HogEx commits to the MWEB data, and moves the pegged in coins to the HogAddr (address holding all MMEB coins), and sends the pegout coins to the addresses specified by the pegout transactions in the MWEB. Any mismatch in MWEB data and the HogEx transaction would result in the block not passing consensus checks.

### Template size constraint (this fork)

Block templates may use the full consensus MWEB weight (`mw::MAX_BLOCK_WEIGHT` = 200,000). There is **no** Litecoin-style `MAX_MINE_WEIGHT` soft-cap. Templates must also keep the final wire-serialized block (`TX_WITH_WITNESS`, including HogEx and `mweb_block`) ≤ **`MAX_BLOCK_SERIALIZED_SIZE_MINE`** (default equals `MAX_BLOCK_SERIALIZED_SIZE_BIP324` = 16,777,214, so every locally mined block can be sent to BIP324 v2 peers; see [consensus.md — Block Serialized Size](consensus.md#block-serialized-size)). The assembler skips chunks that would exceed that budget and applies stronger input-byte skips under size pressure (~2 MB remaining).
### Block packing algorithm (assembler)

Authoritative selection rules for `BlockAssembler::CreateNewBlock` / `addChunks` (TxGraph feerate chunks; no ascending-input primary loop). Weight/size semantics are summarized in [`weight.md`](weight.md).

1. **Reset** — Reserve L1 coinbase/header weight and a pessimistic serialized baseline (`BLOCK_SERIALIZED_COINBASE_RESERVE`). When MWEB is active, stage an empty HogEx/extension pad via `MWEB::Miner::NewBlock` and add `EstimateSerializedExtensionBytes()` to the running size estimate.

2. **Primary walk** — Repeatedly take the next TxGraph chunk in descending package feerate (`GetBlockBuilderChunk`). Chunks are **atomic**: the whole chunk is included or the whole chunk is skipped (no tearing parent/child). If a transaction fails to stage after the limit checks pass (for example its MWEB part conflicts with one already staged), the transactions added before it are unwound, including their staged MWEB state, and the chunk is skipped.

3. **Min-fee floor** — If the chunk fails `block_min_fee_rate`, stop the primary walk (remaining chunks are lower feerate) and continue to the residual pass.

4. **Fit predicate** (`EvaluateChunkBlockLimits` / `TestChunkBlockLimits`) — Reject if any of:
   - L1 weight or sigops would meet/exceed the configured L1 caps (`>=` vs reduced `block_max_weight`)
   - `nBlockMWEBWeight + chunk_mweb_weight > mw::MAX_BLOCK_WEIGHT` (exact 200k allowed; matches consensus / Litecoin `ExceedsMaximum`)
   - **`staged_mweb_inputs + chunk_mweb_inputs > mw::MAX_NUM_INPUTS`** (hard gate: 50 000 allowed, 50 001 not)
   - pessimistic `EstimateChunkSerializedDelta` would exceed `MAX_BLOCK_SERIALIZED_SIZE_MINE`
   - under size pressure (`remaining_ser < BLOCK_SERIALIZED_SIZE_PRESSURE` = 2 MB): `chunk_mweb_inputs * INPUT_BYTES > remaining_ser`

5. **Skip accounting**
   - **Pure size rejects** (serialized-size or size-pressure input×bytes, with locktime/MWEB rules still OK): `SkipBuilderChunk` and **do not** increment `nConsecutiveFailed`.
   - **Other rejects** (L1/MWEB weight, sigops, input cap, locktime): `SkipBuilderChunk` and increment `nConsecutiveFailed`. If `nConsecutiveFailed > 1000` and (L1 weight near-full **or** `remaining_ser < 2MB`), leave the primary walk for residual.
   - **Failed adds** (a chunk that fit, but one of its transactions failed in `AddToBlock`; see step 6): `SkipBuilderChunk` and increment `nConsecutiveFailed`.

6. **Include** — On fit: `AddToBlock` each entry (updates L1/MWEB/size counters; HogEx pad grows). If every entry was added: `IncludeBuilderChunk`, reset consecutive failures, record package feerate. Otherwise restore the block counters and the staged MWEB state saved before the chunk, and skip it (step 5).

7. **Residual fill** — After the primary walk ends (empty builder, min-fee, or consecutive-failure early exit): take remaining mempool transactions not already in the template, sort **smallest serialized delta first** (tie-break: more MWEB inputs, since spending them shrinks the UTXO set), and keep adding any that still pass `TestChunkBlockLimits` until none fit. In-mempool parents must already be included (no tearing). This is the only place smaller txs may enter after higher-feerate size-skips; primary order stays feerate-first.

8. **Commit** — `AddHogExTransaction`, build coinbase + commitments; exact `GetSerializeSize(TX_WITH_WITNESS)` must be ≤ the BIP324 cap (runtime error if estimates were wrong).

Defense-in-depth: `MWEB::Miner::AddMWEBTransaction` also refuses adds that would push staged inputs above `MAX_NUM_INPUTS`.

Product invariants for packing tests: **NO_GAP** (no equal-or-better eligible leftover that still `WouldFit` all budgets) and binding leftover smaller than one typical eligible grain, **or** every remaining eligible chunk individually too large. Do not loosen NEAR_CAP slack to hide assembler holes.

### GBT `sizelimit` vs wire caps

`getblocktemplate`'s `sizelimit` field remains the legacy L1 value (`MAX_BLOCK_SERIALIZED_SIZE` = 4,000,000). It does **not** report either MWEB-aware wire cap. MWEB extension data is carried in the separate `mweb` blob. The assembler enforces the BIP324 mine gate (16,777,214). `CheckBlock` enforces the larger consensus envelope `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB` (~25.8 MB). See [consensus.md — Block Serialized Size](./consensus.md#block-serialized-size). Pools must not treat `sizelimit` as “max block bytes including MWEB.”

----

### Example

GBT Request:
```
getblocktemplate '{"rules": ["mweb", "segwit"]}'
```

GBT Response:
```
{
  "capabilities": [
    "proposal"
  ],
  "version": 536870912,
  "rules": [
    "csv",
    "!segwit",
    "taproot",
    "mweb"
  ],
  "vbavailable": {
  },
  "vbrequired": 0,
  "previousblockhash": "67eb60f64118fdc667e03894c57c10d57c42709fdc0438bafaaee9a3b2bebf0a",
  "transactions": [
    {
      "data": "0200000000010124d9cf4706e8f141b1be6882916c27b5b31a6cf9206604782186729a3870616202000000171600140dbf1844656d0cc2205f5121622711c5ea43e43afeffffff068ca30100000000001976a9143db645a223d02ecc67738b00377a0b92f90562eb88ac168a0100000000001976a9148f535a63d7e45f98b62042ef6c4be3565c3ba3d388ac5e1b16530400000017a9142bb58162483ff309374d93e62da908851b30b55c87ac930100000000001976a91472c1e50b7c762678092f53f8d99fa555b122531c88ac10a00100000000001976a9147d61748d306421a53ebdf9000c3e855254c2d92388ac32a10100000000001976a914aa96a55e1bbbbfe426639e84f7cb5fbe0a95aeab88ac02473044022044a378e3644a7f4531b253d5e17129394b2e3f68bc710186976bc8aafd28d91602202460c94c0c6d0d973584527454786024da7ab63a5ff07416bbdcf6b18729937e0121022eb2a9786cd2830831b063d0c8b31e26c3aad87cf85eedd8391f57cddf9edebb8d882200",
      "txid": "f695435385ef0d7bd8cc3c1d5c10b9f5f0a2e2d6978a7ed5bf011fd3a4817d03",
      "hash": "5c5211aef305551bcdf90e2f4af78fcc834b51041da8512f9fcb14bcff0b07e7",
      "depends": [
      ],
      "fee": 84371,
      "sigops": 21,
      "weight": 1213
    },
    {
      "data": "020000000008013b41f467a3724144d7875b6c4a1a8792b5d6609385f66295edd304bbd1dfe36e0000000000ffffffff0158913ee998020000225820f78bbf399705e3149d58e19de2e43244f9da33bd5c15b57393ee1a6de61700110000000000",
      "txid": "efe1699039d3a8fa35dd3fad367e446937ab33bd19f9f0252c46d09b29fe733f",
      "hash": "efe1699039d3a8fa35dd3fad367e446937ab33bd19f9f0252c46d09b29fe733f",
      "depends": [
      ],
      "fee": 0,
      "sigops": 0,
      "weight": 376
    }
  ],
  "coinbaseaux": {
  },
  "coinbasevalue": 1250084371,
  "longpollid": "67eb60f64118fdc667e03894c57c10d57c42709fdc0438bafaaee9a3b2bebf0a7329",
  "target": "0000000310500000000000000000000000000000000000000000000000000000",
  "mintime": 1648488758,
  "mutable": [
    "time",
    "transactions",
    "prevblock"
  ],
  "noncerange": "00000000ffffffff",
  "sigoplimit": 80000,
  "sizelimit": 4000000,
  "weightlimit": 4000000,
  "curtime": 1648489088,
  "bits": "1d031050",
  "height": 2273263,
  "default_witness_commitment": "6a24aa21a9ed55644a20af179b1ed32e0d2ad936ae8bf97a52cb442212658aed07b000f0d4eb",
  "mweb": "8089de6f4c6806e610517acedc04c9eb1bbbfc1d44bf89cfc65958e7c9ea13801c2e1d2e00000000000000000000000000000000000000000000000000000000000000007b770abb937280dfb1adb111f3e472312fe55ff679c233e8db42abbdf6ebfa61756a15a4d14f7f19abc3a5d4515a2c071c624327b51f12107ecf53cad49ec16700000000000000000000000000000000000000000000000000000000000000008b4e00000000"
}
```

Then the pool would create work as normal, ignoring the "mweb" field until after a valid block is found. In our example, the pool solves the block, whose traditional serialization is:

```
000000200abfbeb2a3e9aefaba3804dc9f70427cd5107cc59438e067c6fd1841f660eb67920f547825ab14356af63467bda7c44369ef0d99be3b7512ac049fa408a8d0c1abf241625010031d52d3583f03010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2a03efaf22194d696e656420627920416e74506f6f6c20fb000100e0e948ee000003266c00000000000000ffffffff0213c6824a000000001976a914ef94ec7962fc91a3d1df1dd1b274fb02a564eb5f88ac0000000000000000266a24aa21a9ed55644a20af179b1ed32e0d2ad936ae8bf97a52cb442212658aed07b000f0d4eb01200000000000000000000000000000000000000000000000000000000000000000000000000200000000010124d9cf4706e8f141b1be6882916c27b5b31a6cf9206604782186729a3870616202000000171600140dbf1844656d0cc2205f5121622711c5ea43e43afeffffff068ca30100000000001976a9143db645a223d02ecc67738b00377a0b92f90562eb88ac168a0100000000001976a9148f535a63d7e45f98b62042ef6c4be3565c3ba3d388ac5e1b16530400000017a9142bb58162483ff309374d93e62da908851b30b55c87ac930100000000001976a91472c1e50b7c762678092f53f8d99fa555b122531c88ac10a00100000000001976a9147d61748d306421a53ebdf9000c3e855254c2d92388ac32a10100000000001976a914aa96a55e1bbbbfe426639e84f7cb5fbe0a95aeab88ac02473044022044a378e3644a7f4531b253d5e17129394b2e3f68bc710186976bc8aafd28d91602202460c94c0c6d0d973584527454786024da7ab63a5ff07416bbdcf6b18729937e0121022eb2a9786cd2830831b063d0c8b31e26c3aad87cf85eedd8391f57cddf9edebb8d882200020000000008013b41f467a3724144d7875b6c4a1a8792b5d6609385f66295edd304bbd1dfe36e0000000000ffffffff0158913ee998020000225820f78bbf399705e3149d58e19de2e43244f9da33bd5c15b57393ee1a6de61700110000000000
```

The pool then simply appends a `1` and then the value from the "mweb" field when calling `submitblock`:

```
submitblock "000000200abfbeb2a3e9aefaba3804dc9f70427cd5107cc59438e067c6fd1841f660eb67920f547825ab14356af63467bda7c44369ef0d99be3b7512ac049fa408a8d0c1abf241625010031d52d3583f03010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2a03efaf22194d696e656420627920416e74506f6f6c20fb000100e0e948ee000003266c00000000000000ffffffff0213c6824a000000001976a914ef94ec7962fc91a3d1df1dd1b274fb02a564eb5f88ac0000000000000000266a24aa21a9ed55644a20af179b1ed32e0d2ad936ae8bf97a52cb442212658aed07b000f0d4eb01200000000000000000000000000000000000000000000000000000000000000000000000000200000000010124d9cf4706e8f141b1be6882916c27b5b31a6cf9206604782186729a3870616202000000171600140dbf1844656d0cc2205f5121622711c5ea43e43afeffffff068ca30100000000001976a9143db645a223d02ecc67738b00377a0b92f90562eb88ac168a0100000000001976a9148f535a63d7e45f98b62042ef6c4be3565c3ba3d388ac5e1b16530400000017a9142bb58162483ff309374d93e62da908851b30b55c87ac930100000000001976a91472c1e50b7c762678092f53f8d99fa555b122531c88ac10a00100000000001976a9147d61748d306421a53ebdf9000c3e855254c2d92388ac32a10100000000001976a914aa96a55e1bbbbfe426639e84f7cb5fbe0a95aeab88ac02473044022044a378e3644a7f4531b253d5e17129394b2e3f68bc710186976bc8aafd28d91602202460c94c0c6d0d973584527454786024da7ab63a5ff07416bbdcf6b18729937e0121022eb2a9786cd2830831b063d0c8b31e26c3aad87cf85eedd8391f57cddf9edebb8d882200020000000008013b41f467a3724144d7875b6c4a1a8792b5d6609385f66295edd304bbd1dfe36e0000000000ffffffff0158913ee998020000225820f78bbf399705e3149d58e19de2e43244f9da33bd5c15b57393ee1a6de61700110000000000018089de6f4c6806e610517acedc04c9eb1bbbfc1d44bf89cfc65958e7c9ea13801c2e1d2e00000000000000000000000000000000000000000000000000000000000000007b770abb937280dfb1adb111f3e472312fe55ff679c233e8db42abbdf6ebfa61756a15a4d14f7f19abc3a5d4515a2c071c624327b51f12107ecf53cad49ec16700000000000000000000000000000000000000000000000000000000000000008b4e00000000"
```
