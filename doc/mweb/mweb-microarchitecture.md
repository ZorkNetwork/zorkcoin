# MWEB Micro-Architecture Specification

How MWEB is wired into this Bitcoin Core tree, and why it is shaped that way. Protocol rules, formats and limits live in the companion documents; this one covers code placement, call order, ownership and the invariants that keep the port correct and mergeable with `bitcoin/bitcoin`.

| Topic | Document |
|---|---|
| Consensus rules, activation parameters, standardness | [consensus.md](./consensus.md) |
| Object and wire formats | [serialization.md](./serialization.md) |
| Weight, size and relay limits | [weight.md](./weight.md) |
| Kernel features and signatures | [kernels.md](./kernels.md) |
| Block assembly and GBT | [mining-changes.md](./mining-changes.md) |
| Undo data, PMMR files, AssumeUTXO section | [store.md](./store.md), [pmmr.md](./pmmr.md) |
| LIP-0006 serving and DoS controls | [light-clients.md](./light-clients.md) |
| Stealth addresses | [stealth-addresses.md](./stealth-addresses.md) |
| Descriptors and wallet lifecycle | [descriptors.md](./descriptors.md) |
| REST and ZMQ | [rest-and-zmq.md](./rest-and-zmq.md) |

The current source is authoritative. If this document and the code disagree, fix one of them in the same change.

---

## 1. Design approach

MWEB is an **extension module** inside Core's layering, not a second node. Every long-lived Core fork pays a conflict tax on upstream merges; the goal is to concentrate that tax in a small, stable set of call sites rather than interleaving MWEB logic through large Core functions.

1. **Algorithms live in dedicated trees** (`src/libmw`, `src/mweb`, `src/node/mweb_*`, `src/wallet/mweb_*`, `src/script/mweb_descriptor.*`) that upstream never edits.
2. **Core files get thin call-outs**: one line into a facade at a fixed point in Core's existing control flow, with a `// MWEB:` comment naming the function, phase and facade.
3. **State lives in sidecars**: Core structs hold one MWEB member (`Peer::m_mweb`, `CTxMemPool::m_mweb`), not scattered fields. Upstream reshuffles the struct; the port re-attaches one line.
4. **Composition over inheritance** into Core classes (wallet keystore adapter, assembler-owned miner).
5. **Foundational seams are accepted tax**, modelled on SegWit: fields on `CTransaction`/`CBlock`, serialization params, service and inventory flags, a versionbits deployment. Do not pimpl them for diff size; serialization clarity and performance win.
6. **Distinct phases stay distinct.** If two checks in one Core function run at different times or answer different questions, they stay two call sites. Never merge phases to shrink line counts.

Lessons this draws on: `libbitcoinkernel` extraction (re-entanglement should be mechanically detectable), Core's subtree discipline for third-party code (`libmw` is treated the same way), Elements' layered feature stacks (consensus → node → wallet → RPC), and Inquisition's centralisation of the few files every soft fork must touch.

**Do not:**

- Copy Core mempool, miner or selection algorithms "with MWEB twists". Wrap or extend them instead.
- Hide MWEB behind `#ifdef`. Hooks are always compiled and are no-ops before activation or with a null engine.
- Expect `libmw` isolation alone to give mergeability; node and wallet glue is where upstream churn lands.
- Invent opaque hook or ticket IDs in comments or docs. Core does not use them.

---

## 2. Package layout

| Path | Responsibility |
|---|---|
| `src/libmw/`, `cmake/libmw.cmake` | Consensus crypto, models, MMR/PMMR, MWEB coins DB, block builder |
| `src/mweb/` | Facades used by Core: `Node`, `MempoolAccept`, `CoinsLifecycle`, `Miner`, `Policy`, `Transact`, `Spend`, `Wallet`, wallet scan, `MWEBMempoolIndex`, models, DB wrapper |
| `src/node/mweb_*` | Peer sidecar, LIP-0006 serve engine/coordinator/budgets, historical view cache, chain scan, leaf DB sync, rollback clone, UTXO enumeration, AssumeUTXO section, P2P message structs |
| `src/wallet/imweb_keystore.h`, `src/wallet/mweb_keychain_util.*` | Keystore interface and keychain helpers |
| `src/script/mweb_descriptor.*` | `mweb(...)` descriptor parsing helpers |
| `src/test/mweb_*`, `src/wallet/test/mweb_*`, `src/test/fuzz/mweb_*`, `src/libmw/test/`, `test/functional/mweb_*` | Tests |
| `contrib/mweb/` | Hotspot token guard (§12) |

Core host files receive includes, foundational fields and thin call-outs only.

---

## 3. Foundational seams

| Core pattern | MWEB analogue | Where |
|---|---|---|
| `TX_NO_WITNESS` / `TransactionSerParams` | `allow_mweb`; `TX_NO_MWEB`, `TX_NO_WITNESS_NO_MWEB` | `primitives/transaction.h` |
| Witness fields on tx | `mweb_tx`, `m_hogEx`; `HasMWEBTx()`, `IsMWEBOnly()`; `CTxInput`/`CTxOutput` over `COutPoint` or `mw::Hash` | `primitives/transaction.h` |
| Witness block data | `CBlock::mweb_block`, `GetHogEx()`; `MwebAllowedInBlockSerialization` is the **single** block serialization gate, also used by `blockencodings.h` | `primitives/block.h` |
| `NODE_WITNESS`, `MSG_WITNESS_FLAG` | `NODE_MWEB`, `NODE_MWEB_LIGHT_CLIENT`, `MSG_MWEB_FLAG` composites | `protocol.h` |
| BIP9 `DeploymentPos` | `DEPLOYMENT_MWEB`, **append-only** in the enum | `consensus/params.h` |
| GBT `segwit` rule | GBT `mweb` rule | `rpc/mining.cpp` (§11) |
| Default-off `CCoinsView` virtuals | `GetMWEBView()` / `GetMWEBCoin()`; `CCoinsViewCache` owns the concrete `mweb_view` | `coins.h` |

`HasMWEBTx()` and `IsMWEBOnly()` have very high fan-out; treat their semantics as frozen. Per-network parameters (deployment, HRP, frozen output IDs, grandfather fields, AssumeUTXO `mweb_hash_serialized`) are in `kernel/chainparams.*`; values are listed in [consensus.md](./consensus.md).

---

## 4. Facades

### `MWEB::Node` (`src/mweb/mweb_node.h`)

| Method | Called from | Role |
|---|---|---|
| `CheckTransaction` | `MemPoolAccept::PreChecks` only | Peg-in alignment + `Transaction::ValidateStructure()`. **No batch crypto** |
| `VerifyTransactionCrypto` | Both mempool accept paths (§5.3) | `Transaction::VerifyCrypto()`; rejects `TX_WITNESS_MUTATED` / `bad-mweb-txn` |
| `CheckBlock` | `CheckBlock` | Context-free extension checks |
| `ContextualCheckBlock` | `ContextualCheckBlock`, `ConnectBlock`, `RollforwardBlock` | Activation, HogEx and peg matching, full block validation |
| `CheckInputMetadataBinding` / `AllowInputMetadataMismatch` | `ConnectBlock` | Input ↔ UTXO pubkey binding, honouring the single grandfathered block |
| `ConnectBlock` | `ConnectBlock`, `RollforwardBlock` | Apply extension state and undo |
| `ApplyBlockIndexMetadata` | `ConnectBlock` | Persist `BLOCK_HAVE_MWEB`, header, `hogex_hash`, `mweb_amount` |
| `DisconnectExtension` | `DisconnectBlock` | Undo on the existing MWEB cache view |
| `VerifyChainstateRoots` | Snapshot load, serve, historical cache | PMMR roots vs header |
| `IsPunishableCompactBlockReject` | `MaybePunishNodeForBlock` | MWEB reject reasons that still discourage a compact-block peer (§10) |

Binding is shared so `ContextualCheckBlock`, `ConnectBlock` and libmw's `ApplyBlockChanges` all honour the same grandfather exception. Do not add an unconditional pubkey check that bypasses it.

### Other facades

| Facade | Role |
|---|---|
| `MWEB::MempoolAccept` | `PreChecks` helpers: pre-activation reject, loose HogEx reject, non-final attached reject (`bad-txns-mweb-not-final`), MWEB input existence / already-known, keep mempool backend |
| `MWEB::CoinsLifecycle` | MWEB view attach, the two lifecycle rewraps, storage-file removal (§7) |
| `MWEB::Policy` | MWEB part of `IsStandardTx`; relay weight and input limits (`CheckWeight`); `HasUncommittedMWEBPayload` for transaction download (§10) |
| `MWEB::Miner` | Owned by `BlockAssembler` (`std::unique_ptr`); per-template `NewBlock` → `AddMWEBTransaction` → `AddHogExTransaction`; `CheckChunkFit` and size estimators |
| `MWEB::Transact`, `MWEB::Spend`, `MWEB::Wallet` | Wallet tx building, funding/peg-out/fee convergence, scanning |
| `node::MWEBServeEngine`, `node::MWEBHistoricalViewCache`, `node::GetMWEBServeCoordinator()` | LIP-0006 serving and historical views |
| `node::mweb_snapshot` | AssumeUTXO section detect / expect / load / pin / recompute |

---

## 5. Mempool admission ordering

### 5.1 Why it differs from Litecoin

Litecoin runs full MWEB crypto (Schnorr and Bulletproof batch verify, kernel and stealth sums) in `MWEB::Node::CheckTransaction` at the top of `PreChecks`, treating all context-free work as "early". That is coherent for dependencies but wrong for fail-fast DoS resistance: a peer could send unique MWEB transactions spending **nonexistent** outputs with unique invalid proofs and force batch verification (and this node's 64 MiB bulletproof/Schnorr scratch churn; Litecoin uses 256 MiB) before the missing-input reject.

This port follows Core's L1 model instead: cheap checks first, expensive crypto beside `PolicyScriptChecks`. The structure/crypto split is in libmw (`ValidateStructure` / `VerifyCrypto`); `Transaction::Validate()` still runs both and remains the block-path entry.

Compatibility with Litecoin: the acceptance set for valid transactions is identical, and invalid crypto is still rejected before admission. Some invalid transactions fail with a different reason or at an earlier stage (for example `bad-txns-inputs-missingorspent` before `bad-mweb-txn`). This is policy only; block validation is unchanged.

### 5.2 `PreChecks` order

`MemPoolAccept::PreChecks` (`src/validation.cpp`), MWEB-relevant steps in order:

| Step | Check | Notes |
|---|---|---|
| A | L1 `CheckTransaction` | |
| B | `MempoolAccept::RejectBeforeActivation` | `mweb-before-activation` |
| B2 | `MWEB::Policy::CheckWeight` when `require_standard` | Relay limits, the same values as Litecoin and 1/50 of the consensus limits: ≤ 1,000 MWEB inputs (`mweb-txn-too-many-inputs`), ≤ 4,000 MWEB weight (`mweb-txn-oversize`). Runs before any MWEB verification |
| C | `Node::CheckTransaction` (if active) | Structure + peg-in alignment |
| D | Coinbase reject | |
| E | `MempoolAccept::RejectLooseHogEx` | |
| E2 | `MempoolAccept::RejectNonFinalAttached` | `bad-txns-mweb-not-final` (sticky `HadAttachedMWEB` after `Finalized()` drop; not cached as a recent reject via `HasUncommittedMWEBPayload`) |
| F | `IsStandardTx` incl. `MWEB::Policy::IsStandardTx` | |
| G | Min non-witness size, skipped for `IsMWEBOnly()` | |
| H | `CheckFinalTxAtTip` | Includes kernel lock height |
| I | Exists by wtxid / txid | |
| J | Conflicts: L1 `GetConflictTx`, MWEB `GetMWEBConflictTx` | |
| K | Input existence: L1 `HaveCoin`, MWEB `MempoolAccept::CheckMWEBInputExists` | **Primary DoS gate before crypto** |
| L | Keep mempool backend when `HasMWEBTx()` (`KeepMempoolBackend`) | MWEB UTXOs are not in `cacheCoins` |
| M | BIP68, `Consensus::CheckTxInputs`, input/witness standardness, sigops | `CheckTxInputs` covers frozen IDs, metadata, fees |
| N | Cache `Workspace::m_mweb_weight` | |
| O | Non-package `CheckFeeRate(vsize, mweb_weight, fees)` | Kernel fee is unauthenticated until crypto |

Conflict lookup (J) and input existence (K) are separate questions and stay separate call sites.

### 5.3 Crypto placement

| Path | Placement |
|---|---|
| Single tx (`AcceptSingleTransactionInternal`) | `VerifyTransactionCrypto` immediately before `PolicyScriptChecks`; therefore before `ConsensusScriptChecks`, `FinalizeSubpackage` and `test_accept` success |
| Package (`AcceptMultipleTransactionsInternal`) | All `PreChecks` first; package aggregate `CheckFeeRate` (sum of `m_mweb_weight`) as its own step; then per workspace `VerifyTransactionCrypto` before each `PolicyScriptChecks`; therefore before the `test_accept` return and before `SubmitPackage` |

Crypto must not be bound only to `ConsensusScriptChecks`: on the package path `SubmitPackage` runs `FinalizeSubpackage` before its `ConsensusScriptChecks` loop, so unverified MWEB transactions would be admitted.

### 5.4 Invariants

1. No MWEB transaction reaches `FinalizeSubpackage` without a successful `VerifyTransactionCrypto`.
2. `PreChecks` success never implies MWEB signatures or rangeproofs were verified; `Node::CheckTransaction` stays cheap.
3. The package `PreChecks` loop stays free of MWEB crypto.
4. Crypto runs in the `PolicyScriptChecks` phase on both paths; the single-tx and package sites are not collapsed into one helper that changes when they run.
5. Package `test_accept` cannot report success for crypto-invalid MWEB transactions.
6. `bypass_limits` (reorg re-add) does not skip crypto.
7. Fee-before-crypto is not the DoS fix; input existence is.
8. Intra-package MWEB coins come from `PackageAddTransaction`, which stages MWEB outputs in `m_temp_added_mweb`; `GetMWEBCoin` checks them first, and `Reset()` clears them, so a failed or `test_accept` package leaves none behind (see [packages.md](./packages.md)).
9. Block-path crypto ordering is a separate threat model; do not change it in the same change as mempool ordering.

Residual risk: an attacker owning a real MWEB UTXO can still force crypto per unique invalid spend. On nodes enforcing standardness, the relay limits of step B2 (see [weight.md](./weight.md)) bound each attempt to about 2% of a block's worth of verification; with `-acceptnonstdtxn` only `Weight::ExceedsMaximum` applies.

### 5.5 Tests

| Test | Coverage |
|---|---|
| `src/test/mweb_mempool_order_tests.cpp` | Missing input skips batch verify; invalid crypto after inputs runs it; package `test_accept` rejects invalid crypto; `CheckTransaction` never batch-verifies; relay limits reject before any MWEB check |
| `src/test/mweb_package_tests.cpp` | Package parents and children linked by MWEB outputs; failed and `test_accept` packages discard their staged MWEB coins |
| `src/test/mweb_reorg_mempool_tests.cpp` | Reorg re-add in dependency order (Litecoin 24.x `reorg_*` cases): same-block MWEB chains in either kernel order, hybrids with L1 and MWEB children, cache misses |
| `src/test/mweb_validation_tests.cpp` | Peg-in and structure cases through the facades |
| `test/functional/mweb_mempool_order.py` | End-to-end ordering |
| `src/test/util/mweb_crypto_counters.h` | Test-only Schnorr/Bulletproof batch-verify counters |

Do not change reject-reason expectations in these tests to make an ordering change pass.

---

## 6. Block validation and chainstate

- **`CheckBlock`:** mined `vtx` entries must not carry `mweb_tx`. Txids do not commit to it, so `MWEB::Node::CheckBlock` rejects it as `BLOCK_MUTATED` right after the merkle root check, before the size, transaction and sigop rules that would count it. Then L1 size with `TX_NO_WITNESS_NO_MWEB`, and full wire size against `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB`, before any MWEB crypto.
- **`ContextualCheckBlock`:** computes activation now and at `pindexPrev`, supplies the UTXO view, calls `MWEB::Node::ContextualCheckBlock`. The HogEx marker and the MWEB body are not committed by the block hash, so inside the facade the checks that read them run in this order (do not reorder):
  1. HogEx presence and placement (`hogex-missing`, `bad-hogex-position`) as `BLOCK_MUTATED`.
  2. No peg-in outputs in the coinbase or HogEx (`bad-tx-unexpected-pegin`).
  3. HogAddr, MWEB header hash and MWEB height.
  4. `mw::Block::HasValidKernelMMR()`: the kernels must match the HogEx-committed kernel root (`bad-blk-mweb`, `BLOCK_MUTATED`).
  5. Canonical peg-out and extra-data feature rules (`bad-mweb-empty-pegout`, `bad-mweb-empty-extradata`), reported as `BLOCK_MUTATED` because empty feature fields have alternate encodings that share a kernel MMR leaf.
  6. Peg-in matching, then full body validation (`ValidateMWEBBlock`).
- **`ConnectBlock`:** for every block, after the L1 input and script checks and before any MWEB state changes, re-runs `MWEB::Node::ContextualCheckBlock` against the parent's MWEB view, because a body reloaded from disk or swapped for another body with the same hash never went through `AcceptBlock`; this also catches a stripped body (`mweb-missing`) or a stray HogEx marker. Then, for blocks with an MWEB body, `CheckInputMetadataBinding` (grandfather-aware), `MWEB::Node::ConnectBlock` and `ApplyBlockIndexMetadata`. No `RefreshMWEBCache` here.
- **`DisconnectBlock`:** `MWEB::Node::DisconnectExtension` applies `mw::BlockUndo` on the existing cache view; never rewrap during a multi-block undo.
- **`DisconnectTip`:** for each kernel leaving the tip, `GetCachedMWEBTxByKernel` restores the full transaction (with `mweb_tx`) into the disconnect pool, because `block.vtx` holds only stripped stubs. These are queued in kernel-ID order after the block's L1 transactions, and the stub of each restored hybrid (same txid) is skipped, so `MaybeUpdateMempoolForReorg` re-adds the queue in dependency order: every queued parent, found through L1 prevouts or MWEB output IDs, before its children (as Litecoin 24.x does).
- **`ConnectTip`:** before `ConnectBlock`, `RefreshMWEBCache` on the reused single-block connect view, because the MWEB layer built at its last reset copied the MWEB header of a tip that `DisconnectTip` may since have rewound (§7). After `view.Flush()` on the active (non-historical) chainstate, in this order: historical cache `Publish` → `PruneToActiveChain` → serve coordinator `CancelNotOnActiveChain` → `PruneCompleted` → `MaybeScheduleWindowWarm` (skipped during IBD). Then mempool removal in this order: `removeMWEBConflictsForBlock` (while the block's mined parents are still in the mempool), `removeForBlock`, then `removeForMWEBKernels`, since MWEB transactions are not in `block.vtx` (§8).
- **`ConnectTip` failure:** any `BLOCK_MUTATED` result discards the stored body (`DiscardFailedConnectBlockData`), so the honest body with the same hash can be downloaded and connected later. This includes `mweb-connect-failed` with `BLOCK_SUMS`, since MWEB input commitments are not committed by the block hash. The block keeps its validated transaction metadata (`nTx`, `m_chain_tx_count`, validity) and is marked `BLOCK_DISCARDED_MUTATED_DATA`, so already-downloaded descendants stay linked and connect when the honest body arrives, also after a restart. `AcceptBlock` accepts that body even when unrequested, and `ReceivedBlockTransactions` clears the flag. Litecoin Core `4dd6aeeb97`.
- **`NewPoWValidBlock`** (compact-block fast relay and the recent-block caches): `AcceptBlock` fires it only for blocks without an MWEB body. For MWEB blocks, `ConnectTip` fires it after the exact body has connected (outside IBD, and never from the background AssumeUTXO chainstate), because the body is not committed by the block hash and some checks need the MWEB UTXO set. `ProcessNewBlock` holds `g_process_new_block_mutex`, so two same-hash bodies cannot be stored and activated concurrently.
- **`RollforwardBlock`:** uses the same `MWEB::Node::ConnectBlock` contract as live connect, including the `ContextualCheckBlock` re-check, which runs when the block read from disk has an MWEB body or MWEB is active, so a stripped body fails as `mweb-missing`; keep signatures in sync.

---

## 7. Coins lifecycle and AssumeUTXO

The MWEB view (`mw::CoinsViewDB`) is attached once in `InitCoinsDB` (`CoinsLifecycle::AttachView`). `MWEB::DBWrapper` holds a raw `CDBWrapper*`, so anything that replaces the coins DB handle would leave it dangling.

`CCoinsViewCache::RefreshMWEBCache` rebuilds the cache's `mweb_view` from its base and **discards uncommitted MWEB changes**. `SetBackend` calls it implicitly. Explicit use is limited to three sanctioned rewrap sites, the first two in `MWEB::CoinsLifecycle`:

1. **`ResizeCoinsCaches`:** force-flush if MWEB state exists, capture the header, `ResizeCache`, then `RewrapAfterDbResize` on the tip and connect-block caches.
2. **Snapshot load:** `ReleasePlaceholderForSnapshotLoad` → `node::LoadMWEBSnapshotSection` → `AttachVerifiedAfterSnapshotLoad` → `MWEB::Node::VerifyChainstateRoots`.
3. **`ConnectTip`:** on the single-block connect view, before `ConnectBlock` (§6). Multi-block walkers accumulate MWEB undo state in their cache layer, so no other connect or disconnect path may rewrap.

`CCoinsViewDB::BatchWrite` flushes MWEB state into the same final batch that writes `DB_BEST_BLOCK`. When an MWEB view is attached, that batch is written with `fSync=true` before `mweb_cache->Compact()` deletes the previous MMR files, so a crash cannot leave the published tip pointing at deleted files.

Snapshot integrity (section presence iff active at base, leaf ↔ PMMR binding, `mweb_hash_serialized` pin at load and recompute in `MaybeValidateSnapshot`) is specified in [store.md](./store.md). After snapshot activation (and cache rebalance), `ScheduleAssumeUTXOWarm` fills the historical cache from the snapshot base. The `ConnectTip` window warm is never scheduled from the background chainstate.

---

## 8. Mempool index

`MWEBMempoolIndex` (`src/mweb/mweb_mempool_index.h`) is the sidecar held as `CTxMemPool::m_mweb`. It is templated on the entry iterator so it does not depend on the multi-index definition.

| Member | Purpose |
|---|---|
| `m_outputs` (output ID → creating tx) | `GetMWEBOutputTx`, `CCoinsViewMemPool::GetMWEBCoin` |
| `m_next` (spent ID → spending entry) | `GetMWEBConflictTx`, parent/child links, `HasNoInputsOf` |
| `m_recent_by_kernel` (FIFO, `DEFAULT_MEMPOOL_MWEB_CACHE_SIZE` = 1000) | `DisconnectTip` replay; filled only on `BLOCK` or `REORG` removal |

Core mutation paths (`addNewTransaction`, `removeUnchecked`, `ChangeSet::ProcessDependencies`, etc.) call `Add`/`Remove` as one-liners. `CCoinsViewMemPool::GetMWEBCoin` resolves package-staged outputs (`m_temp_added_mweb`), then mempool-spent, then mempool-output, then base. MWEB maps are included in `DynamicMemoryUsage`. Entries cache `mweb_weight` at construction; RPC ancestor/descendant MWEB weights traverse the same sets as Core's L1 totals.

**Block connect.** Kernel IDs do not commit to inputs or outputs, so a mempool transaction counts as mined only if its canonical side is in the block (or it is MWEB-only) **and** every one of its kernels is in the block. `CTxMemPool::removeMWEBConflictsForBlock` removes, as `CONFLICT`, transactions that share a kernel with the block or spend a block MWEB input without being mined, plus in-mempool spenders of any output that does not survive the block (spent, cut through, or never created). Valid children of mined parents stay. `removeForMWEBKernels` then removes the mined transactions one by one as `BLOCK` (filling `m_recent_by_kernel`) together with their conflicts, leaving descendants in place. Both keep Core's `vtx`-only `removeForBlock` untouched.

---

## 9. Miner and compact blocks

**Miner.** `BlockAssembler` owns `MWEB::Miner`; L1 weight and sigops gates stay host-side, and `CheckChunkFit` returns the MWEB-specific verdict (`WeightOrInputs` or `Size`). Selected MWEB transactions are stripped before entering `block.vtx`, and `AddHogExTransaction` runs after selection. `m_last_block_mweb_weight` feeds `getmininginfo`. Packing, size estimation and limits are in [mining-changes.md](./mining-changes.md) and [weight.md](./weight.md).

`mw::BlockBuilder::AddTransaction` (behind `AddMWEBTransaction`) rejects a candidate whose kernel ID is already staged, and keeps running kernel and stealth sums (`KernelSumValidator::SumState` / `StealthSumValidator::SumState`). Each candidate extends them with `ValidateAndAdd`, which checks only that candidate's body, so template building stays linear. A transaction that would put the aggregate sums at the point at infinity is left out of the template, even though `ValidateForTx` accepts a single transaction whose own sums are at infinity, because block validation does not.

**Compact blocks.** Peer-supplied transactions may carry `mweb_tx`; mined `vtx` must not. `StripMWEBExtension` (`src/blockencodings.cpp`) runs at **all four** fill sources: prefilled transactions, mempool matches, `vExtraTxnForCompact` matches, and `blocktxn` missing transactions. `mweb_block` is reattached after `vtx` is filled. A source left unstripped makes a valid block fail `MWEB::Node::CheckBlock`.

---

## 10. Net processing and serving

- `Peer::m_mweb` is a `node::PeerMWEBState`. It holds `m_have_mweb` (from VERSION / `NODE_MWEB`), the serve job queue and the connection's credit bucket/refusal counter. Every new connection initializes a fresh bucket and counter; neither is remembered by address. Unaffordable requests are silently discarded, and repeated credit refusals close ordinary connections at the configured threshold. Teardown releases pending serve jobs. See [Connection resource allowance](light-clients.md#connection-resource-allowance) for the serving contract and client retry implications.
- `PeerManagerImpl` owns `std::unique_ptr<node::MWEBServeEngine>`; the engine sees peers through `MakeMWEBServePeerState`. `net_processing` keeps 1:1 thin wrappers per message and lifecycle event; do not collapse them into one generic dispatcher.
- Compact blocks follow upstream's single BIP 152 version, chosen node-wide: version 3 (with the MWEB block) when the node has `NODE_MWEB`, otherwise version 2. `GetCmpctBlocksVersion()` picks it and `CmpctBlockSerParams()` serializes every `cmpctblock` sent or parsed accordingly; SENDCMPCT accepts only that version, so a Litecoin Core 0.21 peer offering 3, 2 and 1 settles on 3. `CBlockHeaderAndShortTxIDs` prefills the HogEx, when present, since it is never in a mempool.
- `MaybePunishNodeForBlock`: the BIP 152 compact-block exemption for `BLOCK_MUTATED` does not cover MWEB bodies, which the header does not commit to. One call-out, `MWEB::Node::IsPunishableCompactBlockReject(state)`, names the MWEB reject reasons that still discourage a compact-block peer; generic consensus failures keep the exemption.
- Transaction download (`node/txdownloadman_impl.cpp`): `MempoolRejectedTx` and `MempoolRejectedPackage` neither cache a rejection in any recent-rejects filter nor forget the request when `MWEB::Policy::HasUncommittedMWEBPayload(tx)` is true (MWEB transactions, HogEx, and transactions with peg-in outputs). Their txid and wtxid do not commit to the MWEB body or the HogEx marker, so a cached rejection of an invalid variant would censor a valid transaction with the same IDs. The rejected-parents orphan path still caches, because a transaction's L1 parents are committed by its txid.
- `GetFetchFlags` sets `MSG_MWEB_FLAG` when the **peer** can serve MWEB (`CanServeMWEB`) and either there is no specific block or that block is post-activation. Local advertisement of `NODE_MWEB` is deliberately not required (a headers-only AssumeUTXO tip may still be pre-MWEB). The block-download walk has its own early return for peers that cannot serve post-activation, a twin of the witness gate rather than merged into it.
- `GETMWEBUTXOS`, header and leafset requests go through the serve job queue, not the full-block path. `ProcessBackgroundWork` keeps three budgeted steps: AssumeUTXO warm, window warm and per-peer serve drain. Budgets and limits are in [light-clients.md](./light-clients.md).

---

## 11. Wallet, RPC and init

**Wallet.**

- `DescriptorScriptPubKeyMan` composes a `MWEBKeyStoreAdapter` member (`m_mweb_keystore`) implementing `IMWEBKeyStore`, rather than inheriting from it.
- `script/descriptor.cpp` holds the `mweb()` descriptor classes and their `Func("mweb")` parse branch; parsing helpers are in `script/mweb_descriptor.*`. The base `Descriptor` has MWEB virtual methods with neutral defaults (form, account checksum, index, scan and spend keys), so non-MWEB descriptors are unchanged.
- `CreateTransaction` routes L1-only transactions and MWEB-aware ones on separate paths. Funding, peg-out and fee convergence sit behind `MWEB::Spend` and `Transact::AddMWEBTx`, so Core's selection body stays intact.
- `GetBalance` adds MWEB funds in a separate `ListMWEBUnspent` pass (`include_mweb`), not folded into the L1 UTXO sum.
- `ListMWEBUnspent` is the single source of available MWEB coins and skips outputs for which `MWEB::IsFrozenOutput` matches `Consensus::Params::frozen_mweb_output_ids`, so frozen outputs are excluded from balances, `listunspent` and automatic selection. Manual `coin_control` selection of a frozen output fails with an error.
- `LoadMWEBInternalDescriptorRecord` checks imported internal addresses against `keychain->GetStealthAddress(index)`. Do not weaken this check.
- Descriptor forms, accounts, scanning and selection are covered in [descriptors.md](./descriptors.md).

**RPC.**

- **`getblock`:** one header formatter fills both the nested `mweb` object and the legacy `mweb_header` fields.
- **Soft forks:** `SoftForkDescPushBack(..., DEPLOYMENT_MWEB)`.
- **Mempool RPCs:** always return the flat `mwebweight` / `ancestormwebweight` / `descendantmwebweight` fields.
- **`dumptxoutset` and snapshot load:** write and load the MWEB section via `node::mweb_snapshot`.
- **GBT:** the `mweb` rule is handled at four separate sites in `rpc/mining.cpp`:
  1. **Declare** the `mweb` client rule.
  2. **Require** it: reject the call if MWEB is active and the client omitted the rule.
  3. **Echo** the rule into the template.
  4. **Embed** the serialized extension body.

**Init.** `-mwebserve*` options are registered in init and mapped into `PeerManager::Options` in `node/peerman_args.cpp`. Keep the registration, the mapping and the struct fields in sync.

---

## 12. Mergeability measurement

`contrib/mweb/check_hotspot_mweb_tokens.sh` counts `mweb|MWEB|mw::` tokens in the Core hotspot files and fails when a file is denser than `contrib/mweb/hotspot_mweb_baseline.txt`. The hotspot files are `validation.cpp`, `net_processing.cpp`, `txmempool.{h,cpp}`, `node/miner.cpp`, `wallet/{spend,scriptpubkeyman,wallet}.cpp` and `script/descriptor.cpp`. Lower the baseline only after an intentional density drop.

Indicators to track across upstream merges:

- MWEB-attributable diff lines in the hotspot files;
- conflict hunks per merge;
- the ratio of dedicated-tree lines to MWEB lines in Core files;
- the share of hotspot references that are single-line facade calls;
- time from an upstream tag to green tests.

Remaining structural merge tax, by design:

- the foundational seams (§3);
- the MWEB descriptor classes beside `DescriptorImpl` in `descriptor.cpp`;
- the L1 skeleton and `GetTxType`/weight call-outs in `wallet/spend.cpp`.

---

## 13. Maintenance rules

- New Core call site: add a `// MWEB:` comment naming the function, phase and facade, and update the relevant section here.
- Sidecar or facade extractions must not change check order, reject reasons or RPC fields.
- Any change to mempool ordering updates §5 and the `validation.cpp` comments in the same change.
- Keep the commit stack layered: `libmw` → primitives/protocol → coins/consensus → validation/mempool → miner/encodings → net/serve → wallet → RPC/init → tests/docs.

---

## 14. @todo

**Pending Litecoin ports.** Several companion documents already describe these as current behavior. Litecoin commit references are listed with each item.

- @todo **Wallet selection under the relay caps** (`9b5bb289b8`): `MWEB::Policy::CheckWeight` enforces the relay limits in `PreChecks` (§5.2), but wallet selection does not yet cap itself to match (see the selection @todo in [descriptors.md](./descriptors.md)).
- @todo **Scratch-frame leak** (`d7ab03d31c`): the early returns in the secp256k1-zkp bulletproof rangeproof code are fixed in this tree's subtree copy. Send the fix to the subtree's upstream so the next subtree update keeps it.

**Other open items.**

- @todo `bad-blk-serialized-size` is classed `BLOCK_CONSENSUS`, but MWEB body bytes are not committed by the block hash. Confirm that a padded valid block cannot get its hash marked permanently invalid.
- @todo `Schnorr::Verify` uses the `aggsig` module while signing uses `schnorrsig_mw`. Consensus uses only the batch verifier, so this is harmless today; align the two or remove `Verify`.
- @todo `LoggerAPI::Initialize` is never called, so libmw log output is discarded.
- @todo Stealth address decoding: see the @todo item in [stealth-addresses.md](./stealth-addresses.md).
- @todo The hotspot guard (§12) fails today. Files over the +15 tolerance: `validation.cpp` 223 against a baseline of 193, `wallet/spend.cpp` 117 against 87, `wallet/scriptpubkeyman.cpp` 267 against 245, `wallet/wallet.cpp` 261 against 207, and `script/descriptor.cpp` 108 against 60. Most of the growth is code, not comments (`validation.cpp`: 160 code, 51 comment, 12 include lines), so thinning means moving logic behind the `src/mweb` facades. The guard also counts include and comment lines, although its header lists them as allowed. Thin the call sites, or deliberately re-baseline with a justification.
- @todo Functional test docstrings still reference deleted docs (`testing.md`, `wire-size-and-bip324.md`) in:
  - `mweb_multinode_scale.py`
  - `mweb_block_packing.py`
  - `mweb_wallet_spend_scale.py`
  - `test_framework/mweb_density_util.py`
  - `test_framework/mweb_stress_mega_util.py`
