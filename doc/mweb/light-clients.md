# Light Clients

Since addresses are not stored on MWEB outputs, identifying coins belonging to a wallet is no longer as simple as sharing a [bloom filter](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki) with a full node, and letting them check for outputs that _probabilistically_ belong to the wallet.

There are 2 ways that existing light clients identify coins belonging to a wallet:

## 1. Server-Side Filtering

[BIP37 - Bloom Filters](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki): Light wallets build a bloom filter for a list of addresses belonging to them, and share it with a full node. That full node then does the work of checking for outputs that _probabilistically_ belong to the wallet.

#### MWEB Equivalent

Since addresses are not stored on MWEB outputs, we cannot identify a wallet's transactions using server-side filtering through probabilistic data structures like bloom filters. The only server-side filtering currently supported for MWEB is filtering using knowledge of private view keys. Light wallets would share their private view keys with a full node, which would then churn through all outputs to find any belonging to the wallet. Unfortunately, this is not a probabilistic process, so full nodes will know with 100% certainty outputs belong to the wallet. To make matters worse, the node will also learn the _value_ of the wallet's outputs. This method is ideal for those who want to use MWEB from a mobile wallet connected to _their own_ full node on a desktop or server, but due to the weakened privacy, you should avoid using this method when connected to untrusted nodes.

## 2. Client-Side Filtering

[BIP157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki): The reverse, where full nodes build a compact filter for each block, and light wallets use those filters to identify blocks that may contain the wallet's transactions.

#### MWEB Equivalent

For those who don't have a trusted full node to connect to, we could use something similar to client side block filtering. More precisely, we could perform client side _output_ filtering. Though no method has yet been designed for building filters as compact as those defined in [BIP158 - Compact Block Filters for Light Clients](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki), nodes can provide light clients with _compact_ MWEB outputs, allowing them to avoid downloading the large rangeproofs associated to each output. In fact, we can be even more data efficient, and download only outputs that are verifiably unspent. Following the process defined in [LIP-0006](https://github.com/DavidBurkett/lips/blob/LIP0006/LIP-0006.mediawiki), light clients can download and check all UTXOs from multiple nodes _in parallel_, avoiding the privacy and verifiability shortcomings of the server-side filtering approaches.
## Serve policy (DoS controls)

LIP-0006 message formats match Litecoin. This node adds **availability controls** around historical serve so peers cannot cheaply exhaust queues, credits, or `cs_main`. Wire compatibility for honest clients is preserved; some invalid or zero-work requests are rejected earlier than on Litecoin.

Implementation: `src/node/mweb_serve.cpp` (and related serve types/coordinator/cache).

### Connection resource allowance

Each new connection starts with a fresh credit bucket at the configured
`-mwebserveburst` allowance (default 50,000). Its previous connection history, if
any, does not affect that allowance. Credits and the credit-refusal counter belong
to the connection; neither is remembered by address or transferred on reconnect.
Credits replenish over time, up to the configured allowance.

Credits estimate the cost of admitting MWEB serving work; they do not reserve an
exact amount of CPU time or network bytes. Per-connection and global queue limits,
budgeted work scheduling, and outbound bandwidth limits provide additional
resource controls.

If a request costs more than the connection's available credits, the node silently
discards it. It sends no rejection, error, `notfound`, or empty response for that
refusal, deducts no credits, and does not queue the request for later retry. The
debug log calls this a **credit denial**; that is an internal admission decision,
not a P2P response. A single refusal normally leaves the connection open, and
unrelated traffic such as ping/pong can continue. The client must apply its own
response deadline and retry policy; refilling credits does not revive the dropped
request.

Repeated unaffordable requests are treated as excessive request traffic. By
default, ten credit refusals within the current 60-second counter window cause
the server to close an ordinary connection. The threshold is configured by
`-mwebservecreditdenydisconnect`; `NoBan` connections are exempt from this closure,
but still face credit admission. The node counts refusals, not whether the client
has processed earlier responses. There is no disconnect timer started by the first
credit refusal.

Disconnecting removes the connection from service and releases its pending serve
jobs during teardown. A new connection gets independent state and a fresh bucket,
whether the previous connection ended normally or after repeated credit refusals.
Shared historical caches, serving coordinators, global queue occupancy, and
outbound bandwidth accounting have their own lifetimes; they do not preserve the
old connection's credit balance. In particular, a cached view can reduce a later
request's charge by avoiding the materialization surcharge.

### Request bounds (`getmwebutxos`)

| Condition | Behavior |
|-----------|----------|
| `num_requested == 0` | Disconnect ordinary peer; **do not enqueue** (no credit spend). **Litecoin divergence:** Litecoin rewinds to the block first, then disconnects on the empty segment. |
| `num_requested > 4096` | Disconnect ordinary peer (same as Litecoin). |
| Unsupported `output_format` | Disconnect ordinary peer (same as Litecoin). |
| `start_index >= mweb_header.GetNumTXOs()` | Disconnect ordinary peer; **do not enqueue**. `GetNumTXOs()` is the output MMR leaf count. **Litecoin divergence:** Litecoin fails only after rewind. |
| `start_index` is a spent leaf | Disconnect ordinary peer after the view is built (same as Litecoin). |
| `start_index > MAX_SIZE` (0x02000000) | The message fails to deserialize and is dropped without a disconnect (same as Litecoin). |

`start_index` is an output MMR leaf index, as in Litecoin and LIP-0006: the first UTXO returned is that leaf, and `mwebutxos` echoes it. Valid clients take unspent leaf indices from `mwebleafset`, request `num_requested ∈ [1, 4096]`, and start the next page at the next unspent leaf after the last one returned.

### Leafset credit cost

`CreditCost` for a leafset job is `max(100, leafset_bytes_hint / 1024)`.

| Path | `leafset_bytes_hint` |
|------|----------------------|
| Historical-cache **hit** | Serialized size of the cached leafset bitset |
| Cache **miss** | `(mweb_header.GetNumTXOs() + 7) / 8` — bit-packed lower bound from the output MMR size. May **overcharge** relative to the eventual unspent bitset; intentional so misses are not stuck at the 100-credit floor while inducing replay/materialization. |

### Header credit cost and outbound budget

`CreditCost` for a header job is `max(100, block_bytes_hint / 1024)` (floor raised from the former flat cost of 10).

| Stage | Behavior |
|-------|----------|
| Depth | No `MAX_MWEB_LEAFSET_DEPTH` limit: the header is read from the stored block, as Litecoin serves it. A pruned (`NODE_NETWORK_LIMITED`) node disconnects ordinary peers asking below its block-serving limit (288 + 2 blocks), as for blocks. Other refusals are silent. Pre-MWEB blocks and missing data match Litecoin. **Litecoin divergence:** this node also refuses during IBD and for blocks off the active chain; Litecoin has no IBD check and serves recently validated stale blocks (`BlockRequestAllowed`). |
| Enqueue | `block_bytes_hint ≈ 4096 + nTx*300 + GetNumTXOs()*64` (conservative wire-size proxy; `CBlockIndex` has no `nSize`) |
| Send | Same outbound-target check as leafset/UTXO: if `GetMaxOutboundTarget() > 0` and bytes left are insufficient (and policy is not `FORCE`), disconnect ordinary peers without sending |
| Lock scope | Resolve `FlatFilePos` under a brief `cs_main` hold; `ReadBlock` disk I/O runs outside that hold |

**Litecoin:** no credit system. Its outbound gate on `mwebheader` is the one for blocks: once the outbound target is reached, ordinary peers asking for a block older than one week (`HISTORICAL_BLOCK_AGE`) are disconnected. This node checks the outbound budget at every depth.

### Historical replay locking

Historical leafset/UTXO serves may rewind a coordinator-local MWEB view from tip to the requested block (`ProcessCoordinatorStep` REPLAY_BACK / REPLAY_FORWARD).

| Stage | Lock scope |
|-------|------------|
| Chain membership | Brief `cs_main` — target, replay tip, and fork must remain on the active chain (fail closed if not). Tip *advance* that keeps those blocks on the active chain is allowed. |
| Preferred rewind | `ReadBlockUndo` (brief lock only for `GetUndoPos`) + MWEB `UndoBlock` on the coordinator-local view — **outside** a long `cs_main` hold |
| Fallback rewind / forward | `ReadBlock` disk I/O outside the long hold; `DisconnectBlock` / `ConnectBlock` under `cs_main` only for the call (those APIs require it) |
| Before send | Snapshot roots must verify against the requested block's `mweb_header` (`VerifyChainstateRoots` / finalize paths); partial views are not sent |

**Litecoin divergence:** Litecoin rewinds under a long `cs_main` hold for the full historical serve. This node shortens that hold for availability while failing closed on reorg/prune races that drop the requested block from the active chain.

### Historical cache warm and miss surcharge

| Control | Behavior |
|---------|----------|
| Window warm | On MWEB `ConnectTip`, `MaybeScheduleWindowWarm` queues a budgeted fill of MWEB heights in `[tip − MAX_MWEB_LEAFSET_DEPTH + 1, tip]` into the existing ring (size capped at depth). Steps run in `ProcessBackgroundWork` (`ProcessOneWindowWarmStep`): tip materialize if needed, then one `ReadBlockUndo` + `UndoBlock` per step. Not a synchronous bootstrap on connect (I3). |
| Miss surcharge | Leafset/UTXO enqueue on historical-cache **miss** adds `MWEB_SERVE_MATERIALIZE_SURCHARGE` (500) on top of existing `CreditCost` (size pricing for leafsets; `num_requested` for UTXOs). Cache **hits** (including tip after publish/warm) do not pay the surcharge. |
| Materialize leafset copy | `MaterializeStep` INIT captures leafset bytes once (`leafset_src_bytes`); LEAFSET_BYTES streams from that buffer (no second `ToDynamicBitSet`). |

**Litecoin:** no historical ring cache, warm, or credit surcharge (fork-only availability controls).

### Other controls

- Historical depth cap for leafset and UTXO requests (`MAX_MWEB_LEAFSET_DEPTH` = 10, as in Litecoin), per-peer / global job queues, token-bucket credits, outbound bandwidth budget, and a historical view cache.
