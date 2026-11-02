# MWEB Weights & Sizes

MWEB uses a **dual-budget** model: L1 (base + witness) follows Bitcoin Core BIP141; the extension block uses Litecoin's abstract MWEB weight. Never fold serialized extension bytes into L1 BIP141 weight.

Serialized block size uses `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB` = `MAX_BLOCK_SERIALIZED_SIZE_BIP324` (16,777,214) for both consensus and mine/BIP324-v2. Canonical detail: [consensus.md — Block Serialized Size](./consensus.md#block-serialized-size).

## Dual budgets + wire size

| Ledger | What it measures | Cap |
|--------|------------------|-----|
| L1 base + witness | BIP141 weight of the non-MWEB transaction/block bytes, plus explicit peg-in/peg-out L1 side-effects | `MAX_BLOCK_WEIGHT` (4,000,000) |
| MWEB extension | `Weight::Calculate` over inputs, kernels, and outputs | Consensus `mw::MAX_BLOCK_WEIGHT` (200,000) |
| Full block wire bytes (consensus) | `GetSerializeSize(TX_WITH_WITNESS(block))` (L1 + HogEx + `mweb_block`) | `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB` = **16,777,214** |
| Mine / BIP324 v2 send | Same wire serialization for templates and v2 body send | `MAX_BLOCK_SERIALIZED_SIZE_BIP324` = **16,777,214** |

Fees: `GetFee(vsize)` for L1 plus `GetMWEBFee(mweb_weight)` (`BASE_MWEB_FEE` = 100 sat per MWEB weight unit).

## L1: Bitcoin Core BIP141 (pre-MWEB compatible)

For transactions without MWEB data, L1 weight is numerically identical to Core:

```
weight = stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
```

Serializer mapping on this tree (Core has no MWEB flag):

| Core concept | This tree |
|--------------|-----------|
| Stripped (no witness) | `TX_NO_WITNESS_NO_MWEB` |
| Total (with witness) | `TX_NO_MWEB` |

Do **not** use `TX_NO_WITNESS` / `TX_WITH_WITNESS` for L1 weight here — those allow MWEB and would include extension bytes.

- `GetTransactionWeight` / `GetBlockWeight` use the `NO_MWEB` serializers.
- `GetTransactionInputWeight` stays Core-only (no MWEB).
- `GetVirtualTransactionSize` remains L1-only; MWEB is charged via `GetMWEBFee` / `GetTotalFee`.
- MWEB-only transactions without peg-outs therefore have an L1 vsize of 0. As in Litecoin, the block policy fee estimator rates transactions with `CFeeRate(fee, vsize, mweb_weight)`: the MWEB fee is subtracted, and a zero vsize (or a fee below the MWEB fee) gives a 0 fee rate. `CFeeRate::GetFeePerK` reports 0 for an empty fee rate.
- Mempool acceptance reports a different rate. The `effective-feerate` of `testmempoolaccept` and `submitpackage`, the package RBF chunk check, and TRUC's size limits use the adjusted weight (sigop-adjusted L1 weight plus MWEB weight) divided by 4 and rounded up, in place of vsize, for a transaction or package with MWEB weight (`MWEB::MempoolAccept::EffectiveFeeRate` and `AdjustedVSize`). The full fee is rated, MWEB fee included, as the mempool ranks transactions. See [packages.md](./packages.md).
- The `maxfeerate` cap of `sendrawtransaction` and `testmempoolaccept` (`MWEB::MempoolAccept::MaxRawTxFee`) is `maxfeerate × vsize` plus an MWEB allowance: the base MWEB fee plus one output's MWEB fee (1,800 sat, the most a wallet adds to the fee when it drops change). Litecoin allows only the base MWEB fee. Unlike Litecoin, a `maxfeerate` above the default scales the MWEB allowance up in proportion (twice the default allows twice the allowance), so a replacement can pay more without disabling the cap. `maxfeerate=0` still disables it. `submitpackage` applies the same cap to each transaction with MWEB weight (`MWEB::MempoolAccept::ExceedsClientMaxFeeRate`); transactions without MWEB keep upstream's fee-rate check.
- `CheckBlock` `bad-blk-length` and `bad-blk-weight` exclude the extension the same way.
- `CheckBlock` also rejects `bad-blk-serialized-size` when `TX_WITH_WITNESS` size exceeds `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB` (before expensive MWEB crypto).

## L1 peg bridges (Litecoin)

Extension bytes are excluded from BIP141; HogEx L1 costs are charged explicitly:

* Each **peg-out**: `GetSerializeSize(CTxOut) * WITNESS_SCALE_FACTOR`
* Each **peg-in** on a hybrid (non-MWEB-only) tx: `164` weight (`41-byte CTxIn * 4`)
* **MWEB-only** txs: L1 weight = peg-out weight only; kernel fees cover MWEB weight

## MWEB extension parameters (Litecoin libmw)

* MAX_BLOCK_WEIGHT = 200,000 (consensus accept cap; miner templates may use the full cap subject to wire size)
* BASE_OUTPUT_WEIGHT = 17
* STANDARD_OUTPUT_FIELDS_WEIGHT = 1
* STANDARD_OUTPUT_WEIGHT = 18
* BASE_KERNEL_WEIGHT = 2
* STEALTH_EXCESS_WEIGHT = 1
* KERNEL_WITH_STEALTH_WEIGHT = 3
* BYTES_PER_WEIGHT = 42
* INPUT_BYTES = 196
* MAX_NUM_INPUTS = 50,000
* `MAX_BLOCK_BYTES` = 21,800,195 — **theoretical** pessimistic extension-body estimate used to define `MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB`. Mining still respects `MAX_BLOCK_SERIALIZED_SIZE_MINE` (default = `MAX_BLOCK_SERIALIZED_SIZE_BIP324`); see [mining-changes.md](./mining-changes.md#template-size-constraint-this-fork).

## Mempool memory markets (policy, non-consensus)

`-maxmempool` is split into two markets. By default `-maxmempoolmweb=80` gives the MWEB market 80% of the byte budget (L1 gets the rest). A market may borrow space the other is not using; under pressure, the market furthest over its share is trimmed first. Hybrids split their memory between markets. Each market has its own rolling minimum fee: L1's is `mempoolminfee` (and excludes the base MWEB fee when bumping), MWEB's is `mwebminfee` in satoshis per 1,000 MWEB weight above the base MWEB fee. Admission requires both. See `getmempoolinfo` fields `mwebusage`, `maxmempoolmweb`, and `mwebminfee`.

## Relay limits (policy, non-consensus)

Standalone MWEB transactions are relayed and accepted to the mempool only within 1/50 of the consensus block limits:

* `MAX_STANDARD_MWEB_TX_WEIGHT` = 4,000 (`Weight::Calculate` of the transaction body) — reject reason `mweb-txn-oversize`
* `MAX_STANDARD_MWEB_TX_INPUTS` = 1,000 — reject reason `mweb-txn-too-many-inputs` (inputs are weightless, so they are capped by count)

Blocks may still contain larger MWEB transactions up to the consensus limits. See [consensus.md — Standardness](./consensus.md#standardness-non-consensus).

`Weight::Calculate`:

```
ExtraBytesToWeight(n) = ceil(n / 42)

input  = ExtraBytesToWeight(extra_data)
kernel = (stealth ? 3 : 2) + pegout script extras + kernel extras
output = (standard fields ? 18 : 17) + output extras

total = Σ inputs + Σ kernels + Σ outputs
```

## Block assembly

The miner tracks three counters (Litecoin weight semantics + BIP324 size; cluster chunks are a Core 28+ structural adaptation only):

* `nBlockWeight += GetTxWeight()` — L1 BIP141 + peg bridges; must not include extension serialization
* `nBlockMWEBWeight += GetMWEBWeight()` — vs `mw::MAX_BLOCK_WEIGHT` with `>` (no mine soft-cap; exact 200k allowed, matching consensus / Litecoin `ExceedsMaximum`)
* `nBlockSerializedSize` — pessimistic running estimate of final `TX_WITH_WITNESS` wire size vs `MAX_BLOCK_SERIALIZED_SIZE_BIP324` (mine / v2 gate)
* staged MWEB input count — vs `mw::MAX_NUM_INPUTS` (50 000); gated in `TestChunkBlockLimits`

Size accounting:

* Reserves `BLOCK_SERIALIZED_COINBASE_RESERVE` = **4096** bytes for coinbase + witness commitment (conservative pad).
* Incremental L1 stub + MWEB body / HogEx deltas from `MWEB::Miner`; final exact `GetSerializeSize` after HogEx + coinbase.
* Under size pressure (`remaining < 2,000,000` bytes), skip chunks whose estimated MWEB input bytes cannot fit (inputs are weightless but dominate wire size). Feerate-chunk order is preserved — no primary reorder by input count.
* After the feerate walk, a **residual fill** adds any remaining mempool txs that still fit, smallest serialized size first, and at equal size the one spending more MWEB inputs first. Full step-by-step rules: [`mining-changes.md`](mining-changes.md#block-packing-algorithm-assembler).

A typical stealth peg-in with change is ~39 MWEB weight (`18 + 18 + 3`). Templates may include far more than Litecoin's old ~512 soft-cap pegins when weight and wire size allow.

## Litecoin divergence

Litecoin keeps a non-consensus `MAX_MINE_WEIGHT = 20,000` miner soft-cap and treats 25,800,195 bytes (`MAX_BLOCK_SERIALIZED_SIZE + MAX_BLOCK_BYTES`) as the consensus / v1 envelope. This chain deletes the mine soft-cap, allows full `mw::MAX_BLOCK_WEIGHT`, keeps the same consensus envelope in `CheckBlock`, and additionally gates **mining and BIP324 v2 send** at **16,777,214** bytes. Details: [consensus.md — Block Serialized Size](./consensus.md#block-serialized-size).
