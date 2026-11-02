# MWEB Consensus

## Prerequisites

### Notation

* Let `G` and `H` be independent generators of the elliptic curve group
* `H(α||β||γ)` represents BLAKE3 hash of concatenated serializations
* Scalar multiplication denoted as `a⋅G` where `a` is scalar
* Point addition/subtraction uses standard `+`/`-` operators

### Cryptographic Assumptions

* All elliptic curve operations use secp256k1
* When a BLAKE3 digest is used as a secp256k1 scalar, it is mapped with libmw's `SecretKey::FromHash` (use the digest if it is in `[1, n−1]`; otherwise rehash under `"MWEB hash-to-scalar"` with a counter). Digests are not reduced modulo the curve order. Switch-commitment blinding (`BLIND_SWITCH`) uses SHA256 instead; see [stealth-addresses.md](stealth-addresses.md).

### Glossary
* **PMMR**: Pruned Merkle Mountain Range (data structure for storing UTXOs)
* **TXO**: Transaction Output
* **UTXO**: Unspent Transaction Output
* **HogEx**: MWEB integration transaction

### Transaction Structure

##### Transaction

* <code>x</code> = kernel offset (scalar)
* <code>x'</code> = stealth offset (scalar)

##### Inputs

* <code>F<sub>i</sub></code> = Input features (bitmask)
    * <code>0x01</code> = Additional input key
    * <code>0x02</code> = Extra Data (Indicating additional byte vector to be included in the signature message)
* <code>O<sub>ID</sub></code> = ID of the output being spent
* <code>C<sub>i</sub></code> = Input commitment (<code>C<sub>o</sub></code> of the output being spent)
* <code>K<sub>i</sub></code> = Input stealth public key (if <code>0x01</code> is set in <code>F<sub>i</sub></code>)
* <code>M<sub>i</sub></code> = Additional input message data (if <code>0x02</code> is set in <code>F<sub>i</sub></code>)
* <code>&sigma;</code> = Input signature

##### Kernels

* <code>M</code> = Type, fee, etc.
* <code>E</code> = Kernel excess
* <code>E'</code> = (Optional) Stealth excess
* <code>&psi;</code> = Kernel signature

##### Outputs

* <code>C<sub>o</sub></code> = Output commitment
* <code>K<sub>s</sub></code> = Sender public key
* <code>K<sub>o</sub></code> = Output public key
* <code>K<sub>e</sub></code> = Key exchange public key
* <code>t[0]</code> = View tag
* <code>v'</code> = Encrypted value
* <code>n'</code> = Encrypted nonce
* <code>&pi;</code> = Rangeproof
* <code>&rho;</code> = Output signature


## Activation and Consensus Parameters

* MWEB is deployed through Bitcoin-style BIP9 deployment `DEPLOYMENT_MWEB` (version bit 4), including `min_activation_height`. A failed signalling window ends in `FAILED` (not forced lock-in). Litecoin instead adds a height-based activation mode and forces `LOCKED_IN` on timeout; this chain does not.
* An input that spends an output ID listed in `frozen_mweb_output_ids` is rejected during block validation. On the ConnectBlock / ContextualCheckBlock path used today, that check fails as `BLOCK_MUTATED` (`bad-blk-mweb`) before the unreachable `BLOCK_CONSENSUS` (`frozen-mweb-output-spent`) path in `ConnectBlock`. The frozen list is empty on every network except a synthetic regtest ID used in tests.
* Per-network MWEB consensus parameters (`Consensus::Params`):

| Parameter | Value (all networks) | Requirement relative to MWEB activation |
|---|---|---|
| `mweb_pegout_feature_activation_height` | @todo MWEB Activation +? | **+0 is adequate.** The rule only rejects kernels that set `PEGOUT_FEATURE_BIT` without peg-outs, and no MWEB block exists before activation, so there is no history to grandfather. Any value at or below the MWEB activation height has the same effect. |
| `mweb_extradata_feature_activation_height` | @todo MWEB Activation +? | **+0 is adequate**, for the same reason (rejects kernels that set `EXTRA_DATA_FEATURE_BIT` with empty extra data). |
| `mweb_kernel_lock_height_grandfather` | `0` | Kernel lock heights are enforced in every MWEB block. Litecoin's historical grandfather height (`KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT`) does not apply here. |
| `mweb_input_metadata_grandfather_blockhash` | unset (null) | No block is exempt from the input commitment/pubkey match rule ([UTXO LeafSet](#utxo-leafset)). Litecoin needs one exempt block; this chain has none. |
| `frozen_mweb_output_ids` | empty (regtest: one synthetic test ID) | No output IDs are frozen. Regtest carries a synthetic ID only to exercise the rule. |
| `PEGOUT_MATURITY` | `6` blocks | Fixed constant. |

The two feature-activation heights exist in Litecoin because those rules were soft-forked in after MWEB had been running (Litecoin mainnet: 3,154,440 and 3,172,640). On this chain both rules are intended to be active from the first MWEB block.

## Rules

For kernel-specific rules (feature bits, feature-gated fields, and kernel signature message layout), see [kernels.md](./kernels.md).

#### Identifiers

* The kernel ID (<code>K<sub>ID</sub></code>) is the BLAKE3 hash of the serialized kernel.
  * See [serialization.md](./serialization.md#mweb_kernel) for the kernel serialization format.
* The output ID (<code>O<sub>ID</sub></code>) is the BLAKE3 hash of the output's commitment, both public keys, the hashes of its output message and rangeproof, and its signature. The full rangeproof and output message are not hashed directly.
  * <code>O<sub>ID</sub> = H(C<sub>o</sub>||K<sub>s</sub>||K<sub>o</sub>||H(O<sub>M</sub>)||H(&pi;)||&rho;)</code>
---

#### Transaction Uniqueness

* Output hashes (<code>O<sub>ID</sub></code>) in the UTXO set shall be unique at all times.
* A block shall not contain 2 inputs that spend the same output ID (<code>O<sub>ID</sub></code>).
* A block shall not be included when it contains an output ID (<code>O<sub>ID</sub></code>) which already exists in the UTXO set.
  * Block is still invalid even if it also contains an input with said output ID (<code>O<sub>ID</sub></code>).
* A block shall not contain 2 outputs with the same ID (<code>O<sub>ID</sub></code>).
  * Block is still invalid even if it also contains an input with said output ID (<code>O<sub>ID</sub></code>).
* A block *could* contain an input which spends an output created in the same block, provided the output ID (<code>O<sub>ID</sub></code>) was not already in the UTXO set.
  * To better support payment proofs, the outputs shall still be added to the TXO MMR, but shall be marked as spent.
* A block shall not contain 2 kernels with the same ID (<code>K<sub>ID</sub></code>).
---

#### Ordering

* Inputs in a block shall be in ascending order by output ID (<code>O<sub>ID</sub></code>).
* Outputs in a block shall be in ascending order by output ID (<code>O<sub>ID</sub></code>).
* Kernels in a block shall be ordered by descending supply change (<code>v<sub>pegin</sub> - (v<sub>pegout</sub> + f)</code>), with ties broken by ascending kernel ID (<code>K<sub>ID</sub></code>).
---

#### PMMRs

* After building an MMR with all of the kernels from a block, the root shall match the header's kernel root.
* The number of kernels in a block shall match the header's kernel size.
* After adding all outputs from a block to the end of the output PMMR, the root shall match the header's output root.
* After adding all outputs from a block to the end of the output PMMR, the size shall match the header's output size.
---

#### UTXO LeafSet

* A simple bitset shall be created and maintained to keep track of which TXOs in the output PMMR remain unspent.
* The bit positions shall map 1-to-1 to PMMR leaf indices. A `0` at that bit position means spent, whereas a `1` means unspent.
  * Ex: If byte 0 bit 2 is a `1`, that means TXO at leaf index `2` is unspent. If byte 2 bit 1 is a `0`, the TXO at leaf index `17` has been spent. etc.
* The hash of the serialized UTXO set after applying the transactions in a block shall match the header's UTXO leafset hash.
* Each input spent by a block must reference an existing unspent UTXO entry.
* For each spent input, the input's commitment and output pubkey must exactly match the referenced UTXO. (This closes the Litecoin input-metadata exploit; see `mweb_input_metadata_grandfather_blockhash` above.)
* An input shall not spend an output ID listed in `frozen_mweb_output_ids`.
---

#### Signatures

* Each kernel without a stealth excess (`E'`) shall have a valid signature (&psi;) of <code>H(K<sub>M</sub>)</code> that verifies for the kernel's excess(`E`).
  * See [kernels.md](./kernels.md#signature) for the signature message (<code>K<sub>M</sub></code>) serialization format
* Each kernel with a stealth excess (`E'`) shall have a valid signature (&psi;) of <code>H(K<sub>M</sub>)</code> for key <code>E<sub>agg</sub> = H(E||E')⋅E + E'</code>.
* Each input shall have a valid signature (<code>&sigma;</code>) of <code>I<sub>M</sub></code> for key <code>K<sub>sig</sub></code>
    * If an input stealth pubkey <code>K<sub>i</sub></code> is included (<code>0x01</code> set in <code>F<sub>i</sub></code>), <code>K<sub>sig</sub> = K<sub>i</sub> + H(K<sub>i</sub>||K<sub>o</sub>)⋅K<sub>o</sub></code>. Otherwise, <code>K<sub>sig</sub> = K<sub>o</sub></code>.
    * If extra data <code>M<sub>i</sub></code> is included (<code>0x02</code> set in <code>F<sub>i</sub></code>), <code>I<sub>M</sub> = H(F<sub>i</sub>||O<sub>ID</sub>||M<sub>i</sub>)</code>. Otherwise, <code>I<sub>M</sub> = H(F<sub>i</sub>||O<sub>ID</sub>)</code>.
* Each output shall have a valid signature (<code>&rho;</code>) of <code>H(C<sub>o</sub>||K<sub>s</sub>||K<sub>o</sub>||H(O<sub>M</sub>)||H(&pi;))</code> for the output's sender pubkey (<code>K<sub>s</sub></code>).
  * `output_message` (<code>O<sub>M</sub></code>, also written <code>m</code> in [stealth-addresses.md](stealth-addresses.md)) is the wire serialization of the output message fields only: `features`, and when set, the standard fields (<code>K<sub>e</sub></code>, <code>t</code>, <code>v'</code>, <code>n'</code>) and/or `extra_data`. See [serialization.md](serialization.md#mweb_output). <code>K<sub>o</sub></code> and <code>K<sub>s</sub></code> are **not** part of <code>O<sub>M</sub></code>; they appear separately on the wire (`receiver_pk` / `sender_pk`) and are bound directly by the signature hash above and by <code>O<sub>ID</sub></code>.---

#### Output Public Keys

* Consensus does **not** require <code>K<sub>e</sub></code> or <code>K<sub>o</sub></code> to be valid secp256k1 points. Both are hashed as raw 33-byte strings.
  * An output whose <code>K<sub>o</sub></code> does not parse is unspendable (the input signature key cannot be formed), so such an output is a permanent UTXO-set entry.
  * An output whose <code>K<sub>e</sub></code> does not parse cannot be identified by any wallet.
  * Standardness rejects both cases ([Standardness](#standardness-non-consensus)), and wallets must skip them during scanning ([stealth-addresses.md](stealth-addresses.md#output-identification)).
* **@todo:** Not solved in latest Litecoin either (policy and wallet guard only). A consensus rule requiring <code>K<sub>e</sub></code> and <code>K<sub>o</sub></code> to parse is needed so a miner cannot place malformed outputs in blocks.
---

#### Bulletproofs

* Each output shall be coupled with a bulletproof (<code>&pi;</code>) that proves the commitment is to a value in the range `[0, 2^64)`.
  * One commitment per proof; the proof is a fixed 675 bytes (`RangeProof::SIZE`). `H` is the value generator and `G` the blinding generator.
* Each bulletproof shall commit to the `output_message` (<code>O<sub>M</sub></code>) through its `extra_commit` input: the `extra_commit` bytes are exactly `OutputMessage::Serialized()`. A proof is invalid unless it verifies for <code>C<sub>o</sub></code> under those same bytes.---

#### Kernel Sums

* The sum of all output commitments (<code>C<sub>o</sub></code>) in the UTXO set at a given block height shall equal the sum of all kernel commitments (`E`) plus the `total_kernel_offset*G` (`x*G`) and the `expected_supply*H` (<code>v_total</code>) of the block.
  * <code>&Sigma;C<sub>o</sub> = &Sigma;E + (x⋅G) + (v_total⋅H)</code> where <code>v_total</code> is the total MWEB supply at the block height.
---

#### Stealth Sums

* The sum of all sender pubkeys (<code>K<sub>s</sub></code>) in a block and all input pubkeys (<code>K<sub>i</sub></code>) in the block must equal the sum of all stealth excesses (`E'`) plus `total_stealth_offset*G` (`x'*G`) plus the sum of all output pubkeys (<code>K<sub>o</sub></code>) being spent in the block.
  * <code>&Sigma;K<sub>s</sub> + &Sigma;K<sub>i</sub> = &Sigma;E' + x'⋅G + &Sigma;K<sub>o</sub></code>
  * <code>&Sigma;K<sub>i</sub></code> runs only over inputs that carry <code>K<sub>i</sub></code> (<code>0x01</code> set in <code>F<sub>i</sub></code>); <code>&Sigma;K<sub>o</sub></code> runs over every input.
---

#### Kernel Features

* A kernel that sets `PEGOUT_FEATURE_BIT` shall contain at least one peg-out (reject reason `bad-mweb-empty-pegout`), at block heights ≥ `mweb_pegout_feature_activation_height`.
* A kernel that sets `EXTRA_DATA_FEATURE_BIT` shall contain non-empty extra data (reject reason `bad-mweb-empty-extradata`), at block heights ≥ `mweb_extradata_feature_activation_height`.
* A kernel that sets `HEIGHT_LOCK_FEATURE_BIT` shall not be included in a block whose height is below its lock height (enforced at heights above `mweb_kernel_lock_height_grandfather`, i.e. always on this chain).
* Details: [kernels.md](./kernels.md).
---

#### Pegging-In && Pegging-Out

* Kernels may include an optional pegout, containing the `amount` & a `scriptPubKey` (serialized `CScript`)
  * The `scriptPubKey` for a pegout shall be non-empty.
  * Miners shall include a matching output in a block's `HogEx` transaction with the exact `amount` and `scriptPubKey` for each pegout in the block.
* Kernels may include an optional pegin `amount`
  * Each pegin kernel must have a corresponding pegin output on the canonical side where the value is <code>v<sub>pegin</sub></code>, witness version is 9, and witness program is the kernel ID (<code>K<sub>ID</sub></code>).
  * The extension block peg-in set must exactly match canonical pegins by `(kernel ID, amount)`.
  * Kernel IDs in the canonical block pegin set must be unique.
* The total MWEB supply (<code>v_total</code>) shall increase by the sum of the block's pegins (<code>v<sub>pegin</sub></code>), and decrease by the sum of the block's pegouts (<code>v<sub>pegout</sub></code>) and the sum of all fees (`f`).
  * <code>v_total<sub>new</sub> = v_total<sub>prev</sub> + &Sigma;v<sub>pegin</sub> - (&Sigma;v<sub>pegout</sub> + &Sigma;f)</code>
* Pegged-out coins require `PEGOUT_MATURITY` (6) blocks to mature before they can be spent. The wallet offers them at 6 confirmations, as released Litecoin Core does; their spend is valid in the next block.
---

#### Block Weight

* Outputs shall be counted as having a weight of 17 + 1 (if "standard fields" are included).
  * Plus <code>&lceil;n/42&rceil;</code> for <code>n</code> bytes of output `extra_data`.
* Kernels shall be counted as having a weight of either 2 (without stealth excess) or 3 (with stealth excess).
  * Plus <code>&lceil;n/42&rceil;</code> for each pegout `scriptPubKey` of <code>n</code> bytes.
  * Plus <code>&lceil;n/42&rceil;</code> for <code>n</code> bytes of kernel `extra_data`.
* Inputs shall not contribute toward the block weight except for `extra_data`, which costs <code>&lceil;n/42&rceil;</code> for <code>n</code> bytes.
* Extension blocks shall be capped at a maximum total weight of 200,000 (`mw::MAX_BLOCK_WEIGHT`).
* Extension blocks shall contain at most 50,000 inputs (`mw::MAX_NUM_INPUTS`).
* Formulas and parameters: [weight.md](./weight.md).

#### Block Serialized Size

* The full wire-serialized block (`GetSerializeSize(TX_WITH_WITNESS(block))`: L1 transactions including HogEx, plus `mweb_block`) shall not exceed **`MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB`** (25,800,195 bytes = `MAX_BLOCK_SERIALIZED_SIZE` 4,000,000 + `mw::MAX_BLOCK_BYTES`, the pessimistic extension body at full `mw::MAX_BLOCK_WEIGHT`).
* This is a **consensus** rule (reject reason `bad-blk-serialized-size`), enforced early in `CheckBlock` before expensive MWEB verification.
* Two non-consensus limits sit below it:
  * `MAX_BLOCK_SERIALIZED_SIZE_BIP324` = 16,777,214 (`(2^24 − 1) − 1`: BIP324's 3-byte length field minus the one-byte short message type). A node refuses to send a larger block body to a BIP324 v2 peer (`CanSendBlockBodyOnPeer`) and disconnects it; such blocks are still accepted, stored, and served over v1. Compact blocks (version 3) carry the MWEB block, so the same applies to them: a v2 peer's request for a compact block that doesn't fit, or for the full block sent instead of a deep compact block, is refused the same way, and a v2 high-bandwidth peer is announced the block with `headers` instead of a compact block. `MAX_PROTOCOL_MESSAGE_LENGTH` (32,000,000) leaves v1 room for any consensus-valid block.
  * `MAX_BLOCK_SERIALIZED_SIZE_MINE` (default = the BIP324 value) caps block templates. See [mining-changes.md](./mining-changes.md#template-size-constraint-this-fork).
* Intentional divergence from Litecoin mining policy: Litecoin's default miner soft-caps extension weight at `MAX_MINE_WEIGHT` (20,000) and has no BIP324 transport; this tree allows full `mw::MAX_BLOCK_WEIGHT` subject to the mine size cap.

#### HogEx

* `HogEx` is a canonical transaction marked with the MWEB serialization flag and an empty MWEB transaction payload.
* `HogEx` is only valid in blocks (never as a loose mempool transaction).
* When MWEB is active:
  * A non-null extension block must be present.
  * The final transaction in the block must be marked as `HogEx`.
  * No earlier transaction in the block may be marked as `HogEx`.
* When MWEB is not active, extension block data must be absent.
* Transactions inside a block must not carry embedded MWEB transaction payloads (`HasMWEBTx() == false` and `HadAttachedMWEB() == false`), including `HogEx`. A non-finalizable attached payload (for example an input with features `0` / no input pubkey) is still attached MWEB: nodes reject it as `BLOCK_MUTATED` / `unexpected-mweb-data`, not as the canonical block after silently dropping the bytes.
* `HogEx` must contain at least one output.
* The first `HogEx` output (`vout[0]`) must be a HogAddr witness program: version `8`, 32-byte program.
  * That 32-byte program must equal the MWEB block hash committed by the extension block.
* The extension block height must match the canonical block height.
* Peg-in scripts (witness version `9`, 32-byte program) are not allowed in coinbase or `HogEx` outputs.
* HogEx inputs must match block peg-ins exactly, in block/txout scan order:
  * For the first `HogEx` after activation, every `HogEx` input is a pegin input.
  * For later blocks, `HogEx.vin[0]` must spend the previous block's `HogEx` output `0`, and remaining `HogEx` inputs must be pegin inputs.
  * Missing or extra `HogEx` inputs are invalid.
* `HogEx` outputs after the first (`vout[1..]`) are pegout outputs.
  * They must match the extension block pegouts by (`amount`, `scriptPubKey`) multiset equality.
* Let <code>H<sub>prev</sub></code> be the previous `HogEx.vout[0]` amount (or `0` for first `HogEx`), and let <code>P</code> be this block's total pegins.
  * The `HogEx` fee must be <code>(H<sub>prev</sub> + P) - vout_total</code>, and this must equal the extension block total fee.
  * The new `HogEx.vout[0]` amount must equal <code>H<sub>prev</sub> + supply_change</code>, where <code>supply_change = P - (pegouts + fees)</code>.
* Pegout maturity handling:
  * `HogEx.vout[0]` is not a pegout and is exempt from pegout maturity.
  * `HogEx.vout[1..]` are pegouts and require 6 confirmations before spending.
  * Undo data records the peg-out flag of each spent coin (see [store.md](./store.md#cblockundo)), so maturity is still enforced after a reorg returns those spends to the mempool.
* Current consensus does **not** globally forbid HogAddr-looking scripts outside `HogEx.vout[0]`; only the first output of `HogEx` is interpreted as the mandatory HogAddr commitment.

## Standardness (non-consensus)

Relay and mempool policy, enforced only when `fRequireStandard` is set:

* **Outputs:** an output is standard only if `features == STANDARD_FIELDS_FEATURE_BIT` (standard fields, no extra data) **and** both <code>K<sub>e</sub></code> and <code>K<sub>o</sub></code> parse as valid secp256k1 points.
* **Kernels:** a kernel is standard only if `features < EXTRA_DATA_FEATURE_BIT` and, if `PEGOUT_FEATURE_BIT` is set, at least one peg-out is present. See [kernels.md](./kernels.md).
* **Inputs:** an input is standard only if it carries no extra data (`F_i < 0x02`).
* **Peg-out scripts** are checked like L1 output scripts by `IsStandardTx` (standard script type, datacarrier budget, bare-multisig policy). Each peg-out must also be at least the dust threshold, as in Litecoin; the ephemeral-dust allowance applies to L1 `vout` only.
* **Peg-in alignment:** for transactions that are not MWEB-only, the set of L1 peg-in scripts must exactly match the MWEB kernel IDs (`kernel-mismatch`).
* **Relay size caps:** a transaction carrying MWEB data is rejected if it has more than `MAX_STANDARD_MWEB_TX_INPUTS` (1,000) inputs (`mweb-txn-too-many-inputs`) or an MWEB weight above `MAX_STANDARD_MWEB_TX_WEIGHT` (4,000) (`mweb-txn-oversize`). These are 1/50 of the consensus block limits and keep a single relayed transaction from forcing a block's worth of signature and rangeproof verification. Inputs carry no weight, so they are capped by count.
* **Replacement fee rate:** when a replacement, or a transaction it directly replaces, carries MWEB data, the replacement must pay at least 1.5x that transaction's fee rate (`MWEB::Policy::CheckReplacementFeeRate`, reject reason `insufficient fee`, or `package RBF failed: insufficient anti-DoS fees` for a package). Fee rate is the modified fee over L1 weight plus MWEB weight, as the mempool ranks transactions, so repeated replacements compound: 100, 150, 225 per weight unit. Rule 4 alone charges the incremental relay fee on L1 vsize, which an MWEB-only transaction lacks. A send from the wallet pays an MWEB-only transaction a fixed 100 per MWEB weight unit, so a new send replaces one only by adding an L1 peg-out that `fee_rate` pays for. Released Litecoin Core never replaces MWEB-only transactions; its 24.x branch replaces them only with `-mempoolfullrbf`, which is off by default. Package replacement's check that the package is its own chunk compares fee rates over the same weight, so an MWEB-only parent and child can replace together.
* **Packages:** locally submitted packages link parents and children through MWEB outputs and refuse two spends of one MWEB output (`conflict-in-package`). Peers never form packages through MWEB links. See [packages.md](./packages.md).
* **Fee bumping:** the wallet's `bumpfee` and `psbtbumpfee` replace MWEB-only, peg-in and peg-out transactions. The replacement keeps the original's inputs and recipients and pays at least 1.5x the original fee over L1 plus MWEB weight, and the old fee plus the incremental relay fee on its L1 size; the kernel pays whatever the fee rate doesn't reach, out of change. A changeless original whose leftover can't pay that is refused. The `outputs` and `original_change_index` options are refused for MWEB transactions, and `psbtbumpfee` needs PSBT version 2. An MWEB-only result of `psbtbumpfee` pays more than `sendrawtransaction`'s default fee cap allows (one MWEB output's fee above the MWEB weight fee), so it is broadcast with `maxfeerate=0`. Litecoin refuses MWEB inputs.

## Mempool validation ordering (policy / availability)

Mempool admission for MWEB transactions intentionally **diverges from Litecoin’s PreChecks ordering**: cheap structure, standardness, relay-cap, finality, conflict, and input-existence checks run before Schnorr/Bulletproof/kernel-sum cryptography. Consensus block validation still uses full `Transaction::Validate()` and is unchanged.
