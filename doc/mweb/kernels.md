# Kernels

## Current Features

All kernels begin with a single byte which acts as a bitvector to specify the "features" of the kernel.
The following feature bits are currently supported, though more could be added in the future:

* `FEE_FEATURE_BIT` = `0x01`
* `PEGIN_FEATURE_BIT` = `0x02`
* `PEGOUT_FEATURE_BIT` = `0x04`
* `HEIGHT_LOCK_FEATURE_BIT` = `0x08`
* `STEALTH_EXCESS_FEATURE_BIT` = `0x10`
* `EXTRA_DATA_FEATURE_BIT` = `0x20`

For each feature bit that's set, the corresponding feature rules apply to that kernel.

***NOTE**: Only `FEE_FEATURE_BIT`, `PEGIN_FEATURE_BIT`, `PEGOUT_FEATURE_BIT`, `HEIGHT_LOCK_FEATURE_BIT`, and `STEALTH_EXCESS_FEATURE_BIT` are considered "standard" features (`Kernel::IsStandard` requires `features < EXTRA_DATA_FEATURE_BIT` and a canonical peg-out field).
Transactions specifying the `EXTRA_DATA_FEATURE_BIT` or any higher feature bits are not relayed or mined by default nodes.
This may change in future releases.*

#### Fee

Kernels specifying the `FEE_FEATURE_BIT` shall contain a (non-negative `var_int`) fee field.
The fee value shall be deducted from the total MWEB supply, and may be collected by the miner of the containing block as part of its coinbase reward.

#### Peg-In

Kernels specifying the `PEGIN_FEATURE_BIT` shall contain a (non-negative `var_int`) peg-in amount field.
The peg-in amount shall be added to the total MWEB supply, and must have a corresponding pegin output on the canonical side.

#### Peg-Out

Kernels specifying the `PEGOUT_FEATURE_BIT` shall contain a vector of pegouts, each consisting of a (non-negative `var_int`) peg-out amount field and a non-empty `scriptPubKey` (serialized as a Bitcoin Core `CScript`; empty scripts are rejected on deserialize).
The peg-out amount shall be deducted from the total MWEB supply by the miner.
The miner shall add an output to the integrating transaction (`HogEx`) for each pegout specified. The output's `amount` and `scriptPubKey` shall match the one specified in the kernel.

The peg-out vector shall not be empty when `PEGOUT_FEATURE_BIT` is set (`Kernel::HasCanonicalPegOutFeature`):
* Consensus: blocks at heights ≥ `mweb_pegout_feature_activation_height` containing such a kernel are rejected (`bad-mweb-empty-pegout`). On this chain the parameter is set relative to MWEB activation (+0 adequate); see [consensus.md](./consensus.md#activation-and-consensus-parameters).
* Policy: such kernels are non-standard at all heights.

#### Height Lock

Kernels specifying the `HEIGHT_LOCK_FEATURE_BIT` shall contain a (non-negative `var_int`) lock height field.
The kernel shall not be included in any block earlier than the lock height specified. This is enforced from the first MWEB block (`mweb_kernel_lock_height_grandfather` = 0).
Mempool admission treats height-locked MWEB transactions like L1 non-final transactions (the lock height is part of `IsFinalTx`): the transaction is rejected as `non-final` until `lock_height` is less than or equal to the next block height.

#### Stealth Excess

Kernels specifying the `STEALTH_EXCESS_FEATURE_BIT` shall contain a (compressed public key) stealth excess (`E'`) field.
The stealth excess will also be used when signing the kernel.

#### Extra Data

Kernels specifying the `EXTRA_DATA_FEATURE_BIT` shall contain a length-prefixed byte vector (`CompactSize` + bytes, as for other `std::vector<uint8_t>` fields). There is no field-specific size limit; size is bounded by MWEB weight (<code>&lceil;n/42&rceil;</code> per kernel) and block size.
The extra data shall not be empty when `EXTRA_DATA_FEATURE_BIT` is set (`Kernel::HasCanonicalExtraDataFeature`): blocks at heights ≥ `mweb_extradata_feature_activation_height` containing such a kernel are rejected (`bad-mweb-empty-extradata`). On this chain the parameter is set relative to MWEB activation (+0 adequate).
No other consensus rules are enforced on the contents of the data, though future soft-forks are likely to take advantage of this field. Kernels with this bit set are non-standard for relay.

These two rules exist because deserialization reads the peg-out and extra-data vectors whenever their bit is set, while serialization writes them only when non-empty; a kernel with the bit set and an empty field would not round-trip.

## Signature

The kernel shall contain a valid Schnorr signature over a 32-byte BLAKE3 hash, the signature message <code>H(K<sub>M</sub>)</code>. <code>K<sub>M</sub></code> is built as follows (`Kernel::GetSignatureMessage`):

1. `features` (1 byte)
2. `excess` (33-byte commitment)
3. `fee` as `VARINT` — if present
4. `pegin_amount` as `VARINT` — if present
5. `pegouts` (vector: `CompactSize` count, then each `VARINT(amount)` + `CScript`) — if non-empty
6. `lock_height` as `VARINT` — if present
7. `stealth_excess` (33-byte pubkey) — if present
8. `extra_data` (`CompactSize` length + bytes) — if non-empty

"If present" and "if non-empty" coincide with "if the feature bit is set" for every kernel valid under the rules above. This order differs from the wire serialization ([serialization.md](./serialization.md#mweb_kernel)), where `excess` comes after all feature fields and `stealth_excess` comes before `extra_data`.

*Example: If the kernel's feature byte is 0x03 (`FEE_FEATURE_BIT` | `PEGIN_FEATURE_BIT`), the message signed shall be: `BLAKE3(0x03 || excess || VARINT(fee) || VARINT(pegin_amount))`*

If the `STEALTH_EXCESS_FEATURE_BIT` is set, instead of verifying against just the kernel excess (`E`), the signature shall verify for key `BLAKE3(E||E')*E + E'`.

## Soft Forks

New features may be defined in the future via softfork. Consensus rules may be agreed upon for the currently undefined feature bits.
Though new data sections cannot be added without hardforking, future feature bits may be used in conjunction with the `EXTRA_DATA_FEATURE_BIT` to include additional kernel data.
