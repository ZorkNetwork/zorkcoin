# AuxPoW mining

AuxPoW is mined with the existing `getblocktemplate` and `submitblock` RPCs.
There is no `createauxblock` / `submitauxblock`. Consensus is
[`consensus.md`](consensus.md); the header-extension layout is
[`serialization.md`](serialization.md).

Native kHeavyHash mining is unchanged. AuxPoW is optional: a miner who is
already producing Kaspa-format hashes can attach a proof to a Zork template.

## What the node gives you

Call `getblocktemplate` as for a native block. The template is **native**:
`version` must not have bit 8 set. Do not pass `-blockversion` with bit 8
(`0x100`); tests use `-blockversion=1081` so GBT stays native.

Use the template’s `previousblockhash`, `transactions`, coinbase / merkle
construction, `curtime`, and `bits` as usual. Zork `nTime` is milliseconds
and `nNonce` is 64-bit — Bitcoin 32-bit assumptions will mis-serialize the
header.

`getblock` / `getblockheader` have no AuxPoW-specific fields. After submit,
bit 8 on `version` (`version & 0x100`) is the signal that the block used
AuxPoW.

## Assemble the header locally

1. Build the Zork coinbase and merkle root from the template (same as native).
2. Set `nVersion` and `nNonce` on a **local** copy only:

   `nVersion = template_version | 0x100`

   `nNonce = 0x576F50787541 << 16 | chain_id` (ASCII `AuxPoW` above the chain ID)

   | Network | Chain ID | `nNonce` wire bytes |
   | --- | --- | --- |
   | main | `0x4b5a` | `ZKAuxPoW` |
   | test / testnet4 | `0x545a` | `ZTAuxPoW` |
   | regtest | `0x525a` | `ZRAuxPoW` |
   | signet | `0x535a` | `ZSAuxPoW` |

   The Zork `nNonce` is not ground for AuxPoW; the Kaspa peer header carries
   the nonce that is ground.
3. Fill `hashPrevBlock`, `hashMerkleRoot`, `nTime`, `nBits` from the template.
4. `hashAuxBlock` is the 88-byte `GetHash()` of those fields. `CAuxPow` is
   **not** hashed.

## Build the Kaspa proof

Solo (one aux-chain leaf) is enough for a valid block:

1. Place `hashAuxBlock` as the sole aux-chain leaf (`nChainIndex = 0`, empty
   chain merkle branch). Pools that merge several child chains use a shared
   aux-chain tree instead (`h = vChainMerkleBranch.size()`, dummy siblings
   allowed). `merkle_size` MUST equal `1 << h`; pick `merkle_nonce` first,
   then `nChainIndex = GetExpectedIndex(nonce, chain_id, h)` (Dogecoin LCG).
2. Write the merged-mining record in the Kaspa coinbase **`extra_data`**
   (not `scriptSig`, not `script_public_key`):

   `{0xfa, 0xbe, 'm', 'm'}` + byte-reversed aux merkle root + `merkle_size`
   (LE u32) + `merkle_nonce` (LE u32).

   Exactly one magic occurrence in `extra_data`. Bytes before/after the
   44-byte record are allowed.
3. Kaspa v2 peer header: `hash_merkle_root` commits to that coinbase (tx
   merkle, coinbase at index 0). Peer header `version` must be 2.
4. Mine Kaspa peer PoW until all of:

   - \(h \le T_K\) (Kaspa compact `bits` on the peer header)
   - \(h \le \lfloor T_K / 3000 \rfloor\)
   - \(h \le \lfloor T_Z / 4 \rfloor\) (\(T_Z\) from the Zork template `bits`)

   Ordinary Kaspa-valid hashes that miss either auxiliary inequality do not
   qualify. The miner chooses Kaspa `bits` (typically the Kaspa network
   target); easy `bits` still have to meet the Zork floor. The easiest `bits`
   that decode are `0x2100ffff` (\(T_K\) = `0xffff << 240`); with them only
   the Zork floor binds, which is what the regtest tests use.
5. Serialize `CAuxPow` (version 1, peer header, coinbase, tx merkle branch,
   chain merkle branch, `nChainIndex`). Total ≤ 1280 bytes; component caps
   in [`serialization.md`](serialization.md).

Python reference for encoding and a solo grind:
`test/functional/test_framework/auxpow.py`
(`build_solo_auxpow_for_block`, `build_auxpow_for_block` for multi-leaf).
End-to-end: `test/functional/feature_auxpow.py`. After MWEB activation:
`test/functional/feature_auxpow_mweb.py`.

## Submit

`submitblock` the full hex:

- 88-byte hashed header fields (bit 8 set)
- then `CAuxPow`
- then `vtx`
- then the MWEB trailer, if the last tx is HogEx

After MWEB activation, `getblocktemplate` with `mweb`+`segwit` includes HogEx
/`mweb`. Keep every GBT `version` bit (BIP9 top bits, MWEB bit 4) and only add
AuxPoW bit 8: `nVersion = template_version | 0x100`.
Serialize with `CBlock.serialize()` (or equivalent), not a header+`vtx`-only
helper that drops the MWEB trailer.

`CAuxPow` counts in block weight at 4 WU per byte (up to 5,120 WU). The
template does not reserve room for it separately; it relies on the default
`-blockreservedweight` of 8,000 WU, which also covers the header and coinbase.
If you lower that option or build a large coinbase from a full template, leave
room for the extension or the block fails `bad-blk-weight`.

Bit 8 without the extension is invalid (`-22` on `submitblock`). Two
different valid extensions can share the 88-byte hash; the node pins the
first-seen proof (`bad-auxpow-mismatch`).

`submitblock` of a valid block that is not the active tip may return
`inconclusive` instead of JSON `null`. That is success for a side-chain
candidate.

AuxPoW chain work is \(\lfloor W \cdot 8192 / (8192 + S)\rfloor\) where \(S\)
is the serialized `CAuxPow` size, so lean proofs earn more than fat ones.
On regtest, native still outranks AuxPoW at the same height.
