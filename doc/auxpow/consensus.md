# Kaspa AuxPoW consensus

Zorkcoin accepts an optional Kaspa-format AuxPoW header extension (`CAuxPow`)
when `nVersion` bit 8 is set. Native kHeavyHash remains valid forever. AuxPoW
is active from genesis on all networks.

Hashed preimage is the 88-byte header fields only. When bit 8 is set, the wire
header is those 88 bytes plus `CAuxPow`. Header-bearing P2P messages include
that extension. `CheckAuxPow` runs on the header; bit 8 without `CAuxPow` is
invalid and must not be indexed or credited chain work.

Full block order: hashed 88 bytes, then `CAuxPow` iff bit 8, then `vtx`, then
the MWEB trailer iff the last transaction is HogEx. AuxPoW is a header
extension. `nVersion` bit 8 is not the transaction HogEx flag.

Solo aux-chain (`h=0`, empty branch, `merkle_size=1`, `nChainIndex=0`) is
valid. Multi-leaf trees are supported: `merkle_size` MUST equal
`1 << vChainMerkleBranch.size()` and `nChainIndex` MUST equal
`GetExpectedIndex(merkle_nonce, nChainId, h)` (Dogecoin LCG). Dummy siblings
are allowed. A 2-leaf proof is a required test fixture.

## Dual targets

With \(T_Z\) from the Zorkcoin header `nBits` and \(T_K\) from the Kaspa peer header `bits`:

- Floor: peer PoW \(h \le \lfloor T_Z / 4 \rfloor\)
- Kaspa-derived: \(h \le \lfloor T_K / 3000 \rfloor\)
- Also \(h \le T_K\)

## AuxPoW header extension

`ZorkKaspaAuxPow` / `CAuxPow` follows the 88-byte hashed fields on the header.
It contains a Kaspa v2 peer header, lean coinbase,
Kaspa tx-merkle branch (coinbase at index 0), and Dogecoin-style aux-chain merkle
branch. The merged-mining magic `0xfabe'mm'` lives in Kaspa coinbase `extra_data`.

Hard size cap: 1280 bytes serialized extension (component caps in `Consensus::Params::auxpow`).

## Chain work

AuxPoW blocks credit `floor(GetBitsProof(nBits) * 8192 / (8192 + S))` where `S` is the
serialized `CAuxPow` size. Multiplication must not wrap `arith_uint256`. ASERT runs
on all blocks unchanged.

Identity is the 88-byte hash, so two valid extensions can share a hash and differ in
`S`. Nodes pin the first verified extension; a later different proof is
`bad-auxpow-mismatch` and must not rewrite `nAuxPowSize` / `nChainWork`.

## Header nonce and chain IDs

Bit 8 is the only `nVersion` bit AuxPoW uses; every other bit keeps its native
and BIP9 meaning. Bit 8 is reserved: no BIP9 deployment may use it, and it lies
outside the live signalling bits (0–4, BIP323) that unknown-version warnings
scan, so AuxPoW blocks never raise those warnings. Version-rolling mining
software must never roll bit 8. An AuxPoW block's 64-bit `nNonce` is locked to

`nNonce = ('AuxPoW' << 16) | chain_id` = `0x576F50787541 << 16 | chain_id`

so the eight little-endian wire bytes read as the two-letter network code
followed by `AuxPoW`. The node rejects any other value (`auxpow nonce marker
mismatch` / `auxpow chain id mismatch`). The Kaspa peer header carries the
ground nonce, so nothing is lost by fixing this one.

| Network | Chain ID | `nNonce` | Wire bytes |
| --- | --- | --- | --- |
| main | `0x4b5a` | `0x576F507875414B5A` | `ZKAuxPoW` |
| test / testnet4 | `0x545a` | `0x576F50787541545A` | `ZTAuxPoW` |
| regtest | `0x525a` | `0x576F50787541525A` | `ZRAuxPoW` |
| signet | `0x535a` | `0x576F50787541535A` | `ZSAuxPoW` |

## Implementation

Logic lives under `src/auxpow/`. Core callouts are limited to `primitives/block`,
`validation`, `chain`, `blockencodings` / net header paths, and Python `messages.py`.
