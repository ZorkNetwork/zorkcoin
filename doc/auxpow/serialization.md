# AuxPoW serialization

Hashed preimage is always the 88-byte Zorkcoin header fields
(`nVersion`, `hashPrevBlock`, `hashMerkleRoot`, `nTime`, `nBits`, `nNonce`).
`GetHash()`, `GetPoWHash()`, and the aux-tree leaf use only those bytes.
The AuxPoW header extension (`CAuxPow` / `ZorkKaspaAuxPow`) is **not** hashed.

## Wire header

When `nVersion` bit 8 is clear, the wire header is those 88 bytes.

When bit 8 is set, the wire header is 88 bytes followed by `CAuxPow` (≤ 1280 bytes).
Bit 8 without the extension is invalid and must not be written as an 88-byte
native-shaped header. `CheckAuxPow` runs on that header.

Header-bearing P2P messages (`headers`, header-sync, compact-block header fields)
include the AuxPoW header extension when bit 8 is set. Compact-block reconstruction
keeps `CAuxPow` because it is part of `CBlockHeader` serialization.

Full block = that header, then `vtx`, then the MWEB trailer iff the last
transaction is HogEx. The AuxPoW header extension is not the MWEB trailer.
`nVersion` bit 8 (AuxPoW) is distinct from the HogEx transaction flag.

## `CAuxPow` layout (after the 88-byte hashed fields)

```
uint32 version                 // = 1
CompactSize peer_header_len    // cap 720
bytes peer_header              // Kaspa v2 RLE header
CompactSize coinbase_tx_len    // cap 400
bytes coinbase_tx              // Kaspa lean coinbase
CompactSize tx_merkle_len      // cap 8
uint256 tx_merkle[tx_merkle_len]
CompactSize chain_merkle_len   // cap 5
uint256 chain_merkle[chain_merkle_len]
int32 nChainIndex
```

Unserialize enforces those CompactSize caps (and total ≤ 1280) before allocating.

## Size and weight

`CAuxPow` is part of the serialized header, so it counts in block weight at
4 WU per byte (at most 5,120 WU), in the serialized-size limit, and in
`getblock` `size` / `weight`. Block templates reserve no separate room for it;
it fits in the default `-blockreservedweight` (8,000 WU) alongside the header
and a typical coinbase.

Kaspa peer header and coinbase encodings match `src/auxpow/kaspa_header.*` /
`kaspa_tx.*`. Python parity: `test/functional/test_framework/auxpow.py`.
