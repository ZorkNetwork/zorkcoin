# AuxPoW testing

## Golden vectors

`test/data/auxpow/kaspa_goldens.txt` is generated from upstream **rusty-kaspa**
commit `a41a333b08848f41bf737b72592e463a6011b8ac`. Hash hex is Kaspa raw byte
order (not Bitcoin `uint256S` display endian).

## Unit suites

- `kaspa_hash_tests`, `kaspa_header_tests`, `kaspa_tx_tests`, `kaspa_merkle_tests`, `kaspa_pow_tests`
- `auxpow_ser_tests`, `auxpow_check_tests`, `auxpow_chain_tests`, `auxpow_reject_tests`

`auxpow_check_tests` includes the Kaspa PoW golden header as a `CAuxPow`
peer header (PoW calculation / endianness; coinbase/MM need not be valid Zork AuxPoW)
and a required 2-leaf aux-chain accept plus sibling/index rejects.

`auxpow_ser_tests` covers the header helpers and version bits:

- `version_helpers`, `nonce_helpers`, `nonce_wire_bytes_per_network`: bit 8,
  the locked `nNonce`, and the `ZKAuxPoW` / `ZTAuxPoW` / `ZRAuxPoW` /
  `ZSAuxPoW` wire bytes.
- `auxpow_bit_reserved_from_versionbits`: no BIP9 deployment uses bit 8, and
  bit 8 is outside the live signalling bits.
- `auxpow_blocks_do_not_trigger_unknown_version_warnings`: three mainnet
  retarget periods of bit-8 blocks raise no warning; a bit-3 control does.
- `auxpow_serialize_and_unserialize_failures`: every serializer and
  unserializer error string.

`auxpow_reject_tests` covers every `CheckAuxPow` reject string (including
`auxpow nonce marker mismatch` and `auxpow chain id mismatch`), size caps, and
Kaspa parser failures: `kaspa_header_truncated_at_every_offset`,
`kaspa_tx_truncated_at_every_offset`, and `kaspa_compact_bits_boundaries`
(cross-checked against `arith_uint256::SetCompact`).

`auxpow_chain_tests` covers indexing, first-seen pinning, compact blocks, and
`asert_ignores_block_type`, which runs regtest with `-test=asert` so ASERT
actually retargets. It alternates AuxPoW and native blocks and requires every
height's `nBits` to match an all-native computation over the same times.

Fuzz: `src/test/fuzz/auxpow.cpp` (`auxpow` target) unserializes `CAuxPow` and
bit-8 `CBlockHeader`; `GetHash()` stays the 88-byte identity; `CheckAuxPow`
must not abort; round-trip serialize must not throw.

## Cheap regtest proofs

Test proofs declare the easiest Kaspa `bits` that decode, `0x2100ffff`
(`EASIEST_KASPA_BITS` in `src/test/util/auxpow.h` and
`test_framework/auxpow.py`). The Kaspa-derived target \(\lfloor T_K/3000\rfloor\)
is then far looser than the Zork floor, so only the 4× floor binds and a solo
grind needs about 4× the attempts of a native block. The Python kHeavyHash caches
its matrix per pre-PoW hash, so each attempt after the first skips matrix
generation. Grind time is still random; about 1 proof in 20 takes three times
the average or more.

## Functional

`feature_auxpow.py` is the **pre-MWEB** path (`setup_clean_chain`, no
`-vbparams=mweb`). It builds solo AuxPoW in Python (blake2b + kHeavyHash),
submits on regtest, rejects AuxPoW-bit headers without the extension, checks
compact-block / `headers` carry `CAuxPow`, checks the locked `nNonce`
(`getblockheader` value, `ZRAuxPoW` wire bytes, wrong nonces rejected),
submits a 2-leaf aux-chain proof, and sends P2P mutations (truncated extension,
CompactSize over caps, invalid Kaspa bytes, first-seen mismatch over
`headers`). Proofs are ground before any announcement so the header and
compact-block checks don't race the node.

`feature_auxpow_mweb.py` is the **MWEB-active** path (`-vbparams=mweb`). It
submits AuxPoW+HogEx+MWEB via `CBlock.serialize()`, compact v3 with a bit-8
header and non-null `mweb_block`, two-node sync of that tip, and independence
(AuxPoW without HogEx fails; native HogEx still works). Do not enable MWEB
inside `feature_auxpow.py`. It also runs:

- `test_mixed_content_auxpow_block`: one AuxPoW block carrying a SegWit spend,
  a Taproot key-path spend, a peg-in, a peg-out, and an MWEB-to-MWEB transfer.
  It is relayed as a compact block with only the coinbase and HogEx
  prefilled, and the receiver must rebuild it from its mempool without
  `getblocktxn`.
- `test_native_auxpow_mweb_reorg`: a native+MWEB tip and an AuxPoW+MWEB tip at
  the same height, reorged both ways with `invalidateblock` /
  `reconsiderblock` and `verifychain` after each; the MWEB transaction follows
  the active tip.

`feature_auxpow_headers_presync.py` syncs a 2051-block chain (two `headers`
messages) with AuxPoW blocks at height 1, mid-chain, at the message boundary,
and at the tip. With `-minimumchainwork` one unit above the chain's work the
peer aborts presync at the tip and indexes nothing. With exactly the chain's
work it reaches sufficient work at the tip, redownloads from genesis, and
stores AuxPoW headers byte-identical to the source.

```
test/functional/test_runner.py feature_auxpow.py feature_auxpow_mweb.py feature_auxpow_headers_presync.py
./bin/test_zorkcoin --run_test='kaspa_*,auxpow_*'
```
