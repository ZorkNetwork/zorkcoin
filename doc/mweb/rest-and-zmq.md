# MWEB notes for REST and ZMQ

Upstream Bitcoin Core documents the base interfaces:

- [`../REST-interface.md`](../REST-interface.md)
- [`../zmq.md`](../zmq.md)

This page only records **MWEB-specific** behavior so those Core docs stay
merge-friendly.

## REST

- JSON block endpoints that use `blockToJSON` include structured `mweb` fields
  when the block has an extension (same shape as RPC `getblock` verbosity ≥ 1).
- JSON header endpoints (`/rest/headers/...json`) carry the same MWEB keys as
  RPC `getblockheader`: `mweb_header`, `mweb_amount` and `prev_mweb_amount`
  when the block has an extension.
- Raw / binary block and transaction responses serialize the full `CBlock` or
  transaction, including the optional MWEB data, unless
  `-rpcserialversion=1` is set, which leaves the MWEB data out (as in Litecoin
  Core). Partial block reads (`/rest/blockpart/...`) always return the on-disk
  bytes.
- There is **no** REST surface for stealth-only scanning or extension UTXO
  enumeration; use RPC (`mwebscanutxoset`, etc.) or LIP-0006 P2P serve.

## ZMQ

- `pubrawblock` / hash-block notifications use the on-disk / wire block bytes:
  the MWEB extension is included when the block has one.
- `pubrawtx` uses transaction serialization with witness (`TX_WITH_WITNESS`);
  loose MWEB txs carry their extension payload when present. With
  `-rpcserialversion=1`, `pubrawblock` and `pubrawtx` leave the MWEB data
  out. HogEx is
  block-only and is not a mempool ZMQ topic.
- There are **no** dedicated MWEB or stealth ZMQ topics.
- BIP158 compact block filters remain L1-oriented; light clients that need
  extension UTXOs should use LIP-0006 (`mwebheader` / `mwebleafset` /
  `getmwebutxos`) rather than filter matching.
