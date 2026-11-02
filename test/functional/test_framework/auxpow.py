#!/usr/bin/env python3
# Copyright (c) 2026 The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Kaspa AuxPoW helpers for functional tests."""

from __future__ import annotations

import hashlib
import struct
from io import BytesIO

from test_framework.crypto.kheavyhash import kheavyhash
from test_framework.messages import (
    CBlock,
    deser_compact_size,
    deser_uint256,
    hash256,
    ser_compact_size,
    ser_uint256,
    uint256_from_compact,
    uint256_from_str,
)

VERSION_AUXPOW_BIT = 0x100
# An AuxPoW block's nNonce is locked to AUXPOW_NONCE_MARKER | chain_id, so its
# little-endian wire bytes read e.g. b"ZRAuxPoW" on regtest.
AUXPOW_NONCE_MARKER = int.from_bytes(b"AuxPoW", "little") << 16
REGTEST_AUXPOW_CHAIN_ID = int.from_bytes(b"ZR", "little")
PCH_MERGED_MINING = b"\xfa\xbe\x6d\x6d"
# Largest target Kaspa compact bits can encode (0xffff << 240). The consensus
# 3000x multiplier is fixed, so this makes regtest grinds as cheap as possible.
EASIEST_KASPA_BITS = 0x2100FFFF


def is_auxpow(n_version: int) -> bool:
    return (n_version & VERSION_AUXPOW_BIT) != 0


def make_auxpow_version(base: int = 0x20000000) -> int:
    return base | VERSION_AUXPOW_BIT


def make_auxpow_nonce(chain_id: int = REGTEST_AUXPOW_CHAIN_ID) -> int:
    return AUXPOW_NONCE_MARKER | (chain_id & 0xFFFF)


def kaspa_hash_from_u64(n: int) -> bytes:
    return b"\x00" * 24 + struct.pack("<Q", n)


def _blake2b_key(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32, key=key).digest()


def kaspa_block_hash(preimage: bytes) -> bytes:
    return _blake2b_key(b"BlockHash", preimage)


def kaspa_tx_hash(preimage: bytes) -> bytes:
    return _blake2b_key(b"TransactionHash", preimage)


def write_kaspa_header_fields(
    *,
    version: int,
    expanded_parents: list[list[bytes]],
    hash_merkle_root: bytes,
    accepted_id_merkle_root: bytes,
    utxo_commitment: bytes,
    timestamp: int,
    bits: int,
    nonce: int,
    daa_score: int,
    blue_score: int,
    blue_work: bytes,
    pruning_point: bytes,
) -> bytes:
    """Hash preimage (expanded parents), not wire RLE."""
    out = bytearray()
    out += struct.pack("<H", version)
    out += struct.pack("<Q", len(expanded_parents))
    for level in expanded_parents:
        out += struct.pack("<Q", len(level))
        for p in level:
            out += p
    out += hash_merkle_root
    out += accepted_id_merkle_root
    out += utxo_commitment
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<I", bits)
    out += struct.pack("<Q", nonce)
    out += struct.pack("<Q", daa_score)
    out += struct.pack("<Q", blue_score)
    out += struct.pack("<Q", len(blue_work))
    out += blue_work
    out += pruning_point
    return bytes(out)


def serialize_kaspa_header_wire(
    *,
    version: int = 2,
    parents: list[bytes] | None = None,
    hash_merkle_root: bytes,
    accepted_id_merkle_root: bytes | None = None,
    utxo_commitment: bytes | None = None,
    timestamp: int,
    bits: int,
    nonce: int,
    daa_score: int = 1,
    blue_score: int = 1,
    blue_work: bytes = b"",
    pruning_point: bytes | None = None,
) -> bytes:
    if parents is None:
        parents = [kaspa_hash_from_u64(1)]
    if accepted_id_merkle_root is None:
        accepted_id_merkle_root = kaspa_hash_from_u64(3)
    if utxo_commitment is None:
        utxo_commitment = kaspa_hash_from_u64(4)
    if pruning_point is None:
        pruning_point = kaspa_hash_from_u64(5)
    out = bytearray()
    out += struct.pack("<H", version)
    out += struct.pack("<Q", 1)
    out.append(1)
    out += struct.pack("<Q", len(parents))
    for p in parents:
        out += p
    out += hash_merkle_root
    out += accepted_id_merkle_root
    out += utxo_commitment
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<I", bits)
    out += struct.pack("<Q", nonce)
    out += struct.pack("<Q", daa_score)
    out += struct.pack("<Q", blue_score)
    out += struct.pack("<Q", len(blue_work))
    out += blue_work
    out += pruning_point
    return bytes(out)


def kaspa_pre_pow_hash_from_wire_fields(
    *,
    hash_merkle_root: bytes,
    timestamp: int,
    bits: int,
    parents: list[bytes] | None = None,
    accepted_id_merkle_root: bytes | None = None,
    utxo_commitment: bytes | None = None,
    daa_score: int = 1,
    blue_score: int = 1,
    pruning_point: bytes | None = None,
) -> bytes:
    if parents is None:
        parents = [kaspa_hash_from_u64(1)]
    if accepted_id_merkle_root is None:
        accepted_id_merkle_root = kaspa_hash_from_u64(3)
    if utxo_commitment is None:
        utxo_commitment = kaspa_hash_from_u64(4)
    if pruning_point is None:
        pruning_point = kaspa_hash_from_u64(5)
    preimage = write_kaspa_header_fields(
        version=2,
        expanded_parents=[parents],
        hash_merkle_root=hash_merkle_root,
        accepted_id_merkle_root=accepted_id_merkle_root,
        utxo_commitment=utxo_commitment,
        timestamp=0,
        bits=bits,
        nonce=0,
        daa_score=daa_score,
        blue_score=blue_score,
        blue_work=b"",
        pruning_point=pruning_point,
    )
    return kaspa_block_hash(preimage)


def kaspa_peer_pow(pre_pow: bytes, timestamp: int, nonce: int) -> bytes:
    work_order = pre_pow + struct.pack("<Q", timestamp) + (b"\x00" * 32) + struct.pack("<Q", nonce)
    return kheavyhash(work_order)


def write_kaspa_coinbase_tx(*, payload: bytes, value: int = 50, script: bytes = b"\x00") -> bytes:
    out = bytearray()
    out += struct.pack("<H", 1)
    out += struct.pack("<Q", 0)
    out += struct.pack("<Q", 1)
    out += struct.pack("<Q", value)
    out += struct.pack("<H", 0)
    out += struct.pack("<Q", len(script))
    out += script
    out.append(0)
    out += struct.pack("<Q", 0)
    out += b"\x01" + b"\x00" * 19
    out += struct.pack("<Q", 0)
    out += struct.pack("<Q", len(payload))
    out += payload
    out += struct.pack("<Q", 0)
    return bytes(out)


def kaspa_coinbase_tx_hash(tx_bytes: bytes) -> bytes:
    # TransactionHash over the same field layout as wire for our lean coinbase.
    return kaspa_tx_hash(tx_bytes)


def make_mm_payload(aux_root: bytes, merkle_size: int = 1, merkle_nonce: int = 0) -> bytes:
    assert len(aux_root) == 32
    payload = bytearray()
    payload += struct.pack("<Q", 0)
    payload += struct.pack("<Q", 0)
    payload += struct.pack("<H", 0)
    payload.append(0)
    payload += PCH_MERGED_MINING
    payload += aux_root[::-1]
    payload += struct.pack("<I", merkle_size)
    payload += struct.pack("<I", merkle_nonce)
    return bytes(payload)


def serialize_auxpow(
    *,
    peer_header: bytes,
    coinbase_tx: bytes,
    tx_merkle_branch: list[bytes] | None = None,
    chain_merkle_branch: list[bytes] | None = None,
    n_chain_index: int = 0,
    version: int = 1,
) -> bytes:
    if tx_merkle_branch is None:
        tx_merkle_branch = []
    if chain_merkle_branch is None:
        chain_merkle_branch = []
    out = bytearray()
    out += struct.pack("<I", version)
    out += ser_compact_size(len(peer_header))
    out += peer_header
    out += ser_compact_size(len(coinbase_tx))
    out += coinbase_tx
    out += ser_compact_size(len(tx_merkle_branch))
    for h in tx_merkle_branch:
        out += h
    out += ser_compact_size(len(chain_merkle_branch))
    for h in chain_merkle_branch:
        out += h
    out += struct.pack("<i", n_chain_index)
    return bytes(out)


def deserialize_auxpow(f) -> bytes:
    """Consume the AuxPoW header extension from a stream (bit-8 path). Returns raw bytes."""
    start = f.tell()
    version = int.from_bytes(f.read(4), "little")
    if version != 1:
        raise ValueError(f"unsupported auxpow version {version}")
    hdr_len = deser_compact_size(f)
    if hdr_len > 720:
        raise ValueError("auxpow peer_header too large")
    f.read(hdr_len)
    tx_len = deser_compact_size(f)
    if tx_len > 400:
        raise ValueError("auxpow coinbase_tx too large")
    f.read(tx_len)
    n_tx = deser_compact_size(f)
    if n_tx > 8:
        raise ValueError("auxpow tx merkle branch too long")
    for _ in range(n_tx):
        deser_uint256(f)
    n_chain = deser_compact_size(f)
    if n_chain > 5:
        raise ValueError("auxpow chain merkle branch too long")
    for _ in range(n_chain):
        deser_uint256(f)
    f.read(4)
    end = f.tell()
    if end - start > 1280:
        raise ValueError("auxpow header extension exceeds max serialized size")
    f.seek(start)
    return f.read(end - start)


def serialize_header(block: CBlock) -> bytes:
    r = b""
    r += block.nVersion.to_bytes(4, "little", signed=True)
    r += ser_uint256(block.hashPrevBlock)
    r += ser_uint256(block.hashMerkleRoot)
    r += block.nTime.to_bytes(8, "little")
    r += block.nBits.to_bytes(4, "little")
    r += block.nNonce.to_bytes(8, "little")
    return r


def serialize_block_with_auxpow(block: CBlock, auxpow_bytes: bytes) -> bytes:
    """Full block wire: hashed header + AuxPoW header extension + vtx (+ MWEB if present).

    Pre-MWEB callers with no mweb_block stay byte-identical. Combined AuxPoW+HogEx
    tests should use CBlock.serialize() so the HogEx transaction and MWEB trailer
    serialize correctly.
    """
    from test_framework.messages import ser_mweb_block, ser_vector

    header = serialize_header(block)
    r = header + auxpow_bytes + ser_vector(block.vtx)
    if getattr(block, "mweb_block", None) is not None:
        r += ser_mweb_block(block.mweb_block)
    return r


def target_div_floor(bits: int, divisor: int) -> int:
    t = uint256_from_compact(bits)
    return t // divisor


def grind_kaspa_nonce(pre_pow: bytes, timestamp: int, bits_k: int, bits_z: int, floor_mult: int = 4, kaspa_mult: int = 3000) -> int:
    limit = min(target_div_floor(bits_k, kaspa_mult), target_div_floor(bits_z, floor_mult))
    nonce = 0
    while True:
        pow_bytes = kaspa_peer_pow(pre_pow, timestamp, nonce)
        if uint256_from_str(pow_bytes) <= limit:
            return nonce
        nonce += 1
        if nonce > 2_000_000:
            raise RuntimeError("failed to grind auxpow nonce")


def get_expected_index(n_nonce: int, n_chain_id: int, h: int) -> int:
    """Dogecoin/Namecoin LCG; matches auxpow::GetExpectedIndex."""
    if h > 31:
        return 0
    rand = n_nonce & 0xFFFFFFFF
    rand = (rand * 1103515245 + 12345) & 0xFFFFFFFF
    rand = (rand + (n_chain_id & 0xFFFFFFFF)) & 0xFFFFFFFF
    rand = (rand * 1103515245 + 12345) & 0xFFFFFFFF
    return rand % (1 << h)


def compute_aux_chain_root(leaf: bytes, branch: list[bytes], index: int) -> bytes:
    """Bitcoin/Dogecoin hash256 pairing (not Kaspa merkle)."""
    h = leaf
    for sibling in branch:
        if (index & 1) == 0:
            h = hash256(h + sibling)
        else:
            h = hash256(sibling + h)
        index >>= 1
    return h


def build_auxpow_for_block(
    block: CBlock,
    *,
    chain_merkle_branch: list[bytes] | None = None,
    merkle_nonce: int = 0,
    n_chain_index: int | None = None,
    kaspa_bits: int = EASIEST_KASPA_BITS,
    extra_parents: int = 0,
    chain_id: int = REGTEST_AUXPOW_CHAIN_ID,
) -> bytes:
    """Build a Kaspa AuxPoW header extension; empty branch is solo."""
    if chain_merkle_branch is None:
        chain_merkle_branch = []
    h = len(chain_merkle_branch)
    if n_chain_index is None:
        n_chain_index = get_expected_index(merkle_nonce, chain_id, h)
    leaf = hash256(serialize_header(block))
    aux_root = compute_aux_chain_root(leaf, chain_merkle_branch, n_chain_index)
    payload = make_mm_payload(aux_root, merkle_size=1 << h, merkle_nonce=merkle_nonce)
    coinbase = write_kaspa_coinbase_tx(payload=payload)
    cb_hash = kaspa_coinbase_tx_hash(coinbase)
    ts = 1_700_000_000_000
    parents = [kaspa_hash_from_u64(1)] + [kaspa_hash_from_u64(100 + i) for i in range(extra_parents)]
    pre = kaspa_pre_pow_hash_from_wire_fields(
        hash_merkle_root=cb_hash,
        timestamp=ts,
        bits=kaspa_bits,
        parents=parents,
    )
    nonce = grind_kaspa_nonce(pre, ts, kaspa_bits, block.nBits)
    peer_header = serialize_kaspa_header_wire(
        hash_merkle_root=cb_hash,
        timestamp=ts,
        bits=kaspa_bits,
        nonce=nonce,
        parents=parents,
    )
    return serialize_auxpow(
        peer_header=peer_header,
        coinbase_tx=coinbase,
        chain_merkle_branch=chain_merkle_branch,
        n_chain_index=n_chain_index,
    )


def build_solo_auxpow_for_block(block: CBlock, *, kaspa_bits: int = EASIEST_KASPA_BITS, extra_parents: int = 0) -> bytes:
    """Build a valid solo (one-leaf) AuxPoW header extension for an already-finalized Zork header."""
    return build_auxpow_for_block(block, kaspa_bits=kaspa_bits, extra_parents=extra_parents)


def build_two_leaf_auxpow_for_block(
    block: CBlock,
    *,
    merkle_nonce: int = 0,
    chain_id: int = REGTEST_AUXPOW_CHAIN_ID,
    kaspa_bits: int = EASIEST_KASPA_BITS,
    extra_parents: int = 0,
    n_chain_index: int | None = None,
) -> bytes:
    """2-leaf aux-chain with a dummy sibling; n_chain_index defaults to GetExpectedIndex."""
    sibling = kaspa_hash_from_u64(99)
    return build_auxpow_for_block(
        block,
        chain_merkle_branch=[sibling],
        merkle_nonce=merkle_nonce,
        n_chain_index=n_chain_index,
        kaspa_bits=kaspa_bits,
        extra_parents=extra_parents,
        chain_id=chain_id,
    )
