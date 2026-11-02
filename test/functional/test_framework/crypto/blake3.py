#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pure-Python BLAKE3 implementation.

Fallback for when the `blake3` package is not installed. It provides the subset of that
package's interface used by the test framework: blake3(data[, key=...]).digest()/hexdigest()
with an optional output length, plus derive_key_context. It is slow and for testing only.
"""

import json
from pathlib import Path
import struct
import unittest

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK32 = 0xffffffff


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK32


def g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & MASK32
    state[d] = rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK32
    state[d] = rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotr32(state[b] ^ state[c], 7)


def compress(cv, block_words, counter, block_len, flags):
    """Return all 16 output words of the BLAKE3 compression function."""
    state = list(cv) + list(IV[:4]) + [counter & MASK32, (counter >> 32) & MASK32, block_len, flags]
    m = list(block_words)
    for round_num in range(7):
        g(state, 0, 4, 8, 12, m[0], m[1])
        g(state, 1, 5, 9, 13, m[2], m[3])
        g(state, 2, 6, 10, 14, m[4], m[5])
        g(state, 3, 7, 11, 15, m[6], m[7])
        g(state, 0, 5, 10, 15, m[8], m[9])
        g(state, 1, 6, 11, 12, m[10], m[11])
        g(state, 2, 7, 8, 13, m[12], m[13])
        g(state, 3, 4, 9, 14, m[14], m[15])
        if round_num < 6:
            m = [m[i] for i in MSG_PERMUTATION]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def words_from_block(block):
    return struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\x00"))


class Output:
    """Inputs to a final compression, which can produce a chaining value or root output bytes."""
    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv = cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return compress(self.cv, self.block_words, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self, length):
        out = b""
        output_block_counter = 0
        while len(out) < length:
            words = compress(self.cv, self.block_words, output_block_counter, self.block_len, self.flags | ROOT)
            out += struct.pack("<16I", *words)
            output_block_counter += 1
        return out[:length]


def chunk_output(key_words, chunk, chunk_counter, flags):
    cv = key_words
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for i, block in enumerate(blocks[:-1]):
        block_flags = flags | (CHUNK_START if i == 0 else 0)
        cv = compress(cv, words_from_block(block), chunk_counter, BLOCK_LEN, block_flags)[:8]
    last_flags = flags | CHUNK_END | (CHUNK_START if len(blocks) == 1 else 0)
    return Output(cv, words_from_block(blocks[-1]), chunk_counter, len(blocks[-1]), last_flags)


def subtree_output(key_words, data, chunk_counter, flags):
    """Output of the subtree over data, whose first chunk has index chunk_counter."""
    if len(data) <= CHUNK_LEN:
        return chunk_output(key_words, data, chunk_counter, flags)
    # The left subtree holds the largest power-of-two number of chunks that leaves the right non-empty.
    num_chunks = (len(data) + CHUNK_LEN - 1) // CHUNK_LEN
    left_chunks = 1 << ((num_chunks - 1).bit_length() - 1)
    left_len = left_chunks * CHUNK_LEN
    left_cv = subtree_output(key_words, data[:left_len], chunk_counter, flags).chaining_value()
    right_cv = subtree_output(key_words, data[left_len:], chunk_counter + left_chunks, flags).chaining_value()
    return Output(key_words, tuple(left_cv) + tuple(right_cv), 0, BLOCK_LEN, flags | PARENT)


def blake3_hash(data, *, key_words=IV, flags=0, length=OUT_LEN):
    return subtree_output(key_words, bytes(data), 0, flags).root_bytes(length)


class blake3:
    """Minimal stand-in for blake3.blake3 from the `blake3` package."""
    def __init__(self, data=b"", *, key=None, derive_key_context=None):
        assert key is None or derive_key_context is None
        if key is not None:
            assert len(key) == KEY_LEN
            self._key_words = struct.unpack("<8I", key)
            self._flags = KEYED_HASH
        elif derive_key_context is not None:
            context_key = blake3_hash(derive_key_context.encode(), flags=DERIVE_KEY_CONTEXT, length=KEY_LEN)
            self._key_words = struct.unpack("<8I", context_key)
            self._flags = DERIVE_KEY_MATERIAL
        else:
            self._key_words = IV
            self._flags = 0
        self._data = bytearray(data)

    def update(self, data):
        self._data += data
        return self

    def digest(self, length=OUT_LEN):
        return blake3_hash(self._data, key_words=self._key_words, flags=self._flags, length=length)

    def hexdigest(self, length=OUT_LEN):
        return self.digest(length).hex()


class TestFrameworkBlake3(unittest.TestCase):
    def test_vectors(self):
        with (Path(__file__).parents[4] / "src/crypto/blake3/test_vectors/test_vectors.json").open() as vectors_file:
            vectors = json.load(vectors_file)
        key = vectors["key"].encode()
        context = vectors["context_string"]
        for case in vectors["cases"]:
            data = bytes(i % 251 for i in range(case["input_len"]))
            for expected, hasher in (
                (case["hash"], blake3(data)),
                (case["keyed_hash"], blake3(data, key=key)),
                (case["derive_key"], blake3(data, derive_key_context=context)),
            ):
                out_len = len(expected) // 2
                self.assertEqual(hasher.hexdigest(out_len), expected)
                self.assertEqual(hasher.hexdigest(), expected[:OUT_LEN * 2])
