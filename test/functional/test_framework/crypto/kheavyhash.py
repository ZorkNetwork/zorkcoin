#!/usr/bin/env python3
# Copyright (c) The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""kHeavyHash matching src/crypto/kheavyhash.cpp.

cSHAKE256 uses Keccak domain 0x04 (not SHA3's 0x06). Matrix setup is
XoShiRo256++ over the pre-PoW seed, regenerated until floating-point rank is 64.
"""
from __future__ import annotations

import functools
import struct

_RNDC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF
_EPS = 1e-9


def _rotl64(x: int, k: int) -> int:
    x &= _MASK64
    return ((x << k) | (x >> (64 - k))) & _MASK64


def _keccak_f(st: list[int]) -> None:
    for rndc in _RNDC:
        bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20]
        bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21]
        bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22]
        bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23]
        bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24]
        t = bc4 ^ _rotl64(bc1, 1)
        st[0] ^= t; st[5] ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t
        t = bc0 ^ _rotl64(bc2, 1)
        st[1] ^= t; st[6] ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t
        t = bc1 ^ _rotl64(bc3, 1)
        st[2] ^= t; st[7] ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t
        t = bc2 ^ _rotl64(bc4, 1)
        st[3] ^= t; st[8] ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t
        t = bc3 ^ _rotl64(bc0, 1)
        st[4] ^= t; st[9] ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t

        t = st[1]
        bc0 = st[10]; st[10] = _rotl64(t, 1); t = bc0
        bc0 = st[7]; st[7] = _rotl64(t, 3); t = bc0
        bc0 = st[11]; st[11] = _rotl64(t, 6); t = bc0
        bc0 = st[17]; st[17] = _rotl64(t, 10); t = bc0
        bc0 = st[18]; st[18] = _rotl64(t, 15); t = bc0
        bc0 = st[3]; st[3] = _rotl64(t, 21); t = bc0
        bc0 = st[5]; st[5] = _rotl64(t, 28); t = bc0
        bc0 = st[16]; st[16] = _rotl64(t, 36); t = bc0
        bc0 = st[8]; st[8] = _rotl64(t, 45); t = bc0
        bc0 = st[21]; st[21] = _rotl64(t, 55); t = bc0
        bc0 = st[24]; st[24] = _rotl64(t, 2); t = bc0
        bc0 = st[4]; st[4] = _rotl64(t, 14); t = bc0
        bc0 = st[15]; st[15] = _rotl64(t, 27); t = bc0
        bc0 = st[23]; st[23] = _rotl64(t, 41); t = bc0
        bc0 = st[19]; st[19] = _rotl64(t, 56); t = bc0
        bc0 = st[13]; st[13] = _rotl64(t, 8); t = bc0
        bc0 = st[12]; st[12] = _rotl64(t, 25); t = bc0
        bc0 = st[2]; st[2] = _rotl64(t, 43); t = bc0
        bc0 = st[20]; st[20] = _rotl64(t, 62); t = bc0
        bc0 = st[14]; st[14] = _rotl64(t, 18); t = bc0
        bc0 = st[22]; st[22] = _rotl64(t, 39); t = bc0
        bc0 = st[9]; st[9] = _rotl64(t, 61); t = bc0
        bc0 = st[6]; st[6] = _rotl64(t, 20); t = bc0
        st[1] = _rotl64(t, 44)

        bc0, bc1, bc2, bc3, bc4 = st[0], st[1], st[2], st[3], st[4]
        st[0] = (bc0 ^ (~bc1 & bc2) ^ rndc) & _MASK64
        st[1] = (bc1 ^ (~bc2 & bc3)) & _MASK64
        st[2] = (bc2 ^ (~bc3 & bc4)) & _MASK64
        st[3] = (bc3 ^ (~bc4 & bc0)) & _MASK64
        st[4] = (bc4 ^ (~bc0 & bc1)) & _MASK64
        bc0, bc1, bc2, bc3, bc4 = st[5], st[6], st[7], st[8], st[9]
        st[5] = (bc0 ^ (~bc1 & bc2)) & _MASK64
        st[6] = (bc1 ^ (~bc2 & bc3)) & _MASK64
        st[7] = (bc2 ^ (~bc3 & bc4)) & _MASK64
        st[8] = (bc3 ^ (~bc4 & bc0)) & _MASK64
        st[9] = (bc4 ^ (~bc0 & bc1)) & _MASK64
        bc0, bc1, bc2, bc3, bc4 = st[10], st[11], st[12], st[13], st[14]
        st[10] = (bc0 ^ (~bc1 & bc2)) & _MASK64
        st[11] = (bc1 ^ (~bc2 & bc3)) & _MASK64
        st[12] = (bc2 ^ (~bc3 & bc4)) & _MASK64
        st[13] = (bc3 ^ (~bc4 & bc0)) & _MASK64
        st[14] = (bc4 ^ (~bc0 & bc1)) & _MASK64
        bc0, bc1, bc2, bc3, bc4 = st[15], st[16], st[17], st[18], st[19]
        st[15] = (bc0 ^ (~bc1 & bc2)) & _MASK64
        st[16] = (bc1 ^ (~bc2 & bc3)) & _MASK64
        st[17] = (bc2 ^ (~bc3 & bc4)) & _MASK64
        st[18] = (bc3 ^ (~bc4 & bc0)) & _MASK64
        st[19] = (bc4 ^ (~bc0 & bc1)) & _MASK64
        bc0, bc1, bc2, bc3, bc4 = st[20], st[21], st[22], st[23], st[24]
        st[20] = (bc0 ^ (~bc1 & bc2)) & _MASK64
        st[21] = (bc1 ^ (~bc2 & bc3)) & _MASK64
        st[22] = (bc2 ^ (~bc3 & bc4)) & _MASK64
        st[23] = (bc3 ^ (~bc4 & bc0)) & _MASK64
        st[24] = (bc4 ^ (~bc0 & bc1)) & _MASK64


class _SHA3_256:
    """Bitcoin Core SHA3_256 sponge (rate 1088), with selectable domain byte."""

    RATE_BUFFERS = 17

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> "_SHA3_256":
        self._state = [0] * 25
        self._buffer = bytearray(8)
        self._bufsize = 0
        self._pos = 0
        return self

    def write(self, data: bytes) -> "_SHA3_256":
        i = 0
        n = len(data)
        if self._bufsize and n >= 8 - self._bufsize:
            need = 8 - self._bufsize
            self._buffer[self._bufsize:] = data[i:i + need]
            i += need
            self._state[self._pos] ^= struct.unpack_from("<Q", self._buffer)[0]
            self._bufsize = 0
            self._pos += 1
            if self._pos == self.RATE_BUFFERS:
                _keccak_f(self._state)
                self._pos = 0
        while n - i >= 8:
            self._state[self._pos] ^= struct.unpack_from("<Q", data, i)[0]
            i += 8
            self._pos += 1
            if self._pos == self.RATE_BUFFERS:
                _keccak_f(self._state)
                self._pos = 0
        if i < n:
            remain = n - i
            self._buffer[:remain] = data[i:]
            self._bufsize = remain
        return self

    def finalize(self, delim: int = 0x06) -> bytes:
        buf = bytearray(8)
        buf[:self._bufsize] = self._buffer[:self._bufsize]
        buf[self._bufsize] ^= delim
        self._state[self._pos] ^= struct.unpack_from("<Q", buf)[0]
        self._state[self.RATE_BUFFERS - 1] ^= 0x8000000000000000
        _keccak_f(self._state)
        return b"".join(struct.pack("<Q", self._state[i]) for i in range(4))


def _cshake_prefix(custom: bytes) -> bytes:
    # bytepad(encode_string("") || encode_string(S), 136) for cSHAKE256
    buf = bytearray(136)
    buf[0] = 1
    buf[1] = 136
    buf[2] = 1
    buf[3] = 0
    buf[4] = 1
    buf[5] = len(custom) * 8
    buf[6:6 + len(custom)] = custom
    return bytes(buf)


class _XoShiRo256PlusPlus:
    def __init__(self, seed: bytes) -> None:
        self.s = list(struct.unpack("<4Q", seed))

    def __call__(self) -> int:
        s0, s1, s2, s3 = self.s
        result = (_rotl64((s0 + s3) & _MASK64, 23) + s0) & _MASK64
        t = (s1 << 17) & _MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = _rotl64(s3, 45)
        self.s = [s0 & _MASK64, s1 & _MASK64, s2 & _MASK64, s3]
        return result


def _is_full_rank(matrix: list[list[int]]) -> bool:
    b = [[float(matrix[i][j]) for j in range(64)] for i in range(64)]
    rank = 0
    row_selected = [False] * 64
    for i in range(64):
        j = 0
        while j < 64:
            if (not row_selected[j]) and abs(b[j][i]) > _EPS:
                break
            j += 1
        if j != 64:
            rank += 1
            row_selected[j] = True
            for p in range(i + 1, 64):
                b[j][p] /= b[j][i]
            for k in range(64):
                if k != j and abs(b[k][i]) > _EPS:
                    for p in range(i + 1, 64):
                        b[k][p] -= b[j][p] * b[k][i]
    return rank == 64


def _generate_matrix(generator: _XoShiRo256PlusPlus) -> list[list[int]]:
    while True:
        matrix = [[0] * 64 for _ in range(64)]
        for i in range(64):
            for j in range(0, 64, 16):
                value = generator()
                for shift in range(16):
                    matrix[i][j + shift] = (value >> (4 * shift)) & 0xF
        if _is_full_rank(matrix):
            return matrix


@functools.lru_cache(maxsize=64)
def _matrix_for_seed(seed: bytes) -> tuple[tuple[int, ...], ...]:
    # The matrix depends only on the pre-PoW seed, which is constant while a
    # nonce is ground; regenerating it per nonce dominates hashing cost.
    return tuple(tuple(row) for row in _generate_matrix(_XoShiRo256PlusPlus(seed)))


class KHeavyHash:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("kHeavyHash seed must be 32 bytes")
        self._hasher = _SHA3_256()
        self._hasher.write(_cshake_prefix(b"ProofOfWorkHash"))
        self._matrix = _matrix_for_seed(bytes(seed))

    def write(self, data: bytes) -> "KHeavyHash":
        self._hasher.write(data)
        return self

    def finalize(self) -> bytes:
        hash_first = self._hasher.finalize(0x04)
        vector = []
        for byte in hash_first:
            vector.append(byte >> 4)
            vector.append(byte & 0xF)
        product = []
        for i in range(64):
            total = 0
            for j in range(64):
                total = (total + self._matrix[i][j] * vector[j]) & 0xFFFF
            product.append(total >> 10)
        hash_second = bytes((product[2 * i] << 4) | product[2 * i + 1] for i in range(32))
        hash_xored = bytes(a ^ b for a, b in zip(hash_first, hash_second))
        hasher = _SHA3_256()
        hasher.write(_cshake_prefix(b"HeavyHash"))
        hasher.write(hash_xored)
        return hasher.finalize(0x04)


def kheavyhash(work_order: bytes) -> bytes:
    """80-byte work order: prePowHash || time || 32 zero bytes || nonce."""
    if len(work_order) != 80:
        raise ValueError(f"work order must be 80 bytes, got {len(work_order)}")
    seed = work_order[:32]
    return KHeavyHash(seed).write(work_order).finalize()
