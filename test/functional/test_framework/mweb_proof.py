#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent LIP-0006 HASH_ONLY segment commitment verification for tests."""

import bisect
import copy
import struct
from io import BytesIO
from types import SimpleNamespace
import unittest

from test_framework.messages import Hash, MWEB_UTXO_FORMAT_HASH_ONLY, blake3, msg_mwebutxos


def segment_root(num_txos, message):
    """Rebuild the PMMR root from output IDs and ordered subtree proof hashes.

    Reconstruct each binary mountain by its leaf interval, then bag its peaks.
    Unlike the C++ producer, this does not derive sibling/pruned-parent indices.
    Uncovered subtrees consume proof hashes in postorder; a final proof hash bags
    all peaks to the right of the segment. Reject redundant or missing hashes.
    """
    assert message.output_format == MWEB_UTXO_FORMAT_HASH_ONLY
    indices = [u.leaf_index for u in message.utxos]
    assert indices and indices == sorted(set(indices))
    assert 0 <= indices[0] <= indices[-1] < num_txos
    assert message.start_index == indices[0]
    proofs = iter(message.proof_hashes)

    def take_proof():
        value = next(proofs, None)
        assert value is not None, "missing segment proof hash"
        return value

    def parent(position, left, right):
        return blake3(struct.pack('<Q', position) + left.serialize() + right.serialize())

    def mountain(first, count, root_position):
        lo = bisect.bisect_left(indices, first)
        hi = bisect.bisect_left(indices, first + count)
        if lo == hi:
            return take_proof()
        if count == 1:
            # libmw hashes a serialized vector: CompactSize(32) precedes the ID.
            return blake3(struct.pack('<Q', root_position) + b'\x20' + message.utxos[lo].output.serialize())
        half = count // 2
        left = mountain(first, half, root_position - count)
        right = mountain(first + half, half, root_position - 1)
        return parent(root_position, left, right)

    peaks = []
    first = position = 0
    lower_peak = None
    for bit in reversed(range(num_txos.bit_length())):
        count = 1 << bit
        if not num_txos & count:
            continue
        if first > indices[-1]:
            lower_peak = take_proof()
            break
        peaks.append(mountain(first, count, position + 2 * count - 2))
        first += count
        position += 2 * count - 1
    assert next(proofs, None) is None, "unused segment proof hash"
    root = lower_peak
    next_position = 2 * num_txos - num_txos.bit_count()
    for peak in reversed(peaks):
        root = peak if root is None else parent(next_position, peak, root)
    assert root is not None
    return root


class TestMWEBProof(unittest.TestCase):
    def test_wire_proof_hashes(self):
        # Fixed wire fields, including an output ID and distinct proof bytes.
        # Hash.deserialize returns a new object; the generic in-place vector
        # decoder used to consume these bytes but leave every proof as Hash(0).
        block_hash = bytes(range(32))
        output_id = bytes(reversed(range(32)))
        proof_hashes = [bytes([i]) * 32 for i in (0, 0x35, 0xA7)]
        prefix = block_hash + b'\x00\x01\x01\x00' + output_id
        for count in range(4):
            with self.subTest(proof_count=count):
                wire = prefix + bytes([count]) + b''.join(proof_hashes[:count])
                stream = BytesIO(wire)
                message = msg_mwebutxos()
                message.deserialize(stream)
                self.assertEqual(stream.read(), b'')
                self.assertEqual(message.block_hash.serialize(), block_hash)
                self.assertEqual(message.utxos[0].output.serialize(), output_id)
                self.assertEqual([h.serialize() for h in message.proof_hashes], proof_hashes[:count])
                self.assertEqual(message.serialize(), wire)

    def test_segment_commitment_and_mutations(self):
        # Three output IDs: a two-leaf mountain plus a one-leaf peak.
        outputs = [Hash(i) for i in (11, 22, 33)]
        leaves = [blake3(struct.pack('<Q', pos) + b'\x20' + out.serialize())
                  for pos, out in zip((0, 1, 3), outputs)]
        first_peak = blake3(struct.pack('<Q', 2) + leaves[0].serialize() + leaves[1].serialize())
        expected = blake3(struct.pack('<Q', 4) + first_peak.serialize() + leaves[2].serialize())
        def page(indices, proofs):
            return SimpleNamespace(output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
                                   start_index=indices[0], proof_hashes=proofs,
                                   utxos=[SimpleNamespace(leaf_index=i, output=outputs[i]) for i in indices])
        pages = [page([0], [leaves[1], leaves[2]]),
                 page([1], [leaves[0], leaves[2]]),
                 page([2], [first_peak]),
                 page([0, 2], [leaves[1]]),
                 page([0, 1, 2], [])]
        for valid in pages:
            with self.subTest(indices=[u.leaf_index for u in valid.utxos]):
                self.assertEqual(segment_root(3, valid), expected)
                changed = copy.deepcopy(valid)
                changed.utxos[0].output = Hash(44)
                self.assertNotEqual(segment_root(3, changed), expected)
                changed = copy.deepcopy(valid)
                changed.proof_hashes.append(Hash(55))
                with self.assertRaises(AssertionError):
                    segment_root(3, changed)
                if valid.proof_hashes:
                    changed = copy.deepcopy(valid)
                    changed.proof_hashes[0] = Hash(66)
                    self.assertNotEqual(segment_root(3, changed), expected)
                    changed.proof_hashes.pop()
                    with self.assertRaises(AssertionError):
                        segment_root(3, changed)
        invalid = page([1, 0], [])
        with self.assertRaises(AssertionError):
            segment_root(3, invalid)
