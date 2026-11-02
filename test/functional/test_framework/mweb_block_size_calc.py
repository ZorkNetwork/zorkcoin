#!/usr/bin/env python3
# Copyright (c) 2026 The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact serialized-block size model for L1 + MWEB blocks.

Derived from source serialization:

  CBlock = CBlockHeader(80)
         + CompactSize(|vtx|) + sum(serialize_with_mweb(tx))
         + [if last tx is HogEx: OptionalPtr(mw::Block)]

  mw::Block (inside OptionalPtr) = Header + TxBody
  TxBody   = CompactSize vectors of Input / Output / Kernel

MWEB mempool txs are merged into one extension body. They do not appear as
separate L1 vtx entries (MWEB-only stubs contribute 0 L1 bytes). "MWEB
transactions" in the high-level API therefore maps to kernels.

Headers are not fixed-width: the MWEB header uses Bitcoin VarInts for height
and cumulative MMR leaf counts. L1 blob space is modeled explicitly because
witness / scriptSig / OP_RETURN can be arbitrary.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Consensus / wire constants (from src/)
# ---------------------------------------------------------------------------

L1_HEADER_BYTES = 80  # version+prev+merkle+time+bits+nonce

# mw::INPUT_BYTES with STEALTH_KEY_FEATURE_BIT, no extra_data
MWEB_INPUT_STANDARD = 196  # 1+32+33+33+33+64

# Standard output: commitment+sender+receiver+message(std)+rangeproof+sig
# message = features(1)+Ke(33)+view_tag(1)+masked_value(8)+masked_nonce(16) = 59
MWEB_OUTPUT_STANDARD = 897  # 33+33+33+59+675+64
MWEB_RANGEPROOF = 675

# Kernel feature bits (mw::Kernel)
KERN_FEE = 0x01
KERN_PEGIN = 0x02
KERN_PEGOUT = 0x04
KERN_HEIGHT_LOCK = 0x08
KERN_STEALTH = 0x10
KERN_EXTRA = 0x20

# Fixed crypto field sizes
SIZE_HASH = 32
SIZE_COMMITMENT = 33
SIZE_PUBKEY = 33
SIZE_SIGNATURE = 64
SIZE_BLINDING = 32

# L1 standard shapes
CTXIN_EMPTY_SCRIPTSIG = 41          # 32+4+1+4
P2WPKH_SPK = 22                     # OP_0 <20>
PEGIN_SPK = 34                      # OP_9 <32>  (MWEB_PEGIN_WITNESS_VERSION=9)
HOGADDR_SPK = 34                    # OP_8 <32>
P2WPKH_WITNESS_ITEMS = (71, 33)     # low-S DER sig + compressed pubkey (typical)

# Caps (informational)
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB = 25_800_195
MAX_BLOCK_SERIALIZED_SIZE_BIP324 = 16_777_214
MW_MAX_NUM_INPUTS = 50_000
MW_MAX_BLOCK_WEIGHT = 200_000
MW_INPUT_BYTES = MWEB_INPUT_STANDARD


# ---------------------------------------------------------------------------
# Encoding helpers (Bitcoin Core CompactSize + VarInt)
# ---------------------------------------------------------------------------

def compact_size_len(n: int) -> int:
    if n < 0:
        raise ValueError("CompactSize cannot be negative")
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def varint_len(n: int) -> int:
    """Bitcoin Core WriteVarInt length (MSB continuation, n=(n>>7)-1 loop)."""
    if n < 0:
        raise ValueError("VarInt cannot be negative")
    length = 0
    while True:
        length += 1
        if n <= 0x7F:
            return length
        n = (n >> 7) - 1


def ser_string_len(payload_len: int) -> int:
    return compact_size_len(payload_len) + payload_len


# ---------------------------------------------------------------------------
# L1 transaction / HogEx / coinbase
# ---------------------------------------------------------------------------

def p2wpkh_witness_len(sig_len: int = 71, pubkey_len: int = 33) -> int:
    """Witness stack for one P2WPKH input (count + items)."""
    return (
        compact_size_len(2)
        + ser_string_len(sig_len)
        + ser_string_len(pubkey_len)
    )


def ctxout_len(script_pubkey_len: int) -> int:
    return 8 + ser_string_len(script_pubkey_len)


def l1_tx_size(
    n_inputs: int,
    output_spk_lens: Sequence[int],
    *,
    witness_bytes_per_input: Optional[Sequence[int]] = None,
    sig_len: int = 71,
    extra_scriptsig_bytes: int = 0,
    extra_witness_bytes: int = 0,
    hogex: bool = False,
    has_mweb_tx: bool = False,
    mweb_tx_bytes: int = 0,
    version_bytes: int = 4,
    locktime_bytes: int = 4,
) -> int:
    """Exact serialize_with_mweb size for one L1 transaction.

    `extra_scriptsig_bytes` / `extra_witness_bytes` are the L1 "blob" knobs:
    additional bytes beyond empty scriptSig / standard P2WPKH witness.
    """
    if n_inputs < 0:
        raise ValueError("n_inputs")
    n_outputs = len(output_spk_lens)

    flags = 0
    # Witness present if any per-input witness or default P2WPKH witnesses.
    has_witness = True
    if witness_bytes_per_input is not None:
        has_witness = any(w > 0 for w in witness_bytes_per_input) or extra_witness_bytes > 0
    if has_witness:
        flags |= 1
    if hogex or has_mweb_tx:
        flags |= 8

    size = version_bytes
    if flags:
        size += 1  # marker = empty vin vector CompactSize(0)
        size += 1  # flags byte

    size += compact_size_len(n_inputs)
    # Each input: 41 + any extra scriptSig bytes (replacing the empty scriptSig's 1-byte CS)
    # Empty scriptSig contributes 1 byte (CompactSize 0) inside the 41.
    # Extra blob bytes are appended inside scriptSig -> +extra (and possibly +CS growth).
    # Model: base 41 per input, plus ser_string growth for blob beyond empty.
    # empty scriptSig ser_string_len(0)=1 already in 41. If blob_i bytes total scriptSig:
    #   delta = ser_string_len(blob) - 1
    if extra_scriptsig_bytes == 0:
        size += n_inputs * CTXIN_EMPTY_SCRIPTSIG
    else:
        # Put all blob on input 0; others empty. Exact under that placement.
        size += (n_inputs - 1) * CTXIN_EMPTY_SCRIPTSIG if n_inputs else 0
        if n_inputs:
            # 32+4 + scriptSig + 4
            size += 32 + 4 + ser_string_len(extra_scriptsig_bytes) + 4

    size += compact_size_len(n_outputs)
    size += sum(ctxout_len(spk) for spk in output_spk_lens)

    if flags & 1:
        if witness_bytes_per_input is not None:
            if len(witness_bytes_per_input) != n_inputs:
                raise ValueError("witness_bytes_per_input length must match n_inputs")
            size += sum(witness_bytes_per_input)
        else:
            size += n_inputs * p2wpkh_witness_len(sig_len)
        size += extra_witness_bytes

    if flags & 8:
        # OptionalPtr(mweb_tx): 0x00 or 0x01 || tx
        if has_mweb_tx:
            size += 1 + mweb_tx_bytes
        else:
            size += 1  # null (HogEx path)

    size += locktime_bytes
    return size


def hogex_size(
    n_vin: int,
    n_pegouts: int = 0,
    *,
    pegout_spk_len: int = P2WPKH_SPK,
) -> int:
    """HogEx: flag 0x08, no witness, null mweb_tx, HogAddr + peg-outs."""
    outs = [HOGADDR_SPK] + [pegout_spk_len] * n_pegouts
    return l1_tx_size(
        n_vin,
        outs,
        witness_bytes_per_input=[0] * n_vin if n_vin else [],
        hogex=True,
        has_mweb_tx=False,
        extra_witness_bytes=0,
    )


def coinbase_size_regtest_typical() -> int:
    """Measured regtest coinbase with BIP34 height + P2PKH + witness commitment.

    Not consensus-constant - override via BlockModel.coinbase_bytes for exactness.
    """
    return 171


# ---------------------------------------------------------------------------
# MWEB header / body / components
# ---------------------------------------------------------------------------

def mweb_input_size(*, stealth_key: bool = True, extra_data: int = 0) -> int:
    size = 1 + SIZE_HASH + SIZE_COMMITMENT + SIZE_PUBKEY  # features+output_id+commit+output_pk
    if stealth_key:
        size += SIZE_PUBKEY
    if extra_data:
        size += ser_string_len(extra_data)
    size += SIZE_SIGNATURE
    return size


def mweb_output_size(*, standard_fields: bool = True, extra_data: int = 0) -> int:
    size = SIZE_COMMITMENT + SIZE_PUBKEY + SIZE_PUBKEY  # commit+sender+receiver
    # OutputMessage
    size += 1  # features
    if standard_fields:
        size += SIZE_PUBKEY + 1 + 8 + 16  # Ke + view_tag + masked_value + masked_nonce
    if extra_data:
        size += ser_string_len(extra_data)
    size += MWEB_RANGEPROOF
    size += SIZE_SIGNATURE
    return size


def mweb_kernel_size(
    features: int,
    *,
    fee: int = 0,
    pegin: int = 0,
    pegouts: Sequence[Tuple[int, int]] = (),
    lock_height: int = 0,
    extra_data: int = 0,
) -> int:
    """pegouts: list of (amount, script_pubkey_len)."""
    size = 1  # features
    if features & KERN_FEE:
        size += varint_len(fee)
    if features & KERN_PEGIN:
        size += varint_len(pegin)
    if features & KERN_PEGOUT:
        size += compact_size_len(len(pegouts))
        for amount, spk_len in pegouts:
            size += varint_len(amount) + ser_string_len(spk_len)
    if features & KERN_HEIGHT_LOCK:
        size += varint_len(lock_height)
    if features & KERN_STEALTH:
        size += SIZE_PUBKEY
    if features & KERN_EXTRA:
        size += ser_string_len(extra_data)
    size += SIZE_COMMITMENT + SIZE_SIGNATURE
    return size


def mweb_header_size(height: int, num_txos: int, num_kernels: int) -> int:
    """mw::Header - 5x32-byte fields + 3 VarInts (height, MMR sizes)."""
    return (
        varint_len(height)
        + 5 * SIZE_HASH  # output/kernel/leafset roots + kernel/stealth offsets
        + varint_len(num_txos)
        + varint_len(num_kernels)
    )


def mweb_body_size(
    n_inputs: int,
    n_outputs: int,
    kernel_sizes: Sequence[int],
    *,
    input_size: int = MWEB_INPUT_STANDARD,
    output_size: int = MWEB_OUTPUT_STANDARD,
    input_extra_total: int = 0,
) -> int:
    """TxBody vector encoding. input_extra_total adds bytes beyond standard inputs."""
    n_kernels = len(kernel_sizes)
    return (
        compact_size_len(n_inputs)
        + n_inputs * input_size
        + input_extra_total
        + compact_size_len(n_outputs)
        + n_outputs * output_size
        + compact_size_len(n_kernels)
        + sum(kernel_sizes)
    )


def mweb_extension_size(header_bytes: int, body_bytes: int) -> int:
    """OptionalPtr present flag + mw::Block (header shared_ptr has no extra flag)."""
    return 1 + header_bytes + body_bytes


# ---------------------------------------------------------------------------
# Full block
# ---------------------------------------------------------------------------

@dataclass
class BlockModel:
    """Fully-specified block for an exact size.

    Economic L1 txs are listed explicitly (each with its own I/O/witness).
    MWEB body is specified by counts + kernel size list (or feature recipe).
    """

    # Economic L1 (excludes coinbase + HogEx)
    l1_txs: List[int] = field(default_factory=list)  # precomputed sizes
    coinbase_bytes: int = 171
    # HogEx / MWEB
    include_mweb: bool = False
    hogex_vin: int = 0
    hogex_pegouts: int = 0
    hogex_pegout_spk_len: int = P2WPKH_SPK
    mweb_inputs: int = 0
    mweb_outputs: int = 0
    kernel_sizes: List[int] = field(default_factory=list)
    mweb_height: int = 0
    mweb_num_txos: int = 0       # cumulative MMR leaves AFTER this block
    mweb_num_kernels_mmr: int = 0
    mweb_input_size: int = MWEB_INPUT_STANDARD
    mweb_output_size: int = MWEB_OUTPUT_STANDARD
    mweb_input_extra_total: int = 0

    def hogex_bytes(self) -> int:
        if not self.include_mweb:
            return 0
        return hogex_size(
            self.hogex_vin,
            self.hogex_pegouts,
            pegout_spk_len=self.hogex_pegout_spk_len,
        )

    def n_vtx(self) -> int:
        n = 1 + len(self.l1_txs)  # coinbase + economic
        if self.include_mweb:
            n += 1  # HogEx
        return n

    def mweb_header_bytes(self) -> int:
        return mweb_header_size(self.mweb_height, self.mweb_num_txos, self.mweb_num_kernels_mmr)

    def mweb_body_bytes(self) -> int:
        return mweb_body_size(
            self.mweb_inputs,
            self.mweb_outputs,
            self.kernel_sizes,
            input_size=self.mweb_input_size,
            output_size=self.mweb_output_size,
            input_extra_total=self.mweb_input_extra_total,
        )

    def mweb_ext_bytes(self) -> int:
        if not self.include_mweb:
            return 0
        return mweb_extension_size(self.mweb_header_bytes(), self.mweb_body_bytes())

    def serialized_size(self) -> int:
        tx_sum = self.coinbase_bytes + sum(self.l1_txs)
        if self.include_mweb:
            tx_sum += self.hogex_bytes()
        return (
            L1_HEADER_BYTES
            + compact_size_len(self.n_vtx())
            + tx_sum
            + self.mweb_ext_bytes()
        )

    def breakdown(self) -> dict:
        return {
            "l1_header": L1_HEADER_BYTES,
            "vtx_compactsize": compact_size_len(self.n_vtx()),
            "n_vtx": self.n_vtx(),
            "coinbase": self.coinbase_bytes,
            "l1_economic_sum": sum(self.l1_txs),
            "l1_economic_count": len(self.l1_txs),
            "hogex": self.hogex_bytes(),
            "mweb_header": self.mweb_header_bytes() if self.include_mweb else 0,
            "mweb_body": self.mweb_body_bytes() if self.include_mweb else 0,
            "mweb_ext": self.mweb_ext_bytes(),
            "total": self.serialized_size(),
        }


def partition_counts(total: int, buckets: int) -> List[int]:
    """Deterministic even partition (first `total % buckets` get +1)."""
    if buckets < 0:
        raise ValueError("buckets")
    if buckets == 0:
        if total:
            raise ValueError("cannot place nonzero items into 0 buckets")
        return []
    base, rem = divmod(total, buckets)
    return [base + (1 if i < rem else 0) for i in range(buckets)]


def block_size_from_counts(
    *,
    l1_inputs: int,
    l1_transactions: int,
    l1_outputs: int,
    mweb_inputs: int,
    mweb_transactions: int,
    mweb_outputs: int,
    l1_blob_bytes: int = 0,
    # --- refinements required for bit-exact results ---
    n_pegin_outputs: int = 0,
    n_pegout: int = 0,
    hogex_prev_input: bool = True,
    mweb_height: int = 1,
    mweb_num_txos: Optional[int] = None,
    mweb_num_kernels_mmr: Optional[int] = None,
    coinbase_bytes: int = 171,
    sig_len: int = 71,
    kernel_fee: int = 3900,
    kernel_features: int = KERN_FEE | KERN_STEALTH,
    pegin_kernel_features: int = KERN_FEE | KERN_PEGIN | KERN_STEALTH,
    pegout_kernel_features: int = KERN_FEE | KERN_PEGOUT | KERN_STEALTH,
    pegin_amount: int = 100_000_000,
    pegout_amount: int = 100_000,
    pegout_spk_len: int = P2WPKH_SPK,
    kernel_sizes: Optional[Sequence[int]] = None,
    l1_tx_sizes: Optional[Sequence[int]] = None,
    include_mweb: Optional[bool] = None,
) -> Tuple[int, dict]:
    """Multi-variable block size under a deterministic packing policy.

    When every structural parameter below is supplied (especially `l1_tx_sizes`
    and `kernel_sizes`), the result is bit-exact for that structure. With only
    the six count arguments, the even-partition + standard-component policy is
    applied - still exact *for that policy*, but a real heterogeneous block can
    differ by sig/varint width and output-type mix (tens-hundreds of bytes).

    Parameters
    ----------
    l1_inputs, l1_outputs, l1_transactions
        Economic L1 only (no coinbase, no HogEx). Inputs/outputs are partitioned
        evenly across `l1_transactions`. First `n_pegin_outputs` outputs globally
        are typed as peg-in (34 B scriptPubKey); the rest are P2WPKH (22 B).
        Ignored for L1 sizing when `l1_tx_sizes` is provided (counts still used
        for validation/metadata).
    mweb_inputs, mweb_outputs, mweb_transactions
        Extension-body counts. `mweb_transactions` == number of kernels.
    l1_blob_bytes
        Extra L1 witness payload beyond the P2WPKH baseline, placed on the first
        economic tx (exact under that placement). Ignored if `l1_tx_sizes` set.
    n_pegin_outputs / n_pegout
        Drive HogEx vin/vout growth and kernel feature mix.
        HogEx vin = (1 if hogex_prev_input else 0) + n_pegin_outputs.
    mweb_num_txos / mweb_num_kernels_mmr
        Cumulative MMR sizes in the MWEB header (NOT per-block counts).
        Default: assume equals this block's body output/kernel counts.
    kernel_sizes / l1_tx_sizes
        Optional exact per-item sizes; length must match the corresponding count.

    Returns (size, breakdown).
    """
    if l1_transactions < 0 or l1_inputs < 0 or l1_outputs < 0:
        raise ValueError("L1 counts must be non-negative")
    if mweb_inputs < 0 or mweb_outputs < 0 or mweb_transactions < 0:
        raise ValueError("MWEB counts must be non-negative")
    if l1_transactions == 0 and (l1_inputs or l1_outputs or l1_blob_bytes):
        raise ValueError("L1 I/O/blob require l1_transactions >= 1")
    if n_pegin_outputs > l1_outputs:
        raise ValueError("n_pegin_outputs cannot exceed l1_outputs")
    if n_pegin_outputs + n_pegout > mweb_transactions and mweb_transactions:
        # Soft warning via breakdown only - peg-in/out kernels are a subset.
        pass

    if include_mweb is None:
        include_mweb = (mweb_inputs + mweb_outputs + mweb_transactions) > 0

    # --- L1 economic txs ---
    if l1_tx_sizes is not None:
        if len(l1_tx_sizes) != l1_transactions:
            raise ValueError("l1_tx_sizes length must equal l1_transactions")
        l1_sizes = list(l1_tx_sizes)
    else:
        in_parts = partition_counts(l1_inputs, l1_transactions) if l1_transactions else []
        out_parts = partition_counts(l1_outputs, l1_transactions) if l1_transactions else []

        # Assign peg-in outputs to the earliest output slots across txs.
        peg_remaining = n_pegin_outputs
        l1_sizes = []
        for i, (ni, no) in enumerate(zip(in_parts, out_parts)):
            spk_lens: List[int] = []
            for _ in range(no):
                if peg_remaining > 0:
                    spk_lens.append(PEGIN_SPK)
                    peg_remaining -= 1
                else:
                    spk_lens.append(P2WPKH_SPK)
            blob = l1_blob_bytes if i == 0 else 0
            l1_sizes.append(
                l1_tx_size(
                    ni,
                    spk_lens,
                    sig_len=sig_len,
                    extra_scriptsig_bytes=0,
                    extra_witness_bytes=blob,
                )
            )

    # --- kernels ---
    if kernel_sizes is not None:
        if len(kernel_sizes) != mweb_transactions:
            raise ValueError("kernel_sizes length must equal mweb_transactions")
        kern_sizes = list(kernel_sizes)
    else:
        # First n_pegin_outputs -> peg-in, next n_pegout -> peg-out, else fee+stealth.
        kern_sizes = []
        for i in range(mweb_transactions):
            if i < n_pegin_outputs:
                kern_sizes.append(
                    mweb_kernel_size(
                        pegin_kernel_features,
                        fee=kernel_fee,
                        pegin=pegin_amount,
                    )
                )
            elif i < n_pegin_outputs + n_pegout:
                kern_sizes.append(
                    mweb_kernel_size(
                        pegout_kernel_features,
                        fee=kernel_fee,
                        pegouts=[(pegout_amount, pegout_spk_len)],
                    )
                )
            else:
                kern_sizes.append(
                    mweb_kernel_size(kernel_features, fee=kernel_fee)
                )

    if mweb_num_txos is None:
        mweb_num_txos = mweb_outputs
    if mweb_num_kernels_mmr is None:
        mweb_num_kernels_mmr = mweb_transactions

    hogex_vin = 0
    if include_mweb:
        hogex_vin = (1 if hogex_prev_input else 0) + n_pegin_outputs

    model = BlockModel(
        l1_txs=l1_sizes,
        coinbase_bytes=coinbase_bytes,
        include_mweb=include_mweb,
        hogex_vin=hogex_vin,
        hogex_pegouts=n_pegout,
        hogex_pegout_spk_len=pegout_spk_len,
        mweb_inputs=mweb_inputs,
        mweb_outputs=mweb_outputs,
        kernel_sizes=kern_sizes,
        mweb_height=mweb_height,
        mweb_num_txos=mweb_num_txos,
        mweb_num_kernels_mmr=mweb_num_kernels_mmr,
    )
    total = model.serialized_size()
    detail = model.breakdown()
    detail.update(
        {
            "policy": "even_partition_l1",
            "l1_inputs": l1_inputs,
            "l1_outputs": l1_outputs,
            "l1_transactions": l1_transactions,
            "l1_blob_bytes": l1_blob_bytes,
            "mweb_inputs": mweb_inputs,
            "mweb_outputs": mweb_outputs,
            "mweb_transactions_kernels": mweb_transactions,
            "n_pegin_outputs": n_pegin_outputs,
            "n_pegout": n_pegout,
            "hogex_vin": hogex_vin,
            "caps": {
                "bip324": MAX_BLOCK_SERIALIZED_SIZE_BIP324,
                "envelope": MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB,
                "l1_legacy": MAX_BLOCK_SERIALIZED_SIZE,
            },
            "vs_bip324": total - MAX_BLOCK_SERIALIZED_SIZE_BIP324,
            "vs_envelope": total - MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB,
        }
    )
    return total, detail


# ---------------------------------------------------------------------------
# Closed-form (when every tx identical / standard components)
# ---------------------------------------------------------------------------

def formula_mweb_body(
    n_in: int,
    n_out: int,
    n_kern: int,
    *,
    input_bytes: int = MWEB_INPUT_STANDARD,
    output_bytes: int = MWEB_OUTPUT_STANDARD,
    kernel_bytes: int = 133,
) -> int:
    """S_body = CS(n_in)+n_in*I + CS(n_out)+n_out*O + CS(n_k)+n_k*K."""
    return (
        compact_size_len(n_in) + n_in * input_bytes
        + compact_size_len(n_out) + n_out * output_bytes
        + compact_size_len(n_kern) + n_kern * kernel_bytes
    )


class TestFrameworkMwebBlockSizeCalc(unittest.TestCase):
    def test_primitives(self):
        self.assertEqual(mweb_input_size(), 196)
        self.assertEqual(mweb_output_size(), 897)
        self.assertEqual(mweb_kernel_size(KERN_FEE | KERN_STEALTH, fee=3900), 133)
        self.assertEqual(hogex_size(416, 0), 17114)
        self.assertEqual(l1_tx_size(1, [P2WPKH_SPK], sig_len=71), 191)
        self.assertEqual(l1_tx_size(1, [P2WPKH_SPK, P2WPKH_SPK], sig_len=71), 222)
        self.assertEqual(l1_tx_size(1, [PEGIN_SPK], sig_len=71), 203)
        self.assertEqual(l1_tx_size(8, [P2WPKH_SPK, P2WPKH_SPK], sig_len=71), 1258)

    def test_block_from_counts(self):
        size, detail = block_size_from_counts(
            l1_inputs=10,
            l1_transactions=10,
            l1_outputs=10,
            mweb_inputs=100,
            mweb_transactions=50,
            mweb_outputs=50,
            n_pegin_outputs=0,
            hogex_prev_input=True,
            mweb_height=100,
            mweb_num_txos=50,
            mweb_num_kernels_mmr=50,
        )
        self.assertEqual(size, detail["total"])
