#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Weight-first production-cap fill plan for MWEB size functionals.

Fills singular consensus maxima (not the pessimistic wire ceiling):

  1. MWEB weight → mw::MAX_BLOCK_WEIGHT (200_000) via consolidations + partials
  2. MWEB inputs → mw::MAX_NUM_INPUTS (50_000) via weightless inputs on those txs
  3. L1 weight → MAX_BLOCK_WEIGHT (4_000_000) via 100-in P2WPKH pads

Standard wallet shapes achieve ~21.8-21.9 MB wire (below MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB).
OP_RETURN trim (in mweb_size_util) fine-tunes the last bytes to an exact target_S.
"""

from __future__ import annotations

from dataclasses import dataclass

from test_framework.mweb_block_size_calc import (
    MAX_BLOCK_SERIALIZED_SIZE_BIP324,
    MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB,
    CTXIN_EMPTY_SCRIPTSIG,
    P2WPKH_SPK,
    block_size_from_counts,
    compact_size_len,
    ctxout_len,
    l1_tx_size,
)

MWEB_ENVELOPE = MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB
BIP324_CAP = MAX_BLOCK_SERIALIZED_SIZE_BIP324

MW_WEIGHT_CONSOL = 21  # stealth kernel + 1 standard output
MW_WEIGHT_PARTIAL = 39  # stealth kernel + 2 standard outputs
MWEB_INPUT_CAP = 50_000
MWEB_WEIGHT_CAP = 200_000

MWEB_CONSOL_INPUTS_PER_TX = 100
# Host wallets for inventory (one full consolidation role each when possible).
CAP_HOST_WALLETS = 384

L1_PAD_INPUTS_PER_TX = 100
L1_WEIGHT_CAP = 4_000_000
L1_FIXED_OVERHEAD_WEIGHT = 700

# GBT floors: consolidation-heavy pack, not partial-only fill.
GBT_MIN_MWEB_INPUTS = 45_000
GBT_MIN_WIRE_FRACTION = 90
GBT_MIN_MWEB_WEIGHT_FRACTION = 95


def l1_pad_tx_weight(n_inputs: int = L1_PAD_INPUTS_PER_TX) -> int:
    """Weight of one multi-input P2WPKH sendall (100-in, 2-out)."""
    spks = [P2WPKH_SPK, P2WPKH_SPK]
    total = l1_tx_size(n_inputs, spks)
    stripped = 4 + 1 + 1
    stripped += compact_size_len(n_inputs) + n_inputs * CTXIN_EMPTY_SCRIPTSIG
    stripped += compact_size_len(len(spks)) + sum(ctxout_len(s) for s in spks)
    stripped += 4
    return stripped * 3 + total


def compute_l1_pad_txs_max(*, n_inputs: int = L1_PAD_INPUTS_PER_TX) -> int:
    """Max 100-in L1 pad txs under the consensus 4M block weight cap."""
    per_tx = l1_pad_tx_weight(n_inputs)
    budget = L1_WEIGHT_CAP - L1_FIXED_OVERHEAD_WEIGHT
    return max(1, budget // per_tx)


L1_PAD_TXS_MAX = compute_l1_pad_txs_max()  # 145 at 100 inputs


@dataclass(frozen=True)
class CapBlockPlan:
    """Exact mempool roles for one production-cap GBT / submitblock attempt."""

    mweb_consol_txs: int
    mweb_consol_inputs_per_tx: int
    mweb_partial_txs: int
    l1_pad_txs: int
    l1_pad_inputs_per_tx: int = L1_PAD_INPUTS_PER_TX
    # Optional extras for reject variants (2.1 / 2.2).
    extra_mweb_inputs: int = 0  # folded into one consolidation (weightless)
    extra_partial_txs: int = 0  # additional 1-in/2-out beyond weight cap (2.2)

    @property
    def mweb_consol_inputs(self) -> int:
        base = self.mweb_consol_txs * self.mweb_consol_inputs_per_tx
        return base + self.extra_mweb_inputs

    @property
    def mweb_partial_inputs(self) -> int:
        return self.mweb_partial_txs + self.extra_partial_txs

    @property
    def mweb_inputs_total(self) -> int:
        return self.mweb_consol_inputs + self.mweb_partial_inputs

    @property
    def mweb_mempool_txs(self) -> int:
        return self.mweb_consol_txs + self.mweb_partial_txs + self.extra_partial_txs

    @property
    def l1_mempool_txs(self) -> int:
        return self.l1_pad_txs

    @property
    def total_mempool_txs(self) -> int:
        return self.mweb_mempool_txs + self.l1_mempool_txs

    @property
    def mweb_weight_estimate(self) -> int:
        return (
            self.mweb_consol_txs * MW_WEIGHT_CONSOL
            + (self.mweb_partial_txs + self.extra_partial_txs) * MW_WEIGHT_PARTIAL
        )

    def describe(self) -> str:
        extra = ""
        if self.extra_mweb_inputs:
            extra += f" +{self.extra_mweb_inputs} extra consol inputs"
        if self.extra_partial_txs:
            extra += f" +{self.extra_partial_txs} overweight partials"
        return (
            f"MWEB: {self.mweb_consol_txs} consolidations "
            f"({self.mweb_consol_inputs_per_tx} in each) + "
            f"{self.mweb_partial_txs} partial 1-in/2-out fills{extra}; "
            f"L1: {self.l1_pad_txs} x {self.l1_pad_inputs_per_tx}-input pads; "
            f"mempool={self.total_mempool_txs} txs "
            f"(~{self.mweb_inputs_total} MWEB inputs, "
            f"~{self.mweb_weight_estimate} MWEB weight)"
        )


def _best_cap_fill_counts(*, max_consol_txs: int = CAP_HOST_WALLETS,
                          max_inputs_per_consol: int = 163) -> tuple[int, int, int]:
    """Choose C consolidations, inputs/tx, and P partials under both caps.

    Caps consolidations at ``max_consol_txs`` (wallet inventory) and inputs per
    consolidation at ``max_inputs_per_consol`` (per-wallet bank size).
    Returns (C, inputs_per_tx, P).
    """
    best = None  # (inputs, weight, C, ipt, P)
    ipt0 = MWEB_CONSOL_INPUTS_PER_TX
    for c in range(0, max_consol_txs + 1):
        rem_wt = MWEB_WEIGHT_CAP - c * MW_WEIGHT_CONSOL
        if rem_wt < 0:
            break
        p = rem_wt // MW_WEIGHT_PARTIAL
        ipt = ipt0
        inns = c * ipt + p
        if c > 0 and inns < MWEB_INPUT_CAP:
            extra = MWEB_INPUT_CAP - inns
            ipt = min(max_inputs_per_consol, ipt0 + extra // c)
            inns = c * ipt + p
            if inns > MWEB_INPUT_CAP:
                p = MWEB_INPUT_CAP - c * ipt
                if p < 0:
                    ipt = min(max_inputs_per_consol, MWEB_INPUT_CAP // c)
                    p = MWEB_INPUT_CAP - c * ipt
        elif inns > MWEB_INPUT_CAP:
            p = MWEB_INPUT_CAP - c * ipt
            if p < 0:
                continue
        wt = c * MW_WEIGHT_CONSOL + max(0, p) * MW_WEIGHT_PARTIAL
        p = max(0, p)
        inns = c * ipt + p
        key = (inns, wt, c, ipt, p)
        if best is None or key[:2] > best[:2]:
            best = key
    assert best is not None
    return best[2], best[3], best[4]


def compute_cap_fill_plan(*, height: int = 1745,
                          max_consol_txs: int = CAP_HOST_WALLETS) -> CapBlockPlan:
    """Production-cap fill: weight-first, then inputs to 50k, L1 pads to 4M."""
    c, ipt, p = _best_cap_fill_counts(max_consol_txs=max_consol_txs)
    return CapBlockPlan(
        mweb_consol_txs=c,
        mweb_consol_inputs_per_tx=ipt,
        mweb_partial_txs=p,
        l1_pad_txs=L1_PAD_TXS_MAX,
    )


def compute_plus_one_input_plan(*, height: int = 1745) -> CapBlockPlan:
    """Near-max plan with exactly one extra MWEB input beyond MAX_NUM_INPUTS."""
    base = compute_cap_fill_plan(height=height)
    # Ensure merged body has MAX_NUM_INPUTS + 1.
    need_extra = MWEB_INPUT_CAP + 1 - base.mweb_inputs_total
    if need_extra < 1:
        need_extra = 1
    return CapBlockPlan(
        mweb_consol_txs=base.mweb_consol_txs,
        mweb_consol_inputs_per_tx=base.mweb_consol_inputs_per_tx,
        mweb_partial_txs=base.mweb_partial_txs,
        l1_pad_txs=base.l1_pad_txs,
        extra_mweb_inputs=need_extra,
    )


def compute_plus_weight_plan(*, height: int = 1745) -> CapBlockPlan:
    """Near-max plan with one extra partial so weight exceeds 200k (inputs ≤ 50k).

    Uses a weight-saturated mix that leaves input headroom, then adds one partial.
    """
    # Fill weight exactly (or as close as possible) with room for +1 partial input.
    c = 100  # 10k consolidation inputs — well under 50k
    p = (MWEB_WEIGHT_CAP - c * MW_WEIGHT_CONSOL) // MW_WEIGHT_PARTIAL
    assert c * MWEB_CONSOL_INPUTS_PER_TX + p + 1 <= MWEB_INPUT_CAP
    return CapBlockPlan(
        mweb_consol_txs=c,
        mweb_consol_inputs_per_tx=MWEB_CONSOL_INPUTS_PER_TX,
        mweb_partial_txs=p,
        l1_pad_txs=L1_PAD_TXS_MAX,
        extra_partial_txs=1,
    )


def compute_bip324_edge_plan(*, height: int = 1745) -> CapBlockPlan:
    """L1-full plan with as many normal MWEB txs as fit under BIP324 wire.

    Starts from cap-fill and reduces MWEB density until modeled wire ≤ BIP324.
    """
    base = compute_cap_fill_plan(height=height)
    c, ipt, p, l1 = (
        base.mweb_consol_txs,
        base.mweb_consol_inputs_per_tx,
        base.mweb_partial_txs,
        base.l1_pad_txs,
    )
    while c > 0 or p > 0:
        plan = CapBlockPlan(
            mweb_consol_txs=c,
            mweb_consol_inputs_per_tx=ipt,
            mweb_partial_txs=p,
            l1_pad_txs=l1,
        )
        wire, _ = model_plan_wire(plan, height=height)
        if wire <= BIP324_CAP:
            return plan
        if p > 0:
            p -= max(1, p // 20)
        elif c > 0:
            c -= 1
        else:
            break
    return CapBlockPlan(
        mweb_consol_txs=max(1, c),
        mweb_consol_inputs_per_tx=max(1, ipt),
        mweb_partial_txs=max(0, p),
        l1_pad_txs=l1,
    )


def model_plan_wire(plan: CapBlockPlan, *, height: int = 1745) -> tuple[int, dict]:
    """Model serialized block size for ``plan`` using block_size_calc."""
    mweb_kernels = plan.mweb_consol_txs + plan.mweb_partial_txs + plan.extra_partial_txs
    mweb_outputs = (
        plan.mweb_consol_txs
        + 2 * (plan.mweb_partial_txs + plan.extra_partial_txs)
    )
    l1_inputs = plan.l1_pad_txs * plan.l1_pad_inputs_per_tx
    l1_sizes = [
        l1_tx_size(plan.l1_pad_inputs_per_tx, [P2WPKH_SPK, P2WPKH_SPK])
        for _ in range(plan.l1_pad_txs)
    ]
    return block_size_from_counts(
        l1_inputs=l1_inputs,
        l1_transactions=plan.l1_pad_txs,
        l1_outputs=plan.l1_pad_txs * 2,
        mweb_inputs=plan.mweb_inputs_total,
        mweb_transactions=mweb_kernels,
        mweb_outputs=mweb_outputs,
        mweb_height=height,
        l1_tx_sizes=l1_sizes,
    )


def gbt_min_wire_for_plan(plan: CapBlockPlan, *, height: int = 1745) -> int:
    wire, _ = model_plan_wire(plan, height=height)
    return wire * GBT_MIN_WIRE_FRACTION // 100


def gbt_matches_cap_plan(gbt, plan: CapBlockPlan, *, gbt_diag: dict) -> None:
    """Validate GBT took a consolidation-heavy near-cap pack."""
    if gbt_diag["mweb_inputs"] < min(GBT_MIN_MWEB_INPUTS, plan.mweb_inputs_total * 90 // 100):
        raise AssertionError(
            f"GBT MWEB inputs {gbt_diag['mweb_inputs']} too low for cap plan; "
            f"plan={plan.describe()} diag={gbt_diag}"
        )
    min_consol_in = plan.mweb_consol_inputs * 90 // 100
    if gbt_diag["mweb_inputs"] < min_consol_in:
        raise AssertionError(
            f"GBT MWEB inputs {gbt_diag['mweb_inputs']} < 90% of planned "
            f"consolidation inputs ({min_consol_in}); "
            f"plan={plan.describe()} diag={gbt_diag}"
        )
    min_l1 = min(plan.l1_pad_txs, 80)
    if gbt_diag["l1_txs"] < min_l1:
        raise AssertionError(
            f"GBT L1 txs {gbt_diag['l1_txs']} < {min_l1} (plan {plan.l1_pad_txs}); "
            f"diag={gbt_diag}"
        )


# --- Back-compat aliases for older envelope module imports ---
EnvelopeBlockPlan = CapBlockPlan
ENVELOPE_HOST_WALLETS = CAP_HOST_WALLETS
MWEB_CONSOL_TXS = None  # unused; compute_cap_fill_plan chooses C


def compute_envelope_block_plan(*, height: int = 1745) -> CapBlockPlan:
    return compute_cap_fill_plan(height=height)


def plan_reaches_envelope(plan: CapBlockPlan, *, height: int = 1745) -> bool:
    """Legacy name: true if modeled wire exceeds the pessimistic ceiling (unexpected for cap-fill)."""
    wire, _ = model_plan_wire(plan, height=height)
    return wire > MWEB_ENVELOPE


def gbt_matches_plan(gbt, plan: CapBlockPlan, *, gbt_diag: dict) -> None:
    gbt_matches_cap_plan(gbt, plan, gbt_diag=gbt_diag)
