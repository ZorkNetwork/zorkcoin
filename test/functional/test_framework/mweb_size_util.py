#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for MWEB serialized-size band functionals (mine-max / mine-test).

Fill recipe (valid txs only) — ~1.3k-block path, not long classic growth:

  1. Lean fund: ~400 reserve + 2xwallet rotate + 110 maturity + top-up
  2. L1 fan-out: many small P2WPKH UTXOs per wallet (witness-pad inventory)
  3. MWEB peg-in bank: 0.01 → fresh MWEB address each (L1-forced peg-in)
  4. Final flood only: MWEB consolidations + weight-fill + L1 pad → one GBT tip

Classic 1-in/1-out growth is intentionally omitted: it weight-binds near
~11 MB and cannot reach BIP324/envelope in useful time.

Inventory worked backward from Phase 8 (must be confirmed on-chain before
pack; spendzeroconfchange=0). 384 wallets on miner:

  Phase 8 pack (one mempool tip, then GBT; spendzeroconfchange=0 — confirmed
  bank only, no chaining mempool outputs):
    Pass A  changeless multi-input MWEB→MWEB consolidations until ≥50k inputs
            are queued in mempool (full wallet batches; assembler picks ≤50k)
    Pass B  partial MWEB→MWEB sends on every remaining 0.01 bank coin (pay +
            change; oversubscribes 200k MWEB weight — assembler optimizes)
    L1      up to 200 pad txs x 100 inputs (assembler picks ≤4M L1 weight)
    Do not pre-split budgets in the harness; queue generously, let CreateNewBlock
    pack under input / MWEB-weight / serialized-size / L1-weight caps.

  Phase 6 bank @ pack-1:
    62_592 MWEB UTXOs (384x163 x 0.01) ≈ 625.92 LTC — all L1 peg-in, not MWEB→MWEB

  Phase 5 fan-out @ peg-in start (~17 blocks, batched multi-output):
    ≥108_672 L1 UTXOs (384x283 x 0.05) — must leave ≥100 coins/wallet after
    163 peg-ins so Phase-8 L1 pads can run (was 250 → only ~87 left; pads failed)
    Peg-ins draw ~163x0.01 LTC/wallet from this pool (~1.63 LTC/wallet + fees)

  Phases 1-4 before fan-out (~1_278 blocks + maturity):
    Top-up 384x20 LTC ≈ 7_680 LTC spendable
    Funder reserve 400 coinbases funds early fan-out waves

  Future shortcut (not used here): tar a datadir whose tip is post-Phase 6 with
  a verified listunspent bank count, then run Phase 8 only on that snapshot.
"""

from decimal import Decimal
import contextlib
import errno
import http.client
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import (
    add_witness_commitment,
    create_coinbase,
)
from test_framework.messages import (
    CBlock,
    CTransaction,
    FromHex,
    Hash,
    MWEBBlock,
    MWEBInput,
    msg_block,
)
from test_framework.p2p import P2PInterface
from test_framework.mweb_density_util import _create_or_load_wallet
from test_framework.mweb_cap_block_plan import (
    BIP324_CAP as PLAN_BIP324_CAP,
    CapBlockPlan,
    GBT_MIN_MWEB_INPUTS,
    L1_PAD_TXS_MAX as ENVELOPE_L1_PAD_TXS_MAX,
    MWEB_ENVELOPE as PLAN_MWEB_ENVELOPE,
    compute_cap_fill_plan,
    gbt_matches_cap_plan,
    gbt_min_wire_for_plan,
    model_plan_wire,
)
# Legacy alias used by older imports / envelope shim.
from test_framework.mweb_util import MWEB_GBT_REQUEST_PARAMS, init_mweb_wallet
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    p2p_port,
    resolve_mweb_mine_bitcoind,
    rpc_port,
)


BIP324_CAP = 16_777_214
MWEB_ENVELOPE = 25_800_195
MWEB_ENVELOPE_PLUS = MWEB_ENVELOPE + 512
INPUT_BYTES = 196

DEFAULT_ECONOMIC_NODES = 8
# Wallets live on the miner by default (see prepare_size_economy); 384 total.
DEFAULT_WALLETS_PER_NODE = 384
# 3-node envelope topology: few fresh wallets on miner (1/4 quotas), full bank on host.
MINER_WALLET_COUNT = 8
MINER_TX_DIVISOR = 4
DEFAULT_BLOCKS_PER_WALLET = 2
WALLET_PREFIX = "mweb_sz_"

# Lean funding (transcript ~1400-block budget).
FUNDER_RESERVE_BLOCKS = 400
MATURITY_BLOCKS = 110
TARGET_WALLET_BALANCE = Decimal("20")  # covers 283x0.05 fan-out + peg-in fees + change

# 125% inventory targets (384 wallets on miner).
# L1 fan-out must leave enough confirmed coins AFTER peg-ins for Phase-8 pads.
# Peg-ins consume one L1 coin each; pads need L1_PAD_INPUTS_PER_TX (+ trim spare).
MWEB_BANK_PER_WALLET = 163          # x 0.01 → 62_592 MWEB UTXOs
MWEB_BANK_AMOUNT = Decimal("0.01")
L1_PAD_INPUTS_PER_TX = 100
L1_TRIM_SPARE_INPUTS = 20           # reserved on first pad wallet for OP_RETURN trim
L1_FANOUT_PER_WALLET = (
    MWEB_BANK_PER_WALLET + L1_PAD_INPUTS_PER_TX + L1_TRIM_SPARE_INPUTS
)  # 283 x 0.05 — was 250, which left only ~87 coins after peg-in (< 100 pad)
L1_FANOUT_AMOUNT = Decimal("0.05")
# Peg-ins per wallet per wave: queue all remaining (≤163); mine drains ~6.2k/block.
MWEB_PEGINS_PER_WALLET_PER_WAVE = MWEB_BANK_PER_WALLET
# Heartbeat while Phase 6 queues tens of thousands of peg-ins / drains mempool.
PHASE6_STATUS_INTERVAL_S = 600  # 10 minutes
# Fail if the wallet hosts stop relaying peg-ins to the miner for this long.
PHASE6_RELAY_STALL_S = 1800
# Wallet hosts (384 wallets) validate fat peg-in blocks slowly; poll gently.
WALLET_HOST_SYNC_POLL_FAR_S = 300   # while >1 block behind miner
WALLET_HOST_SYNC_POLL_NEAR_S = 60    # within 1 block of miner tip
WALLET_HOST_SYNC_LOG_S = 600
WALLET_HOST_SYNC_SAMPLE_WALLETS = 16
# Parallel MWEB address pre-create (one worker per host node, or per-party chunk).
DEFAULT_MWEB_PRECREATE_NODES = 4
# L1 fan-out: multi-output sends per tx / funder sendmany chunk (weight-bound).
L1_OUTS_PER_TX = 150
L1_FUNDER_SENDMANY_CHUNK = 500

# Phase 8 mid-band: queue mempool layers; BlockAssembler / GBT choose the fit.
# Cap-fill uses ``mweb_cap_block_plan`` — weight-first then inputs to 50k.
MWEB_INPUT_CAP = 50_000
MWEB_WEIGHT_CAP = 200_000
MW_WEIGHT_CONSOL = 21
MW_WEIGHT_PARTIAL = 39
MW_WEIGHT_EXACT_DRAIN = 21
WEIGHT_FILL_AMOUNT = Decimal("0.009")
PHASE8_PEELS_PER_WALLET = 0
L1_PAD_INPUTS_PER_TX = 100
L1_PAD_MAX_TXS = 200
# Legacy aliases (cap-fill path uses CapBlockPlan).
MWEB_CONSOL_INPUT_CAP_ENVELOPE = 45_100
L1_PAD_MAX_TXS_ENVELOPE = ENVELOPE_L1_PAD_TXS_MAX
GBT_MIN_MWEB_INPUTS_ENVELOPE = GBT_MIN_MWEB_INPUTS
AMT_NEAR_DUST = Decimal("0.000015")
AMT_MIN = Decimal("0.00001")
# Cap-fill pack feerates (sat/vB): consolidations must outrank partials.
# Cap-fill: consolidations must outrank partials in BlockAssembler chunk order.
# Empirically fee_rate=50 still lost to partials under MWEB fee/weight accounting
# (GBT saturates ~200k MWEB weight at ~48k inputs). Prefer a large gap + prioritise.
ENVELOPE_CONSOL_FEE_RATE = 500
ENVELOPE_PARTIAL_FEE_RATE = 1
TRIM_FEE_RATE = 100
# BIP125 replacements must raise *absolute* fee. Shrinking OP_RETURN lowers
# vsize, so fee_rate alone must climb enough that abs_fee still increases.
TRIM_RBF_ABS_FEE_BUMP_SATS = 1_000
# Legacy alias used by exact-envelope trim loops.
INPUTS_PER_CONSOLIDATION = 16
# Issue E: minimum MWEB coins written to accept dump as "scale".
ISSUE_E_MIN_MWEB_COINS = 20_000
OP_RETURN_TRIM_MAX_ATTEMPTS = 32
OP_RETURN_MAX_PAYLOAD = 8_000
# Phase-8: do not accept a template that misses plan targets; fee-bump / densify / rebuild.
PACK_GBT_MAX_ATTEMPTS = 6
PACK_PRIORITY_FEE_DELTA = 10_000_000  # sats via prioritisetransaction
# Plus-one reject: only MWEB input count matters (no L1 / weight fill).
PLUS_ONE_INPUT_TARGET = 50_001
PLUS_ONE_INPUTS_PER_TX = 50  # 999x50 + 1x51 = 50_001
PLUS_ONE_FEE_RATE = 10
PLUS_ONE_FEE_PAD = Decimal("0.0001")
# Plus-weight reject: L1 pads + minimal-input MWEB partials, then RBF one tx
# (add one output / +18 weight, plus a tiny peg-out / +1 kernel weight) so packed
# MWEB weight is just over 200k.
# Base N=5128 x 39 = 199_992; after 3-out + peg-out RBF: 200_011 (≤ mine-test +39).
PLUS_WEIGHT_CAP = 200_000
PLUS_WEIGHT_KERNEL = 3          # KERNEL_WITH_STEALTH_WEIGHT
PLUS_WEIGHT_OUTPUT = 18         # STANDARD_OUTPUT_WEIGHT
PLUS_WEIGHT_PEGOUT = 1          # kernel extra data for one P2WPKH peg-out
PLUS_WEIGHT_PARTIAL = 39        # stealth kernel + 2 standard outs
PLUS_WEIGHT_BASE_PARTIALS = 5128
PLUS_WEIGHT_BASE_FEE_RATE = 1
# Replacing a tx with MWEB data needs 1.5x its fee rate, measured as fee over
# L1 weight + MWEB weight. Pure MWEB→MWEB fee is GetMWEBFee(weight) only
# (fee_rate ignored: always 100 per MWEB weight), so each RBF includes a tiny
# L1 peg-out (31 vB, 124 weight) that fee_rate pays for:
#   seed 2-out:            3,900 / 39               = 100
#   3-out + peg-out @1000: 31x1000 + 5,800 = 36,800 / (124 + 58) ≈ 202 (≥ 150)
#   2-out + peg-out @2000: 31x2000 + 4,000 = 66,000 / (124 + 40) ≈ 402 (≥ 303)
# The single 0.01 input covers both (change ≈ 0.0036, then ≈ 0.0013).
PLUS_WEIGHT_RBF_FEE_RATE = 1000
PLUS_WEIGHT_ACCEPT_FEE_RATE = 2000
PLUS_WEIGHT_PAY_AMOUNT = Decimal("0.009")
PLUS_WEIGHT_RBF_PAY_AMOUNT = Decimal("0.003")
PLUS_WEIGHT_ACCEPT_MWEB_AMOUNT = Decimal("0.008")
PLUS_WEIGHT_ACCEPT_L1_AMOUNT = Decimal("0.00001")


def estimate_mweb_body_weight(n_outputs, n_kernels):
    """Consensus weight for standard stealth kernels + standard outputs (no extras)."""
    return n_kernels * PLUS_WEIGHT_KERNEL + n_outputs * PLUS_WEIGHT_OUTPUT


def scaled_wallet_quota(full, divisor=1):
    """Per-wallet quota on a host that does ``1/divisor`` of the full inventory."""
    return max(1, full // divisor)


def party_l1_fanout(party, default=L1_FANOUT_PER_WALLET):
    return party.get("l1_fanout", default)


def party_mweb_bank(party, default=MWEB_BANK_PER_WALLET):
    return party.get("mweb_bank", default)


def block_wire_bytes(node, blockhash):
    return len(node.getblock(blockhash, 0)) // 2


def gbt_wire_estimate(node):
    gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
    total = 0
    for entry in gbt.get("transactions", []):
        total += len(entry["data"]) // 2
    if "mweb" in gbt:
        total += len(gbt["mweb"]) // 2
    total += 300
    return total, len(gbt.get("transactions", [])), gbt


def gbt_mweb_body_counts(gbt):
    """Return (inputs, outputs, kernels) from a GBT ``mweb`` hex field."""
    if "mweb" not in gbt:
        return 0, 0, 0
    mweb_block = FromHex(MWEBBlock(), gbt["mweb"])
    body = mweb_block.body
    return len(body.inputs), len(body.outputs), len(body.kernels)


def gbt_pack_diagnostics(gbt):
    """Human-readable GBT pack stats for logs / failure messages."""
    l1_wire = sum(len(t["data"]) // 2 for t in gbt.get("transactions", []))
    mweb_wire = len(gbt.get("mweb", "")) // 2
    n_in, n_out, n_k = gbt_mweb_body_counts(gbt)
    return {
        "gbt_est": l1_wire + mweb_wire + 300,
        "l1_txs": len(gbt.get("transactions", [])),
        "l1_wire": l1_wire,
        "mweb_wire": mweb_wire,
        "mweb_inputs": n_in,
        "mweb_outputs": n_out,
        "mweb_kernels": n_k,
        "mweb_weight_est": estimate_mweb_body_weight(n_out, n_k),
    }


def assemble_solved_block_from_gbt(node):
    gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
    assert "mweb" in gbt, "expected mweb field in GBT"
    txs = []
    for entry in gbt["transactions"]:
        tx = FromHex(CTransaction(), entry["data"])
        tx.rehash()
        txs.append(tx)
    fees_sats = int(gbt["coinbasevalue"]) - 50 * 100_000_000
    if fees_sats < 0:
        fees_sats = 0
    coinbase = create_coinbase(height=int(gbt["height"]), fees=fees_sats)
    block = CBlock()
    block.nVersion = gbt["version"]
    block.hashPrevBlock = int(gbt["previousblockhash"], 16)
    block.nTime = gbt["curtime"]
    block.nBits = int(gbt["bits"], 16)
    block.nNonce = 0
    block.vtx = [coinbase] + txs
    block.mweb_block = FromHex(MWEBBlock(), gbt["mweb"])
    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return block


def assemble_solved_block_from_gbt_with_timeout(node, *, rpc_timeout):
    """GBT + solve using the node's full RPC timeout (not the default half)."""
    rpc = node._rpc
    old_timeout = rpc.timeout
    try:
        rpc.timeout = int(rpc_timeout)
        return assemble_solved_block_from_gbt(node)
    finally:
        rpc.timeout = old_timeout


# serialize.h MAX_SIZE = 32 MiB caps HTTP JSON-RPC bodies. Hex-encoded wire
# doubles size, so submitblock of a ~21 MB block (~43 MB JSON) gets a BrokenPipe
# before the server logs the method. Deliver large blocks over v1 P2P instead.
RPC_SUBMITBLOCK_SAFE_WIRE = 15_000_000


def submit_block_via_p2p(node, block, *, timeout=1800, supports_v2_p2p=False):
    """Push a solved block over P2P and wait until it becomes the tip."""
    tip_before = node.getbestblockhash()
    peer = node.add_p2p_connection(P2PInterface(), supports_v2_p2p=supports_v2_p2p)
    try:
        peer.send_without_ping(msg_block(block))
        node.wait_until(
            lambda: node.getbestblockhash() == block.hash,
            timeout=timeout,
        )
    finally:
        try:
            peer.peer_disconnect()
        except Exception:
            pass
        try:
            node.disconnect_p2ps()
        except Exception:
            pass
    assert node.getbestblockhash() != tip_before
    return block.hash


def reject_block_via_p2p(node, block, *, reject_msgs, tip_before=None,
                         height_before=None, timeout=180):
    """Push a block that must be rejected; tip/height stay unchanged.

    ``reject_msgs`` are substrings expected in the node's debug log (same style
    as ``mweb_block_packing`` size-gate checks).
    """
    if tip_before is None:
        tip_before = node.getbestblockhash()
    if height_before is None:
        height_before = node.getblockcount()
    peer = node.add_p2p_connection(P2PInterface(), supports_v2_p2p=False)
    try:
        with node.assert_debug_log(expected_msgs=list(reject_msgs), timeout=timeout):
            peer.send_without_ping(msg_block(block))
    finally:
        try:
            peer.peer_disconnect()
        except Exception:
            pass
        try:
            node.disconnect_p2ps()
        except Exception:
            pass
    assert node.getbestblockhash() == tip_before
    assert node.getblockcount() == height_before


def submit_solved_block(node, block, *, timeout=1800):
    """Prefer RPC submitblock for small blocks; P2P when hex would exceed HTTP MAX_SIZE."""
    wire = len(block.serialize())
    if wire <= RPC_SUBMITBLOCK_SAFE_WIRE:
        result = node.submitblock(block.serialize().hex())
        if result is not None:
            raise AssertionError(f"submitblock rejected: {result}")
        return block.hash
    return submit_block_via_p2p(node, block, timeout=timeout)


ENVELOPE_PAD_MARGIN = 10_000
MAX_PROTOCOL_BLOCK_BYTES = 32_000_000


def pad_mweb_block_past_envelope(block, *, envelope=MWEB_ENVELOPE,
                                 margin=ENVELOPE_PAD_MARGIN):
    """Append weightless synthetic MWEB inputs until ``S > envelope``.

    Same size-gate pattern as ``mweb_block_packing.py``: CheckBlock rejects
    ``bad-blk-serialized-size`` before MWEB crypto validates the pad bytes.
    Recomputes merkle root, witness commitment, and regtest PoW.
    """
    assert block.mweb_block is not None
    base_s = len(block.serialize())
    if base_s > envelope:
        return block, base_s, 0, base_s
    need = envelope - base_s + margin
    n_extra = max(need // INPUT_BYTES + 100, 1)
    for i in range(n_extra):
        inp = MWEBInput()
        inp.features = 0x01
        inp.output_id = Hash(i + 0xE00E0000)
        inp.commitment = 1
        inp.output_pubkey = 2
        inp.input_pubkey = 3
        inp.signature = 4
        block.mweb_block.body.inputs.append(inp)
    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    final_s = len(block.serialize())
    if final_s <= envelope:
        raise AssertionError(
            f"Envelope pad failed: base={base_s} padded={final_s} <= {envelope}"
        )
    if final_s >= MAX_PROTOCOL_BLOCK_BYTES:
        raise AssertionError(
            f"Envelope pad exceeds protocol message room: {final_s}"
        )
    return block, final_s, n_extra, base_s


class MWEBSizeTestMixin:
    def add_options(self, parser):
        """Long-running size tests default to pausing with nodes up on failure."""
        BitcoinTestFramework.add_options(self, parser)
        parser.set_defaults(pauseonfailure=True)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def require_mine_binary(self, variant):
        path = resolve_mweb_mine_bitcoind(self.binary_paths, variant=variant)
        if path is None:
            raise SkipTest(
                f"bitcoind-mine-{variant} not found beside bitcoind "
                "(build targets bitcoind-mine-max / bitcoind-mine-test)"
            )
        return path

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def sync_all(self, nodes=None):
        timeout = int(self.rpc_timeout)
        self.sync_blocks(nodes, timeout=timeout)
        self.sync_mempools(nodes, timeout=timeout)

    @contextlib.contextmanager
    def _full_rpc_timeout(self, node):
        """Use the node's full rpc_timeout for one slow RPC (default client is half)."""
        rpc = node._rpc
        old_timeout = rpc.timeout
        try:
            rpc.timeout = int(node.rpc_timeout)
            yield
        finally:
            rpc.timeout = old_timeout

    def ensure_peer_mesh(self):
        """Connect missing P2P links only (no block/mempool/validation-queue sync)."""
        n = len(self.nodes)
        for i in range(n):
            for j in range(i + 1, n):
                b_sub = self.nodes[j].getnetworkinfo()["subversion"]
                already = any(
                    p.get("subver") == b_sub for p in self.nodes[i].getpeerinfo()
                )
                if already:
                    continue
                try:
                    self.connect_nodes(i, j)
                except Exception:
                    pass

    def disconnect_all_peers(self):
        """Drop every node-to-node link (keeps bitcoinds up)."""
        n = len(self.nodes)
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                try:
                    self.disconnect_nodes(i, j)
                except Exception:
                    pass

    def connect_nodes_persistent(self, a, b, *, peer_advertises_v2=None):
        """Like ``connect_nodes``, but ``addnode … add`` so the dialer retries.

        ``connect_nodes`` uses ``onetry`` (no automatic reconnect). After a
        block-download stall disconnect, persistent addnode is required for the
        outbound side to dial again (~60s retry in ThreadOpenAddedConnections).
        """
        from_connection = self.nodes[a]
        to_connection = self.nodes[b]
        from_subver = from_connection.getnetworkinfo()["subversion"]
        to_subver = to_connection.getnetworkinfo()["subversion"]

        def find_conn(node, peer_subversion, inbound):
            return next(
                filter(
                    lambda peer: peer["subver"] == peer_subversion
                    and peer["inbound"] == inbound,
                    node.getpeerinfo(),
                ),
                None,
            )

        self.wait_until(lambda: not find_conn(from_connection, to_subver, inbound=False))
        self.wait_until(lambda: not find_conn(to_connection, from_subver, inbound=True))

        ip_port = f"127.0.0.1:{p2p_port(b)}"
        if peer_advertises_v2 is None:
            peer_advertises_v2 = from_connection.use_v2transport
        from_connection.addnode(
            node=ip_port, command="add", v2transport=peer_advertises_v2
        )

        self.wait_until(
            lambda: find_conn(from_connection, to_subver, inbound=False) is not None
        )
        self.wait_until(
            lambda: find_conn(to_connection, from_subver, inbound=True) is not None
        )

        def check_bytesrecv(peer, msg_type, min_bytes_recv):
            assert peer is not None, "Error: peer disconnected"
            return peer["bytesrecv_per_msg"].pop(msg_type, 0) >= min_bytes_recv

        self.wait_until(
            lambda: check_bytesrecv(
                find_conn(from_connection, to_subver, inbound=False), "pong", 29
            )
        )
        self.wait_until(
            lambda: check_bytesrecv(
                find_conn(to_connection, from_subver, inbound=True), "pong", 29
            )
        )

    def peerinfo_to(self, node, other):
        """Return getpeerinfo entry on ``node`` for ``other``, or None."""
        sub = other.getnetworkinfo()["subversion"]
        for peer in node.getpeerinfo():
            if peer.get("subver") == sub:
                return peer
        return None

    def wait_for_transport(self, node, other, expected, *, timeout=180, label=None):
        """Wait until ``node`` has a live peer link to ``other`` on ``expected`` transport."""
        label = label or f"transport {node.index}->{other.index}={expected}"
        self.log.info("waiting for %s (timeout=%ds)", label, timeout)

        def ok():
            peer = self.peerinfo_to(node, other)
            return peer is not None and peer.get("transport_protocol_type") == expected

        self.wait_until(ok, timeout=timeout)
        return self.assert_transport(node, other, expected)

    def assert_transport(self, node, other, expected):
        peer = self.peerinfo_to(node, other)
        assert peer is not None, (
            f"no peer link {node.index}->{other.index} "
            f"(peers={node.getpeerinfo()})"
        )
        got = peer.get("transport_protocol_type")
        assert got == expected, (
            f"transport {node.index}->{other.index}: got {got!r} want {expected!r} "
            f"peer={peer}"
        )
        return peer

    def assert_nodes_alive(self, nodes=None):
        """No crashes / fatal exits on the given bitcoinds."""
        nodes = self.nodes if nodes is None else nodes
        for node in nodes:
            assert node.process is not None and node.process.poll() is None, (
                f"node{node.index} exited with code {node.process.poll() if node.process else 'n/a'}"
            )
            # Cheap RPC proves the HTTP/RPC thread is still servicing.
            node.getblockcount()

    def wait_for_tip(self, nodes, tip, *, timeout=1800, label="tip"):
        """Wait until every node reaches ``tip`` (hash string)."""
        nodes = list(nodes)
        deadline = time.time() + int(timeout * self.options.timeout_factor)
        last_log = time.monotonic()
        while True:
            self.assert_nodes_alive(nodes)
            heights = []
            tips = []
            all_ok = True
            for node in nodes:
                with self._full_rpc_timeout(node):
                    h = node.getblockcount()
                    t = node.getbestblockhash()
                heights.append(h)
                tips.append(t)
                if t != tip:
                    all_ok = False
            if all_ok:
                self.log.info("%s sync done: all at %s", label, tip)
                return
            now = time.monotonic()
            if now - last_log >= 30:
                last_log = now
                self.log.info(
                    "%s wait: tips=%s heights=%s want=%s",
                    label, tips, heights, tip,
                )
            if time.time() >= deadline:
                raise AssertionError(
                    f"{label} sync timeout: tips={tips} heights={heights} want={tip}"
                )
            time.sleep(2)

    def setup_max_cap_propagation_mesh(self, *, builder_idx, dut_idx,
                                        v1_idx, v2_idx, isolate_idxs=()):
        """Wire the 1.2 transport graph (all links explicit).

        builder --v1--> DUT
        DUT     --v1--> V1Peer
        DUT     --v2--> V2Peer
        V1Peer  --v1--> V2Peer   (side-path so V2Peer still reaches tip)

        ``isolate_idxs`` (e.g. wallet host) stay disconnected from this mesh so a
        21 MB tip does not stall on hundreds of wallet callbacks.
        """
        self.disconnect_all_peers()
        # builder (v2 disabled) → DUT: always v1
        self.connect_nodes(builder_idx, dut_idx, peer_advertises_v2=False)
        # DUT (v2 enabled) → V1Peer: force v1 even though DUT speaks v2
        self.connect_nodes(dut_idx, v1_idx, peer_advertises_v2=False)
        # DUT → V2Peer: both v2-capable → negotiate v2
        self.connect_nodes(dut_idx, v2_idx, peer_advertises_v2=True)
        # V1Peer (v2 disabled) → V2Peer: v1 side-path
        self.connect_nodes(v1_idx, v2_idx, peer_advertises_v2=False)

        builder, dut = self.nodes[builder_idx], self.nodes[dut_idx]
        v1, v2 = self.nodes[v1_idx], self.nodes[v2_idx]
        self.assert_transport(builder, dut, "v1")
        self.assert_transport(dut, v1, "v1")
        self.assert_transport(dut, v2, "v2")
        self.assert_transport(v1, v2, "v1")
        self.log.info(
            "max-cap propagation mesh ready: "
            "builder%d--v1-->dut%d--v1-->v1peer%d; dut%d--v2-->v2peer%d; "
            "v1peer%d--v1-->v2peer%d (isolated=%s)",
            builder_idx, dut_idx, v1_idx, dut_idx, v2_idx, v1_idx, v2_idx,
            list(isolate_idxs),
        )

    def connect_full_mesh(self):
        self.ensure_peer_mesh()
        self.sync_all()

    def _mempool_txid_sets(self, nodes):
        pools = []
        for node in nodes:
            with self._full_rpc_timeout(node):
                pools.append(set(node.getrawmempool()))
        return pools

    def sync_mempools_light(self, nodes, *, wait=1, timeout=60, log_interval_s=60):
        """Wait for identical mempools without syncwithvalidationinterfacequeue.

        Required after Phase 8 on wallet hosts with hundreds of wallets: flushing
        the validation interface can exceed the HTTP client timeout while wallet
        callbacks drain, even though mempool relay only needs getrawmempool parity.
        """
        rpc_connections = list(nodes)
        timeout = int(timeout * self.options.timeout_factor)
        stop_time = time.time() + timeout
        last_log = time.monotonic()
        pool = []
        while time.time() <= stop_time:
            pool = self._mempool_txid_sets(rpc_connections)
            if pool.count(pool[0]) == len(rpc_connections):
                return pool[0]
            if not all(len(x.getpeerinfo()) for x in rpc_connections):
                self.ensure_peer_mesh()
            now = time.monotonic()
            if now - last_log >= log_interval_s:
                last_log = now
                sizes = [len(p) for p in pool]
                self.log.info("mempool light sync: sizes=%s", sizes)
            time.sleep(wait)
        raise AssertionError(
            "Light mempool sync timed out after {}s: sizes={}".format(
                timeout, [len(p) for p in pool],
            )
        )

    def log_manual_intervention_state(self):
        """Extra context for --pauseonfailure (grep MANUAL_INTERVENTION)."""
        if not self.nodes:
            return
        builder = self.nodes[0]
        parts = [
            f"MANUAL_INTERVENTION datadir={self.options.tmpdir}",
            f"builder_node=0 rpc_port={rpc_port(0)}",
        ]
        try:
            parts.append(f"height={builder.getblockcount()}")
            with self._full_rpc_timeout(builder):
                parts.append(f"builder_mempool={len(builder.getrawmempool())}")
            est, n_tx, _ = gbt_wire_estimate(builder)
            parts.append(f"gbt_est={est} gbt_txs={n_tx} envelope={MWEB_ENVELOPE}")
        except Exception as e:
            parts.append(f"gbt_error={e}")
        for i, node in enumerate(self.nodes[1:], start=1):
            try:
                with self._full_rpc_timeout(node):
                    mp = len(node.getrawmempool())
                parts.append(
                    f"node{i}=rpc_port:{rpc_port(i)} mempool={mp} height={node.getblockcount()}"
                )
            except Exception as e:
                parts.append(f"node{i}=rpc_error:{e}")
        parts.append(
            "NEXT: ensure builder peers wallet host; relay Phase8 mempool; "
            "gbt_wire_estimate(builder); assemble_solved_block_from_gbt; "
            "validator.submitblock"
        )
        self.log.error(" | ".join(parts))

    def setup_economic_wallets(self, *, wallets_per_node=DEFAULT_WALLETS_PER_NODE,
                               prefix=WALLET_PREFIX, nodes=None):
        """Create wallets on the given nodes (default: all self.nodes)."""
        nodes = list(self.nodes if nodes is None else nodes)
        parties = []
        for node_idx, node in enumerate(nodes):
            # Prefer the framework index when node is from self.nodes.
            try:
                global_idx = self.nodes.index(node)
            except ValueError:
                global_idx = node_idx
            for w in range(wallets_per_node):
                name = f"{prefix}n{global_idx}w{w}"
                rpc = _create_or_load_wallet(node, name)
                parties.append({"node_idx": global_idx, "name": name, "rpc": rpc})
        self.log.info(
            "Economic wallets: host_nodes=%d wallets_per_node=%d total=%d",
            len(nodes), wallets_per_node, len(parties),
        )
        return parties

    def setup_economic_wallets_split(self, *, hosts, total_wallets,
                                     prefix=WALLET_PREFIX):
        """Split ``total_wallets`` evenly across ``hosts``."""
        n = len(hosts)
        base, rem = divmod(total_wallets, n)
        counts = [base + (1 if i < rem else 0) for i in range(n)]
        parties = []
        for host_i, (node, count) in enumerate(zip(hosts, counts)):
            if count < 1:
                continue
            try:
                global_idx = self.nodes.index(node)
            except ValueError:
                global_idx = host_i
            for w in range(count):
                name = f"{prefix}n{global_idx}w{w}"
                rpc = _create_or_load_wallet(node, name)
                parties.append({"node_idx": global_idx, "name": name, "rpc": rpc})
        self.log.info(
            "Economic wallets: host_nodes=%d total=%d per_host=%s",
            len(hosts), total_wallets, counts,
        )
        return parties

    def setup_economic_wallets_tiered(self, *, miner, wallet_host,
                                      miner_wallets=MINER_WALLET_COUNT,
                                      host_wallets=DEFAULT_WALLETS_PER_NODE,
                                      miner_tx_divisor=MINER_TX_DIVISOR,
                                      prefix=WALLET_PREFIX):
        """Miner hosts a small wallet set at reduced quotas; host carries the full bank."""
        miner_idx = self.nodes.index(miner)
        host_idx = self.nodes.index(wallet_host)
        l1_miner = scaled_wallet_quota(L1_FANOUT_PER_WALLET, miner_tx_divisor)
        mweb_miner = scaled_wallet_quota(MWEB_BANK_PER_WALLET, miner_tx_divisor)
        parties = []
        for w in range(miner_wallets):
            name = f"{prefix}n{miner_idx}w{w}"
            rpc = _create_or_load_wallet(miner, name)
            parties.append({
                "node_idx": miner_idx,
                "name": name,
                "rpc": rpc,
                "l1_fanout": l1_miner,
                "mweb_bank": mweb_miner,
                "host_role": "miner",
            })
        for w in range(host_wallets):
            name = f"{prefix}n{host_idx}w{w}"
            rpc = _create_or_load_wallet(wallet_host, name)
            parties.append({
                "node_idx": host_idx,
                "name": name,
                "rpc": rpc,
                "l1_fanout": L1_FANOUT_PER_WALLET,
                "mweb_bank": MWEB_BANK_PER_WALLET,
                "host_role": "wallet_host",
            })
        mweb_target = sum(party_mweb_bank(p) for p in parties)
        l1_target = sum(party_l1_fanout(p) for p in parties)
        self.log.info(
            "Economic wallets 3-node: miner=%d@%d (1/%d quotas l1=%d mweb=%d) "
            "host=%d@%d (full quotas) total=%d pegins≈%d l1_outs≈%d",
            miner_wallets, miner_idx, miner_tx_divisor, l1_miner, mweb_miner,
            host_wallets, host_idx, len(parties), mweb_target, l1_target,
        )
        return parties

    def wallet_host_nodes(self, miner, *, precreate_nodes=DEFAULT_MWEB_PRECREATE_NODES,
                          exclude=None):
        """Up to ``precreate_nodes`` nodes for wallet RPC (always includes ``miner``)."""
        exclude_set = set(exclude or [])
        hosts = []
        if miner not in exclude_set:
            hosts.append(miner)
        for node in self.nodes:
            if node in hosts or node in exclude_set:
                continue
            hosts.append(node)
            if len(hosts) >= precreate_nodes:
                break
        if len(hosts) < precreate_nodes:
            self.log.warning(
                "precreate_nodes=%d requested but only %d wallet hosts available",
                precreate_nodes, len(hosts),
            )
        return hosts

    def _safe_send(self, wallet, addr, amount, *, fee_rate=None, return_txid=False):
        """Send ``amount`` to ``addr``. Optional ``fee_rate`` (sat/vB) for feerate priority."""
        try:
            if fee_rate is None:
                txid = wallet.sendtoaddress(addr, amount)
            else:
                txid = self._txid_from_send_result(
                    wallet.send(outputs={addr: amount}, fee_rate=fee_rate)
                )
            if return_txid:
                return True, txid if isinstance(txid, str) else self._txid_from_send_result(txid)
            return True
        except JSONRPCException:
            if return_txid:
                return False, None
            return False

    def _safe_mweb_consolidate(self, wallet, dest, utxos, *, fee_pad=Decimal("0.0001"),
                               fee_rate=None, return_txid=False):
        """MWEB→MWEB consolidation via explicit output_id inputs (send RPC).

        ``fee_rate``: when set, beats low-feerate partials in BlockAssembler sort.
        """
        if len(utxos) < 1:
            return (False, 0, None) if return_txid else (False, 0)
        oids = []
        total = Decimal(0)
        for u in utxos:
            oid = u.get("output_id")
            if not oid:
                # Fall back to amount-based selection if output_id missing.
                return self._safe_mweb_consolidate_by_amount(
                    wallet, dest, utxos, fee_pad=fee_pad, fee_rate=fee_rate,
                    return_txid=return_txid,
                )
            oids.append({"output_id": oid})
            total += Decimal(str(u["amount"]))
        send_amt = total - fee_pad
        if send_amt <= 0:
            return (False, 0, None) if return_txid else (False, 0)
        try:
            options = {
                "inputs": oids,
                "add_inputs": False,
            }
            kwargs = {"outputs": {dest: send_amt}, "options": options}
            if fee_rate is not None:
                kwargs["fee_rate"] = fee_rate
            else:
                kwargs["fee_rate"] = 1
            txid = wallet.send(**kwargs)
            if return_txid:
                return True, len(oids), self._txid_from_send_result(txid)
            return True, len(oids)
        except JSONRPCException:
            return (False, 0, None) if return_txid else (False, 0)

    def _safe_mweb_consolidate_by_amount(self, wallet, dest, utxos, *,
                                         fee_pad=Decimal("0.0001"), fee_rate=None,
                                         return_txid=False):
        """Legacy amount-based consolidation when output_id is unavailable."""
        amounts = sorted(Decimal(str(u["amount"])) for u in utxos)
        if len(set(amounts)) == 1 and amounts[0] == MWEB_BANK_AMOUNT:
            n_inputs = len(utxos)
            send_amt = n_inputs * MWEB_BANK_AMOUNT - fee_pad
        else:
            n_inputs = len(utxos)
            total = sum(amounts)
            send_amt = total - fee_pad
        if send_amt <= 0:
            return (False, 0, None) if return_txid else (False, 0)
        if return_txid:
            ok, txid = self._safe_send(
                wallet, dest, send_amt, fee_rate=fee_rate, return_txid=True,
            )
            return (ok, n_inputs if ok else 0, txid)
        if self._safe_send(wallet, dest, send_amt, fee_rate=fee_rate):
            return True, n_inputs
        return False, 0

    def _safe_mweb_weight_fill(self, wallet, dest, *, amount=WEIGHT_FILL_AMOUNT,
                               fee_rate=None, utxo=None, return_txid=False):
        """Partial MWEB→MWEB spend: 1 input, payee + change (~39 MWEB weight)."""
        if amount <= 0:
            return (False, None) if return_txid else False
        if utxo is not None and utxo.get("output_id"):
            try:
                options = {
                    "inputs": [{"output_id": utxo["output_id"]}],
                    "add_inputs": False,
                }
                kwargs = {"outputs": {dest: amount}, "options": options}
                kwargs["fee_rate"] = 1 if fee_rate is None else fee_rate
                txid = wallet.send(**kwargs)
                if return_txid:
                    return True, self._txid_from_send_result(txid)
                return True
            except JSONRPCException:
                return (False, None) if return_txid else False
        if return_txid:
            return self._safe_send(
                wallet, dest, amount, fee_rate=fee_rate, return_txid=True,
            )
        return self._safe_send(wallet, dest, amount, fee_rate=fee_rate)

    def _safe_multi_send(self, wallet, outputs, *, inputs=None):
        """Multi-output L1 send; ``outputs`` is {addr: amount}."""
        if not outputs:
            return False
        try:
            options = {"fee_rate": 1}
            if inputs is not None:
                options["inputs"] = inputs
                options["add_inputs"] = False
            wallet.send(outputs=outputs, fee_rate=1, options=options)
            return True
        except JSONRPCException:
            return False

    def _queue_l1_multi_out_tx(self, wallet, dest_queue, amount, *,
                               outs_per_tx=L1_OUTS_PER_TX):
        """Queue one multi-output tx from ``dest_queue``; return outputs queued."""
        if not dest_queue:
            return 0
        fee_pad = Decimal("0.0001")
        utxos = [
            u for u in self._l1_utxos(wallet)
            if "vout" in u and Decimal(str(u["amount"])) >= amount
        ]
        if not utxos:
            return 0
        chunk_size = min(outs_per_tx, len(dest_queue))
        total_bal = sum(Decimal(str(u["amount"])) for u in utxos)
        max_by_bal = int((total_bal - fee_pad) / amount)
        if max_by_bal < 1:
            return 0
        chunk_size = min(chunk_size, max_by_bal)
        total_needed = chunk_size * amount + fee_pad
        addrs = [dest_queue.pop(0) for _ in range(chunk_size)]
        outputs = {addr: amount for addr in addrs}
        big = [u for u in utxos if Decimal(str(u["amount"])) >= total_needed]
        if big:
            big.sort(key=lambda u: Decimal(str(u["amount"])))
            u = big[0]
            inputs = [{"txid": u["txid"], "vout": u["vout"]}]
            if self._safe_multi_send(wallet, outputs, inputs=inputs):
                return chunk_size
        else:
            selected = []
            running = Decimal(0)
            for u in sorted(utxos, key=lambda x: Decimal(str(x["amount"]))):
                selected.append(u)
                running += Decimal(str(u["amount"]))
                if running >= total_needed:
                    break
            if running < total_needed:
                for addr in reversed(addrs):
                    dest_queue.insert(0, addr)
                return 0
            inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]
            if self._safe_multi_send(wallet, outputs, inputs=inputs):
                return chunk_size
        for addr in reversed(addrs):
            dest_queue.insert(0, addr)
        return 0

    @staticmethod
    def _estimate_op_return_trim_vsize(n_inputs, payload_len):
        """Rough vsize for  n-in P2WPKH + pay (+ OP_RETURN) + change.

        Calibrated on the bip324 RBF trim run: 2-in with payload 3380 → vsize
        3603 (≈ 223 + payload); payload 0 (no nulldata) → ~96.
        """
        if payload_len <= 0:
            return max(64, 48 * n_inputs + 50)
        return max(64, 48 * n_inputs + 127 + int(payload_len))

    @staticmethod
    def _fee_rate_for_abs_floor(vsize, min_abs_fee_sats):
        """Minimal sat/vB so fee_rate * vsize meets ``min_abs_fee_sats``."""
        vsize = max(1, int(vsize))
        needed = max(0, int(min_abs_fee_sats))
        return max(TRIM_FEE_RATE, (needed + vsize - 1) // vsize)

    def _mempool_spender_of(self, node, inputs):
        """Return txid currently spending the first locked outpoint, else None."""
        if not inputs:
            return None
        want = (inputs[0]["txid"], int(inputs[0]["vout"]))
        with self._full_rpc_timeout(node):
            for txid in node.getrawmempool():
                raw = node.getrawtransaction(txid, True)
                for vin in raw.get("vin", []):
                    if (vin.get("txid"), vin.get("vout")) == want:
                        return txid
        return None

    def _queue_op_return_trim_tx(self, wallet, *, inputs, dest, payload_hex, fee_rate=TRIM_FEE_RATE):
        """Queue/RBF an L1 spend with an optional OP_RETURN data output.

        Always signals BIP125 replaceable and pins ``inputs`` so later trim
        attempts can RBF the same outpoints (payload/fee only) instead of
        burning fresh confirmed UTXOs each iteration.

        Returns the new txid on wallet accept, or None on RPC failure. Callers
        must still confirm the txid replaced the prior spender in the *miner*
        mempool — wallet ``send`` can record a conflict that never enters the
        mempool when absolute fee does not rise (BIP125).
        """
        if not inputs:
            return None
        try:
            total = sum(Decimal(str(u["amount"])) for u in inputs)
            # Leave headroom for fee; higher feerates need a larger reserve.
            fee_frac = min(Decimal("0.5"), Decimal("0.1") + Decimal(fee_rate) / Decimal("2000"))
            send_amt = (total * (Decimal("1") - fee_frac)).quantize(Decimal("0.00000001"))
            if send_amt <= 0:
                return None
            outputs = [{dest: send_amt}]
            if payload_hex is not None and len(payload_hex) > 0:
                outputs.append({"data": payload_hex})
            options = {
                "inputs": [{"txid": u["txid"], "vout": u["vout"]} for u in inputs],
                "add_inputs": False,
                "replaceable": True,
            }
            result = wallet.send(
                outputs=outputs,
                fee_rate=fee_rate,
                options=options,
            )
            if isinstance(result, dict):
                return result.get("txid")
            return result
        except JSONRPCException:
            return None

    def _safe_mweb_exact_drain(self, wallet, dest, *, amount=MWEB_BANK_AMOUNT):
        """1-input exact MWEB→MWEB spend (no change, ~21 MWEB weight)."""
        fee_pad = Decimal("0.0001")
        send_amt = amount - fee_pad
        if send_amt <= 0:
            return False
        return self._safe_send(wallet, dest, send_amt)

    def _safe_pegin(self, wallet, addr, amount):
        """L1→MWEB peg-in forced via explicit L1 inputs.

        Bare sendtoaddress(mweb) prefers MWEB_TO_MWEB once the wallet holds
        MWEB coins (TryEarlyFunding), which recycles the bank instead of
        growing it. Selecting L1 outpoints makes HasSelected() true and
        skips that path.
        """
        fee_pad = Decimal("0.0001")
        candidates = [
            u for u in self._l1_utxos(wallet)
            if Decimal(str(u["amount"])) >= amount + fee_pad
            and "vout" in u
        ]
        if not candidates:
            return False
        # Prefer the smallest sufficient coin to preserve large L1 pads.
        candidates.sort(key=lambda u: Decimal(str(u["amount"])))
        u = candidates[0]
        try:
            wallet.send(
                outputs={addr: amount},
                fee_rate=1,
                options={
                    "inputs": [{"txid": u["txid"], "vout": u["vout"]}],
                    "add_inputs": False,
                },
            )
            return True
        except JSONRPCException:
            return False

    def _mweb_utxos(self, wallet, *, minconf=1):
        try:
            return [
                u for u in wallet.listunspent(minconf=minconf)
                if str(u.get("address", "")).startswith("bcrt1m")
            ]
        except JSONRPCException:
            return []

    @staticmethod
    def _txid_from_send_result(res):
        """``wallet.send`` returns ``{txid, complete}`` (or a bare txid string)."""
        if isinstance(res, dict):
            if res.get("complete") is False:
                raise AssertionError(f"wallet.send incomplete: {res}")
            txid = res.get("txid")
            if not txid:
                raise AssertionError(f"wallet.send missing txid: {res}")
            return txid
        if isinstance(res, str) and res:
            return res
        raise AssertionError(f"unexpected wallet.send result: {res!r}")

    def send_mweb(self, wallet, *, output_ids, outputs, fee_rate=1, add_inputs=False):
        """Reusable explicit MWEB ``send``: caller selects inputs and outputs.

        ``output_ids``: iterable of MWEB output_id hex strings.
        ``outputs``: ``{address: amount}`` (MWEB and/or L1 destinations).
        """
        oids = list(output_ids)
        if not oids:
            raise AssertionError("send_mweb requires at least one output_id")
        if not outputs:
            raise AssertionError("send_mweb requires at least one output")
        res = wallet.send(
            outputs=outputs,
            fee_rate=fee_rate,
            options={
                "inputs": [{"output_id": oid} for oid in oids],
                "add_inputs": bool(add_inputs),
            },
        )
        return self._txid_from_send_result(res)

    def send_mweb_many_to_one(self, wallet, utxos, *, dest=None,
                              fee_pad=PLUS_ONE_FEE_PAD, fee_rate=PLUS_ONE_FEE_RATE):
        """N confirmed MWEB coins → one MWEB output (changeless consolidation).

        Looks up ``output_id`` on each utxo; creates a fresh MWEB address when
        ``dest`` is omitted. Returns ``(txid, n_inputs, dest)``.
        """
        if not utxos:
            raise AssertionError("send_mweb_many_to_one: empty utxo list")
        oids = []
        total = Decimal(0)
        for u in utxos:
            oid = u.get("output_id")
            if not oid:
                raise AssertionError(f"utxo missing output_id: {u}")
            oids.append(oid)
            total += Decimal(str(u["amount"]))
        send_amt = total - fee_pad
        if send_amt <= 0:
            raise AssertionError(
                f"send_mweb_many_to_one: fee_pad {fee_pad} >= total {total}"
            )
        if dest is None:
            dest = wallet.getnewaddress(address_type="mweb")
        txid = self.send_mweb(
            wallet,
            output_ids=oids,
            outputs={dest: send_amt},
            fee_rate=fee_rate,
            add_inputs=False,
        )
        return txid, len(oids), dest

    def queue_plus_one_input_only_pack(self, miner, parties, *,
                                      inputs_per_tx=PLUS_ONE_INPUTS_PER_TX,
                                      target_inputs=PLUS_ONE_INPUT_TARGET):
        """Mempool-only pack: N-in/1-out MWEB consolidations totaling ``target_inputs``.

        No L1 pads, no weight-fill partials. Default: 999x50 + 1x51 = 50_001.
        Only these txs are submitted; GBT on mine-test must pack every input.
        """
        if inputs_per_tx < 2:
            raise ValueError(inputs_per_tx)
        if target_inputs < inputs_per_tx + 1:
            raise ValueError(target_inputs)
        # 999x50 + 1x51 = 50_001 (not (target-1)//ipt, which yields 1000x50 + 1x1).
        last_n = inputs_per_tx + 1
        if (target_inputs - last_n) % inputs_per_tx != 0:
            raise ValueError(
                f"target_inputs={target_inputs} not reachable as "
                f"Nx{inputs_per_tx} + 1x{last_n}"
            )
        n_full = (target_inputs - last_n) // inputs_per_tx
        n_txs = n_full + 1
        assert n_full * inputs_per_tx + last_n == target_inputs, (
            n_full, inputs_per_tx, last_n, target_inputs,
        )
        self.log.info(
            "Plus-one input pack: %dx%d-in + 1x%d-in = %d inputs (%d txs); "
            "no L1, no weight fill",
            n_full, inputs_per_tx, last_n, target_inputs, n_txs,
        )

        # Per-party confirmed MWEB inventory (spendzeroconfchange=0 / minconf=1).
        pools = []
        total_avail = 0
        for p in parties:
            utxos = [u for u in self._mweb_utxos(p["rpc"]) if u.get("output_id")]
            if utxos:
                pools.append({"party": p, "utxos": utxos})
                total_avail += len(utxos)
        if total_avail < target_inputs:
            raise AssertionError(
                f"Need ≥{target_inputs} confirmed MWEB UTXOs with output_id; "
                f"have {total_avail}"
            )

        # Prefer large inventories; miner tier may have <50 bank coins.
        pools.sort(key=lambda s: len(s["utxos"]), reverse=True)

        def take_batch(n):
            for slot in pools:
                if len(slot["utxos"]) >= n:
                    batch = slot["utxos"][:n]
                    slot["utxos"] = slot["utxos"][n:]
                    return slot["party"], batch
            sizes = sorted((len(s["utxos"]) for s in pools), reverse=True)[:8]
            raise AssertionError(
                f"No single wallet has ≥{n} confirmed MWEB UTXOs left "
                f"(top remaining={sizes})"
            )

        txids = []
        queued_inputs = 0
        dest_idx = 0
        n_parties = len(parties)

        def next_dest():
            nonlocal dest_idx
            dest = parties[dest_idx % n_parties]["rpc"].getnewaddress(address_type="mweb")
            dest_idx += 1
            return dest

        # Reserve the +1 (51-in) batch first so we do not fragment below 51.
        p, batch = take_batch(last_n)
        txid, n_in, _ = self.send_mweb_many_to_one(
            p["rpc"], batch, dest=next_dest(),
        )
        assert n_in == last_n, (n_in, last_n)
        txids.append(txid)
        queued_inputs += n_in

        for i in range(n_full):
            p, batch = take_batch(inputs_per_tx)
            txid, n_in, _ = self.send_mweb_many_to_one(
                p["rpc"], batch, dest=next_dest(),
            )
            assert n_in == inputs_per_tx, (n_in, inputs_per_tx)
            txids.append(txid)
            queued_inputs += n_in
            if (i + 1) % 100 == 0 or i + 1 == n_full:
                self.log.info(
                    "Plus-one queue: %d/%d x%d-in txs (%d inputs so far)",
                    i + 1, n_full, inputs_per_tx, queued_inputs,
                )

        assert queued_inputs == target_inputs, (queued_inputs, target_inputs)
        assert len(txids) == n_txs, (len(txids), n_txs)

        builder_mempool = self._sync_pack_mempool_to_miner(miner, parties)
        if builder_mempool != n_txs:
            raise AssertionError(
                f"Plus-one mempool must be exactly the pack txs: "
                f"have {builder_mempool} want {n_txs}"
            )
        self.log.info(
            "Plus-one pack queued: txs=%d inputs=%d builder_mempool=%d",
            n_txs, queued_inputs, builder_mempool,
        )
        return {
            "txids": txids,
            "n_txs": n_txs,
            "inputs": queued_inputs,
            "builder_mempool": builder_mempool,
        }

    def flood_plus_one_input_pack(self, miner, parties):
        """Queue 50k+1-input-only pack and return GBT diagnostics (mine-test builder)."""
        with self._full_rpc_timeout(miner):
            leftover = len(miner.getrawmempool())
        if leftover:
            self.log.info(
                "Clearing %d leftover mempool txs before plus-one pack", leftover,
            )
            miner = self._reset_pack_mempools(miner, parties)
        meta = self.queue_plus_one_input_only_pack(miner, parties)
        self.log.info(
            "Plus-one GBT starting (builder_mempool=%d); expect seconds-minutes",
            meta["builder_mempool"],
        )
        with self._full_rpc_timeout(miner):
            est, _n_tx, gbt = gbt_wire_estimate(miner)
        diag = gbt_pack_diagnostics(gbt)
        self.log.info(
            "Plus-one GBT: est=%d mweb_in=%d mweb_kernels=%d l1_txs=%d "
            "(want mweb_in=%d kernels=%d)",
            est, diag["mweb_inputs"], diag["mweb_kernels"], diag["l1_txs"],
            meta["inputs"], meta["n_txs"],
        )
        if diag["mweb_inputs"] < meta["inputs"]:
            raise AssertionError(
                f"Plus-one GBT under-packed inputs: {diag['mweb_inputs']} < "
                f"{meta['inputs']} (kernels={diag['mweb_kernels']} "
                f"mempool={meta['builder_mempool']} diag={diag})"
            )
        if diag["mweb_kernels"] < meta["n_txs"]:
            raise AssertionError(
                f"Plus-one GBT missing kernels: {diag['mweb_kernels']} < "
                f"{meta['n_txs']} diag={diag}"
            )
        return est, diag, meta

    def _push_mempool_txs_to_miner(self, miner, parties, *, txids=None):
        """Explicitly copy mempool txs to the builder (avoids INV re-advertise gaps)."""
        with self._full_rpc_timeout(miner):
            have = set(miner.getrawmempool())
        want = set(txids) if txids is not None else None
        pushed = 0
        skipped = 0
        miner_idx = self._miner_node_index(miner)
        for p in parties:
            if p["node_idx"] == miner_idx:
                continue
            node = self.nodes[p["node_idx"]]
            with self._full_rpc_timeout(node):
                host_txids = node.getrawmempool()
            for txid in host_txids:
                if want is not None and txid not in want:
                    continue
                if txid in have:
                    continue
                try:
                    with self._full_rpc_timeout(node):
                        raw = node.getrawtransaction(txid)
                    with self._full_rpc_timeout(miner):
                        miner.sendrawtransaction(raw)
                    have.add(txid)
                    pushed += 1
                except JSONRPCException:
                    skipped += 1
        return len(have), pushed, skipped

    def _send_mweb_replaceable(self, wallet, *, output_id, outputs, fee_rate):
        """MWEB send with BIP125 replaceable signaling (for later output-count RBF)."""
        res = wallet.send(
            outputs=outputs,
            fee_rate=fee_rate,
            options={
                "inputs": [{"output_id": output_id}],
                "add_inputs": False,
                "replaceable": True,
            },
        )
        return self._txid_from_send_result(res)

    def queue_plus_weight_rbf_pack(self, miner, parties, *,
                                  n_partials=PLUS_WEIGHT_BASE_PARTIALS,
                                  l1_pad_txs=None):
        """L1 pads + 1-in/2-out MWEB fills; RBF one tx to 3 outs past weight cap.

        Minimal MWEB inputs (one per partial). No consolidations. Wire headroom
        comes from L1 pads. Adjustment is a single RBF that adds one output
        (+18 weight) and a tiny peg-out (+1 weight) whose L1 fee meets the 1.5x
        MWEB replacement fee rate. Returns meta including final GBT diagnostics.
        """
        if l1_pad_txs is None:
            l1_pad_txs = ENVELOPE_L1_PAD_TXS_MAX
        base_wt = n_partials * PLUS_WEIGHT_PARTIAL
        after_wt = (n_partials - 1) * PLUS_WEIGHT_PARTIAL + (
            PLUS_WEIGHT_KERNEL + PLUS_WEIGHT_PEGOUT + 3 * PLUS_WEIGHT_OUTPUT
        )
        if base_wt > PLUS_WEIGHT_CAP:
            raise AssertionError(f"base weight {base_wt} already over cap")
        if after_wt <= PLUS_WEIGHT_CAP:
            raise AssertionError(
                f"RBF+1-out weight {after_wt} still ≤ cap {PLUS_WEIGHT_CAP}"
            )
        self.log.info(
            "Plus-weight pack: %dx1-in/2-out MWEB (wt=%d) + L1 pads=%d; "
            "RBF one tx → 3-out (modeled wt=%d > %d)",
            n_partials, base_wt, l1_pad_txs, after_wt, PLUS_WEIGHT_CAP,
        )

        # Collect confirmed 0.01 MWEB bank coins (one input each).
        slots = []
        for p in parties:
            for u in self._mweb_utxos(p["rpc"]):
                if not u.get("output_id"):
                    continue
                if Decimal(str(u["amount"])) < MWEB_BANK_AMOUNT:
                    continue
                slots.append((p, u))
                if len(slots) >= n_partials:
                    break
            if len(slots) >= n_partials:
                break
        if len(slots) < n_partials:
            raise AssertionError(
                f"Need {n_partials} MWEB bank coins; have {len(slots)}"
            )
        slots = slots[:n_partials]

        dest_idx = 0
        n_parties = len(parties)

        def next_dest():
            nonlocal dest_idx
            dest = parties[dest_idx % n_parties]["rpc"].getnewaddress(
                address_type="mweb",
            )
            dest_idx += 1
            return dest

        # First slot is the RBF-adjustable tx; rest are static 2-out fills.
        adj_party, adj_utxo = slots[0]
        adj_oid = adj_utxo["output_id"]
        adj_txid = self._send_mweb_replaceable(
            adj_party["rpc"],
            output_id=adj_oid,
            outputs={next_dest(): PLUS_WEIGHT_PAY_AMOUNT},
            fee_rate=PLUS_WEIGHT_BASE_FEE_RATE,
        )
        self.log.info(
            "Plus-weight adjustable seed: txid=%s output_id=%s fee_rate=%d",
            adj_txid, adj_oid, PLUS_WEIGHT_BASE_FEE_RATE,
        )

        mweb_txids = [adj_txid]
        for i, (p, u) in enumerate(slots[1:], start=1):
            ok, txid = self._safe_mweb_weight_fill(
                p["rpc"], next_dest(),
                fee_rate=PLUS_WEIGHT_BASE_FEE_RATE, utxo=u, return_txid=True,
            )
            if not ok or not txid:
                raise AssertionError(
                    f"Plus-weight partial failed after {i}/{n_partials}"
                )
            mweb_txids.append(txid)
            if i % 500 == 0 or i + 1 == n_partials:
                self.log.info(
                    "Plus-weight MWEB queue: %d/%d partials", i + 1, n_partials,
                )

        l1_queued = self.queue_l1_witness_pad(parties, max_txs=l1_pad_txs)
        if l1_queued < l1_pad_txs:
            self.log.warning(
                "Plus-weight L1 pads short: %d < %d (continuing)",
                l1_queued, l1_pad_txs,
            )

        expected = n_partials + l1_queued
        mempool_n, pushed, skipped = self._push_mempool_txs_to_miner(
            miner, parties, txids=None,
        )
        self.log.info(
            "Plus-weight pre-RBF push: builder=%d pushed=%d skipped=%d "
            "expected≈%d",
            mempool_n, pushed, skipped, expected,
        )
        # Also wait for peer relay of anything push missed.
        mempool_n = self._sync_pack_mempool_to_miner(miner, parties)
        if mempool_n < expected * 99 // 100:
            mempool_n, pushed2, skipped2 = self._push_mempool_txs_to_miner(
                miner, parties,
            )
            self.log.info(
                "Plus-weight pre-RBF re-push: builder=%d pushed=%d skipped=%d",
                mempool_n, pushed2, skipped2,
            )
            mempool_n = self._sync_pack_mempool_to_miner(miner, parties)
        if mempool_n < expected * 99 // 100:
            raise AssertionError(
                f"Plus-weight pre-RBF mempool incomplete: builder={mempool_n} "
                f"want≈{expected}"
            )

        with self._full_rpc_timeout(miner):
            est, _n, gbt = gbt_wire_estimate(miner)
        diag = gbt_pack_diagnostics(gbt)
        self.log.info(
            "Plus-weight GBT before RBF: est=%d mweb_wt≈%d in=%d out=%d "
            "kernels=%d (want wt≤%d)",
            diag["gbt_est"], diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_outputs"], diag["mweb_kernels"], PLUS_WEIGHT_CAP,
        )
        if diag["mweb_weight_est"] > PLUS_WEIGHT_CAP:
            raise AssertionError(
                f"Pre-RBF already over weight: {diag['mweb_weight_est']}"
            )

        # RBF the adjustable tx: 2 payees + change ⇒ 3 standard outputs (+18 wt),
        # plus a tiny peg-out (+1 wt) so fee_rate can pay the 1.5x replacement rate.
        d1, d2 = next_dest(), next_dest()
        new_txid = self._send_mweb_replaceable(
            adj_party["rpc"],
            output_id=adj_oid,
            outputs={
                d1: PLUS_WEIGHT_RBF_PAY_AMOUNT,
                d2: PLUS_WEIGHT_RBF_PAY_AMOUNT,
                adj_party["rpc"].getnewaddress(): PLUS_WEIGHT_ACCEPT_L1_AMOUNT,
            },
            fee_rate=PLUS_WEIGHT_RBF_FEE_RATE,
        )
        self.log.info(
            "Plus-weight RBF: %s → %s (fee_rate %d→%d, +1 output, +peg-out)",
            adj_txid, new_txid,
            PLUS_WEIGHT_BASE_FEE_RATE, PLUS_WEIGHT_RBF_FEE_RATE,
        )
        if new_txid == adj_txid:
            raise AssertionError("Plus-weight RBF did not create a new txid")

        self._push_plus_weight_replacement(
            miner, parties, adj_party["rpc"], new_txid,
            label="Plus-weight post-RBF",
        )
        with self._full_rpc_timeout(miner):
            builder_set = set(miner.getrawmempool())
        if adj_txid in builder_set and new_txid not in builder_set:
            raise AssertionError(
                f"Plus-weight RBF not on builder: old={adj_txid} still present, "
                f"new={new_txid} missing"
            )

        with self._full_rpc_timeout(miner):
            est, _n, gbt = gbt_wire_estimate(miner)
        diag = gbt_pack_diagnostics(gbt)
        self.log.info(
            "Plus-weight GBT after RBF: est=%d mweb_wt≈%d in=%d out=%d "
            "kernels=%d envelope=%d",
            diag["gbt_est"], diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_outputs"], diag["mweb_kernels"], MWEB_ENVELOPE,
        )
        return {
            "adj_party": adj_party,
            "adj_output_id": adj_oid,
            "adj_old_txid": adj_txid,
            "adj_new_txid": new_txid,
            "n_partials": n_partials,
            "l1_pads": l1_queued,
            "modeled_weight_base": base_wt,
            "modeled_weight_after": after_wt,
            "gbt_est": est,
            "diag": diag,
        }

    def _push_plus_weight_replacement(self, miner, parties, wallet, txid, *, label):
        """Push one RBF replacement onto the builder mempool and verify it landed."""
        try:
            raw = wallet.gettransaction(txid)["hex"]
            with self._full_rpc_timeout(miner):
                miner.sendrawtransaction(raw)
        except JSONRPCException as e:
            self.log.warning("%s direct push: %s", label, e)
        mempool_n, pushed, skipped = self._push_mempool_txs_to_miner(
            miner, parties,
        )
        self.log.info(
            "%s push: builder=%d pushed=%d skipped=%d",
            label, mempool_n, pushed, skipped,
        )
        with self._full_rpc_timeout(miner):
            builder_set = set(miner.getrawmempool())
        if txid not in builder_set:
            try:
                raw = wallet.getrawtransaction(txid)
                with self._full_rpc_timeout(miner):
                    miner.sendrawtransaction(raw)
            except JSONRPCException as e:
                raise AssertionError(
                    f"{label} missing on builder and push failed: {e}"
                ) from e
            with self._full_rpc_timeout(miner):
                builder_set = set(miner.getrawmempool())
        if txid not in builder_set:
            raise AssertionError(f"{label} still missing on builder: {txid}")
        return mempool_n

    def plus_weight_rbf_back_under_cap(self, miner, parties, meta, *,
                                      fee_rate=PLUS_WEIGHT_ACCEPT_FEE_RATE):
        """RBF the adjustable tx under the weight cap with a higher package fee.

        Pure MWEB fee equals GetMWEBFee(weight), so dropping 3-out→2-out always
        lowers absolute fee and mempool rejects the replacement. Spend the same
        MWEB input to one MWEB out + a tiny L1 out; fee_rate then supplies the
        1.5x replacement fee rate (fee 0.00066 over weight 164 ≈ 402 ≥ 1.5 x
        0.000368 over 182 ≈ 303; see PLUS_WEIGHT_RBF_FEE_RATE).
        """
        adj_party = meta["adj_party"]
        adj_oid = meta["adj_output_id"]
        prev_txid = meta["adj_new_txid"]
        dest_mweb = adj_party["rpc"].getnewaddress(address_type="mweb")
        dest_l1 = adj_party["rpc"].getnewaddress()
        under_txid = self._send_mweb_replaceable(
            adj_party["rpc"],
            output_id=adj_oid,
            outputs={
                dest_mweb: PLUS_WEIGHT_ACCEPT_MWEB_AMOUNT,
                dest_l1: PLUS_WEIGHT_ACCEPT_L1_AMOUNT,
            },
            fee_rate=fee_rate,
        )
        self.log.info(
            "Plus-weight RBF back under cap: %s → %s (fee_rate=%d, "
            "MWEB+L1 hybrid replaces 3-out)",
            prev_txid, under_txid, fee_rate,
        )
        if under_txid == prev_txid:
            raise AssertionError("Plus-weight under-cap RBF did not create a new txid")

        self._push_plus_weight_replacement(
            miner, parties, adj_party["rpc"], under_txid,
            label="Plus-weight under-cap RBF",
        )
        with self._full_rpc_timeout(miner):
            builder_set = set(miner.getrawmempool())
        if prev_txid in builder_set:
            raise AssertionError(
                f"Plus-weight under-cap RBF: overweight tx {prev_txid} still "
                f"in builder mempool"
            )

        with self._full_rpc_timeout(miner):
            est, _n, gbt = gbt_wire_estimate(miner)
        diag = gbt_pack_diagnostics(gbt)
        self.log.info(
            "Plus-weight GBT under cap: est=%d mweb_wt≈%d in=%d out=%d "
            "kernels=%d (want wt≤%d)",
            diag["gbt_est"], diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_outputs"], diag["mweb_kernels"], PLUS_WEIGHT_CAP,
        )
        if diag["mweb_weight_est"] > PLUS_WEIGHT_CAP:
            raise AssertionError(
                f"Under-cap RBF still over weight: {diag['mweb_weight_est']} "
                f"> {PLUS_WEIGHT_CAP} diag={diag}"
            )
        if diag["gbt_est"] > MWEB_ENVELOPE:
            raise AssertionError(
                f"Under-cap GBT over envelope: est={diag['gbt_est']} > "
                f"{MWEB_ENVELOPE} diag={diag}"
            )
        meta = dict(meta)
        meta["adj_under_txid"] = under_txid
        meta["gbt_est"] = est
        meta["diag"] = diag
        return est, diag, meta

    def flood_plus_weight_rbf_pack(self, miner, parties):
        """Queue L1+MWEB pack, RBF one tx over weight cap, return GBT diag.

        Iterates GBT until packed MWEB weight > 200k and wire ≤ envelope.
        Does not assemble — caller decides when to mine/submit.
        """
        with self._full_rpc_timeout(miner):
            leftover = len(miner.getrawmempool())
        if leftover:
            self.log.info(
                "Clearing %d leftover mempool txs before plus-weight pack",
                leftover,
            )
            miner = self._reset_pack_mempools(miner, parties)

        meta = self.queue_plus_weight_rbf_pack(miner, parties)
        diag = meta["diag"]

        if diag["mweb_weight_est"] <= PLUS_WEIGHT_CAP:
            raise AssertionError(
                f"Plus-weight GBT not over cap: mweb_wt≈{diag['mweb_weight_est']} "
                f"≤ {PLUS_WEIGHT_CAP} diag={diag}"
            )
        if diag["gbt_est"] > MWEB_ENVELOPE:
            raise AssertionError(
                f"Plus-weight GBT over envelope: est={diag['gbt_est']} > "
                f"{MWEB_ENVELOPE} diag={diag}"
            )
        self.log.info(
            "Plus-weight pack ready: est=%d mweb_wt≈%d in=%d kernels=%d",
            diag["gbt_est"], diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_kernels"],
        )
        return diag["gbt_est"], diag, meta

    def _l1_utxos(self, wallet, *, minconf=1):
        try:
            return [
                u for u in wallet.listunspent(minconf=minconf)
                if not str(u.get("address", "")).startswith("bcrt1m")
            ]
        except JSONRPCException:
            return []

    def fund_wallets_lean(self, miner, parties, *,
                          reserve_blocks=FUNDER_RESERVE_BLOCKS,
                          blocks_per_wallet=DEFAULT_BLOCKS_PER_WALLET,
                          target_balance=TARGET_WALLET_BALANCE):
        """Phases 1-4: reserve + rotate + maturity + top-up (~1.3k path)."""
        funder = miner.get_wallet_rpc(self.default_wallet_name)
        funder_addr = funder.getnewaddress()
        self.log.info("Phase1 funder reserve (%d blocks)", reserve_blocks)
        for i in range(reserve_blocks):
            self.generatetoaddress(miner, 1, funder_addr, sync_fun=self.no_op)
            if (i + 1) % 100 == 0:
                self.log.info("  reserve %d / %d", i + 1, reserve_blocks)

        total_blocks = len(parties) * blocks_per_wallet
        self.log.info("Phase2 rotate %d coinbases across %d wallets", total_blocks, len(parties))
        done = 0
        for p in parties:
            addr = p["rpc"].getnewaddress()
            for _ in range(blocks_per_wallet):
                self.generatetoaddress(miner, 1, addr, sync_fun=self.no_op)
                done += 1
                if done % 200 == 0:
                    self.log.info("  rotate %d / %d", done, total_blocks)

        self.log.info("Phase3 maturity (+%d)", MATURITY_BLOCKS)
        self.generate(miner, MATURITY_BLOCKS, sync_fun=self.no_op)
        self.sync_all()

        self.log.info("Phase4 top-up to %s", target_balance)
        for p in parties:
            bal = p["rpc"].getbalance()
            if bal >= target_balance:
                continue
            gap = target_balance - bal
            for _attempt in range(8):
                try:
                    if funder.getbalance() < gap:
                        for _ in range(40):
                            self.generatetoaddress(miner, 1, funder_addr, sync_fun=self.no_op)
                        self.generate(miner, MATURITY_BLOCKS, sync_fun=self.no_op)
                    funder.sendtoaddress(p["rpc"].getnewaddress(), gap)
                    break
                except JSONRPCException as e:
                    self.log.debug("top-up retry %s: %s", p["name"], e)
        self.generate(miner, 1, sync_fun=self.no_op)
        self.sync_all()
        ok = sum(1 for p in parties if p["rpc"].getbalance() >= target_balance * Decimal("0.5"))
        self.log.info("Funding complete: %d / %d wallets funded (height=%d)",
                      ok, len(parties), miner.getblockcount())
        assert ok >= len(parties) // 2, f"only {ok}/{len(parties)} wallets funded"

    def _miner_node_index(self, miner):
        return self.nodes.index(miner)

    def _node_restart_extra_args(self, node_idx, *, disable_wallet):
        args = [a for a in self.extra_args[node_idx] if a != "-disablewallet"]
        if disable_wallet:
            args.append("-disablewallet")
        return args

    def _miner_restart_extra_args(self, miner, *, disable_wallet):
        return self._node_restart_extra_args(
            self._miner_node_index(miner), disable_wallet=disable_wallet,
        )

    def _party_host_nodes(self, parties, *, miner):
        """Non-miner nodes that host economic wallets (node_idx -> parties)."""
        miner_idx = self.nodes.index(miner)
        hosts = {}
        for p in parties:
            idx = p["node_idx"]
            if idx == miner_idx:
                continue
            hosts.setdefault(idx, []).append(p)
        return hosts

    def _reload_node_wallets(self, node_idx, parties):
        """Reload economic wallets on one node after restart."""
        node = self.nodes[node_idx]
        for p in parties:
            if p["node_idx"] != node_idx:
                continue
            p["rpc"] = _create_or_load_wallet(node, p["name"])

    def _reload_miner_wallets(self, miner, parties):
        """Reload default + economic wallets after a wallet-enabled restart.

        Wallets already exist on disk (load_on_startup). Never createwallet here —
        that fails with -4 and aborts after the multi-hour economy.
        """
        idx = self._miner_node_index(miner)
        node = self.nodes[idx]
        name = self.default_wallet_name
        if name and name not in node.listwallets():
            node.loadwallet(name)
        self._reload_node_wallets(idx, parties)

    def swap_miner_mine_binary(self, miner, variant, parties, *, label=""):
        """Stop the builder, point it at another mine binary, reload wallets.

        Reject tests must run Phase 6 on ``bitcoind-mine-max`` (consensus-safe
        generate). Swap to ``bitcoind-mine-test`` only before the over-budget
        reject GBT so CreateNewBlock can exceed input/weight caps.
        """
        path = self.require_mine_binary(variant)
        idx = self._miner_node_index(miner)
        extra = self._miner_restart_extra_args(miner, disable_wallet=False)
        height = miner.getblockcount()
        mempool = len(miner.getrawmempool())
        self.log.info(
            "Swap node%d bitcoind -> %s (%s) height=%d mempool=%d",
            idx, path, label or variant, height, mempool,
        )
        self.stop_node(idx)
        node = self.nodes[idx]
        node.binaries = node.binaries.with_bitcoind(path)
        need_ipc = any(a.startswith("-ipcbind") for a in node.args)
        datadir_i = next(
            i for i, a in enumerate(node.args) if a.startswith("-datadir=")
        )
        node.args = node.binaries.node_argv(need_ipc=need_ipc) + node.args[datadir_i:]
        self.start_node(idx, extra_args=extra)
        miner = self.nodes[idx]
        self._reload_miner_wallets(miner, parties)
        # Reconnect P2P and wait for shared tips only. Do not sync_all():
        # flushing the wallet-host validation interface after Phase 6 can
        # exceed the HTTP timeout even though tips already match.
        self.ensure_peer_mesh()
        self.sync_blocks(timeout=int(self.rpc_timeout))
        assert_equal(miner.getblockcount(), height)
        return miner

    def _ensure_node_alive(self, node):
        proc = node.process
        if proc is None or proc.poll() is not None:
            code = proc.poll() if proc is not None else "n/a"
            raise AssertionError(
                f"node{node.index} died during RPC (exit={code}); "
                f"datadir={node.datadir_path}"
            )

    def _is_stale_rpc_error(self, exc):
        if isinstance(exc, (
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            http.client.RemoteDisconnected,
            http.client.CannotSendRequest,
            http.client.ResponseNotReady,
        )):
            return True
        if isinstance(exc, OSError) and exc.errno in (
            errno.EPIPE, errno.ECONNRESET, errno.ECONNABORTED,
        ):
            return True
        return False

    def _reset_node_rpc(self, node):
        """Drop a stale HTTP session and reconnect; bitcoind stays up."""
        node.wait_for_rpc_connection(wait_for_import=False)

    def _rpc_retry(self, node, fn, *, attempts=3, label="rpc"):
        """Call ``fn``; on a dead HTTP socket, reset the proxy and retry.

        Does not mask a dead bitcoind: process exit fails immediately.
        """
        last = None
        for i in range(attempts):
            self._ensure_node_alive(node)
            try:
                return fn()
            except Exception as e:
                if not self._is_stale_rpc_error(e):
                    raise
                last = e
                self.log.warning(
                    "Stale RPC on node%d %s (%s); reset connection retry %d/%d",
                    node.index, label, type(e).__name__, i + 1, attempts,
                )
                self._reset_node_rpc(node)
        self._ensure_node_alive(node)
        raise last

    def _nodes_linked(self, a, b):
        """True if either side lists the other in getpeerinfo."""
        a_sub = self._rpc_retry(
            a, lambda: a.getnetworkinfo()["subversion"], label="getnetworkinfo",
        )
        b_sub = self._rpc_retry(
            b, lambda: b.getnetworkinfo()["subversion"], label="getnetworkinfo",
        )
        a_peers = self._rpc_retry(a, lambda: a.getpeerinfo(), label="getpeerinfo")
        if any(p.get("subver") == b_sub for p in a_peers):
            return True
        b_peers = self._rpc_retry(b, lambda: b.getpeerinfo(), label="getpeerinfo")
        return any(p.get("subver") == a_sub for p in b_peers)

    def _ensure_miner_host_link(self, host, miner):
        """Reconnect host↔miner if that specific link is missing.

        Catch-up used to reconnect only when the host had zero peers. A host
        can keep unrelated connections and still lose the miner.
        """
        if self._nodes_linked(host, miner):
            return
        self.log.warning(
            "Wallet host node%d has no miner node%d link; persistent reconnect",
            host.index, miner.index,
        )
        try:
            self.connect_nodes_persistent(host.index, miner.index)
        except Exception as e:
            self.log.warning("persistent host->miner connect failed: %s", e)
            try:
                self.connect_nodes_persistent(miner.index, host.index)
            except Exception as e2:
                self.log.warning("persistent miner->host connect failed: %s", e2)

    def _measure_rpc_latency(self, node, method="getblockcount"):
        """Wall-clock seconds for one node RPC call (catch-up health signal)."""
        t0 = time.monotonic()
        if method == "getblockcount":
            value = self._rpc_retry(
                node, lambda: node.getblockcount(), label="getblockcount",
            )
        else:
            raise ValueError(method)
        return time.monotonic() - t0, value

    def record_wallet_host_rpc_baselines(self, parties, miner):
        """Baseline host RPC latency while chain is quiet (before peg-in mine)."""
        self._wallet_host_rpc_baseline = {}
        for node_idx in self._party_host_nodes(parties, miner=miner):
            node = self.nodes[node_idx]
            samples = [self._measure_rpc_latency(node)[0] for _ in range(3)]
            baseline = sum(samples) / len(samples)
            self._wallet_host_rpc_baseline[node_idx] = baseline
            self.log.info(
                "Wallet host node%d RPC baseline getblockcount=%.3fs (samples=%s)",
                node_idx, baseline, ", ".join(f"{s:.3f}" for s in samples),
            )

    def _sample_parties(self, parties, n=WALLET_HOST_SYNC_SAMPLE_WALLETS):
        if len(parties) <= n:
            return parties
        step = max(1, len(parties) // n)
        return [parties[i] for i in range(0, len(parties), step)][:n]

    def _wallet_host_mweb_sample_stats(self, host_parties):
        """Sampled confirmed MWEB UTXOs on a wallet host (progress signal)."""
        sample = self._sample_parties(host_parties)
        wallets_with = 0
        total = 0
        for p in sample:
            n = len(self._mweb_utxos(p["rpc"], minconf=1))
            if n:
                wallets_with += 1
            total += n
        return wallets_with, total, len(sample)

    def wait_for_wallet_hosts_after_pegin_mine(self, miner, parties):
        """After miner drains peg-ins, wallet hosts catch up block-by-block.

        No restarts — hosts must process ConnectTip + wallet callbacks on every
        fat block.  Poll height (primary), sampled confirmed MWEB balances, and
        RPC latency vs baseline until each host matches the miner tip.
        """
        hosts = self._party_host_nodes(parties, miner=miner)
        if not hosts:
            self.sync_all()
            return
        if not getattr(self, "_wallet_host_rpc_baseline", None):
            self.record_wallet_host_rpc_baselines(parties, miner)
        timeout = max(int(self.rpc_timeout) * 12, 86_400)
        deadline = time.monotonic() + timeout
        last_log = time.monotonic()
        last_heights = {idx: None for idx in hosts}
        self.log.info(
            "Phase6 wallet-host catch-up: miner_height=%d hosts=%s timeout=%ds",
            self._rpc_retry(miner, lambda: miner.getblockcount(), label="getblockcount"),
            sorted(hosts.keys()), timeout,
        )
        while time.monotonic() < deadline:
            miner_height = self._rpc_retry(
                miner, lambda: miner.getblockcount(), label="getblockcount",
            )
            all_synced = True
            status_parts = []
            for node_idx, host_parties in hosts.items():
                host = self.nodes[node_idx]
                try:
                    latency, host_height = self._measure_rpc_latency(host)
                except JSONRPCException as e:
                    self.log.warning(
                        "Wallet host node%d RPC error during catch-up: %s",
                        node_idx, e,
                    )
                    all_synced = False
                    status_parts.append(f"node{node_idx}=rpc_error")
                    continue
                gap = miner_height - host_height
                if gap > 0:
                    all_synced = False
                    self._ensure_miner_host_link(host, miner)
                baseline = self._wallet_host_rpc_baseline.get(node_idx)
                prev_h = last_heights[node_idx]
                progress = (
                    f"node{node_idx} h={host_height} gap={gap} "
                    f"rpc={latency:.2f}s"
                )
                if baseline:
                    progress += f" baseline={baseline:.2f}s"
                if prev_h is not None and host_height > prev_h:
                    progress += f" (+{host_height - prev_h} blocks)"
                status_parts.append(progress)
                last_heights[node_idx] = host_height
            if all_synced:
                self.log.info(
                    "Phase6 wallet-host catch-up done at height=%d",
                    miner_height,
                )
                # Tip equality is enough. Do not sync_all() or listunspent-sample
                # here: Confirmed wallet callbacks may still saturate RPC for a
                # long time after UpdateTip, and blocking on them stalls Phase 8.
                return
            now = time.monotonic()
            if now - last_log >= WALLET_HOST_SYNC_LOG_S:
                last_log = now
                self.log.info(
                    "Phase6 wallet-host catch-up: miner_h=%d %s",
                    miner_height, " | ".join(status_parts),
                )
            max_gap = max(
                miner_height - last_heights[idx]
                for idx in hosts
                if last_heights[idx] is not None
            )
            poll_s = (
                WALLET_HOST_SYNC_POLL_NEAR_S if max_gap <= 1
                else WALLET_HOST_SYNC_POLL_FAR_S
            )
            time.sleep(poll_s)
        raise AssertionError(
            "Wallet host catch-up timed out after "
            f"{timeout}s (miner_h={self._rpc_retry(miner, lambda: miner.getblockcount(), label='getblockcount')})"
        )

    def _wait_wallet_host_rpc_quiet(self, parties, miner, *, quiet_s=2.0,
                                    stable_samples=3, timeout=None):
        """Block until wallet-host getblockcount latency is consistently low.

        After tip catch-up, Confirmed callbacks can still monopolize the wallet
        for a long time; listunspent (mweb_utxo_stats / Phase 8) must wait.
        """
        hosts = self._party_host_nodes(parties, miner=miner)
        if not hosts:
            return
        if timeout is None:
            timeout = max(int(self.rpc_timeout), 7200)
        deadline = time.monotonic() + timeout
        last_log = time.monotonic()
        self.log.info(
            "Phase6 waiting for wallet-host RPC quiet (<%.1fs x %d) hosts=%s",
            quiet_s, stable_samples, sorted(hosts.keys()),
        )
        streaks = {idx: 0 for idx in hosts}
        while time.monotonic() < deadline:
            all_quiet = True
            parts = []
            for node_idx in hosts:
                host = self.nodes[node_idx]
                try:
                    latency, height = self._measure_rpc_latency(host)
                except JSONRPCException as e:
                    streaks[node_idx] = 0
                    all_quiet = False
                    parts.append(f"node{node_idx}=err:{e}")
                    continue
                if latency <= quiet_s:
                    streaks[node_idx] += 1
                else:
                    streaks[node_idx] = 0
                    all_quiet = False
                parts.append(
                    f"node{node_idx} h={height} rpc={latency:.2f}s "
                    f"streak={streaks[node_idx]}/{stable_samples}"
                )
                if streaks[node_idx] < stable_samples:
                    all_quiet = False
            now = time.monotonic()
            if now - last_log >= WALLET_HOST_SYNC_LOG_S:
                last_log = now
                self.log.info("Phase6 RPC quiet wait: %s", " | ".join(parts))
            if all_quiet:
                self.log.info("Phase6 wallet-host RPC quiet")
                return
            time.sleep(WALLET_HOST_SYNC_POLL_NEAR_S)
        raise AssertionError(
            "Wallet host RPC did not become quiet within "
            f"{timeout}s ({' | '.join(parts)})"
        )

    def _generate_long(self, miner, nblocks=1, **kwargs):
        """generate() using full ``rpc_timeout`` (HTTP client defaults to half)."""
        # NOTE: duplicate guard — method body continues below in file.
        rpc = miner._rpc
        old_timeout = rpc.timeout
        try:
            rpc.timeout = int(miner.rpc_timeout)
            return self.generate(miner, nblocks, **kwargs)
        finally:
            rpc.timeout = old_timeout

    def _restart_miner_wallet_policy(self, miner, *, disable_wallet, parties=None,
                                     label="", extra_args_append=None):
        """Stop/start miner; optionally drop wallets to skip validation callbacks."""
        idx = self._miner_node_index(miner)
        mempool = len(miner.getrawmempool())
        height = miner.getblockcount()
        self.log.info(
            "Restart node%d %s: disablewallet=%s height=%d mempool=%d append=%s",
            idx, label, disable_wallet, height, mempool, extra_args_append or [],
        )
        extra = self._miner_restart_extra_args(miner, disable_wallet=disable_wallet)
        if extra_args_append:
            extra = list(extra) + list(extra_args_append)
        self.restart_node(idx, extra_args=extra)
        miner = self.nodes[idx]
        if not disable_wallet and parties is not None:
            self._reload_miner_wallets(miner, parties)
        self.connect_full_mesh()
        return miner

    def mine_until_mempool_empty(self, miner, *, max_blocks=200, sync=False,
                                 log_interval_s=None, log_label="mine",
                                 disable_wallet=False, parties=None):
        """Mine until mempool drains or max_blocks.

        sync=False (default): skip inter-node sync while draining — MWEB peg-in
        blocks are expensive to relay; callers sync once after the wave.

        disable_wallet: stop/start miner with ``-disablewallet`` for the drain
        (diagnostic: skip wallet validation-interface callbacks during connect).

        Use getrawmempool(), not getmempoolinfo()['size']: MWEB-only entries
        can report size=0 while still pending.

        log_interval_s: if set, emit INFO heartbeats at most this often while
        draining (Phase 6 may need many blocks on a fat mempool).
        """
        if disable_wallet:
            miner = self._restart_miner_wallet_policy(
                miner, disable_wallet=True, label=f"{log_label} pre-mine",
            )
        try:
            last_log = time.monotonic()
            for i in range(max_blocks):
                mempool = miner.getrawmempool()
                if not mempool:
                    if sync:
                        self.sync_all()
                    return i
                if log_interval_s is not None:
                    now = time.monotonic()
                    if now - last_log >= log_interval_s:
                        last_log = now
                        self.log.info(
                            "  %s: block %d/%d height=%d mempool=%d",
                            log_label, i + 1, max_blocks, miner.getblockcount(),
                            len(mempool),
                        )
                gen = self._generate_long if disable_wallet else self.generate
                gen(miner, 1, sync_fun=self.no_op)
                if sync:
                    self.sync_all()
            left = len(miner.getrawmempool())
            if left:
                self.log.warning(
                    "mempool still has %d txs after %d blocks", left, max_blocks,
                )
            if sync:
                self.sync_all()
            return max_blocks
        finally:
            if disable_wallet:
                idx = self._miner_node_index(miner)
                miner = self._restart_miner_wallet_policy(
                    self.nodes[idx],
                    disable_wallet=False,
                    parties=parties,
                    label=f"{log_label} post-mine",
                )

    def wait_for_peer_mempool_sync(self, miner, peer, *, target_count,
                                   log_interval_s=60):
        """Wait until ``peer`` has relayed the builder mempool (count match)."""
        last_log = time.monotonic()
        while True:
            builder_n = len(miner.getrawmempool())
            peer_n = len(peer.getrawmempool())
            now = time.monotonic()
            if now - last_log >= log_interval_s:
                last_log = now
                self.log.info(
                    "Phase6 peer mempool sync: builder=%d peer=%d target=%d height=%d",
                    builder_n, peer_n, target_count, miner.getblockcount(),
                )
            if (peer_n >= target_count and builder_n >= target_count
                    and peer_n >= builder_n * 99 // 100):
                return builder_n, peer_n
            time.sleep(10)

    def wait_for_host_mempools_on_miner(self, miner, parties, *,
                                        log_interval_s=PHASE6_STATUS_INTERVAL_S):
        """Wait until the miner holds every transaction in the wallet hosts' mempools.

        mine_until_mempool_empty stops once the miner's mempool is empty, so
        mining before the hosts finish relaying leaves the rest unconfirmed.
        Fails if the number missing stops falling for PHASE6_RELAY_STALL_S.
        """
        hosts = self._party_host_nodes(parties, miner=miner)
        # A host behind the miner still holds transactions the miner has mined.
        self.wait_for_wallet_hosts_after_pegin_mine(miner, parties)
        best = None
        best_time = last_log = time.monotonic()
        while True:
            have = set(miner.getrawmempool())
            missing = sum(len(set(self.nodes[idx].getrawmempool()) - have) for idx in hosts)
            if missing == 0:
                return len(have)
            now = time.monotonic()
            if best is None or missing < best:
                best, best_time = missing, now
            if now - last_log >= log_interval_s:
                last_log = now
                self.log.info(
                    "Phase6 relay to miner: missing=%d miner_mempool=%d height=%d",
                    missing, len(have), miner.getblockcount(),
                )
            assert now - best_time < PHASE6_RELAY_STALL_S, (
                f"Phase6 relay to miner stalled: {missing} wallet-host transactions "
                f"missing from the miner, no progress for {PHASE6_RELAY_STALL_S}s"
            )
            time.sleep(10)

    def log_manual_mine_ready(self, miner, peer, *, builder_mempool, peer_mempool):
        """Emit a single grep-friendly line for external kill/restart/mine."""
        mi = self._miner_node_index(miner)
        pi = self.nodes.index(peer)
        self.log.info(
            "MANUAL_MINE_READY node%d height=%d builder_mempool=%d "
            "node%d peer_mempool=%d datadir=%s "
            "ACTION: SIGKILL builder, restart bitcoind-mine-test with "
            "-disablewallet + same args, addnode peer, generatetoaddress",
            mi, miner.getblockcount(), builder_mempool,
            pi, peer_mempool, miner.datadir_path,
        )

    def wait_manual_mine_external(self, miner, *, log_interval_s=600):
        """Keep nodes up while operator performs external kill/restart/mine.

        Avoid RPC here — builder may be unresponsive while wallet callbacks drain.
        """
        last_log = time.monotonic()
        while True:
            now = time.monotonic()
            if now - last_log >= log_interval_s:
                last_log = now
                self.log.info("MANUAL_MINE_READY: still waiting for external mine")
            time.sleep(30)

    def _phase6_log_stage(self, miner, stage, **fields):
        """Immediate Phase 6 stage line (not rate-limited)."""
        parts = []
        if "queued" in fields and "target" in fields:
            parts.append(f"queued={fields['queued']}/{fields['target']}")
        elif "queued" in fields:
            parts.append(f"queued={fields['queued']}")
        elif "target" in fields:
            parts.append(f"target={fields['target']}")
        for key in ("addrs", "wallets", "workers", "hosts", "wave", "sent"):
            if key in fields:
                parts.append(f"{key}={fields[key]}")
        if fields.get("height") is None and "height" not in fields:
            try:
                parts.append(f"height={miner.getblockcount()}")
            except JSONRPCException:
                pass
        elif "height" in fields:
            parts.append(f"height={fields['height']}")
        if fields.get("mempool") is None and "mempool" not in fields:
            try:
                parts.append(f"mempool={len(miner.getrawmempool())}")
            except JSONRPCException:
                pass
        elif "mempool" in fields:
            parts.append(f"mempool={fields['mempool']}")
        self.log.info("Phase6 %s: %s", stage, " ".join(parts))

    def _phase6_wallets_done(self, parties, per_wallet=None):
        """Parties with all per-wallet peg-ins queued (not a sum of mweb_done)."""
        default = per_wallet if per_wallet is not None else MWEB_BANK_PER_WALLET
        return sum(
            1 for p in parties
            if p.get("mweb_done", 0) >= party_mweb_bank(p, default)
        )

    def _phase6_status(self, miner, *, stage, last_log, queued, target, parties=None,
                       per_wallet=None, **extra):
        """Rate-limited Phase 6 progress (long queue/mine runs).

        Party ``mweb_done`` is peg-ins queued for that wallet (0..per_wallet).
        Do not sum ``mweb_done`` across parties — that mixes UTXO/peg-in counts
        with wallet completion. Use ``_phase6_wallets_done`` for wallets=X/Y.
        """
        now = time.monotonic()
        if now - last_log[0] < PHASE6_STATUS_INTERVAL_S:
            return
        last_log[0] = now
        if parties is not None and "wallets" not in extra:
            extra["wallets"] = (
                f"{self._phase6_wallets_done(parties, per_wallet)}/{len(parties)}"
            )
        self._phase6_log_stage(
            miner, stage, queued=queued, target=target, **extra,
        )

    def _phase6_precreate_party(self, party, per_wallet):
        party["mweb_dests"] = [
            party["rpc"].getnewaddress(address_type="mweb") for _ in range(per_wallet)
        ]
        party["mweb_done"] = 0
        return per_wallet

    def _phase6_host_batches(self, parties, parallel_nodes):
        """Partition parties for parallel Phase 6 workers (one batch per host)."""
        by_node = {}
        for p in parties:
            by_node.setdefault(p["node_idx"], []).append(p)
        if len(by_node) >= 2:
            batches = list(by_node.values())
            workers = min(parallel_nodes, len(batches))
            return batches, workers
        workers = min(parallel_nodes, len(parties))
        if workers < 2:
            return [parties], 1
        chunk = (len(parties) + workers - 1) // workers
        batches = [parties[i:i + chunk] for i in range(0, len(parties), chunk)]
        return batches, len(batches)

    def _phase6_host_label(self, batch):
        return f"node{batch[0]['node_idx']}"

    def _phase6_precreate_parallel(self, miner, parties, *, per_wallet,
                                   precreate_nodes, last_log):
        target = sum(party_mweb_bank(p, per_wallet) for p in parties)
        batches, workers = self._phase6_host_batches(parties, precreate_nodes)
        host_labels = ",".join(self._phase6_host_label(b) for b in batches)
        self._phase6_log_stage(
            miner, "pre-create start",
            wallets=len(parties), workers=workers,
            hosts=host_labels, target=target,
        )
        addrs_created = [0]
        wallets_done = [0]
        lock = threading.Lock()

        def worker(batch):
            for p in batch:
                quota = party_mweb_bank(p, per_wallet)
                self._phase6_precreate_party(p, quota)
                with lock:
                    addrs_created[0] += quota
                    wallets_done[0] += 1
                    self._phase6_status(
                        miner, stage="pre-create", last_log=last_log,
                        queued=addrs_created[0], target=target,
                        wallets=f"{wallets_done[0]}/{len(parties)}",
                    )

        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(worker, batches))
        self._phase6_log_stage(
            miner, "pre-create done",
            wallets=len(parties), target=target,
        )
        return target

    def _phase6_queue_pegin_wave(self, miner, parties, *, per_wallet, per_wave,
                                 amount, parallel_nodes, wave, last_log,
                                 queued, target):
        """Queue up to ``per_wave`` peg-ins per wallet, in parallel per host."""
        batches, workers = self._phase6_host_batches(parties, parallel_nodes)
        wave_queued = [0]
        lock = threading.Lock()

        def worker(batch):
            local = 0
            for p in batch:
                wallet_quota = party_mweb_bank(p, per_wallet)
                n_this_wallet = 0
                while p["mweb_done"] < wallet_quota and n_this_wallet < per_wave:
                    addr = p["mweb_dests"][p["mweb_done"]]
                    if self._safe_pegin(p["rpc"], addr, amount):
                        p["mweb_done"] += 1
                        local += 1
                        n_this_wallet += 1
                        with lock:
                            wave_queued[0] += 1
                            self._phase6_status(
                                miner, stage="queue", last_log=last_log,
                                queued=queued + wave_queued[0], target=target,
                                parties=parties, per_wallet=per_wallet, wave=wave,
                            )
                    else:
                        break
            return local

        with ThreadPoolExecutor(max_workers=workers) as ex:
            sent_parts = list(ex.map(worker, batches))
        sent_this_wave = sum(sent_parts)
        queued += sent_this_wave
        self._phase6_status(
            miner, stage="queue", last_log=last_log,
            queued=queued, target=target, parties=parties, per_wallet=per_wallet,
            wave=wave, workers=workers, sent=sent_this_wave,
        )
        return sent_this_wave, queued

    def mine_in_chunks(self, miner, *, pending_hint=0, max_blocks=50):
        """Alias: drain mempool (legacy name)."""
        return self.mine_until_mempool_empty(miner, max_blocks=max_blocks, sync=False)

    def phase_l1_fanout(self, miner, parties, *,
                       per_wallet=L1_FANOUT_PER_WALLET,
                       amount=L1_FANOUT_AMOUNT):
        """Phase 5: batched multi-output L1 fan-out (~17 blocks, not peel loop).

        Per wave: funder sendmany batches (while reserve coins last), then each
        wallet queues multi-output ``send`` txs (up to ``L1_OUTS_PER_TX`` outs
        per tx), then mine once until mempool drains. spendzeroconfchange=0 is
        fine — multiple confirmed inputs / many outputs per tx are allowed.
        """
        funder = miner.get_wallet_rpc(self.default_wallet_name)
        target = sum(party_l1_fanout(p, per_wallet) for p in parties)
        for p in parties:
            quota = party_l1_fanout(p, per_wallet)
            p["l1_dests"] = [p["rpc"].getnewaddress() for _ in range(quota)]

        queued = 0
        wave = 0
        while queued < target:
            remaining = sum(len(p["l1_dests"]) for p in parties)
            if remaining == 0:
                break
            wave += 1
            sent_this_wave = 0

            # Funder: batched 0.05 stamps while mature coinbases remain.
            while remaining > 0:
                batch = []
                for p in parties:
                    while p["l1_dests"] and len(batch) < L1_FUNDER_SENDMANY_CHUNK:
                        batch.append((p, p["l1_dests"].pop()))
                if not batch:
                    break
                amounts = {addr: amount for _p, addr in batch}
                try:
                    funder.sendmany("", amounts, fee_rate=1)
                    sent_this_wave += len(batch)
                    queued += len(batch)
                    remaining -= len(batch)
                except JSONRPCException:
                    for p, addr in reversed(batch):
                        p["l1_dests"].append(addr)
                    break

            # Wallets: multi-output fan-out from confirmed L1 bank.
            for p in parties:
                while p["l1_dests"]:
                    n_out = self._queue_l1_multi_out_tx(p["rpc"], p["l1_dests"], amount)
                    if not n_out:
                        break
                    sent_this_wave += n_out
                    queued += n_out

            if sent_this_wave == 0:
                self.log.warning(
                    "L1 fan-out stalled at queued=%d / %d", queued, target,
                )
                break
            self.mine_until_mempool_empty(miner, max_blocks=80, sync=False)
            if wave <= 3 or wave % 5 == 0 or queued >= target:
                self.log.info(
                    "  L1 fan-out wave %d: queued=%d / %d outs_this_wave=%d height=%d",
                    wave, queued, target, sent_this_wave, miner.getblockcount(),
                )
        self.log.info(
            "Phase5 L1 fan-out done: queued=%d / %d waves=%d height=%d",
            queued, target, wave, miner.getblockcount(),
        )
        return queued

    def phase_mweb_pegin_bank(self, miner, parties, *,
                              per_wallet=MWEB_BANK_PER_WALLET,
                              amount=MWEB_BANK_AMOUNT,
                              per_wave=MWEB_PEGINS_PER_WALLET_PER_WAVE,
                              precreate_nodes=DEFAULT_MWEB_PRECREATE_NODES,
                              peer=None,
                              defer_mine=False):
        """Phase 6: peg-in to fresh MWEB addresses.

        Each wave queues up to ``per_wave`` peg-ins per wallet (default: all
        remaining, ≤163). Normally mine until drained once per wave.

        ``defer_mine``: queue only; wait for ``peer`` to mirror the builder
        mempool, log MANUAL_MINE_READY, then block for external kill/restart/mine.

        ``precreate_nodes``: parallel host workers for pre-create and peg-in
        queue (one batch per wallet-host node when wallets are split).
        Returns queued peg-in count (not listunspent; that undercounts).
        """
        last_log = [time.monotonic()]
        self._phase6_precreate_parallel(
            miner, parties, per_wallet=per_wallet,
            precreate_nodes=precreate_nodes, last_log=last_log,
        )

        target = sum(party_mweb_bank(p, per_wallet) for p in parties)
        batches, workers = self._phase6_host_batches(parties, precreate_nodes)
        host_labels = ",".join(self._phase6_host_label(b) for b in batches)
        self._phase6_log_stage(
            miner, "peg-in queue start",
            target=target, workers=workers, hosts=host_labels,
        )
        queued = 0
        wave = 0
        last_log[0] = time.monotonic()
        while queued < target:
            wave += 1
            self._phase6_log_stage(
                miner, f"peg-in wave {wave} queue start",
                queued=queued, target=target, workers=workers, hosts=host_labels,
            )
            sent_this_wave, queued = self._phase6_queue_pegin_wave(
                miner, parties,
                per_wallet=per_wallet, per_wave=per_wave, amount=amount,
                parallel_nodes=precreate_nodes, wave=wave,
                last_log=last_log, queued=queued, target=target,
            )
            if sent_this_wave == 0:
                self.log.warning(
                    "MWEB bank stalled at queued=%d / %d (need more L1 UTXOs)",
                    queued, target,
                )
                break
            if defer_mine:
                break
            self.wait_for_host_mempools_on_miner(miner, parties)
            self._phase6_log_stage(
                miner, f"peg-in wave {wave} mine start",
                queued=queued, target=target, sent=sent_this_wave,
            )
            last_log[0] = time.monotonic()
            blocks = self.mine_until_mempool_empty(
                miner, max_blocks=200, sync=False,
                log_interval_s=PHASE6_STATUS_INTERVAL_S,
                log_label=f"Phase6 wave {wave} mine",
            )
            if wave <= 5 or wave % 2 == 0 or queued >= target:
                self.log.info(
                    "  MWEB bank wave %d: queued=%d / %d sent=%d mined=%d height=%d",
                    wave, queued, target, sent_this_wave, blocks,
                    miner.getblockcount(),
                )
        if defer_mine:
            assert peer is not None, "defer_mine requires peer node for relay check"
            self._phase6_log_stage(
                miner, "peg-in queue done awaiting peer relay",
                queued=queued, target=target,
            )
            builder_n, peer_n = self.wait_for_peer_mempool_sync(
                miner, peer, target_count=queued,
                log_interval_s=PHASE6_STATUS_INTERVAL_S,
            )
            self.log.info(
                "Phase6 peer relay complete: builder=%d peer=%d queued=%d",
                builder_n, peer_n, queued,
            )
            self.log_manual_mine_ready(
                miner, peer, builder_mempool=builder_n, peer_mempool=peer_n,
            )
            self.wait_manual_mine_external(miner)
            return queued
        self.wait_for_wallet_hosts_after_pegin_mine(miner, parties)
        self._wait_wallet_host_rpc_quiet(parties, miner)
        nonempty, total_utxo, mx = self.mweb_utxo_stats(parties)
        self.log.info(
            "Phase6 MWEB bank done: queued=%d / %d height=%d "
            "confirmed_mweb_utxos=%d wallets_nonempty=%d max/wallet=%d",
            queued, target, miner.getblockcount(), total_utxo, nonempty, mx,
        )
        # Bare sendtoaddress used to recycle via MWEB_TO_MWEB (~net-zero UTXOs).
        min_expected = min(queued, max(1, queued * 9 // 10))
        assert total_utxo >= min_expected, (
            f"MWEB bank did not accumulate: queued={queued} "
            f"confirmed_utxos={total_utxo} (expected ≥{min_expected}). "
            f"Peg-ins must be L1-forced; check _safe_pegin."
        )
        return queued

    def mweb_utxo_stats(self, parties):
        nonempty = 0
        total = 0
        mx = 0
        for p in parties:
            n = len(self._mweb_utxos(p["rpc"]))
            if n:
                nonempty += 1
            total += n
            mx = max(mx, n)
        return nonempty, total, mx

    def _sendall_inputs(self, wallet, dest, utxos, *, fee_rate=1):
        """Spend exactly these confirmed UTXOs to dest via sendall."""
        if not utxos:
            return False
        inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
        try:
            wallet.sendall(recipients=[dest], fee_rate=fee_rate, options={"inputs": inputs})
            return True
        except JSONRPCException:
            try:
                # Older/alternate named form used in some wallet tests.
                wallet.sendall(recipients=[dest], inputs=inputs, fee_rate=fee_rate)
                return True
            except JSONRPCException:
                return False

    def queue_mweb_phase8_pack(self, parties, *,
                               peels_per_wallet=PHASE8_PEELS_PER_WALLET,
                               input_cap=MWEB_INPUT_CAP,
                               weight_fill=True,
                               exact_drains=False):
        """Phase 8 MWEB pack for one GBT tip (confirmed bank only).

        Pass A queues changeless multi-input consolidations until ``input_cap``
        inputs sit in mempool.

        ``weight_fill=True`` (mid-band): partial 0.01→0.009 spends on every
        remaining bank coin — **never** use for envelope oversize (poisons GBT).

        ``exact_drains=True`` (envelope): after Pass A, 1-in/1-out exact spends
        on remaining 0.01 bank coins to add outputs/weight without pay+change bloat.
        """
        if peels_per_wallet:
            self.log.warning(
                "Phase8 peels_per_wallet=%d ignored (use pass A/B pack)",
                peels_per_wallet,
            )
        if weight_fill and exact_drains:
            raise ValueError("weight_fill and exact_drains are mutually exclusive")
        consol_queued = 0
        consol_inputs = 0
        fill_queued = 0
        fill_inputs = 0
        drain_queued = 0
        failed = 0
        n = len(parties)
        dest_idx = 0

        # --- Pass A: high-input changeless consolidations ---
        for p in parties:
            if consol_inputs >= input_cap:
                break
            utxos = self._mweb_utxos(p["rpc"])
            if not utxos:
                continue
            while utxos and consol_inputs < input_cap:
                room = input_cap - consol_inputs
                batch_size = min(len(utxos), room)
                if batch_size < 1:
                    break
                batch = utxos[:batch_size]
                utxos = utxos[batch_size:]
                dest = parties[dest_idx % n]["rpc"].getnewaddress(address_type="mweb")
                dest_idx += 1
                ok, n_in = self._safe_mweb_consolidate(p["rpc"], dest, batch)
                if ok:
                    consol_queued += 1
                    consol_inputs += n_in
                else:
                    failed += 1
                    break

        if weight_fill:
            # --- Pass B (mid-band): partial spends — not for envelope tests ---
            for p in parties:
                utxos = [
                    u for u in self._mweb_utxos(p["rpc"])
                    if Decimal(str(u["amount"])) >= MWEB_BANK_AMOUNT
                ]
                for _u in utxos:
                    dest = parties[dest_idx % n]["rpc"].getnewaddress(address_type="mweb")
                    dest_idx += 1
                    if self._safe_mweb_weight_fill(p["rpc"], dest):
                        fill_queued += 1
                        fill_inputs += 1
                    else:
                        failed += 1
        elif exact_drains:
            # --- Pass B (envelope): exact 1-in drains on remaining bank coins ---
            for p in parties:
                utxos = [
                    u for u in self._mweb_utxos(p["rpc"])
                    if Decimal(str(u["amount"])) >= MWEB_BANK_AMOUNT
                ]
                for _u in utxos:
                    dest = parties[dest_idx % n]["rpc"].getnewaddress(address_type="mweb")
                    dest_idx += 1
                    if self._safe_mweb_exact_drain(p["rpc"], dest):
                        drain_queued += 1
                    else:
                        failed += 1

        total_inputs = consol_inputs + fill_inputs
        est_mweb_weight = consol_queued * MW_WEIGHT_CONSOL
        if weight_fill:
            est_mweb_weight += fill_queued * MW_WEIGHT_PARTIAL
        elif exact_drains:
            est_mweb_weight += drain_queued * MW_WEIGHT_EXACT_DRAIN
        self.log.info(
            "Phase8 MWEB pack: consolidations=%d (~%d in) weight_fill=%d (~%d in) "
            "exact_drains=%d mempool_total_inputs≈%d est_mweb_weight≈%d fail=%d",
            consol_queued, consol_inputs, fill_queued, fill_inputs,
            drain_queued, total_inputs, est_mweb_weight, failed,
        )
        if consol_inputs < min(input_cap, GBT_MIN_MWEB_INPUTS_ENVELOPE) and exact_drains:
            self.log.warning(
                "Phase8 pass A queued only %d consolidation inputs (want ≥%d for envelope)",
                consol_inputs, min(input_cap, GBT_MIN_MWEB_INPUTS_ENVELOPE),
            )
        return consol_queued + fill_queued + drain_queued, total_inputs

    def _abandon_unconfirmed_party_txs(self, parties):
        """Abandon wallet-unconfirmed txs so roles can be re-queued with new fees."""
        abandoned = 0
        for p in parties:
            wallet = p["rpc"]
            try:
                txs = wallet.listtransactions("*", 1_000_000, 0, True)
            except JSONRPCException:
                continue
            seen = set()
            for tx in txs:
                if int(tx.get("confirmations", 1)) != 0:
                    continue
                txid = tx.get("txid")
                if not txid or txid in seen:
                    continue
                seen.add(txid)
                try:
                    wallet.abandontransaction(txid)
                    abandoned += 1
                except JSONRPCException:
                    pass
        return abandoned

    def _reset_pack_mempools(self, miner, parties):
        """Abandon pack txs and restart nodes so mempools drop the abandoned entries.

        ``abandontransaction`` only frees wallet coins; bitcoind keeps the txs in
        mempool until restart (or RBF). Restart is the reliable harness reset.
        """
        n_abandon = self._abandon_unconfirmed_party_txs(parties)
        idxs = {self._miner_node_index(miner)}
        for p in parties:
            idxs.add(p["node_idx"])
        self.log.info(
            "Pack mempool reset: abandoned=%d restarting nodes=%s",
            n_abandon, sorted(idxs),
        )
        for idx in sorted(idxs):
            extra = self._node_restart_extra_args(idx, disable_wallet=False)
            self.restart_node(idx, extra_args=extra)
            node = self.nodes[idx]
            name = self.default_wallet_name
            if name and name not in node.listwallets():
                try:
                    node.loadwallet(name)
                except JSONRPCException:
                    pass
            self._reload_node_wallets(idx, parties)
        self.ensure_peer_mesh()
        self.sync_blocks(timeout=int(self.rpc_timeout))
        return self.nodes[self._miner_node_index(miner)]

    def _densify_plan_for_inputs(self, plan, *, attempt):
        """On retry, shift inputs into consolidations (cheaper MWEB weight).

        Cap-fill queues ~5k partials (39 wt each). CreateNewBlock then hits the
        MWEB weight cap (~200k) with a partial-heavy mix at ~48k body inputs.
        Raising ``inputs_per_tx`` (toward the per-wallet bank) and cutting
        partials keeps ``mweb_inputs_total`` while dropping weight so consols fit.
        """
        if attempt <= 0 or plan.extra_mweb_inputs <= 0:
            return plan
        # Per-wallet MWEB bank after peg-ins (see MWEB_BANK_PER_WALLET).
        max_ipt = MWEB_BANK_PER_WALLET
        if plan.mweb_consol_inputs_per_tx >= max_ipt:
            return plan
        keep_partials = max(64, plan.mweb_partial_txs // (2 + attempt))
        want_move = plan.mweb_partial_txs - keep_partials
        room = (max_ipt - plan.mweb_consol_inputs_per_tx) * plan.mweb_consol_txs
        move = min(want_move, room)
        # Only move whole inputs-per-consol steps so no wallet exceeds the bank.
        per = move // plan.mweb_consol_txs
        if per <= 0:
            return plan
        move = per * plan.mweb_consol_txs
        new_ipt = plan.mweb_consol_inputs_per_tx + per
        new_partials = plan.mweb_partial_txs - move
        denser = CapBlockPlan(
            mweb_consol_txs=plan.mweb_consol_txs,
            mweb_consol_inputs_per_tx=new_ipt,
            mweb_partial_txs=new_partials,
            l1_pad_txs=plan.l1_pad_txs,
            l1_pad_inputs_per_tx=plan.l1_pad_inputs_per_tx,
            extra_mweb_inputs=plan.extra_mweb_inputs,
            extra_partial_txs=plan.extra_partial_txs,
        )
        assert denser.mweb_inputs_total == plan.mweb_inputs_total, (
            denser.mweb_inputs_total, plan.mweb_inputs_total
        )
        assert new_ipt + denser.extra_mweb_inputs <= max_ipt, (
            new_ipt, denser.extra_mweb_inputs, max_ipt
        )
        self.log.info(
            "Densify plan attempt %d: ipt %d → %d, partials %d → %d "
            "(inputs_total=%d, est_weight %d → %d)",
            attempt, plan.mweb_consol_inputs_per_tx, denser.mweb_consol_inputs_per_tx,
            plan.mweb_partial_txs, denser.mweb_partial_txs,
            denser.mweb_inputs_total,
            plan.mweb_weight_estimate, denser.mweb_weight_estimate,
        )
        return denser

    def _gbt_meets_plan_targets(self, plan, diag, *, base_plan=None):
        """Strict targets for reject variants; soft floors otherwise."""
        target = base_plan if base_plan is not None else plan
        if target.extra_mweb_inputs > 0:
            return diag["mweb_inputs"] >= target.mweb_inputs_total
        if target.extra_partial_txs > 0:
            want_k = (
                target.mweb_consol_txs + target.mweb_partial_txs + target.extra_partial_txs
            )
            return diag["mweb_kernels"] >= want_k
        return True

    def _prioritise_pack_roles(self, miner, consol_txids, partial_txids):
        """Force consolidations ahead of partials on the next CreateNewBlock walk."""
        for txid in consol_txids:
            try:
                miner.prioritisetransaction(txid=txid, fee_delta=PACK_PRIORITY_FEE_DELTA)
            except JSONRPCException as e:
                self.log.warning("prioritise consol %s: %s", txid, e)
        for txid in partial_txids:
            try:
                miner.prioritisetransaction(txid=txid, fee_delta=-PACK_PRIORITY_FEE_DELTA)
            except JSONRPCException as e:
                self.log.warning("prioritise partial %s: %s", txid, e)

    def queue_deterministic_envelope_pack(self, parties, plan, *,
                                          consol_fee_rate=None, partial_fee_rate=None):
        """Queue **exactly** the txs in ``plan`` by role — no blind wallet walks.

        Roles (assigned up front from inventory, then executed):
          1. ``plan.mweb_consol_txs`` wallets each produce one consolidation
             (inputs_per_tx, with optional extra_mweb_inputs on the first)
          2. Exactly ``plan.mweb_partial_txs + extra_partial_txs`` leftover coins
             → 1-in/2-out fills
          3. Exactly ``plan.l1_pad_txs`` L1 100-in pads

        Consolidations use a higher fee_rate so BlockAssembler prefers them.
        Returns ``(queued_count, consol_txids, partial_txids)``.
        """
        if consol_fee_rate is None:
            consol_fee_rate = ENVELOPE_CONSOL_FEE_RATE
        if partial_fee_rate is None:
            partial_fee_rate = ENVELOPE_PARTIAL_FEE_RATE
        need_in = plan.mweb_consol_inputs_per_tx
        dest_idx = 0
        n = len(parties)

        def next_dest_mweb():
            nonlocal dest_idx
            addr = parties[dest_idx % n]["rpc"].getnewaddress(address_type="mweb")
            dest_idx += 1
            return addr

        def next_dest_l1():
            nonlocal dest_idx
            addr = parties[dest_idx % n]["rpc"].getnewaddress()
            dest_idx += 1
            return addr

        self.log.info(
            "CapBlockPlan queue: %s consol_fee=%d partial_fee=%d",
            plan.describe(), consol_fee_rate, partial_fee_rate,
        )
        wire_est, model_detail = model_plan_wire(plan)
        self.log.info(
            "CapBlockPlan model: wire≈%d envelope=%d bip324=%d gap_env=%d detail_mweb_in=%d",
            wire_est, PLAN_MWEB_ENVELOPE, PLAN_BIP324_CAP,
            PLAN_MWEB_ENVELOPE - wire_est,
            model_detail.get("mweb_inputs", plan.mweb_inputs_total),
        )

        # --- Role A: consolidations (first may carry extra_mweb_inputs) ---
        consol_wallets = []
        for p in parties:
            if len(consol_wallets) >= plan.mweb_consol_txs:
                break
            want = need_in + (plan.extra_mweb_inputs if not consol_wallets else 0)
            if len(self._mweb_utxos(p["rpc"])) >= want:
                consol_wallets.append(p)
        if len(consol_wallets) < plan.mweb_consol_txs:
            raise AssertionError(
                f"Need {plan.mweb_consol_txs} wallets with ≥{need_in} MWEB UTXOs; "
                f"only {len(consol_wallets)} available"
            )

        consol_queued = 0
        consol_inputs = 0
        consol_txids = []
        for i, p in enumerate(consol_wallets):
            utxos = self._mweb_utxos(p["rpc"])
            batch_n = need_in + (plan.extra_mweb_inputs if i == 0 else 0)
            batch = utxos[:batch_n]
            ok, n_in, txid = self._safe_mweb_consolidate(
                p["rpc"], next_dest_mweb(), batch, fee_rate=consol_fee_rate,
                return_txid=True,
            )
            if not ok or n_in != batch_n:
                raise AssertionError(
                    f"Consolidation role failed on {p['name']}: ok={ok} n_in={n_in} "
                    f"want {batch_n}"
                )
            if txid:
                consol_txids.append(txid)
            consol_queued += 1
            consol_inputs += n_in
        assert consol_queued == plan.mweb_consol_txs

        # --- Role B: partials including optional overweight extras ---
        partial_needed = plan.mweb_partial_txs + plan.extra_partial_txs
        partial_slots = []
        for p in parties:
            for u in self._mweb_utxos(p["rpc"]):
                if Decimal(str(u["amount"])) >= MWEB_BANK_AMOUNT:
                    partial_slots.append((p, u))
                    if len(partial_slots) >= partial_needed:
                        break
            if len(partial_slots) >= partial_needed:
                break
        if len(partial_slots) < partial_needed:
            raise AssertionError(
                f"Need {partial_needed} partial slots (≥{MWEB_BANK_AMOUNT} MWEB); "
                f"only {len(partial_slots)} available after consolidations"
            )
        partial_slots = partial_slots[:partial_needed]

        partial_queued = 0
        partial_txids = []
        for p, u in partial_slots:
            ok, txid = self._safe_mweb_weight_fill(
                p["rpc"], next_dest_mweb(), fee_rate=partial_fee_rate, utxo=u,
                return_txid=True,
            )
            if not ok:
                raise AssertionError(
                    f"Partial role failed on {p['name']} after {partial_queued} successes"
                )
            if txid:
                partial_txids.append(txid)
            partial_queued += 1
        assert partial_queued == partial_needed

        # --- Role C: exactly L L1 pads (reserve trim spare on first wallet only) ---
        l1_queued = 0
        pad_inputs = plan.l1_pad_inputs_per_tx
        for i, p in enumerate(parties):
            if l1_queued >= plan.l1_pad_txs:
                break
            while l1_queued < plan.l1_pad_txs:
                utxos = self._l1_utxos(p["rpc"])
                # Trim spare only on the first party (OP_RETURN loop uses parties[0]).
                spare = L1_TRIM_SPARE_INPUTS if i == 0 else 0
                if len(utxos) < pad_inputs + spare:
                    break
                selected = utxos[:pad_inputs]
                if not self._sendall_inputs(p["rpc"], next_dest_l1(), selected):
                    raise AssertionError(
                        f"L1 pad role failed on {p['name']} after {l1_queued} successes"
                    )
                l1_queued += 1
        if l1_queued < plan.l1_pad_txs:
            # Inventory diagnostic for the iterative loop.
            avail = [len(self._l1_utxos(p["rpc"])) for p in parties[:16]]
            raise AssertionError(
                f"L1 pad role short: {l1_queued} < {plan.l1_pad_txs} "
                f"(need {pad_inputs}/tx after peg-ins; sample_l1_counts={avail}). "
                f"Increase L1_FANOUT_PER_WALLET (now {L1_FANOUT_PER_WALLET})."
            )

        self.log.info(
            "CapBlockPlan queued EXACT: consol=%d (~%d in) partial=%d l1_pad=%d",
            consol_queued, consol_inputs, partial_queued, l1_queued,
        )
        return (
            consol_queued + partial_queued + l1_queued,
            consol_txids,
            partial_txids,
        )

    def _assert_gbt_cap_pack(self, miner, gbt, *, builder_mempool, plan):
        """Validate GBT matches ``CapBlockPlan`` before assembly."""
        diag = gbt_pack_diagnostics(gbt)
        min_wire = gbt_min_wire_for_plan(plan)
        self.log.info(
            "Phase8 GBT pack: builder_mempool=%d est=%d (min≈%d) l1_txs=%d l1_wire=%d "
            "mweb_wire=%d mweb_in=%d mweb_out=%d mweb_kernels=%d plan_mempool≈%d",
            builder_mempool, diag["gbt_est"], min_wire, diag["l1_txs"], diag["l1_wire"],
            diag["mweb_wire"], diag["mweb_inputs"], diag["mweb_outputs"],
            diag["mweb_kernels"], plan.total_mempool_txs,
        )
        gbt_matches_cap_plan(gbt, plan, gbt_diag=diag)
        if diag["gbt_est"] < min_wire:
            wire_est, _ = model_plan_wire(plan)
            raise AssertionError(
                f"Phase8 GBT base pack too small: est={diag['gbt_est']} < min≈{min_wire} "
                f"(plan modeled {wire_est}). diag={diag}"
            )
        return diag

    def flood_cap_fill_pack(self, miner, parties, *, plan=None):
        """Phase 8 for production-cap fill: exact role pack → GBT.

        Iterates when the template misses plan targets (your fee-replace loop):
          1. Queue roles (consols outrank partials on fee_rate).
          2. GBT; if short, ``prioritisetransaction`` to prefer consols and rebuild.
          3. If still short, abandon + restart mempools, densify (fewer partials),
             bump consol fees, and re-queue.
        Reject variants require strict input/kernel targets; cap-fill keeps soft floors.
        """
        if plan is None:
            plan = compute_cap_fill_plan()
        base_plan = plan
        wire_est, _ = model_plan_wire(plan)
        self.log.info(
            "CapBlockPlan: %s modeled_base≈%d envelope=%d bip324=%d",
            plan.describe(), wire_est, PLAN_MWEB_ENVELOPE, PLAN_BIP324_CAP,
        )
        if wire_est > PLAN_MWEB_ENVELOPE:
            raise AssertionError(
                f"Preflight: modeled wire {wire_est} exceeds envelope {PLAN_MWEB_ENVELOPE}"
            )

        last_diag = None
        for attempt in range(PACK_GBT_MAX_ATTEMPTS):
            plan = self._densify_plan_for_inputs(base_plan, attempt=attempt)
            consol_fee = ENVELOPE_CONSOL_FEE_RATE + attempt * 250
            partial_fee = ENVELOPE_PARTIAL_FEE_RATE

            if attempt > 0:
                miner = self._reset_pack_mempools(miner, parties)
                self.log.info(
                    "Pack GBT retry %d/%d: densify + consol_fee=%d",
                    attempt + 1, PACK_GBT_MAX_ATTEMPTS, consol_fee,
                )

            _queued, consol_txids, partial_txids = self.queue_deterministic_envelope_pack(
                parties, plan,
                consol_fee_rate=consol_fee,
                partial_fee_rate=partial_fee,
            )
            builder_mempool = self._sync_pack_mempool_to_miner(miner, parties)
            expected = plan.total_mempool_txs
            if builder_mempool > expected * 11 // 10:
                raise AssertionError(
                    f"Phase8 mempool poisoned: builder={builder_mempool} >> "
                    f"plan={expected} (extra txs will break GBT)"
                )
            self.log.info(
                "Phase8 GBT starting attempt=%d (builder_mempool=%d); "
                "expect minutes for ~5k MWEB txs",
                attempt, builder_mempool,
            )

            # Inner loop: fee-priority rebuild without re-queueing.
            for prio_round in range(3):
                if prio_round > 0:
                    self.log.info(
                        "Pack GBT priority bump round %d (consols +%d sats, partials -%d)",
                        prio_round, PACK_PRIORITY_FEE_DELTA, PACK_PRIORITY_FEE_DELTA,
                    )
                    self._prioritise_pack_roles(miner, consol_txids, partial_txids)
                with self._full_rpc_timeout(miner):
                    est, _n_tx, gbt = gbt_wire_estimate(miner)
                diag = gbt_pack_diagnostics(gbt)
                last_diag = diag
                self.log.info(
                    "Phase8 GBT attempt=%d prio=%d: est=%d mweb_in=%d mweb_kernels=%d "
                    "want_in>=%s want_kernels>=%s",
                    attempt, prio_round, diag["gbt_est"], diag["mweb_inputs"],
                    diag["mweb_kernels"],
                    plan.mweb_inputs_total if plan.extra_mweb_inputs else "soft",
                    (plan.mweb_consol_txs + plan.mweb_partial_txs + plan.extra_partial_txs)
                    if plan.extra_partial_txs else "soft",
                )
                if self._gbt_meets_plan_targets(plan, diag, base_plan=base_plan):
                    diag = self._assert_gbt_cap_pack(
                        miner, gbt, builder_mempool=builder_mempool, plan=plan,
                    )
                    return est, diag, plan
                if prio_round == 0 and (consol_txids or partial_txids):
                    continue  # try priority bump before abandoning
                break

            self.log.warning(
                "Pack GBT attempt %d missed targets (mweb_in=%d kernels=%d); "
                "will abandon/reset if retries remain",
                attempt, diag["mweb_inputs"], diag["mweb_kernels"],
            )

        raise AssertionError(
            f"Phase8 GBT never met plan targets after {PACK_GBT_MAX_ATTEMPTS} attempts: "
            f"last={last_diag} plan={base_plan.describe()}"
        )

    def flood_envelope_reject_pack(self, miner, parties):
        """Back-compat alias → cap-fill pack (no longer targets oversize via plan)."""
        return self.flood_cap_fill_pack(miner, parties)

    def assemble_and_trim_to_size(self, miner, parties, *, target_s=None,
                                  max_attempts=OP_RETURN_TRIM_MAX_ATTEMPTS):
        """Assemble from GBT; optionally OP_RETURN-trim until ``len(serialize)==target_s``.

        If ``target_s`` is None, returns the first assembled block (achieved max).
        Trim picks a small confirmed L1 input set once, then RBFs that same
        outpoint set (BIP125) while adjusting OP_RETURN payload and fee_rate.

        BIP125 requires each replacement to pay a higher *absolute* fee. Shrinking
        the OP_RETURN reduces vsize, so a fixed +10 sat/vB bump is not enough —
        fee_rate is derived from an absolute-fee floor that only rises after a
        replacement is observed in the miner mempool.
        """
        block = assemble_solved_block_from_gbt_with_timeout(
            miner, rpc_timeout=miner.rpc_timeout,
        )
        S = len(block.serialize())
        if target_s is None or S == target_s:
            self.log.info("Assembled block wire=%d (target=%s)", S, target_s)
            return block, S

        trim_party = parties[0]
        wallet = trim_party["rpc"]
        utxos = self._l1_utxos(wallet)
        if len(utxos) < 1:
            raise AssertionError(
                f"No L1 UTXOs for OP_RETURN trim (S={S} target={target_s})"
            )
        # One (or few) confirmed inputs, locked for the whole RBF loop.
        n_in = min(len(utxos), 2)
        selected = utxos[:n_in]
        dest = parties[min(1, len(parties) - 1)]["rpc"].getnewaddress()
        self.log.info(
            "OP_RETURN trim RBF: locking %d L1 input(s) %s",
            n_in,
            [(u["txid"][:8], u["vout"]) for u in selected],
        )

        if S < target_s:
            payload_len = min(OP_RETURN_MAX_PAYLOAD, target_s - S)
        else:
            # Already over: introduce a replaceable high-fee tx that can later
            # shrink via smaller payloads (displacing itself under RBF).
            payload_len = min(OP_RETURN_MAX_PAYLOAD, max(1, S - target_s))

        # Absolute fee floor for the next BIP125 replacement (sats). Starts at 0
        # so the first send only needs TRIM_FEE_RATE; then tracks the live
        # mempool spender's fee + bump.
        min_abs_fee_sats = 0
        live_txid = None
        for attempt in range(max_attempts):
            delta = target_s - S
            vsize_est = self._estimate_op_return_trim_vsize(n_in, payload_len)
            fee_rate = self._fee_rate_for_abs_floor(
                vsize_est, min_abs_fee_sats + TRIM_RBF_ABS_FEE_BUMP_SATS,
            )
            self.log.info(
                "OP_RETURN trim attempt %d: S=%d target=%d delta=%d "
                "payload_len=%d fee_rate=%d vsize_est=%d min_abs_fee=%d "
                "live=%s",
                attempt, S, target_s, delta, payload_len, fee_rate, vsize_est,
                min_abs_fee_sats, (live_txid or "-")[:8],
            )
            if delta == 0:
                break

            payload_hex = (b"\xab" * payload_len).hex() if payload_len > 0 else ""
            new_txid = self._queue_op_return_trim_tx(
                wallet, inputs=selected, dest=dest,
                payload_hex=payload_hex, fee_rate=fee_rate,
            )
            if not new_txid:
                # CompactSize cliffs / fee-floor: nudge payload, raise abs floor.
                min_abs_fee_sats = max(
                    min_abs_fee_sats + TRIM_RBF_ABS_FEE_BUMP_SATS,
                    min_abs_fee_sats + 10 * vsize_est,
                )
                for adj in (0, 1, -1, 2, -2, 8, -8, 16, -16):
                    plen = max(0, min(OP_RETURN_MAX_PAYLOAD, payload_len + adj))
                    vs = self._estimate_op_return_trim_vsize(n_in, plen)
                    fr = self._fee_rate_for_abs_floor(
                        vs, min_abs_fee_sats + TRIM_RBF_ABS_FEE_BUMP_SATS,
                    )
                    new_txid = self._queue_op_return_trim_tx(
                        wallet, inputs=selected, dest=dest,
                        payload_hex=(b"\xab" * plen).hex() if plen > 0 else "",
                        fee_rate=fr,
                    )
                    if new_txid:
                        payload_len = plen
                        fee_rate = fr
                        break
            if not new_txid:
                raise AssertionError(
                    f"OP_RETURN trim RBF send failed at attempt {attempt} "
                    f"S={S} target={target_s} fee_rate={fee_rate} "
                    f"payload_len={payload_len} min_abs_fee={min_abs_fee_sats}"
                )

            self._sync_pack_mempool_to_miner(miner, parties)
            spender = self._mempool_spender_of(miner, selected)
            if spender != new_txid:
                # Wallet accepted a conflict that mempool rejected (typical when
                # abs fee fell with a smaller OP_RETURN). Raise floor; do not
                # trust S for payload adaptation — GBT still has the old pad.
                with self._full_rpc_timeout(miner):
                    if live_txid:
                        try:
                            entry = miner.getmempoolentry(live_txid)
                            live_fee = int(
                                Decimal(str(entry["fees"]["base"])) * Decimal("1e8")
                            )
                            min_abs_fee_sats = max(min_abs_fee_sats, live_fee)
                        except JSONRPCException:
                            pass
                min_abs_fee_sats += max(
                    TRIM_RBF_ABS_FEE_BUMP_SATS,
                    # Next try must clear prior abs fee even at this smaller size.
                    fee_rate * vsize_est // 10,
                )
                self.log.warning(
                    "OP_RETURN trim RBF not in miner mempool: want=%s have=%s "
                    "raising min_abs_fee→%d",
                    new_txid[:8], (spender or "-")[:8], min_abs_fee_sats,
                )
                continue

            live_txid = new_txid
            with self._full_rpc_timeout(miner):
                entry = miner.getmempoolentry(live_txid)
                live_fee = int(Decimal(str(entry["fees"]["base"])) * Decimal("1e8"))
            min_abs_fee_sats = live_fee
            self.log.info(
                "OP_RETURN trim RBF landed: txid=%s fee_sats=%d fee_rate=%d",
                live_txid[:8], live_fee, fee_rate,
            )

            block = assemble_solved_block_from_gbt_with_timeout(
                miner, rpc_timeout=miner.rpc_timeout,
            )
            S = len(block.serialize())
            if S == target_s:
                self.log.info("OP_RETURN trim matched target wire=%d", S)
                return block, S

            # Adapt payload toward target only after a successful mempool RBF.
            payload_len = max(0, min(OP_RETURN_MAX_PAYLOAD, payload_len + (target_s - S)))

        raise AssertionError(
            f"OP_RETURN trim failed to hit exact size after {max_attempts} attempts: "
            f"S={S} target={target_s}. Stop and ask — CompactSize cliff?"
        )

    def measure_dumptxoutset_scale(self, node, *, dump_path, min_coins=ISSUE_E_MIN_MWEB_COINS):
        """Issue E: time dumptxoutset on the density-grown tip; log metrics (no wall-clock assert)."""
        t0 = time.time()
        result = node.dumptxoutset(dump_path, "latest")
        elapsed = time.time() - t0
        self.log.info(
            "Issue E dumptxoutset: elapsed=%.3fs path=%s coins_written=%s "
            "mweb_coins_written=%s mweb_hash=%s base_height=%s",
            elapsed, dump_path,
            result.get("coins_written"),
            result.get("mweb_coins_written"),
            result.get("mweb_hash"),
            result.get("base_height"),
        )
        for key in (
            "mweb_leafdb_entries_written",
            "mweb_o_dat_bytes",
            "mweb_leaf_dat_bytes",
            "mweb_prun_dat_bytes",
        ):
            if key in result:
                self.log.info("Issue E %s=%s", key, result[key])
        mweb_coins = int(result.get("mweb_coins_written", 0))
        if mweb_coins < min_coins:
            raise AssertionError(
                f"Issue E scale too small: mweb_coins_written={mweb_coins} < {min_coins}"
            )
        return result, elapsed

    def measure_assumeutxo_warm(self, loader_node, dump_path, *, timeout=600):
        """Issue A (A1): loadtxoutset and measure warm window only — no scheduler fix.

        Regtest only accepts dumptxoutset/loadtxoutset at heights with hardcoded
        assumeutxo metadata (110/200/299/750). Cap-fill tips are far above those
        heights, so this measurement usually logs a skip rather than failing the
        suite. Dense-bank dump metrics (Issue E) remain the scale signal.
        """
        try:
            t0 = time.time()
            result = loader_node.loadtxoutset(dump_path)
            load_elapsed = time.time() - t0
        except JSONRPCException as e:
            err = str(e)
            if "not recognized" in err or "snapshot heights are available" in err:
                self.log.info(
                    "Issue A warm measurement skipped: tip snapshot hash is not "
                    "in regtest assumeutxo metadata (%s). Issue E dump metrics "
                    "still apply at this bank scale.",
                    err.split("]")[0] if "]" in err else err[:160],
                )
            else:
                self.log.warning(
                    "Issue A loadtxoutset skipped/failed (measurement only): %s", e,
                )
            return {"load_elapsed": None, "error": str(e), "skipped": True}
        self.log.info(
            "Issue A loadtxoutset: elapsed=%.3fs result_keys=%s",
            load_elapsed, list(result.keys()) if isinstance(result, dict) else type(result),
        )
        # Wait until snapshot tip is active / IBD latch clears if exposed.
        t1 = time.time()
        deadline = t1 + timeout
        last_info = None
        while time.time() < deadline:
            try:
                info = loader_node.getchainstates()
                last_info = info
                if isinstance(info, dict):
                    states = info.get("chainstates", info.get("states", []))
                else:
                    states = info
                if states:
                    snap = None
                    for cs in states:
                        if cs.get("from_snapshot") or cs.get("snapshot_blockhash"):
                            snap = cs
                            break
                    if snap is not None:
                        warm_elapsed = time.time() - t1
                        self.log.info(
                            "Issue A warm observation: warm_wait=%.3fs snapshot=%s "
                            "blocks=%s ibd=%s",
                            warm_elapsed, snap.get("snapshot_blockhash"),
                            snap.get("blocks"), snap.get("initialblockdownload"),
                        )
                        return {
                            "load_elapsed": load_elapsed,
                            "warm_elapsed": warm_elapsed,
                            "chainstates": info,
                        }
            except JSONRPCException as e:
                self.log.info("Issue A getchainstates: %s", e)
            time.sleep(2)
        self.log.warning(
            "Issue A warm measurement timed out after %.1fs last=%s",
            timeout, last_info,
        )
        return {
            "load_elapsed": load_elapsed,
            "warm_elapsed": time.time() - t1,
            "chainstates": last_info,
            "timed_out": True,
        }

    def _assert_gbt_envelope_pack(self, miner, gbt, *, builder_mempool, plan):
        return self._assert_gbt_cap_pack(
            miner, gbt, builder_mempool=builder_mempool, plan=plan,
        )

    def queue_mweb_consolidations(self, parties, *,
                                  inputs_per_tx=INPUTS_PER_CONSOLIDATION,
                                  max_txs=8000):
        """Back-compat: Phase 8 pack (ignores thin inputs_per_tx)."""
        queued, _inputs = self.queue_mweb_phase8_pack(parties)
        return queued

    def queue_l1_witness_pad(self, parties, *,
                             inputs_per_tx=L1_PAD_INPUTS_PER_TX,
                             max_txs=L1_PAD_MAX_TXS):
        """Multi-input L1 P2WPKH pads from the fan-out bank (witness bytes)."""
        queued = 0
        approx_inputs = 0
        failed = 0
        n = len(parties)
        for i, p in enumerate(parties):
            if queued >= max_txs:
                break
            while queued < max_txs:
                utxos = self._l1_utxos(p["rpc"])
                if len(utxos) < max(8, inputs_per_tx // 4):
                    break
                selected = utxos[: min(len(utxos), inputs_per_tx)]
                dest = parties[(i + 1 + queued) % n]["rpc"].getnewaddress()
                if self._sendall_inputs(p["rpc"], dest, selected):
                    queued += 1
                    approx_inputs += len(selected)
                else:
                    failed += 1
                    break
        self.log.info(
            "Phase8 L1 pad: txs=%d ~inputs=%d fail=%d",
            queued, approx_inputs, failed,
        )
        return queued

    def queue_l1_pad_mesh(self, parties, *, amount=AMT_MIN, addrs_per=8):
        """Back-compat alias → real multi-input L1 pad."""
        return self.queue_l1_witness_pad(parties)

    def prepare_size_economy(self, miner, *,
                             wallets_per_node=DEFAULT_WALLETS_PER_NODE,
                             total_wallets=None,
                             l1_per_wallet=L1_FANOUT_PER_WALLET,
                             mweb_per_wallet=MWEB_BANK_PER_WALLET,
                             precreate_nodes=DEFAULT_MWEB_PRECREATE_NODES,
                             exclude_wallet_hosts=None,
                             wallet_nodes=None,
                             wallet_host=None,
                             miner_wallets=MINER_WALLET_COUNT,
                             host_wallets=DEFAULT_WALLETS_PER_NODE,
                             miner_tx_divisor=MINER_TX_DIVISOR,
                             peer=None,
                             defer_phase6_mine=False):
        """Full inventory path through peg-in bank; no classic growth."""
        self.connect_full_mesh()
        if wallet_host is not None:
            parties = self.setup_economic_wallets_tiered(
                miner=miner,
                wallet_host=wallet_host,
                miner_wallets=miner_wallets,
                host_wallets=host_wallets,
                miner_tx_divisor=miner_tx_divisor,
            )
            precreate_nodes = max(precreate_nodes, 2)
        else:
            total = total_wallets if total_wallets is not None else wallets_per_node
            if wallet_nodes is not None:
                hosts = list(wallet_nodes)
            else:
                hosts = self.wallet_host_nodes(
                    miner, precreate_nodes=precreate_nodes,
                    exclude=exclude_wallet_hosts,
                )
            if len(hosts) == 1:
                parties = self.setup_economic_wallets(
                    wallets_per_node=total, nodes=hosts,
                )
            else:
                parties = self.setup_economic_wallets_split(
                    hosts=hosts, total_wallets=total,
                )
        self.fund_wallets_lean(miner, parties)
        self.record_wallet_host_rpc_baselines(parties, miner)
        self.phase_l1_fanout(miner, parties, per_wallet=l1_per_wallet)
        mweb_target = sum(party_mweb_bank(p, mweb_per_wallet) for p in parties)
        mweb_queued = self.phase_mweb_pegin_bank(
            miner, parties, per_wallet=mweb_per_wallet,
            precreate_nodes=precreate_nodes,
            peer=peer, defer_mine=defer_phase6_mine,
        )
        assert mweb_queued >= min(20_000, mweb_target // 2), (
            f"MWEB bank too thin: queued={mweb_queued} target≈{mweb_target}"
        )
        self.log.info(
            "Size economy ready at height=%d mweb_pegins=%d",
            miner.getblockcount(), mweb_queued,
        )
        self.sync_all()
        return parties

    def _sync_pack_mempool_to_miner(self, miner, parties):
        """Relay Phase 8 spends to the GBT node (tiered: most txs start on wallet hosts).

        Success is builder-centric: GBT only needs the builder mempool. Do not
        require identical txid sets — miner-wallet consolidations never appear on
        the host, so equality can hang forever at sizes like [5449, 4809].
        """
        miner_idx = self._miner_node_index(miner)
        host_idxs = sorted({p["node_idx"] for p in parties} - {miner_idx})
        host_max = 0
        for idx in host_idxs:
            host = self.nodes[idx]
            with self._full_rpc_timeout(host):
                host_n = len(host.getrawmempool())
            host_max = max(host_max, host_n)
            self.log.info("Phase8 pre-relay: node%d mempool=%d", idx, host_n)

        self.ensure_peer_mesh()
        # Cap wait even when --timeout-factor is large (equality is not the goal).
        deadline = time.monotonic() + 180
        last_log = time.monotonic()
        mempool_n = 0
        while True:
            with self._full_rpc_timeout(miner):
                mempool_n = len(miner.getrawmempool())
            if not host_idxs or mempool_n >= host_max * 99 // 100:
                break
            if time.monotonic() >= deadline:
                break
            if not miner.getpeerinfo():
                self.ensure_peer_mesh()
            now = time.monotonic()
            if now - last_log >= 30:
                last_log = now
                self.log.info(
                    "Phase8 relay wait: builder=%d host_max=%d",
                    mempool_n, host_max,
                )
            time.sleep(2)

        self.log.info(
            "Phase8 mempool relay to builder node%d: peers=%s builder_mempool=%d host_max=%d",
            miner_idx, host_idxs, mempool_n, host_max,
        )
        if host_idxs and mempool_n < host_max * 99 // 100:
            raise AssertionError(
                f"Phase8 mempool relay incomplete: builder={mempool_n} "
                f"wallet_host_max={host_max}"
            )
        return mempool_n

    def flood_for_wire_target(self, miner, parties, *, target_min, target_max=None,
                              max_floods=1, weight_fill=True, exact_drains=False,
                              consolidate_input_cap=MWEB_INPUT_CAP,
                              l1_pad_max_txs=L1_PAD_MAX_TXS):
        """Phase 8: pack spends into ONE mempool tip, then GBT. Never re-seed mid-flood."""
        if target_min > MWEB_ENVELOPE:
            est, _diag, _plan = self.flood_envelope_reject_pack(miner, parties)
            return est
        self.queue_mweb_phase8_pack(
            parties,
            input_cap=consolidate_input_cap,
            weight_fill=weight_fill,
            exact_drains=exact_drains,
        )
        self.queue_l1_witness_pad(parties, max_txs=l1_pad_max_txs)
        builder_mempool = self._sync_pack_mempool_to_miner(miner, parties)
        with self._full_rpc_timeout(miner):
            est, n_tx, gbt = gbt_wire_estimate(miner)
        self.log.info(
            "Phase8 flood: builder_mempool=%d gbt_txs=%d gbt_est≈%d "
            "(%.2f%% BIP324, %.2f%% envelope)",
            builder_mempool, n_tx, est,
            100.0 * est / BIP324_CAP, 100.0 * est / MWEB_ENVELOPE,
        )
        if est < target_min:
            raise AssertionError(
                f"Phase8 pack under target: est={est} < {target_min} "
                f"(builder_mempool={builder_mempool})."
            )
        if target_max is not None and est > target_max:
            self.log.warning(
                "Phase8 est %d above target_max %d (caller may trim)", est, target_max
            )
        return est

    # --- Back-compat aliases used by older test drafts ---
    def prepare_funded_economy(self, miner, **kwargs):
        return self.prepare_size_economy(miner, **kwargs)

    def grow_until_wire(self, miner, parties, *, target_min, target_max=None,
                        max_floods=6, **_kw):
        est = self.flood_for_wire_target(
            miner, parties, target_min=target_min, target_max=target_max,
            max_floods=max_floods,
        )
        if est < target_min:
            raise AssertionError(
                f"Could not reach wire>={target_min}; best_est={est}. "
                f"Need denser consolidations or L1 witness pad."
            )
        if target_max is not None and est > target_max:
            # Still mine one tip if under mine budget; caller measures.
            pass
        miner = self._restart_miner_wallet_policy(
            miner, disable_wallet=True, label="grow_until_wire pre-mine",
        )
        try:
            h = self._generate_long(miner, 1, sync_fun=self.no_op)[0]
        finally:
            miner = self._restart_miner_wallet_policy(
                miner, disable_wallet=False, parties=parties,
                label="grow_until_wire post-mine",
            )
        self.sync_all()
        S = block_wire_bytes(miner, h)
        if S < target_min:
            raise AssertionError(
                f"Mined tip wire={S} < target_min={target_min} (est was {est})"
            )
        if target_max is not None and S > target_max:
            raise AssertionError(
                f"wire {S} exceeded target_max {target_max} (target_min={target_min})"
            )
        return h, S
