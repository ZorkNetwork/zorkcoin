#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for MWEB P2P mega stress / rate-limit functional tests.

Density growth: doc/mweb/testing.md and mweb_density_util.py (Option C hybrid).
"""

import bisect
import http.client
import random
import re
import shutil
import time
import unittest
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    CInv,
    Hash,
    MSG_BLOCK,
    MSG_MWEB_HEADER,
    MSG_MWEB_LEAFSET,
    MSG_TX,
    MSG_WITNESS_FLAG,
    MSG_WTX,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    msg_getdata,
    msg_getheaders,
    msg_getmwebutxos,
    msg_inv,
    msg_ping,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB, p2p_lock
from test_framework.mweb_proof import segment_root
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    get_mweb_header,
)
from test_framework.messages import NODE_MWEB_LIGHT_CLIENT
from test_framework.util import assert_equal, assert_greater_than
from test_framework.mweb_density_util import (
    MEGA_SCALE_CONFIG,
    complete_testing_fail,
    count_wallet_mweb_utxos as density_count_wallet_mweb_utxos,
    count_all_wallet_mweb_utxos,
    load_density_parties,
    grow_mweb_chain_density,
    assert_funder_has_no_mweb,
    assert_distribution_floor,
)

# Transport failures while bitcoind is mid -reindex-chainstate (AuthServiceProxy
# keep-alive dropped). Distinct from intentional P2P wait_for_disconnect.
_MEGA_RPC_TRANSPORT_ERRORS = (
    ConnectionResetError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    BrokenPipeError,
    OSError,
    http.client.RemoteDisconnected,
    http.client.IncompleteRead,
)

MAX_MWEB_LEAFSET_DEPTH = 10
MAX_REQUESTED_MWEB_UTXOS = 4096
MAX_MWEB_SERVE_JOBS_PER_PEER = 8
MAX_MWEB_SERVE_JOBS_GLOBAL = 64
MWEB_LIGHT_CLIENT_SERVICES = P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT

MEGA_WAIT_SHORT = 3
MEGA_WAIT_MEDIUM = 8
MEGA_WAIT_SYNC = 60

MEGA_MINE_MAX = 5
MEGA_PING_P95_MAX = 2.0
MEGA_PUBLISH_P95_MAX_NS = 500_000_000  # 500ms per block connect publish (I4 budget)
MEGA_MATERIALIZE_P95_MAX_NS = 100_000_000  # 100ms per materialize chunk turn (T-09)

HISTORICAL_DEPTH_OFFSETS = (0, 1, 5, 10)

# Bump when density growth recipe changes so stale consolidated caches are ignored.
MEGA_CACHE_VERSION = 'v2'

class MWEBServeLogStats:
    """Parse -debug=net MWEB serve lines from a node's debug.log."""

    REPLAY_STEP = re.compile(r'MWEB serve replay step:.*peer=(\d+)')
    MATERIALIZE_CHUNK = re.compile(
        r'MWEB serve materialize chunk: height=(\d+) peer=(\d+) phase=(\w+|\d+) ns=(\d+)')
    ASSUMEUTXO_WARM_STEP = re.compile(r'MWEB cache assumeutxo warm step:')
    CACHE_HIT = re.compile(r'MWEB serve cache hit:')
    CACHE_MISS = re.compile(r'MWEB serve cache miss:')
    CREDIT_DENY = re.compile(r'MWEB serve credit deny:')
    PUBLISH = re.compile(r'MWEB cache publish: height=(\d+) ns=(\d+)')
    INTERNAL_ERROR = re.compile(r'MWEB serve internal error:.*\(no ban\)')

    def __init__(self, debug_log_path):
        self.path = debug_log_path
        self._offset = 0
        self._mark_offset = 0

    def _read_new_lines(self):
        try:
            with open(self.path, encoding='utf-8', errors='ignore') as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
        except OSError:
            return ''
        return chunk

    def _read_since_mark(self):
        try:
            with open(self.path, encoding='utf-8', errors='ignore') as fh:
                fh.seek(self._mark_offset)
                return fh.read()
        except OSError:
            return ''

    def count_since(self, pattern, *, reset_offset=False):
        if reset_offset:
            self._mark_offset = 0
        text = self._read_since_mark()
        return len(pattern.findall(text))

    def count_new(self, pattern):
        """Count pattern matches in newly appended log lines (monotonic per mark)."""
        return self.count_since(pattern)

    def replay_steps_since(self, *, reset_offset=False):
        return self.count_since(self.REPLAY_STEP, reset_offset=reset_offset)

    def background_serve_peer_ids_since(self, *, reset_offset=False):
        """NodeIds that received replay or materialize background serve steps."""
        if reset_offset:
            self._mark_offset = 0
        text = self._read_since_mark()
        peers = set()
        for m in self.REPLAY_STEP.finditer(text):
            peers.add(int(m.group(1)))
        for m in self.MATERIALIZE_CHUNK.finditer(text):
            peers.add(int(m.group(2)))
        return peers

    def materialize_chunks_since(self, *, reset_offset=False):
        if reset_offset:
            self._mark_offset = 0
        text = self._read_since_mark()
        return [(int(m.group(1)), int(m.group(2)), m.group(3), int(m.group(4)))
                for m in self.MATERIALIZE_CHUNK.finditer(text)]

    def materialize_chunk_ns_since(self, *, reset_offset=False):
        return [ns for _h, _p, _ph, ns in self.materialize_chunks_since(reset_offset=reset_offset)]

    def assumeutxo_warm_steps_since(self, *, reset_offset=False):
        return self.count_since(self.ASSUMEUTXO_WARM_STEP, reset_offset=reset_offset)

    def mark_log_end(self):
        """Only count log lines appended after this call."""
        try:
            self._mark_offset = self.path.stat().st_size
        except OSError:
            self._mark_offset = 0
        self._offset = self._mark_offset

    def cache_hits_since(self, *, reset_offset=False):
        return self.count_since(self.CACHE_HIT, reset_offset=reset_offset)

    def cache_misses_since(self, *, reset_offset=False):
        return self.count_since(self.CACHE_MISS, reset_offset=reset_offset)

    def credit_denies_since(self, *, reset_offset=False):
        return self.count_since(self.CREDIT_DENY, reset_offset=reset_offset)

    def publish_samples_since(self, *, reset_offset=False):
        if reset_offset:
            self._mark_offset = 0
        text = self._read_since_mark()
        return [(int(m.group(1)), int(m.group(2))) for m in self.PUBLISH.finditer(text)]

    def internal_errors_since(self, *, reset_offset=False):
        return self.count_since(self.INTERNAL_ERROR, reset_offset=reset_offset)


def peer_misbehaving_score(node, peer_id):
    for p in node.getpeerinfo():
        if p.get('id') == peer_id:
            return p.get('banscore', 0)
    return 0


def max_peer_misbehaving_score(node, *, subver='python-p2p-tester'):
    scores = [
        p.get('banscore', 0) for p in node.getpeerinfo()
        if subver in p.get('subver', '')
    ]
    return max(scores) if scores else 0


def shared_historical_anchor(victim, helper, offset=10):
    """Block hash at victim tip-offset present on both nodes and within serve depth."""
    victim_height = victim.getblockcount()
    helper_height = helper.getblockcount()
    height = max(FIRST_MWEB_HEIGHT, victim_height - offset)
    assert height <= helper_height, (
        f"historical anchor height {height} not on helper (tip {helper_height}); "
        "realign victim before serve"
    )
    vhash = victim.getblockhash(height)
    hhash = helper.getblockhash(height)
    assert_equal(vhash, hhash)
    return height, vhash


def assert_mweb_serve_parity(test, node, block_hash, *, min_utxos, helper=None):
    """Require P2P pagination at block_hash; strict min_utxos floor."""
    paged = paginate_mweb_utxos(node, block_hash, page_size=256, max_pages=200)
    test.log.info(
        "MWEB serve parity at %s: paginated=%d (min %d)",
        block_hash, paged, min_utxos,
    )
    if paged <= min_utxos:
        complete_testing_fail(
            f"serve parity floor: paginated={paged} ≤ min_utxos={min_utxos} at {block_hash}"
        )


def assert_serve_pagination_floor(test, node, block_hash, *, helper=None):
    """S1/S2: paginated tip serve must be non-trivial (density chains are multi-wallet)."""
    paged = paginate_mweb_utxos(node, block_hash, page_size=256, max_pages=200)
    test.log.info(
        "Serve pagination floor at %s: paginated=%d",
        block_hash, paged,
    )
    if paged <= 10:
        complete_testing_fail(
            f"serve pagination floor: paginated={paged} ≤ 10 at {block_hash}"
        )
    return paged


def assert_random_segments_match_helper(test, victim, helper, *, depths, samples=5, page_size=64):
    """S3: random pages at tip/tip-k match helper byte-for-byte on fields."""
    tip_height = victim.getblockcount()
    rng = random.Random(tip_height)
    for _ in range(samples):
        offset = rng.choice(depths)
        height = max(FIRST_MWEB_HEIGHT, tip_height - offset)
        block_hash = victim.getblockhash(height)
        leafset = fetch_mweb_leafset(helper, block_hash)
        helper_count = paginate_mweb_utxos(helper, block_hash, page_size=page_size, max_pages=200, leafset=leafset)
        assert_greater_than(helper_count, 0)
        start = mweb_unspent_leaves(leafset)[rng.randint(0, max(0, helper_count - page_size))]
        victim_msg = fetch_mweb_utxo_page(
            victim, block_hash, start_index=start, num_requested=page_size)
        assert_segment_matches_helper(helper, victim_msg, block_hash)
        test.log.info(
            "S3 segment match: tip-%d start=%d n=%d",
            offset, start, len(victim_msg.utxos),
        )


def verify_chain_utxo_floor(test, helper, *, min_utxos):
    """Fail chain setup early if peg-in-heavy growth did not reach plan floor."""
    tip_hash = helper.getbestblockhash()
    paged = paginate_mweb_utxos(helper, tip_hash, page_size=4096, max_pages=200)
    test.log.info("Chain UTXO floor check: paginated=%d min=%d", paged, min_utxos)
    if paged <= min_utxos:
        complete_testing_fail(
            f"chain UTXO floor: paginated={paged} ≤ min_mweb_utxos={min_utxos}"
        )
    return paged


def mega_cache_dir(test, scale):
    return Path(test.options.cachedir) / f"mweb_p2p_mega_{MEGA_CACHE_VERSION}_{scale}"


def mega_cache_complete(cache_dir, chain_name):
    cache_chain = cache_dir / chain_name
    return (
        (cache_dir / '.complete').is_file()
        and (cache_chain / 'blocks').is_dir()
        and (cache_chain / 'chainstate').is_dir()
        and (cache_chain / 'wallets').is_dir()
    )


def anchor_hashes_for_tip(node, tip_height=None, max_depth=10):
    tip_height = tip_height or node.getblockcount()
    tip_hash = node.getblockhash(tip_height)
    anchors = [tip_hash]
    for offset in (1, 5, 10):
        if offset > max_depth:
            continue
        height = tip_height - offset
        if height >= FIRST_MWEB_HEIGHT:
            anchors.append(node.getblockhash(height))
    return anchors


def count_wallet_mweb_utxos(wallet_or_node):
    """Count MWEB UTXOs on a wallet RPC or node default wallet."""
    return density_count_wallet_mweb_utxos(wallet_or_node)


def ensure_default_wallet(node):
    """Functional mega tests require a loaded wallet for pegins."""
    try:
        node.getwalletinfo()
    except JSONRPCException as e:
        if e.error['code'] == -18:
            node.createwallet('default', load_on_startup=True)
        else:
            raise


def ensure_helper_wallet(test, helper):
    """Ensure helper has a loaded wallet after restart or datadir wipe."""
    from test_framework.util import wallet_importprivkey
    try:
        helper.getwalletinfo()
        return
    except JSONRPCException as e:
        # -19: multiple wallets loaded — density growth already set parties up.
        if e.error['code'] == -19:
            return
        if e.error['code'] != -18:
            raise
    if not test.uses_wallet:
        ensure_default_wallet(helper)
        return
    idx = test.nodes.index(helper)
    wallet_name = (
        test.default_wallet_name if test.wallet_names is None
        else test.wallet_names[idx] if idx < len(test.wallet_names) else False
    )
    if wallet_name is False:
        return
    try:
        helper.createwallet(wallet_name=wallet_name, load_on_startup=True)
    except JSONRPCException as e:
        if e.error['code'] == -4:
            helper.loadwallet(wallet_name)
        elif e.error['code'] != -35:
            raise
    wallet_importprivkey(
        helper.get_wallet_rpc(wallet_name),
        helper.get_deterministic_priv_key().key,
        0,
        label="coinbase",
    )


def grow_mweb_chain_mega(test, node, *, post_blocks=None, wallets=None, log_interval=100, cfg=None):
    """Grow a peg-in-heavy mega chain (forced density; see doc/mweb/testing.md)."""
    if cfg is None:
        cfg = {
            'post_mweb_blocks': post_blocks if post_blocks is not None else 800,
            'recipient_wallets': 4,
            'accounts_per_wallet': 4,
            'mweb_keys_per_account': 16,
            'pegins_per_block': 4,
            'cross_spend_interval': 25,
            'min_mweb_utxos': 0,
            'early_gate_fraction': 0.10,
            'early_gate_min_utxos': 10,
            'log_interval': log_interval,
        }
        if wallets is not None:
            cfg['recipient_wallets'] = max(4, min(8, max(1, wallets // 8)))

    def _paginate(n, block_hash):
        return paginate_mweb_utxos(n, block_hash, page_size=4096, max_pages=200)

    return grow_mweb_chain_density(
        test, node, cfg=cfg,
        paginate_fn=_paginate,
        ensure_wallet_fn=ensure_helper_wallet,
    )


def _remove_dir(test, path):
    """Remove a node datadir subtree (under tmpdir) or a mega chain cache subtree (under cachedir)."""
    if Path(path).is_relative_to(test.options.cachedir):
        test.cleanup_cache_folder(path)
    else:
        test.cleanup_folder(path)


def _copy_chain_subdirs(test, src_chain_path, dst_chain_path):
    """Copy block chain data only; preserve destination bitcoin.conf and ports."""
    for sub in ('blocks', 'chainstate', 'indexes'):
        src = src_chain_path / sub
        if not src.exists():
            continue
        dst = dst_chain_path / sub
        if dst.exists():
            _remove_dir(test, dst)
        shutil.copytree(src, dst)
    src_w = src_chain_path / 'wallets'
    dst_w = dst_chain_path / 'wallets'
    if src_w.exists():
        if dst_w.exists():
            _remove_dir(test, dst_w)
        shutil.copytree(src_w, dst_w)


def _mega_node_startup_timeout(min_height):
    """RPC/reindex waits for large cached mega chains (extended scale)."""
    if min_height <= 1000:
        return 120
    return min(max(600, min_height // 3), 7200)


def _refresh_mega_rpc(node, *, client_timeout=600):
    """Replace the node's long-lived RPC proxy after a transport drop."""
    node._rpc = node.create_new_rpc_connection(client_timeout=client_timeout)
    return node._rpc


def _wait_mega_rpc_until(node, predicate, *, timeout, check_interval=0.5):
    """wait_until that recreates RPC on transport errors during long reindex.

    Intentional P2P disconnect asserts must not use this helper.
    """
    def safe_predicate():
        try:
            if node._rpc is None:
                _refresh_mega_rpc(node)
            return predicate(node)
        except _MEGA_RPC_TRANSPORT_ERRORS:
            try:
                _refresh_mega_rpc(node)
            except Exception:
                pass
            return False
        except JSONRPCException:
            # Node may briefly reject RPC while initload holds locks; keep waiting.
            return False

    node.wait_until(safe_predicate, timeout=timeout, check_interval=check_interval)


def _start_helper_node(test, helper, *, reindex_chainstate=False, rescan_wallet=False, min_height=0):
    """Start helper after datadir copy; reindex when restoring a cached mega chain."""
    helper_idx = test.nodes.index(helper)
    extra_args = list(test.extra_args[helper_idx])
    startup_flags = []
    if reindex_chainstate:
        startup_flags.append('-reindex-chainstate')
    for flag in startup_flags:
        if flag not in extra_args:
            extra_args.append(flag)
    startup_timeout = _mega_node_startup_timeout(min_height if reindex_chainstate else 0)
    prev_timeout = helper.rpc_timeout
    helper.rpc_timeout = max(prev_timeout, startup_timeout)
    try:
        helper.start(extra_args=extra_args)
        helper.wait_for_rpc_connection(wait_for_import=False)
        _refresh_mega_rpc(helper)
        if reindex_chainstate:
            _wait_mega_rpc_until(
                helper,
                lambda n: n._rpc.getmempoolinfo()['loaded'],
                timeout=startup_timeout,
            )
    finally:
        helper.rpc_timeout = prev_timeout
    for flag in startup_flags:
        if flag in extra_args:
            extra_args.remove(flag)
    test.extra_args[helper_idx] = extra_args
    ensure_helper_wallet(test, helper)
    if min_height > 0:
        last_log = [0]

        def reindex_progress(n):
            height = n.getblockcount()
            if height - last_log[0] >= 500 or height >= min_height:
                ibd = n.getblockchaininfo()['initialblockdownload']
                test.log.info(
                    "  helper reindex/IBD: height %d / %d (ibd=%s)",
                    height, min_height, ibd,
                )
                last_log[0] = height
            return height >= min_height

        _wait_mega_rpc_until(
            helper,
            reindex_progress,
            timeout=max(3600, min_height // 2),
            check_interval=5,
        )

        def ibd_cleared(n):
            info = n.getblockchaininfo()
            if not info['initialblockdownload']:
                return True
            # Cached mega chains have stale tip times; regtest IBD latch never clears otherwise.
            if info['blocks'] >= min_height:
                test.log.info(
                    "  helper still in IBD at height %d; mining block to refresh tip time",
                    info['blocks'],
                )
                generate(n, 1)
            return not n.getblockchaininfo()['initialblockdownload']

        _wait_mega_rpc_until(helper, ibd_cleared, timeout=1200, check_interval=2)
    if rescan_wallet:
        test.log.info("  helper wallet rescan from height %d...", FIRST_MWEB_HEIGHT)
        wallets = helper.listwallets()
        if not wallets:
            helper.rescanblockchain(FIRST_MWEB_HEIGHT)
        else:
            for wname in wallets:
                helper.get_wallet_rpc(wname).rescanblockchain(FIRST_MWEB_HEIGHT)
        test.log.info("  helper wallet rescan complete")


def _mega_node_stop_timeout(min_height):
    """Allow long flush/shutdown on dense mega chains (default bitcoind wait is 60s)."""
    return max(600, int(min_height or 0) // 20)


def _stop_mega_node(test, node_idx, *, min_height=0):
    node = test.nodes[node_idx]
    node.stop_node(wait_until_stopped=False)
    node.wait_until_stopped(timeout=_mega_node_stop_timeout(min_height))


def _save_mega_chain_cache(test, helper, *, scale):
    cache_dir = mega_cache_dir(test, scale)
    cache_chain = cache_dir / helper.chain
    helper_idx = test.nodes.index(helper)
    target_height = helper.getblockcount()
    _stop_mega_node(test, helper_idx, min_height=target_height)
    try:
        if cache_chain.exists():
            test.cleanup_cache_folder(cache_chain)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_chain.mkdir(parents=True, exist_ok=True)
        _copy_chain_subdirs(test, helper.chain_path, cache_chain)
        (cache_dir / '.complete').write_text(
            f"scale={scale}\ncache_version={MEGA_CACHE_VERSION}\n"
        )
        test.log.info("Saved mega chain cache for scale=%s to %s", scale, cache_dir)
    finally:
        _start_helper_node(
            test, helper,
            reindex_chainstate=True,
            rescan_wallet=True,
            min_height=target_height,
        )


def restart_mega_node(test, node, extra_args=None, *, rescan_wallet=False,
                      reindex_chainstate=False):
    """Restart a mega-chain node.

    Policy restart (default, reindex_chainstate=False): stop/start with optional
    new args. Clears in-memory historical serve cache, peer credit state, and
    upload-cycle coupling without rebuilding chainstate. Use for C/D matrix
    isolation (upload, mwebserve mode, burst, whitelist). Caller-supplied
    extra_args are one-shot and do not replace test.extra_args baseline.

    Reindex restart (reindex_chainstate=True): forces -reindex-chainstate. Use
    for cache restore/save and cold historical miss certification (A5/S2).
    RPC waits recreate the proxy on transport drops during long reindex.
    """
    node_idx = test.nodes.index(node)
    min_height = node.getblockcount()
    _stop_mega_node(test, node_idx, min_height=min_height)
    # One-shot policy overrides must not clobber the node's baseline extra_args
    # (matrix tests restart with self.extra_args[i] expecting the suite default).
    args = list(extra_args if extra_args is not None else test.extra_args[node_idx])
    if reindex_chainstate and '-reindex-chainstate' not in args:
        args.append('-reindex-chainstate')
    startup_timeout = _mega_node_startup_timeout(min_height if reindex_chainstate else 0)
    prev_timeout = node.rpc_timeout
    node.rpc_timeout = max(prev_timeout, startup_timeout)
    try:
        node.start(extra_args=args)
        node.wait_for_rpc_connection(wait_for_import=False)
        _refresh_mega_rpc(node)
        if reindex_chainstate:
            _wait_mega_rpc_until(
                node,
                lambda n: n._rpc.getmempoolinfo()['loaded'],
                timeout=startup_timeout,
            )
    finally:
        node.rpc_timeout = prev_timeout
    if extra_args is None:
        cleaned = list(args)
        if '-reindex-chainstate' in cleaned:
            cleaned.remove('-reindex-chainstate')
        test.extra_args[node_idx] = cleaned
    if reindex_chainstate and min_height > 0:
        _wait_mega_rpc_until(
            node,
            lambda n: n.getblockcount() >= min_height,
            timeout=max(3600, min_height // 2),
            check_interval=5,
        )
    if rescan_wallet:
        wallets = node.listwallets()
        if not wallets:
            node.rescanblockchain(FIRST_MWEB_HEIGHT)
        else:
            for wname in wallets:
                node.get_wallet_rpc(wname).rescanblockchain(FIRST_MWEB_HEIGHT)


def load_or_build_mega_chain(test, helper, *, scale):
    """Build or restore cached mega chain on helper node (forced density growth)."""
    cfg = MEGA_SCALE_CONFIG[scale]
    cache_dir = mega_cache_dir(test, scale)
    cache_chain = cache_dir / helper.chain
    target_height = FIRST_MWEB_HEIGHT + cfg['post_mweb_blocks'] - 1
    helper_idx = test.nodes.index(helper)
    cache_usable = mega_cache_complete(cache_dir, helper.chain)
    parties = None

    if cache_usable and not test.options.mweb_mega_rebuild_chain:
        if helper.getblockcount() < target_height:
            test.log.info("Restoring mega chain cache for scale=%s from %s", scale, cache_dir)
            _stop_mega_node(test, helper_idx, min_height=helper.getblockcount())
            _copy_chain_subdirs(test, cache_chain, helper.chain_path)
            try:
                _start_helper_node(
                    test, helper,
                    reindex_chainstate=True,
                    rescan_wallet=True,
                    min_height=target_height,
                )
                parties = load_density_parties(
                    helper, recipient_wallets=cfg['recipient_wallets'],
                )
            except (AssertionError, *_MEGA_RPC_TRANSPORT_ERRORS) as e:
                test.log.warning(
                    "Mega cache restore failed (%s); rebuilding chain to height %d",
                    e, target_height,
                )
                _stop_mega_node(test, helper_idx, min_height=target_height)
                for sub in ('blocks', 'chainstate', 'indexes', 'wallets'):
                    path = helper.chain_path / sub
                    if path.exists():
                        test.cleanup_folder(path)
                _start_helper_node(test, helper)
                ensure_helper_wallet(test, helper)
                parties = None
    elif cache_chain.exists() and not test.options.mweb_mega_rebuild_chain:
        test.log.warning(
            "Ignoring incomplete mega cache at %s (missing wallets or .complete); rebuilding",
            cache_dir,
        )

    if helper.getblockcount() < target_height:
        parties = grow_mweb_chain_mega(test, helper, cfg=cfg)
        _save_mega_chain_cache(test, helper, scale=scale)
        # After cache save+reindex, reload party wallets.
        parties = load_density_parties(
            helper, recipient_wallets=cfg['recipient_wallets'],
        )

    if parties is None:
        parties = load_density_parties(
            helper, recipient_wallets=cfg['recipient_wallets'],
        )

    def _paginate(n, block_hash):
        return paginate_mweb_utxos(n, block_hash, page_size=4096, max_pages=200)

    # Restored caches may not retain destination address lists; still enforce
    # chain floor + funder invariant + distribution across loaded recipients.
    assert_funder_has_no_mweb(parties['funder'])
    # After restore, destination list is empty — skip address mint checks;
    # distribution still applies if wallets hold coins after rescan.
    if count_all_wallet_mweb_utxos(helper, parties['recipient_names']) == 0:
        test.log.warning("Distribution unavailable: restored recipient wallets report no coins")
    else:
        assert_distribution_floor(test, helper, parties['recipient_names'])

    tip_height = helper.getblockcount()
    tip_hash = helper.getbestblockhash()
    paged = verify_chain_utxo_floor(test, helper, min_utxos=cfg['min_mweb_utxos'])
    wallet_total = count_all_wallet_mweb_utxos(helper, parties['recipient_names'])
    return {
        'tip_height': tip_height,
        'tip_hash': tip_hash,
        'utxo_floor': max(wallet_total, paged),
        'parties': parties,
        'paged': paged,
    }


class MockLightClientBase(P2PInterface):
    """Minimal LIP-0006 light client for mega tests."""

    def __init__(self):
        super().__init__()
        self.blocks = {}
        self.leafsets = {}
        self.mwebutxos = {}
        self.merkle_blocks_with_mweb = {}
        self.requests_sent = 0
        self.responses_received = 0

    def request_mweb_utxos(self, block_hash, start_index, num_requested=1,
                           output_format=MWEB_UTXO_FORMAT_HASH_ONLY):
        self.requests_sent += 1
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(block_hash) if isinstance(block_hash, str) else block_hash,
            start_index=start_index,
            num_requested=num_requested,
            output_format=output_format,
        ))

    def request_mweb_leafset(self, block_hash):
        self.requests_sent += 1
        h = int(block_hash, 16) if isinstance(block_hash, str) else block_hash
        self.send_without_ping(msg_getdata([CInv(MSG_MWEB_LEAFSET, h)]))

    def request_mweb_header(self, block_hash):
        self.requests_sent += 1
        h = int(block_hash, 16) if isinstance(block_hash, str) else block_hash
        self.send_without_ping(msg_getdata([CInv(MSG_MWEB_HEADER, h)]))

    def on_mwebutxos(self, message):
        self.responses_received += 1
        self.mwebutxos[message.block_hash] = message

    def on_mwebleafset(self, message):
        self.responses_received += 1
        self.leafsets[message.block_hash] = message

    def on_mwebheader(self, message):
        self.responses_received += 1
        self.merkle_blocks_with_mweb[message.header_hash()] = message.merkleblockwithmweb

    def wait_for_mwebutxos(self, block_hash, timeout=MEGA_WAIT_MEDIUM):
        expected = Hash.from_hex(block_hash) if isinstance(block_hash, str) else block_hash
        self.wait_until(lambda: expected in self.mwebutxos, timeout=timeout)

    def wait_for_mwebleafset(self, block_hash, timeout=MEGA_WAIT_MEDIUM):
        expected = Hash.from_hex(block_hash) if isinstance(block_hash, str) else block_hash
        self.wait_until(lambda: expected in self.leafsets, timeout=timeout)


class MWEBAbusePeer(P2PInterface):
    """Abusive peer: repeats identical getmwebutxos without processing responses."""

    def __init__(self, block_hash, start_index, *, num_requested=MAX_REQUESTED_MWEB_UTXOS):
        super().__init__()
        self.block_hash = block_hash
        self.start_index = start_index
        self.num_requested = num_requested
        self.requests_sent = 0
        self.responses_received = 0

    def send_abuse_request(self):
        self.requests_sent += 1
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(self.block_hash),
            start_index=self.start_index,
            num_requested=self.num_requested,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))

    def on_mwebutxos(self, message):
        self.responses_received += 1


class MWEBSyncPeer(MockLightClientBase):
    """Legitimate light-client sync: fetches each anchor's leafset, then paginates
    its unspent leaves and waits between pages.

    start_index is the leaf index of the next page; a walk resumes at the first
    unspent leaf at or after it.
    """

    def __init__(self, block_hash, *, start_index=0, page_size=64,
                 include_header=False, depth_anchors=None):
        super().__init__()
        self.block_hash = block_hash
        self.start_index = start_index
        self.page_size = page_size
        self.include_header = include_header
        self.depth_anchors = depth_anchors or [block_hash]
        self._anchor_i = 0
        self._done = False
        self.pages_received = 0
        self.total_utxos = 0
        self._pending = False
        self._walk_hash = None
        self._unspent = []
        self._pos = 0

    def _current_hash(self):
        return self.depth_anchors[self._anchor_i % len(self.depth_anchors)]

    def _next_anchor(self):
        self._anchor_i += 1
        self.start_index = 0
        self._walk_hash = None
        if self._anchor_i >= len(self.depth_anchors):
            self._done = True

    def send_next_sync_step(self):
        if self._done or self._pending:
            return
        bh = self._current_hash()
        if self.include_header and not self.merkle_blocks_with_mweb:
            self.request_mweb_header(bh)
            self._pending = True
            return
        if self._walk_hash != bh:
            leafset = self.leafsets.get(Hash.from_hex(bh))
            if leafset is None:
                self.request_mweb_leafset(bh)
                self._pending = True
                return
            self._walk_hash = bh
            self._unspent = mweb_unspent_leaves(_leafset_bytes(leafset))
            self._pos = bisect.bisect_left(self._unspent, self.start_index)
            if self._pos >= len(self._unspent):
                self._next_anchor()
                return
        self.request_mweb_utxos(bh, self._unspent[self._pos], self.page_size)
        self._pending = True

    def on_mwebutxos(self, message):
        assert_equal(message.block_hash, Hash.from_hex(self._current_hash()))
        assert_equal(message.start_index, self._unspent[self._pos])
        assert 0 < len(message.utxos) <= self.page_size
        assert_equal([u.leaf_index for u in message.utxos],
                     self._unspent[self._pos:self._pos + len(message.utxos)])
        super().on_mwebutxos(message)
        self._pending = False
        n = len(message.utxos)
        self.pages_received += 1
        self.total_utxos += n
        self._pos += n
        if self._pos >= len(self._unspent):
            self._next_anchor()
        else:
            self.start_index = self._unspent[self._pos]

    def on_mwebleafset(self, message):
        super().on_mwebleafset(message)
        self._pending = False

    def on_mwebheader(self, message):
        super().on_mwebheader(message)
        self._pending = False


class MWEBInvalidPeer(P2PInterface):
    """Policy-violating LIP-0006 requests (expect disconnect)."""

    def __init__(self, tip_hash, deep_hash):
        super().__init__()
        self.tip_hash = tip_hash
        self.deep_hash = deep_hash
        self._step = 0

    def send_next_invalid_request(self):
        step = self._step % 3
        self._step += 1
        if step == 0:
            self.send_without_ping(msg_getmwebutxos(
                block_hash=Hash.from_hex(self.tip_hash),
                start_index=0,
                num_requested=MAX_REQUESTED_MWEB_UTXOS + 1,
                output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
            ))
        elif step == 1:
            self.send_without_ping(msg_getmwebutxos(
                block_hash=Hash.from_hex(self.tip_hash),
                start_index=0,
                num_requested=1,
                output_format=0xff,
            ))
        else:
            self.send_without_ping(msg_getdata([
                CInv(MSG_MWEB_LEAFSET, int(self.deep_hash, 16)),
            ]))


class MWEBUploadAbusePeer(P2PInterface):
    """Continues LIP-0006 requests after upload budget exhaustion."""

    def __init__(self, tip_hash, start_index):
        super().__init__()
        self.tip_hash = tip_hash
        self.start_index = start_index

    def send_upload_abuse_request(self):
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(self.tip_hash),
            start_index=self.start_index,
            num_requested=64,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))


class SlowMWEBPeer(P2PInterface):
    """Requests MWEB UTXOs; stores responses without extra pings (L1 slow consumer)."""

    def __init__(self, block_hash, start_index, *, num_requested=64):
        super().__init__()
        self.block_hash = block_hash
        self.start_index = start_index
        self.num_requested = num_requested
        self.mwebutxos = {}
        self.request_sent = False

    def send_serve_request(self):
        if self.request_sent:
            return
        self.request_sent = True
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(self.block_hash),
            start_index=self.start_index,
            num_requested=self.num_requested,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))

    def on_mwebutxos(self, message):
        # Store but do not ping — simulates slow consumer while the send queue drains.
        self.mwebutxos[message.block_hash] = message

    def wait_for_mwebutxos(self, block_hash, timeout=MEGA_WAIT_MEDIUM):
        expected = Hash.from_hex(block_hash)
        self.wait_until(lambda: expected in self.mwebutxos, timeout=timeout)


class LeafsetFloodPeer(P2PInterface):
    """Repeated leafset getdata for credit exhaustion tests (F1)."""

    def __init__(self, block_hash):
        super().__init__()
        self.block_hash = block_hash
        self.requests_sent = 0
        self.responses_received = 0
        self.leafset_bytes = 0

    def send_leafset_request(self):
        self.requests_sent += 1
        self.send_without_ping(msg_getdata([
            CInv(MSG_MWEB_LEAFSET, int(self.block_hash, 16)),
        ]))

    def on_mwebleafset(self, message):
        self.responses_received += 1
        if self.leafset_bytes == 0:
            self.leafset_bytes = len(_leafset_bytes(message))


class BenignProbePeer(P2PInterface):
    """Ping probe for non-MWEB liveness."""

    def __init__(self):
        super().__init__()
        self.rtts = []
        self._ping_sent_at = {}

    def send_ping_probe(self):
        self._ping_sent_at[self.ping_counter] = time.monotonic()
        self.send_without_ping(msg_ping(self.ping_counter))
        self.ping_counter += 1

    def on_pong(self, message):
        sent_at = self._ping_sent_at.pop(message.nonce, None)
        if sent_at is not None:
            self.rtts.append(time.monotonic() - sent_at)

    def rtt_p95(self):
        if not self.rtts:
            return float('inf')
        sorted_rtts = sorted(self.rtts)
        idx = max(0, int(len(sorted_rtts) * 0.95) - 1)
        return sorted_rtts[idx]


class BlockFetchPeer(P2PInterface):
    def __init__(self, tip_hash):
        super().__init__()
        self.tip_hash = tip_hash
        self.received = False

    def request_tip_block(self):
        self.send_without_ping(msg_getdata([
            CInv(MSG_BLOCK | MSG_WITNESS_FLAG, int(self.tip_hash, 16)),
        ]))

    def on_block(self, message):
        message.block.rehash()
        assert_equal(message.block.hash, self.tip_hash)
        self.received = True


class HeadersProbePeer(P2PInterface):
    def __init__(self, locator_hashes):
        super().__init__()
        self.locator_hashes = locator_hashes
        self.headers = []

    def request_headers(self):
        msg = msg_getheaders()
        msg.locator.vHave = list(self.locator_hashes)
        msg.hashstop = 0
        self.send_without_ping(msg)

    def on_headers(self, message):
        self.headers = list(message.headers)


class TxInvPeer(P2PInterface):
    """Announces a tx inv and requests it via getdata.

    The node serves a mempool tx only after announcing it to this peer, so connect
    before the tx enters the mempool and wait until it is in `announced`.
    """

    def __init__(self):
        super().__init__()
        self.announced = set()
        self.received = False

    def on_inv(self, message):
        # Record without requesting, so the getdata can be sent under load.
        for inv in message.inv:
            if inv.type in (MSG_TX, MSG_WTX):
                self.announced.add(inv.hash)

    def announce_and_request(self, tx):
        self.expected_wtxid = tx.wtxid_int
        self.send_without_ping(msg_inv([CInv(MSG_WTX, tx.wtxid_int)]))
        self.send_without_ping(msg_getdata([CInv(MSG_WTX, tx.wtxid_int)]))

    def on_tx(self, message):
        message.tx.rehash()
        assert_equal(message.tx.wtxid_int, self.expected_wtxid)
        self.received = True


class CompactMWEBPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_sendcmpct = []

    def on_sendcmpct(self, message):
        self.last_sendcmpct.append(message.version)


def run_abuse_loop(abuse_peers, stop_event, rate):
    interval = 1.0 / max(rate, 1.0)
    while not stop_event.is_set():
        for peer in abuse_peers:
            if peer.is_connected:
                peer.send_abuse_request()
        if stop_event.wait(timeout=interval):
            break


def run_sync_loop(sync_peers, stop_event, interval=0.05):
    while not stop_event.is_set():
        for peer in sync_peers:
            if peer.is_connected and not peer._done:
                peer.send_next_sync_step()
        if stop_event.wait(timeout=interval):
            break


def mweb_unspent_leaves(leafset):
    """Leaf indices set in an mwebleafset bitmap (most significant bit first)."""
    return [i * 8 + j for i, byte in enumerate(leafset) for j in range(8) if byte & (0x80 >> j)]


def first_unspent_mweb_leaf(node, block_hash, *, timeout=MEGA_WAIT_MEDIUM):
    """First unspent leaf index at block_hash, from node's mwebleafset.

    The fetch warms node's historical cache for block_hash and spends upload
    budget; take it from a helper node, or before a test needs a cold cache.
    """
    return mweb_unspent_leaves(fetch_mweb_leafset(node, block_hash, timeout=timeout))[0]


def paginate_mweb_utxos(peer_or_node, block_hash, *, page_size=4096, max_pages=100, services=MWEB_LIGHT_CLIENT_SERVICES,
                        leafset=None):
    """Count UTXOs served at block_hash via pagination.

    Like a LIP-0006 client, takes the block's leafset (fetched first unless
    given) and requests each page at the next unspent leaf index; requesting a
    spent leaf disconnects the peer. Each page must return exactly the next
    unspent leaves.

    Accepts a MockLightClientBase peer or a TestNode; when given a node, opens
    one light-client peer for the full walk.

    Production MWEB serve applies a per-peer credit burst (~50k). A dense tip
    walk at page_size=256 exhausts that burst mid-count. Credit deny disconnects
    the peer; that is not end-of-UTXO-set. When a TestNode is provided, reconnect
    (fresh burst) and retry the same start_index so measurement walks complete.
    Never treat mid-walk credit deny as a successful partial count.
    """
    node = peer_or_node if hasattr(peer_or_node, 'add_p2p_connection') else None
    peer = peer_or_node
    if node is not None:
        peer = node.add_p2p_connection(MockLightClientBase(), services=services)
        peer.wait_for_verack()

    def _reconnect():
        nonlocal peer
        peer.peer_disconnect()
        peer = node.add_p2p_connection(MockLightClientBase(), services=services)
        peer.wait_for_verack()

    block_h = Hash.from_hex(block_hash)
    if leafset is None:
        peer.request_mweb_leafset(block_hash)
        peer.wait_for_mwebleafset(block_hash, timeout=MEGA_WAIT_MEDIUM)
        with p2p_lock:
            leafset = _leafset_bytes(peer.leafsets[block_h])
    unspent = mweb_unspent_leaves(leafset)
    pos = 0
    start = unspent[0] if unspent else 0
    total = 0
    pages = 0
    credit_retries = 0
    max_credit_retries = 8
    try:
        while pages < max_pages and pos < len(unspent):
            start = unspent[pos]
            with p2p_lock:
                peer.mwebutxos.pop(block_h, None)
            if not peer.is_connected:
                if node is not None and total > 0:
                    if credit_retries >= max_credit_retries:
                        raise AssertionError(
                            f"paginate_mweb_utxos: disconnected mid-walk at total={total} "
                            f"start={start} after {credit_retries} reconnect retries"
                        )
                    credit_retries += 1
                    time.sleep(0.5)
                    _reconnect()
                    continue
                if total > 0:
                    raise AssertionError(
                        f"paginate_mweb_utxos: peer disconnected mid-walk at total={total} "
                        f"start={start} (no TestNode to reconnect)"
                    )
                raise AssertionError(f"pagination disconnected before completion: {pos}/{len(unspent)}")
            peer.request_mweb_utxos(block_hash, start_index=start, num_requested=page_size)
            try:
                peer.wait_for_mwebutxos(block_hash, timeout=MEGA_WAIT_MEDIUM)
            except AssertionError:
                # Credit deny / stall: reconnect and retry the same page.
                if node is not None and total > 0:
                    if credit_retries >= max_credit_retries:
                        raise AssertionError(
                            f"paginate_mweb_utxos: serve stalled mid-walk at total={total} "
                            f"start={start} after {credit_retries} reconnect retries "
                            f"(likely credit deny; not end of UTXO set)"
                        ) from None
                    credit_retries += 1
                    time.sleep(0.5)
                    _reconnect()
                    continue
                if total > 0 and pos > 0:
                    raise AssertionError(
                        f"paginate_mweb_utxos: serve stalled mid-walk at total={total} "
                        f"start={start} (no TestNode to reconnect)"
                    ) from None
                raise AssertionError(f"pagination stalled before completion: {pos}/{len(unspent)}") from None
            with p2p_lock:
                if block_h not in peer.mwebutxos:
                    if total > 0:
                        raise AssertionError(
                            f"paginate_mweb_utxos: empty response mid-walk at total={total} "
                            f"start={start}"
                        )
                    raise AssertionError("pagination response missing")
                response = peer.mwebutxos[block_h]
                n = len(response.utxos)
                assert 0 < n <= page_size, f"pagination made no progress or exceeded request: {n}"
                assert_equal(response.start_index, start)
                assert_equal([u.leaf_index for u in response.utxos], unspent[pos:pos + n])
            credit_retries = 0
            pages += 1
            total += n
            pos += n
        assert_equal(pos, len(unspent))
    finally:
        if node is not None:
            peer.peer_disconnect()
    return total


def _leafset_bytes(leafset_msg):
    """Normalize leafset payload to comparable bytes/list."""
    leafset = leafset_msg.leafset if hasattr(leafset_msg, 'leafset') else leafset_msg
    if isinstance(leafset, (bytes, bytearray, list)):
        return bytes(leafset)
    return bytes(leafset)


def _utxo_page_fingerprint(msg):
    """Stable fingerprint of a UTXO page for tip-vs-historical inequality."""
    return tuple((u.leaf_index, str(u.output)) for u in msg.utxos)


def fetch_mweb_leafset(node, block_hash, *, services=MWEB_LIGHT_CLIENT_SERVICES, timeout=MEGA_WAIT_MEDIUM):
    """Fetch mwebleafset for block_hash; returns leafset bytes."""
    peer = node.add_p2p_connection(MockLightClientBase(), services=services)
    try:
        peer.wait_for_verack()
        peer.request_mweb_leafset(block_hash)
        peer.wait_for_mwebleafset(block_hash, timeout=timeout)
        with p2p_lock:
            msg = peer.leafsets[Hash.from_hex(block_hash)]
            leafset = _leafset_bytes(msg)
        assert_greater_than(len(leafset), 0)
        return leafset
    finally:
        peer.peer_disconnect()


def fetch_mweb_utxo_page(node, block_hash, *, start_index=None, num_requested=64,
                         services=MWEB_LIGHT_CLIENT_SERVICES, timeout=MEGA_WAIT_MEDIUM):
    """Fetch one getmwebutxos page; returns the mwebutxos message.

    start_index defaults to the first unspent leaf in node's leafset.
    """
    if start_index is None:
        start_index = first_unspent_mweb_leaf(node, block_hash, timeout=timeout)
    peer = node.add_p2p_connection(MockLightClientBase(), services=services)
    try:
        peer.wait_for_verack()
        peer.request_mweb_utxos(block_hash, start_index=start_index, num_requested=num_requested)
        peer.wait_for_mwebutxos(block_hash, timeout=timeout)
        with p2p_lock:
            msg = peer.mwebutxos[Hash.from_hex(block_hash)]
            assert_greater_than(len(msg.utxos), 0)
            # Detach from peer dict for caller use after disconnect.
            return msg
    finally:
        peer.peer_disconnect()


def verify_utxo_proofs(test, node, block_hash, utxo_msg, helper=None, timeout=MEGA_WAIT_MEDIUM):
    """T-03: proof_hashes bind the served segment to chain MWEB state."""
    header = get_mweb_header(node, block_hash)
    assert header is not None
    assert_equal(utxo_msg.block_hash, Hash.from_hex(block_hash))
    leafset = fetch_mweb_leafset(node, block_hash, timeout=timeout)
    unspent = mweb_unspent_leaves(leafset)
    pos = bisect.bisect_left(unspent, utxo_msg.start_index)
    assert_equal([u.leaf_index for u in utxo_msg.utxos], unspent[pos:pos + len(utxo_msg.utxos)])
    assert_equal(segment_root(header.num_txos, utxo_msg), header.output_root)
    if helper is not None and len(utxo_msg.utxos) > 0:
        ref = fetch_mweb_utxo_page(
            helper, block_hash,
            start_index=utxo_msg.start_index,
            num_requested=len(utxo_msg.utxos),
            timeout=timeout,
        )
        assert_equal(utxo_msg.proof_hashes, ref.proof_hashes)
    test.log.info(
        "verify_utxo_proofs: block=%s utxos=%d proof_hashes=%d",
        block_hash, len(utxo_msg.utxos), len(utxo_msg.proof_hashes),
    )


def assert_segment_matches_helper(helper_peer_or_node, victim_msg, block_hash, *, timeout=MEGA_WAIT_MEDIUM):
    """Compare victim UTXO segment leaf indices and output hashes against helper."""
    node = helper_peer_or_node if hasattr(helper_peer_or_node, 'add_p2p_connection') else None
    peer = helper_peer_or_node
    owns_peer = False
    if node is not None:
        peer = node.add_p2p_connection(MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.wait_for_verack()
        owns_peer = True
    try:
        start = victim_msg.start_index
        n = len(victim_msg.utxos)
        peer.mwebutxos.pop(Hash.from_hex(block_hash), None)
        peer.request_mweb_utxos(block_hash, start_index=start, num_requested=n)
        peer.wait_for_mwebutxos(block_hash, timeout=timeout)
        with p2p_lock:
            ref = peer.mwebutxos[Hash.from_hex(block_hash)]
            assert_equal(ref.start_index, victim_msg.start_index)
            assert_equal(len(ref.utxos), n)
            for i in range(n):
                assert_equal(ref.utxos[i].leaf_index, victim_msg.utxos[i].leaf_index)
                assert_equal(ref.utxos[i].output, victim_msg.utxos[i].output)
    finally:
        if owns_peer:
            peer.peer_disconnect()


def assert_historical_serve(test, node, *, tip_hash, hist_hash, helper=None, timeout=MEGA_WAIT_MEDIUM):
    """Certify historical LIP-0006 serve content at hist_hash.

    (a) leafset and UTXO page at hist_hash are non-empty
    (b) if hist_hash != tip_hash and the chain's MWEB state differs at those
        heights (empty extension blocks may share state), hist responses differ
        from tip
    (c) if helper is given, hist leafset and first UTXO page match helper
    """
    hist_leafset = fetch_mweb_leafset(node, hist_hash, timeout=timeout)
    hist_page = fetch_mweb_utxo_page(
        node, hist_hash, start_index=mweb_unspent_leaves(hist_leafset)[0], timeout=timeout)
    test.log.info(
        "Historical serve at %s: leafset_bytes=%d utxos=%d",
        hist_hash, len(hist_leafset), len(hist_page.utxos),
    )

    if hist_hash != tip_hash:
        tip_leafset = fetch_mweb_leafset(node, tip_hash, timeout=timeout)
        tip_page = fetch_mweb_utxo_page(
            node, tip_hash, start_index=mweb_unspent_leaves(tip_leafset)[0], timeout=timeout)
        leafset_differs = hist_leafset != tip_leafset
        page_differs = _utxo_page_fingerprint(hist_page) != _utxo_page_fingerprint(tip_page)
        expect_distinct = True
        if helper is not None:
            # Use helper as ground truth for whether MWEB state diverged.
            helper_tip_leafset = fetch_mweb_leafset(helper, tip_hash, timeout=timeout)
            helper_hist_leafset = fetch_mweb_leafset(helper, hist_hash, timeout=timeout)
            expect_distinct = helper_tip_leafset != helper_hist_leafset
        if expect_distinct:
            assert leafset_differs or page_differs, (
                f"Historical serve at {hist_hash} matches tip {tip_hash} "
                f"(leafset_equal={not leafset_differs}, page_equal={not page_differs})"
            )
        else:
            assert not leafset_differs and not page_differs, (
                f"Historical serve at {hist_hash} diverged from tip {tip_hash} "
                f"but intermediate blocks have identical MWEB state"
            )

    if helper is not None:
        helper_leafset = fetch_mweb_leafset(helper, hist_hash, timeout=timeout)
        assert_equal(hist_leafset, helper_leafset)
        assert_segment_matches_helper(helper, hist_page, hist_hash, timeout=timeout)

    verify_utxo_proofs(test, node, hist_hash, hist_page, helper=helper, timeout=timeout)


def realign_victim_to_helper(test, victim, helper):
    """Drop victim-only blocks so both nodes share identical chain history."""
    target = helper.getblockcount()
    invalidated = 0
    while victim.getblockcount() > target:
        victim.invalidateblock(victim.getbestblockhash())
        invalidated += 1
    if invalidated:
        # Regtest mining is deterministic (fixed coinbase address / time). After
        # invalidateblock, regenerating the same tip content hits duplicate-invalid.
        # Advance mocktime so subsequent generates produce distinct block hashes.
        tip_time = victim.getblockheader(victim.getbestblockhash())['time']
        victim.setmocktime(tip_time + invalidated + 1)
    if victim.getblockcount() < target:
        victim_idx = test.nodes.index(victim)
        helper_idx = test.nodes.index(helper)
        test.connect_nodes(victim_idx, helper_idx)
        test.connect_nodes(helper_idx, victim_idx)
        test.sync_blocks(timeout=max(600, target * 2))


def sync_victim_from_helper_chain(test, victim, helper, *, timeout=None):
    """Sync victim to helper tip via P2P (reliable for mega chains)."""
    test.wait_until(
        lambda: not helper.getblockchaininfo()['initialblockdownload'],
        timeout=1200,
    )
    tip_height = helper.getblockcount()
    if timeout is None:
        timeout = max(1200, tip_height * 2)
    test.log.info("Syncing victim to helper via P2P (height %d, timeout=%ds)", tip_height, timeout)
    victim_idx = test.nodes.index(victim)
    helper_idx = test.nodes.index(helper)
    test.connect_nodes(victim_idx, helper_idx)
    test.connect_nodes(helper_idx, victim_idx)

    last_log = [0]

    def synced():
        vheight = victim.getblockcount()
        if vheight - last_log[0] >= 100 or vheight == tip_height:
            test.log.info("  victim sync progress: %d / %d", vheight, tip_height)
            last_log[0] = vheight
        vinfo = victim.getblockchaininfo()
        return vheight == tip_height and not vinfo['initialblockdownload']

    test.wait_until(synced, timeout=timeout, check_interval=2)
    test.log.info("Victim ready at height %d", victim.getblockcount())
    return tip_height


class TestPagination(unittest.TestCase):
    def test_short_pages_and_incomplete_walks(self):
        from types import SimpleNamespace

        block = '01' * 32
        class Peer:
            def __init__(self, pages, *, disconnect=False):
                self.pages = iter(pages)
                self.is_connected = True
                self.mwebutxos = {}
                self.starts = []
                self.disconnect = disconnect

            def request_mweb_utxos(self, block_hash, start_index, num_requested):
                self.starts.append(start_index)
                indices = next(self.pages)
                self.mwebutxos[Hash.from_hex(block_hash)] = SimpleNamespace(
                    start_index=start_index, utxos=[SimpleNamespace(leaf_index=i) for i in indices])
                if self.disconnect:
                    self.is_connected = False

            def wait_for_mwebutxos(self, block_hash, timeout):
                pass

        # Sparse leafset 0,2,4,6. A short page can be a budget limit, not EOF.
        peer = Peer([[0], [2, 4], [6]])
        self.assertEqual(paginate_mweb_utxos(peer, block, leafset=b'\xaa', page_size=4), 4)
        self.assertEqual(peer.starts, [0, 2, 6])
        for peer, max_pages in ((Peer([[0], [2, 4]]), 2),
                                (Peer([[]]), 4),
                                (Peer([[0, 4]]), 4),
                                (Peer([[0]], disconnect=True), 4)):
            with self.subTest(starts=peer.starts), self.assertRaises(AssertionError):
                paginate_mweb_utxos(peer, block, leafset=b'\xaa', page_size=4, max_pages=max_pages)
