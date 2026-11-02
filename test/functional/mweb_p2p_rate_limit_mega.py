#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB P2P rate-limit mega tests — §7.7 C/D matrix at plan-scale mega chain.

Exercises production serve, upload limits, and IBD gating on peg-in-heavy chains,
plus tip serve parity and tip-1 historical identity after restart.
"""

import time

from test_framework.messages import (
    CInv,
    Hash,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    MSG_MWEB_LEAFSET,
    NODE_MWEB_LIGHT_CLIENT,
    msg_getdata,
    msg_getmwebutxos,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    generate,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.mweb_stress_mega_util import (
    LeafsetFloodPeer,
    MEGA_PUBLISH_P95_MAX_NS,
    MEGA_WAIT_MEDIUM,
    MEGA_WAIT_SHORT,
    MWEB_LIGHT_CLIENT_SERVICES,
    MWEBAbusePeer,
    MWEBUploadAbusePeer,
    MWEBServeLogStats,
    assert_historical_serve,
    assert_mweb_serve_parity,
    first_unspent_mweb_leaf,
    load_or_build_mega_chain,
    paginate_mweb_utxos,
    restart_mega_node,
    shared_historical_anchor,
    sync_victim_from_helper_chain,
)
from test_framework.util import (
    assert_greater_than,
)

UPLOAD_LIMIT_ARGS = ['-maxuploadtarget=100k']
# Regtest chain work stays below mainnet minimum, so IBD latch never clears on a fresh node.
IBD_MIN_CHAINWORK = "0x0000000000000000000000000000000000000001128750f82f4c366153a3a030"


class MWEBLightClientPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.mwebutxos = {}

    def request_mweb_utxos(self, block_hash, start_index, num_requested=1):
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(block_hash),
            start_index=start_index,
            num_requested=num_requested,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))

    def on_mwebutxos(self, message):
        self.mwebutxos[message.block_hash] = message

    def wait_for_mwebutxos(self, block_hash, timeout=MEGA_WAIT_MEDIUM):
        expected = Hash.from_hex(block_hash)
        self.wait_until(lambda: expected in self.mwebutxos, timeout=timeout)


class MWEBP2PRateLimitMegaTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [mweb_extra_args([])[0], mweb_extra_args([])[0]]
        self.tip_hash = None

    def add_options(self, parser):
        parser.add_argument(
            '--mweb-mega-scale',
            default='full',
            choices=['quick', 'full', 'extended'],
            help='Mega chain scale for rate-limit tests (default: full)',
        )
        parser.add_argument(
            '--mweb-mega-rebuild-chain',
            action='store_true',
            default=False,
            help='Force rebuild of cached mega chain',
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def setup_mega_tip(self):
        scale = self.options.mweb_mega_scale
        helper = self.nodes[1]
        load_or_build_mega_chain(self, helper, scale=scale)
        victim = self.nodes[0]
        self.stop_node(0)
        for sub in ('blocks', 'chainstate', 'indexes'):
            path = victim.chain_path / sub
            if path.exists():
                self.cleanup_folder(path)
        victim.blocks_path.mkdir(parents=True, exist_ok=True)
        self.start_node(0, extra_args=self.extra_args[0])
        victim._rpc = victim.create_new_rpc_connection(client_timeout=600)
        sync_victim_from_helper_chain(self, victim, helper)
        # Parity against the shared tip (before victim-only empty generates).
        shared_hash = helper.getbestblockhash()
        helper_count = paginate_mweb_utxos(helper, shared_hash, page_size=256, max_pages=200)
        assert_mweb_serve_parity(
            self, victim, shared_hash, min_utxos=max(0, helper_count - 1),
        )
        generate(victim, 3)
        self.tip_hash = victim.getbestblockhash()
        self.log.info(
            "Mega tip ready at height %d (scale=%s, shared_utxos=%d)",
            victim.getblockcount(), scale, helper_count,
        )

    def test_historical_tip_minus_one_after_restart(self):
        """After restart, tip-1 leafset/UTXOs differ from tip and match helper."""
        self.log.info("Historical tip-1 serve after restart")
        victim = self.nodes[0]
        helper = self.nodes[1]
        # Use heights present on both nodes (victim may have empty blocks above).
        shared_height = helper.getblockcount()
        tip_hash = victim.getblockhash(shared_height)
        hist_hash = victim.getblockhash(shared_height - 1)
        # Cold historical serve after restart: reindex certifies miss path on mega chainstate.
        restart_mega_node(self, victim, reindex_chainstate=True)
        victim = self.nodes[0]
        assert_historical_serve(
            self, victim, tip_hash=tip_hash, hist_hash=hist_hash, helper=helper,
        )
        self.tip_hash = victim.getbestblockhash()

    def restart_victim(self, extra_args=None, *, reindex_chainstate=False):
        """Policy restart by default; pass reindex_chainstate=True for cold miss."""
        restart_mega_node(
            self, self.nodes[0], extra_args=extra_args,
            reindex_chainstate=reindex_chainstate,
        )
        generate(self.nodes[0], 1)
        return self.nodes[0].getbestblockhash()

    def restart_victim_node(self, extra_args=None, *, reindex_chainstate=False):
        """Policy restart by default (C/D matrix). Use reindex only for cold miss."""
        restart_mega_node(
            self, self.nodes[0], extra_args=extra_args,
            reindex_chainstate=reindex_chainstate,
        )

    def fresh_tip(self, node_index=0):
        return self.nodes[node_index].getbestblockhash()

    def localservices_has_light_client(self, node):
        services = int(node.getnetworkinfo()['localservices'], 16)
        return bool(services & NODE_MWEB_LIGHT_CLIENT)

    def upload_target_reached(self, node):
        return node.getnettotals()['uploadtarget']['target_reached']

    def exhaust_upload_budget(self, node, tip_hash, disconnect_after=True):
        witness_block = CInv(MSG_BLOCK | MSG_WITNESS_FLAG, int(tip_hash, 16))
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        for _ in range(2000):
            if self.upload_target_reached(node):
                break
            if not peer.is_connected:
                if self.upload_target_reached(node):
                    break
                peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
            peer.send_without_ping(msg_getdata([witness_block]))
            time.sleep(0.02)
            if not peer.is_connected and self.upload_target_reached(node):
                break
        self.wait_until(lambda: self.upload_target_reached(node), timeout=MEGA_WAIT_MEDIUM)
        if disconnect_after:
            node.disconnect_p2ps()

    def reduce_upload_budget(self, node, tip_hash, max_bytes_left):
        witness_block = CInv(MSG_BLOCK | MSG_WITNESS_FLAG, int(tip_hash, 16))
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        for _ in range(2000):
            upload = node.getnettotals()['uploadtarget']
            if upload['target_reached']:
                raise AssertionError('upload target reached while reducing budget')
            if upload['bytes_left_in_cycle'] <= max_bytes_left:
                return peer
            if not peer.is_connected:
                peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
            peer.send_without_ping(msg_getdata([witness_block]))
            time.sleep(0.02)
        upload = node.getnettotals()['uploadtarget']
        assert_greater_than(upload['bytes_left_in_cycle'], 0)
        return peer

    def test_blocksonly_no_serve(self, tip_hash):
        self.log.info("D1: -blocksonly clears MWEB_LIGHT_CLIENT and ignores serve")
        tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)
        self.restart_victim_node( extra_args=[*mweb_extra_args(["-blocksonly"])[0]])
        assert not self.localservices_has_light_client(self.nodes[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, tip_leaf)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        with p2p_lock:
            assert Hash.from_hex(tip_hash) not in peer.mwebutxos
            assert peer.is_connected

    def test_blocksonly_override(self, tip_hash):
        self.log.info("D2: -mwebserveinblocksonly serves under blocksonly")
        tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)
        self.restart_victim_node( extra_args=[*mweb_extra_args(["-blocksonly", "-mwebserveinblocksonly=1"])[0]])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, tip_leaf)
        peer.wait_for_mwebutxos(tip_hash, timeout=MEGA_WAIT_MEDIUM)

    def test_mwebserve_off(self, tip_hash):
        self.log.info("D3: -mwebserve=0 disables light-client serve")
        tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)
        self.restart_victim_node( extra_args=[*mweb_extra_args(["-mwebserve=0"])[0]])
        assert not self.localservices_has_light_client(self.nodes[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, tip_leaf)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        with p2p_lock:
            assert Hash.from_hex(tip_hash) not in peer.mwebutxos

    def test_upload_limit_disconnect(self, tip_hash):
        self.log.info("C6: upload limit disconnects LIP-0006 requests")
        self.restart_victim_node( extra_args=[*mweb_extra_args(UPLOAD_LIMIT_ARGS)[0]])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        self.exhaust_upload_budget(node, tip_hash)
        assert self.upload_target_reached(node)
        peer2 = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer2.request_mweb_utxos(tip_hash, tip_leaf)
        peer2.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)

    def test_upload_abuse_peer(self, tip_hash):
        self.log.info("C6b: upload abuse peer disconnected after budget exhausted")
        self.restart_victim_node( extra_args=[*mweb_extra_args(UPLOAD_LIMIT_ARGS)[0]])
        node = self.nodes[0]
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        self.exhaust_upload_budget(node, tip_hash, disconnect_after=False)
        abuse = node.add_p2p_connection(MWEBUploadAbusePeer(tip_hash, tip_leaf), services=MWEB_LIGHT_CLIENT_SERVICES)
        abuse.send_upload_abuse_request()
        abuse.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)

    def test_download_bypass(self, tip_hash):
        self.log.info("C7: download permission bypasses upload limit for serve")
        self.restart_victim_node( extra_args=[
            *mweb_extra_args([*UPLOAD_LIMIT_ARGS, '-whitelist=download@127.0.0.1'])[0],
        ])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        self.exhaust_upload_budget(node, tip_hash, disconnect_after=False)
        assert self.upload_target_reached(node)
        tip_hash = self.fresh_tip()
        peer.request_mweb_utxos(tip_hash, tip_leaf)
        peer.wait_for_mwebutxos(tip_hash, timeout=MEGA_WAIT_MEDIUM)
        assert peer.is_connected

    def test_partial_utxo_large_chain(self, tip_hash):
        self.log.info("D5: partial UTXO on large leafset from mega chain")
        self.restart_victim_node( extra_args=[*mweb_extra_args(UPLOAD_LIMIT_ARGS)[0]])
        node = self.nodes[0]
        # Taken before the budget cut; the block mined below has no MWEB spends,
        # so the leaf stays unspent at the new tip.
        tip_leaf = first_unspent_mweb_leaf(node, self.fresh_tip())
        self.reduce_upload_budget(node, self.fresh_tip(), max_bytes_left=512 * 256)
        node.disconnect_p2ps()
        generate(node, 1)
        tip_hash = self.fresh_tip()
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        upload = node.getnettotals()['uploadtarget']
        assert_greater_than(upload['bytes_left_in_cycle'], 0)
        peer.request_mweb_utxos(tip_hash, tip_leaf, num_requested=4096)
        peer.wait_for_mwebutxos(tip_hash, timeout=MEGA_WAIT_MEDIUM)
        with p2p_lock:
            response = peer.mwebutxos[Hash.from_hex(tip_hash)]
            assert len(response.utxos) < 4096
            assert_greater_than(len(response.utxos), 0)
            assert peer.is_connected

    def test_service_bit_refresh(self, tip_hash):
        self.log.info("D6: MWEB_LIGHT_CLIENT returns after upload cycle reset")
        self.restart_victim_node( extra_args=[*mweb_extra_args(UPLOAD_LIMIT_ARGS)[0]])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        self.exhaust_upload_budget(node, tip_hash)
        assert self.upload_target_reached(node)
        peer = node.add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        assert not self.localservices_has_light_client(node)
        node.disconnect_p2ps()
        now = int(time.time())
        node.setmocktime(now + 25 * 3600)
        peer2 = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer2.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        self.wait_until(lambda: not self.upload_target_reached(node), timeout=MEGA_WAIT_SHORT)
        self.wait_until(lambda: self.localservices_has_light_client(node), timeout=MEGA_WAIT_SHORT)
        serve_hash = self.fresh_tip()
        peer2.request_mweb_utxos(serve_hash, tip_leaf)
        peer2.wait_for_mwebutxos(serve_hash, timeout=MEGA_WAIT_MEDIUM)

    def test_force_serve_at_limit(self, tip_hash):
        self.log.info("D4: -mwebserve=1 serves despite upload limit")
        tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)
        self.restart_victim_node( extra_args=[*mweb_extra_args([*UPLOAD_LIMIT_ARGS, '-mwebserve=1'])[0]])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        assert self.upload_target_reached(self.nodes[0])
        # Policy restart does not reindex tip updates; service bits refresh on
        # msghand (MaybeRefreshMwebLightClientServices). Ping first like
        # mweb_p2p_rate_limit.py test_service_bit_refresh.
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        assert self.localservices_has_light_client(self.nodes[0])
        peer.request_mweb_utxos(tip_hash, tip_leaf)
        peer.wait_for_mwebutxos(tip_hash, timeout=MEGA_WAIT_MEDIUM)

    def test_cpu_credit_exhaustion(self, tip_hash):
        self.log.info("C8: low mwebserveburst + abuse peer rate limited")
        tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)
        self.restart_victim_node( extra_args=[*mweb_extra_args(['-mwebserveburst=100', '-debug=net'])[0]])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        abuse = node.add_p2p_connection(
            MWEBAbusePeer(tip_hash, tip_leaf, num_requested=50), services=MWEB_LIGHT_CLIENT_SERVICES)
        with node.assert_debug_log(['MWEB serve credit deny:']):
            for _ in range(20):
                if not abuse.is_connected:
                    break
                try:
                    abuse.send_abuse_request()
                except OSError:
                    break
            abuse.wait_for_disconnect(timeout=MEGA_WAIT_MEDIUM)
        assert abuse.responses_received < abuse.requests_sent
        node.disconnect_p2ps()
        self.log.info("C8: abuse peer limited (connected=%s)", abuse.is_connected)

    def test_ibd_silent_ignore(self):
        """C9: getmwebutxos ignored while victim in IBD."""
        self.log.info("C9: IBD victim silently ignores getmwebutxos")
        helper = self.nodes[1]
        victim = self.nodes[0]
        self.stop_node(0)
        self.cleanup_folder(victim.blocks_path)
        self.cleanup_folder(victim.chain_path / "chainstate")
        indexes = victim.chain_path / "indexes"
        if indexes.exists():
            self.cleanup_folder(indexes)
        victim.blocks_path.mkdir(parents=True, exist_ok=True)
        ibd_args = [
            *mweb_extra_args([
                '-connect=0',
                f'-minimumchainwork={IBD_MIN_CHAINWORK}',
            ])[0],
        ]
        self.start_node(0, extra_args=ibd_args)
        setup_mweb_chain(victim)
        assert victim.getblockchaininfo()['initialblockdownload']
        self.connect_nodes(0, 1)
        assert victim.getblockcount() < helper.getblockcount()
        tip_hash = victim.getbestblockhash()
        peer = victim.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, 0)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        with p2p_lock:
            assert Hash.from_hex(tip_hash) not in peer.mwebutxos
            assert peer.is_connected

    def test_inactive_chain_ignore(self, tip_hash):
        """C5: inactive fork hash ignored, peer stays connected."""
        self.log.info("C5: inactive chain hash ignored")
        node = self.nodes[0]
        self.restart_victim_node( extra_args=self.extra_args[0])
        stale = generate(node, 1)[0]
        stale_leaf = first_unspent_mweb_leaf(node, stale)
        node.invalidateblock(stale)
        node.generatetoaddress(nblocks=2, address=node.getnewaddress(), called_by_framework=True)
        node.reconsiderblock(stale)
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(stale, stale_leaf)
        peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        with p2p_lock:
            assert Hash.from_hex(stale) not in peer.mwebutxos
            assert peer.is_connected
        serve_hash = self.fresh_tip()
        peer.request_mweb_utxos(serve_hash, first_unspent_mweb_leaf(node, serve_hash))
        peer.wait_for_mwebutxos(serve_hash, timeout=MEGA_WAIT_MEDIUM)

    def test_m1_chunked_replay_steps(self):
        """M1: empty cache tip-10 completes with many replay steps (chunked, not megastep)."""
        self.log.info("M1: chunked replay steps on mega chain")
        victim = self.nodes[0]
        _, hist_hash = shared_historical_anchor(victim, self.nodes[1], offset=10)
        hist_leaf = first_unspent_mweb_leaf(self.nodes[1], hist_hash, timeout=180)
        extra = [*mweb_extra_args(['-debug=net'])[0]]
        # Policy restart + RPC clear: cold ring without full chainstate reindex.
        self.restart_victim_node(extra_args=extra)
        victim = self.nodes[0]
        victim.clearmwebhistoricalcache()
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.mark_log_end()
        peer = victim.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(hist_hash, hist_leaf)
        peer.wait_for_mwebutxos(hist_hash, timeout=180)
        replay_steps = stats.replay_steps_since()
        self.log.info("M1: replay steps=%d", replay_steps)
        assert_greater_than(replay_steps, 9)
        victim.disconnect_p2ps()

    def test_m2_publish_overhead_bounded(self):
        """M2: per-block cache publish latency stays within I4 budget on mega chain."""
        self.log.info("M2: publish overhead bounded")
        victim = self.nodes[0]
        helper = self.nodes[1]
        # Seed ring with tip snapshot so ConnectBlock Publish has a parent entry.
        tip_hash = victim.getbestblockhash()
        seed_peer = victim.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        seed_peer.request_mweb_utxos(tip_hash, first_unspent_mweb_leaf(victim, tip_hash, timeout=180))
        seed_peer.wait_for_mwebutxos(tip_hash, timeout=180)
        victim.disconnect_p2ps()
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.publish_samples_since(reset_offset=True)
        fund_addr = victim.getnewaddress()
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 0)
        from test_framework.mweb_density_util import FUNDER_WALLET_NAME
        funder = helper.get_wallet_rpc(FUNDER_WALLET_NAME)
        funder.sendtoaddress(fund_addr, 1.0)
        generate(helper, 1)
        self.sync_blocks([victim, helper])
        self.wait_until(lambda: victim.getbalance() >= 0.5, timeout=30)
        addr = victim.getnewaddress(address_type='mweb')
        for _ in range(3):
            victim.sendtoaddress(addr, 0.01)
        generate(victim, 3)
        samples = stats.publish_samples_since()
        self.log.info("M2: publish samples=%d (max_ns=%s)", len(samples),
                      max((ns for _, ns in samples), default=0))
        assert_greater_than(len(samples), 0)
        max_ns = max(ns for _, ns in samples)
        assert max_ns < MEGA_PUBLISH_P95_MAX_NS, f"publish ns {max_ns} exceeds budget"
        victim.disconnect_p2ps()
        self.restart_victim_node(extra_args=self.extra_args[0])

    def test_f1_leafset_credit_floor(self):
        """F1: real leafset responses exhaust the floor-priced credit budget.

        These profiles stay below 100 KiB; above-floor hint propagation is tested
        by mweb_serve_tests_chain/enqueue_credit_hints_above_pricing_floors.
        """
        burst = 800  # enough for a cold 500 surcharge plus three 100-credit replies
        self.restart_victim_node(extra_args=[*mweb_extra_args([
            f'-mwebserveburst={burst}', '-debug=net',
        ])[0]])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        stats = MWEBServeLogStats(node.debug_log_path)
        stats.mark_log_end()
        peer = node.add_p2p_connection(
            LeafsetFloodPeer(tip_hash), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.send_leafset_request()
        self.wait_until(lambda: peer.leafset_bytes > 0, timeout=MEGA_WAIT_MEDIUM)
        assert 0 < peer.leafset_bytes <= 100 * 1024
        # Synchronize each request so a queued/unprocessed request is not denial.
        for _ in range(burst // 100 + 1):
            peer.send_leafset_request()
            peer.sync_with_ping(timeout=MEGA_WAIT_MEDIUM)
            if stats.count_new(stats.CREDIT_DENY):
                break
        assert_greater_than(stats.count_new(stats.CREDIT_DENY), 0)
        assert_greater_than(peer.responses_received, 0)
        assert peer.responses_received < peer.requests_sent
        self.log.info("F1: leafset=%d bytes, responses=%d requests=%d denies=%d",
                      peer.leafset_bytes, peer.responses_received, peer.requests_sent,
                      stats.count_new(stats.CREDIT_DENY))
        node.disconnect_p2ps()
        self.restart_victim_node(extra_args=self.extra_args[0])

    def test_f2_leafset_upload_disconnect(self):
        """F2: leafset getdata after upload budget exhausted disconnects peer."""
        self.log.info("F2: leafset upload disconnect on mega chain")
        self.restart_victim_node(extra_args=[*mweb_extra_args(UPLOAD_LIMIT_ARGS)[0]])
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        self.exhaust_upload_budget(node, tip_hash)
        peer = node.add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.send_without_ping(msg_getdata([CInv(MSG_MWEB_LEAFSET, int(tip_hash, 16))]))
        peer.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)
        self.restart_victim_node(extra_args=self.extra_args[0])

    def test_e2_start_index_past_eof(self):
        """E2: start_index past EOF disconnects peer."""
        self.log.info("E2: start_index past EOF")
        node = self.nodes[0]
        tip_hash = self.fresh_tip()
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, start_index=10_000_000, num_requested=1)
        peer.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)
        node.disconnect_p2ps()

    def run_test(self):
        self.setup_mega_tip()
        tip_hash = self.tip_hash

        self.test_historical_tip_minus_one_after_restart()
        tip_hash = self.tip_hash

        self.test_blocksonly_no_serve(tip_hash)
        self.restart_victim_node( extra_args=self.extra_args[0])
        tip_hash = self.fresh_tip()

        self.test_blocksonly_override(tip_hash)
        self.restart_victim_node( extra_args=self.extra_args[0])
        tip_hash = self.fresh_tip()

        self.test_mwebserve_off(tip_hash)
        self.restart_victim_node( extra_args=self.extra_args[0])
        tip_hash = self.fresh_tip()

        self.test_force_serve_at_limit(tip_hash)
        self.restart_victim_node( extra_args=self.extra_args[0])
        tip_hash = self.fresh_tip()

        self.test_download_bypass(tip_hash)

        self.test_upload_limit_disconnect(tip_hash)
        tip_hash = self.restart_victim()

        self.test_upload_abuse_peer(tip_hash)
        tip_hash = self.restart_victim()

        self.test_partial_utxo_large_chain(tip_hash)
        tip_hash = self.restart_victim()

        self.test_service_bit_refresh(tip_hash)
        tip_hash = self.restart_victim()

        self.test_cpu_credit_exhaustion(tip_hash)
        tip_hash = self.restart_victim()

        self.test_inactive_chain_ignore(tip_hash)
        tip_hash = self.restart_victim()

        self.test_ibd_silent_ignore()

        # C9 leaves victim in partial IBD; restore mega chain before §9 tests.
        victim = self.nodes[0]
        helper = self.nodes[1]
        self.stop_node(0)
        for sub in ('blocks', 'chainstate', 'indexes'):
            path = victim.chain_path / sub
            if path.exists():
                self.cleanup_folder(path)
        victim.blocks_path.mkdir(parents=True, exist_ok=True)
        self.start_node(0, extra_args=self.extra_args[0])
        victim._rpc = victim.create_new_rpc_connection(client_timeout=600)
        sync_victim_from_helper_chain(self, self.nodes[0], helper)
        generate(self.nodes[0], 3)

        self.log.info("--- §9 M/F/E coverage ---")
        self.test_m1_chunked_replay_steps()
        self.test_m2_publish_overhead_bounded()
        self.test_f1_leafset_credit_floor()
        self.test_f2_leafset_upload_disconnect()
        self.test_e2_start_index_past_eof()

        self.log.info("=== MWEB P2P rate limit mega: ALL PASSED ===")


if __name__ == '__main__':
    MWEBP2PRateLimitMegaTest(__file__).main()
