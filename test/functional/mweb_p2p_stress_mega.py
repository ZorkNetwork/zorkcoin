#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
MWEB P2P mega stress tests (P-01) — full §7.7 matrix at plan scale.

Scales: quick (~800) / full (~8000) / extended (~16000) post-MWEB blocks via --mweb-mega-scale.
Certifies tip and historical LIP-0006 serve (tip-1/5/10), cache-miss after restart,
victim IBD parity, and post-reorg tip serve via content equality and tip-vs-historical
inequality. Manual execution only.
"""

import threading
import time

from test_framework.messages import (
    CInv,
    MSG_MWEB_LEAFSET,
    NODE_MWEB,
    NODE_NETWORK,
    NODE_WITNESS,
    Hash,
    msg_getdata,
    msg_sendcmpct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    get_mweb_header,
    mweb_extra_args,
)
from test_framework.mweb_stress_mega_util import (
    BenignProbePeer,
    BlockFetchPeer,
    CompactMWEBPeer,
    HeadersProbePeer,
    HISTORICAL_DEPTH_OFFSETS,
    MAX_MWEB_LEAFSET_DEPTH,
    MAX_MWEB_SERVE_JOBS_GLOBAL,
    MAX_MWEB_SERVE_JOBS_PER_PEER,
    MEGA_MINE_MAX,
    MEGA_MATERIALIZE_P95_MAX_NS,
    MEGA_PING_P95_MAX,
    MEGA_SCALE_CONFIG,
    MEGA_WAIT_MEDIUM,
    MEGA_WAIT_SHORT,
    MEGA_WAIT_SYNC,
    MWEB_LIGHT_CLIENT_SERVICES,
    MWEBAbusePeer,
    MWEBInvalidPeer,
    MWEBServeLogStats,
    MWEBSyncPeer,
    MockLightClientBase,
    SlowMWEBPeer,
    TxInvPeer,
    anchor_hashes_for_tip,
    assert_historical_serve,
    assert_mweb_serve_parity,
    assert_random_segments_match_helper,
    assert_segment_matches_helper,
    assert_serve_pagination_floor,
    fetch_mweb_leafset,
    fetch_mweb_utxo_page,
    first_unspent_mweb_leaf,
    load_or_build_mega_chain,
    mweb_unspent_leaves,
    paginate_mweb_utxos,
    realign_victim_to_helper,
    restart_mega_node,
    run_abuse_loop,
    run_sync_loop,
    shared_historical_anchor,
    sync_victim_from_helper_chain,
    max_peer_misbehaving_score,
)
from test_framework.p2p import p2p_lock
from test_framework.util import assert_equal, assert_greater_than


class MWEBP2PStressMegaTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # The global queue cap test opens more tx-relaying inbound peers than
        # the framework's maxconnections=76 and the default
        # inboundrelaypercent=50 allow.
        self.extra_args = [
            mweb_extra_args(['-maxconnections=125', '-inboundrelaypercent=100'])[0],
            mweb_extra_args([])[0],
        ]
        self.chain_meta = None
        self.victim = None
        self.helper = None

    def add_options(self, parser):
        parser.add_argument(
            '--mweb-mega-scale',
            default='quick',
            choices=['quick', 'full', 'extended'],
            help='Mega stress scale (default: quick)',
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

    def setup_mega_topology(self):
        self.helper = self.nodes[1]
        self.victim = self.nodes[0]
        scale = self.options.mweb_mega_scale
        cfg = MEGA_SCALE_CONFIG[scale]
        self.chain_meta = load_or_build_mega_chain(self, self.helper, scale=scale)
        assert_greater_than(self.chain_meta['utxo_floor'], 0)
        generate(self.helper, 3)
        tip_hash = self.helper.getbestblockhash()
        assert_mweb_serve_parity(self, self.helper, tip_hash, min_utxos=cfg['min_mweb_utxos'])
        self.stop_node(0)
        for sub in ('blocks', 'chainstate', 'indexes'):
            path = self.victim.chain_path / sub
            if path.exists():
                self.cleanup_folder(path)
        self.victim.blocks_path.mkdir(parents=True, exist_ok=True)
        self.start_node(0, extra_args=self.extra_args[0])
        self.victim._rpc = self.victim.create_new_rpc_connection(client_timeout=600)
        sync_victim_from_helper_chain(self, self.victim, self.helper)
        self.chain_meta['tip_height'] = self.victim.getblockcount()
        self.chain_meta['tip_hash'] = self.victim.getbestblockhash()
        assert_mweb_serve_parity(
            self, self.victim, self.chain_meta['tip_hash'], min_utxos=cfg['min_mweb_utxos'],
        )

    def stable_anchor_hash(self, victim):
        """Near-tip anchors within MAX_MWEB_LEAFSET_DEPTH for serve requests."""
        return anchor_hashes_for_tip(victim)[0]

    def depth_anchors(self, victim):
        return anchor_hashes_for_tip(victim)

    def run_concurrent_abuse_and_sync(self):
        """Core P-01 liveness: abusive peers + legitimate sync peers concurrently."""
        scale = self.options.mweb_mega_scale
        cfg = MEGA_SCALE_CONFIG[scale]
        victim = self.victim
        # Capture a tip present on both nodes before victim-only mining.
        shared_tip = self.helper.getbestblockhash()
        generate(victim, 1)
        self.chain_meta['tip_hash'] = victim.getbestblockhash()
        anchor = self.stable_anchor_hash(victim)
        anchors = self.depth_anchors(victim)
        # Keep each outstanding sync walk pinned while the tip advances twice.
        # Replacing its anchors mid-page makes a valid old response look foreign.
        anchors = [h for h in anchors if victim.getblockheader(h)['height'] + MAX_MWEB_LEAFSET_DEPTH
                   >= victim.getblockcount() + 2]
        unspent = mweb_unspent_leaves(fetch_mweb_leafset(victim, anchor))

        abuse_peers = []
        for _ in range(cfg['n_abuse']):
            p = victim.add_p2p_connection(
                MWEBAbusePeer(anchor, unspent[0], num_requested=256),
                services=MWEB_LIGHT_CLIENT_SERVICES, wait_for_verack=False)
            p.wait_for_verack()
            abuse_peers.append(p)

        sync_peers = []
        page = 64
        for i in range(cfg['n_sync']):
            start = unspent[min(i * page, len(unspent) - 1)]
            p = victim.add_p2p_connection(
                MWEBSyncPeer(anchor, start_index=start, page_size=page, depth_anchors=anchors),
                services=MWEB_LIGHT_CLIENT_SERVICES,
                wait_for_verack=False,
            )
            p.wait_for_verack()
            sync_peers.append(p)

        benign = victim.add_p2p_connection(BenignProbePeer(), wait_for_verack=False)
        benign.wait_for_verack()
        locator = [int(victim.getblockhash(max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 20)), 16)]
        headers_peer = victim.add_p2p_connection(
            HeadersProbePeer(locator), wait_for_verack=False)
        headers_peer.wait_for_verack()

        stop_abuse = threading.Event()
        stop_sync = threading.Event()
        abuse_thread = threading.Thread(
            target=run_abuse_loop, args=(abuse_peers, stop_abuse, cfg['abuse_rate']), daemon=True)
        sync_thread = threading.Thread(
            target=run_sync_loop, args=(sync_peers, stop_sync), daemon=True)
        abuse_thread.start()
        sync_thread.start()

        try:
            # Let sync peers receive at least one page before abuse ramps up.
            time.sleep(1.0)

            mine_start = time.monotonic()
            generate(victim, 2)
            mine_elapsed = time.monotonic() - mine_start

            deadline = time.monotonic() + cfg['abuse_seconds']
            while time.monotonic() < deadline:
                if benign.is_connected:
                    benign.send_ping_probe()
                time.sleep(0.05)

            assert mine_elapsed < MEGA_MINE_MAX, f"Mining stalled ({mine_elapsed:.2f}s)"
            assert benign.is_connected, "Benign peer disconnected during load"

            connected_sync = sum(1 for p in sync_peers if p.is_connected)
            sync_pages = sum(p.pages_received for p in sync_peers)
            abuse_connected = sum(1 for p in abuse_peers if p.is_connected)
            abuse_responses = sum(p.responses_received for p in abuse_peers)
            self.log.info(
                "Load result: sync peers connected %d/%d pages %d; "
                "abuse peers connected %d/%d responses %d",
                connected_sync, len(sync_peers), sync_pages,
                abuse_connected, len(abuse_peers), abuse_responses,
            )
            assert_greater_than(sync_pages, 0)

            benign.sync_with_ping(timeout=MEGA_WAIT_MEDIUM)
            assert_greater_than(len(benign.rtts), 0)
            p95 = benign.rtt_p95()
            self.log.info("Benign ping p95: %.3fs", p95)
            assert p95 < MEGA_PING_P95_MAX, f"Ping p95 too high ({p95:.3f}s)"

            # Victim mines ahead of helper during load. Cross-check a segment at the
            # pre-mine shared tip so both nodes serve the same block hash.
            shared_msg = fetch_mweb_utxo_page(
                self.victim, shared_tip, start_index=first_unspent_mweb_leaf(self.helper, shared_tip),
                num_requested=64)
            self.log.info(
                "Sync segment validated: %d utxos at index %d hash %s",
                len(shared_msg.utxos), shared_msg.start_index, shared_tip,
            )
            assert_segment_matches_helper(self.helper, shared_msg, shared_tip)

            headers_peer.request_headers()
            headers_peer.wait_until(lambda: len(headers_peer.headers) > 0, timeout=MEGA_WAIT_MEDIUM)
            new_tip = victim.getbestblockhash()
            fetch_peer = victim.add_p2p_connection(
                BlockFetchPeer(new_tip), wait_for_verack=False)
            fetch_peer.wait_for_verack()
            fetch_peer.request_tip_block()
            fetch_peer.wait_until(lambda: fetch_peer.received, timeout=MEGA_WAIT_MEDIUM)

        finally:
            stop_abuse.set()
            stop_sync.set()
            abuse_thread.join(timeout=MEGA_WAIT_SHORT)
            sync_thread.join(timeout=MEGA_WAIT_SHORT)
        assert not abuse_thread.is_alive() and not sync_thread.is_alive()
        victim.disconnect_p2ps()
        self.log.info("Core concurrent abuse+sync: PASSED")

    def test_invalid_peer_disconnect(self):
        """C1-C3: invalid requests disconnect."""
        victim = self.victim
        tip_hash = self.chain_meta['tip_hash']
        deep_height = victim.getblockcount() - MAX_MWEB_LEAFSET_DEPTH - 1
        deep_hash = victim.getblockhash(deep_height) if deep_height >= FIRST_MWEB_HEIGHT else tip_hash
        assert deep_height >= FIRST_MWEB_HEIGHT
        for step in range(3):
            invalid = victim.add_p2p_connection(MWEBInvalidPeer(tip_hash, deep_hash))
            invalid._step = step
            invalid.send_next_invalid_request()
            invalid.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)
            victim.disconnect_p2ps()
        self.log.info("Invalid peer disconnect: PASSED")

    def test_c4_pre_mweb_disconnect(self):
        """C4: pre-MWEB block hash disconnects."""
        victim = self.victim
        pre_mweb_hash = victim.getblockhash(FIRST_MWEB_HEIGHT - 1)
        peer = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.send_without_ping(msg_getdata([
            CInv(MSG_MWEB_LEAFSET, int(pre_mweb_hash, 16)),
        ]))
        peer.wait_for_disconnect(timeout=MEGA_WAIT_SHORT)
        victim.disconnect_p2ps()
        self.log.info("C4 pre-MWEB disconnect: PASSED")

    def test_sync_depth_variants(self):
        """A2: serve at tip, tip-1, tip-5, tip-10 matches helper and differs from tip."""
        victim = self.victim
        tip_hash = victim.getbestblockhash()
        tip_height = victim.getblockcount()
        for offset in HISTORICAL_DEPTH_OFFSETS:
            height = tip_height - offset
            if height < FIRST_MWEB_HEIGHT:
                continue
            hist_hash = victim.getblockhash(height)
            self.log.info("A2: historical serve at tip-%d (%s)", offset, hist_hash)
            assert_historical_serve(
                self, victim, tip_hash=tip_hash, hist_hash=hist_hash, helper=self.helper,
                timeout=180,
            )
        self.log.info("Sync depth variants: PASSED")

    def test_cache_miss_replay(self):
        """A5: victim restart clears cache; historical serve at tip-10 after cold replay."""
        victim = self.victim
        tip_hash = victim.getbestblockhash()
        hist_height = max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 10)
        hist_hash = victim.getblockhash(hist_height)
        restart_mega_node(self, victim, reindex_chainstate=True)
        self.victim = self.nodes[0]
        assert_historical_serve(
            self, self.victim, tip_hash=tip_hash, hist_hash=hist_hash, helper=self.helper,
            timeout=180,
        )
        self.log.info("Cache miss replay: PASSED")

    def test_sync_leafset_and_header(self):
        """A3/A4: sync peer requests leafset, header, and UTXOs; leafset matches helper."""
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        peer = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, include_header=True, page_size=16),
            services=MWEB_LIGHT_CLIENT_SERVICES,
        )
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and peer.pages_received == 0:
            peer.send_next_sync_step()
            time.sleep(0.05)
        assert_greater_than(peer.pages_received, 0)
        with p2p_lock:
            assert anchor in peer.merkle_blocks_with_mweb
            assert_equal(peer.merkle_blocks_with_mweb[anchor].mweb_header,
                         get_mweb_header(self.helper, anchor))
        victim.disconnect_p2ps()
        victim_leafset = fetch_mweb_leafset(victim, anchor)
        helper_leafset = fetch_mweb_leafset(self.helper, anchor)
        assert_equal(victim_leafset, helper_leafset)
        self.log.info("Sync leafset+header: PASSED")

    def test_full_pagination(self):
        """A6: one sync peer paginates entire UTXO set vs helper count."""
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        helper_count = paginate_mweb_utxos(self.helper, anchor, page_size=4096, max_pages=200)
        sync_peer = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, page_size=4096),
            services=MWEB_LIGHT_CLIENT_SERVICES,
        )
        # Large UTXO sets need more than one MEGA_WAIT_MEDIUM window.
        deadline = time.monotonic() + max(30.0, helper_count / 200.0)
        while time.monotonic() < deadline and not sync_peer._done:
            sync_peer.send_next_sync_step()
            time.sleep(0.02)
        assert_greater_than(sync_peer.total_utxos, 0)
        assert_equal(sync_peer.total_utxos, helper_count)
        victim.disconnect_p2ps()
        self.log.info("Full pagination (%d utxos): PASSED", helper_count)

    def refresh_serve_tip(self, victim):
        generate(victim, 1)
        return victim.getbestblockhash()

    def test_max_num_requested_valid(self):
        """A7: valid num_requested=4096 from sync peer."""
        victim = self.victim
        anchor = self.refresh_serve_tip(victim)
        peer = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(anchor, start_index=first_unspent_mweb_leaf(victim, anchor), num_requested=4096)
        peer.wait_for_mwebutxos(anchor, timeout=MEGA_WAIT_MEDIUM)
        assert peer.is_connected
        victim.disconnect_p2ps()
        self.log.info("Max num_requested valid: PASSED")

    def test_per_peer_queue_cap(self):
        """A8: burst exceeds per-peer queue; victim stays alive."""
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        peer = victim.add_p2p_connection(
            MWEBAbusePeer(anchor, first_unspent_mweb_leaf(victim, anchor), num_requested=16),
            services=MWEB_LIGHT_CLIENT_SERVICES)
        for _ in range(MAX_MWEB_SERVE_JOBS_PER_PEER + 4):
            peer.send_abuse_request()
        time.sleep(0.5)
        benign = victim.add_p2p_connection(BenignProbePeer())
        benign.send_ping_probe()
        benign.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        assert benign.is_connected
        victim.disconnect_p2ps()
        self.log.info("Per-peer queue cap: PASSED")

    def test_global_queue_cap(self):
        """A9: global request burst preserves liveness; unit u15 checks the exact cap."""
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        anchor_leaf = first_unspent_mweb_leaf(victim, anchor)
        peers = []
        n_peers = MAX_MWEB_SERVE_JOBS_GLOBAL + 8
        for _ in range(n_peers):
            p = victim.add_p2p_connection(
                MWEBAbusePeer(anchor, anchor_leaf, num_requested=8),
                services=MWEB_LIGHT_CLIENT_SERVICES,
                wait_for_verack=False,
            )
            p.wait_for_verack()
            peers.append(p)
        for p in peers:
            p.send_abuse_request()
        time.sleep(0.5)
        benign = victim.add_p2p_connection(BenignProbePeer())
        benign.send_ping_probe()
        benign.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        assert benign.is_connected
        victim.disconnect_p2ps()
        self.log.info("Global queue cap: PASSED")

    def test_tx_relay_under_load(self):
        """B4: tx inv/getdata during MWEB load."""
        from test_framework.mweb_density_util import FUNDER_WALLET_NAME
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        anchor_leaf = first_unspent_mweb_leaf(victim, anchor)
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 0)
        generate(self.helper, 1)
        tx_peer = victim.add_p2p_connection(TxInvPeer())
        funder = self.helper.get_wallet_rpc(FUNDER_WALLET_NAME)
        txid = funder.sendtoaddress(funder.getnewaddress(), 0.01)
        self.wait_until(lambda: txid in victim.getrawmempool(), timeout=MEGA_WAIT_MEDIUM)
        raw = funder.getrawtransaction(txid)
        from test_framework.messages import FromHex, CTransaction
        tx = FromHex(CTransaction(), raw)
        # Inbound announcements trickle out on a Poisson timer (5 s mean).
        tx_peer.wait_until(lambda: tx.wtxid_int in tx_peer.announced, timeout=MEGA_WAIT_SYNC)
        abuse = victim.add_p2p_connection(
            MWEBAbusePeer(anchor, anchor_leaf), services=MWEB_LIGHT_CLIENT_SERVICES)
        stop = threading.Event()
        t = threading.Thread(target=run_abuse_loop, args=([abuse], stop, 20), daemon=True)
        t.start()
        try:
            self.wait_until(lambda: abuse.responses_received > 0, timeout=MEGA_WAIT_MEDIUM)
            tx_peer.announce_and_request(tx)
            tx_peer.wait_until(lambda: tx_peer.received, timeout=MEGA_WAIT_MEDIUM)
        finally:
            stop.set()
            t.join(timeout=MEGA_WAIT_SHORT)
        assert not t.is_alive()
        victim.disconnect_p2ps()
        self.log.info("Tx relay under load: PASSED")

    def test_compact_block_under_load(self):
        """B5: compact block v3 negotiation during load."""
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        anchor_leaf = first_unspent_mweb_leaf(victim, anchor)
        abuse = victim.add_p2p_connection(
            MWEBAbusePeer(anchor, anchor_leaf), services=MWEB_LIGHT_CLIENT_SERVICES)
        stop = threading.Event()
        t = threading.Thread(target=run_abuse_loop, args=([abuse], stop, 20), daemon=True)
        t.start()
        try:
            self.wait_until(lambda: abuse.responses_received > 0, timeout=MEGA_WAIT_MEDIUM)
            cmpct = victim.add_p2p_connection(
                CompactMWEBPeer(), services=NODE_NETWORK | NODE_WITNESS | NODE_MWEB)
            cmpct.wait_until(lambda: 3 in cmpct.last_sendcmpct, timeout=MEGA_WAIT_SHORT)
            cmpct.send_and_ping(msg_sendcmpct(announce=True, version=3))
        finally:
            stop.set()
            t.join(timeout=MEGA_WAIT_SHORT)
        assert not t.is_alive()
        victim.disconnect_p2ps()
        self.log.info("Compact block under load: PASSED")

    def test_reorg_during_serve(self):
        """§7.7 E1: reorg during sync serve — no crash; new tip serves; stale tip ignored."""
        from test_framework.messages import Hash

        victim = self.victim
        cfg = MEGA_SCALE_CONFIG[self.options.mweb_mega_scale]
        anchor = self.stable_anchor_hash(victim)
        peer = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, page_size=32), services=MWEB_LIGHT_CLIENT_SERVICES)
        tip = victim.getbestblockhash()
        tip_leaf = first_unspent_mweb_leaf(victim, tip)
        peer.send_next_sync_step()
        peer.wait_for_mwebleafset(anchor)
        peer.send_next_sync_step()
        victim.invalidateblock(tip)
        # Two blocks so the replacement fork has more work than the stale tip.
        victim.generatetoaddress(nblocks=2, address=victim.getnewaddress(), called_by_framework=True)
        victim.reconsiderblock(tip)
        time.sleep(0.5)
        peer.send_next_sync_step()
        assert peer.is_connected or peer.pages_received > 0
        victim.disconnect_p2ps()
        new_tip = victim.getbestblockhash()
        assert new_tip != tip
        assert_mweb_serve_parity(self, victim, new_tip, min_utxos=cfg['min_mweb_utxos'])
        stale_peer = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        stale_peer.request_mweb_utxos(tip, start_index=tip_leaf, num_requested=1)
        stale_peer.sync_with_ping(timeout=MEGA_WAIT_SHORT)
        with p2p_lock:
            assert Hash.from_hex(tip) not in stale_peer.mwebutxos
            assert stale_peer.is_connected
        victim.disconnect_p2ps()
        self.chain_meta['tip_hash'] = new_tip
        self.log.info("Reorg during serve: PASSED")

    def test_mid_sync_disconnect_resume(self):
        """E2: disconnect sync peer mid-pagination; reconnect resumes."""
        victim = self.victim
        generate(victim, 1)
        anchor = victim.getbestblockhash()
        peer = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, page_size=32), services=MWEB_LIGHT_CLIENT_SERVICES)
        deadline = time.monotonic() + MEGA_WAIT_MEDIUM
        while time.monotonic() < deadline and peer.pages_received == 0:
            peer.send_next_sync_step()
            time.sleep(0.05)
        assert_greater_than(peer.pages_received, 0)
        saved_index = peer.start_index
        peer.peer_disconnect()
        peer2 = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, start_index=saved_index, page_size=32),
            services=MWEB_LIGHT_CLIENT_SERVICES,
        )
        deadline = time.monotonic() + MEGA_WAIT_MEDIUM
        while time.monotonic() < deadline and peer2.pages_received == 0:
            peer2.send_next_sync_step()
            time.sleep(0.05)
        assert_greater_than(peer2.pages_received, 0)
        victim.disconnect_p2ps()
        self.log.info("Mid-sync disconnect resume: PASSED")

    def test_sendbuffer_pressure(self):
        """E3: a page exceeds the send-buffer threshold; complete sync recovers."""
        victim = self.victim
        # -maxsendbuffer is in kilobytes, not bytes. The old 5,000-KB setting
        # with a 16-item page never approached the configured threshold.
        self.restart_node(0, extra_args=[*mweb_extra_args(['-maxsendbuffer=5'])[0]])
        self.victim = self.nodes[0]
        victim = self.victim
        anchor = self.stable_anchor_hash(victim)
        peer = victim.add_p2p_connection(
            MWEBSyncPeer(anchor, page_size=4096), services=MWEB_LIGHT_CLIENT_SERVICES)
        deadline = time.monotonic() + MEGA_WAIT_SYNC
        while time.monotonic() < deadline and not peer._done:
            peer.send_next_sync_step()
            time.sleep(0.05)
        assert peer._done
        expected = len(mweb_unspent_leaves(fetch_mweb_leafset(self.helper, anchor)))
        assert_equal(peer.total_utxos, expected)
        with p2p_lock:
            message = peer.mwebutxos[Hash.from_hex(anchor)]
            assert_greater_than(len(message.serialize()), 5 * 1000)
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("Send buffer pressure: PASSED")

    def test_l1_eviction_under_serve(self):
        """L1: serve at tip-10 in flight while tip advances — response completes."""
        victim = self.victim
        _, hist_hash = shared_historical_anchor(victim, self.helper, offset=10)
        peer = victim.add_p2p_connection(
            SlowMWEBPeer(hist_hash, first_unspent_mweb_leaf(self.helper, hist_hash)),
            services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.send_serve_request()
        time.sleep(1)
        for _ in range(11):
            generate(victim, 1)
            time.sleep(0.05)
        peer.wait_for_mwebutxos(hist_hash, timeout=180)
        msg = peer.mwebutxos[Hash.from_hex(hist_hash)]
        assert_segment_matches_helper(self.helper, msg, hist_hash, timeout=180)
        victim.disconnect_p2ps()
        self.log.info("L1 eviction under serve: PASSED")

    def test_l2_multi_peer_eviction_under_mine(self):
        """L2: many peers at tip-10 while victim mines continuously."""
        victim = self.victim
        _, hist_hash = shared_historical_anchor(victim, self.helper, offset=10)
        hist_leaf = first_unspent_mweb_leaf(self.helper, hist_hash, timeout=180)
        helper_msg = fetch_mweb_utxo_page(
            self.helper, hist_hash, start_index=hist_leaf, num_requested=64, timeout=180)
        n_peers = 8
        peers = []
        for _ in range(n_peers):
            p = victim.add_p2p_connection(
                MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
            p.request_mweb_utxos(hist_hash, start_index=hist_leaf, num_requested=64)
            peers.append(p)
        time.sleep(1)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            generate(victim, 1)
            time.sleep(0.5)
        for p in peers:
            p.wait_for_mwebutxos(hist_hash, timeout=180)
            msg = p.mwebutxos[Hash.from_hex(hist_hash)]
            assert_greater_than(len(msg.utxos), 0)
            for i in range(min(len(msg.utxos), len(helper_msg.utxos))):
                assert_equal(msg.utxos[i].leaf_index, helper_msg.utxos[i].leaf_index)
                assert_equal(msg.utxos[i].output, helper_msg.utxos[i].output)
        victim.disconnect_p2ps()
        self.log.info("L2 multi-peer eviction under mine: PASSED")

    def test_h1_warm_cache_no_replay(self):
        """H1: warm-cache tip flood must not trigger replay steps."""
        victim = self.victim
        extra = [*mweb_extra_args(['-debug=net'])[0]]
        self.restart_node(0, extra_args=extra)
        self.victim = self.nodes[0]
        victim = self.victim
        tip_hash = victim.getbestblockhash()
        tip_leaf = first_unspent_mweb_leaf(victim, tip_hash)
        warm = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        warm.request_mweb_utxos(tip_hash, tip_leaf)
        warm.wait_for_mwebutxos(tip_hash)
        victim.disconnect_p2ps()
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.mark_log_end()
        flood = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        for _ in range(100):
            flood.request_mweb_utxos(tip_hash, tip_leaf, num_requested=1)
        flood.wait_until(lambda: flood.responses_received > 0, timeout=MEGA_WAIT_MEDIUM)
        replay_steps = stats.replay_steps_since()
        self.log.info("H1 warm flood replay steps=%d", replay_steps)
        assert_equal(replay_steps, 0)
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("H1 warm cache no replay: PASSED")

    def test_s1_tip_pagination_floor(self):
        """S1: strict pagination floor at mega tip."""
        assert_serve_pagination_floor(
            self, self.victim, self.victim.getbestblockhash(), helper=self.helper)
        self.log.info("S1 tip pagination floor: PASSED")

    def test_s2_restart_historical_floor(self):
        """S2: after restart, serve at tip-10 meets strict floor."""
        victim = self.victim
        tip_height = victim.getblockcount()
        hist_height = max(FIRST_MWEB_HEIGHT, tip_height - 10)
        hist_hash = victim.getblockhash(hist_height)
        restart_mega_node(self, victim, reindex_chainstate=True)
        self.victim = self.nodes[0]
        assert_serve_pagination_floor(self, self.victim, hist_hash, helper=self.helper)
        self.log.info("S2 restart historical floor: PASSED")

    def test_s3_random_segment_fingerprint(self):
        """S3: random pages at tip/tip-5/tip-10 match helper."""
        assert_random_segments_match_helper(
            self, self.victim, self.helper,
            depths=[0, 5, 10], samples=5,
        )
        self.log.info("S3 random segment fingerprint: PASSED")

    def test_materialize_budget(self):
        """T-09/T-17: cold miss uses chunked materialize within per-turn budget."""
        victim = self.victim
        hist_height = max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 10)
        hist_hash = victim.getblockhash(hist_height)
        hist_leaf = first_unspent_mweb_leaf(victim, hist_hash, timeout=180)
        restart_mega_node(self, victim, extra_args=[*mweb_extra_args(['-debug=net'])[0]])
        self.victim = self.nodes[0]
        victim = self.victim
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.mark_log_end()
        peer = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(hist_hash, hist_leaf)
        peer.wait_for_mwebutxos(hist_hash, timeout=180)
        time.sleep(0.5)  # debug.log may lag the P2P response
        chunk_ns = stats.materialize_chunk_ns_since()
        replay_steps = stats.replay_steps_since()
        cache_misses = stats.cache_misses_since()
        self.log.info("T-09 materialize chunks=%d replay_steps=%d cache_misses=%d",
                      len(chunk_ns), replay_steps, cache_misses)
        assert_greater_than(cache_misses, 0)
        assert_greater_than(replay_steps, 0)
        assert_greater_than(len(chunk_ns), 0)
        sorted_ns = sorted(chunk_ns)
        p95 = sorted_ns[int(0.95 * (len(sorted_ns) - 1))]
        assert p95 < MEGA_MATERIALIZE_P95_MAX_NS, f"materialize p95 {p95}ns exceeds budget"
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("T-09 materialize budget: PASSED")

    def test_i14_dedup(self):
        """T-10: 8 peers on same cold hash share one coordinator replay chain."""
        victim = self.victim
        hist_height = max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 10)
        hist_hash = victim.getblockhash(hist_height)
        hist_leaf = first_unspent_mweb_leaf(victim, hist_hash, timeout=180)
        restart_mega_node(self, victim, extra_args=[*mweb_extra_args(['-debug=net'])[0]])
        self.victim = self.nodes[0]
        victim = self.victim
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.mark_log_end()
        peers = [
            victim.add_p2p_connection(MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
            for _ in range(8)
        ]
        for peer in peers:
            peer.request_mweb_utxos(hist_hash, hist_leaf)
        for peer in peers:
            peer.wait_for_mwebutxos(hist_hash, timeout=180)
        replay_steps = stats.replay_steps_since()
        self.log.info("T-10 I14 replay steps with 8 peers=%d", replay_steps)
        assert 0 < replay_steps <= 10, f"I14 expected one ten-block replay, got {replay_steps}"
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("T-10 I14 dedup: PASSED")

    def test_i8_distinct_historical_jobs(self):
        """I8: distinct cold historical jobs complete; unit u24 proves lock exclusion."""
        victim = self.victim
        hist_height = max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 10)
        hist_hash = victim.getblockhash(hist_height)
        hist_leaf = first_unspent_mweb_leaf(victim, hist_hash, timeout=180)
        other_hash = victim.getblockhash(hist_height + 1)
        other_leaf = first_unspent_mweb_leaf(victim, other_hash, timeout=180)
        restart_mega_node(self, victim, extra_args=[*mweb_extra_args(['-debug=net'])[0]])
        self.victim = self.nodes[0]
        victim = self.victim
        stats = MWEBServeLogStats(victim.debug_log_path)
        stats.mark_log_end()
        p1 = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        p2 = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        p1.request_mweb_utxos(hist_hash, hist_leaf)
        p2.request_mweb_utxos(other_hash, other_leaf)
        p1.wait_for_mwebutxos(hist_hash, timeout=180)
        p2.wait_for_mwebutxos(other_hash, timeout=180)
        steps = stats.replay_steps_since()
        self.log.info("I8 replay steps with dual cold miss=%d", steps)
        assert_greater_than(steps, 1)
        for peer, anchor in ((p1, hist_hash), (p2, other_hash)):
            assert_segment_matches_helper(self.helper, peer.mwebutxos[Hash.from_hex(anchor)], anchor)
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("I8 distinct historical jobs: PASSED")

    def test_i10_fullnode_ungated(self):
        """I10: full-node block fetch during serve; B4/B5 cover tx/compact negotiation."""
        victim = self.victim
        tip_hash = victim.getbestblockhash()
        sync_peer = victim.add_p2p_connection(
            MWEBSyncPeer(tip_hash, page_size=32), services=MWEB_LIGHT_CLIENT_SERVICES)
        fetch_peer = victim.add_p2p_connection(
            BlockFetchPeer(tip_hash), wait_for_verack=False)
        fetch_peer.wait_for_verack()
        fetch_peer.request_tip_block()
        deadline = time.monotonic() + MEGA_WAIT_MEDIUM
        while time.monotonic() < deadline and sync_peer.pages_received == 0:
            sync_peer.send_next_sync_step()
            time.sleep(0.05)
        fetch_peer.wait_until(lambda: fetch_peer.received, timeout=MEGA_WAIT_MEDIUM)
        assert_greater_than(sync_peer.pages_received, 0)
        victim.disconnect_p2ps()
        self.log.info("I10 full-node ungated: PASSED")

    def test_e1_internal_fault_no_ban(self):
        """§9 E1 (I9): injected internal fault must not ban peer."""
        victim = self.victim
        tip_hash = victim.getbestblockhash()
        extra = [*mweb_extra_args(['-debug=net', '-mwebserveinjectbadcache=1'])[0]]
        self.restart_node(0, extra_args=extra)
        self.victim = self.nodes[0]
        victim = self.victim
        peer = victim.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, start_index=0, num_requested=1)
        time.sleep(2)
        assert peer.is_connected, "Peer banned/disconnected on internal node fault"
        assert_equal(max_peer_misbehaving_score(victim), 0)
        stats = MWEBServeLogStats(victim.debug_log_path)
        assert_greater_than(stats.internal_errors_since(reset_offset=True), 0)
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])
        self.victim = self.nodes[0]
        self.log.info("E1 internal fault no ban: PASSED")

    def run_test(self):
        scale = self.options.mweb_mega_scale
        self.log.info("=== MWEB P2P stress mega (scale=%s) ===", scale)
        self.setup_mega_topology()

        self.log.info("--- Matrix subtests (pre-load) ---")
        self.test_invalid_peer_disconnect()
        self.test_c4_pre_mweb_disconnect()
        self.test_sync_depth_variants()
        self.test_sync_leafset_and_header()
        self.test_cache_miss_replay()
        self.test_full_pagination()
        self.test_max_num_requested_valid()
        self.test_per_peer_queue_cap()

        self.log.info("--- Core concurrent abuse + sync ---")
        self.run_concurrent_abuse_and_sync()
        realign_victim_to_helper(self, self.victim, self.helper)
        restart_mega_node(self, self.victim)
        self.victim = self.nodes[0]
        self.chain_meta['tip_hash'] = self.victim.getbestblockhash()
        self.chain_meta['tip_height'] = self.victim.getblockcount()

        self.log.info("--- Matrix subtests (post-load) ---")
        self.test_tx_relay_under_load()
        self.test_compact_block_under_load()
        self.test_mid_sync_disconnect_resume()
        self.test_reorg_during_serve()
        self.test_global_queue_cap()
        self.test_sendbuffer_pressure()

        realign_victim_to_helper(self, self.victim, self.helper)
        self.chain_meta['tip_hash'] = self.victim.getbestblockhash()

        self.log.info("--- §9 L/H/S/I/E coverage ---")
        self.test_l1_eviction_under_serve()
        realign_victim_to_helper(self, self.victim, self.helper)
        self.test_l2_multi_peer_eviction_under_mine()
        realign_victim_to_helper(self, self.victim, self.helper)
        self.test_h1_warm_cache_no_replay()
        self.test_s1_tip_pagination_floor()
        self.test_s2_restart_historical_floor()
        self.test_s3_random_segment_fingerprint()
        self.test_materialize_budget()
        self.test_i14_dedup()
        self.test_i8_distinct_historical_jobs()
        self.test_i10_fullnode_ungated()
        self.test_e1_internal_fault_no_ban()

        self.log.info("=== MWEB P2P stress mega: ALL PASSED (scale=%s) ===", scale)


if __name__ == '__main__':
    MWEBP2PStressMegaTest(__file__).main()
