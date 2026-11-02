#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
MWEB P2P liveness stress (P-01) — quick and full scales.

Quick scale (~20 post-MWEB blocks, ~10s flood): extended CI gate.
Full scale (16_000+ post-MWEB blocks, 120s flood): manual release sign-off;
expect 30-90 minutes setup on typical hardware.
"""

from contextlib import contextmanager
import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    mweb_extra_args,
)
from test_framework.mweb_stress_util import (
    anchor_hashes_for_tip,
    BenignProbePeer,
    BlockFetchPeer,
    flood_victim,
    grow_mweb_chain,
    HeadersProbePeer,
    MAX_MWEB_LEAFSET_DEPTH,
    MWEBFloodPeer,
    MWEBInvalidPeer,
    MWEB_LIGHT_CLIENT_SERVICES,
)
from test_framework.mweb_stress_mega_util import first_unspent_mweb_leaf
from test_framework.util import assert_greater_than

QUICK_POST_MWEB_BLOCKS = 20
QUICK_FLOOD_ITERATIONS = 5
QUICK_ATTACKER_PEERS = 1
QUICK_FLOOD_RATE = 5

FULL_POST_MWEB_BLOCKS = 16_000
FULL_FLOOD_SECONDS = 120
FULL_ATTACKER_PEERS = 8
FULL_FLOOD_RATE = 20


class MWEBP2PStressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [mweb_extra_args([])[0], mweb_extra_args([])[0]]
        self.scale = 'quick'

    def add_options(self, parser):
        parser.add_argument(
            '--mweb-stress-scale',
            default='quick',
            choices=['quick', 'full'],
            help='Stress test scale (default: quick)',
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def anchor_leaves(self, anchors):
        """Fetch start leaves from the helper so the victim's historical cache stays cold."""
        self.sync_blocks()
        return {block_hash: first_unspent_mweb_leaf(self.nodes[1], block_hash) for block_hash in anchors}

    def setup_network(self):
        """Full scale keeps nodes isolated during helper chain growth."""
        self.setup_nodes()
        if self.options.mweb_stress_scale != 'full':
            for i in range(self.num_nodes - 1):
                self.connect_nodes(i + 1, i)
            self.sync_all()

    def activate_mweb_chain(self, node, post_blocks):
        """Reach MWEB activation, then extend the chain (quick path)."""
        target_pre_mweb = FIRST_MWEB_HEIGHT - 1
        self.log.info(
            "Setting up MWEB chain: generating blocks to height %d (this may take 1-2 minutes)...",
            target_pre_mweb,
        )
        while node.getblockcount() < target_pre_mweb:
            remaining = target_pre_mweb - node.getblockcount()
            batch = min(50, remaining)
            start_height = node.getblockcount() + 1
            end_height = node.getblockcount() + batch
            self.log.info("  generating blocks %d-%d of %d", start_height, end_height, target_pre_mweb)
            generate(node, batch)
        self.log.info("  pegging into MWEB and mining activation block at height %d", FIRST_MWEB_HEIGHT)
        node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)
        generate(node, 1)
        if post_blocks > 1:
            self.log.info("  extending chain by %d post-MWEB blocks", post_blocks - 1)
            generate(node, post_blocks - 1)
        self.log.info("MWEB chain ready at height %d", node.getblockcount())

    def setup_full_chain(self):
        """Helper node builds a long post-MWEB chain; victim syncs to tip."""
        helper = self.nodes[1]
        victim = self.nodes[0]
        self.log.info("Growing %d post-MWEB blocks on helper node", FULL_POST_MWEB_BLOCKS)
        grow_mweb_chain(
            self,
            helper,
            post_blocks=FULL_POST_MWEB_BLOCKS,
            wallets=16,
            pegin_interval=10,
            reconnect_peers=False,
        )
        tip_height = helper.getblockcount()
        self.log.info("Connecting victim to helper and syncing to height %d", tip_height)
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: victim.getblockcount() == tip_height and not victim.getblockchaininfo()['initialblockdownload'],
            timeout=3600,
        )
        self.log.info("Victim synced to height %d", victim.getblockcount())
        return victim, helper, tip_height

    @contextmanager
    def active_flood(self, peers, rate):
        stop = threading.Event()
        errors = []
        def run():
            try:
                flood_victim(peers, stop, rate)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            self.wait_until(lambda: sum(p.responses_received for p in peers) > 0, timeout=30)
            before = sum(p.requests_sent for p in peers)
            yield
            self.wait_until(lambda: sum(p.requests_sent for p in peers) > before, timeout=5)
        finally:
            stop.set()
            worker.join(timeout=10)
        assert not worker.is_alive()
        assert not errors, errors

    def run_liveness_flood(self, victim, tip_hash, anchors, *, flood_seconds=None, flood_iterations=None, attacker_count, flood_rate, mine_blocks=2, verify_p2p_block=True):
        self.log.info("=== Liveness flood: connect %d attacker peers ===", attacker_count)
        attackers = []
        # Keep anchors valid while mining advances the tip during the flood.
        anchors = [h for h in anchors if victim.getblockheader(h)['height'] + MAX_MWEB_LEAFSET_DEPTH
                   >= victim.getblockcount() + mine_blocks]
        leaves = self.anchor_leaves(anchors)
        for i in range(attacker_count):
            peer = victim.add_p2p_connection(
                MWEBFloodPeer(anchors, leaves),
                services=MWEB_LIGHT_CLIENT_SERVICES,
                wait_for_verack=False,
            )
            peer.wait_for_verack()
            attackers.append(peer)
            self.log.info("  attacker peer %d/%d ready", i + 1, attacker_count)

        benign = victim.add_p2p_connection(BenignProbePeer(), wait_for_verack=False)
        benign.wait_for_verack()
        headers_peer = None
        if verify_p2p_block:
            locator_height = max(FIRST_MWEB_HEIGHT, victim.getblockcount() - 20)
            locator = [int(victim.getblockhash(locator_height), 16)]
            headers_peer = victim.add_p2p_connection(
                HeadersProbePeer(locator), wait_for_verack=False)
            headers_peer.wait_for_verack()

        self.log.info("=== Liveness flood: invalid peer (expect disconnect) ===")
        stale_hash = victim.getblockhash(FIRST_MWEB_HEIGHT)
        deep_height = victim.getblockcount() - MAX_MWEB_LEAFSET_DEPTH - 1
        deep_hash = victim.getblockhash(deep_height) if deep_height >= FIRST_MWEB_HEIGHT else stale_hash
        invalid_peer = victim.add_p2p_connection(MWEBInvalidPeer(tip_hash, deep_hash))
        invalid_peer.send_next_mweb_request()
        invalid_peer.wait_for_disconnect(timeout=30)

        with self.active_flood(attackers, flood_rate):
            self.log.info("=== Liveness flood: mine %d blocks with peers connected ===", mine_blocks)
            mine_start = time.time()
            generate(victim, mine_blocks)
            mine_elapsed = time.time() - mine_start
            self.log.info(
                "Mined %d blocks in %.2fs; flood anchors through tip height %d",
                mine_blocks, mine_elapsed, victim.getblockcount(),
            )

            if flood_iterations is not None:
                self.log.info("=== Liveness flood: %d iterations ===", flood_iterations)
                for i in range(flood_iterations):
                    for peer in attackers:
                        if peer.is_connected:
                            peer.send_next_mweb_request()
                    if benign.is_connected:
                        benign.send_ping_probe()
                    time.sleep(0.2)
            else:
                self.log.info("=== Liveness flood: %ds at %d req/s per peer ===", flood_seconds, flood_rate)
                deadline = time.time() + flood_seconds
                last_log = time.time()
                while time.time() < deadline:
                    if benign.is_connected:
                        benign.send_ping_probe()
                    if time.time() - last_log >= 10:
                        remaining = int(deadline - time.time())
                        total_sent = sum(p.requests_sent for p in attackers)
                        total_recv = sum(p.responses_received for p in attackers)
                        self.log.info("  flood in progress: ~%ds left, %d requests sent, %d responses",
                                      remaining, total_sent, total_recv)
                        last_log = time.time()
                    time.sleep(0.2)

            assert benign.is_connected, "Benign probe peer disconnected during flood"
            benign.sync_with_ping(timeout=30)
            assert_greater_than(len(benign.rtts), 0)
            self.log.info("Benign ping p95: %.3fs", benign.rtt_p95())

            if verify_p2p_block:
                self.log.info("=== Liveness flood: verify headers + block fetch ===")
                new_tip_hash = victim.getbestblockhash()
                headers_peer.request_headers()
                headers_peer.wait_until(lambda: len(headers_peer.headers) > 0, timeout=30)
                fetch_peer = victim.add_p2p_connection(BlockFetchPeer(new_tip_hash), wait_for_verack=False)
                fetch_peer.wait_for_verack()
                fetch_peer.request_tip_block()
                fetch_peer.wait_until(lambda: fetch_peer.received, timeout=60)

        self.log.info("=== Liveness flood: cleanup ===")
        for p in list(victim.p2ps):
            p.peer_disconnect()
        victim.p2ps.clear()
        time.sleep(1)

        return benign, mine_elapsed

    def run_quick(self):
        node = self.nodes[0]
        self.log.info("=== Quick stress: chain setup ===")
        self.activate_mweb_chain(node, QUICK_POST_MWEB_BLOCKS)
        tip_hash = node.getbestblockhash()
        anchors = anchor_hashes_for_tip(node)
        self.log.info("=== Quick stress: invalid peer (expect disconnect) ===")

        deep_height = node.getblockcount() - MAX_MWEB_LEAFSET_DEPTH - 1
        deep_hash = node.getblockhash(deep_height) if deep_height >= FIRST_MWEB_HEIGHT else tip_hash
        invalid_peer = node.add_p2p_connection(MWEBInvalidPeer(tip_hash, deep_hash))
        invalid_peer.send_next_mweb_request()
        invalid_peer.wait_for_disconnect(timeout=30)
        self.log.info("Invalid peer disconnected as expected")

        anchors = [h for h in anchors if node.getblockheader(h)['height'] + MAX_MWEB_LEAFSET_DEPTH
                   >= node.getblockcount() + 2]
        self.log.info("=== Quick stress: connect peers (flood + benign) ===")
        flood_peer = node.add_p2p_connection(
            MWEBFloodPeer(anchors, self.anchor_leaves(anchors)),
            services=MWEB_LIGHT_CLIENT_SERVICES,
            wait_for_verack=False,
        )
        benign = node.add_p2p_connection(BenignProbePeer(), wait_for_verack=False)
        flood_peer.wait_for_verack()
        benign.wait_for_verack()
        self.log.info("Flood and benign peers connected (verack complete)")

        with self.active_flood([flood_peer], QUICK_FLOOD_RATE):
            self.log.info("=== Quick stress: mine 2 blocks with peers connected ===")
            mine_start = time.time()
            generate(node, 2)
            mine_elapsed = time.time() - mine_start
            self.log.info(
                "Mined 2 blocks in %.2fs; flood anchors through tip height %d",
                mine_elapsed, node.getblockcount(),
            )
            assert mine_elapsed < 30, "Mining stalled with MWEB peers connected (quick)"

            self.log.info("=== Quick stress: MWEB flood (%d iterations) + benign ping ===", QUICK_FLOOD_ITERATIONS)
            for i in range(QUICK_FLOOD_ITERATIONS):
                if not flood_peer.is_connected:
                    break
                flood_peer.send_next_mweb_request()
                if benign.is_connected:
                    benign.send_ping_probe()
                self.log.info("  flood request %d/%d sent", i + 1, QUICK_FLOOD_ITERATIONS)
                time.sleep(0.2)

            assert benign.is_connected, "Benign probe peer disconnected during flood"
            benign.sync_with_ping(timeout=30)
            assert_greater_than(len(benign.rtts), 0)
            self.log.info("Benign ping p95: %.3fs", benign.rtt_p95())
            assert benign.rtt_p95() < 10, "Benign ping p95 too high (quick)"

            self.log.info(
                "Waiting for MWEB responses (%d/%d received)...",
                flood_peer.responses_received,
                flood_peer.requests_sent,
            )
            self.wait_until(
                lambda: flood_peer.responses_received > 0,
                timeout=30,
            )
            self.log.info(
                "Received %d MWEB responses for %d requests",
                flood_peer.responses_received,
                flood_peer.requests_sent,
            )

        self.log.info("=== Quick stress: cleanup ===")
        node.disconnect_p2ps()
        self.log.info("=== Quick stress: PASSED ===")

    def run_full(self):
        victim, helper, tip_height = self.setup_full_chain()
        tip_hash = victim.getbestblockhash()
        anchors = anchor_hashes_for_tip(victim, tip_height)
        self.log.info("=== Full stress: liveness flood on synced victim ===")
        benign, mine_elapsed = self.run_liveness_flood(
            victim,
            tip_hash,
            anchors,
            flood_seconds=FULL_FLOOD_SECONDS,
            attacker_count=FULL_ATTACKER_PEERS,
            flood_rate=FULL_FLOOD_RATE,
            mine_blocks=3,
        )
        assert mine_elapsed < 120, "Mining stalled under MWEB flood (full)"
        if benign.rtts:
            assert benign.rtt_p95() < 5, "Benign ping p95 too high (full)"
        assert_greater_than(tip_height - FIRST_MWEB_HEIGHT, 1000)
        self.log.info("=== Full stress: PASSED ===")

    def run_test(self):
        self.scale = self.options.mweb_stress_scale
        self.log.info("Starting MWEB P2P stress test (scale=%s)", self.scale)
        if self.scale == 'full':
            self.run_full()
        else:
            self.run_quick()


if __name__ == '__main__':
    MWEBP2PStressTest(__file__).main()
