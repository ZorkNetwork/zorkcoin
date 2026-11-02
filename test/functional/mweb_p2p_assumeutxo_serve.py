#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""M3: MWEB P2P serve after AssumeUTXO snapshot activate (chunked warm + serve)."""

import re
import time

from test_framework.assumeutxo_util import (
    ASSUMEUTXO_BASE_HEIGHT,
    build_assumeutxo_base_chain,
)
from test_framework.messages import (
    Hash,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    NODE_MWEB_LIGHT_CLIENT,
    msg_getmwebutxos,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    ASSUMEUTXO_MWEB_BLOCKHASH,
    MWEB_VB_START_TIME,
    SNAPSHOT_BASE_MWEB,
    assert_assumeutxo_mweb_dump,
    finish_assumeutxo_mweb_chain,
    generate,
    init_assumeutxo_mweb_wallet,
    restart_node_for_mweb_extension,
    with_assumeutxo_mweb_vbparams,
)
from test_framework.mweb_stress_mega_util import (
    MEGA_WAIT_MEDIUM,
    MWEBServeLogStats,
    _mega_node_startup_timeout,
    fetch_mweb_leafset,
    fetch_mweb_utxo_page,
    paginate_mweb_utxos,
    verify_utxo_proofs,
)
from test_framework.util import assert_equal, assert_greater_than

ASSUMEUTXO_PRE_EXTENSION_HEIGHT = 399
MWEB_LIGHT_CLIENT_SERVICES = P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT

WARM_LOG = re.compile(r'MWEBHistoricalViewCache: warmed AssumeUTXO snapshot at height')


class MWEBLightClientPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.mwebutxos = {}

    def request_mweb_utxos(self, block_hash, start_index=0, num_requested=64):
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


class MWEBP2PAssumeUtxoServeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2
        self.extra_args = [
            with_assumeutxo_mweb_vbparams(['-debug=net', '-dbcache=512']),
            with_assumeutxo_mweb_vbparams(['-debug=net', '-dbcache=512']),
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def build_mweb_snapshot_chain(self, node):
        """Match mweb_generate_assumeutxo_hashes.py / feature_assumeutxo MWEB extension."""
        self.restart_node(0, extra_args=["-vbparams=mweb:-2:0"])
        build_assumeutxo_base_chain(self, node, sync_fun=self.no_op)
        restart_node_for_mweb_extension(self, node_index=0)
        node.setmocktime(MWEB_VB_START_TIME)
        self.generate(
            node,
            nblocks=ASSUMEUTXO_PRE_EXTENSION_HEIGHT - ASSUMEUTXO_BASE_HEIGHT,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), ASSUMEUTXO_PRE_EXTENSION_HEIGHT)
        self.restart_node(0, extra_args=["-vbparams=mweb:-2:0"])
        restart_node_for_mweb_extension(self, node_index=0)
        node.setmocktime(MWEB_VB_START_TIME)
        finish_assumeutxo_mweb_chain(self, node, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), SNAPSHOT_BASE_MWEB)
        assert_equal(node.getbestblockhash(), ASSUMEUTXO_MWEB_BLOCKHASH)

    def count_warm_log_lines(self, debug_log_path):
        try:
            with open(debug_log_path, encoding='utf-8', errors='ignore') as fh:
                return sum(1 for line in fh if WARM_LOG.search(line))
        except OSError:
            return 0

    def wait_ibd_cleared(self, node, *, min_height):
        """Wait for IBD latch to clear; mine if tip time is stale on cached chains."""

        def ibd_cleared():
            info = node.getblockchaininfo()
            if not info['initialblockdownload']:
                return True
            if info['blocks'] >= min_height:
                self.log.info(
                    "  node still in IBD at height %d; mining block to refresh tip time",
                    info['blocks'],
                )
                generate(node, 1)
            return not node.getblockchaininfo()['initialblockdownload']

        ibd_timeout = max(120, _mega_node_startup_timeout(min_height) // 4)
        self.wait_until(ibd_cleared, timeout=ibd_timeout, check_interval=2)

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        self.log.info("Build MWEB AssumeUTXO chain on node0 through height %d", SNAPSHOT_BASE_MWEB)
        init_assumeutxo_mweb_wallet(self, node=0)
        self.build_mweb_snapshot_chain(n0)

        self.log.info("Dump MWEB UTXO snapshot at height %d", SNAPSHOT_BASE_MWEB)
        dump_output = n0.dumptxoutset('mweb_assumeutxo_serve.dat', 'latest')
        assert_assumeutxo_mweb_dump(dump_output)
        snapshot_hash = dump_output['base_hash']
        snapshot_leafset = fetch_mweb_leafset(n0, snapshot_hash)
        helper_utxos = paginate_mweb_utxos(n0, snapshot_hash, page_size=256, max_pages=50, leafset=snapshot_leafset)
        assert_greater_than(helper_utxos, 0)

        self.log.info("Load snapshot on node1 and activate at height %d", SNAPSHOT_BASE_MWEB)
        warm_before = self.count_warm_log_lines(n1.debug_log_path)
        stats = MWEBServeLogStats(n1.debug_log_path)
        warm_steps_before = stats.assumeutxo_warm_steps_since(reset_offset=True)

        for height in range(1, SNAPSHOT_BASE_MWEB + 1):
            block = n0.getblock(n0.getblockhash(height), 0)
            n1.submitheader(block)
        # MWEB snapshot load reads the base block from disk to verify the extension header.
        n1.submitblock(n0.getblock(snapshot_hash, 0))
        time.sleep(0.5)
        n1._rpc = n1.create_new_rpc_connection(client_timeout=600)
        loaded = n1.loadtxoutset(dump_output['path'])
        assert_equal(loaded['base_height'], SNAPSHOT_BASE_MWEB)
        assert_equal(loaded['tip_hash'], snapshot_hash)

        self.wait_until(
            lambda: self.count_warm_log_lines(n1.debug_log_path) > warm_before,
            timeout=120,
            check_interval=0.5,
        )

        n1.setmocktime(MWEB_VB_START_TIME)
        self.connect_nodes(0, 1)
        self.sync_all()
        self.wait_ibd_cleared(n1, min_height=SNAPSHOT_BASE_MWEB)
        self.disconnect_nodes(0, 1)

        warm_after = self.count_warm_log_lines(n1.debug_log_path)
        warm_steps = stats.assumeutxo_warm_steps_since()
        self.log.info(
            "AssumeUTXO warm log lines: before=%d after=%d steps=%d",
            warm_before, warm_after, warm_steps,
        )
        assert_greater_than(warm_after, warm_before)
        assert_greater_than(warm_steps, warm_steps_before)
        assert_greater_than(warm_steps, 0)

        assert_equal(n1.getblockchaininfo()['initialblockdownload'], False)

        self.log.info("M3: serve at snapshot height after AssumeUTXO activate")
        stats.mark_log_end()
        peer = n1.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.wait_for_verack()
        victim_utxos = paginate_mweb_utxos(peer, snapshot_hash, page_size=256, max_pages=50, leafset=snapshot_leafset)
        self.log.info("Served %d UTXOs at snapshot height", victim_utxos)
        assert_greater_than(victim_utxos, 0)
        assert_greater_than(victim_utxos, helper_utxos // 2)
        snapshot_page = fetch_mweb_utxo_page(n1, snapshot_hash, num_requested=64)
        verify_utxo_proofs(self, n1, snapshot_hash, snapshot_page)

        replay_steps = stats.replay_steps_since(reset_offset=False)
        self.log.info("Replay steps after warm serve=%d", replay_steps)
        assert_equal(replay_steps, 0)

        self.log.info("Wait for AssumeUTXO background validation (spent LeafDB backfill)")
        self.connect_nodes(0, 1)
        self.wait_until(lambda: len(n1.getchainstates()["chainstates"]) == 1, timeout=900)
        self.log.info("Mine past snapshot tip and serve after backfill")
        generate(n0, 2)
        self.sync_all()
        tip = n1.getbestblockhash()
        peer2 = n1.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer2.wait_for_verack()
        tip_utxos = paginate_mweb_utxos(peer2, tip, page_size=256, max_pages=50, leafset=fetch_mweb_leafset(n0, tip))
        self.log.info("Served %d UTXOs at post-validation tip", tip_utxos)
        assert_greater_than(tip_utxos, 0)
        self.disconnect_nodes(0, 1)

        self.log.info("=== MWEB P2P AssumeUTXO serve (M3): PASSED ===")


if __name__ == '__main__':
    MWEBP2PAssumeUtxoServeTest(__file__).main()
