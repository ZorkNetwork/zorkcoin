#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB AssumeUTXO loadtxoutset fetches the snapshot-base block out of order.

Headers of the snapshot base are required. Parent block bodies 1…N-1 are not.
If the base body is missing, loadtxoutset requests MSG_MWEB_BLOCK from a
NODE_MWEB peer rather than waiting for IBD to height N.
"""

from test_framework.assumeutxo_util import (
    ASSUMEUTXO_BASE_HEIGHT,
    build_assumeutxo_base_chain,
)
from test_framework.messages import (
    CBlock,
    MSG_MWEB_FLAG,
    from_hex,
    msg_block,
    msg_no_mweb_block,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SERVICES_MWEB,
    p2p_lock,
)
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
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

ASSUMEUTXO_PRE_EXTENSION_HEIGHT = 399


class MWEBSnapshotBlockPeer(P2PInterface):
    """Serve only the snapshot-base block, with MWEB data iff GETDATA asked for it."""

    def __init__(self, block):
        super().__init__()
        self.block = block
        self.getdata_types = []

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_types.append(inv.type)
            if inv.hash != self.block.hash_int:
                continue
            if inv.type & MSG_MWEB_FLAG:
                self.send_without_ping(msg_block(self.block))
            else:
                self.send_without_ping(msg_no_mweb_block(self.block))


class FeatureAssumeutxoMwebFetchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 3
        self.rpc_timeout = 120
        self.extra_args = [
            with_assumeutxo_mweb_vbparams(['-debug=net']),
            with_assumeutxo_mweb_vbparams(['-debug=net']),
            with_assumeutxo_mweb_vbparams(['-debug=net']),
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def build_mweb_snapshot_chain(self, node):
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

    def submit_headers(self, dest, src, height):
        for h in range(1, height + 1):
            dest.submitheader(src.getblock(src.getblockhash(h), 0))

    def run_test(self):
        n0, n1, n2 = self.nodes

        self.log.info("Build MWEB AssumeUTXO chain on node0 through height %d", SNAPSHOT_BASE_MWEB)
        init_assumeutxo_mweb_wallet(self, node=0)
        self.build_mweb_snapshot_chain(n0)

        self.log.info("Dump MWEB UTXO snapshot at height %d", SNAPSHOT_BASE_MWEB)
        dump_output = n0.dumptxoutset('mweb_assumeutxo_fetch.dat', 'latest')
        assert_assumeutxo_mweb_dump(dump_output)
        snapshot_hash = dump_output['base_hash']
        snapshot_path = dump_output['path']
        snapshot_block = from_hex(CBlock(), n0.getblock(snapshot_hash, 0))
        assert snapshot_block.mweb_block is not None

        self.log.info("Headers-only node1: no NODE_MWEB peer, loadtxoutset must fail")
        self.submit_headers(n1, n0, SNAPSHOT_BASE_MWEB)
        assert_greater_than(SNAPSHOT_BASE_MWEB, n1.getblockcount())
        assert_raises_rpc_error(
            -1,
            "Block not available (not fully downloaded)",
            n1.getblock,
            snapshot_hash,
        )
        witness_peer = n1.add_p2p_connection(P2PInterface(), services=P2P_SERVICES)
        witness_peer.wait_for_verack()
        assert_raises_rpc_error(-1, "NODE_MWEB peer", n1.loadtxoutset, snapshot_path)
        n1.disconnect_p2ps()

        self.log.info("Headers-only node1: fetch the one MWEB base block, then load")
        height_before = n1.getblockcount()
        assert_greater_than(SNAPSHOT_BASE_MWEB, height_before)
        mweb_peer = n1.add_p2p_connection(
            MWEBSnapshotBlockPeer(snapshot_block),
            services=P2P_SERVICES_MWEB,
        )
        mweb_peer.wait_for_verack()
        n1._rpc = n1.create_new_rpc_connection(client_timeout=600)
        with n1.assert_debug_log(
            [f"Requesting block {snapshot_hash}", "(MWEB)"],
            unexpected_msgs=[],
        ):
            loaded = n1.loadtxoutset(snapshot_path)
        assert_equal(loaded['base_height'], SNAPSHOT_BASE_MWEB)
        assert_equal(loaded['tip_hash'], snapshot_hash)
        with p2p_lock:
            requested_mweb = any(inv_type & MSG_MWEB_FLAG for inv_type in mweb_peer.getdata_types)
        assert requested_mweb, "GETDATA for the snapshot base must include MSG_MWEB_FLAG"

        n1.getblock(snapshot_hash)
        parent_hash = n0.getblockhash(SNAPSHOT_BASE_MWEB - 1)
        assert_raises_rpc_error(
            -1,
            "Block not available (not fully downloaded)",
            n1.getblock,
            parent_hash,
        )
        chainstates = n1.getchainstates()['chainstates']
        assert_equal(len(chainstates), 2)
        assert_equal(chainstates[1]['blocks'], SNAPSHOT_BASE_MWEB)
        assert_equal(chainstates[1]['validated'], False)

        self.log.info("After load, sync further blocks from node0 past the snapshot")
        generate(n0, 10)
        n1.disconnect_p2ps()
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        assert_greater_than(n1.getblockcount(), SNAPSHOT_BASE_MWEB)
        n1.getblock(n0.getbestblockhash())

        self.log.info("node2 already has the base body: load without fetching")
        self.submit_headers(n2, n0, SNAPSHOT_BASE_MWEB)
        n2.submitblock(n0.getblock(snapshot_hash, 0))
        n2._rpc = n2.create_new_rpc_connection(client_timeout=600)
        with n2.assert_debug_log([], unexpected_msgs=["Requesting block"]):
            loaded2 = n2.loadtxoutset(snapshot_path)
        assert_equal(loaded2['base_height'], SNAPSHOT_BASE_MWEB)
        assert_equal(loaded2['tip_hash'], snapshot_hash)

        self.log.info("Restart node2 above the snapshot base, before background validation")
        # Five blocks above the base keep it within the default -checkblocks=6.
        # Startup block verification checks those blocks fully, then stops at
        # the base, which has data but no undo data.
        tip2 = SNAPSHOT_BASE_MWEB + 5
        for h in range(SNAPSHOT_BASE_MWEB + 1, tip2 + 1):
            assert_equal(n2.submitblock(n0.getblock(n0.getblockhash(h), 0)), None)
        with n2.assert_debug_log([f"Block verification stopping at height {SNAPSHOT_BASE_MWEB} (assumeutxo snapshot base, no undo data)"]):
            self.restart_node(2, extra_args=self.extra_args[2])
        chainstates2 = n2.getchainstates()['chainstates']
        assert_equal(len(chainstates2), 2)
        assert_equal(chainstates2[1]['blocks'], tip2)

        self.log.info("Background validation completes after the restart")
        n2.setmocktime(MWEB_VB_START_TIME)
        self.connect_nodes(0, 2)
        self.wait_until(lambda: len(n2.getchainstates()['chainstates']) == 1)
        self.sync_blocks([n0, n2])


if __name__ == '__main__':
    FeatureAssumeutxoMwebFetchTest(__file__).main()
