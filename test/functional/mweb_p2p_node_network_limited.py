#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""NODE_NETWORK_LIMITED on a chain with MWEB active.

Tests that a node configured with -prune=550 signals the MWEB services along
with NODE_NETWORK_LIMITED, and that it serves MWEB blocks within the same
limits as other blocks:
    - send an MWEB block (MSG_MWEB_BLOCK), with its MWEB data, within 288 + 2 of the tip
    - disconnect peers who request an MWEB block older than that
    - the same for MWEB headers (MSG_MWEB_HEADER)
    - a node close to the tip downloads MWEB blocks from it, but no historical ones.

The chain up to and past MWEB activation comes from the precomputed fixture
(load_mweb_fixture), so no wallet is needed.
"""
from test_framework.messages import (
    CInv,
    MSG_MWEB_BLOCK,
    MSG_MWEB_HEADER,
    NODE_MWEB,
    NODE_MWEB_LIGHT_CLIENT,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
    NODE_WITNESS,
    msg_getdata,
)
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, load_mweb_fixture, mweb_extra_args
from test_framework.p2p import P2P_SERVICES_MWEB, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    try_rpc,
)

# Minimum blocks required to signal NODE_NETWORK_LIMITED #
NODE_NETWORK_LIMITED_MIN_BLOCKS = 288


class P2PIgnoreInv(P2PInterface):
    def on_inv(self, message):
        # The node will send us invs for other blocks. Ignore them.
        pass

    def send_getdata_for_mweb_block(self, blockhash):
        self.send_without_ping(msg_getdata([CInv(MSG_MWEB_BLOCK, int(blockhash, 16))]))

    def send_getdata_for_mweb_header(self, blockhash):
        self.send_without_ping(msg_getdata([CInv(MSG_MWEB_HEADER, int(blockhash, 16))]))


class MWEBNodeNetworkLimitedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(['-prune=550'], [], [])

    def disconnect_all(self):
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def assert_same_mweb_block(self, node, reference, block_hash):
        assert_equal(node.getblock(block_hash)["mweb_header"], reference.getblock(block_hash)["mweb_header"])

    def test_avoid_requesting_historical_blocks(self):
        self.log.info("Test full node does not request MWEB blocks beyond the limited peer threshold")
        pruned_node = self.nodes[0]
        miner = self.nodes[1]
        full_node = self.nodes[2]

        # Connect and generate block to ensure IBD=false
        self.connect_nodes(1, 0)
        self.connect_nodes(1, 2)
        self.generate(miner, 1)

        # Verify peers are out of IBD
        for node in self.nodes:
            assert not node.getblockchaininfo()['initialblockdownload']

        # Isolate full_node (the node will remain out of IBD)
        full_node.setnetworkactive(False)
        self.wait_until(lambda: len(full_node.getpeerinfo()) == 0)

        # Mine blocks and sync the pruned node. Surpass the NETWORK_NODE_LIMITED threshold.
        # Blocks deeper than the threshold are considered "historical blocks"
        num_historial_blocks = 12
        self.generate(miner, NODE_NETWORK_LIMITED_MIN_BLOCKS + num_historial_blocks, sync_fun=self.no_op)
        self.sync_blocks([miner, pruned_node])

        # Connect full_node to prune_node and check peers don't disconnect right away.
        # (they will disconnect if full_node, which is chain-wise behind, request blocks
        # older than NODE_NETWORK_LIMITED_MIN_BLOCKS)
        start_height_full_node = full_node.getblockcount()
        full_node.setnetworkactive(True)
        self.connect_nodes(2, 0)
        assert_equal(len(full_node.getpeerinfo()), 1)

        # Wait until the full_node is headers-wise sync
        best_block_hash = pruned_node.getbestblockhash()
        default_value = {'status': ''}  # No status
        self.wait_until(lambda: next(filter(lambda x: x['hash'] == best_block_hash, full_node.getchaintips()), default_value)['status'] == "headers-only")

        # The full node downloads the blocks within the threshold (with a
        # 2-block buffer), MWEB data included, and no historical block.
        tip_height = pruned_node.getblockcount()
        limit_buffer = 2
        # Prevent races by waiting for the tip to arrive first
        self.wait_until(lambda: not try_rpc(-1, "Block not available (not fully downloaded)", full_node.getblock, pruned_node.getbestblockhash()))
        for height in range(start_height_full_node + 1, tip_height + 1):
            block_hash = pruned_node.getblockhash(height)
            if height <= tip_height - (NODE_NETWORK_LIMITED_MIN_BLOCKS - limit_buffer):
                assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", full_node.getblock, block_hash)
            else:
                self.assert_same_mweb_block(full_node, pruned_node, block_hash)

        # Lastly, ensure the full_node is not sync and verify it can get synced by
        # establishing a connection with another full node capable of providing them.
        assert_equal(full_node.getblockcount(), start_height_full_node)
        self.connect_nodes(2, 1)
        self.sync_blocks([miner, full_node])
        self.assert_same_mweb_block(full_node, miner, miner.getbestblockhash())

    def run_test(self):
        pruned_node, miner, full_node = self.nodes
        fixture = load_mweb_fixture(self, miner)
        # The fixture's blocks are dated at its mock time; nodes running on the
        # real clock would see them as stale and stay in IBD.
        pruned_node.setmocktime(fixture["mocktime"])
        full_node.setmocktime(fixture["mocktime"])

        node = pruned_node.add_p2p_connection(P2PIgnoreInv(), services=P2P_SERVICES_MWEB)

        expected_services = NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_MWEB | NODE_MWEB_LIGHT_CLIENT
        if self.options.v2transport:
            expected_services |= NODE_P2P_V2

        self.log.info("Check that node has signalled expected services.")
        assert_equal(node.nServices, expected_services)

        self.log.info("Check that the localservices is as expected.")
        assert_equal(int(pruned_node.getnetworkinfo()['localservices'], 16), expected_services)

        self.log.info("Mine enough MWEB blocks to reach the NODE_NETWORK_LIMITED range.")
        self.connect_nodes(0, 1)
        blocks = self.generate(miner, 292, sync_fun=lambda: self.sync_blocks([pruned_node, miner]))
        assert_greater_than(pruned_node.getblockheader(blocks[0])['height'], FIRST_MWEB_HEIGHT)

        self.log.info("Make sure we can max retrieve MWEB block at tip-288, with its MWEB data.")
        node.send_getdata_for_mweb_block(blocks[1])  # last block in valid range
        node.wait_for_block(int(blocks[1], 16), timeout=3)
        with p2p_lock:
            block = node.last_message["block"].block
        assert block.mweb_block is not None
        assert block.vtx[-1].hogex

        self.log.info("Requesting MWEB block at tip-289 must fail (ignored).")
        node.send_getdata_for_mweb_block(blocks[0])  # first block outside of the 288+2 limit
        node.wait_for_disconnect(timeout=5)

        self.log.info("MWEB headers follow the same limit: served at tip-288, disconnect at tip-289.")
        header_peer = pruned_node.add_p2p_connection(P2PIgnoreInv(), services=P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT)
        header_peer.send_getdata_for_mweb_header(blocks[1])
        header_peer.wait_for_mwebheader(blocks[1], timeout=10)
        header_peer.send_getdata_for_mweb_header(blocks[0])
        header_peer.wait_for_disconnect(timeout=5)
        pruned_node.disconnect_p2ps()

        # connect unsynced node 2 with pruned NODE_NETWORK_LIMITED peer
        # because node 2 is in IBD and node 0 is a NODE_NETWORK_LIMITED peer, sync must not be possible
        self.connect_nodes(0, 2)
        try:
            self.sync_blocks([pruned_node, full_node], timeout=5)
        except Exception:
            pass
        # node2 must remain at height 0
        assert_equal(full_node.getblockheader(full_node.getbestblockhash())['height'], 0)

        # now connect also to node 1 (non pruned)
        self.connect_nodes(1, 2)

        # sync must be possible
        self.sync_blocks()
        self.assert_same_mweb_block(full_node, miner, miner.getblockhash(FIRST_MWEB_HEIGHT))
        self.assert_same_mweb_block(full_node, miner, miner.getbestblockhash())

        # disconnect all peers
        self.disconnect_all()

        # mine 10 MWEB blocks on node 0 (pruned node)
        self.generate(pruned_node, 10, sync_fun=self.no_op)

        # connect node1 (non pruned) with node0 (pruned) and check if the can sync
        self.connect_nodes(0, 1)

        # sync must be possible, node 1 is no longer in IBD and should therefore connect to node 0 (NODE_NETWORK_LIMITED)
        self.sync_blocks([pruned_node, miner])
        self.assert_same_mweb_block(miner, pruned_node, pruned_node.getbestblockhash())

        self.test_avoid_requesting_historical_blocks()


if __name__ == '__main__':
    MWEBNodeNetworkLimitedTest(__file__).main()
