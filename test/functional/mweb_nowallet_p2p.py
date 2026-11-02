#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB block, compact block and transaction relay between nodes built without a wallet.

The chain and the MWEB transactions come from the precomputed fixture
(load_mweb_fixture).
"""

from test_framework.messages import (
    CInv,
    HeaderAndShortIDs,
    MSG_BLOCK,
    MSG_CMPCT_BLOCK,
    MSG_MWEB_BLOCK,
    MSG_WITNESS_FLAG,
    NODE_NETWORK,
    NODE_WITNESS,
    msg_getdata,
)
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, load_mweb_fixture, mweb_extra_args
from test_framework.p2p import P2P_SERVICES_MWEB, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

LOOSE_TXS = ("mweb_to_mweb", "pegin", "pegout")


class MWEBNoWalletP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args([], [])

    def setup_network(self):
        self.setup_nodes()

    def get_block(self, node, block_hash, inv_type, services):
        peer = node.add_p2p_connection(P2PInterface(), services=services)
        peer.send_and_ping(msg_getdata([CInv(inv_type, int(block_hash, 16))]))
        peer.wait_for_block(int(block_hash, 16))
        with p2p_lock:
            block = peer.last_message["block"].block
        peer.peer_disconnect()
        peer.wait_for_disconnect()
        return block

    def run_test(self):
        node0, node1 = self.nodes
        fixture = load_mweb_fixture(self, node0)
        txs = fixture["txs"]
        node1.setmocktime(fixture["mocktime"])
        # MiniWallet scans the mempool, whose MWEB outputs it can't parse, so make it first.
        mining_address = MiniWallet(node0).get_address()

        self.log.info("A node downloads the MWEB chain from a peer")
        self.connect_nodes(1, 0)
        self.sync_blocks()
        first_mweb_block = node0.getblockhash(FIRST_MWEB_HEIGHT)
        assert_equal(node1.getblock(first_mweb_block)["mweb_header"], node0.getblock(first_mweb_block)["mweb_header"])

        self.log.info("MWEB transactions relay")
        for name in LOOSE_TXS:
            node0.sendrawtransaction(txs[name]["hex"])
        # Announcement timers run on mock time, so move it past them.
        for node in self.nodes:
            node.setmocktime(fixture["mocktime"] + 600)
        self.sync_mempools()
        assert_equal(sorted(node1.getrawmempool()), sorted(txs[n]["txid"] for n in LOOSE_TXS))

        self.log.info("The block confirming them arrives as a compact block, rebuilt from the mempool")
        # The MWEB-only transactions travel in the MWEB block and the peg-in comes from the mempool.
        # The coinbase and the HogEx, which is never in a mempool, are prefilled.
        with node1.assert_debug_log(["Successfully reconstructed block", "2 txn prefilled, 1 txn from mempool", "and 0 txn ("]):
            block_hash = self.generatetoaddress(node0, 1, mining_address)[0]
        assert_equal(node1.getrawmempool(), [])
        assert_equal(node1.getblock(block_hash)["mweb_header"], node0.getblock(block_hash)["mweb_header"])

        self.log.info("A low-bandwidth request for an MWEB block gets a compact block")
        peer = node1.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB)
        peer.send_and_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, int(block_hash, 16))]))
        peer.wait_until(lambda: "cmpctblock" in peer.last_message)
        with p2p_lock:
            p2p_cmpct = peer.last_message["cmpctblock"].header_and_shortids
        assert_equal(p2p_cmpct.header.hash_hex, block_hash)
        assert p2p_cmpct.mweb_block is not None
        cmpct = HeaderAndShortIDs(p2p_cmpct)
        block_txids = node1.getblock(block_hash)["tx"]
        assert_equal([p.index for p in cmpct.prefilled_txn], [0, len(block_txids) - 1])
        assert cmpct.prefilled_txn[-1].tx.hogex
        assert_equal(cmpct.prefilled_txn[-1].tx.txid_hex, block_txids[-1])
        assert_equal(len(cmpct.shortids), len(block_txids) - 2)
        peer.peer_disconnect()
        peer.wait_for_disconnect()

        self.log.info("MSG_BLOCK leaves the MWEB data out; MSG_MWEB_BLOCK carries it")
        plain = self.get_block(node1, block_hash, MSG_BLOCK | MSG_WITNESS_FLAG, NODE_NETWORK | NODE_WITNESS)
        assert_equal(plain.mweb_block, None)
        assert not plain.vtx[-1].hogex
        full = self.get_block(node1, block_hash, MSG_MWEB_BLOCK, P2P_SERVICES_MWEB)
        assert full.mweb_block is not None
        assert full.vtx[-1].hogex


if __name__ == "__main__":
    MWEBNoWalletP2PTest(__file__).main()
