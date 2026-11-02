#!/usr/bin/env python3
# Copyright (c) 2026 The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""AuxPoW headers through low-work headers presync and redownload.

A chain longer than one headers message, with AuxPoW blocks in the first
message, at its boundary and at the tip, is synced by a node whose
-minimumchainwork equals the chain's work, so the headers go through
presync, redownload and acceptance. With one unit more required work the
same chain must stay unindexed, which pins presync to the same size-discounted
AuxPoW work that validation credits.
"""

from test_framework.auxpow import (
    build_solo_auxpow_for_block,
    make_auxpow_nonce,
    make_auxpow_version,
)
from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

HEADERS_PER_MESSAGE = 2000


class AuxPowHeadersPresyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.rpc_timeout *= 4
        self.extra_args = [["-checkblockindex=0"], ["-checkblockindex=0"]]

    def setup_network(self):
        self.setup_nodes()

    def _submit_auxpow_block(self, label, extra_parents=0):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        block = create_block(
            hashprev=int(tip, 16),
            coinbase=create_coinbase(height=node.getblockcount() + 1, extra_output_script=CScript([OP_RETURN, label])),
            ntime=node.getblock(tip)["time"] + 1000,
            version=make_auxpow_version(),
        )
        block.nNonce = make_auxpow_nonce()
        block.auxpow = build_solo_auxpow_for_block(block, extra_parents=extra_parents)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block.hash

    def _mine_native_to(self, height):
        node = self.nodes[0]
        self.generate(node, height - node.getblockcount(), sync_fun=self.no_op)

    def run_test(self):
        node0 = self.nodes[0]
        self.log.info("Build a chain spanning two headers messages with AuxPoW blocks throughout")
        aux_hashes = [self._submit_auxpow_block(b"first")]
        self._mine_native_to(1000)
        aux_hashes.append(self._submit_auxpow_block(b"fat", extra_parents=12))
        self._mine_native_to(HEADERS_PER_MESSAGE - 1)
        aux_hashes.append(self._submit_auxpow_block(b"boundary"))
        assert_equal(node0.getblockcount(), HEADERS_PER_MESSAGE)
        self._mine_native_to(HEADERS_PER_MESSAGE + 50)
        aux_hashes.append(self._submit_auxpow_block(b"tip"))
        tip = node0.getbestblockhash()
        tip_height = node0.getblockcount()
        chain_work = int(node0.getblockheader(tip)["chainwork"], 16)

        self.log.info("One unit more than the chain's work: presync must give up")
        self.restart_node(1, extra_args=[f"-minimumchainwork={chain_work + 1:#x}", "-debug=net", "-checkblockindex=0"])
        with self.nodes[1].assert_debug_log(
            expected_msgs=[
                "Initial headers sync started with peer=",
                f"incomplete headers message at height={tip_height} (presync phase)",
            ],
            unexpected_msgs=["Initial headers sync transition"],
            timeout=60,
        ):
            self.connect_nodes(1, 0)
        assert_equal([t["height"] for t in self.nodes[1].getchaintips()], [0])
        self.disconnect_nodes(1, 0)

        self.log.info("Exactly the chain's work: presync, redownload and acceptance")
        self.restart_node(1, extra_args=[f"-minimumchainwork={chain_work:#x}", "-debug=net", "-checkblockindex=0"])
        with self.nodes[1].assert_debug_log(
            expected_msgs=[
                "Initial headers sync started with peer=",
                f"reached sufficient work at height={tip_height}, redownloading from height=0",
                "Initial headers sync complete with peer=",
            ],
            timeout=120,
        ):
            self.connect_nodes(1, 0)
        self.sync_blocks(timeout=240)
        node1 = self.nodes[1]
        assert_equal(node1.getbestblockhash(), tip)
        assert_equal(int(node1.getblockheader(tip)["chainwork"], 16), chain_work)
        for block_hash in aux_hashes:
            header = node1.getblockheader(block_hash)
            assert header["version"] & 0x100
            assert_equal(header["nonce"], make_auxpow_nonce())
            raw = node1.getblockheader(block_hash, False)
            assert len(raw) > 2 * 88
            assert_equal(raw, node0.getblockheader(block_hash, False))


if __name__ == "__main__":
    AuxPowHeadersPresyncTest(__file__).main()
