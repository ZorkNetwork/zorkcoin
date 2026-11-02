#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test flushing MWEB state rewound past the first MWEB block.

Invalidate the first MWEB block (best MWEB header becomes null), restart the
node so the rewound state is flushed to disk, then reconsider the block. If the
rewound MWEB state is not flushed, the stale on-disk MWEB coins make the block
fail to reconnect.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.util import assert_equal


class MWEBRewindActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Activate MWEB with a peg-in")
        setup_mweb_chain(node)
        self.generate(node, 2, sync_fun=self.no_op)
        tip_height = node.getblockcount()

        self.log.info("Find the first block carrying an MWEB header")
        first_mweb_hash = None
        first_mweb_height = 0
        for h in range(1, tip_height + 1):
            blk = node.getblock(node.getblockhash(h))
            if 'mweb' in blk:
                first_mweb_hash = blk['hash']
                first_mweb_height = h
                break
        assert first_mweb_hash is not None, "no MWEB block found"

        self.log.info("Invalidate the first MWEB block (rewinds MWEB state to a null header)")
        node.invalidateblock(first_mweb_hash)
        assert_equal(node.getblockcount(), first_mweb_height - 1)

        self.log.info("Restart the node to flush the rewound (empty) MWEB state")
        self.restart_node(0)
        assert_equal(node.getblockcount(), first_mweb_height - 1)

        self.log.info("Reconsider the block; the original chain must reconnect cleanly")
        node.reconsiderblock(first_mweb_hash)
        assert_equal(node.getblockcount(), tip_height)
        assert_equal(node.getbestblockhash(), node.getblockhash(tip_height))

        self.log.info("Restart once more and mine on top to confirm the state is consistent")
        self.restart_node(0)
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), tip_height + 1)


if __name__ == '__main__':
    MWEBRewindActivationTest(__file__).main()
