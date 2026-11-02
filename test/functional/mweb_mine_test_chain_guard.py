#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that bitcoind-mine-test refuses to run outside regtest.

That build can mine templates over the consensus size limits for the MWEB size
functionals, so on any public chain it could mine blocks every node rejects.
"""

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import resolve_mweb_mine_bitcoind


class MWEBMineTestChainGuardTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes)

    def run_test(self):
        mine_test = resolve_mweb_mine_bitcoind(self.binary_paths, variant="test")
        if mine_test is None:
            raise SkipTest("bitcoind-mine-test has not been built.")

        self.log.info("bitcoind-mine-test refuses to start on signet")
        node = self.nodes[0]
        node.binaries = node.binaries.with_bitcoind(mine_test)
        datadir_index = next(i for i, arg in enumerate(node.args) if arg.startswith("-datadir="))
        node.args = node.binaries.node_argv() + node.args[datadir_index:]
        node.assert_start_raises_init_error(
            expected_msg="Error: bitcoind-mine-test can mine invalid blocks for testing and only runs with -regtest.",
        )


if __name__ == '__main__':
    MWEBMineTestChainGuardTest(__file__).main()
