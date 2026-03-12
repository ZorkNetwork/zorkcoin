#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ASERTi3-12h difficulty adjustment algorithm.

Uses regtest so setmocktime works (required for controlling block timestamps).
GetNextWorkRequired calls ASERT on all chains; fPowNoRetargeting only affects
MineBlocksOnDemand, not the nBits calculation.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than, assert_less_than


# Zorkcoin regtest genesis time (ms) -> seconds for setmocktime
REGTEST_GENESIS_TIME_SEC = 1765210800  # 1765210800000 // 1000
# 2.5 min block spacing in seconds
TARGET_SPACING_SEC = 150


class ASERTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = 'regtest'  # Required for setmocktime
        self.extra_args = [['-vbparams=mweb:-2:0']]
        self.rpc_timeout = 120  # generatetoaddress can be slow on resource-constrained systems

    def run_test(self):
        node = self.nodes[0]
        addr = node.get_deterministic_priv_key().address

        # Start from genesis
        self.log.info("Mining initial blocks with ideal 2.5min spacing...")
        for i in range(10):
            t = REGTEST_GENESIS_TIME_SEC + (i + 1) * TARGET_SPACING_SEC
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        # After ~10 blocks on ideal schedule, difficulty should stay roughly constant
        tip = node.getblock(node.getbestblockhash())
        diff_start = node.getmininginfo()['difficulty']
        self.log.info(f"After 10 ideal blocks: difficulty={diff_start}, bits={tip['bits']}")

        # Mine 5 more with same spacing - difficulty should remain stable
        for i in range(5):
            t = REGTEST_GENESIS_TIME_SEC + (10 + i + 1) * TARGET_SPACING_SEC
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        tip = node.getblock(node.getbestblockhash())
        diff_after_stable = node.getmininginfo()['difficulty']
        self.log.info(f"After 15 ideal blocks: difficulty={diff_after_stable}, bits={tip['bits']}")

        # Difficulty should be within 5% (rounding/approximation tolerance)
        assert_less_than(diff_after_stable, Decimal(diff_start) * Decimal('1.05'))
        assert_greater_than(diff_after_stable, Decimal(diff_start) * Decimal('0.95'))
        self.log.info("All ASERT tests passed")


if __name__ == '__main__':
    ASERTTest().main()
