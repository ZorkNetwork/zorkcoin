#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Extended ASERT difficulty tests for regtest.

Requires build with: ./configure --enable-asert-regtest --with-incompatible-bdb
Run with: source .venv/bin/activate && test_runner.py --asert-regtest

Other regtest-based tests will NOT work with the ASERT regtest build.
Skipped with a clear message when not built for ASERT regtest.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_greater_than, assert_less_than


# Zorkcoin uses millisecond block timestamps. setmocktime RPC accepts seconds
# and multiplies by 1000 internally; blocks store nTime in ms.
REGTEST_GENESIS_TIME_SEC = 1765210800  # genesis nTime/1000
TARGET_SPACING_SEC = 150  # 2.5 min


class ASERTRegtestTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = 'regtest'  # Required for setmocktime
        self.extra_args = [['-vbparams=mweb:-2:0']]
        self.rpc_timeout = 180  # Extended: generatetoaddress with retargeting can be slower

    def run_test(self):
        node = self.nodes[0]
        if not node.getasertregtestbuild():
            raise SkipTest(
                "Skipping: requires build with ./configure --enable-asert-regtest --with-incompatible-bdb. "
                "This is a development test for extended ASERT DAA validation; run with: "
                "test_runner.py --asert-regtest"
            )
        addr = node.get_deterministic_priv_key().address

        # Start with blocks on ideal schedule to establish baseline difficulty
        self.log.info("Mining initial blocks with ideal 2.5min spacing...")
        for i in range(10):
            t = REGTEST_GENESIS_TIME_SEC + (i + 1) * TARGET_SPACING_SEC
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        tip = node.getblock(node.getbestblockhash())
        diff_baseline = node.getmininginfo()['difficulty']
        self.log.info(f"Baseline after 10 ideal blocks: difficulty={diff_baseline}, bits={tip['bits']}")

        # 2 blocks at exactly ideal spacing to stabilize DAA before fast mining
        t_base = REGTEST_GENESIS_TIME_SEC + 10 * TARGET_SPACING_SEC
        self.log.info("Mining 2 blocks at ideal spacing (stabilize before fast)...")
        for i in range(2):
            t = t_base + (i + 1) * TARGET_SPACING_SEC
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        tip = node.getblock(node.getbestblockhash())
        diff_baseline = node.getmininginfo()['difficulty']
        self.log.info(f"Baseline after 12 ideal blocks: difficulty={diff_baseline}, bits={tip['bits']}")

        # Fast mining: 75s spacing (2x faster than target)
        # Block 12 is at genesis + 12*150s; blocks 13+ must be 75s apart
        NUM_FAST_BLOCKS = 5
        self.log.info(f"Mining {NUM_FAST_BLOCKS} blocks with 75s spacing (fast)...")
        t_base = REGTEST_GENESIS_TIME_SEC + 12 * TARGET_SPACING_SEC
        for i in range(NUM_FAST_BLOCKS):
            t = t_base + (i + 1) * 75
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        tip = node.getblock(node.getbestblockhash())
        diff_after_fast = node.getmininginfo()['difficulty']
        self.log.info(f"After fast mining: difficulty={diff_after_fast}, bits={tip['bits']}")

        # 2 blocks at exactly ideal spacing to stabilize DAA before slow mining
        t_base = REGTEST_GENESIS_TIME_SEC + 12 * TARGET_SPACING_SEC + NUM_FAST_BLOCKS * 75
        self.log.info("Mining 2 blocks at ideal spacing (stabilize before slow)...")
        for i in range(2):
            t = t_base + (i + 1) * TARGET_SPACING_SEC
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        # Slow mining: 300s spacing (2x slower than target)
        # Blocks 20+ must be 300s apart
        t_base = REGTEST_GENESIS_TIME_SEC + 12 * TARGET_SPACING_SEC + NUM_FAST_BLOCKS * 75 + 2 * TARGET_SPACING_SEC
        self.log.info(f"Mining {NUM_FAST_BLOCKS} blocks with 300s spacing (slow)...")
        for i in range(NUM_FAST_BLOCKS):
            t = t_base + (i + 1) * 300
            node.setmocktime(t)
            node.generatetoaddress(1, addr)

        tip = node.getblock(node.getbestblockhash())
        diff_after_slow = node.getmininginfo()['difficulty']
        self.log.info(f"After slow mining: difficulty={diff_after_slow}, bits={tip['bits']}")

        # ASERT spec: fast mining -> difficulty increases; slow mining -> difficulty decreases
        assert_greater_than(diff_after_fast, Decimal(diff_baseline) * Decimal('1.001'))
        assert_less_than(diff_after_slow, Decimal(diff_after_fast) * Decimal('0.999'))

        self.log.info("All ASERT regtest tests passed")


if __name__ == '__main__':
    ASERTRegtestTest().main()
