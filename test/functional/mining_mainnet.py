#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ASERT difficulty movement.

Bitcoin Core's original mining_mainnet used an SMA retarget fixture
(mainnet_alt.json). Zorkcoin uses GravityAsert from genesis. This test runs
on regtest with `-test=asert` (enables retargeting).

Regtest also allows min-difficulty blocks after a long gap. We first mine a
few easy min-diff blocks, then a run of fast blocks (gap < 2× spacing) and
check that ASERT raises difficulty.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

# nPowTargetSpacing from chainparams.
POW_TARGET_SPACING_MS = 1 << 17
UNSPENDABLE_DESC = "raw(51)"


class MiningMainnetTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Enable ASERT retargeting on regtest (default regtest has fPowNoRetargeting).
        self.extra_args = [["-test=asert"]]
        self.rpc_timeout = 120

    def run_test(self):
        node = self.nodes[0]
        node.stderr.seek(0)
        node.stderr.truncate()

        tip_hdr = node.getblockheader(node.getbestblockhash())
        tip_time_ms = tip_hdr["time"]
        assert_equal(node.getblockcount(), 0)

        node.setmocktime(tip_time_ms // 1000)

        # Long gaps → min-difficulty (powLimit) so the first blocks are cheap to mine.
        for height in range(1, 4):
            tip_time_ms += POW_TARGET_SPACING_MS * 3
            node.setmocktime(tip_time_ms // 1000)
            self.generatetodescriptor(node, 1, UNSPENDABLE_DESC)
            assert_equal(node.getblockcount(), height)

        baseline = node.getmininginfo()
        baseline_diff = baseline["difficulty"]
        self.log.info(f"after min-diff warmup: difficulty={baseline_diff} next={baseline['next']['difficulty']}")

        # Fast blocks (gap < 2× spacing) so min-diff does not apply and ASERT tightens.
        n_fast = 4
        for height in range(4, 4 + n_fast):
            tip_time_ms += POW_TARGET_SPACING_MS // 4
            node.setmocktime(tip_time_ms // 1000)
            self.generatetodescriptor(node, 1, UNSPENDABLE_DESC)
            assert_equal(node.getblockcount(), height)

        final = node.getmininginfo()
        self.log.info(
            f"after {n_fast} fast blocks: tip difficulty={final['difficulty']} "
            f"next={final['next']['difficulty']}"
        )
        assert_greater_than(final["difficulty"], baseline_diff)
        # Next work is genesis-anchored ASERT, not min-diff, so it must also sit
        # well above the powLimit tip. Do not compare next-to-next: warmup next
        # is already ASERT-from-genesis and a short fast run need not exceed it.
        assert_greater_than(final["next"]["difficulty"], baseline_diff)

        block_info = node.getblock(node.getblockhash(3 + n_fast))
        assert_equal(block_info["bits"], final["bits"])
        assert_equal(block_info["difficulty"], final["difficulty"])


if __name__ == "__main__":
    MiningMainnetTest(__file__).main()
