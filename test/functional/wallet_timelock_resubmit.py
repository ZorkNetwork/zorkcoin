#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a future-locktime wallet tx remains unconfirmed, is periodically
resubmitted, enters the mempool once final, and confirms when mined.

Covers the CommitTransaction → failed broadcast → ResubmitWalletTransactions
path that height-locked MWEB txs share once IsFinalTx enforces kernel locks.
"""
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

# Upper bound of the wallet resend timer (see CWallet::GetDefaultNextResend).
RESEND_TIMER_LIMIT = 36 * 60 * 60


class WalletTimelockResubmitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        height = node.getblockcount()
        # nLockTime must be < tip+1 to be final. locktime=height+3 becomes
        # final only after three new blocks (tip == height+3 ⇒ tip+1 == height+4).
        locktime = height + 3
        blocks_until_final = 3

        self.log.info("Create wallet tx with future locktime")
        addr = node.getnewaddress()
        txid = node.send(outputs=[{addr: 1}], options={"locktime": locktime})["txid"]
        hex_tx = node.gettransaction(txid)["hex"]

        assert_equal(node.gettransaction(txid)["confirmations"], 0)
        accept = node.testmempoolaccept([hex_tx])[0]
        assert_equal(accept["allowed"], False)
        assert_equal(accept["reject-reason"], "non-final")
        assert txid not in node.getrawmempool()

        self.log.info("Advance chain before lock expiry; tx must stay out of mempool")
        self.generate(node, blocks_until_final - 1)
        assert_equal(node.gettransaction(txid)["confirmations"], 0)
        accept = node.testmempoolaccept([hex_tx])[0]
        assert_equal(accept["allowed"], False)
        assert_equal(accept["reject-reason"], "non-final")
        assert txid not in node.getrawmempool()

        self.log.info("Advance past lock expiry so the tx is final for the next block")
        self.generate(node, 1)
        assert_equal(node.getblockcount(), locktime)
        accept = node.testmempoolaccept([hex_tx])[0]
        assert_equal(accept["allowed"], True)
        # Still only in the wallet until resubmit runs.
        assert txid not in node.getrawmempool()
        assert_equal(node.gettransaction(txid)["confirmations"], 0)

        # ResubmitWalletTransactions skips txs newer than m_best_block_time - 5 minutes.
        block_time = int(time.time()) + 6 * 60
        node.setmocktime(block_time)
        self.generate(node, 1)
        node.syncwithvalidationinterfacequeue()
        # Re-check finality after the extra block (still final).
        assert_equal(node.testmempoolaccept([hex_tx])[0]["allowed"], True)

        self.log.info("Trigger periodic wallet resubmit; tx should enter the mempool")
        now = int(time.time())
        with node.assert_debug_log(["resubmit 1 unconfirmed transactions"], timeout=2):
            node.setmocktime(now + RESEND_TIMER_LIMIT)
            node.mockscheduler(60)
        self.wait_until(lambda: txid in node.getrawmempool())

        self.log.info("Mine the resubmitted tx")
        self.generate(node, 1)
        assert_greater_than(node.gettransaction(txid)["confirmations"], 0)
        assert txid not in node.getrawmempool()


if __name__ == "__main__":
    WalletTimelockResubmitTest(__file__).main()
