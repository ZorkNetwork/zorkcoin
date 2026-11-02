#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB mempool validation ordering (fail-fast before expensive crypto) — RPC smoke coverage.

Unit suite `mweb_mempool_order_tests` proves fail-fast (no batch verify on
missing inputs) and that invalid crypto still rejects before admission.
This functional test checks wallet/RPC acceptance still works after the
mempool reorder and that confirmed MWEB txs are not re-admitted.
"""

from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBMempoolOrderTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'])
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        # Single-node: do not pass self (reconnect_mweb_peers requires peers).
        setup_mweb_chain(node)

        self.log.info("Valid MWEB send is accepted to the mempool")
        dest = node.getnewaddress(address_type='mweb')
        txid = node.sendtoaddress(dest, 0.5)
        assert_equal(set(node.getrawmempool()), {txid})
        raw_hex = node.gettransaction(txid=txid)['hex']

        self.log.info("Mine the tx; re-submit reports already-known (not success)")
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])
        known = node.testmempoolaccept([raw_hex])
        assert_equal(known[0]['allowed'], False)
        assert_equal(known[0]['reject-reason'], 'txn-already-known')

        self.log.info("Subsequent valid MWEB send still enters the mempool")
        dest2 = node.getnewaddress(address_type='mweb')
        txid2 = node.sendtoaddress(dest2, 0.25)
        assert_equal(set(node.getrawmempool()), {txid2})
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])


if __name__ == '__main__':
    MWEBMempoolOrderTest(__file__).main()
