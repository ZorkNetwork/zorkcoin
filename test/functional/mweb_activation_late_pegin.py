#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject first-active-block attempts without a peg-in, then recover on its arrival.

This complements the immediate-peg-in activation tests retained from Litecoin.
Assembly failure and rejection of a received block exercise separate paths.
"""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, MWEB_GBT_REQUEST_PARAMS, get_hogex_tx, mweb_extra_args
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBLatePeginTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def state(self):
        node = self.nodes[0]
        node.syncwithvalidationinterfacequeue()
        coins = node.gettxoutsetinfo('muhash')
        return (node.getbestblockhash(), node.getblockcount(),
                {k: coins[k] for k in ('bestblock', 'txouts', 'total_amount', 'muhash')},
                node.getrawmempool(), node.getbalances())

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, FIRST_MWEB_HEIGHT - 1)
        deployment = node.getdeploymentinfo()['deployments']['mweb']
        assert_equal(deployment['bip9']['status_next'], 'active')
        assert_equal(deployment['bip9']['status'], 'locked_in')
        assert 'mweb' not in node.getblock(node.getbestblockhash())
        before = self.state()
        assert_equal(before[3], [])
        initial_time = node.getblockheader(before[0])['time']

        for delay in (1, 3600, 86400):
            node.setmocktime(initial_time + delay)
            assert_raises_rpc_error(-1, 'bad-txns-vin-empty',
                                    node.getblocktemplate, MWEB_GBT_REQUEST_PARAMS)
            assert_raises_rpc_error(-1, 'bad-txns-vin-empty',
                                    node.generatetoaddress, 1, node.get_deterministic_priv_key().address,
                                    called_by_framework=True)
            # A received L1-only block is also invalid at this next height.
            block = create_block(int(before[0], 16), create_coinbase(FIRST_MWEB_HEIGHT),
                                 ntime=initial_time + delay)
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), 'mweb-missing')
            assert_equal(self.state(), before)

        self.restart_node(0)
        node.setmocktime(initial_time + 86400)
        assert_equal(self.state(), before)
        assert_raises_rpc_error(-1, 'bad-txns-vin-empty',
                                node.getblocktemplate, MWEB_GBT_REQUEST_PARAMS)

        pegin = node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)
        assert_equal(node.getrawmempool(), [pegin])
        template = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        assert 'mweb' in template
        first = self.generate(node, 1)[0]
        assert_equal(node.getblockcount(), FIRST_MWEB_HEIGHT)
        assert_equal(node.getdeploymentinfo()['deployments']['mweb']['active'], True)
        assert_equal(node.getblock(first)['tx'][1], pegin)
        hogex = get_hogex_tx(node, first)
        assert_equal(len(hogex.vin), 1)
        assert_equal(hogex.vin[0].prevout.hash, int(pegin, 16))
        assert_equal(node.getrawmempool(), [])
        for successor in self.generate(node, 2):
            assert 'mweb' in node.getblock(successor)
            assert_equal(len(get_hogex_tx(node, successor).vin), 1)


if __name__ == '__main__':
    MWEBLatePeginTest(__file__).main()
