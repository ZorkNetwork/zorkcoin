#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool re-org scenarios for MWEB transactions

Test re-org scenarios with a mempool that contains transactions
that create or spend (directly or indirectly) MWEB outputs.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.mweb_util import init_mweb_wallet, generate, setup_mweb_chain, mweb_extra_args

class MWEBReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], [])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.basic_reorg_test()
        self.multiple_blocks_reorg_test()
        self.unconfirmed_parent_reorg_test()
        self.same_block_hybrid_child_reorg_test()
        self.orphaned_mweb_input_reorg_test()

    def basic_reorg_test(self):
        self.log.info("Create all pre-MWEB blocks")
        setup_mweb_chain(self.nodes[0], self)
        self.sync_all()

        self.log.info("Pegin some coins in pegin_tx1. pegin_tx1 should be in the mempool")
        node0_mweb_addr = self.nodes[0].getnewaddress(address_type='mweb')
        pegin_tx1_id = self.nodes[0].sendtoaddress(node0_mweb_addr, 100)
        self.sync_all()

        assert_equal(set(self.nodes[1].getrawmempool()), {pegin_tx1_id})

        self.log.info("Mine pegin_tx1 in block0a, and mine a few blocks on top. mempool should be empty")
        block0a = self.generate(self.nodes[0], 4)[0]
        self.sync_all()

        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        self.log.info("Invalidate block0a. pegin_tx1 should be back in the mempool")
        self.nodes[1].invalidateblock(block0a)
        assert_equal(set(self.nodes[1].getrawmempool()), {pegin_tx1_id})

        self.log.info("Generate block0b. pegin_tx1 should be included in the block")
        block0b_hash = generate(self.nodes[1], 1)[0]

        block0b_txs = self.nodes[1].getblock(block0b_hash, 2)['tx']
        assert_equal(len(block0b_txs), 3)
        assert_equal(block0b_txs[1]['txid'], pegin_tx1_id)

        generate(self.nodes[1], 5)
        self.sync_blocks()

    def multiple_blocks_reorg_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Make sure nodes are in sync
        generate(node0, 10)
        self.sync_all()

        # disconnect the nodes and mine separate forks
        self.disconnect_nodes(0, 1)
        generate(node0, 5)
        generate(node1, 5)

        def fork_state(node):
            tip = node.getbestblockhash()
            coins = sorted((coin['output_id'], coin['amount'], coin['confirmations'])
                           for coin in node.listunspent() if coin.get('output_id'))
            return tip, node.getblockheader(tip), coins

        forks = [fork_state(node) for node in self.nodes]
        assert forks[0][0] != forks[1][0]
        assert forks[0][2]
        self.log.info("Reload both disconnected forks before reconnecting")
        self.stop_nodes()
        self.start_nodes()
        for node, expected in zip(self.nodes, forks, strict=True):
            assert_equal(node.getconnectioncount(), 0)
            assert_equal(fork_state(node), expected)

        # reconnect the nodes and have node0 mine 1 block, forcing a reorg on node1
        self.connect_nodes(0, 1)
        winning_tip = generate(node0, 1)[0]
        self.sync_blocks()
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), winning_tip)

    def unconfirmed_parent_reorg_test(self):
        self.log.info("MWEB and peg-in transactions whose parents return to the mempool stay in it after a reorg")
        node0 = self.nodes[0]
        self.sync_all()

        parent_mweb = node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), 5)
        parent_l1 = node0.sendtoaddress(node0.getnewaddress(address_type='bech32'), 5)
        block = generate(node0, 1)[0]
        self.sync_all()

        mweb_coin = next(u for u in node0.listunspent(1) if u.get('output_id') and u['amount'] == 5)
        l1_coin = next(u for u in node0.listunspent(1) if u.get('txid') == parent_l1 and u['amount'] == 5)
        mweb_child = node0.send(outputs={node0.getnewaddress(address_type='mweb'): 1},
                                options={"inputs": [{"output_id": mweb_coin['output_id']}], "add_inputs": False, "locktime": 0})['txid']
        pegin_child = node0.send(outputs={node0.getnewaddress(address_type='mweb'): 1},
                                 options={"inputs": [{"txid": l1_coin['txid'], "vout": l1_coin['vout']}], "add_inputs": False, "locktime": 0})['txid']
        assert_equal(set(node0.getrawmempool()), {mweb_child, pegin_child})
        # Ordered ahead of its parent, the child must still be linked to it
        # once the parent returns, or the mempool check fails.
        node0.prioritisetransaction(txid=mweb_child, fee_delta=100_000_000)

        node0.invalidateblock(block)
        assert_equal(set(node0.getrawmempool()), {parent_mweb, parent_l1, mweb_child, pegin_child})
        for parent, child in ((parent_mweb, mweb_child), (parent_l1, pegin_child)):
            assert_equal(node0.getmempoolentry(child)['ancestorcount'], 2)
            assert_equal(node0.getmempoolentry(parent)['descendantcount'], 2)
        check_trigger = node0.sendtoaddress(node0.getnewaddress(address_type='bech32'), 1)

        node0.reconsiderblock(block)
        assert_equal(set(node0.getrawmempool()), {mweb_child, pegin_child, check_trigger})
        node0.prioritisetransaction(txid=mweb_child, fee_delta=-100_000_000)
        generate(node0, 1)
        self.sync_all()
        assert_equal(node0.getrawmempool(), [])

    def same_block_hybrid_child_reorg_test(self):
        self.log.info("A peg-in and an L1 child of it, mined in one block, both return to the mempool after a reorg")
        node0 = self.nodes[0]
        self.sync_all()

        l1_coin = next(u for u in node0.listunspent(1) if not u.get('output_id') and u['amount'] > 20)
        l1_addr = node0.getnewaddress(address_type='bech32')
        pegin = node0.send(outputs=[{node0.getnewaddress(address_type='mweb'): 3}, {l1_addr: 5}],
                           options={"inputs": [{"txid": l1_coin['txid'], "vout": l1_coin['vout']}], "add_inputs": False})['txid']
        pegin_l1_out = next(u for u in node0.listunspent(0) if u.get('txid') == pegin and u.get('address') == l1_addr)
        l1_child = node0.send(outputs={node0.getnewaddress(address_type='bech32'): 4},
                              options={"inputs": [{"txid": pegin, "vout": pegin_l1_out['vout']}], "add_inputs": False})['txid']
        block = generate(node0, 1)[0]
        assert {pegin, l1_child} <= {tx['txid'] for tx in node0.getblock(block, 2)['tx']}

        node0.invalidateblock(block)
        assert_equal(set(node0.getrawmempool()), {pegin, l1_child})
        assert_equal(node0.getmempoolentry(l1_child)['ancestorcount'], 2)

        node0.reconsiderblock(block)
        assert_equal(node0.getrawmempool(), [])
        self.sync_all()

    def orphaned_mweb_input_reorg_test(self):
        self.log.info("An MWEB spend whose parent is double-spent on the new chain leaves the mempool")
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        self.sync_all()
        self.disconnect_nodes(0, 1)

        l1_coin = next(u for u in node0.listunspent(1) if not u.get('output_id') and u['amount'] > 10)
        double_spend = node0.createrawtransaction(
            [{"txid": l1_coin['txid'], "vout": l1_coin['vout']}],
            {node0.getnewaddress(address_type='bech32'): l1_coin['amount'] - Decimal('0.001')})
        double_spend = node0.signrawtransactionwithwallet(double_spend)['hex']

        pegin = node0.send(outputs={node0.getnewaddress(address_type='mweb'): 5},
                           options={"inputs": [{"txid": l1_coin['txid'], "vout": l1_coin['vout']}], "add_inputs": False})['txid']
        generate(node0, 1)

        node1.sendrawtransaction(double_spend)
        generate(node1, 2)

        mweb_coins = [u for u in node0.listunspent(1) if u.get('output_id') and u['amount'] == 5]
        assert_equal(len(mweb_coins), 1)
        mweb_coin = mweb_coins[0]
        mweb_child = node0.send(outputs={node0.getnewaddress(address_type='mweb'): 1},
                                options={"inputs": [{"output_id": mweb_coin['output_id']}], "add_inputs": False})['txid']
        assert mweb_child in node0.getrawmempool()

        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        mempool = node0.getrawmempool()
        assert pegin not in mempool
        assert mweb_child not in mempool


if __name__ == '__main__':
    MWEBReorgTest(__file__).main()
