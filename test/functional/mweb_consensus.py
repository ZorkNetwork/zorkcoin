#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A peg-in and its complete withdrawal mine in successive MWEB blocks."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.mweb_util import get_hog_addr_txout, init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        miner, receiver = self.nodes
        setup_mweb_chain(miner, self)
        baseline = get_hog_addr_txout(miner).nValue
        amount = Decimal('25')

        self.log.info("Create a peg-in parent paying the other wallet, with canonical change")
        coin = max((coin for coin in miner.listunspent() if 'vout' in coin), key=lambda coin: coin['amount'])
        parent = miner.send(outputs={receiver.getnewaddress(address_type='mweb'): amount}, fee_rate=10, options={
            'inputs': [{'txid': coin['txid'], 'vout': coin['vout']}],
            'add_inputs': False,
            'change_address': miner.getrawchangeaddress(address_type='bech32'),
        })['txid']
        parent_tx = miner.gettransaction(parent)
        assert_equal((parent_tx['confirmations'], parent_tx['amount']), (0, -amount))
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {parent})
        parent_raw = miner.getrawtransaction(parent, True)
        parent_kernel, = [kernel['kernel_id'] for kernel in parent_raw['vkern']]
        owned, = receiver.listunspent(minconf=0)
        assert_equal((owned['txid'], owned['amount']), (parent, amount))

        self.log.info("Spend the parent's entire unconfirmed MWEB output as a peg-out child")
        destination = miner.getnewaddress(address_type='bech32')
        child = receiver.send(outputs={destination: amount}, fee_rate=10, options={
            'inputs': [{'mweb_out': owned['output_id']}],
            'add_inputs': False,
            'include_unsafe': True,
            'subtract_fee_from_outputs': [0],
        })['txid']
        child_tx = receiver.gettransaction(child)
        fee = -child_tx['fee']
        assert fee > 0
        assert_equal((child_tx['confirmations'], child_tx['amount']), (0, -(amount - fee)))
        child_raw = receiver.getrawtransaction(child, True)
        assert_equal(child_raw['vin'], [{'ismweb': True, 'output_id': owned['output_id']}])
        child_kernel, = [kernel['kernel_id'] for kernel in child_raw['vkern']]
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {parent, child})

        self.log.info("The zero-sum aggregate must leave its parent mined and its child in the pool")
        first_block, = self.generate(receiver, 1)
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {child})
            block = node.getblock(first_block, 2)
            assert parent in [tx['txid'] for tx in block['tx']]
            assert_equal({kernel['kernel_id'] for kernel in block['mweb']['kernels']}, {parent_kernel})
            assert_equal(get_hog_addr_txout(node).nValue, baseline + int(amount * COIN))
        assert_equal(miner.gettransaction(parent)['confirmations'], 1)
        assert_equal(receiver.gettransaction(child)['confirmations'], 0)

        self.log.info("The next block includes the child and restores the original MWEB supply")
        second_block, = self.generate(receiver, 1)
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
            block = node.getblock(second_block, 2)
            # Native canonical tx arrays omit loose pure-MWEB transaction IDs.
            assert_equal({kernel['kernel_id'] for kernel in block['mweb']['kernels']}, {child_kernel})
            assert_equal(get_hog_addr_txout(node).nValue, baseline)
        assert_equal(receiver.gettransaction(child)['confirmations'], 1)
        paid, = miner.listreceivedbyaddress(minconf=0, address_filter=destination)
        assert_equal((paid['amount'], paid['confirmations']), (amount - fee, 1))


if __name__ == '__main__':
    MWEBConsensusTest(__file__).main()
