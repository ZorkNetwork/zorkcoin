#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that we can pegout all coins in the MWEB"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, init_mweb_wallet, get_hog_addr_txout, mweb_extra_args

class MWEBPegoutAllTest(BitcoinTestFramework):
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
        amount = Decimal('10')
        self.log.info("Activate MWEB with exactly ten coins and canonical change")
        self.generate(miner, FIRST_MWEB_HEIGHT - 1)
        coin = max(miner.listunspent(), key=lambda coin: coin['amount'])
        pegin = miner.send(outputs={miner.getnewaddress(address_type='mweb'): amount}, fee_rate=10, options={
            'inputs': [{'txid': coin['txid'], 'vout': coin['vout']}],
            'add_inputs': False,
            'change_address': miner.getrawchangeaddress(address_type='bech32'),
        })['txid']
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {pegin})
        self.generate(miner, 1)
        for node in self.nodes:
            assert_equal(get_hog_addr_txout(node).nValue, int(amount * COIN))
        source, = [coin for coin in miner.listunspent() if coin.get('output_id')]
        assert_equal(source['amount'], amount)

        self.log.info("Transfer the complete MWEB supply to the second wallet, subtracting its fee")
        address = receiver.getnewaddress(address_type='mweb')
        transfer = miner.sendtoaddress(address, amount, subtractfeefromamount=True)
        transfer_fee = -miner.gettransaction(transfer)['fee']
        assert transfer_fee > 0
        decoded = miner.getrawtransaction(transfer, True)
        assert_equal(decoded['vin'], [{'ismweb': True, 'output_id': source['output_id']}])
        assert all(output['ismweb'] for output in decoded['vout'])
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {transfer})
        self.generate(miner, 1)
        balance = amount - transfer_fee
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
            assert_equal(get_hog_addr_txout(node).nValue, int(balance * COIN))
        assert_equal([coin for coin in miner.listunspent() if coin.get('output_id')], [])
        received, = receiver.listunspent()
        assert_equal((received['address'], received['amount']), (address, balance))
        assert_equal(receiver.getbalance(), balance)

        self.log.info("Withdraw that exact remaining supply, subtracting the peg-out fee")
        destination = receiver.getnewaddress(address_type='bech32')
        pegout = receiver.sendtoaddress(destination, balance, subtractfeefromamount=True)
        pegout_fee = -receiver.gettransaction(pegout)['fee']
        assert pegout_fee > 0
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(set(node.getrawmempool()), {pegout})
        self.generate(miner, 1)
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
        assert_equal([coin for coin in receiver.listunspent() if coin.get('output_id')], [])
        paid, = receiver.listreceivedbyaddress(minconf=0, address_filter=destination)
        assert_equal((paid['amount'], paid['confirmations']), (balance - pegout_fee, 1))

        self.log.info("Check that pegged in amount is 0")
        for node in self.nodes:
            assert_equal(get_hog_addr_txout(node).nValue, 0)

        self.log.info("Ensure we can mine the next block")
        previous_height = miner.getblockcount()
        self.generate(miner, 1)
        assert_equal(receiver.getblockcount(), previous_height + 1)

if __name__ == '__main__':
    MWEBPegoutAllTest(__file__).main()
