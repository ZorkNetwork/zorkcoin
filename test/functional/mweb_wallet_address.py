#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB addresses on wallets that have no MWEB keys.

Litecoin Core's mweb_wallet_address.py opens a pre-HD wallet and expects
getnewaddress(mweb) to fail. This node has descriptor wallets only, so the
wallets without MWEB keys are an L1-only wallet, a blank wallet and a wallet
with private keys disabled. The L1-only wallet then adds an MWEB descriptor,
receives to it and spends from it.

Also checks the wallet address RPCs on MWEB addresses as Litecoin returns them:
getaddressinfo, getreceivedbyaddress, getreceivedbylabel, listaddressgroupings
and the listunspent count and sum limits.
"""
from decimal import Decimal

from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        setup_mweb_chain(node)

        self.log.info("A wallet with only L1 descriptors has no MWEB addresses")
        # The keys come from a wallet the miner doesn't share, so that the MWEB
        # account createwalletdescriptor derives from them is not the miner's.
        node.createwallet(wallet_name='keysource')
        keysource = node.get_wallet_rpc('keysource')
        node.createwallet(wallet_name='l1only', blank=True)
        wallet = node.get_wallet_rpc('l1only')
        l1_descs = [d for d in keysource.listdescriptors(True)['descriptors'] if d['desc'].startswith('wpkh(')]
        assert_equal(len(l1_descs), 2)
        results = wallet.importdescriptors([{'desc': d['desc'], 'timestamp': 'now', 'active': True, 'internal': d['internal']}
                                            for d in l1_descs])
        assert all(r['success'] for r in results), results
        wallet.getnewaddress(address_type='bech32')
        assert_raises_rpc_error(-12, "No mweb addresses available", wallet.getnewaddress, address_type='mweb')
        assert_raises_rpc_error(-12, "No mweb addresses available", wallet.getrawchangeaddress, 'mweb')

        self.log.info("Blank and keys-disabled wallets have no MWEB addresses")
        node.createwallet(wallet_name='blank', blank=True)
        node.createwallet(wallet_name='nokeys', disable_private_keys=True)
        for name in ('blank', 'nokeys'):
            assert_raises_rpc_error(-4, "This wallet has no available keys",
                                    node.get_wallet_rpc(name).getnewaddress, address_type='mweb')

        self.log.info("After createwalletdescriptor('mweb') the L1-only wallet receives and spends MWEB")
        wallet.createwalletdescriptor('mweb')
        addr = wallet.getnewaddress(address_type='mweb')
        assert addr.startswith('bcrt1m')
        txid = miner.sendtoaddress(addr, 2)
        self.generate(node, 1)
        coins = wallet.listunspent(addresses=[addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], Decimal('2'))
        assert_equal(wallet.gettransaction(txid)['amount'], Decimal('2'))

        dest = miner.getnewaddress(address_type='mweb')
        spend_txid = wallet.sendtoaddress(dest, 1)
        assert spend_txid in node.getrawmempool()
        self.generate(node, 1)
        assert_equal(wallet.gettransaction(spend_txid)['confirmations'], 1)
        assert_equal(wallet.listunspent(addresses=[addr]), [])
        assert_equal(len([c for c in miner.listunspent(addresses=[dest]) if c['amount'] == Decimal('1')]), 1)

        self.log.info("getaddressinfo: MWEB addresses have no scriptPubKey, and the change address is change")
        change_addr = wallet.getrawchangeaddress('mweb')
        info = wallet.getaddressinfo(addr)
        assert 'scriptPubKey' not in info
        assert_equal((info['ismine'], info['ismweb'], info['ischange']), (True, True, False))
        assert_equal(wallet.getaddressinfo(change_addr)['ischange'], True)
        assert 'scriptPubKey' in wallet.getaddressinfo(wallet.getnewaddress(address_type='bech32'))

        self.log.info("getreceivedbyaddress and getreceivedbylabel count MWEB receives")
        assert_equal(wallet.getreceivedbyaddress(addr), Decimal('2'))
        wallet.setlabel(addr, 'mweb label')
        assert_equal(wallet.getreceivedbylabel('mweb label'), Decimal('2'))
        assert_raises_rpc_error(-4, "Address not found in wallet", wallet.getreceivedbyaddress, dest)

        self.log.info("listaddressgroupings groups the spent MWEB address with its change")
        group, = [g for g in wallet.listaddressgroupings() if any(entry[0] == addr for entry in g)]
        balances = {entry[0]: entry[1] for entry in group}
        assert_equal(balances[addr], 0)
        assert_equal(balances[change_addr], wallet.getbalance())

        self.log.info("listunspent maximumCount and minimumSumAmount cover MWEB coins")
        for _ in range(2):
            miner.sendtoaddress(wallet.getnewaddress(address_type='mweb'), 1)
        self.generate(node, 1)
        coins = wallet.listunspent()
        assert_equal(len(coins), 3)
        assert all(c['spendable'] for c in coins)
        assert_equal(len(wallet.listunspent(query_options={'maximumCount': 2})), 2)
        assert_equal(len(wallet.listunspent(query_options={'minimumSumAmount': Decimal('0.5')})), 1)


if __name__ == '__main__':
    MWEBWalletAddressTest(__file__).main()
