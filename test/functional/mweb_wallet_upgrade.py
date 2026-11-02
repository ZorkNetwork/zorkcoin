#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a wallet made by a release without MWEB can receive and spend MWEB.

Port of Litecoin Core's mweb_wallet_upgrade.py, which upgrades a non-HD
wallet made by an older Litecoin Core. This node has descriptor wallets only:
the wallet is made by a previous release of the Bitcoin Core node this one is
built on, and gains MWEB through createwalletdescriptor('mweb'). Needs previous
releases (test/get_previous_releases.py).
"""

from decimal import Decimal
import os
import shutil

from test_framework.mweb_util import setup_mweb_chain, with_mweb_vbparams
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PRE_MWEB_RELEASE = 310000
WALLET_NAME = 'pre_mweb'


class MWEBWalletUpgradeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [with_mweb_vbparams([]), ['-nowallet']]
        self.wallet_names = [self.default_wallet_name]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args, versions=[None, PRE_MWEB_RELEASE])
        self.start_nodes()
        self.import_deterministic_coinbase_privkeys()

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        old_node = self.nodes[1]

        self.log.info("Setting up MWEB chain")
        setup_mweb_chain(node)

        self.log.info("Creating a wallet with the release without MWEB")
        old_node.createwallet(wallet_name=WALLET_NAME)
        old_node.unloadwallet(WALLET_NAME)
        self.stop_node(1)
        shutil.copytree(os.path.join(old_node.wallets_path, WALLET_NAME), os.path.join(node.wallets_path, WALLET_NAME))

        self.log.info("Loading it and adding an MWEB account")
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.createwalletdescriptor('mweb')

        self.log.info("Sending to the upgraded wallet's MWEB address")
        mweb_addr = wallet.getnewaddress(address_type='mweb')
        tx1_id = miner.sendtoaddress(mweb_addr, 25)
        node.syncwithvalidationinterfacequeue()
        tx1 = wallet.gettransaction(txid=tx1_id)
        assert_equal(tx1['confirmations'], 0)
        assert_equal(tx1['amount'], Decimal('25'))
        assert_equal(tx1['details'][0]['address'], mweb_addr)
        self.generate(node, 1, sync_fun=self.no_op)
        node.syncwithvalidationinterfacequeue()

        self.log.info("Spending the upgraded wallet's MWEB coins")
        mining_mweb_addr = miner.getnewaddress(address_type='mweb')
        tx2_id = wallet.sendtoaddress(mining_mweb_addr, 10)
        self.generate(node, 1, sync_fun=self.no_op)
        node.syncwithvalidationinterfacequeue()
        tx2 = miner.gettransaction(txid=tx2_id)
        assert_equal(tx2['confirmations'], 1)
        assert_equal(tx2['amount'], Decimal('10'))
        assert_equal(tx2['details'][0]['address'], mining_mweb_addr)


if __name__ == '__main__':
    MWEBWalletUpgradeTest(__file__).main()
