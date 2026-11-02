#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that wallets loaded on one node only see their own MWEB coins.

The node's MWEB view is shared, so each wallet must claim outputs only with its
own accounts, including after a rescan.
"""

from decimal import Decimal

from test_framework.mweb_util import FIRST_MWEB_HEIGHT, generate, init_mweb_wallet, list_mweb_account_checksums, mweb_extra_args
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletIsolationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(["-keypool=100"])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check(self, wallet, amount, address, other_address, other_txid):
        assert_equal([(c["address"], c["amount"]) for c in wallet.listunspent()], [(address, amount)])
        assert_equal(wallet.listunspent(addresses=[other_address]), [])
        assert_equal(wallet.getbalances()["mine"]["trusted"], amount)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", wallet.gettransaction, other_txid)

    def run_test(self):
        node = self.nodes[0]
        generate(node, FIRST_MWEB_HEIGHT - 1)
        funding = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="alice")
        node.createwallet(wallet_name="bob")
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")
        assert set(list_mweb_account_checksums(alice)).isdisjoint(list_mweb_account_checksums(bob))

        self.log.info("Each wallet sees only the coin paid to it")
        alice_address = alice.getnewaddress(address_type="mweb")
        bob_address = bob.getnewaddress(address_type="mweb")
        alice_txid = funding.sendtoaddress(alice_address, 1)
        bob_txid = funding.sendtoaddress(bob_address, 2)
        self.generate(node, 1)
        self.check(alice, Decimal("1"), alice_address, bob_address, bob_txid)
        self.check(bob, Decimal("2"), bob_address, alice_address, alice_txid)

        self.log.info("Rescans don't claim the other wallet's coin")
        for wallet in (alice, bob):
            wallet.rescanblockchain(0)
            for checksum in list_mweb_account_checksums(wallet):
                wallet.mwebrescan(checksum, 0, 100)
        self.check(alice, Decimal("1"), alice_address, bob_address, bob_txid)
        self.check(bob, Decimal("2"), bob_address, alice_address, alice_txid)

        self.log.info("Once spent, the coin leaves only its own wallet")
        payee = funding.getnewaddress(address_type="mweb")
        alice.sendtoaddress(address=payee, amount=1, subtractfeefromamount=True)
        self.generate(node, 1)
        assert_equal(alice.listunspent(), [])
        assert_equal(alice.getbalances()["mine"]["trusted"], 0)
        self.check(bob, Decimal("2"), bob_address, alice_address, alice_txid)


if __name__ == '__main__':
    MWEBWalletIsolationTest(__file__).main()
