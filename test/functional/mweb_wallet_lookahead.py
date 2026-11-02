#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the MWEB address lookahead.

Each MWEB account watches -mwebkeypool unused addresses from its next index, as
L1 watches -keypool scripts. A payment to a watched address is found as soon as
it is mined, even when another copy of the keys handed the address out, and
moves the window past it.
"""

from decimal import Decimal
import time

from test_framework.mweb_device import MWEBDevice
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    get_mweb_account_checksum,
    get_mweb_account_descriptor,
    init_mweb_wallet,
    mweb_extra_args,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

KEYPOOL = 100
SMALL_KEYPOOL = 5
# A new account hands out receive addresses from index 2; 0 and 1 are change and peg-in.
FIRST_INDEX = 2
# Last index a bare mwebscanutxoset probes before any lookahead.
UTXO_SCAN_RANGE_END = 1000
MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"


class MWEBWalletLookaheadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([f"-keypool={KEYPOOL}"])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def pay(self, address, amount=1):
        self.funding.sendtoaddress(address, amount)
        self.generate(self.nodes[0], 1)

    def issue(self, wallet, issued, last_index):
        """Extend issued, indexed by MWEB address index, with the wallet's addresses through last_index."""
        if not issued:
            issued.extend([None] * FIRST_INDEX)
        while len(issued) <= last_index:
            issued.append(wallet.getnewaddress(address_type="mweb"))
        return issued

    def copy_of(self, issuer, name):
        """A wallet given the issuer's MWEB account after the issuer handed out its addresses."""
        node = self.nodes[0]
        node.createwallet(wallet_name=name, blank=True)
        copy = node.get_wallet_rpc(name)
        account = get_mweb_account_descriptor(issuer, private=True)["desc"]
        assert copy.importdescriptors([{"desc": account, "timestamp": "now", "active": True}])[0]["success"]
        return copy

    def run_test(self):
        node = self.nodes[0]
        generate(node, FIRST_MWEB_HEIGHT - 1)
        self.funding = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="issuer")
        issuer = node.get_wallet_rpc("issuer")

        self.log.info("A copy of the keys finds a payment to an address only the other copy handed out")
        issued = self.issue(issuer, [], 4 * KEYPOOL)
        copy = self.copy_of(issuer, "copy")
        last_watched = FIRST_INDEX + KEYPOOL - 1
        self.pay(issued[last_watched])
        coin, = copy.listunspent()
        assert_equal((coin["address"], coin["amount"]), (issued[last_watched], Decimal("1")))
        assert issued[last_watched] in copy.getaddressesbylabel("")

        self.log.info("Each payment moves the window past it")
        paid = [last_watched]
        for _ in range(2):
            paid.append(paid[-1] + KEYPOOL)
            self.pay(issued[paid[-1]])
        assert_equal(sorted(c["address"] for c in copy.listunspent()), sorted(issued[i] for i in paid))

        self.log.info("Payments the window reaches only through other payments in the same block are found")
        # Outputs are ordered by id, so four chained payments come in ascending order 1 time in 24.
        self.issue(issuer, issued, paid[-1] + 4 * KEYPOOL)
        for _ in range(4):
            paid.append(paid[-1] + KEYPOOL)
            self.funding.sendtoaddress(issued[paid[-1]], 1)
        self.generate(node, 1)
        assert_equal(sorted(c["address"] for c in copy.listunspent()), sorted(issued[i] for i in paid))

        self.log.info("A payment just past the window is found only by a rescan")
        past_window = paid[-1] + 1 + KEYPOOL
        self.issue(issuer, issued, past_window + 1)
        self.pay(issued[past_window])
        assert issued[past_window] not in [c["address"] for c in copy.listunspent()]
        copy.mwebrescan(get_mweb_account_checksum(copy), 0, past_window)
        assert issued[past_window] in [c["address"] for c in copy.listunspent()]
        assert_equal(copy.getnewaddress(address_type="mweb"), issued[past_window + 1])

        self.log.info("A watch-only copy finds payments to addresses the signing device handed out")
        device = MWEBDevice(MNEMONIC)
        node.createwallet(wallet_name="device", blank=True)
        device_wallet = node.get_wallet_rpc("device")
        assert device_wallet.importdescriptors([{"desc": device.private_descriptor(), "timestamp": "now", "active": True}])[0]["success"]
        node.createwallet(wallet_name="watcher", blank=True, disable_private_keys=True)
        watcher = node.get_wallet_rpc("watcher")
        assert watcher.importdescriptors([{"desc": device.public_descriptor(), "timestamp": "now", "active": True}])[0]["success"]
        shown = self.issue(device_wallet, [], FIRST_INDEX + KEYPOOL - 1)
        self.pay(shown[-1], 2)
        coin, = watcher.listunspent()
        assert_equal((coin["address"], coin["amount"]), (shown[-1], Decimal("2")))

        self.log.info("-mwebkeypool sets the window size")
        self.restart_node(0, extra_args=self.extra_args[0] + [f"-mwebkeypool={SMALL_KEYPOOL}"])
        if self.default_wallet_name not in node.listwallets():
            node.loadwallet(self.default_wallet_name)
        self.funding = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="small_issuer")
        small_issuer = node.get_wallet_rpc("small_issuer")
        small_issued = self.issue(small_issuer, [], FIRST_INDEX + 2 * SMALL_KEYPOOL)
        small = self.copy_of(small_issuer, "small")
        self.pay(small_issued[FIRST_INDEX + SMALL_KEYPOOL])
        assert_equal(small.listunspent(), [])
        self.pay(small_issued[FIRST_INDEX + SMALL_KEYPOOL - 1])
        assert_equal([c["address"] for c in small.listunspent()], [small_issued[FIRST_INDEX + SMALL_KEYPOOL - 1]])

        self.log.info("A UTXO set scan finds coins its index range reaches only through the lookahead of other coins")
        node.createwallet(wallet_name="utxo_issuer")
        utxo_issuer = node.get_wallet_rpc("utxo_issuer")
        # The scan probes indices 0..1000; each later coin is one window past the one before it.
        chain = [UTXO_SCAN_RANGE_END + i * SMALL_KEYPOOL for i in range(4)]
        utxo_issued = self.issue(utxo_issuer, [], chain[-1])
        for index in chain:
            self.funding.sendtoaddress(utxo_issued[index], 1)
        self.generate(node, 1)
        # Move past the import's rescan window, so only the UTXO set scan can find the coins.
        # Blocks from the future stop the node from restarting, so this comes last.
        node.setmocktime(int(time.time()) + 3 * 60 * 60)
        self.generate(node, 1)
        utxo_copy = self.copy_of(utxo_issuer, "utxo_copy")
        assert_equal(utxo_copy.listunspent(), [])
        assert utxo_copy.mwebscanutxoset()["success"]
        assert_equal(sorted(c["address"] for c in utxo_copy.listunspent()), sorted(utxo_issued[i] for i in chain))


if __name__ == '__main__':
    MWEBWalletLookaheadTest(__file__).main()
