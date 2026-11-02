#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB wallet UTXO-set scan on synced regtest (import + idempotency)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    assert_mweb_utxo_scan_stats,
    get_mweb_account_descriptor,
    mweb_extra_args,
    reconnect_mweb_peers,
)
from test_framework.util import assert_equal, assert_greater_than_or_equal, wallet_importprivkey


class WalletMWEBUtxoScanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.rpc_timeout = 120
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], [])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _mweb_balance(self, wallet):
        return sum(
            coin['amount']
            for coin in wallet.listunspent(minconf=1)
            if coin.get('address', '').startswith('tmweb')
        )

    def _mweb_unspent(self, wallet):
        return sorted(
            (coin['amount'], coin['address'])
            for coin in wallet.listunspent(minconf=1)
            if coin.get('address', '').startswith('tmweb')
        )

    def _fund_mweb_wallet(self, n0, wallet):
        wallet_importprivkey(wallet, n0.get_deterministic_priv_key().key, 0, label="coinbase")
        self.generate(n0, 430)
        addr = wallet.getnewaddress(address_type='mweb')
        pegin1 = wallet.sendtoaddress(addr, 10)
        assert_equal(set(n0.getrawmempool()), set())
        wallet.abandontransaction(pegin1)
        self.generate(n0, 1)
        reconnect_mweb_peers(self)
        wallet.sendtoaddress(addr, 10)
        self.generate(n0, 10)
        self.sync_all()

    def run_test(self):
        n0 = self.nodes[0]

        self.log.info("Path 1: synced import + UTXO scan RPC")
        n0.createwallet("sync_src")
        src = n0.get_wallet_rpc("sync_src")
        self._fund_mweb_wallet(n0, src)

        baseline_balance = self._mweb_balance(src)
        baseline_coins = self._mweb_unspent(src)
        account = get_mweb_account_descriptor(src, private=True)
        assert account

        n0.createwallet("sync_import", blank=True)
        importer = n0.get_wallet_rpc("sync_import")
        result = importer.importdescriptors([{
            "desc": account['desc'],
            "timestamp": account['timestamp'],
            "active": True,
        }])
        assert result[0]['success']

        assert_equal(self._mweb_balance(importer), baseline_balance)
        assert_equal(self._mweb_unspent(importer), baseline_coins)
        assert_mweb_utxo_scan_stats(importer)
        assert_greater_than_or_equal(len(importer.listtransactions()), 1)

        self.log.info("Path 5: repeated mwebscanutxoset is idempotent")
        first = assert_mweb_utxo_scan_stats(importer)
        balance = self._mweb_balance(importer)
        second = importer.mwebscanutxoset()
        assert second['success']
        assert_equal(second['persisted'], 0)

        n0.unloadwallet("sync_import")
        n0.loadwallet("sync_import")
        importer = n0.get_wallet_rpc("sync_import")
        assert_equal(self._mweb_balance(importer), balance)
        assert_equal(self._mweb_unspent(importer), baseline_coins)
        assert first['matched'] >= 1


if __name__ == "__main__":
    WalletMWEBUtxoScanTest(__file__).main()
