#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB wallet behavior on top of an AssumeUTXO snapshot."""

import os
from decimal import Decimal

from test_framework.assumeutxo_util import build_assumeutxo_base_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    ASSUMEUTXO_MWEB_HDKEY_TPRV,
    ASSUMEUTXO_MWEB_PEGIN_AMOUNT,
    ASSUMEUTXO_FIRST_MWEB_HEIGHT,
    MWEB_VB_START_TIME,
    SNAPSHOT_BASE_MWEB,
    assert_assumeutxo_mweb_dump,
    assert_mweb_utxo_scan_stats,
    broadcast_assumeutxo_pegin,
    generate_deterministic_blocks,
    get_mweb_account_descriptor,
    get_mweb_account_checksum,
    init_assumeutxo_mweb_wallet,
    init_named_assumeutxo_mweb_wallet,
    restart_node_for_mweb_extension,
    with_assumeutxo_mweb_vbparams,
)
from test_framework.util import assert_equal


class WalletMWEBAssumeutxoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2
        self.rpc_timeout = 120
        self.extra_args = [
            ["-vbparams=mweb:-2:0"],
            with_assumeutxo_mweb_vbparams([]),
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def _wallet_mweb_state(self, wallet):
        coins = wallet.listunspent(minconf=1)
        return wallet.getbalance(), sorted((coin["txid"], coin["amount"], coin["address"]) for coin in coins)

    def _assert_same_wallet_state(self, wallet, expected_balance, expected_coins):
        balance, coins = self._wallet_mweb_state(wallet)
        assert_equal(balance, expected_balance)
        assert_equal(coins, expected_coins)

    def _assert_snapshot_active(self, node):
        chainstates = node.getchainstates()["chainstates"]
        assert_equal(len(chainstates), 2)
        assert_equal(chainstates[1]["blocks"], SNAPSHOT_BASE_MWEB)
        assert_equal(chainstates[1]["validated"], False)

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        self.log.info("Build AssumeUTXO base chain through height 299 with MWEB disabled")
        build_assumeutxo_base_chain(self, n0, sync_fun=self.no_op)

        self.log.info("Restart node0 with MWEB enabled and prepare the committed deterministic MWEB wallet")
        restart_node_for_mweb_extension(self, node_index=0)
        for node in self.nodes:
            node.setmocktime(MWEB_VB_START_TIME)

        init_assumeutxo_mweb_wallet(self, node=0)
        observer = init_named_assumeutxo_mweb_wallet(
            self,
            node=0,
            wallet_name="mweb_observer",
            import_coinbase=False,
        )

        self.log.info("Mine the committed MWEB AssumeUTXO chain through the first MWEB block")
        generate_deterministic_blocks(
            self,
            n0,
            ASSUMEUTXO_FIRST_MWEB_HEIGHT - 1 - n0.getblockcount(),
            sync_fun=self.no_op,
        )
        broadcast_assumeutxo_pegin(self, n0, sync_fun=self.no_op)

        self.log.info("Advance to the committed MWEB snapshot height")
        generate_deterministic_blocks(self, n0, SNAPSHOT_BASE_MWEB - n0.getblockcount(), sync_fun=self.no_op)
        assert_equal(n0.getblockcount(), SNAPSHOT_BASE_MWEB)

        # Peg-in is to committed HD index 0; observer shares the key without L1 coinbase.
        # Widen stealth indices so source state matches importdescriptors UTXO-scan coverage.
        observer.mwebscanutxoset(get_mweb_account_checksum(observer), 0, 100)
        source_balance, source_coins = self._wallet_mweb_state(observer)
        assert source_balance >= Decimal(str(ASSUMEUTXO_MWEB_PEGIN_AMOUNT)), source_balance
        assert len(source_coins) > 0

        backup_a = os.path.join(self.options.tmpdir, "mweb_restore_a.dat")
        observer.backupwallet(backup_a)

        self.log.info("Create the committed MWEB AssumeUTXO snapshot")
        snapshot = n0.dumptxoutset("mweb_wallet_assumeutxo.dat", "latest")
        assert_assumeutxo_mweb_dump(snapshot)

        self.log.info("Provide headers and the base block required for snapshot activation")
        for height in range(1, SNAPSHOT_BASE_MWEB + 1):
            n1.submitheader(n0.getblock(n0.getblockhash(height), 0))
        n1.submitblock(n0.getblock(snapshot["base_hash"], 0))

        self.log.info("Load the MWEB snapshot on node1")
        loaded = n1.loadtxoutset(snapshot["path"])
        assert_equal(loaded["base_height"], SNAPSHOT_BASE_MWEB)
        self._assert_snapshot_active(n1)

        self.log.info("Cold wallet: bare mwebscanutxoset recovers without prior window scan")
        n1.createwallet("mweb_cold", blank=True)
        cold = n1.get_wallet_rpc("mweb_cold")
        xpub = cold.addhdkey(ASSUMEUTXO_MWEB_HDKEY_TPRV)['xpub']
        cold.createwalletdescriptor('mweb', {'hdkey': xpub})
        assert_equal(cold.getbalance(), 0)
        cold_stats = cold.mwebscanutxoset()
        assert cold_stats['success'], cold_stats
        assert cold_stats['matched'] >= 1, cold_stats
        assert 'warnings' not in cold_stats, cold_stats
        assert_equal(cold.getbalance(), source_balance)
        assert_mweb_utxo_scan_stats(cold)

        self.log.info("Fresh importdescriptors on snapshot node returns deferred-history warning")
        account = get_mweb_account_descriptor(observer, private=True)
        n1.createwallet("assume_import", blank=True)
        importer = n1.get_wallet_rpc("assume_import")
        result = importer.importdescriptors([{
            "desc": account['desc'],
            "timestamp": account['timestamp'],
            "active": True,
        }])
        assert result[0]['success'], result[0]
        assert 'warnings' in result[0]
        assert any('deferred' in w.lower() or 'chainstate' in w.lower() for w in result[0]['warnings'])
        assert_equal(importer.getbalance(), source_balance)
        assert_mweb_utxo_scan_stats(importer)

        self.log.info("loadwallet on snapshot node (recover via mwebscanutxoset)")
        backup_load = os.path.join(self.options.tmpdir, "mweb_loadwallet.dat")
        observer.backupwallet(backup_load)
        n1.restorewallet("mweb_loadwallet", backup_load)
        n1.unloadwallet("mweb_loadwallet")
        n1.loadwallet("mweb_loadwallet")
        loaded = n1.get_wallet_rpc("mweb_loadwallet")
        loaded.mwebscanutxoset()
        self._assert_same_wallet_state(loaded, source_balance, source_coins)
        assert_mweb_utxo_scan_stats(loaded)

        self.log.info("Restore the same backed-up MWEB wallet into two independent wallet instances")
        n1.restorewallet("mweb_restore_a", backup_a)
        n1.restorewallet("mweb_restore_b", backup_a)
        restored_a = n1.get_wallet_rpc("mweb_restore_a")
        restored_b = n1.get_wallet_rpc("mweb_restore_b")
        restored_a.mwebscanutxoset()
        restored_b.mwebscanutxoset()
        self._assert_same_wallet_state(restored_a, source_balance, source_coins)
        self._assert_same_wallet_state(restored_b, source_balance, source_coins)

        self.log.info("Reload both restored wallets and verify snapshot-backed MWEB state is stable")
        n1.unloadwallet("mweb_restore_a")
        n1.unloadwallet("mweb_restore_b")
        n1.loadwallet("mweb_restore_a")
        n1.loadwallet("mweb_restore_b")
        restored_a = n1.get_wallet_rpc("mweb_restore_a")
        restored_b = n1.get_wallet_rpc("mweb_restore_b")
        restored_a.mwebscanutxoset()
        restored_b.mwebscanutxoset()
        self._assert_same_wallet_state(restored_a, source_balance, source_coins)
        self._assert_same_wallet_state(restored_b, source_balance, source_coins)


if __name__ == "__main__":
    WalletMWEBAssumeutxoTest(__file__).main()
