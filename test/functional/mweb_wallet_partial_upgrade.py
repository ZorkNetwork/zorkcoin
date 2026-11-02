#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test upgrading partial MWEB wallet entries when the full tx later reappears."""

import shutil
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class MWEBWalletPartialUpgradeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(['-keypool=100'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setting up MWEB funds in the sender wallet")
        setup_mweb_chain(node)
        for output_count in (1, 2):
            self.check_partial_upgrade(output_count)

    def check_partial_upgrade(self, output_count):
        node = self.nodes[0]
        self.log.info("Checking %s partial receives merging into one full transaction", output_count)
        self.log.info("Creating and snapshotting a receiver wallet before the receive")
        receiver_name = f"receiver_{output_count}"
        node.createwallet(receiver_name)
        self.stop_node(0)
        snapshot_name = self.snapshot_wallet(self.nodes[0], receiver_name)
        self.start_node(0, self.extra_args[0])
        node = self.nodes[0]
        sender_wallet = node.get_wallet_rpc(self.default_wallet_name)
        receiver_wallet = self.get_or_load_wallet(node, receiver_name)

        self.log.info("Receive and confirm an MWEB transaction")
        amount = Decimal("0.5")
        addresses = [receiver_wallet.getnewaddress(address_type="mweb") for _ in range(output_count)]
        recipients = {address: amount / output_count for address in addresses}
        txid = sender_wallet.sendmany("", recipients)
        sender_tx_hex = sender_wallet.gettransaction(txid)["hex"]
        blockhash = self.generate(node, 1, sync_fun=self.no_op)[0]
        confirmed_tx = receiver_wallet.gettransaction(txid)
        assert_equal(confirmed_tx["amount"], amount)
        assert_equal(confirmed_tx["confirmations"], 1)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        self.assert_total_mine_balance(receiver_wallet, amount)
        expected_outputs = {
            coin["address"]: coin["output_id"]
            for coin in receiver_wallet.listunspent(addresses=addresses)
        }
        assert_equal(set(expected_outputs), set(addresses))
        original_history = self.assert_receive_history(receiver_wallet, recipients, expected_outputs, txid, 1)
        original_order = [entry["mweb_out"] for entry in original_history]

        self.log.info("Restore the receiver wallet snapshot and rescan into the partial state")
        self.stop_node(0)
        self.restore_wallet(self.nodes[0], receiver_name, snapshot_name)
        self.start_node(0, self.extra_args[0])
        node = self.nodes[0]
        sender_wallet = node.get_wallet_rpc(self.default_wallet_name)
        receiver_wallet = self.get_or_load_wallet(node, receiver_name)
        receiver_wallet.rescanblockchain(0)

        assert_equal(receiver_wallet.getwalletinfo()["txcount"], output_count)
        self.assert_total_mine_balance(receiver_wallet, amount)
        assert self.find_listwallettransactions_entry(receiver_wallet, txid) is None
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", receiver_wallet.gettransaction, txid)
        partial_history = self.assert_receive_history(receiver_wallet, recipients, expected_outputs, None, 1)
        partial_ids = {entry["txid"] for entry in partial_history}
        assert_equal(len(partial_ids), output_count)

        self.log.info("Invalidate the block and rebroadcast the full transaction")
        node.invalidateblock(blockhash)
        assert_equal(node.sendrawtransaction(sender_tx_hex), txid)
        self.wait_until(lambda: txid in node.getrawmempool())
        self.wait_until(lambda: self.has_wallet_transaction(receiver_wallet, txid))
        node.syncwithvalidationinterfacequeue()

        mempool_tx = receiver_wallet.gettransaction(txid)
        assert_equal(mempool_tx["amount"], amount)
        assert_equal(mempool_tx["confirmations"], 0)
        if receiver_wallet.getwalletinfo()["txcount"] != 1:
            self.log.info("Receiver after rebroadcast: balances=%s; history=%s",
                          receiver_wallet.getbalances(), receiver_wallet.listtransactions(count=1000))
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        self.assert_total_mine_balance(receiver_wallet, amount)
        mempool_history = self.assert_receive_history(receiver_wallet, recipients, expected_outputs, txid, 0)
        assert_equal([entry["mweb_out"] for entry in mempool_history], original_order)
        assert partial_ids.isdisjoint({entry["txid"] for entry in receiver_wallet.listwallettransactions()})

        self.log.info("Reconfirm the transaction and ensure the partial entry was upgraded in place")
        node.reconsiderblock(blockhash)
        self.wait_until(lambda: node.getbestblockhash() == blockhash)
        self.wait_until(lambda: receiver_wallet.gettransaction(txid)["confirmations"] == 1)
        node.syncwithvalidationinterfacequeue()

        final_tx = receiver_wallet.gettransaction(txid)
        assert_equal(final_tx["amount"], amount)
        assert_equal(final_tx["confirmations"], 1)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        assert_equal(receiver_wallet.getbalances()["mine"]["trusted"], amount)
        self.assert_total_mine_balance(receiver_wallet, amount)
        final_history = self.assert_receive_history(receiver_wallet, recipients, expected_outputs, txid, 1)
        assert_equal([entry["mweb_out"] for entry in final_history], original_order)

        self.log.info("Reload and rescan preserve the merged transaction without obsolete partial rows")
        node.unloadwallet(receiver_name)
        receiver_wallet = self.get_or_load_wallet(node, receiver_name)
        receiver_wallet.rescanblockchain(0)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        assert_equal(receiver_wallet.gettransaction(txid)["amount"], amount)
        assert_equal(receiver_wallet.getbalances()["mine"]["trusted"], amount)
        receives = [row for row in receiver_wallet.listtransactions(count=1000) if row["category"] == "receive"]
        assert_equal(len(receives), output_count)
        assert_equal({row["txid"] for row in receives}, {txid})
        assert_equal(len({row["mweb_out"] for row in receives}), output_count)
        reloaded_history = self.assert_receive_history(receiver_wallet, recipients, expected_outputs, txid, 1)
        assert_equal([entry["mweb_out"] for entry in reloaded_history], original_order)

    def assert_receive_history(self, wallet, recipients, expected_outputs, txid, confirmations):
        history = wallet.listwallettransactions()
        assert_equal(len(history), len(recipients))
        assert_equal({entry["address"] for entry in history}, set(recipients))
        assert_equal({entry["mweb_out"] for entry in history}, set(expected_outputs.values()))
        for entry in history:
            address = entry["address"]
            assert_equal(entry["type"], "RecvWithAddress")
            assert_equal(entry["amount"], recipients[address])
            assert_equal(entry["net"], recipients[address])
            assert_equal(entry["mweb_out"], expected_outputs[address])
            assert_equal(entry["confirmations"], confirmations)
            assert "fee" not in entry and "vout" not in entry and "pegout" not in entry
            if txid is not None:
                assert_equal(entry["txid"], txid)
            if confirmations == 0:
                assert_equal(entry["trusted"], False)
        coins = wallet.listunspent(minconf=0, addresses=list(recipients))
        assert_equal({coin["output_id"] for coin in coins}, set(expected_outputs.values()))
        assert_equal(len(coins), len(recipients))
        for coin in coins:
            assert_equal(coin["amount"], recipients[coin["address"]])
            assert_equal(coin["confirmations"], confirmations)
        safe_coins = wallet.listunspent(minconf=0, addresses=list(recipients), include_unsafe=False)
        assert_equal({coin["output_id"] for coin in safe_coins},
                     set(expected_outputs.values()) if confirmations > 0 else set())
        mine = wallet.getbalances()["mine"]
        total = sum(recipients.values())
        assert_equal(mine["trusted"], total if confirmations > 0 else 0)
        assert_equal(mine["untrusted_pending"], total if confirmations == 0 else 0)
        assert_equal(mine["immature"], 0)
        return history

    def get_or_load_wallet(self, node, wallet_name):
        if wallet_name not in node.listwallets():
            node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def snapshot_wallet(self, node, wallet_name, suffix="snapshot"):
        wallet_dir = node.wallets_path
        src_path = wallet_dir / wallet_name
        snapshot_name = f"{wallet_name}_{suffix}"
        dst_path = wallet_dir / snapshot_name
        if dst_path.exists():
            shutil.rmtree(dst_path)
        shutil.copytree(src_path, dst_path)
        return snapshot_name

    def restore_wallet(self, node, wallet_name, snapshot_name):
        wallet_dir = node.wallets_path
        wallet_path = wallet_dir / wallet_name
        snapshot_path = wallet_dir / snapshot_name
        if wallet_path.exists():
            shutil.rmtree(wallet_path)
        shutil.copytree(snapshot_path, wallet_path)

    def assert_total_mine_balance(self, wallet, expected):
        mine_balances = wallet.getbalances()["mine"]
        total = (
            mine_balances.get("trusted", Decimal("0")) +
            mine_balances.get("untrusted_pending", Decimal("0")) +
            mine_balances.get("immature", Decimal("0"))
        )
        assert_equal(total, expected)

    def has_wallet_transaction(self, wallet, txid):
        try:
            wallet.gettransaction(txid)
            return True
        except JSONRPCException:
            return False

    def find_listwallettransactions_entry(self, wallet, txid):
        for entry in wallet.listwallettransactions():
            if entry.get("txid") == txid:
                return entry
        return None


if __name__ == '__main__':
    MWEBWalletPartialUpgradeTest(__file__).main()
