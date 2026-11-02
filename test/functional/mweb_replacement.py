#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replacing a transaction that carries MWEB data needs 1.5x its fee rate.

Fee rates are fee over adjusted weight (L1 weight plus MWEB weight). A send
from the wallet pays an MWEB-only transaction exactly 100 per MWEB weight unit,
so a new send can only replace one by adding an L1 peg-out output that fee_rate
charges for. The rule also covers L1-only and package replacements of peg-ins.

bumpfee and psbtbumpfee pay that rate, adding the extra fee to the kernel, and
keep the original's inputs and recipients.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBReplacementTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def build(self, coin, outputs, fee_rate=None):
        if isinstance(coin, str):
            coin = {"output_id": coin}
        res = self.nodes[0].send(
            outputs=outputs,
            fee_rate=fee_rate,
            options={"inputs": [coin], "add_inputs": False, "add_to_wallet": False},
        )
        assert res["complete"]
        return res["hex"]

    def assert_rejected(self, tx_hex):
        res = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "insufficient fee")
        assert "1.5x" in res["reject-details"], res

    def rate(self, txid):
        """Fee rate in satoshis per adjusted weight unit (L1 weight plus MWEB weight)."""
        entry = self.nodes[0].getmempoolentry(txid)
        return entry["fees"]["modified"] * COIN / (entry["weight"] + entry["mwebweight"])

    def assert_pays_1_5x(self, txid, old_entry):
        """The replacement's fee over adjusted weight is at least 1.5x the replaced entry's."""
        new_entry = self.nodes[0].getmempoolentry(txid)
        new_fee, old_fee = (int(e["fees"]["base"] * COIN) for e in (new_entry, old_entry))
        new_weight, old_weight = (e["weight"] + e["mwebweight"] for e in (new_entry, old_entry))
        assert 2 * new_fee * old_weight >= 3 * old_fee * new_weight, (new_entry, old_entry)

    def assert_keeps(self, txid, original_vin, dest, amount):
        """The replacement spends every original input and still pays dest the amount."""
        node = self.nodes[0]
        vin = node.getrawtransaction(txid, 1)["vin"]
        for original in original_vin:
            assert any(all(i.get(k) == original.get(k) for k in ("txid", "vout", "output_id")) for i in vin), (original, vin)
        mweb = node.getmempoolentry(txid)["mweb"]
        info = node.getaddressinfo(dest)
        if info["ismweb"]:
            paid = {u["output_id"] for u in node.listunspent(minconf=0, addresses=[dest]) if u["amount"] == amount}
            assert paid & set(mweb["outputs"]), mweb
        else:
            assert {"amount": int(amount * COIN), "scriptpubkey": info["scriptPubKey"]} in mweb["pegouts"], mweb

    def child_of(self, parent_hex, address, fee):
        """Sign a child spending the parent's output to address, paying fee satoshis."""
        node = self.nodes[0]
        parent = node.decoderawtransaction(parent_hex)
        out = next(o for o in parent["vout"] if o["scriptPubKey"].get("address") == address)
        prevtx = {"txid": parent["txid"], "vout": out["n"], "scriptPubKey": out["scriptPubKey"]["hex"], "amount": out["value"]}
        child = node.createrawtransaction([{"txid": parent["txid"], "vout": out["n"]}],
                                          {node.getnewaddress(): out["value"] - Decimal(fee) / COIN})
        signed = node.signrawtransactionwithwallet(child, [prevtx])
        assert signed["complete"]
        return signed["hex"]

    def package_weight(self, *tx_hexes):
        return sum(self.nodes[0].decoderawtransaction(h)["weight"] for h in tx_hexes)

    def assert_replaces(self, tx_hex, replaced_txid, maxfeerate=None):
        node = self.nodes[0]
        txid = node.sendrawtransaction(tx_hex, maxfeerate)
        mempool = node.getrawmempool()
        assert txid in mempool
        assert replaced_txid not in mempool
        return txid

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)

        coins = [u for u in node.listunspent() if u.get("output_id")]
        assert coins
        output_id = coins[0]["output_id"]
        mweb_dest = node.getnewaddress(address_type="mweb")
        mweb_dest2 = node.getnewaddress(address_type="mweb")
        l1_dest = node.getnewaddress()

        self.log.info("An MWEB-only send pays 100 per MWEB weight unit")
        original = node.sendrawtransaction(self.build(output_id, {mweb_dest: Decimal("0.1")}))
        entry = node.getmempoolentry(original)
        assert_equal(entry["weight"], 0)
        assert_equal(entry["mwebweight"], 39)
        assert_equal(entry["fees"]["base"], Decimal("0.00003900"))

        self.log.info("The wallet's MWEB-only replacement keeps that rate, so it is refused")
        self.assert_rejected(self.build(output_id, {mweb_dest: Decimal("0.1"), mweb_dest2: Decimal("0.1")}))

        self.log.info("A peg-out hybrid below 1.5x is refused; at or above it replaces")
        self.assert_rejected(self.build(output_id, {mweb_dest: Decimal("0.1"), l1_dest: Decimal("0.00001")}, fee_rate=500))

        self.log.info("A native MWEB descendant of the original loses with its parent")
        node.syncwithvalidationinterfacequeue()
        original_coin, = [u for u in node.listunspent(minconf=0, addresses=[mweb_dest])
                          if u['txid'] == original and u['amount'] == Decimal('0.1')]
        descendant = node.sendrawtransaction(self.build(
            original_coin['output_id'], {node.getnewaddress(address_type='mweb'): Decimal('0.05')}))
        assert_equal(node.getrawtransaction(descendant, 1)['vin'],
                     [{'ismweb': True, 'output_id': original_coin['output_id']}])
        assert_equal(node.getmempoolentry(descendant)['weight'], 0)
        assert_equal(node.getmempoolentry(descendant)['ancestorcount'], 2)
        assert_equal(node.getmempoolentry(original)['descendantcount'], 2)
        first = self.assert_replaces(
            self.build(output_id, {mweb_dest: Decimal("0.1"), l1_dest: Decimal("0.00001")}, fee_rate=800), original)
        assert descendant not in node.getrawmempool()
        node.syncwithvalidationinterfacequeue()
        for txid in (original, descendant):
            removed = node.gettransaction(txid)
            assert_equal(removed['confirmations'], 0)
            assert_equal(removed['trusted'], False)

        self.log.info("The next replacement needs 1.5x again, not just a higher fee rate")
        first_entry = node.getmempoolentry(first)
        first_rate = first_entry["fees"]["base"] / (first_entry["weight"] + first_entry["mwebweight"])
        assert first_rate > Decimal("0.00000150")
        self.assert_rejected(self.build(output_id, {mweb_dest: Decimal("0.1"), l1_dest: Decimal("0.00001")}, fee_rate=1000))
        second = self.assert_replaces(
            self.build(output_id, {mweb_dest: Decimal("0.1"), l1_dest: Decimal("0.00001")}, fee_rate=1500), first)
        winning_hex = node.getrawtransaction(second)
        winning_block = self.generate(node, 1)[0]
        assert second not in node.getrawmempool()

        def assert_conflict_state(*, confirmed):
            node.syncwithvalidationinterfacequeue()
            transactions = {txid: node.gettransaction(txid) for txid in (original, first, second, descendant)}
            self.log.info("MWEB replacement state (confirmed=%s): %s", confirmed,
                          {txid: {key: tx[key] for key in ('confirmations', 'walletconflicts')}
                           for txid, tx in transactions.items()})
            for txid in (original, first, second):
                tx = transactions[txid]
                assert_equal(set(tx['walletconflicts']), {original, first, second} - {txid})
                assert_equal(tx['confirmations'], (1 if txid == second else -1) if confirmed else 0)
                if confirmed and txid == second:
                    assert_equal(tx['blockhash'], winning_block)
                else:
                    assert 'blockhash' not in tx
                if txid != second:
                    assert_equal(tx['trusted'], False)
            child = transactions[descendant]
            assert_equal(child['confirmations'], -1 if confirmed else 0)
            # The descendant inherits its parent's state; it spends a distinct
            # output and has no direct double-spend relation to the winner.
            assert_equal(child['walletconflicts'], [])
            assert_equal(child['trusted'], False)
            assert 'blockhash' not in child
            assert descendant not in node.getrawmempool()

        assert_conflict_state(confirmed=True)
        self.log.info("Confirmed MWEB conflict state survives wallet reload on daemon restart")
        # Keep the persisted mempool's winner fixed across reloads; wallet
        # rebroadcast must not choose a different unconfirmed candidate.
        self.restart_node(0, extra_args=self.extra_args[0] + ['-walletbroadcast=0'])
        node = self.nodes[0]
        assert_conflict_state(confirmed=True)

        self.log.info("Disconnecting the winner clears inherited block conflicts")
        node.invalidateblock(winning_block)
        # The aggregate extension block does not reconstruct its original
        # per-transaction bodies when disconnected after a restart.
        assert_equal(node.getrawmempool(), [])
        assert_conflict_state(confirmed=False)
        self.log.info("Resubmit the same known winner before reloading unconfirmed conflict state")
        assert_equal(node.sendrawtransaction(winning_hex), second)
        assert_equal(set(node.getrawmempool()), {second})
        assert_conflict_state(confirmed=False)
        self.restart_node(0, extra_args=self.extra_args[0] + ['-walletbroadcast=0'])
        node = self.nodes[0]
        assert_equal(set(node.getrawmempool()), {second})
        assert_conflict_state(confirmed=False)

        self.log.info("Reconfirming the same winner restores direct and descendant conflict state")
        node.reconsiderblock(winning_block)
        assert_equal(node.getbestblockhash(), winning_block)
        assert_equal(node.getrawmempool(), [])
        assert_conflict_state(confirmed=True)
        self.restart_node(0)
        node = self.nodes[0]
        assert_conflict_state(confirmed=True)

        self.log.info("An L1-only replacement of a peg-in needs 1.5x the peg-in's fee rate")
        l1_coins = sorted((u for u in node.listunspent() if not u.get("output_id")), key=lambda u: u["amount"])
        coin = {"txid": l1_coins[-1]["txid"], "vout": l1_coins[-1]["vout"]}
        pegin = node.sendrawtransaction(self.build(coin, {mweb_dest: Decimal("0.1")}, fee_rate=10))
        pegin_entry = node.getmempoolentry(pegin)
        assert pegin_entry["weight"] > 0 and pegin_entry["mwebweight"] > 0
        # Five payees make the replacement heavier, so Rules 3 and 4 pass and only the 1.5x step refuses it.
        payees = {node.getnewaddress(): Decimal("0.01") for _ in range(5)}
        pegin_rate = self.rate(pegin)
        self.assert_rejected(self.build(coin, payees, fee_rate=int(pegin_rate * 4 * Decimal("1.3"))))
        l1_replacement = self.assert_replaces(self.build(coin, payees, fee_rate=int(pegin_rate * 4 * Decimal("1.7")) + 1), pegin)
        assert self.rate(l1_replacement) >= pegin_rate * Decimal("1.5")

        self.log.info("A package replacing a peg-in needs 1.5x the peg-in's fee rate")
        coin = {"txid": l1_coins[-2]["txid"], "vout": l1_coins[-2]["vout"]}
        pegin = node.sendrawtransaction(self.build(coin, {mweb_dest: Decimal("0.1")}, fee_rate=10))
        pegin_rate = self.rate(pegin)
        parent_address = node.getnewaddress()
        parent = self.build(coin, {parent_address: Decimal("0.5")}, fee_rate=1)
        parent_fee = int((l1_coins[-2]["amount"] - sum(o["value"] for o in node.decoderawtransaction(parent)["vout"])) * COIN)
        weight = self.package_weight(parent, self.child_of(parent, parent_address, 1000))
        for factor, accepted in ((Decimal("1.3"), False), (Decimal("1.7"), True)):
            child_fee = int(pegin_rate * factor * weight) - parent_fee
            res = node.submitpackage([parent, self.child_of(parent, parent_address, child_fee)])
            if accepted:
                assert_equal(res["package_msg"], "success")
                assert pegin not in node.getrawmempool()
            else:
                assert res["package_msg"].startswith("package RBF failed: insufficient anti-DoS fees"), res
                assert "1.5x" in res["package_msg"], res
                assert pegin in node.getrawmempool()
        self.generate(node, 1)

        self.log.info("bumpfee pays 1.5x the fee rate of MWEB-only, peg-in and peg-out sends")
        mweb_coins = sorted((u for u in node.listunspent() if u.get("output_id")), key=lambda u: u["amount"])
        l1_coin = max((u for u in node.listunspent() if not u.get("output_id")), key=lambda u: u["amount"])
        sends = [
            ("MWEB-only", {"output_id": mweb_coins[-1]["output_id"]}, mweb_dest2),
            ("peg-in", {"txid": l1_coin["txid"], "vout": l1_coin["vout"]}, mweb_dest),
            ("peg-out", {"output_id": mweb_coins[-2]["output_id"]}, l1_dest),
        ]
        for kind, coin, dest in sends:
            self.log.info(f"bumpfee replaces a {kind} send twice")
            txid = node.send(outputs={dest: Decimal("0.1")}, options={"inputs": [coin], "add_inputs": False})["txid"]
            assert node.getmempoolentry(txid)["mwebweight"] > 0
            original_vin = node.getrawtransaction(txid, 1)["vin"]
            assert_raises_rpc_error(-8, "not supported for transactions with MWEB data", node.bumpfee, txid,
                                    {"outputs": [{dest: Decimal("0.1")}]})
            for options in ({}, {"fee_rate": 200}):
                old_entry = node.getmempoolentry(txid)
                res = node.bumpfee(txid, options)
                assert_equal(res["origfee"], old_entry["fees"]["base"])
                txid = res["txid"]
                assert_equal(node.getmempoolentry(txid)["fees"]["base"], res["fee"])
                self.assert_pays_1_5x(txid, old_entry)
                self.assert_keeps(txid, original_vin, dest, Decimal("0.1"))

        self.generate(node, 1)

        self.log.info("psbtbumpfee needs PSBT version 2 for MWEB data, and its PSBT replaces the send")
        mweb_coin = max((u for u in node.listunspent() if u.get("output_id")), key=lambda u: u["amount"])
        txid = node.send(outputs={mweb_dest: Decimal("0.1")},
                         options={"inputs": [{"output_id": mweb_coin["output_id"]}], "add_inputs": False})["txid"]
        assert_raises_rpc_error(-8, "MWEB PSBTs require PSBT version 2", node.psbtbumpfee, txid, {"psbt_version": 0})
        old_entry = node.getmempoolentry(txid)
        original_vin = node.getrawtransaction(txid, 1)["vin"]
        res = node.psbtbumpfee(txid)
        signed = node.walletprocesspsbt(res["psbt"])
        assert signed["complete"]
        # Without L1 size, the raw-fee cap allows only one MWEB output's fee over the MWEB weight fee.
        assert_raises_rpc_error(-25, "Fee exceeds maximum", node.sendrawtransaction, signed["hex"])
        bumped = self.assert_replaces(signed["hex"], txid, maxfeerate=0)
        assert_equal(node.getmempoolentry(bumped)["fees"]["base"], res["fee"])
        self.assert_pays_1_5x(bumped, old_entry)
        self.assert_keeps(bumped, original_vin, mweb_dest, Decimal("0.1"))
        self.generate(node, 1)
        assert_equal(node.gettransaction(bumped)["confirmations"], 1)

        self.log.info("bumpfee replaces a peg-out to the wallet's own change address, which pays the fee")
        mweb_coin = max((u for u in node.listunspent() if u.get("output_id")), key=lambda u: u["amount"])
        change = node.getrawchangeaddress()
        txid = node.send(outputs={change: Decimal("0.1")},
                         options={"inputs": [{"output_id": mweb_coin["output_id"]}], "add_inputs": False})["txid"]
        old_entry = node.getmempoolentry(txid)
        res = node.bumpfee(txid)
        self.assert_pays_1_5x(res["txid"], old_entry)
        pegouts = node.getmempoolentry(res["txid"])["mweb"]["pegouts"]
        assert_equal([p["scriptpubkey"] for p in pegouts], [node.getaddressinfo(change)["scriptPubKey"]])
        assert_equal(pegouts[0]["amount"], int(Decimal("0.1") * COIN) - int(res["fee"] * COIN))


if __name__ == "__main__":
    MWEBReplacementTest(__file__).main()
