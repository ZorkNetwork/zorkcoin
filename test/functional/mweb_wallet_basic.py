#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Basic MWEB Wallet test"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    init_mweb_wallet, generate, setup_mweb_chain, mweb_extra_args, with_mweb_vbparams,
    mweb_unspent_output_ids, decode_wallet_tx, mweb_vin_output_ids,
    assert_exact_mweb_inputs, assert_l1_inputs_include, assert_pegout_payments_include,
    assert_mweb_oids_spent,
)
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

# Litecoin-compatible MWEB kernel fee when a change output is present (weight units).
MWEB_FEE_WITH_CHANGE = Decimal('0.00003900')
# Two stealth outputs + kernel (no change): (18+18+3)*100 sat.
MWEB_FEE_TWO_OUT_NO_CHANGE = Decimal('0.00003900')
# Two stealth outputs + change + kernel: (18*3+3)*100 sat.
MWEB_FEE_TWO_OUT_WITH_CHANGE = Decimal('0.00005700')


class MWEBWalletBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'], [])  # immediate tx relay

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        self.log.info("Setting up MWEB chain")
        setup_mweb_chain(node0, self)

        #
        # Send to node1 mweb
        #
        self.log.info("Send to node1 mweb address")
        n1_addr = node1.getnewaddress(address_type='mweb')
        tx1_id = node0.sendtoaddress(n1_addr, 25)
        self.sync_mempools()

        self.log.info("Verify node0's wallet lists the transaction as spent")
        n0_tx1 = node0.gettransaction(txid=tx1_id)
        assert_equal(n0_tx1['confirmations'], 0)
        assert n0_tx1['amount'] == -25
        assert n0_tx1['fee'] < 0 and n0_tx1['fee'] > -0.1

        self.log.info("Verify node1's wallet receives the unconfirmed transaction")
        n1_addr_coins = node1.listreceivedbyaddress(minconf=0, address_filter=n1_addr)
        assert_equal(len(n1_addr_coins), 1)
        assert n1_addr_coins[0]['amount'] == 25
        assert n1_addr_coins[0]['confirmations'] == 0
        assert node1.getbalances()['mine']['untrusted_pending'] == 25
        assert node1.getbalances()['mine']['trusted'] == 0

        self.log.info("Mine the next block")
        generate(node0, 1)
        self.sync_blocks()

        self.log.info("Verify node1's wallet lists the transaction as confirmed")
        n1_addr_coins = node1.listunspent(addresses=[n1_addr])
        assert_equal(len(n1_addr_coins), 1)
        assert n1_addr_coins[0]['amount'] == 25
        assert n1_addr_coins[0]['confirmations'] == 1
        assert node1.getbalances()['mine']['untrusted_pending'] == 0
        assert node1.getbalances()['mine']['trusted'] == 25

        self.log.info("Verify node0's wallet lists the transaction as confirmed")
        n0_tx1 = node0.gettransaction(txid=tx1_id)
        assert_equal(n0_tx1['confirmations'], 1)
        assert n0_tx1['amount'] == -25
        assert n0_tx1['fee'] < 0 and n0_tx1['fee'] > -0.1

        self.log.info("Restart node1 with wallet broadcast disabled")
        self.restart_node(1, with_mweb_vbparams(['-whitelist=noban@127.0.0.1', '-walletbroadcast=0']))
        node1 = self.nodes[1]
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_all()

        #
        # Pegout to node2
        #
        self.log.info("Create a pegout and relay it with maxfeerate=0")
        n2_addr = node2.getnewaddress(address_type='bech32')
        tx2_id = node1.sendtoaddress(address=n2_addr, amount=15, fee_rate=10)
        tx2_hex = node1.gettransaction(txid=tx2_id)['hex']
        assert tx2_id not in node1.getrawmempool()
        tx2_accept = node1.testmempoolaccept([tx2_hex], 0)[0]
        assert_equal(tx2_accept['txid'], tx2_id)
        assert_equal(tx2_accept['allowed'], True)
        assert_equal(node1.sendrawtransaction(tx2_hex, 0), tx2_id)
        self.sync_mempools()

        self.log.info("Verify node1's wallet lists the transactions as spent")
        n1_tx2 = node1.gettransaction(txid=tx2_id)
        assert_equal(n1_tx2['confirmations'], 0)
        assert_equal(n1_tx2['amount'], -15)
        assert n1_tx2['fee'] < 0 and n1_tx2['fee'] > -0.1

        self.log.info("Verify node2's wallet receives the first pegout transaction")
        assert tx2_id in node2.getrawmempool()
        n2_tx2 = node2.gettransaction(tx2_id)
        assert_equal(n2_tx2['confirmations'], 0)
        assert_equal(n2_tx2['amount'], 15)
        assert tx2_id in node1.getrawmempool()

        #
        # Pegout to node2 using subtract fee from amount
        #
        self.log.info("Create a subtract-fee pegout and relay it with maxfeerate=0")
        n2_addr2 = node2.getnewaddress(address_type='bech32')
        tx3_id = node1.sendtoaddress(address=n2_addr2, amount=5, subtractfeefromamount=True)
        tx3_hex = node1.gettransaction(txid=tx3_id)['hex']
        assert tx3_id not in node1.getrawmempool()
        tx3_accept = node1.testmempoolaccept([tx3_hex], 0)[0]
        assert_equal(tx3_accept['txid'], tx3_id)
        assert_equal(tx3_accept['allowed'], True)
        assert_equal(node1.sendrawtransaction(tx3_hex, 0), tx3_id)
        self.sync_mempools()

        n1_tx3 = node1.gettransaction(txid=tx3_id)
        assert_equal(n1_tx3['confirmations'], 0)
        assert n1_tx3['amount'] > -5 and n1_tx3['amount'] < -4.9
        assert n1_tx3['fee'] < 0 and n1_tx3['fee'] > -0.1

        self.log.info("Verify node2's wallet receives the second pegout transaction")
        n2_addr2_coins = node2.listreceivedbyaddress(minconf=0, address_filter=n2_addr2)
        assert_equal(len(n2_addr2_coins), 1)
        assert n2_addr2_coins[0]['amount'] < 5 and n2_addr2_coins[0]['amount'] > 4.9
        assert_equal(n2_addr2_coins[0]['confirmations'], 0)
        assert tx3_id in node1.getrawmempool()

        self.log.info("Mine next block to make sure the transactions confirm successfully")
        generate(node0, 1)
        self.sync_all()
        assert tx2_id not in node1.getrawmempool()
        assert tx3_id not in node1.getrawmempool()

        n2_addr2_coins = node2.listreceivedbyaddress(minconf=0, address_filter=n2_addr2)
        assert_equal(len(n2_addr2_coins), 1)
        assert n2_addr2_coins[0]['amount'] < 5 and n2_addr2_coins[0]['amount'] > 4.9
        assert_equal(n2_addr2_coins[0]['confirmations'], 1)

        n2_balances = node2.getbalances()['mine']
        assert n2_balances['immature'] > 19.9 and n2_balances['immature'] < 20
        assert_equal(n2_balances['untrusted_pending'], 0)
        assert_equal(n2_balances['trusted'], 0)

        # TODO: Conflicting txs
        # TODO: Duplicate hash

        self.log.info("Restart node1 with wallet broadcast enabled and top up its MWEB balance")
        self.restart_node(1, with_mweb_vbparams(['-whitelist=noban@127.0.0.1']))
        node1 = self.nodes[1]
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        node0.sendtoaddress(node1.getnewaddress(address_type='mweb'), 10)
        generate(node0, 1)
        self.sync_all()

        #
        # MWEB→MWEB (Litecoin-parity fee/amount/txid/balance)
        #
        self.log.info("MWEB→MWEB: Litecoin-compatible fee, amount, txid, and balances")
        payment = Decimal('5')
        n0_mweb = node0.getnewaddress(address_type='mweb')
        mweb_txid = node1.sendtoaddress(n0_mweb, payment)
        self.sync_mempools()
        n1_mweb_tx = node1.gettransaction(txid=mweb_txid)
        assert_equal(n1_mweb_tx['amount'], -payment)
        assert_equal(n1_mweb_tx['fee'], -MWEB_FEE_WITH_CHANGE)
        # Reported txid must round-trip through gettransaction (no GetHash flip).
        assert_equal(node1.gettransaction(txid=n1_mweb_tx['txid'])['txid'], n1_mweb_tx['txid'])
        generate(node0, 1)
        self.sync_blocks()
        n1_mweb_tx = node1.gettransaction(txid=mweb_txid)
        assert_equal(n1_mweb_tx['confirmations'], 1)
        assert_equal(n1_mweb_tx['amount'], -payment)
        assert_equal(n1_mweb_tx['fee'], -MWEB_FEE_WITH_CHANGE)
        assert_equal(node1.gettransaction(txid=n1_mweb_tx['txid'])['txid'], n1_mweb_tx['txid'])

        def sum_unspent(node):
            return sum((c['amount'] for c in node.listunspent()), Decimal('0'))

        assert_equal(node1.getbalances()['mine']['trusted'], sum_unspent(node1))
        assert_equal(node0.getbalances()['mine']['trusted'], sum_unspent(node0))
        n0_recv = node0.gettransaction(txid=mweb_txid)
        assert any(d.get('category') == 'receive' and d.get('amount') == payment for d in n0_recv['details'])

        #
        # wallet RPC `send` → MWEB (regression: must not abort the node)
        # Also exercises uncommon multi-recipient shapes (not everyday UX).
        #
        self.test_send_rpc_mweb(node0, node1, node2)
        self.test_send_rpc_input_io(node0, node1, node2)

        self.log.info("Self-send should list stealth address details (send + receive)")
        self_addr = node0.getnewaddress(address_type='mweb')
        self_txid = node0.sendtoaddress(self_addr, 10)
        self_tx = node0.gettransaction(txid=self_txid)
        assert len(self_tx['details']) >= 1
        assert any(d.get('address') == self_addr and 'mweb_out' in d for d in self_tx['details'])
        generate(node0, 1)
        self.sync_blocks()

        self.test_persisted_output_lock_restart(node0, node1, node2)

    def test_persisted_output_lock_restart(self, funding_node, wallet_node, receiver_node):
        self.log.info("An encrypted wallet restart cannot sign a persisted MWEB output until unlocked")
        name = 'persisted_mweb_lock'
        wallet_node.createwallet(wallet_name=name, load_on_startup=True)
        wallet = wallet_node.get_wallet_rpc(name)
        funding_node.sendtoaddress(wallet.getnewaddress(address_type='mweb'), Decimal('2'))
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        source, = wallet.listunspent()
        assert_equal(source['amount'], Decimal('2'))
        wallet.encryptwallet('persisted-mweb-output')
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_all()
        wallet = wallet_node.get_wallet_rpc(name)
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        retained, = wallet.listunspent()
        assert_equal((retained['output_id'], retained['amount']), (source['output_id'], Decimal('2')))
        destination = receiver_node.getnewaddress(address_type='bech32')
        before = wallet.listunspent()
        mempool_before = set(wallet_node.getrawmempool())
        # Signed sends require spending keys. The native RPC returns an unsigned
        # draft while locked when the caller explicitly requests a PSBT.
        assert_raises_rpc_error(-4, 'is not spendable', wallet.send,
                                outputs={destination: Decimal('1')}, options={
                                    'inputs': [{'mweb_out': source['output_id']}],
                                    'add_inputs': False, 'fee_rate': 10})
        assert_equal(wallet.listunspent(), before)
        assert_equal(set(wallet_node.getrawmempool()), mempool_before)
        assert_raises_rpc_error(-4, 'walletpassphrase first', wallet.send,
                                outputs={destination: Decimal('1')}, options={'fee_rate': 10})
        options = {'fee_rate': 10, 'psbt': True}
        incomplete = wallet.send(outputs={destination: Decimal('1')}, options=options)
        assert_equal(incomplete['complete'], False)
        assert 'txid' not in incomplete and 'psbt' in incomplete
        selected, = wallet.decodepsbt(incomplete['psbt'])['inputs']
        assert_equal(selected['mweb']['output_id'], source['output_id'])
        assert_equal(wallet.listunspent(), before)
        assert_equal(set(wallet_node.getrawmempool()), mempool_before)
        wallet.walletpassphrase('persisted-mweb-output', 600)
        sent = wallet.send(outputs={destination: Decimal('1')}, options={'fee_rate': 10})
        assert sent['complete']
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        tx = wallet.gettransaction(sent['txid'], verbose=True)
        assert_equal(tx['decoded']['vin'], [{'ismweb': True, 'output_id': source['output_id']}])
        assert_equal((tx['amount'], tx['confirmations']), (Decimal('-1'), 1))
        assert tx['fee'] < 0
        assert_equal(wallet.getbalances()['mine']['trusted'], Decimal('1') + tx['fee'])
        paid, = receiver_node.listreceivedbyaddress(minconf=0, address_filter=destination)
        assert_equal((paid['amount'], paid['confirmations']), (Decimal('1'), 1))


    def test_send_rpc_mweb(self, node0, node1, node2):
        """Cover wallet `send` to MWEB destinations and multi-recipient shapes."""
        self.log.info("Top up node1 MWEB balance for send-RPC coverage")
        topup = node1.getnewaddress(address_type='mweb')
        node0.sendtoaddress(topup, 40)
        generate(node0, 1)
        self.sync_blocks()

        # --- Basic send options (like wallet_send.py, MWEB dest) ---
        self.log.info("send → MWEB (default / v2): node must stay up")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('1.0')})
        assert_equal(res['complete'], True)
        assert 'txid' in res
        self.sync_mempools()
        assert_equal(node1.gettransaction(res['txid'])['confirmations'], 0)

        self.log.info("send → MWEB with add_to_wallet=True")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.5')}, options={"add_to_wallet": True})
        assert_equal(res['complete'], True)
        assert 'txid' in res

        self.log.info("send → MWEB with add_to_wallet=False returns hex")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.5')}, options={"add_to_wallet": False})
        assert_equal(res['complete'], True)
        assert 'hex' in res
        txid = node1.sendrawtransaction(res['hex'])
        self.sync_mempools()
        assert txid in node0.getrawmempool() or txid in node1.getrawmempool()

        self.log.info("send → MWEB with version=3")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.25')}, options={"add_to_wallet": True}, version=3)
        assert_equal(res['complete'], True)
        decoded = node1.gettransaction(txid=res['txid'], verbose=True)['decoded']
        assert_equal(decoded['version'], 3)

        self.log.info("send → MWEB with subtract_fee_from_outputs")
        dest = node0.getnewaddress(address_type='mweb')
        amt = Decimal('1.0')
        res = node1.send(outputs={dest: amt}, options={"subtract_fee_from_outputs": [0]})
        assert_equal(res['complete'], True)
        tx = node1.gettransaction(res['txid'])
        assert_greater_than(amt, -tx['amount'])  # amount debited less than request after SFFO
        assert tx['fee'] < 0

        self.log.info("send → MWEB with psbt=True returns a signed MWEB PSBT without broadcasting it")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.1')}, options={"psbt": True})
        assert_equal(res['complete'], True)
        assert 'txid' in res
        assert res['txid'] not in node1.getrawmempool()
        final = node1.finalizepsbt(res['psbt'])
        assert_equal(final['complete'], True)
        assert_equal(node1.sendrawtransaction(final['hex']), res['txid'])
        self.sync_mempools()
        assert res['txid'] in node0.getrawmempool()
        generate(node0, 1)
        self.sync_blocks()

        # --- Privacy-safe send: no silent peg-in; explicit L1/MWEB inputs ---
        self.log.info("send → MWEB with enough MWEB auto-selects MWEB→MWEB (node stays up)")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.25')})
        assert_equal(res['complete'], True)
        assert node1.getblockcount() >= 0  # process still alive

        self.log.info("send → MWEB with insufficient MWEB and no L1 inputs is a hard error (not silent peg-in)")
        # node2 holds only L1 coins: the earlier peg-outs and this payment.
        node0.sendtoaddress(node2.getnewaddress(), 10)
        generate(node0, 1)
        self.sync_blocks()
        node2_mweb = [u for u in node2.listunspent(0) if u.get('output_id')]
        assert_equal(len(node2_mweb), 0)
        assert_greater_than(node2.getbalances()['mine']['trusted'], Decimal('0'))
        dest = node0.getnewaddress(address_type='mweb')
        before_ids = {t['txid'] for t in node2.listtransactions("*", 10000) if 'txid' in t}
        assert_raises_rpc_error(-4, "Insufficient MWEB funds for a confidential send",
                                node2.send, outputs={dest: Decimal('1.0')})
        after_ids = {t['txid'] for t in node2.listtransactions("*", 10000) if 'txid' in t}
        assert_equal(after_ids, before_ids)
        assert_equal(len(node2.getrawmempool()), 0)
        assert node2.getblockcount() >= 0

        self.log.info("sendtoaddress → MWEB with only L1 still pegs in (unchanged)")
        dest = node1.getnewaddress(address_type='mweb')
        txid = node0.sendtoaddress(dest, Decimal('1.5'))
        assert txid
        generate(node0, 1)
        self.sync_blocks()

        self.log.info("Peg-in via send with explicit L1 inputs (implied peg-in)")
        for _ in range(3):
            node0.sendtoaddress(node0.getnewaddress(), 1)
        generate(node0, 1)
        self.sync_blocks()
        l1_utxos = [u for u in node0.listunspent(1) if 'vout' in u and not u.get('output_id')]
        assert_greater_than(len(l1_utxos), 0)
        dest = node1.getnewaddress(address_type='mweb')
        preset_l1 = (l1_utxos[0]['txid'], l1_utxos[0]['vout'])
        res = node0.send(outputs={dest: Decimal('0.4')},
                         options={"inputs": [{"txid": l1_utxos[0]['txid'], "vout": l1_utxos[0]['vout']}],
                                  "add_inputs": True})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node0, res['txid'])
        assert_l1_inputs_include(decoded, {preset_l1})
        generate(node0, 1)
        self.sync_blocks()

        self.log.info("multi L1 → mweb via send(inputs=...)")
        l1_utxos = [u for u in node0.listunspent(1) if 'vout' in u and not u.get('output_id')]
        assert_greater_than(len(l1_utxos), 1)
        inputs = [{"txid": l1_utxos[0]['txid'], "vout": l1_utxos[0]['vout']},
                  {"txid": l1_utxos[1]['txid'], "vout": l1_utxos[1]['vout']}]
        preset_l1s = {(inputs[0]['txid'], inputs[0]['vout']), (inputs[1]['txid'], inputs[1]['vout'])}
        dest = node1.getnewaddress(address_type='mweb')
        res = node0.send(outputs={dest: Decimal('0.5')},
                         options={"inputs": inputs, "add_inputs": True})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node0, res['txid'])
        assert_l1_inputs_include(decoded, preset_l1s)
        generate(node0, 1)
        self.sync_blocks()

        self.log.info("send → MWEB with explicit output_id inputs (MWEB→MWEB)")
        small_addrs = [node1.getnewaddress(address_type='mweb') for _ in range(3)]
        for a in small_addrs:
            node0.sendtoaddress(a, Decimal('1.0'))
        generate(node0, 1)
        self.sync_blocks()
        # Pick a 1.0 coin and spend a fraction with add_inputs=false so the
        # decoded vin set equals exactly that preset (change covers the fee).
        one_ltc = [u for u in node1.listunspent(1)
                   if u.get('output_id') and u['amount'] == Decimal('1.0')]
        assert_greater_than(len(one_ltc), 0)
        oid = one_ltc[0]['output_id']
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('0.5')},
                         options={"inputs": [{"output_id": oid}], "add_inputs": False})
        assert_equal(res['complete'], True)
        self.sync_mempools()
        decoded = decode_wallet_tx(node1, res['txid'])
        assert_exact_mweb_inputs(decoded, {oid})
        assert_equal(node1.gettransaction(res['txid'])['confirmations'], 0)
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, {oid})

        self.log.info("Fund several small MWEB UTXOs on node1 for multi-input spends")
        # (already funded above; keep log for continuity)

        self.log.info("multi mweb → mweb (amount selects multiple inputs)")
        dest = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={dest: Decimal('2.5')})
        assert_equal(res['complete'], True)

        self.log.info("mweb → multi mweb (uncommon multi-recipient path)")
        d1 = node0.getnewaddress(address_type='mweb')
        d2 = node0.getnewaddress(address_type='mweb')
        res = node1.send(outputs={d1: Decimal('0.3'), d2: Decimal('0.3')})
        assert_equal(res['complete'], True)
        tx = node1.gettransaction(res['txid'])
        assert tx['fee'] in (-MWEB_FEE_TWO_OUT_NO_CHANGE, -MWEB_FEE_TWO_OUT_WITH_CHANGE)
        generate(node0, 1)
        self.sync_blocks()

        self.log.info("multi mweb → multi mweb")
        d1 = node0.getnewaddress(address_type='mweb')
        d2 = node1.getnewaddress(address_type='mweb')
        res = node1.send(outputs={d1: Decimal('0.2'), d2: Decimal('0.2')})
        assert_equal(res['complete'], True)

        self.log.info("mweb → mweb + L1 hybrid recipients")
        mweb_d = node0.getnewaddress(address_type='mweb')
        l1_d = node2.getnewaddress(address_type='bech32')
        res = node1.send(outputs={mweb_d: Decimal('0.15'), l1_d: Decimal('0.15')})
        assert_equal(res['complete'], True)

        self.log.info("mweb → multi L1 (implied peg-out)")
        l1a = node2.getnewaddress(address_type='bech32')
        l1b = node2.getnewaddress(address_type='bech32')
        res = node1.send(outputs={l1a: Decimal('0.1'), l1b: Decimal('0.1')})
        assert_equal(res['complete'], True)

        self.log.info("multi mweb → mweb + L1")
        mweb_d = node0.getnewaddress(address_type='mweb')
        l1_d = node2.getnewaddress(address_type='bech32')
        res = node1.send(outputs={mweb_d: Decimal('0.2'), l1_d: Decimal('0.1')})
        assert_equal(res['complete'], True)

        self.log.info("mweb → multi L1 + multi mweb")
        outs = {
            node0.getnewaddress(address_type='mweb'): Decimal('0.1'),
            node1.getnewaddress(address_type='mweb'): Decimal('0.1'),
            node2.getnewaddress(address_type='bech32'): Decimal('0.1'),
            node2.getnewaddress(address_type='bech32'): Decimal('0.1'),
        }
        res = node1.send(outputs=outs)
        assert_equal(res['complete'], True)

        generate(node0, 1)
        self.sync_blocks()
        # Ensure node1 still has MWEB left for later peg-out coverage.
        assert_greater_than(node1.getbalances()['mine']['trusted'], Decimal('15'))

        # Dual L1+MWEB input presets toward an MWEB dest remain uncommon
        # (ENABLE_MWEB_UNCOMMON_SENDS). Everyday send auto-funding never mixes.

    def test_send_rpc_input_io(self, node0, node1, node2):
        """Robust input/output asserts for send presets (errors, peg-out, dual)."""
        UNKNOWN_OID = '00' * 32

        self.log.info("send input errors: malformed / mixed / unknown output_id; bad L1 control")
        dest_mweb = node0.getnewaddress(address_type='mweb')
        dest_l1 = node2.getnewaddress(address_type='bech32')
        assert_raises_rpc_error(-8, "output_id must be of length 64",
                                node1.send, outputs={dest_mweb: Decimal('0.1')},
                                options={"inputs": [{"output_id": "abcd"}]})
        assert_raises_rpc_error(-8, "must not mix output_id with L1 fields",
                                node1.send, outputs={dest_mweb: Decimal('0.1')},
                                options={"inputs": [{"output_id": UNKNOWN_OID,
                                                     "txid": "11" * 32, "vout": 0}]})
        before_ids = {t['txid'] for t in node1.listtransactions("*", 10000) if 'txid' in t}
        assert_raises_rpc_error(-4, "Unable to find MWEB output",
                                node1.send, outputs={dest_mweb: Decimal('0.1')},
                                options={"inputs": [{"output_id": UNKNOWN_OID}]})
        assert_raises_rpc_error(-4, "Unable to find MWEB output",
                                node1.send, outputs={dest_l1: Decimal('0.1')},
                                options={"inputs": [{"output_id": UNKNOWN_OID}]})
        after_ids = {t['txid'] for t in node1.listtransactions("*", 10000) if 'txid' in t}
        assert_equal(after_ids, before_ids)
        assert_raises_rpc_error(-4, "Unable to find UTXO for external input",
                                node0.send, outputs={dest_mweb: Decimal('0.1')},
                                options={"inputs": [{"txid": "11" * 32, "vout": 0}],
                                         "add_inputs": False})

        self.log.info("Fund dedicated MWEB coins on node1 for explicit peg-out / dual presets")
        # Fresh amounts so we can pick coins by value without colliding with leftovers.
        peg_addrs = [node1.getnewaddress(address_type='mweb') for _ in range(6)]
        for a in peg_addrs:
            node0.sendtoaddress(a, Decimal('5.0'))
        # L1 coins on node1 for dual-input path.
        for _ in range(2):
            node0.sendtoaddress(node1.getnewaddress(address_type='bech32'), Decimal('3.0'))
        generate(node0, 1)
        self.sync_blocks()
        fives = [u for u in node1.listunspent(1)
                 if u.get('output_id') and u['amount'] == Decimal('5.0')]
        assert_greater_than(len(fives), 5)
        l1_n1 = [u for u in node1.listunspent(1) if 'vout' in u and not u.get('output_id')
                 and u['amount'] >= Decimal('2.9')]
        assert_greater_than(len(l1_n1), 0)

        def take_fives(n):
            assert_greater_than(len(fives), n - 1)
            taken = fives[:n]
            del fives[:n]
            return taken

        self.log.info("explicit peg-out: 1 MWEB → 1 L1")
        coin = take_fives(1)[0]
        oid = coin['output_id']
        l1_dest = node2.getnewaddress(address_type='bech32')
        amt = Decimal('1.0')
        res = node1.send(outputs={l1_dest: amt},
                         options={"inputs": [{"output_id": oid}], "add_inputs": False})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert_exact_mweb_inputs(decoded, {oid})
        assert_pegout_payments_include(decoded, [(l1_dest, amt)])
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, {oid})
        assert res['txid'] not in node1.getrawmempool()
        recv = node2.listreceivedbyaddress(minconf=0, address_filter=l1_dest)
        assert_equal(len(recv), 1)
        assert_equal(recv[0]['amount'], amt)
        assert_greater_than(recv[0]['confirmations'], 0)

        self.log.info("explicit peg-out: N MWEB → 1 L1")
        coins = take_fives(2)
        oids = {c['output_id'] for c in coins}
        l1_dest = node2.getnewaddress(address_type='bech32')
        amt = Decimal('3.0')
        res = node1.send(outputs={l1_dest: amt},
                         options={"inputs": [{"output_id": c['output_id']} for c in coins],
                                  "add_inputs": False})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert_exact_mweb_inputs(decoded, oids)
        assert_pegout_payments_include(decoded, [(l1_dest, amt)])
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, oids)
        assert res['txid'] not in node1.getrawmempool()
        recv = node2.listreceivedbyaddress(minconf=0, address_filter=l1_dest)
        assert_equal(len(recv), 1)
        assert_equal(recv[0]['amount'], amt)
        assert_greater_than(recv[0]['confirmations'], 0)

        self.log.info("explicit peg-out: 1 MWEB → M L1")
        coin = take_fives(1)[0]
        oid = coin['output_id']
        a1 = node2.getnewaddress(address_type='bech32')
        a2 = node2.getnewaddress(address_type='bech32')
        res = node1.send(outputs={a1: Decimal('1.0'), a2: Decimal('1.0')},
                         options={"inputs": [{"output_id": oid}], "add_inputs": False})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert_exact_mweb_inputs(decoded, {oid})
        assert_pegout_payments_include(decoded, [(a1, Decimal('1.0')), (a2, Decimal('1.0'))])
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, {oid})
        assert res['txid'] not in node1.getrawmempool()
        for addr, amount in ((a1, Decimal('1.0')), (a2, Decimal('1.0'))):
            recv = node2.listreceivedbyaddress(minconf=0, address_filter=addr)
            assert_equal(len(recv), 1)
            assert_equal(recv[0]['amount'], amount)
            assert_greater_than(recv[0]['confirmations'], 0)

        self.log.info("explicit peg-out: N MWEB → M L1")
        coins = take_fives(2)
        oids = {c['output_id'] for c in coins}
        a1 = node2.getnewaddress(address_type='bech32')
        a2 = node2.getnewaddress(address_type='bech32')
        res = node1.send(outputs={a1: Decimal('1.5'), a2: Decimal('1.5')},
                         options={"inputs": [{"output_id": c['output_id']} for c in coins],
                                  "add_inputs": False})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert_exact_mweb_inputs(decoded, oids)
        assert_pegout_payments_include(decoded, [(a1, Decimal('1.5')), (a2, Decimal('1.5'))])
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, oids)
        assert res['txid'] not in node1.getrawmempool()
        for addr, amount in ((a1, Decimal('1.5')), (a2, Decimal('1.5'))):
            recv = node2.listreceivedbyaddress(minconf=0, address_filter=addr)
            assert_equal(len(recv), 1)
            assert_equal(recv[0]['amount'], amount)
            assert_greater_than(recv[0]['confirmations'], 0)

        self.log.info("undersized MWEB presets for peg-out fail without inventing L1 inputs")
        tiny_addr = node1.getnewaddress(address_type='mweb')
        node0.sendtoaddress(tiny_addr, Decimal('0.01'))
        generate(node0, 1)
        self.sync_blocks()
        tiny = [u for u in node1.listunspent(1)
                if u.get('output_id') and u['amount'] == Decimal('0.01')]
        assert_equal(len(tiny), 1)
        before_ids = {t['txid'] for t in node1.listtransactions("*", 10000) if 'txid' in t}
        assert_raises_rpc_error(-4, None,
                                node1.send, outputs={node2.getnewaddress(): Decimal('1.0')},
                                options={"inputs": [{"output_id": tiny[0]['output_id']}],
                                         "add_inputs": False})
        after_ids = {t['txid'] for t in node1.listtransactions("*", 10000) if 'txid' in t}
        assert_equal(after_ids, before_ids)
        # Tiny coin must still be unspent (no partial spend / silent mix).
        assert tiny[0]['output_id'] in mweb_unspent_output_ids(node1, 0)

        self.log.info("dual L1+MWEB → 1 MWEB dest (uncommon path)")
        # Refresh MWEB + L1 presets on node1.
        dual_mweb_addr = node1.getnewaddress(address_type='mweb')
        node0.sendtoaddress(dual_mweb_addr, Decimal('2.0'))
        node0.sendtoaddress(node1.getnewaddress(address_type='bech32'), Decimal('4.0'))
        generate(node0, 1)
        self.sync_blocks()
        mweb_coin = [u for u in node1.listunspent(1)
                     if u.get('output_id') and u['amount'] == Decimal('2.0')][0]
        l1_coin = [u for u in node1.listunspent(1)
                   if 'vout' in u and not u.get('output_id') and u['amount'] >= Decimal('3.9')][0]
        dest = node0.getnewaddress(address_type='mweb')
        # Amount above MWEB-only so L1 peg-in remainder is required.
        res = node1.send(outputs={dest: Decimal('5.0')},
                         options={"inputs": [
                             {"output_id": mweb_coin['output_id']},
                             {"txid": l1_coin['txid'], "vout": l1_coin['vout']},
                         ], "add_inputs": True})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert mweb_coin['output_id'] in mweb_vin_output_ids(decoded)
        assert_l1_inputs_include(decoded, {(l1_coin['txid'], l1_coin['vout'])})
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, {mweb_coin['output_id']})
        assert res['txid'] not in node1.getrawmempool()

        self.log.info("dual L1+MWEB → multi MWEB dests")
        dual_mweb_addr = node1.getnewaddress(address_type='mweb')
        node0.sendtoaddress(dual_mweb_addr, Decimal('2.0'))
        node0.sendtoaddress(node1.getnewaddress(address_type='bech32'), Decimal('4.0'))
        generate(node0, 1)
        self.sync_blocks()
        mweb_coin = [u for u in node1.listunspent(1)
                     if u.get('output_id') and u['amount'] == Decimal('2.0')][0]
        l1_coin = [u for u in node1.listunspent(1)
                   if 'vout' in u and not u.get('output_id') and u['amount'] >= Decimal('3.9')][0]
        d1 = node0.getnewaddress(address_type='mweb')
        d2 = node2.getnewaddress(address_type='mweb')
        res = node1.send(outputs={d1: Decimal('2.5'), d2: Decimal('2.5')},
                         options={"inputs": [
                             {"output_id": mweb_coin['output_id']},
                             {"txid": l1_coin['txid'], "vout": l1_coin['vout']},
                         ], "add_inputs": True})
        assert_equal(res['complete'], True)
        decoded = decode_wallet_tx(node1, res['txid'])
        assert mweb_coin['output_id'] in mweb_vin_output_ids(decoded)
        assert_l1_inputs_include(decoded, {(l1_coin['txid'], l1_coin['vout'])})
        # Recipient wallets should see the payments after mine.
        self.sync_mempools()
        generate(node0, 1)
        self.sync_blocks()
        assert_mweb_oids_spent(node1, {mweb_coin['output_id']})
        n0_recv = [u for u in node0.listunspent(1)
                   if u.get('address') == d1 and u['amount'] == Decimal('2.5')]
        n2_recv = [u for u in node2.listunspent(1)
                   if u.get('address') == d2 and u['amount'] == Decimal('2.5')]
        assert_equal(len(n0_recv), 1)
        assert_equal(len(n2_recv), 1)


if __name__ == '__main__':
    MWEBWalletBasicTest(__file__).main()
