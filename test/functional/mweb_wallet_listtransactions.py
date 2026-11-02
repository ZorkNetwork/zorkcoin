#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test how the wallet lists MWEB transactions.

Litecoin Core's wallet_listwallettransactions.py checks, made with
listtransactions (wallet_listwallettransactions.py makes them with
listwallettransactions): SendToAddress is a "send" entry, RecvWithAddress a
"receive" entry, and SendToSelf a "send" and a "receive" entry for the same
amount.

Also checks Litecoin's listtransactions shape for MWEB: peg-out sends carry
neither "vout" nor "mweb_out", peg-out receives carry an all-zero "mweb_out",
HogEx outputs are "immature" and then "hogex", and partial_mweb amounts are
integer satoshis.
"""
from decimal import Decimal
from struct import pack, unpack

from test_framework.mweb_util import generate, init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.messages import COIN, blake3, ser_string
from test_framework.psbt import (
    PSBT,
    PSBT_KERN_FEE,
    PSBT_KERN_PEGIN_AMOUNT,
    PSBT_KERN_PEGOUT,
    PSBT_KERN_FEATURES,
    PSBT_OUT_AMOUNT,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_array_result, assert_equal, assert_raises_rpc_error

ZERO_MWEB_OUT = "00" * 32


class MWEBWalletListTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'], [])  # immediate tx relay

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def mine(self, node):
        blockhash = generate(node, 1)[0]
        self.sync_all()
        return blockhash, node.getblockheader(blockhash)['height']

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        self.log.info("Setting up MWEB chain")
        setup_mweb_chain(node0, self)
        self.sync_all()

        self.log.info("L1 send from node0 to node1")
        txid = node0.sendtoaddress(node1.getnewaddress(), 0.1)
        self.sync_all()
        assert_array_result(node0.listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-0.1"), "confirmations": 0})
        assert_array_result(node1.listtransactions(),
                            {"txid": txid},
                            {"category": "receive", "amount": Decimal("0.1"), "confirmations": 0})
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node0.listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-0.1"), "confirmations": 1,
                             "blockhash": blockhash, "blockheight": blockheight})
        assert_array_result(node1.listtransactions(),
                            {"txid": txid},
                            {"category": "receive", "amount": Decimal("0.1"), "confirmations": 1,
                             "blockhash": blockhash, "blockheight": blockheight})

        self.log.info("L1 send to self")
        txid = node0.sendtoaddress(node0.getnewaddress(), 0.2)
        assert_array_result(node0.listtransactions(),
                            {"txid": txid, "category": "receive"},
                            {"amount": Decimal("0.2")})

        self.log.info("Peg-in to self lists a send and a receive of the amount")
        node0_mweb_addr = node0.getnewaddress(address_type='mweb')
        txid = node0.sendtoaddress(node0_mweb_addr, 0.4)
        for category, amount in (("send", Decimal("-0.4")), ("receive", Decimal("0.4"))):
            assert_array_result(node0.listtransactions(),
                                {"txid": txid, "category": category},
                                {"amount": amount, "address": node0_mweb_addr, "confirmations": 0})
        blockhash, blockheight = self.mine(node0)
        for category, amount in (("send", Decimal("-0.4")), ("receive", Decimal("0.4"))):
            assert_array_result(node0.listtransactions(),
                                {"txid": txid, "category": category},
                                {"amount": amount, "address": node0_mweb_addr, "confirmations": 1,
                                 "blockhash": blockhash, "blockheight": blockheight})

        self.log.info("Peg-in from node0 to node1")
        node1_mweb_addr = node1.getnewaddress(address_type='mweb')
        txid = node0.sendtoaddress(node1_mweb_addr, 5)
        self.sync_all()
        assert_array_result(node0.listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-5.0"), "confirmations": 0, "address": node1_mweb_addr})
        assert_array_result(node1.listtransactions(),
                            {"address": node1_mweb_addr},
                            {"txid": txid, "category": "receive", "amount": Decimal("5.0"), "confirmations": 0})
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node0.listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-5.0"), "confirmations": 1,
                             "blockheight": blockheight, "address": node1_mweb_addr})
        assert_array_result(node1.listtransactions(),
                            {"address": node1_mweb_addr},
                            {"txid": txid, "category": "receive", "amount": Decimal("5.0"), "confirmations": 1,
                             "blockheight": blockheight})

        self.log.info("Peg-out from node1 to node0 while node0 is online")
        node0_addr = node0.getnewaddress()
        txid = node1.sendtoaddress(node0_addr, 3)
        self.sync_all()
        assert_array_result(node1.listtransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "category": "send", "amount": Decimal("-3.0"), "confirmations": 0})
        assert_array_result(node0.listtransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "category": "receive", "amount": Decimal("3.0"), "confirmations": 0,
                             "mweb_out": ZERO_MWEB_OUT})
        send, = [t for t in node1.listtransactions() if t["txid"] == txid and t["category"] == "send"]
        assert "vout" not in send and "mweb_out" not in send, send
        blockhash, blockheight = self.mine(node0)
        hogex_txid = node0.getblock(blockhash)['tx'][-1]
        assert_array_result(node1.listtransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "category": "send", "amount": Decimal("-3.0"), "confirmations": 1,
                             "blockheight": blockheight})
        assert_array_result(node0.listtransactions(),
                            {"address": node0_addr, "txid": txid},
                            {"category": "receive", "amount": Decimal("3.0"), "confirmations": 1,
                             "blockheight": blockheight, "mweb_out": ZERO_MWEB_OUT})
        assert_array_result(node0.listtransactions(),
                            {"address": node0_addr, "txid": hogex_txid},
                            {"category": "immature", "amount": Decimal("3.0"), "confirmations": 1, "vout": 1})

        self.log.info("listreceivedbyaddress counts the peg-out once, through its MWEB transaction")
        received, = node0.listreceivedbyaddress(address_filter=node0_addr)
        assert_equal(received['amount'], Decimal("3.0"))
        assert_equal(received['txids'], [txid])

        self.log.info("Peg-out and MWEB send from node1 to node2, mined while node2 is offline")
        # node2 never sees the MWEB transactions, only the peg-out kernel, the HogEx output
        # and its MWEB output in the block.
        node2_addr = node2.getnewaddress()
        node2_mweb_addr = node2.getnewaddress(address_type='mweb')
        self.stop_node(2)
        txid = node1.sendtoaddress(node2_addr, 1)
        node1.sendtoaddress(node2_mweb_addr, Decimal("0.7"))
        blockhash = generate(node1, 1)[0]
        blockheight = node1.getblockheader(blockhash)['height']
        hogex_txid = node1.getblock(blockhash)['tx'][-1]
        self.start_node(2)
        self.connect_nodes(2, 0)
        self.connect_nodes(2, 1)
        self.sync_all()

        assert_array_result(node1.listtransactions(),
                            {"address": node2_addr},
                            {"txid": txid, "category": "send", "amount": Decimal("-1.0"), "confirmations": 1,
                             "blockheight": blockheight})
        assert_array_result(node2.listtransactions(),
                            {"address": node2_addr},
                            {"txid": hogex_txid, "category": "immature", "amount": Decimal("1.0"), "confirmations": 1,
                             "blockheight": blockheight})
        assert_equal(node2.gettransaction(hogex_txid)['amount'], Decimal("1.0"))
        received, = node2.listreceivedbyaddress(address_filter=node2_addr)
        assert_equal(received['txids'], [hogex_txid])

        partial, = [t for t in node2.listtransactions() if t.get("address") == node2_mweb_addr]
        assert_equal(partial["category"], "receive")
        assert_equal(partial["partial_mweb"]["received"]["amount"], int(Decimal("0.7") * COIN))
        assert_equal(partial["partial_mweb"]["received"]["output_id"], partial["mweb_out"])

        self.log.info("A sent MWEB output the wallet can't read is listed without address and amount")
        # A copy of node1's wallet sees node1's MWEB send spend its coins, but only node1
        # kept the recipient's details.
        node2.createwallet(wallet_name='node1_copy', blank=True)
        node1_copy = node2.get_wallet_rpc('node1_copy')
        descriptors = node1.listdescriptors(True)['descriptors']
        # Active (account) descriptors first: MWEB internal descriptors need their account.
        for batch in ([d for d in descriptors if d['active']], [d for d in descriptors if not d['active']]):
            imports = [{'desc': d['desc'], 'timestamp': 0, 'active': d['active'], 'internal': d.get('internal', False)}
                       if d['active'] else {'desc': d['desc'], 'timestamp': 0} for d in batch]
            for d, imported in zip(imports, node1_copy.importdescriptors(imports)):
                assert imported['success'], (d, imported)
        assert_equal(node1_copy.getbalances()['mine'], node1.getbalances()['mine'])
        recipient_mweb_addr = node0.getnewaddress(address_type='mweb')
        txid = node1.sendtoaddress(recipient_mweb_addr, Decimal("0.05"))
        self.sync_all()
        self.wait_until(lambda: txid in [t['txid'] for t in node1_copy.listtransactions()])
        sent_by_node1, = [t for t in node1.listtransactions() if t['txid'] == txid and t['category'] == 'send']
        assert_equal(sent_by_node1['address'], recipient_mweb_addr)
        sent_seen_by_copy, = [t for t in node1_copy.listtransactions() if t['txid'] == txid and t['category'] == 'send']
        assert 'address' not in sent_seen_by_copy, sent_seen_by_copy
        assert_equal(sent_seen_by_copy['amount'], Decimal("0"))
        assert_equal(sent_seen_by_copy['mweb_out'], sent_by_node1['mweb_out'])
        node2.unloadwallet('node1_copy')

        self.log.info("HogEx outputs are \"hogex\" once mature")
        for _ in range(7):
            self.mine(node0)
        assert_array_result(node2.listtransactions(),
                            {"address": node2_addr},
                            {"txid": hogex_txid, "category": "immature", "confirmations": 8})
        self.mine(node0)
        assert_array_result(node2.listtransactions(),
                            {"address": node2_addr},
                            {"txid": hogex_txid, "category": "hogex", "amount": Decimal("1.0"), "confirmations": 9})

        self.test_native_external_send_history(node0, node1)
        self.test_native_pegout_component_ids(node0, node1)
        self.test_native_mixed_receive_components(node0, node1)
        self.test_native_history_shape_matrix(node0, node1)

    def test_native_history_shape_matrix(self, miner, wallet_node):
        """Four layer shapes x external/self/restored payer, using admitted and mined transactions."""
        for shape in ('mweb', 'pegin', 'pegout', 'combined'):
            for mode in ('external', 'self', 'restored'):
                name = f'history_{shape}_{mode}'
                self.log.info('History matrix: %s', name)
                wallet_node.createwallet(wallet_name=name, load_on_startup=False)
                sender = wallet_node.get_wallet_rpc(name)
                if shape in ('pegin', 'combined'):
                    miner.sendtoaddress(sender.getnewaddress(), 3 if shape == 'combined' else 6)
                if shape != 'pegin':
                    miner.sendtoaddress(sender.getnewaddress(address_type='mweb'), 3 if shape == 'combined' else 6)
                self.sync_mempools()
                self.mine(miner)
                inputs = [{'mweb_out': c['output_id']} if 'output_id' in c else
                          {'txid': c['txid'], 'vout': c['vout']} for c in sender.listunspent()]
                funding_ids = {row['txid'] for row in sender.listwallettransactions()}
                receiver = sender if mode == 'self' else miner
                layers = ('bech32', 'mweb') if shape == 'combined' else ('bech32' if shape == 'pegout' else 'mweb',)
                payments = {receiver.getnewaddress(address_type=layer): Decimal(1) for layer in layers}
                backup = wallet_node.datadir_path / f'{name}.bak'
                if mode == 'restored':
                    sender.backupwallet(backup)
                sent = sender.send(outputs=[{address: amount} for address, amount in payments.items()], options={
                    'inputs': inputs, 'add_inputs': False, 'fee_rate': 10,
                })
                assert sent['complete']
                txid = sent['txid']
                self.sync_mempools()
                block, _ = self.mine(miner)
                transaction = sender.gettransaction(txid)
                fee = -transaction['fee']
                assert fee > 0
                rows = sender.listwallettransactions(txid=txid)
                if mode == 'self':
                    row, = rows
                    assert_equal((row['type'], row['net']), ('SendToSelf', -fee))
                    assert_equal(row['amount'], sum(payments.values()))
                    if shape in ('pegout', 'combined'):
                        hogex = miner.getblock(block)['tx'][-1]
                        assert_equal(sender.listwallettransactions(txid=hogex), [])
                else:
                    assert_equal(len(rows), len(payments))
                    assert_equal({row['address']: -row['amount'] for row in rows}, payments)
                    assert all(row['type'] == 'SendToAddress' for row in rows)
                    assert_equal(sum(row['net'] for row in rows), -sum(payments.values()) - fee)
                    assert_equal(sum(row['fee'] for row in rows), -fee)
                assert all(row['confirmations'] == 1 and row['blockhash'] == block for row in rows)
                component_order = [(row.get('mweb_out'), row.get('pegout'), row.get('vout')) for row in rows]
                sender.rescanblockchain(0)
                assert_equal([(row.get('mweb_out'), row.get('pegout'), row.get('vout'))
                              for row in sender.listwallettransactions(txid=txid)], component_order)

                if mode == 'restored':
                    clone_name = name + '_copy'
                    wallet_node.restorewallet(clone_name, backup, load_on_startup=False)
                    clone = wallet_node.get_wallet_rpc(clone_name)
                    expected_coins = {(c['output_id'], c['amount'], c['address']) for c in sender.listunspent()}
                    assert_equal({(c['output_id'], c['amount'], c['address']) for c in clone.listunspent()}, expected_coins)
                    history = clone.listwallettransactions()
                    # Every payer was restored from before the send. Standalone
                    # MWEB bodies cannot be reconstructed from an aggregate block;
                    # canonical peg-in bodies retain their L1 transaction identity.
                    if shape in ('mweb', 'pegout'):
                        assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', clone.gettransaction, txid)
                    else:
                        assert_equal(clone.gettransaction(txid)['confirmations'], 1)
                    for txin in inputs:
                        if 'mweb_out' in txin:
                            spend_id = blake3(b'S' + bytes.fromhex(txin['mweb_out'])).to_byte_arr()[::-1].hex()
                            assert_equal(clone.gettransaction(spend_id)['partial_mweb'],
                                         {'spent': {'output_id': txin['mweb_out']}})
                    new_rows = [row for row in history if row['txid'] not in funding_ids]
                    assert new_rows
                    assert not any(row.get('address') in payments for row in new_rows)
                    if sum(row['net'] for row in history) != sum(c['amount'] for c in clone.listunspent()):
                        self.log.error('Restored %s history=%s, coins=%s, original amounts=%s',
                                       shape, history, clone.listunspent(),
                                       {key: transaction[key] for key in ('amount', 'fee', 'details')})
                    assert_equal(sum(row['net'] for row in history),
                                 sum(c['amount'] for c in clone.listunspent()))
                    for _ in range(2):
                        clone.rescanblockchain(0)
                        assert_equal(clone.listwallettransactions(), history)
                        assert_equal({(c['output_id'], c['amount'], c['address']) for c in clone.listunspent()}, expected_coins)
                    wallet_node.unloadwallet(clone_name, load_on_startup=False)
                wallet_node.unloadwallet(name, load_on_startup=False)

    def test_native_mixed_receive_components(self, funding_node, wallet_node):
        self.log.info("One known receive preserves canonical, MWEB and peg-out component identities and ordering")
        wallet_node.createwallet(wallet_name='mweb_mixed_components_sender')
        receiver_name = 'mweb_mixed_components_receiver'
        wallet_node.createwallet(wallet_name=receiver_name)
        sender = wallet_node.get_wallet_rpc('mweb_mixed_components_sender')
        receiver = wallet_node.get_wallet_rpc(receiver_name)
        funding_node.sendtoaddress(sender.getnewaddress(), Decimal('10'))
        funding_node.sendtoaddress(sender.getnewaddress(address_type='mweb'), Decimal('5'))
        self.sync_mempools()
        self.mine(funding_node)
        coins = sender.listunspent()
        assert_equal(len(coins), 2)
        inputs = [{'mweb_out': coin['output_id']} if 'output_id' in coin else
                  {'txid': coin['txid'], 'vout': coin['vout']} for coin in coins]
        canonical_address = receiver.getnewaddress()
        mweb_address = receiver.getnewaddress(address_type='mweb')
        pegout_address = receiver.getnewaddress()
        # Start with direct L1 change and one MWEB payment. Adding a canonical
        # recipient through funding would route that change through the kernel.
        funded = sender.walletcreatefundedpsbt(
            inputs, [{mweb_address: Decimal('12')}], 0,
            {'add_inputs': False, 'fee_rate': 10, 'changeAddress': canonical_address})
        decoded_psbt = sender.decodepsbt(funded['psbt'])
        draft = PSBT.from_base64(funded['psbt'])
        kernel_map, = draft.k
        assert 0x08 not in kernel_map.map  # no kernel signature before mutation
        change, = [output for output, decoded in zip(draft.o, decoded_psbt['outputs'])
                   if decoded.get('script', {}).get('address') == canonical_address]
        bridge, = [output for output, decoded in zip(draft.o, decoded_psbt['outputs'])
                   if decoded.get('script', {}).get('type') == 'witness_mweb_pegin']
        assert_equal(Decimal(unpack('<q', change.map[PSBT_OUT_AMOUNT])[0]) / COIN,
                     Decimal('3') - funded['fee'])
        # Move one coin from direct change to a peg-out, paying an additional
        # 10,000 satoshis on MWEB so the new kernel has ample relay fee.
        extra_fee = 10_000
        delta = COIN + extra_fee
        fee = funded['fee'] + Decimal(extra_fee) / COIN
        for fields, key, adjustment in (
            (change.map, PSBT_OUT_AMOUNT, -delta),
            (bridge.map, PSBT_OUT_AMOUNT, delta),
            (kernel_map.map, PSBT_KERN_PEGIN_AMOUNT, delta),
            (kernel_map.map, PSBT_KERN_FEE, extra_fee),
        ):
            fields[key] = pack('<q', unpack('<q', fields[key])[0] + adjustment)
        kernel_map.map[PSBT_KERN_FEATURES] = bytes([kernel_map.map[PSBT_KERN_FEATURES][0] | 0x04])
        pegout_script = bytes.fromhex(receiver.getaddressinfo(pegout_address)['scriptPubKey'])
        kernel_map.map[bytes([PSBT_KERN_PEGOUT, 0])] = pack('<q', COIN) + ser_string(pegout_script)
        signed = sender.walletprocesspsbt(draft.to_base64())
        assert signed['complete']
        finalized = sender.finalizepsbt(signed['psbt'])
        assert finalized['complete']
        admission, = sender.testmempoolaccept([finalized['hex']])
        assert admission['allowed'], admission
        txid = sender.sendrawtransaction(finalized['hex'])
        self.sync_all()
        assert_equal(wallet_node.getmempoolentry(txid)['fees']['base'], fee)
        decoded = receiver.gettransaction(txid, verbose=True)['decoded']
        canonical, = [out for out in decoded['vout'] if not out['ismweb'] and
                      out['scriptPubKey'].get('address') == canonical_address]
        assert_equal(canonical['value'], Decimal('2') - fee)
        mweb, = [out for out in decoded['vout'] if out['ismweb']]
        kernel, = decoded['vkern']
        pegout, = kernel['pegout']
        assert_equal((pegout['scriptPubKey']['address'], pegout['value']), (pegout_address, Decimal('1')))
        assert kernel['pegin'] > 0
        assert_equal(Decimal('5') + kernel['pegin'], Decimal('13') + kernel['fee'])
        l1_fee = Decimal('10') - sum(out['value'] for out in decoded['vout'] if not out['ismweb'])
        assert_equal(l1_fee + kernel['fee'], fee)
        expected = [
            ('pegout', f'{kernel["kernel_id"]}:0', pegout_address, Decimal('1')),
            ('mweb_out', mweb['output_id'], mweb_address, Decimal('12')),
            ('vout', canonical['n'], canonical_address, canonical['value']),
        ]

        def check_components(confirmations):
            rows = receiver.listwallettransactions(txid=txid)
            assert_equal(len(rows), 3)
            for row, (kind, component, address, amount) in zip(rows, expected):
                assert_equal(row[kind], component)
                assert_equal((row['type'], row['address'], row['amount'], row['net']),
                             ('RecvWithAddress', address, amount, amount))
                assert_equal(row['confirmations'], confirmations)
                assert_equal({key for key in ('vout', 'mweb_out', 'pegout') if key in row}, {kind})
                assert 'fee' not in row
            assert_equal(sum(row['amount'] for row in rows), Decimal('15') - fee)

        check_components(0)
        self.mine(funding_node)
        check_components(1)
        wallet_node.unloadwallet(receiver_name)
        wallet_node.loadwallet(receiver_name)
        receiver = wallet_node.get_wallet_rpc(receiver_name)
        check_components(1)
        receiver.rescanblockchain(0)
        check_components(1)

    def test_native_pegout_component_ids(self, funding_node, wallet_node):
        self.log.info("Native peg-out component IDs match exact signed kernel positions across reload/rescan")
        wallet_name = 'mweb_pegout_components'
        wallet_node.createwallet(wallet_name=wallet_name)
        sender = wallet_node.get_wallet_rpc(wallet_name)
        funding_node.sendtoaddress(sender.getnewaddress(address_type='mweb'), Decimal('5'))
        self.sync_mempools()
        self.mine(funding_node)
        coin, = sender.listunspent()
        payments = {funding_node.getnewaddress(): Decimal('1'),
                    funding_node.getnewaddress(): Decimal('2')}
        sent = sender.send(outputs=[{address: amount} for address, amount in payments.items()],
                           options={'inputs': [{'mweb_out': coin['output_id']}], 'add_inputs': False})
        assert sent['complete']
        txid = sent['txid']
        self.sync_all()
        decoded = sender.gettransaction(txid, verbose=True)['decoded']
        assert_equal(decoded['vin'], [{'ismweb': True, 'output_id': coin['output_id']}])
        kernel, = decoded['vkern']
        assert_equal(kernel['pegin'], 0)
        assert_equal(len(kernel['pegout']), 2)
        assert_equal({p['scriptPubKey']['address']: p['value'] for p in kernel['pegout']}, payments)
        for pegout in kernel['pegout']:
            assert_equal(pegout['scriptPubKey']['hex'],
                         funding_node.getaddressinfo(pegout['scriptPubKey']['address'])['scriptPubKey'])
        expected = {
            f'{kernel["kernel_id"]}:{position}': (pegout['scriptPubKey']['address'], -pegout['value'])
            for position, pegout in enumerate(kernel['pegout'])
        }

        def check_components(confirmations):
            transaction = sender.gettransaction(txid, verbose=True)
            assert_equal(transaction['decoded']['vkern'], [kernel])
            rows = sender.listwallettransactions(txid=txid)
            assert_equal(len(rows), 2)
            # The RPC returns history in descending component sort order.
            assert_equal([row['pegout'] for row in rows], list(reversed(expected)))
            assert_equal({row['pegout']: (row['address'], row['amount']) for row in rows}, expected)
            for row in rows:
                assert_equal(row['type'], 'SendToAddress')
                assert_equal(row['confirmations'], confirmations)
                assert 'vout' not in row and 'mweb_out' not in row
            assert_equal(sum(row['net'] for row in rows), -sum(payments.values()) + transaction['fee'])

        check_components(0)
        self.mine(funding_node)
        check_components(1)
        wallet_node.unloadwallet(wallet_name)
        wallet_node.loadwallet(wallet_name)
        sender = wallet_node.get_wallet_rpc(wallet_name)
        check_components(1)
        sender.rescanblockchain(0)
        check_components(1)

    def test_native_external_send_history(self, funding_node, wallet_node):
        self.log.info("Native external-send history excludes change and survives wallet reload/rescan")
        wallet_name = 'mweb_external_history'
        wallet_node.createwallet(wallet_name=wallet_name)
        sender = wallet_node.get_wallet_rpc(wallet_name)
        funding_address = sender.getnewaddress(address_type='mweb')
        funding_txid = funding_node.sendtoaddress(funding_address, Decimal('2'))
        self.sync_mempools()
        self.mine(funding_node)
        funding_coin, = sender.listunspent()
        assert_equal((funding_coin['txid'], funding_coin['amount']), (funding_txid, Decimal('2')))

        recipient = funding_node.getnewaddress(address_type='mweb')
        assert_equal(sender.getaddressinfo(recipient)['ismine'], False)
        payment = Decimal('0.5')
        sent = sender.send(outputs={recipient: payment},
                           options={'inputs': [{'mweb_out': funding_coin['output_id']}], 'add_inputs': False})
        assert sent['complete']
        txid = sent['txid']
        self.sync_all()
        transaction = sender.gettransaction(txid, verbose=True)
        decoded = transaction['decoded']
        assert_equal(decoded['vin'], [{'ismweb': True, 'output_id': funding_coin['output_id']}])
        assert_equal(decoded['weight'], 0)
        assert_equal(len(decoded['vout']), 2)
        assert all(output['ismweb'] for output in decoded['vout'])
        kernel, = decoded['vkern']
        assert_equal((kernel['pegin'], kernel['pegout']), (0, []))
        # Two standard outputs weigh 18 each and the plain kernel weighs 3;
        # standard inputs weigh 0 and the fixed MWEB charge is 100 sat/WU.
        expected_weight = 2 * 18 + 3
        fee = Decimal(expected_weight * 100) / COIN
        assert_equal(decoded['mweb_weight'], expected_weight)
        assert_equal(kernel['fee'], fee)
        entry = wallet_node.getmempoolentry(txid)
        assert_equal((entry['mwebweight'], entry['fees']['base']), (expected_weight, fee))

        received_coin, = funding_node.listunspent(minconf=0, addresses=[recipient])
        assert_equal((received_coin['txid'], received_coin['amount']), (txid, payment))
        change_coin, = sender.listunspent(minconf=0)
        change = Decimal('2') - payment - fee
        assert_equal(change_coin['amount'], change)
        recipient_id, change_id = received_coin['output_id'], change_coin['output_id']
        assert recipient_id != change_id
        assert_equal({output['output_id'] for output in decoded['vout']}, {recipient_id, change_id})

        def check_history(confirmations, blockhash=None):
            tx = sender.gettransaction(txid, verbose=True)
            assert_equal((tx['amount'], tx['fee'], tx['confirmations']), (-payment, -fee, confirmations))
            assert_equal(tx['decoded'], decoded)
            assert_equal(tx['hex'], transaction['hex'])
            history = sender.listwallettransactions()
            assert_equal(len(history), 2)
            assert_equal({row['txid'] for row in history}, {funding_txid, txid})
            assert_equal(sender.getwalletinfo()['txcount'], 2)
            record, = sender.listwallettransactions(txid=txid)
            expected = {'type': 'SendToAddress', 'txid': txid, 'address': recipient,
                        'mweb_out': recipient_id, 'amount': -payment, 'fee': -fee,
                        'net': -payment - fee, 'confirmations': confirmations}
            if blockhash is not None:
                expected['blockhash'] = blockhash
            else:
                assert 'blockhash' not in record
                assert_equal(record['trusted'], True)
            assert_equal({key: record[key] for key in expected}, expected)
            assert 'vout' not in record and 'pegout' not in record
            # A sole external payment row leaves no row for the change output.
            assert record['mweb_out'] != change_id
            coin, = sender.listunspent(minconf=0)
            assert_equal((coin['txid'], coin['output_id'], coin['amount'], coin['confirmations']),
                         (txid, change_id, change, confirmations))
            mine = sender.getbalances()['mine']
            assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (change, 0, 0))
            return expected

        check_history(0)
        blockhash, _ = self.mine(funding_node)
        confirmed_history = check_history(1, blockhash)

        # Reload the same wallet to verify persisted full bodies and sender metadata.
        wallet_node.unloadwallet(wallet_name)
        wallet_node.loadwallet(wallet_name)
        sender = wallet_node.get_wallet_rpc(wallet_name)
        assert_equal(check_history(1, blockhash), confirmed_history)
        sender.rescanblockchain(0)
        assert_equal(check_history(1, blockhash), confirmed_history)
        wallet_node.unloadwallet(wallet_name)


if __name__ == '__main__':
    MWEBWalletListTransactionsTest(__file__).main()
