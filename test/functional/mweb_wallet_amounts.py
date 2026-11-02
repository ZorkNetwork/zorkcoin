#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check RPC amounts against actual payments and both fee markets.

Mixed inputs are explicitly selected. MWEB-destination automatic funding does
not silently mix layers; canonical-destination funding has its own mixed fallback.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBWalletAmountsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name='payments', load_on_startup=True)
        receiver = node.get_wallet_rpc('payments')
        cases = [
            # name, MWEB inputs, L1 input, destination layer, payment, subtract fee, rate
            ('l1_control', [], '6', 'bech32', '5', False, '10'),
            ('mw_control', ['1.5', '2.5'], '0', 'mweb', '3', False, '10'),
            ('l1_pegin', [], '6', 'mweb', '5', False, '10'),
            ('mixed_pegout', ['1.5', '2.5'], '2', 'bech32', '5', False, '10'),
            ('mixed_mweb', ['1.5', '2.5'], '2', 'mweb', '5', False, '10'),
            ('changeless_pegout', ['1.5', '2.5'], '2', 'bech32', '6', True, '10'),
            ('changeless_mweb', ['1.5', '2.5'], '2', 'mweb', '6', True, '10'),
            ('fractional', ['1.00000001', '2.99999999'], '2', 'mweb', '4.23456789', False, '10.125'),
        ]
        results = []
        for name, mw_values, l1_value, layer, nominal, subtract_fee, rate in cases:
            self.log.info('Exact payment/amount and split fees: %s', name)
            node.createwallet(wallet_name=name, load_on_startup=True)
            wallet = node.get_wallet_rpc(name)
            mw_total = sum(map(Decimal, mw_values), Decimal(0))
            l1_total = Decimal(l1_value)
            for amount in mw_values:
                miner.sendtoaddress(wallet.getnewaddress(address_type='mweb'), Decimal(amount))
            if l1_total:
                miner.sendtoaddress(wallet.getnewaddress(address_type='bech32'), l1_total)
            self.generate(node, 1)
            coins = wallet.listunspent()
            assert_equal(sorted(coin['amount'] for coin in coins),
                         sorted([Decimal(value) for value in mw_values] + ([l1_total] if l1_total else [])))
            inputs = [{'mweb_out': coin['output_id']} if 'output_id' in coin else
                      {'txid': coin['txid'], 'vout': coin['vout']} for coin in coins]
            address = receiver.getnewaddress(address_type=layer)

            clone_name = None
            if name == 'mixed_mweb':
                # Same input/change keys, without the sender's random output metadata.
                clone_name = 'opaque_copy'
                node.createwallet(wallet_name=clone_name, blank=True, load_on_startup=True)
                clone = node.get_wallet_rpc(clone_name)
                descriptors = wallet.listdescriptors(True)['descriptors']
                for active in (True, False):
                    batch = [dict(desc=d['desc'], timestamp=0, active=d['active'],
                                  internal=d.get('internal', False)) if active else
                             dict(desc=d['desc'], timestamp=0)
                             for d in descriptors if d['active'] == active]
                    for imported in clone.importdescriptors(batch):
                        assert imported['success'], imported
                assert_equal(clone.getbalances()['mine'], wallet.getbalances()['mine'])

            options = {'add_inputs': False, 'fee_rate': Decimal(rate)}
            if subtract_fee:
                options['subtractFeeFromOutputs'] = [0]
            funded = wallet.walletcreatefundedpsbt(inputs, [{address: Decimal(nominal)}], 0, options)
            psbt = node.decodepsbt(funded['psbt'])
            processed = wallet.walletprocesspsbt(funded['psbt'])
            assert processed['complete']
            finalized = wallet.finalizepsbt(processed['psbt'])
            assert finalized['complete']
            raw = node.decoderawtransaction(finalized['hex'])
            assert_equal({vin['output_id'] for vin in raw['vin'] if vin['ismweb']},
                         {coin['output_id'] for coin in coins if 'output_id' in coin})
            assert_equal({(vin['txid'], vin['vout']) for vin in raw['vin'] if not vin['ismweb']},
                         {(coin['txid'], coin['vout']) for coin in coins if 'output_id' not in coin})
            canonical = [out for out in raw['vout'] if not out['ismweb']]
            l1_fee = l1_total - sum((out['value'] for out in canonical), Decimal(0))
            kernels = raw.get('vkern', [])
            mw_fee = sum((kernel['fee'] for kernel in kernels), Decimal(0))
            fee = l1_fee + mw_fee
            assert_equal(fee, funded['fee'])
            assert l1_fee >= 0 and mw_fee >= 0 and fee > 0
            assert_equal(fee * COIN, int(fee * COIN))
            if kernels:
                kernel, = kernels
                bridges = [out for out in canonical if out['scriptPubKey']['type'] == 'witness_mweb_pegin']
                assert_equal(sum((out['value'] for out in bridges), Decimal(0)), kernel['pegin'])
                mw_outputs = [out for out in psbt['outputs'] if 'mweb' in out]
                pegouts = kernel['pegout']
                assert_equal(mw_total + kernel['pegin'],
                             sum((out['amount'] for out in mw_outputs), Decimal(0)) +
                             sum((out['value'] for out in pegouts), Decimal(0)) + mw_fee)
                if l1_total:
                    assert kernel['pegin'] > 0 and l1_fee > 0 and mw_fee > 0
            else:
                mw_outputs, pegouts = [], []
            if layer == 'mweb':
                paid, = [out['amount'] for out in mw_outputs if out['mweb']['address'] == address]
            else:
                paid, = ([out['value'] for out in canonical if out['scriptPubKey'].get('address') == address] +
                         [out['value'] for out in pegouts if out['scriptPubKey']['address'] == address])
            assert_equal(paid, Decimal(nominal) - (fee if subtract_fee else 0))
            change = mw_total + l1_total - paid - fee
            assert_equal(change == 0, subtract_fee)
            assert_equal(funded['changepos'] == -1, subtract_fee)
            txid = node.sendrawtransaction(finalized['hex'])
            node.syncwithvalidationinterfacequeue()
            assert_equal(node.getmempoolentry(txid)['fees']['base'], fee)
            result = dict(name=name, txid=txid, address=address, layer=layer, payment=paid,
                          fee=fee, change=change, clone=clone_name)
            self.check_amount(node, result, confirmed=False)
            self.generate(node, 1)
            self.check_amount(node, result, confirmed=True)
            results.append(result)

        self.log.info('All exact amounts, fees and owned change survive restart and rescan')
        self.restart_node(0)
        for result in results:
            self.check_amount(node, result, confirmed=True)
            node.get_wallet_rpc(result['name']).rescanblockchain(0)
            if result['clone']:
                node.get_wallet_rpc(result['clone']).rescanblockchain(0)
            self.check_amount(node, result, confirmed=True)

    def check_amount(self, node, result, *, confirmed):
        name, txid = result['name'], result['txid']
        wallet = node.get_wallet_rpc(name)
        tx = wallet.gettransaction(txid)
        assert_equal((tx['amount'], tx['fee']), (-result['payment'], -result['fee']))
        assert_equal(tx['confirmations'] > 0, confirmed)
        row, = wallet.listwallettransactions(txid=txid)
        assert_equal((row['type'], row['address'], row['amount'], row['fee'], row['net']),
                     ('SendToAddress', result['address'], -result['payment'], -result['fee'],
                      -result['payment'] - result['fee']))
        coins = wallet.listunspent(minconf=0)
        assert_equal(sum((coin['amount'] for coin in coins), Decimal(0)), result['change'])
        assert_equal(len(coins), int(result['change'] > 0))
        mine = wallet.getbalances()['mine']
        assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (result['change'], 0, 0))
        receiver = node.get_wallet_rpc('payments')
        if result['layer'] == 'mweb':
            paid, = receiver.listunspent(minconf=0, addresses=[result['address']])
        else:
            paid, = receiver.listreceivedbyaddress(minconf=0, address_filter=result['address'])
        assert_equal(paid['amount'], result['payment'])
        if result['clone']:
            clone = node.get_wallet_rpc(result['clone'])
            opaque = clone.gettransaction(txid)
            assert_equal((opaque['amount'], opaque['fee']), (-result['payment'], -result['fee']))
            unknown, = clone.listwallettransactions(txid=txid)
            # Native history retains an unknown output's ID and zero amount;
            # aggregate RPC accounting still knows the owned debit/change/fees.
            assert 'address' not in unknown
            assert_equal((unknown['type'], unknown['amount'], unknown['net']),
                         ('SendToOther', 0, -result['fee']))
            assert_equal(unknown['mweb_out'], row['mweb_out'])
            assert_equal(clone.getbalances()['mine'], mine)
        self.log.info('%s amount=%s fee=%s change=%s confirmed=%s',
                      name, tx['amount'], tx['fee'], result['change'], confirmed)


if __name__ == '__main__':
    MWEBWalletAmountsTest(__file__).main()
