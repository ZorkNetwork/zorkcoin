#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test where the wallet pays change on transactions with an MWEB part.

A transparent change address on a transaction that spends MWEB coins gets its
change as a kernel peg-out; change too small to be worth spending goes to the fee
instead. A peg-in pays transparent change as an ordinary output, as in Litecoin.
A stealth change address gets an MWEB change output.

Also test sends with no fee estimate and the default -fallbackfee of 0: only
MWEB-to-MWEB sends with no peg-out change, which pay a fixed fee per MWEB weight
unit, succeed.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    MWEB_GBT_REQUEST_PARAMS,
    get_mweb_account_descriptor,
    init_mweb_wallet,
    setup_mweb_chain,
    mweb_extra_args,
)
from test_framework.util import assert_equal, assert_raises_rpc_error


# Matches consensus/consensus.h PEGOUT_MATURITY.
PEGOUT_MATURITY = 6
# Matches policy/feerate.cpp BASE_MWEB_FEE, in satoshis per MWEB weight unit.
BASE_MWEB_FEE = 100


def sats(amount):
    return int(amount * COIN)


class MWEBWalletChangeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.funding_node = self.nodes[0]
        self.wallet_node = self.nodes[1]
        setup_mweb_chain(self.funding_node, self)
        self.sync_all()

        self.wallet = self.wallet_node.get_wallet_rpc(self.default_wallet_name)
        self.funding = self.funding_node.get_wallet_rpc(self.default_wallet_name)
        self.coins = [self.receive_mweb(Decimal(amount)) for amount in ('1', '2', '3', '4')]
        self.funding_node.createwallet(wallet_name='transparent_only')
        self.payer = self.funding_node.get_wallet_rpc('transparent_only')
        self.funding.sendtoaddress(self.payer.getnewaddress(), 3)
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)

        self.test_mweb_to_mweb()
        self.test_pegout()
        self.test_pegin()
        self.test_dust_change()
        self.test_stealth_change_address()
        self.test_send()
        self.test_no_fee_estimate()
        self.test_p2pkh_pegout_change_is_mined()
        self.test_imported_change_survives_encryption()

    def test_imported_change_survives_encryption(self):
        self.log.info("An imported active account preserves fixed change across encryption and reload")
        name = 'imported_fixed_change'
        self.wallet_node.createwallet(wallet_name=name, blank=True)
        imported = self.wallet_node.get_wallet_rpc(name)
        account = get_mweb_account_descriptor(self.wallet, private=True)
        result = imported.importdescriptors([{'desc': account['desc'], 'timestamp': 0, 'active': True}])
        assert result[0]['success'], result
        change = imported.getrawchangeaddress('mweb')
        assert_equal(change, self.wallet.getrawchangeaddress('mweb'))
        before = get_mweb_account_descriptor(imported)['desc']
        coins = {(c['output_id'], c['amount'], c['address']) for c in imported.listunspent()}
        assert coins
        imported.encryptwallet('fixed-change')
        assert_equal(get_mweb_account_descriptor(imported)['desc'], before)
        assert_equal(imported.getaddressinfo(change)['ischange'], True)
        self.wallet_node.unloadwallet(name)
        self.wallet_node.loadwallet(name)
        imported = self.wallet_node.get_wallet_rpc(name)
        assert_equal(get_mweb_account_descriptor(imported)['desc'], before)
        assert_equal(imported.getaddressinfo(change)['ischange'], True)
        assert_equal({(c['output_id'], c['amount'], c['address']) for c in imported.listunspent()}, coins)
        imported.walletpassphrase('fixed-change', 60)
        assert_equal(imported.getrawchangeaddress('mweb'), change)

    def receive_mweb(self, amount):
        address = self.wallet.getnewaddress(address_type='mweb')
        self.funding.sendtoaddress(address, amount)
        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        utxo, = self.wallet.listunspent(addresses=[address])
        return {'input': {'mweb_out': utxo['output_id']}, 'amount': amount}

    def fund(self, wallet, inputs, outputs, options):
        funded = wallet.walletcreatefundedpsbt(inputs, outputs, 0, {'fee_rate': 10, **options})
        return funded, wallet.decodepsbt(funded['psbt'])

    def pegouts(self, decoded):
        return [(p['scriptPubKey']['address'], p['amount']) for k in decoded['kernels'] for p in k.get('pegouts', [])]

    def mweb_outputs(self, decoded):
        return [(o['mweb']['address'], sats(o['amount'])) for o in decoded['outputs'] if 'mweb' in o]

    def transparent_outputs(self, decoded):
        return [o for o in decoded['outputs'] if 'mweb' not in o]

    def kernel_fee(self, decoded):
        return sum(k['fee'] for k in decoded['kernels'])

    def test_mweb_to_mweb(self):
        self.log.info("A transparent change address on an MWEB-to-MWEB payment gets a peg-out")
        recipient = self.funding.getnewaddress(address_type='mweb')
        change = self.wallet.getrawchangeaddress()
        coin = self.coins[0]
        funded, decoded = self.fund(self.wallet, [coin['input']], [{recipient: Decimal('0.5')}],
                                    {'add_inputs': False, 'changeAddress': change})
        assert_equal(funded['changepos'], -1)
        assert_equal(self.transparent_outputs(decoded), [])
        assert_equal(self.mweb_outputs(decoded), [(recipient, COIN // 2)])
        (pegout_address, pegout_amount), = self.pegouts(decoded)
        assert_equal(pegout_address, change)
        fee = sats(funded['fee'])
        assert_equal(self.kernel_fee(decoded), fee)
        assert_equal(pegout_amount, sats(coin['amount']) - COIN // 2 - fee)

        # The peg-out costs its kernel weight and the HogEx output; a stealth change output costs more at this rate.
        stealth_funded, stealth_decoded = self.fund(self.wallet, [coin['input']], [{recipient: Decimal('0.5')}], {'add_inputs': False})
        assert sats(funded['fee']) < sats(stealth_funded['fee'])

        self.log.info("getrawchangeaddress mweb returns the stealth address MWEB change is paid to")
        stealth_change = stealth_decoded['outputs'][stealth_funded['changepos']]['mweb']['address']
        assert_equal(self.wallet.getrawchangeaddress('mweb'), stealth_change)
        assert_equal(self.wallet.getrawchangeaddress('mweb'), stealth_change)

    def test_pegout(self):
        self.log.info("A transparent change address on a peg-out gets a second peg-out")
        recipient = self.funding.getnewaddress(address_type='bech32')
        change = self.wallet.getrawchangeaddress()
        coin = self.coins[1]
        funded, decoded = self.fund(self.wallet, [coin['input']], [{recipient: Decimal('0.5')}],
                                    {'add_inputs': False, 'changeAddress': change})
        assert_equal(funded['changepos'], -1)
        assert_equal(self.mweb_outputs(decoded), [])
        fee = sats(funded['fee'])
        assert_equal(self.pegouts(decoded), [(recipient, COIN // 2), (change, sats(coin['amount']) - COIN // 2 - fee)])

    def test_pegin(self):
        self.log.info("A transparent change address on a peg-in gets a transparent change output, as in Litecoin")
        recipient = self.wallet.getnewaddress(address_type='mweb')
        change = self.payer.getrawchangeaddress()
        funded, decoded = self.fund(self.payer, [], [{recipient: 1}], {'changeAddress': change})
        assert funded['changepos'] != -1
        assert_equal(self.pegouts(decoded), [])
        assert_equal(self.mweb_outputs(decoded), [(recipient, COIN)])
        change_output = decoded['outputs'][funded['changepos']]
        assert_equal(change_output['script']['address'], change)
        pegin_output, = [o for o in self.transparent_outputs(decoded) if o is not change_output]
        # The peg-in carries the payment and the kernel fee; the change stays transparent.
        assert_equal(sats(pegin_output['amount']), COIN + self.kernel_fee(decoded))
        assert_equal(self.payer.analyzepsbt(funded['psbt'])['fee'], funded['fee'])

        self.log.info("Without a change address, peg-in change goes to MWEB")
        funded, decoded = self.fund(self.payer, [], [{recipient: 1}], {})
        assert_equal(self.pegouts(decoded), [])
        assert_equal(len(self.mweb_outputs(decoded)), 2)
        assert_equal(len(self.transparent_outputs(decoded)), 1)

    def test_dust_change(self):
        self.log.info("Peg-out change too small to spend goes to the fee")
        recipient = self.funding.getnewaddress(address_type='mweb')
        change = self.wallet.getrawchangeaddress()
        coin = self.coins[2]
        funded, _ = self.fund(self.wallet, [coin['input']], [{recipient: 1}], {'add_inputs': False, 'changeAddress': change})
        fee = sats(funded['fee'])
        available = sats(coin['amount']) - fee

        # The fee does not depend on the amounts, so the change is exactly what is left over.
        kept = available - 5000
        funded, decoded = self.fund(self.wallet, [coin['input']], [{recipient: Decimal(kept) / COIN}],
                                    {'add_inputs': False, 'changeAddress': change})
        assert_equal(self.pegouts(decoded), [(change, 5000)])
        assert_equal(sats(funded['fee']), fee)

        dropped = available - 200
        funded, decoded = self.fund(self.wallet, [coin['input']], [{recipient: Decimal(dropped) / COIN}],
                                    {'add_inputs': False, 'changeAddress': change})
        assert_equal(funded['changepos'], -1)
        assert_equal(self.pegouts(decoded), [])
        assert_equal(self.mweb_outputs(decoded), [(recipient, dropped)])
        assert_equal(self.kernel_fee(decoded), fee + 200)
        assert_equal(sats(funded['fee']), fee + 200)

    def test_stealth_change_address(self):
        self.log.info("A stealth change address gets the MWEB change output")
        recipient = self.funding.getnewaddress(address_type='mweb')
        change = self.wallet.getnewaddress(address_type='mweb')
        coin = self.coins[3]
        funded, decoded = self.fund(self.wallet, [coin['input']], [{recipient: 1}], {'add_inputs': False, 'changeAddress': change})
        fee = sats(funded['fee'])
        assert_equal(self.pegouts(decoded), [])
        assert_equal(self.mweb_outputs(decoded), [(recipient, COIN), (change, sats(coin['amount']) - COIN - fee)])
        assert_equal(funded['changepos'], 1)

        self.log.info("A stealth change address on a peg-in gets the MWEB change output")
        payer_change = self.wallet.getnewaddress(address_type='mweb')
        stealth = self.funding.getnewaddress(address_type='mweb')
        funded, decoded = self.fund(self.payer, [], [{stealth: Decimal('0.5')}], {'changeAddress': payer_change})
        assert_equal([address for address, _ in self.mweb_outputs(decoded)], [stealth, payer_change])

        self.log.info("A stealth change address is refused for a payment without an MWEB part")
        assert_raises_rpc_error(-4, "MWEB change is incompatible with this transaction type",
                                self.payer.walletcreatefundedpsbt, [], [{self.funding.getnewaddress(): 1}], 0,
                                {'changeAddress': payer_change, 'fee_rate': 10})

    def test_send(self):
        self.log.info("send pays peg-out change that the wallet receives on its transparent change address")
        recipient = self.funding.getnewaddress(address_type='mweb')
        change = self.wallet.getrawchangeaddress()
        coin = self.receive_mweb(Decimal('2'))
        result = self.wallet.send(outputs={recipient: 1},
                                  options={'inputs': [coin['input']], 'add_inputs': False, 'change_address': change, 'fee_rate': 10})
        assert result['complete']
        fee = -sats(self.wallet.gettransaction(result['txid'])['fee'])
        self.sync_mempools()
        # The wallet lists peg-outs at consensus maturity.
        self.generate(self.funding_node, PEGOUT_MATURITY, sync_fun=self.sync_all)
        received, = self.wallet.listunspent(addresses=[change])
        assert_equal(sats(received['amount']), COIN - fee)

    def test_no_fee_estimate(self):
        self.log.info("With no -fallbackfee setting and no fee estimate, only MWEB-to-MWEB sends succeed")
        for node in self.nodes:
            node.replace_in_config([("fallbackfee=", "#fallbackfee=")])
            self.restart_node(node.index)
        self.connect_nodes(0, 1)
        self.reload_wallet_rpcs()
        self.funding_node.loadwallet('transparent_only')
        payer = self.funding_node.get_wallet_rpc('transparent_only')
        error = "Fee estimation failed. Fallbackfee is disabled"

        assert_equal(self.wallet_node.estimatesmartfee(1)['errors'], ["Insufficient data or no feerate found"])
        result = self.wallet.sendtoaddress(self.funding.getnewaddress(address_type='mweb'), Decimal('0.5'), verbose=True)
        tx = self.wallet.gettransaction(result['txid'])
        assert_equal(-sats(tx['fee']), self.wallet_node.decoderawtransaction(tx['hex'])['mweb_weight'] * BASE_MWEB_FEE)

        coin, other_coin = [u for u in self.wallet.listunspent() if 'output_id' in u][:2]
        swept = self.wallet.sendall([self.funding.getnewaddress(address_type='mweb')], inputs=[{'mweb_out': coin['output_id']}])
        assert swept['complete']
        tx = self.wallet.gettransaction(swept['txid'])
        assert_equal(-sats(tx['fee']), self.wallet_node.decoderawtransaction(tx['hex'])['mweb_weight'] * BASE_MWEB_FEE)

        # A peg-in and a peg-out pay for L1 bytes at a fee rate, so they still need an estimate.
        assert_raises_rpc_error(-6, error, payer.sendtoaddress, self.wallet.getnewaddress(address_type='mweb'), 1)
        assert_raises_rpc_error(-4, error, self.wallet.send, outputs={self.funding.getnewaddress(): Decimal('0.1')},
                                options={'inputs': [{'mweb_out': other_coin['output_id']}], 'add_inputs': False})
        assert_raises_rpc_error(-4, error, self.wallet.sendall, [self.funding.getnewaddress()],
                                inputs=[{'mweb_out': other_coin['output_id']}])
        assert_raises_rpc_error(-4, error, self.wallet.send, outputs={self.funding.getnewaddress(address_type='mweb'): Decimal('0.1')},
                                options={'inputs': [{'mweb_out': other_coin['output_id']}], 'add_inputs': False,
                                         'change_address': self.wallet.getrawchangeaddress()})
        assert_raises_rpc_error(-4, error, payer.sendall, [self.funding.getnewaddress()])

        assert_equal(set(self.wallet_node.getrawmempool()), {result['txid'], swept['txid']})
        self.sync_mempools()
        for node in self.nodes:
            node.replace_in_config([("#fallbackfee=", "fallbackfee=")])
            self.restart_node(node.index)
        self.connect_nodes(0, 1)
        self.reload_wallet_rpcs()
        self.sync_mempools()

    def reload_wallet_rpcs(self):
        self.wallet = self.wallet_node.get_wallet_rpc(self.default_wallet_name)
        self.funding = self.funding_node.get_wallet_rpc(self.default_wallet_name)

    def test_p2pkh_pegout_change_is_mined(self):
        self.log.info("An MWEB payment whose peg-out change pays a P2PKH address is mined")
        address = self.wallet.getnewaddress(address_type='mweb')
        self.funding.sendtoaddress(address, 2, fee_rate=10)
        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        utxo, = self.wallet.listunspent(addresses=[address])
        change = self.wallet.getrawchangeaddress('legacy')
        result = self.wallet.send(outputs={self.funding.getnewaddress(address_type='mweb'): 1},
                                  options={'inputs': [{'mweb_out': utxo['output_id']}], 'add_inputs': False,
                                           'change_address': change, 'fee_rate': 10})
        assert result['complete']
        decoded = self.wallet_node.decoderawtransaction(self.wallet.gettransaction(result['txid'])['hex'])
        assert_equal([p['scriptPubKey']['address'] for k in decoded['vkern'] for p in k['pegout']], [change])

        # The peg-out's sigops move to the HogEx; they must be counted on the transaction first.
        self.sync_mempools()
        self.funding_node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        assert_equal(self.wallet.gettransaction(result['txid'])['confirmations'], 1)

if __name__ == '__main__':
    MWEBWalletChangeTest(__file__).main()
