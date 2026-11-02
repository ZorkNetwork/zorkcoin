#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the shape of wallet transactions with MWEB parts.

For each combination of funding (transparent coins, MWEB coins or both) and
recipients (transparent, MWEB or both) check the transaction type, which
outputs, MWEB outputs and peg-outs exist, where the change goes and how
subtract-fee-from-outputs splits the fee. Also check the PSBT fill, sign and
finalize flows for a peg-in and for a pure MWEB spend.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import init_mweb_wallet, setup_mweb_chain, mweb_extra_args
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


def sats(amount):
    return int(Decimal(amount) * COIN)


class MWEBWalletTxBuilderTest(BitcoinTestFramework):
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
        self.funding = self.funding_node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Fund wallets holding transparent coins, MWEB coins or both")
        specs = {
            'transparent': [('bech32', Decimal('10'))],
            'mweb': [('mweb', Decimal('5'))],
            'mixed': [('bech32', Decimal('10')), ('mweb', Decimal('5'))],
            'small_pegin': [('bech32', Decimal('0.0004')), ('mweb', Decimal('5'))],
            'tiny_pegin': [('bech32', Decimal('0.0000173')), ('mweb', Decimal('5'))],
            # Only the last coin of each address type is recorded in self.coins.
            'topup': [('bech32', Decimal('1')), ('bech32', Decimal('0.0004')), ('mweb', Decimal('5'))],
            'mweb_pair': [('mweb', Decimal('1')), ('mweb', Decimal('5'))],
        }
        self.wallets = {}
        self.coins = {}
        addresses = {}
        for name, coins in specs.items():
            self.wallet_node.createwallet(wallet_name=name)
            wallet = self.wallet_node.get_wallet_rpc(name)
            self.wallets[name] = wallet
            for address_type, amount in coins:
                address = wallet.getnewaddress(address_type=address_type)
                self.funding.sendtoaddress(address, amount)
                addresses[(name, address_type)] = address
        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        for (name, address_type), address in addresses.items():
            utxo, = self.wallets[name].listunspent(addresses=[address])
            coin = {'mweb_out': utxo['output_id']} if address_type == 'mweb' else {'txid': utxo['txid'], 'vout': utxo['vout']}
            self.coins[(name, address_type)] = coin

        self.transparent1 = self.funding.getnewaddress(address_type='bech32')
        self.transparent2 = self.funding.getnewaddress(address_type='bech32')
        self.stealth1 = self.funding.getnewaddress(address_type='mweb')
        self.stealth2 = self.funding.getnewaddress(address_type='mweb')

        self.test_transparent_funding()
        self.test_pegin()
        self.test_mweb_funding()
        self.test_custom_change()
        self.test_mweb_selection_targets()
        self.test_exact_selection_policy()
        self.test_pegin_pegout()
        self.test_failed_mixed_funding_preserves_inputs_and_wallet()
        self.test_selected_pegin_pegout()
        self.test_pegin_limits()
        self.test_psbt_pegin()
        self.test_psbt_mweb_spend()
        self.test_sent_output_address()

    def test_failed_mixed_funding_preserves_inputs_and_wallet(self):
        self.log.info("Failed mixed PSBT funding preserves wallet state and caller sequences; retry succeeds")
        wallet = self.wallets['mixed']
        canonical = {**self.coins[('mixed', 'bech32')], 'sequence': 123456}
        inputs = [canonical, self.coins[('mixed', 'mweb')]]
        outputs = [{self.transparent1: 1}, {self.stealth1: 2}]
        original_inputs = [dict(txin) for txin in inputs]
        before_coins = wallet.listunspent()
        before_locks = wallet.listlockunspent()
        before_history = wallet.listtransactions(count=1000)
        for options in ({'subtractFeeFromOutputs': [2]}, {'subtractFeeFromOutputs': [-1]}):
            assert_raises_rpc_error(-8, "", wallet.walletcreatefundedpsbt, inputs, outputs, 0,
                                    {'add_inputs': False, 'fee_rate': 10, 'lockUnspents': True, **options})
            assert_equal(inputs, original_inputs)
            assert_equal(wallet.listunspent(), before_coins)
            assert_equal(wallet.listlockunspent(), before_locks)
            assert_equal(wallet.listtransactions(count=1000), before_history)
        _, decoded, summary = self.fund(wallet, inputs, outputs, subtractFeeFromOutputs=[1])
        transparent, = [txin for txin in decoded['inputs'] if 'mweb' not in txin]
        assert_equal(transparent['sequence'], canonical['sequence'])
        assert_equal(summary['pegouts'], [(self.transparent1, COIN)])
        assert_equal(summary['mout'][0], (self.stealth1, 2 * COIN - sats(decoded['fee'])))
        assert_equal(inputs, original_inputs)
        assert_equal(wallet.listunspent(), before_coins)
        assert_equal(wallet.listlockunspent(), before_locks)

    def summary(self, decoded):
        s = {'tin': [], 'min': [], 'tout': [], 'pegin': [], 'mout': [], 'pegouts': [], 'kernel_fee': 0, 'pegin_amount': None}
        for txin in decoded['inputs']:
            if 'mweb' in txin:
                s['min'].append(txin['mweb']['amount'])
            else:
                s['tin'].append(sats(txin['witness_utxo']['amount']))
        for output in decoded['outputs']:
            if 'mweb' in output:
                s['mout'].append((output['mweb']['address'], sats(output['amount'])))
            elif output['script']['type'] == 'witness_mweb_pegin':
                s['pegin'].append(sats(output['amount']))
            else:
                s['tout'].append((output['script']['address'], sats(output['amount'])))
        for kernel in decoded.get('kernels', []):
            s['kernel_fee'] += kernel.get('fee', 0)
            if 'pegin_amount' in kernel:
                s['pegin_amount'] = (s['pegin_amount'] or 0) + kernel['pegin_amount']
            s['pegouts'] += [(p['scriptPubKey']['address'], p['amount']) for p in kernel.get('pegouts', [])]
        return s

    def fund(self, wallet, inputs, outputs, **options):
        options.setdefault('fee_rate', 10)
        if inputs:
            options.setdefault('add_inputs', False)
        funded = wallet.walletcreatefundedpsbt(inputs, outputs, 0, options)
        decoded = wallet.decodepsbt(funded['psbt'])
        s = self.summary(decoded)

        # The peg-in output carries exactly the kernel's peg-in amount, the MWEB side
        # balances, and the fee is the transparent fee plus the kernel fee.
        fee = sats(funded['fee'])
        assert_equal(sats(wallet.analyzepsbt(funded['psbt'])['fee']), fee)
        assert_equal(s['pegin'], [] if s['pegin_amount'] is None else [s['pegin_amount']])
        if 'kernels' in decoded:
            assert_equal(sum(s['min']) + (s['pegin_amount'] or 0),
                         sum(a for _, a in s['mout']) + sum(a for _, a in s['pegouts']) + s['kernel_fee'])
        transparent_fee = sum(s['tin']) - sum(a for _, a in s['tout']) - sum(s['pegin'])
        assert_equal(fee, transparent_fee + s['kernel_fee'])
        return funded, decoded, s

    def fund_with_odd_fee(self, wallet, inputs, outputs, **options):
        for fee_rate in ['10.001', '10.003', '10.007', '10.011', '10.013', '10.017', '10.019', '10.023']:
            result = self.fund(wallet, inputs, outputs, fee_rate=Decimal(fee_rate), **options)
            if sats(result[0]['fee']) % 2:
                return result
        raise AssertionError("No fee rate gave an odd fee")

    def change(self, wallet, funded, decoded, layer):
        """Return the change output's address and amount, checking that the wallet owns it."""
        output = decoded['outputs'][funded['changepos']]
        assert_equal('mweb' in output, layer == 'mweb')
        address = output['mweb']['address'] if layer == 'mweb' else output['script']['address']
        assert address not in [self.transparent1, self.transparent2, self.stealth1, self.stealth2]
        assert wallet.getaddressinfo(address)['ismine']
        return address, sats(output['amount'])

    def test_transparent_funding(self):
        wallet = self.wallets['transparent']
        coin = self.coins[('transparent', 'bech32')]

        self.log.info("Transparent coins pay transparent recipients without an MWEB part; change is transparent")
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 2}])
        assert 'kernels' not in decoded
        assert_equal(len(s['tin']), 1)
        change = self.change(wallet, funded, decoded, 'transparent')
        assert_equal(sorted(s['tout']), sorted([(self.transparent1, 2 * COIN), change]))

        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 2}, {self.transparent2: 3}])
        assert 'kernels' not in decoded
        assert_equal(len(s['tin']), 1)
        change = self.change(wallet, funded, decoded, 'transparent')
        assert_equal(sorted(s['tout']), sorted([(self.transparent1, 2 * COIN), (self.transparent2, 3 * COIN), change]))

        self.log.info("A custom transparent change address on a transparent payment gets the change")
        change_address = wallet.getrawchangeaddress()
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 2}], changeAddress=change_address)
        assert 'kernels' not in decoded
        address, amount = self.change(wallet, funded, decoded, 'transparent')
        assert_equal(address, change_address)
        assert_greater_than(amount, 0)
        assert_equal(sorted(s['tout']), sorted([(self.transparent1, 2 * COIN), (change_address, amount)]))

        self.log.info("Transparent recipients that subtract the fee leave no change and split the fee")
        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 10}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert 'kernels' not in decoded
        assert_equal(s['tout'], [(self.transparent1, 10 * COIN - sats(funded['fee']))])

        funded, decoded, s = self.fund_with_odd_fee(wallet, [coin], [{self.transparent1: 5}, {self.transparent2: 5}],
                                                    subtractFeeFromOutputs=[0, 1])
        fee = sats(funded['fee'])
        assert_equal(funded['changepos'], -1)
        assert_equal(sorted(s['tout']), sorted([(self.transparent1, 5 * COIN - fee // 2 - 1), (self.transparent2, 5 * COIN - fee // 2)]))

    def test_pegin(self):
        wallet = self.wallets['transparent']
        coin = self.coins[('transparent', 'bech32')]

        self.log.info("Transparent coins pay MWEB recipients through a peg-in; change is an MWEB output")
        for inputs in ([], [coin]):
            funded, decoded, s = self.fund(wallet, inputs, [{self.stealth1: 5}])
            assert_equal((len(s['tin']), len(s['min'])), (1, 0))
            assert_equal((s['tout'], s['pegouts']), ([], []))
            assert_equal(len(s['pegin']), 1)
            change = self.change(wallet, funded, decoded, 'mweb')
            assert_equal(s['mout'], [(self.stealth1, 5 * COIN), change])
            assert_equal(funded['changepos'], 2)

        funded, decoded, s = self.fund(wallet, [], [{self.stealth1: 2}, {self.stealth2: 3}])
        assert_equal((len(s['tin']), len(s['min']), len(s['pegin'])), (1, 0, 1))
        assert_equal((s['tout'], s['pegouts']), ([], []))
        change = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN), (self.stealth2, 3 * COIN), change])

        self.log.info("Transparent coins pay a transparent and an MWEB recipient; only the MWEB payment is pegged in")
        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 1}, {self.stealth1: 2}])
        assert_equal((len(s['tin']), len(s['min']), len(s['pegin'])), (1, 0, 1))
        assert_equal(s['tout'], [(self.transparent1, COIN)])
        assert_equal(s['pegouts'], [])
        change = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN), change])

        self.log.info("A custom MWEB change address on a peg-in gets the MWEB change output")
        change_address = wallet.getnewaddress(address_type='mweb')
        funded, decoded, s = self.fund(wallet, [], [{self.stealth1: 5}], changeAddress=change_address)
        assert_equal((len(s['tin']), len(s['pegin'])), (1, 1))
        address, amount = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(address, change_address)
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN), (change_address, amount)])

        self.log.info("MWEB recipients of transparent coins that subtract the fee leave no change and split the fee")
        funded, decoded, s = self.fund(wallet, [coin], [{self.stealth1: 10}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((len(s['tin']), len(s['pegin']), s['tout']), (1, 1, []))
        assert_equal(s['mout'], [(self.stealth1, 10 * COIN - sats(funded['fee']))])

        funded, decoded, s = self.fund_with_odd_fee(wallet, [coin], [{self.stealth1: 5}, {self.stealth2: 5}],
                                                    subtractFeeFromOutputs=[0, 1])
        fee = sats(funded['fee'])
        assert_equal(funded['changepos'], -1)
        assert_equal((len(s['pegin']), s['tout']), (1, []))
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN - fee // 2 - 1), (self.stealth2, 5 * COIN - fee // 2)])

    def test_mweb_funding(self):
        wallet = self.wallets['mweb']
        coin = self.coins[('mweb', 'mweb')]

        self.log.info("MWEB coins pay MWEB recipients in an MWEB-only transaction; change is an MWEB output")
        funded, decoded, s = self.fund(wallet, [coin], [{self.stealth1: 2}])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin'], s['pegouts']), ([], [5 * COIN], [], [], []))
        change = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN), change])
        assert_equal(funded['changepos'], 1)

        funded, decoded, s = self.fund(wallet, [coin], [{self.stealth1: 1}, {self.stealth2: 2}])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin'], s['pegouts']), ([], [5 * COIN], [], [], []))
        change = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(s['mout'], [(self.stealth1, COIN), (self.stealth2, 2 * COIN), change])

        self.log.info("MWEB coins pay transparent recipients with peg-outs; change is an MWEB output")
        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 1}])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin']), ([], [5 * COIN], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, COIN)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        assert_equal(funded['changepos'], 0)

        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 1}, {self.transparent2: 2}])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin']), ([], [5 * COIN], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, COIN), (self.transparent2, 2 * COIN)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])

        self.log.info("A custom MWEB change address on a peg-out gets the MWEB change output")
        change_address = wallet.getnewaddress(address_type='mweb')
        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 1}], changeAddress=change_address)
        address, amount = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(address, change_address)
        assert_equal(s['mout'], [(change_address, amount)])
        assert_equal(s['pegouts'], [(self.transparent1, COIN)])

        self.log.info("Recipients of MWEB coins that subtract the fee leave no change and split the fee")
        funded, decoded, s = self.fund(wallet, [coin], [{self.stealth1: 5}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tout'], s['pegin'], s['pegouts']), ([], [], []))
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN - sats(funded['fee']))])

        funded, decoded, s = self.fund(wallet, [coin], [{self.transparent1: 5}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tout'], s['pegin'], s['mout']), ([], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, 5 * COIN - sats(funded['fee']))])

        self.log.info("A peg-out left as dust after its share of the fee is refused")
        funded, _, _ = self.fund(wallet, [coin], [{self.transparent1: 1}], subtractFeeFromOutputs=[0])
        assert_raises_rpc_error(-4, "The transaction amount is too small to send after the fee has been deducted",
                                self.fund, wallet, [coin], [{self.transparent1: Decimal(sats(funded['fee']) + 100) / COIN}],
                                subtractFeeFromOutputs=[0])

        for recipient1, recipient2, paid, unpaid in [(self.stealth1, self.stealth2, 'mout', 'pegouts'),
                                                     (self.transparent1, self.transparent2, 'pegouts', 'mout')]:
            funded, decoded, s = self.fund(wallet, [coin], [{recipient1: 2}, {recipient2: 3}], subtractFeeFromOutputs=[0, 1])
            fee = sats(funded['fee'])
            assert_equal(funded['changepos'], -1)
            assert_equal((s['tout'], s['pegin'], s[unpaid]), ([], [], []))
            assert_equal(s[paid], [(recipient1, 2 * COIN - fee // 2 - fee % 2), (recipient2, 3 * COIN - fee // 2)])

        self.log.info("A selected MWEB coin short of a change output pays the recipient without change")
        for inputs in ([coin], []):
            funded, decoded, s = self.fund(wallet, inputs, [{self.stealth1: Decimal('4.99997')}])
            assert_equal(funded['changepos'], -1)
            assert_equal((s['min'], s['pegouts']), ([5 * COIN], []))
            assert_equal(s['mout'], [(self.stealth1, 5 * COIN - 3000)])
            assert_equal(sats(funded['fee']), 3000)

        self.log.info("The MWEB change position finds the change when it goes to the recipient's address")
        shared = wallet.getnewaddress(address_type='mweb')
        funded, decoded, s = self.fund(wallet, [], [{shared: 2}], changeAddress=shared)
        assert_equal([address for address, _ in s['mout']], [shared, shared])
        output = decoded['outputs'][funded['changepos']]
        assert_equal(output['mweb']['address'], shared)
        assert_equal(sats(output['amount']), 3 * COIN - sats(funded['fee']))
        assert_greater_than(sats(output['amount']), 2 * COIN)

    def test_custom_change(self):
        transparent = self.wallets['transparent']
        mweb = self.wallets['mweb']
        transparent_coin = self.coins[('transparent', 'bech32')]
        mweb_coin = self.coins[('mweb', 'mweb')]
        inventory = {name: self.wallets[name].listunspent() for name in ('transparent', 'mweb')}

        self.log.info("An L1-funded MWEB recipient with custom canonical change leaves the change on L1")
        change_address = transparent.getrawchangeaddress(address_type='bech32')
        funded, decoded, s = self.fund(transparent, [transparent_coin], [{self.stealth1: 5}],
                                       changeAddress=change_address)
        assert_equal((s['tin'], s['min'], s['pegouts']), ([10 * COIN], [], []))
        assert_equal([(txin['previous_txid'], txin['previous_vout']) for txin in decoded['inputs']],
                     [(transparent_coin['txid'], transparent_coin['vout'])])
        assert_equal(len(decoded['kernels']), 1)
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN)])
        assert_equal(s['pegin'], [5 * COIN + s['kernel_fee']])
        assert_equal(len(decoded['outputs']), 3)
        address, amount = self.change(transparent, funded, decoded, 'transparent')
        assert_equal((address, amount), (change_address, 5 * COIN - sats(funded['fee'])))
        assert_greater_than(amount, 0)
        assert_equal(s['tout'], [(change_address, amount)])

        self.log.info("An MWEB-funded MWEB recipient pegs custom canonical change out")
        change_address = mweb.getrawchangeaddress(address_type='bech32')
        assert mweb.getaddressinfo(change_address)['ismine']
        funded, decoded, s = self.fund(mweb, [mweb_coin], [{self.stealth1: 2}],
                                       changeAddress=change_address)
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin']), ([], [5 * COIN], [], []))
        assert_equal([txin['mweb']['output_id'] for txin in decoded['inputs']], [mweb_coin['mweb_out']])
        assert_equal(len(decoded['kernels']), 1)
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN)])
        change_amount = 3 * COIN - sats(funded['fee'])
        assert_greater_than(change_amount, 0)
        assert_equal(s['pegouts'], [(change_address, change_amount)])
        assert_equal(s['kernel_fee'], sats(funded['fee']))
        # changepos indexes PSBT outputs; native kernel peg-outs have no such index.
        assert_equal(funded['changepos'], -1)
        assert_equal(len(decoded['outputs']), 1)

        self.log.info("An MWEB-funded canonical recipient and custom canonical change create exactly two peg-outs")
        funded, decoded, s = self.fund(mweb, [mweb_coin], [{self.transparent1: 1}],
                                       changeAddress=change_address)
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin'], s['mout']), ([], [5 * COIN], [], [], []))
        assert_equal([txin['mweb']['output_id'] for txin in decoded['inputs']], [mweb_coin['mweb_out']])
        assert_equal(len(decoded['kernels']), 1)
        assert_equal(decoded['outputs'], [])
        change_amount = 4 * COIN - sats(funded['fee'])
        assert_greater_than(change_amount, 0)
        assert_equal(s['pegouts'], [(self.transparent1, COIN), (change_address, change_amount)])
        assert_equal(s['kernel_fee'], sats(funded['fee']))
        assert_equal(funded['changepos'], -1)

        self.log.info("An L1-only canonical payment rejects custom MWEB change without spending its coin")
        change_address = transparent.getnewaddress(address_type='mweb')
        assert_equal(transparent.listunspent(), inventory['transparent'])
        assert_raises_rpc_error(-4, "MWEB change is incompatible with this transaction type",
                                self.fund, transparent, [transparent_coin], [{self.transparent1: 2}],
                                changeAddress=change_address)
        for name, before in inventory.items():
            assert_equal(self.wallets[name].listunspent(), before)
            assert_equal(self.wallets[name].listlockunspent(), [])

    def test_exact_selection_policy(self):
        def check_inputs(decoded, canonical, mweb):
            assert_equal(
                sorted((txin['previous_txid'], txin['previous_vout'])
                       for txin in decoded['inputs'] if 'mweb' not in txin),
                sorted((coin['txid'], coin['vout']) for coin in canonical),
            )
            assert_equal(
                sorted(txin['mweb']['output_id'] for txin in decoded['inputs'] if 'mweb' in txin),
                sorted(coin['mweb_out'] for coin in mweb),
            )

        self.log.info("Competing layers select the exact single input on the recipient's layer")
        wallet = self.wallets['mixed']
        canonical = self.coins[('mixed', 'bech32')]
        mweb = self.coins[('mixed', 'mweb')]
        inventory = wallet.listunspent()
        _, decoded, s = self.fund(wallet, [], [{self.stealth1: 1}])
        check_inputs(decoded, [], [mweb])
        assert_equal((s['tin'], s['min'], s['pegin'], s['pegouts']), ([], [5 * COIN], [], []))
        _, decoded, s = self.fund(wallet, [], [{self.transparent1: 1}])
        check_inputs(decoded, [canonical], [])
        assert_equal((s['tin'], s['min'], s['pegin'], s['pegouts']), ([10 * COIN], [], [], []))

        self.log.info("An explicit MWEB input pays the canonical recipient only through a peg-out")
        _, decoded, s = self.fund(wallet, [mweb], [{self.transparent1: 1}])
        check_inputs(decoded, [], [mweb])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin']), ([], [5 * COIN], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, COIN)])

        self.log.info("Neither layer alone funds the larger payment; automatic fallback selects both exact IDs")
        for coin, error in ((canonical, "The preselected coins total amount does not cover the transaction target"),
                            (mweb, "Insufficient funds")):
            assert_raises_rpc_error(-4, error, self.fund,
                                    wallet, [coin], [{self.transparent1: 12}])
        for inputs in ([], [canonical, mweb]):
            _, decoded, s = self.fund(wallet, inputs, [{self.transparent1: 12}])
            check_inputs(decoded, [canonical], [mweb])
            assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
            assert_greater_than(s['pegin_amount'], 0)
            assert_equal(s['pegouts'], [(self.transparent1, 12 * COIN)])
        assert_equal(wallet.listunspent(), inventory)
        assert_equal(wallet.listlockunspent(), [])

        self.log.info("Manual MWEB picks remain mandatory and supplement only when enabled")
        pair = self.wallets['mweb_pair']
        selected = self.coins[('mweb_pair', 'mweb')]
        supplemental, = [coin for coin in pair.listunspent() if coin['amount'] == Decimal('1')]
        supplemental = {'mweb_out': supplemental['output_id']}
        pair_inventory = pair.listunspent()
        funded, decoded, _ = self.fund(pair, [selected], [{self.stealth1: 5}], subtractFeeFromOutputs=[0])
        check_inputs(decoded, [], [selected])
        assert_equal(funded['changepos'], -1)
        assert_raises_rpc_error(-4, "Insufficient funds", self.fund,
                                pair, [selected], [{self.stealth1: Decimal('5.5')}])
        _, decoded, _ = self.fund(pair, [selected], [{self.stealth1: Decimal('5.5')}], add_inputs=True)
        check_inputs(decoded, [], [selected, supplemental])

        self.log.info("Locked MWEB coins are excluded from automatic top-up but explicit picks override their lock")
        pair.lockunspent(False, [supplemental])
        try:
            assert_raises_rpc_error(-4, "Insufficient funds", self.fund,
                                    pair, [selected], [{self.stealth1: Decimal('5.5')}], add_inputs=True)
            funded, decoded, _ = self.fund(pair, [supplemental], [{self.stealth1: Decimal('0.5')}])
            check_inputs(decoded, [], [supplemental])
            signed = pair.walletprocesspsbt(funded['psbt'])
            assert signed['complete']
            finalized = pair.finalizepsbt(signed['psbt'])
            assert finalized['complete']
            accepted, = pair.testmempoolaccept([finalized['hex']])
            assert accepted['allowed']
        finally:
            pair.lockunspent(True, [supplemental])
        assert_equal(pair.listunspent(), pair_inventory)
        assert_equal(pair.listlockunspent(), [])

    def test_pegin_pegout(self):
        wallet = self.wallets['mixed']
        coins = [self.coins[('mixed', 'bech32')], self.coins[('mixed', 'mweb')]]

        self.log.info("Transparent and MWEB coins pay transparent recipients with a peg-in and peg-outs")
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 12}])
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(len(s['pegin']), 1)
        assert_equal(s['pegouts'], [(self.transparent1, 12 * COIN)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        assert_equal(funded['changepos'], 1)

        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 6}, {self.transparent2: 6}])
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(len(s['pegin']), 1)
        assert_equal(s['pegouts'], [(self.transparent1, 6 * COIN), (self.transparent2, 6 * COIN)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])

        self.log.info("A custom MWEB change address on a peg-in and peg-out gets the MWEB change output")
        change_address = wallet.getnewaddress(address_type='mweb')
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 12}], changeAddress=change_address)
        address, amount = self.change(wallet, funded, decoded, 'mweb')
        assert_equal(address, change_address)
        assert_equal(s['mout'], [(change_address, amount)])
        assert_equal(s['pegouts'], [(self.transparent1, 12 * COIN)])

        self.log.info("At a fractional fee rate the fee is the transparent fee plus the kernel fee")
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 12}], fee_rate=Decimal('10.1'))
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(s['pegouts'], [(self.transparent1, 12 * COIN)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        assert_equal(sats(funded['fee']), 10 * COIN - s['pegin_amount'] + s['kernel_fee'])

        self.log.info("Transparent recipients of transparent and MWEB coins that subtract the fee leave no change")
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 15}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tin'], s['min'], s['tout'], s['mout']), ([10 * COIN], [5 * COIN], [], []))
        assert_greater_than(s['pegin_amount'], 0)
        assert_equal(s['pegouts'], [(self.transparent1, 15 * COIN - sats(funded['fee']))])

        funded, decoded, s = self.fund_with_odd_fee(wallet, [], [{self.transparent1: 5}, {self.transparent2: 10}],
                                                    subtractFeeFromOutputs=[0, 1])
        fee = sats(funded['fee'])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tin'], s['min'], s['tout'], s['mout']), ([10 * COIN], [5 * COIN], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, 5 * COIN - fee // 2 - 1), (self.transparent2, 10 * COIN - fee // 2)])

        self.log.info("A small transparent coin pegs in what is left after its share of the fee")
        small = self.wallets['small_pegin']
        funded, decoded, s = self.fund(small, [], [{self.transparent1: Decimal('5.0004')}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tin'], s['min'], s['tout'], s['mout']), ([40000], [5 * COIN], [], []))
        assert_greater_than(s['pegin_amount'], 0)
        assert_equal(s['pegouts'], [(self.transparent1, 5 * COIN + 40000 - sats(funded['fee']))])

        self.log.info("Mixed recipients prefer MWEB funding: the transparent recipient gets a peg-out")
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: 1}, {self.stealth1: 2}])
        assert_equal((s['tin'], s['min'], s['tout'], s['pegin']), ([], [5 * COIN], [], []))
        assert_equal(s['pegouts'], [(self.transparent1, COIN)])
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN), self.change(wallet, funded, decoded, 'mweb')])

        self.log.info("Selected transparent and MWEB coins pay mixed recipients with a peg-in and a peg-out")
        funded, decoded, s = self.fund(wallet, coins, [{self.transparent1: 1}, {self.stealth1: 2}])
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(len(s['pegin']), 1)
        assert_equal(s['pegouts'], [(self.transparent1, COIN)])
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN), self.change(wallet, funded, decoded, 'mweb')])

        self.log.info("A stealth output paying the fee gets the odd satoshi before a peg-out")
        funded, decoded, s = self.fund_with_odd_fee(wallet, coins, [{self.transparent1: 13}, {self.stealth1: 2}],
                                                    subtractFeeFromOutputs=[0, 1])
        fee = sats(funded['fee'])
        assert_equal(funded['changepos'], -1)
        assert_equal(s['pegouts'], [(self.transparent1, 13 * COIN - fee // 2)])
        assert_equal(s['mout'], [(self.stealth1, 2 * COIN - fee // 2 - 1)])

        self.log.info("Selected transparent and MWEB coins pay one MWEB recipient that subtracts the fee")
        funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: 15}], subtractFeeFromOutputs=[0])
        assert_equal(funded['changepos'], -1)
        assert_equal((s['tin'], s['min'], s['tout'], s['pegouts']), ([10 * COIN], [5 * COIN], [], []))
        assert_equal(len(s['pegin']), 1)
        assert_equal(s['mout'], [(self.stealth1, 15 * COIN - sats(funded['fee']))])

        self.log.info("A transparent change address on a peg-in from both layers gets transparent change, as in Litecoin")
        change_address = wallet.getrawchangeaddress()
        funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: 12}], changeAddress=change_address)
        assert_equal((s['tin'], s['min'], s['pegouts']), ([10 * COIN], [5 * COIN], []))
        assert_equal(s['mout'], [(self.stealth1, 12 * COIN)])
        assert_equal(s['tout'], [(change_address, 3 * COIN - sats(funded['fee']))])
        assert_equal(decoded['outputs'][funded['changepos']]['script']['address'], change_address)
        assert_equal(s['pegin'], [7 * COIN + s['kernel_fee']])

        self.log.info("Leftover too small for transparent change goes to the fee, with no peg-out")
        changeless = 0
        for leftover in range(fee_with_change := sats(funded['fee']), fee_with_change + 6000, 200):
            funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: Decimal(15 * COIN - leftover) / COIN}], changeAddress=change_address)
            assert_equal((s['tin'], s['min'], s['pegouts']), ([10 * COIN], [5 * COIN], []))
            assert_equal(s['mout'], [(self.stealth1, 15 * COIN - leftover)])
            if funded['changepos'] == -1:
                changeless += 1
                assert_equal(s['tout'], [])
                assert_equal(sats(funded['fee']), leftover)
            else:
                assert_equal(s['tout'], [(change_address, leftover - sats(funded['fee']))])
        assert changeless > 0

        self.log.info("MWEB coins that already pay the MWEB recipient peg their change out to a transparent change address")
        funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: 1}], changeAddress=change_address)
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(s['mout'], [(self.stealth1, COIN)])
        assert_equal(s['pegouts'], [(change_address, 14 * COIN - sats(funded['fee']))])
        assert_greater_than(100000, sats(funded['fee']))

        self.log.info("MWEB coins just short of an MWEB recipient that pays the fee peg their change out too")
        funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: Decimal('5.00001')}], changeAddress=change_address,
                                       subtractFeeFromOutputs=[0])
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN + 1000 - sats(funded['fee']))])
        assert_equal(s['pegouts'], [(change_address, 10 * COIN - 1000)])

    def test_mweb_selection_targets(self):
        self.log.info("Sweeping the MWEB balance with subtract-fee-from-outputs spends only MWEB coins")
        wallet = self.wallets['mixed']
        funded, decoded, s = self.fund(wallet, [], [{self.stealth1: 5}], subtractFeeFromOutputs=[0])
        assert_equal((s['tin'], s['min'], s['pegin']), ([], [5 * COIN], []))
        assert_equal(s['mout'], [(self.stealth1, 5 * COIN - sats(funded['fee']))])

        self.log.info("MWEB coins paying MWEB and transparent recipients are selected with the peg-out's fee")
        wallet = self.wallets['mweb_pair']
        selected = self.coins[('mweb_pair', 'mweb')]
        for leftover in range(3000, 5200, 40):
            for inputs, amount in (([], Decimal(3 * COIN - leftover) / COIN),
                                   ([selected], Decimal(2 * COIN - leftover) / COIN)):
                funded, decoded, s = self.fund(wallet, inputs, [{self.stealth1: 3}, {self.transparent1: amount}])
                assert_equal((s['tin'], s['pegin']), ([], []))
                assert_equal(s['pegouts'], [(self.transparent1, sats(amount))])
                assert (self.stealth1, 3 * COIN) in s['mout']

    def test_selected_pegin_pegout(self):
        wallet = self.wallets['mixed']
        coins = [self.coins[('mixed', 'bech32')], self.coins[('mixed', 'mweb')]]

        self.log.info("Selected transparent and MWEB coins pay a transparent recipient with a peg-in and a peg-out")
        for amount in (1, 12):
            funded, decoded, s = self.fund(wallet, coins, [{self.transparent1: amount}])
            assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
            assert_equal(len(s['pegin']), 1)
            assert_equal(s['pegouts'], [(self.transparent1, amount * COIN)])
            assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        fee_with_change = sats(funded['fee'])

        self.log.info("MWEB change is kept however small, once the change output's fee is paid")
        leftover = fee_with_change + 100
        funded, decoded, s = self.fund(wallet, coins, [{self.transparent1: Decimal(15 * COIN - leftover) / COIN}])
        assert_equal((s['tin'], s['min'], s['tout']), ([10 * COIN], [5 * COIN], []))
        assert_equal(s['pegouts'], [(self.transparent1, 15 * COIN - leftover)])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        assert_equal(s['mout'][0][1], 100)
        assert_equal(sats(funded['fee']), fee_with_change)

        self.log.info("Selected coins short of the fee are topped up with another transparent coin")
        wallet = self.wallets['topup']
        small = self.coins[('topup', 'bech32')]
        mweb = self.coins[('topup', 'mweb')]
        for shortfall in range(3000, 4300, 100):
            amount = Decimal(5 * COIN + 40000 - shortfall) / COIN
            funded, decoded, s = self.fund(wallet, [small, mweb], [{self.transparent1: amount}], add_inputs=True)
            assert_equal(s['min'], [5 * COIN])
            assert 40000 in s['tin']
            assert_equal(s['pegouts'], [(self.transparent1, sats(amount))])
            funded, decoded, s = self.fund(wallet, [small, mweb], [{self.stealth1: amount}], add_inputs=True)
            assert_equal(s['min'], [5 * COIN])
            assert 40000 in s['tin']
            assert_equal(s['mout'][0], (self.stealth1, sats(amount)))

        self.log.info("Automatic selection short of the fee reports insufficient funds")
        wallet = self.wallets['mixed']
        assert_raises_rpc_error(-4, "Insufficient funds", self.fund, wallet, [],
                                [{self.transparent1: Decimal(15 * COIN - 3600) / COIN}])
        funded, decoded, s = self.fund(wallet, [], [{self.transparent1: Decimal(15 * COIN - 4500) / COIN}])
        assert_equal(s['mout'], [self.change(wallet, funded, decoded, 'mweb')])
        assert_equal(sats(funded['fee']) + s['mout'][0][1], 4500)

    def test_pegin_limits(self):
        wallet = self.wallets['tiny_pegin']
        coins = [self.coins[('tiny_pegin', 'bech32')], self.coins[('tiny_pegin', 'mweb')]]
        amount = Decimal('5.0000173')

        self.log.info("A transparent coin smaller than its share of the fee cannot be pegged in")
        assert_raises_rpc_error(-4, "The transaction amount is too small to pay the fee",
                                wallet.walletcreatefundedpsbt, [], [{self.transparent1: amount}], 0,
                                {'fee_rate': 20, 'subtractFeeFromOutputs': [0]})
        assert_raises_rpc_error(-4, "The transaction amount is too small to pay the fee",
                                wallet.walletcreatefundedpsbt, coins, [{self.stealth1: amount}], 0,
                                {'fee_rate': 20, 'subtractFeeFromOutputs': [0], 'add_inputs': False})

        self.log.info("A transparent coin that would peg in dust is refused")
        assert_raises_rpc_error(-4, "The transaction amount is too small to send after the fee has been deducted",
                                wallet.walletcreatefundedpsbt, [], [{self.transparent1: amount}], 0,
                                {'fee_rate': 10, 'subtractFeeFromOutputs': [0]})
        assert_equal(len(wallet.listunspent()), 2)

        self.log.info("A small transparent coin with a larger MWEB coin keeps the MWEB surplus as change")
        wallet = self.wallets['small_pegin']
        coins = [self.coins[('small_pegin', 'bech32')], self.coins[('small_pegin', 'mweb')]]
        change_address = wallet.getrawchangeaddress()
        for fee_rate in (1, 10):
            funded, decoded, s = self.fund(wallet, coins, [{self.stealth1: 1}], changeAddress=change_address, fee_rate=fee_rate)
            assert_equal((s['tin'], s['min'], s['tout']), ([40000], [5 * COIN], []))
            assert_equal(s['pegouts'], [(change_address, 4 * COIN + 40000 - sats(funded['fee']))])
            assert_greater_than(20000, sats(funded['fee']))

    def test_psbt_pegin(self):
        self.log.info("Wallet PSBT processing fills, signs and finalizes an unsigned peg-in")
        wallet = self.wallets['transparent']
        recipient = wallet.getnewaddress(address_type='mweb')
        funded = wallet.walletcreatefundedpsbt([], [{recipient: 5}], 123, {'fee_rate': 10})
        draft = wallet.decodepsbt(funded['psbt'])
        assert_equal((draft['tx_version'], draft['fallback_locktime']), (2, 123))
        filled = wallet.walletprocesspsbt(funded['psbt'], False, 'ALL', True)
        assert not filled['complete']
        assert_equal(wallet.analyzepsbt(filled['psbt'])['next'], 'signer')
        signed = wallet.walletprocesspsbt(filled['psbt'], True, 'ALL', False)
        assert signed['complete']
        finalized = wallet.finalizepsbt(signed['psbt'])
        assert finalized['complete']
        mweb_amounts = sorted(sats(o['amount']) for o in wallet.decodepsbt(signed['psbt'])['outputs'] if 'mweb' in o)

        txid = self.wallet_node.sendrawtransaction(finalized['hex'])
        decoded = self.wallet_node.getrawtransaction(txid, True)
        assert_equal((decoded['version'], decoded['locktime']), (2, 123))
        kernel_id, = [kernel['kernel_id'] for kernel in decoded['vkern']]
        pegin_scripts = [o['scriptPubKey']['hex'] for o in decoded['vout'] if not o['ismweb'] and o['scriptPubKey']['type'] == 'witness_mweb_pegin']
        assert_equal(pegin_scripts, ['5920' + kernel_id])

        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        received = sorted(sats(u['amount']) for u in wallet.listunspent() if u['txid'] == txid and 'output_id' in u)
        assert_equal(received, mweb_amounts)
        assert 5 * COIN in received

    def test_psbt_mweb_spend(self):
        self.log.info("Wallet PSBT processing signs and finalizes an unsigned pure MWEB spend")
        wallet = self.wallets['mweb']
        coin = self.coins[('mweb', 'mweb')]
        recipient = self.funding.getnewaddress(address_type='mweb')
        funded = wallet.walletcreatefundedpsbt([coin], [{recipient: 2}], 0, {'add_inputs': False, 'fee_rate': 10})
        signed = wallet.walletprocesspsbt(funded['psbt'])
        assert signed['complete']
        mweb_input, = [txin['mweb'] for txin in wallet.decodepsbt(signed['psbt'])['inputs']]
        assert_equal(mweb_input['output_id'], coin['mweb_out'])
        assert 'signature' in mweb_input
        finalized = wallet.finalizepsbt(signed['psbt'])
        assert finalized['complete']

        decoded = self.wallet_node.decoderawtransaction(finalized['hex'])
        assert all(txin['ismweb'] for txin in decoded['vin'])
        assert all(txout['ismweb'] for txout in decoded['vout'])
        before = wallet.listunspent()
        locks_before = wallet.listlockunspent()
        assert_raises_rpc_error(
            -8,
            "fundrawtransaction does not support MWEB transaction hex; use walletcreatefundedpsbt for MWEB transaction drafts",
            wallet.fundrawtransaction, finalized['hex'], {'lockUnspents': True})
        assert_equal(wallet.listunspent(), before)
        assert_equal(wallet.listlockunspent(), locks_before)
        self.wallet_node.sendrawtransaction(finalized['hex'])
        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        assert_equal([u['amount'] for u in self.funding.listunspent(addresses=[recipient])], [2])

    def test_sent_output_address(self):
        self.log.info("A sent external MWEB output keeps its stealth address in wallet metadata")
        wallet = self.wallets['mweb']
        recipient = self.funding.getnewaddress(address_type='mweb')
        txid = wallet.sendtoaddress(recipient, 1)
        sent, = [d for d in wallet.gettransaction(txid)['details'] if d['category'] == 'send']
        assert_equal(sent['address'], recipient)
        self.sync_mempools()
        self.generate(self.funding_node, 1, sync_fun=self.sync_all)
        received, = self.funding.listunspent(addresses=[recipient])
        assert_equal(received['output_id'], sent['mweb_out'])
        assert_equal(received['amount'], 1)
        listed, = [t for t in wallet.listtransactions() if t['txid'] == txid and t['category'] == 'send']
        assert_equal(listed['address'], recipient)


if __name__ == '__main__':
    MWEBWalletTxBuilderTest(__file__).main()
