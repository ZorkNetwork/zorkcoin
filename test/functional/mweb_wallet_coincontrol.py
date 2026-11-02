#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet RPC coin control with MWEB outputs."""

from decimal import Decimal

from test_framework.messages import COIN, CTransaction, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import get_mweb_account_descriptor, init_mweb_wallet, setup_mweb_chain, mweb_extra_args
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletCoinControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        funding_node = self.nodes[0]
        wallet_node = self.nodes[1]

        self.log.info("Set up an active MWEB chain and five distinct wallet outputs")
        setup_mweb_chain(funding_node, self)
        self.sync_all()
        coins = self.create_mweb_coins(
            funding_node,
            wallet_node,
            [Decimal('1'), Decimal('2'), Decimal('3'), Decimal('4'), Decimal('5')],
        )

        self.test_listunspent(wallet_node, coins)
        self.test_locking(funding_node, wallet_node, coins)
        self.test_explicit_inputs(funding_node, wallet_node, coins)
        self.test_invalid_inputs(funding_node, wallet_node, coins)
        self.test_funding_failure_retry(funding_node, wallet_node, coins)
        self.test_mixed_inputs(funding_node, wallet_node, coins)
        self.test_createpsbt(funding_node, wallet_node, coins[:3])
        self.test_spent_input(funding_node, wallet_node, coins[-1])
        self.test_mixed_pegin(funding_node, wallet_node)
        self.test_unsafe_incoming(funding_node, wallet_node)
        self.test_depth_and_partial_spends(funding_node, wallet_node)

    def test_depth_and_partial_spends(self, funding_node, wallet_node):
        self.log.info("MWEB selection keeps same-address outputs independent under either APS setting")
        wallet_node.createwallet(wallet_name='mweb_depth_aps', load_on_startup=True)
        receiver = wallet_node.get_wallet_rpc('mweb_depth_aps')
        funding_wallet = funding_node.get_wallet_rpc(self.default_wallet_name)
        address = receiver.getnewaddress(address_type='mweb')
        deep_txid = funding_wallet.sendtoaddress(address, Decimal('0.6'))
        self.sync_mempools()
        self.generate(funding_node, 5, sync_fun=self.sync_all)
        shallow_txid = funding_wallet.sendtoaddress(address, Decimal('1'))
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)

        coins = receiver.listunspent(addresses=[address])
        assert_equal(len(coins), 2)
        deep, = [coin for coin in coins if coin['txid'] == deep_txid]
        shallow, = [coin for coin in coins if coin['txid'] == shallow_txid]
        assert_equal((deep['amount'], deep['confirmations']), (Decimal('0.6'), 6))
        assert_equal((shallow['amount'], shallow['confirmations']), (Decimal('1'), 1))
        deep_id, shallow_id = deep['output_id'], shallow['output_id']
        assert deep_id != shallow_id
        recipient = funding_wallet.getnewaddress(address_type='mweb')

        # Disable the optional APS retry so each run exercises its requested mode.
        # Funding PSBTs leaves both coins unspent for the identical second run.
        for avoid_partial_spends in (0, 1):
            self.restart_node(1, extra_args=self.extra_args[1] + [
                f'-avoidpartialspends={avoid_partial_spends}', '-maxapsfee=-1'])
            receiver = wallet_node.get_wallet_rpc('mweb_depth_aps')
            self.connect_nodes(0, 1)
            self.sync_all()

            def selected(amount, **options):
                funded = receiver.walletcreatefundedpsbt([], {recipient: amount}, 0,
                                                       {'fee_rate': 10, **options})
                return self.mweb_input_ids(receiver, funded['psbt'])

            # Both receipts use the active account. Its smallest-first policy
            # needs just the deep coin for a small payment and both for a larger one.
            assert_equal(selected(Decimal('0.5')), {deep_id})
            assert_equal(selected(Decimal('0.8')), {deep_id, shallow_id})

            self.log.info("MWEB confirmation bounds remain hard until the caller changes them")
            assert_equal(selected(Decimal('0.5'), minconf=6), {deep_id})
            assert_raises_rpc_error(-4, "Insufficient funds", receiver.walletcreatefundedpsbt,
                                   [], {recipient: Decimal('0.8')}, 0,
                                   {'fee_rate': 10, 'minconf': 6})
            assert_equal(selected(Decimal('0.8'), minconf=1), {deep_id, shallow_id})
            assert_equal(selected(Decimal('0.8'), minconf=1, maxconf=1), {shallow_id})
            assert_equal({coin['output_id'] for coin in receiver.listunspent(addresses=[address])},
                         {deep_id, shallow_id})
            assert_equal(receiver.listlockunspent(), [])

    def test_unsafe_incoming(self, funding_node, wallet_node):
        self.log.info("Unsafe-only incoming MWEB funds require explicit funding opt-in")
        wallet_node.createwallet(wallet_name='unsafe_mweb_receiver')
        receiver = wallet_node.get_wallet_rpc('unsafe_mweb_receiver')
        address = receiver.getnewaddress(address_type='mweb')
        funding_wallet = funding_node.get_wallet_rpc(self.default_wallet_name)
        incoming = funding_wallet.sendtoaddress(address, Decimal('0.3'))
        self.sync_mempools()
        wallet_node.syncwithvalidationinterfacequeue()
        assert_equal(receiver.listunspent(minconf=0, include_unsafe=False), [])
        coins = receiver.listunspent(minconf=0, include_unsafe=True)
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['txid'], incoming)
        assert_equal(coins[0]['confirmations'], 0)
        outputs = {funding_wallet.getnewaddress(address_type='mweb'): Decimal('0.1')}
        assert_raises_rpc_error(-4, "Insufficient funds", receiver.walletcreatefundedpsbt,
                               [], outputs, 0, {'fee_rate': 10})
        funded = receiver.walletcreatefundedpsbt([], outputs, 0,
                                               {'fee_rate': 10, 'include_unsafe': True})
        assert_equal(self.mweb_input_ids(receiver, funded['psbt']), {coins[0]['output_id']})
        assert_equal(receiver.listlockunspent(), [])
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        confirmed = receiver.walletcreatefundedpsbt([], outputs, 0, {'fee_rate': 10})
        assert_equal(self.mweb_input_ids(receiver, confirmed['psbt']), {coins[0]['output_id']})

    def create_mweb_coins(self, funding_node, wallet_node, amounts):
        payments = []
        for amount in amounts:
            address = wallet_node.getnewaddress(address_type='mweb')
            txid = funding_node.sendtoaddress(address, amount)
            payments.append((address, txid, amount))
            self.sync_mempools()

        self.generate(funding_node, 1, sync_fun=self.sync_all)

        coins = []
        for address, txid, amount in payments:
            utxos = wallet_node.listunspent(addresses=[address])
            assert_equal(len(utxos), 1)
            utxo = utxos[0]
            assert_equal(utxo['txid'], txid)
            assert_equal(utxo['amount'], amount)
            assert 'output_id' in utxo
            assert 'vout' not in utxo
            coins.append({
                'address': address,
                'amount': amount,
                'input': {'mweb_out': utxo['output_id']},
            })
        return coins

    def test_listunspent(self, wallet, coins):
        self.log.info("listunspent exposes stable MWEB coin-control identifiers and applies amount filters")
        expected_ids = {coin['input']['mweb_out'] for coin in coins[2:4]}
        filtered = wallet.listunspent(
            minconf=1,
            maxconf=9999999,
            addresses=[],
            include_unsafe=True,
            query_options={
                'minimumAmount': Decimal('3'),
                'maximumAmount': Decimal('4'),
            },
        )
        assert_equal({utxo['output_id'] for utxo in filtered}, expected_ids)
        assert all('vout' not in utxo for utxo in filtered)

    def test_locking(self, funding_node, wallet, coins):
        self.log.info("lockunspent accepts MWEB ids and automatic selection skips locked MWEB outputs")
        coin = coins[3]
        assert_raises_rpc_error(
            -8,
            "Invalid parameter, expected locked output",
            wallet.lockunspent,
            True,
            [coin['input']],
        )
        wallet.lockunspent(False, [coin['input']])
        assert_equal(wallet.listlockunspent(), [coin['input']])
        assert_equal(wallet.listunspent(addresses=[coin['address']]), [])
        assert_raises_rpc_error(
            -8,
            "Invalid parameter, output already locked",
            wallet.lockunspent,
            False,
            [coin['input']],
        )

        automatic = wallet.walletcreatefundedpsbt(
            [],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            0,
            {'fee_rate': 10},
        )
        assert coin['input']['mweb_out'] not in self.mweb_input_ids(wallet, automatic['psbt'])
        unlocked_total = sum(c['amount'] for c in coins) - coin['amount']
        assert_raises_rpc_error(
            -4,
            "Insufficient funds",
            wallet.walletcreatefundedpsbt,
            [],
            {funding_node.getnewaddress(address_type='mweb'): unlocked_total + Decimal('0.5')},
            0,
            {'fee_rate': 10},
        )

        automatic_sweep = wallet.sendall(
            recipients=[funding_node.getnewaddress(address_type='mweb')],
            options={'add_to_wallet': False, 'fee_rate': 10, 'psbt': True},
        )
        assert automatic_sweep['complete']
        assert coin['input']['mweb_out'] not in self.mweb_input_ids(wallet, automatic_sweep['psbt'])

        self.log.info("A manually selected MWEB coin remains usable while locked")
        manual = wallet.walletcreatefundedpsbt(
            [coin['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        assert_equal(self.mweb_input_ids(wallet, manual['psbt']), {coin['input']['mweb_out']})

        self.log.info("Non-persistent MWEB locks are cleared on restart")
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [])

        self.log.info("Persistent MWEB locks survive restart and unlocking erases the database record")
        wallet.lockunspent(False, [coin['input']])
        wallet.lockunspent(False, [coin['input']], True)
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [coin['input']])
        wallet.lockunspent(True, [coin['input']])
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [])
        self.connect_nodes(0, 1)

    def test_explicit_inputs(self, funding_node, wallet, coins):
        self.log.info("walletcreatefundedpsbt uses exactly one requested MWEB input and locks it")
        selected = coins[0]
        funded = wallet.walletcreatefundedpsbt(
            [selected['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.25')},
            0,
            {
                'add_inputs': False,
                'fee_rate': 10,
                'lockUnspents': True,
            },
        )
        assert_equal(funded['changepos'], 1)
        assert funded['fee'] > 0
        assert_equal(self.mweb_input_ids(wallet, funded['psbt']), {selected['input']['mweb_out']})
        assert_equal(wallet.listlockunspent(), [selected['input']])
        wallet.lockunspent(True, [selected['input']])

        self.log.info("An MWEB spend of a whole coin has no change output")
        exact = wallet.walletcreatefundedpsbt(
            [selected['input']],
            {funding_node.getnewaddress(address_type='mweb'): selected['amount']},
            0,
            {'add_inputs': False, 'fee_rate': 10, 'subtractFeeFromOutputs': [0]},
        )
        assert_equal(exact['changepos'], -1)
        assert_equal(len(wallet.decodepsbt(exact['psbt'])['outputs']), 1)

        self.log.info("send accepts an exact MWEB input and returns a complete PSBT")
        selected = coins[1]
        sent = wallet.send(
            outputs={funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            options={
                'add_inputs': False,
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [selected['input']],
                'lock_unspents': True,
                'psbt': True,
            },
        )
        assert sent['complete']
        assert 'hex' in sent
        assert 'txid' in sent
        assert_equal(self.mweb_input_ids(wallet, sent['psbt']), {selected['input']['mweb_out']})
        assert_equal(wallet.listlockunspent(), [selected['input']])
        wallet.lockunspent(True, [selected['input']])

        self.log.info("add_inputs controls whether an explicitly selected MWEB coin may be supplemented")
        assert_raises_rpc_error(
            -4,
            "Insufficient funds",
            wallet.walletcreatefundedpsbt,
            [coins[0]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('1.5')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        supplemented = wallet.walletcreatefundedpsbt(
            [coins[0]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('1.5')},
            0,
            {'add_inputs': True, 'fee_rate': 10},
        )
        supplemented_ids = self.mweb_input_ids(wallet, supplemented['psbt'])
        assert_equal(supplemented_ids, {coins[0]['input']['mweb_out'], coins[1]['input']['mweb_out']})

        self.log.info("sendall honors an explicit MWEB subset for both MWEB sends and pegouts")
        swept = wallet.sendall(
            recipients=[funding_node.getnewaddress(address_type='mweb')],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [coins[0]['input'], coins[1]['input']],
                'lock_unspents': True,
                'psbt': True,
            },
        )
        assert swept['complete']
        assert 'hex' in swept
        assert 'txid' in swept
        swept_decoded = wallet.decodepsbt(swept['psbt'])
        # The sweep leaves no change, not even a zero-value output, and pays no fee for one:
        # one output and a kernel weigh 21 units at 100 sat each.
        assert_equal(len(swept_decoded['outputs']), 1)
        assert_equal(swept_decoded['kernels'][0]['fee'], 2_100)
        assert 'mweb_tx_offset' in swept_decoded
        assert 'mweb_stealth_offset' in swept_decoded
        assert wallet.finalizepsbt(swept['psbt'])['complete']
        assert_equal(
            self.mweb_input_ids(wallet, swept['psbt']),
            {coins[0]['input']['mweb_out'], coins[1]['input']['mweb_out']},
        )
        assert_equal(self.locked_ids(wallet), {
            ('mweb', coins[0]['input']['mweb_out']),
            ('mweb', coins[1]['input']['mweb_out']),
        })
        wallet.lockunspent(True)

        pegout = wallet.sendall(
            recipients=[funding_node.getnewaddress()],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [coins[2]['input']],
                'psbt': True,
            },
        )
        assert pegout['complete']
        decoded = wallet.decodepsbt(pegout['psbt'])
        assert_equal(self.mweb_input_ids(wallet, pegout['psbt']), {coins[2]['input']['mweb_out']})
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)

        self.log.info("fundrawtransaction reports the PSBT requirement when only MWEB funding is available")
        raw = wallet.createrawtransaction([], {funding_node.getnewaddress(): Decimal('0.25')})
        assert_raises_rpc_error(
            -8,
            "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding",
            wallet.fundrawtransaction,
            raw,
        )

    def test_invalid_inputs(self, funding_node, wallet, coins):
        self.log.info("MWEB input objects reject malformed, ambiguous, and inapplicable fields")
        recipient = funding_node.getnewaddress(address_type='mweb')
        invalid_id = '00'
        non_hex_id = 'zz' * 32
        unknown_id = '00' * 32

        for output_id in [invalid_id, non_hex_id]:
            assert_raises_rpc_error(
                -8,
                "mweb_out must be a 64-character hexadecimal string",
                wallet.walletcreatefundedpsbt,
                [{'mweb_out': output_id}],
                {recipient: Decimal('0.25')},
            )
            assert_raises_rpc_error(
                -8,
                "mweb_out must be a 64-character hexadecimal string",
                wallet.lockunspent,
                False,
                [{'mweb_out': output_id}],
            )

        mixed_form = {
            'mweb_out': coins[0]['input']['mweb_out'],
            'txid': coins[0]['input']['mweb_out'],
            'vout': 0,
        }
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.walletcreatefundedpsbt,
            [mixed_form],
            {recipient: Decimal('0.25')},
        )
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.lockunspent,
            False,
            [mixed_form],
        )
        for field in ['sequence', 'weight']:
            invalid = dict(coins[0]['input'])
            invalid[field] = 1
            assert_raises_rpc_error(
                -8,
                "sequence and weight do not apply to MWEB inputs",
                wallet.walletcreatefundedpsbt,
                [invalid],
                {recipient: Decimal('0.25')},
            )

        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            wallet.walletcreatefundedpsbt,
            inputs=[coins[0]['input']],
            outputs={recipient: Decimal('0.25')},
            locktime=0,
            options={'add_inputs': False, 'fee_rate': 10},
            bip32derivs=True,
            psbt_version=0,
        )

        assert_raises_rpc_error(
            -8,
            "unknown MWEB output",
            wallet.lockunspent,
            False,
            [{'mweb_out': unknown_id}],
        )
        assert_raises_rpc_error(
            -4,
            "Unable to find MWEB output",
            wallet.walletcreatefundedpsbt,
            [{'mweb_out': unknown_id}],
            {recipient: Decimal('0.25')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        assert_raises_rpc_error(
            -8,
            "not part of wallet",
            wallet.sendall,
            [recipient],
            None,
            'unset',
            None,
            {'inputs': [{'mweb_out': unknown_id}]},
        )

        self.log.info("An MWEB output the wallet sent to someone else is not a wallet input")
        sent_id = coins[0]['input']['mweb_out']
        assert_raises_rpc_error(
            -8,
            "unknown MWEB output",
            funding_node.lockunspent,
            False,
            [{'mweb_out': sent_id}],
        )
        assert_raises_rpc_error(
            -8,
            "not part of wallet",
            funding_node.sendall,
            [recipient],
            None,
            'unset',
            None,
            {'inputs': [{'mweb_out': sent_id}]},
        )

        self.log.info("lockunspent validates the full request before changing any locks")
        assert_raises_rpc_error(
            -8,
            "unknown MWEB output",
            wallet.lockunspent,
            False,
            [coins[0]['input'], {'mweb_out': unknown_id}],
        )
        assert_equal(wallet.listlockunspent(), [])

    def test_funding_failure_retry(self, funding_node, wallet, coins):
        self.log.info("Failed native funding preserves inventory and locks before a PSBT retry")
        selected = coins[2]
        unrelated = [coin['input'] for coin in coins if coin != selected]
        wallet.lockunspent(False, unrelated)
        before = wallet.listunspent()
        locks_before = self.locked_ids(wallet)
        mempool_before = set(wallet.getrawmempool())
        canonical = funding_node.getnewaddress(address_type='bech32')
        stealth = funding_node.getnewaddress(address_type='mweb')
        fixed_change = wallet.getrawchangeaddress(address_type='mweb')
        account_before = get_mweb_account_descriptor(wallet)
        assert_equal(account_before['next'], account_before['next_index'])
        options = {'add_inputs': False, 'fee_rate': 10, 'lockUnspents': True}

        def check_unchanged():
            assert_equal(wallet.listunspent(), before)
            assert_equal(self.locked_ids(wallet), locks_before)
            assert_equal(set(wallet.getrawmempool()), mempool_before)
            assert_equal(get_mweb_account_descriptor(wallet), account_before)
            assert_equal(wallet.getrawchangeaddress(address_type='mweb'), fixed_change)

        # A changeless build neither issues a receive index nor rotates the
        # account's reserved change address. Its input remains reusable here.
        sweep = wallet.walletcreatefundedpsbt(
            [selected['input']], [{stealth: selected['amount']}], 0,
            {**options, 'lockUnspents': False, 'subtractFeeFromOutputs': [0]})
        sweep_decoded = wallet.decodepsbt(sweep['psbt'])
        assert_equal(sweep['changepos'], -1)
        sweep_output, = sweep_decoded['outputs']
        assert_equal((sweep_output['mweb']['address'], sweep_output['amount']),
                     (stealth, selected['amount'] - sweep['fee']))
        signed_sweep = wallet.walletprocesspsbt(sweep['psbt'])
        assert signed_sweep['complete']
        final_sweep = wallet.finalizepsbt(signed_sweep['psbt'])
        assert final_sweep['complete']
        admitted_sweep, = wallet.testmempoolaccept([final_sweep['hex']])
        assert admitted_sweep['allowed'], admitted_sweep
        check_unchanged()

        assert_raises_rpc_error(
            -4, "The transaction amount is too small", wallet.walletcreatefundedpsbt,
            [selected['input']], [{stealth: Decimal(1) / COIN}, {canonical: 1}], 123,
            {**options, 'subtractFeeFromOutputs': [0]})
        check_unchanged()
        assert_raises_rpc_error(
            -4, "Unable to find MWEB output", wallet.walletcreatefundedpsbt,
            [{'mweb_out': '01' * 32}], [{stealth: 1}, {canonical: 1}], 123, options)
        check_unchanged()

        # The legacy raw result cannot represent a peg-out. Its attempted
        # automatic selection must not lock the sole available MWEB coin.
        raw = wallet.createrawtransaction([], {canonical: 1}, 456, False)
        assert_raises_rpc_error(
            -8, "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding",
            wallet.fundrawtransaction, raw, {'fee_rate': 10, 'lockUnspents': True})
        check_unchanged()

        for outputs, locktime, payers in [([{canonical: 1}], 456, []),
                                         ([{stealth: 1}, {canonical: 1}], 123, [0])]:
            funded = wallet.walletcreatefundedpsbt(
                [selected['input']], outputs, locktime, {**options, 'subtractFeeFromOutputs': payers})
            decoded = wallet.decodepsbt(funded['psbt'])
            assert_equal(decoded['fallback_locktime'], locktime)
            txin, = decoded['inputs']
            assert_equal(txin['mweb']['output_id'], selected['input']['mweb_out'])
            assert_equal(self.locked_ids(wallet), locks_before | {('mweb', selected['input']['mweb_out'])})
            kernel, = decoded['kernels']
            assert 'pegin_amount' not in kernel
            pegout, = kernel['pegouts']
            assert_equal((pegout['scriptPubKey']['address'], pegout['amount']), (canonical, COIN))
            assert all('mweb' in output for output in decoded['outputs'])
            change = decoded['outputs'][funded['changepos']]
            assert_equal(change['mweb']['address'], fixed_change)
            assert change['mweb']['address'] not in (canonical, stealth)
            assert wallet.getaddressinfo(change['mweb']['address'])['ismine']
            expected_change = selected['amount'] - len(outputs) - (funded['fee'] if not payers else 0)
            assert_equal(change['amount'], expected_change)
            if payers:
                payment, = [output for output in decoded['outputs'] if output['mweb']['address'] == stealth]
                assert_equal(payment['amount'], 1 - funded['fee'])
            else:
                assert_equal(len(decoded['outputs']), 1)
            assert_equal(selected['amount'], 1 + sum(output['amount'] for output in decoded['outputs']) + funded['fee'])
            signed = wallet.walletprocesspsbt(funded['psbt'])
            assert signed['complete']
            finalized = wallet.finalizepsbt(signed['psbt'])
            assert finalized['complete']
            accepted, = wallet.testmempoolaccept([finalized['hex']])
            assert accepted['allowed']
            wallet.lockunspent(True, [selected['input']])
            check_unchanged()
        wallet.lockunspent(True, unrelated)
        assert_equal(wallet.listlockunspent(), [])

    def test_mixed_inputs(self, funding_node, wallet, coins):
        self.log.info("walletcreatefundedpsbt combines explicitly selected transparent and MWEB inputs")
        address = wallet.getnewaddress(address_type='bech32')
        txid = funding_node.sendtoaddress(address, Decimal('1.5'))
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        utxos = wallet.listunspent(addresses=[address])
        assert_equal(len(utxos), 1)
        transparent = {'txid': txid, 'vout': utxos[0]['vout']}

        funded = wallet.walletcreatefundedpsbt(
            [transparent, coins[3]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('2')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        decoded = wallet.decodepsbt(funded['psbt'])
        assert_equal(len(decoded['inputs']), 2)
        assert_equal(self.mweb_input_ids(wallet, funded['psbt']), {coins[3]['input']['mweb_out']})
        transparent_inputs = [txin for txin in decoded['inputs'] if 'mweb' not in txin]
        assert_equal(len(transparent_inputs), 1)
        assert_equal(transparent_inputs[0]['previous_txid'], transparent['txid'])
        assert_equal(transparent_inputs[0]['previous_vout'], transparent['vout'])

        self.log.info("Mixed funding preserves canonical locktime and default/explicit sequences")
        recipient = funding_node.getnewaddress(address_type='mweb')
        before = wallet.listunspent()
        locks_before = wallet.listlockunspent()
        controls = [(locktime, replaceable, None)
                    for locktime in (0, 123) for replaceable in (None, False, True)]
        controls.append((123, False, 12345))
        for locktime, replaceable, sequence in controls:
            canonical = dict(transparent)
            if sequence is not None:
                canonical['sequence'] = sequence
            options = {'add_inputs': False, 'fee_rate': 10}
            if replaceable is not None:
                options['replaceable'] = replaceable
            draft = wallet.walletcreatefundedpsbt(
                [canonical, coins[3]['input']], {recipient: Decimal('2')}, locktime, options)
            parsed = wallet.decodepsbt(draft['psbt'])
            assert_equal(parsed['fallback_locktime'], locktime)
            assert_equal(len(parsed['inputs']), 2)
            l1_input, = [txin for txin in parsed['inputs'] if 'mweb' not in txin]
            mweb_input, = [txin for txin in parsed['inputs'] if 'mweb' in txin]
            assert_equal((l1_input['previous_txid'], l1_input['previous_vout']),
                         (transparent['txid'], transparent['vout']))
            expected_sequence = sequence if sequence is not None else (
                0xfffffffd if replaceable is not False else 0xfffffffe if locktime else 0xffffffff)
            assert_equal(l1_input.get('sequence', 0xffffffff), expected_sequence)
            assert_equal(mweb_input['mweb']['output_id'], coins[3]['input']['mweb_out'])
            assert 'sequence' not in mweb_input
            assert 'signature' not in mweb_input['mweb']
        assert_equal(wallet.listunspent(), before)
        assert_equal(wallet.listlockunspent(), locks_before)

        self.log.info("Mixed funding requires explicit layer selection and locks both canonical and MWEB inputs")
        # A lone MWEB preset must not silently pull in canonical coins. Keep the
        # other MWEB coins locked so its shortfall cannot be filled on that layer.
        unrelated = [coin['input'] for coin in coins if coin != coins[3]]
        wallet.lockunspent(False, unrelated)
        unrelated_locks = self.locked_ids(wallet)
        available_before = wallet.listunspent()
        mempool_before = set(wallet.getrawmempool())
        assert_raises_rpc_error(
            -4, "Insufficient funds", wallet.walletcreatefundedpsbt,
            [coins[3]['input']], {recipient: Decimal('4.5')}, 123,
            {'add_inputs': True, 'fee_rate': 10, 'lockUnspents': True, 'replaceable': False})
        assert_equal(wallet.listunspent(), available_before)
        assert_equal(self.locked_ids(wallet), unrelated_locks)
        locked = wallet.walletcreatefundedpsbt(
            [transparent, coins[3]['input']], {recipient: Decimal('4.5')}, 123,
            {'add_inputs': False, 'fee_rate': 10, 'lockUnspents': True, 'replaceable': False})
        parsed = wallet.decodepsbt(locked['psbt'])
        assert_equal(parsed['fallback_locktime'], 123)
        assert_equal(len(parsed['inputs']), 2)
        l1_input, = [txin for txin in parsed['inputs'] if 'mweb' not in txin]
        mweb_input, = [txin for txin in parsed['inputs'] if 'mweb' in txin]
        assert_equal((l1_input['previous_txid'], l1_input['previous_vout'], l1_input['sequence']),
                     (transparent['txid'], transparent['vout'], 0xfffffffe))
        assert_equal(mweb_input['mweb']['output_id'], coins[3]['input']['mweb_out'])
        expected_locks = unrelated_locks | {
            ('l1', transparent['txid'], transparent['vout']),
            ('mweb', coins[3]['input']['mweb_out']),
        }
        assert_equal(self.locked_ids(wallet), expected_locks)
        kernel, = parsed['kernels']
        assert not kernel.get('pegouts')
        bridge, = [output for output in parsed['outputs'] if 'mweb' not in output]
        assert_equal(bridge['script']['type'], 'witness_mweb_pegin')
        assert_equal(int(bridge['amount'] * COIN), kernel['pegin_amount'])
        mweb_outputs = [output for output in parsed['outputs'] if 'mweb' in output]
        assert_equal(len(mweb_outputs), 2)
        payment, = [output for output in mweb_outputs if output['mweb']['address'] == recipient]
        assert_equal(payment['amount'], Decimal('4.5'))
        change = parsed['outputs'][locked['changepos']]
        assert 'mweb' in change and change['mweb']['address'] != recipient
        assert wallet.getaddressinfo(change['mweb']['address'])['ismine']
        assert_equal(Decimal('5.5'), sum(output['amount'] for output in mweb_outputs) + locked['fee'])
        assert_equal(4 * COIN + kernel['pegin_amount'],
                     sum(int(output['amount'] * COIN) for output in mweb_outputs) + kernel['fee'])
        signed = wallet.walletprocesspsbt(locked['psbt'])
        assert signed['complete']
        finalized = wallet.finalizepsbt(signed['psbt'])
        assert finalized['complete']
        raw = wallet.decoderawtransaction(finalized['hex'])
        assert raw['vin'][0]['txinwitness']
        accepted, = wallet.testmempoolaccept([finalized['hex']])
        assert accepted['allowed']
        assert_equal(set(wallet.getrawmempool()), mempool_before)
        assert_equal(self.locked_ids(wallet), expected_locks)
        wallet.lockunspent(True)
        assert_equal(wallet.listunspent(), before)
        assert_equal(wallet.listlockunspent(), locks_before)

        self.log.info("lockunspent handles mixed transparent/MWEB arrays and unlock-all")
        wallet.lockunspent(False, [transparent, coins[3]['input']])
        assert_equal(self.locked_ids(wallet), {
            ('l1', transparent['txid'], transparent['vout']),
            ('mweb', coins[3]['input']['mweb_out']),
        })
        wallet.lockunspent(True)
        assert_equal(wallet.listlockunspent(), [])

        self.test_transparent_raw_funding(funding_node, wallet, transparent, utxos[0]['amount'])

    def test_transparent_raw_funding(self, funding_node, wallet, coin, amount):
        self.log.info("Ordinary raw funding keeps fee-payer indexes through every change position")
        first = funding_node.getnewaddress(address_type='bech32')
        second = funding_node.getnewaddress(address_type='bech32')
        raw = wallet.createrawtransaction([coin], [{first: Decimal('0.25')}, {second: Decimal('0.5')}], 123, False)
        before = wallet.listunspent()
        locks_before = wallet.listlockunspent()
        mempool_before = set(wallet.getrawmempool())
        for position in range(3):
            funded = wallet.fundrawtransaction(raw, {
                'add_inputs': False, 'fee_rate': 10, 'subtractFeeFromOutputs': [1], 'changePosition': position})
            assert_equal(funded['changepos'], position)
            decoded = wallet.decoderawtransaction(funded['hex'])
            txin, = decoded['vin']
            assert_equal((txin['txid'], txin['vout'], txin['sequence']),
                         (coin['txid'], coin['vout'], 0xfffffffe))
            assert_equal((decoded['version'], decoded['locktime']), (2, 123))
            assert_equal(len(decoded['vout']), 3)
            paid = {output['scriptPubKey']['address']: output['value'] for output in decoded['vout']}
            assert_equal(paid[first], Decimal('0.25'))
            assert_equal(paid[second], Decimal('0.5') - funded['fee'])
            change = decoded['vout'][position]
            assert change['scriptPubKey']['address'] not in (first, second)
            assert wallet.getaddressinfo(change['scriptPubKey']['address'])['ismine']
            assert_equal(change['value'], amount - Decimal('0.75'))
            assert_equal(sum(paid.values()) + funded['fee'], amount)
            unsigned = FromHex(CTransaction(), funded['hex'])
            assert not unsigned.hogex and unsigned.mweb_tx is None
            signed = wallet.signrawtransactionwithwallet(funded['hex'])
            assert signed['complete']
            signed_tx = FromHex(CTransaction(), signed['hex'])
            assert_equal(signed_tx.serialize_without_witness(), unsigned.serialize_without_witness())
            assert signed_tx.wit.vtxinwit[0].scriptWitness.stack
            accepted, = wallet.testmempoolaccept([signed['hex']])
            assert accepted['allowed']
        assert_equal(wallet.listunspent(), before)
        assert_equal(wallet.listlockunspent(), locks_before)
        assert_equal(set(wallet.getrawmempool()), mempool_before)

    def test_mixed_pegin(self, funding_node, wallet_node):
        self.log.info("Transparent coins pay a transparent and an MWEB recipient in one peg-in")
        funding_node.createwallet(wallet_name='transparent_only')
        payer = funding_node.get_wallet_rpc('transparent_only')
        default = funding_node.get_wallet_rpc(self.default_wallet_name)
        default.sendtoaddress(payer.getnewaddress(), 3)
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        transparent = wallet_node.getnewaddress(address_type='bech32')
        stealth = wallet_node.getnewaddress(address_type='mweb')

        def paid(decoded):
            return {o['mweb']['address'] if 'mweb' in o else o['script'].get('address', o['script']['hex']): int(o['amount'] * COIN)
                    for o in decoded['outputs']}

        # The transparent side carries the transparent payment and a peg-in of
        # everything the MWEB side spends: the MWEB outputs, including change, and the kernel fee.
        funded = payer.walletcreatefundedpsbt([], [{transparent: 1}, {stealth: 1}], 0, {'fee_rate': 10})
        decoded = payer.decodepsbt(funded['psbt'])
        assert_equal(paid(decoded)[transparent], COIN)
        assert_equal(paid(decoded)[stealth], COIN)
        pegin = decoded['kernels'][0]['fee'] + sum(int(o['amount'] * COIN) for o in decoded['outputs'] if 'mweb' in o)
        assert_equal(sorted(int(o['amount'] * COIN) for o in decoded['outputs'] if 'mweb' not in o), sorted([COIN, pegin]))

        # The recipients share the fee; with an odd fee the transparent recipient pays
        # the odd satoshi, whatever the recipient order.
        for outputs in ([{transparent: 1}, {stealth: 1}], [{stealth: 1}, {transparent: 1}]):
            for fee_rate in [Decimal('10.001'), Decimal('10.003'), Decimal('10.007'), Decimal('10.011')]:
                funded = payer.walletcreatefundedpsbt([], outputs, 0, {'fee_rate': fee_rate, 'subtractFeeFromOutputs': [0, 1]})
                fee = int(funded['fee'] * COIN)
                if fee % 2:
                    break
            assert_equal(fee % 2, 1)
            decoded = payer.decodepsbt(funded['psbt'])
            assert_equal(paid(decoded)[transparent], COIN - fee // 2 - 1)
            assert_equal(paid(decoded)[stealth], COIN - fee // 2)

        funded = payer.walletcreatefundedpsbt([], [{transparent: 1}, {stealth: 1}], 0, {'fee_rate': 10, 'subtractFeeFromOutputs': [1]})
        fee = int(funded['fee'] * COIN)
        decoded = payer.decodepsbt(funded['psbt'])
        assert_equal(paid(decoded)[transparent], COIN)
        assert_equal(paid(decoded)[stealth], COIN - fee)

        # The fee does not depend on the amounts, so these leave the transparent recipient dust or less than nothing.
        assert_raises_rpc_error(-4, "The transaction amount is too small to send after the fee has been deducted",
                                payer.walletcreatefundedpsbt, [], [{transparent: Decimal(fee + 100) / COIN}, {stealth: 1}], 0,
                                {'fee_rate': 10, 'subtractFeeFromOutputs': [0]})
        assert_raises_rpc_error(-4, "The transaction amount is too small to pay the fee",
                                payer.walletcreatefundedpsbt, [], [{transparent: Decimal(fee - 100) / COIN}, {stealth: 1}], 0,
                                {'fee_rate': 10, 'subtractFeeFromOutputs': [0]})

        txid = payer.sendmany("", {transparent: 1, stealth: 1}, 0, "", [transparent])
        fee = -int(payer.gettransaction(txid)['fee'] * COIN)
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        received = {u['address']: u['amount'] for u in wallet_node.listunspent(addresses=[transparent, stealth])}
        assert_equal(received, {transparent: Decimal(COIN - fee) / COIN, stealth: 1})

    def test_spent_input(self, funding_node, wallet, coin):
        self.log.info("Committing a manually selected locked MWEB coin unlocks and spends it")
        wallet.lockunspent(False, [coin['input']])
        assert_equal(wallet.listlockunspent(), [coin['input']])
        sent = wallet.send(
            outputs={funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            options={
                'add_inputs': False,
                'fee_rate': 10,
                'inputs': [coin['input']],
            },
        )
        assert sent['complete']
        self.sync_mempools()
        assert_equal(wallet.listlockunspent(), [])
        assert_equal(wallet.listunspent(addresses=[coin['address']]), [])

        self.log.info("Spent MWEB identifiers are rejected by locking and explicit sendall selection")
        assert_raises_rpc_error(
            -8,
            "expected unspent output",
            wallet.lockunspent,
            False,
            [coin['input']],
        )
        assert_raises_rpc_error(
            -8,
            "was already spent",
            wallet.sendall,
            [funding_node.getnewaddress(address_type='mweb')],
            None,
            'unset',
            None,
            {'inputs': [coin['input']]},
        )

    def test_createpsbt(self, funding_node, wallet, coins):
        self.log.info("createpsbt creates an ID-only MWEB input for the updater role")
        recipient = funding_node.getnewaddress(address_type='mweb')
        fee = Decimal('0.0001')
        selected = coins[:2]
        amount = sum((coin['amount'] for coin in selected), Decimal('0')) - fee
        created = wallet.createpsbt([coin['input'] for coin in selected], {recipient: amount})
        decoded = wallet.decodepsbt(created)
        assert_equal(
            [txin['mweb']['output_id'] for txin in decoded['inputs']],
            [coin['input']['mweb_out'] for coin in selected],
        )
        assert all(set(txin['mweb']) == {'output_id'} for txin in decoded['inputs'])
        assert_equal(wallet.analyzepsbt(created)['next'], 'updater')

        self.log.info("utxoupdatepsbt attaches public fields but leaves the confidential amount to the owner")
        public_updated = funding_node.utxoupdatepsbt(created)
        public_inputs = [txin['mweb'] for txin in funding_node.decodepsbt(public_updated)['inputs']]
        assert all('output_commit' in txin for txin in public_inputs)
        assert all('output_pubkey' in txin for txin in public_inputs)
        assert all('amount' not in txin for txin in public_inputs)
        assert_equal(funding_node.analyzepsbt(public_updated)['next'], 'updater')

        self.log.info("walletprocesspsbt supplies private metadata and infers the MWEB kernel fee")
        private_updated = wallet.walletprocesspsbt(public_updated, False)
        assert not private_updated['complete']
        updated_decoded = wallet.decodepsbt(private_updated['psbt'])
        updated_inputs = [txin['mweb'] for txin in updated_decoded['inputs']]
        assert_equal(
            [txin['amount'] for txin in updated_inputs],
            [self.to_sats(coin['amount']) for coin in selected],
        )
        assert all('shared_secret' in txin for txin in updated_inputs)
        assert all(txin['address_descriptor'].startswith('mweb(') for txin in updated_inputs)
        assert all('signature' not in txin for txin in updated_inputs)
        assert_equal(len(updated_decoded['kernels']), 1)
        assert_equal(updated_decoded['kernels'][0]['fee'], self.to_sats(fee))
        analysis = wallet.analyzepsbt(private_updated['psbt'])
        assert_equal(analysis['next'], 'signer')
        assert_equal(analysis['fee'], fee)

        signed = wallet.walletprocesspsbt(private_updated['psbt'])
        assert signed['complete']
        for combined in [
            wallet.combinepsbt([created, signed['psbt']]),
            wallet.combinepsbt([signed['psbt'], created]),
        ]:
            assert wallet.finalizepsbt(combined)['complete']
        finalized = wallet.finalizepsbt(signed['psbt'])
        assert finalized['complete']
        funding_node.sendrawtransaction(finalized['hex'], 0)

        self.log.info("Transparent createpsbt destinations become pegouts for MWEB-only inputs")
        pegout_recipient = funding_node.getnewaddress(address_type='bech32')
        pegout_amount = coins[2]['amount'] - fee
        pegout_created = wallet.createpsbt([coins[2]['input']], {pegout_recipient: pegout_amount})
        pegout_decoded = wallet.decodepsbt(pegout_created)
        assert_equal(len(pegout_decoded['outputs']), 0)
        assert_equal(len(pegout_decoded['kernels']), 1)
        assert 'fee' not in pegout_decoded['kernels'][0]
        assert_equal(len(pegout_decoded['kernels'][0]['pegouts']), 1)
        assert_equal(pegout_decoded['kernels'][0]['pegouts'][0]['amount'], self.to_sats(pegout_amount))
        assert_equal(pegout_decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], pegout_recipient)

        pegout_signed = wallet.walletprocesspsbt(pegout_created)
        assert pegout_signed['complete']
        assert wallet.finalizepsbt(wallet.combinepsbt([pegout_created, pegout_signed['psbt']]))['complete']
        pegout_finalized = wallet.finalizepsbt(pegout_signed['psbt'])
        assert pegout_finalized['complete']
        funding_node.sendrawtransaction(pegout_finalized['hex'], 0)
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)

        received = funding_node.listunspent(addresses=[recipient])
        assert_equal(len(received), 1)
        assert_equal(received[0]['amount'], amount)
        pegout_received = funding_node.listreceivedbyaddress(minconf=1, address_filter=pegout_recipient)
        assert_equal(len(pegout_received), 1)
        assert_equal(pegout_received[0]['amount'], pegout_amount)

        self.log.info("createpsbt validates MWEB identifiers and rejects ambiguous input layers")
        unknown = {'mweb_out': '11' * 32}
        unknown_psbt = wallet.createpsbt([unknown], {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')})
        assert_equal(wallet.analyzepsbt(unknown_psbt)['next'], 'updater')
        assert not wallet.walletprocesspsbt(unknown_psbt)['complete']

        for output_id in ['00', 'zz' * 32]:
            assert_raises_rpc_error(
                -8,
                "mweb_out must be a 64-character hexadecimal string",
                wallet.createpsbt,
                [{'mweb_out': output_id}],
                {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
            )

        mixed_form = {'mweb_out': unknown['mweb_out'], 'txid': unknown['mweb_out'], 'vout': 0}
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.createpsbt,
            [mixed_form],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )
        assert_raises_rpc_error(
            -8,
            "sequence and weight do not apply to MWEB inputs",
            wallet.createpsbt,
            [dict(unknown, sequence=1)],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )
        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            wallet.createpsbt,
            inputs=[unknown],
            outputs={wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
            psbt_version=0,
        )
        assert_raises_rpc_error(
            -8,
            "MWEB inputs cannot be represented in raw transaction hex",
            wallet.createrawtransaction,
            [unknown],
            {wallet.getnewaddress(): Decimal('0.1')},
        )

        transparent = next(utxo for utxo in wallet.listunspent() if 'vout' in utxo)
        assert_raises_rpc_error(
            -8,
            "Mixed transparent and MWEB inputs require explicit peg-in or pegout metadata",
            wallet.createpsbt,
            [unknown, {'txid': transparent['txid'], 'vout': transparent['vout']}],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )

    def mweb_input_ids(self, wallet, psbt):
        return {
            txin['mweb']['output_id']
            for txin in wallet.decodepsbt(psbt)['inputs']
            if 'mweb' in txin
        }

    def to_sats(self, amount):
        return int(amount * Decimal('100000000'))

    def locked_ids(self, wallet):
        result = set()
        for output in wallet.listlockunspent():
            if 'mweb_out' in output:
                result.add(('mweb', output['mweb_out']))
            else:
                result.add(('l1', output['txid'], output['vout']))
        return result


if __name__ == '__main__':
    MWEBWalletCoinControlTest(__file__).main()
