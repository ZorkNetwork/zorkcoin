#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet policy for mixed transparent and MWEB recipients and MWEB change."""

from decimal import Decimal
from itertools import permutations

from test_framework.messages import COIN, blake3, ser_pubkey, ser_signature, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import init_mweb_wallet, setup_mweb_chain, mweb_extra_args
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletRecipientsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        sender = self.nodes[0]
        receiver = self.nodes[1]

        self.log.info("Set up spendable balances on both the transparent and MWEB layers")
        setup_mweb_chain(sender, self)
        mweb_funding_address = sender.getnewaddress(address_type='mweb')
        sender.sendtoaddress(mweb_funding_address, 30)
        self.generate(sender, 1, sync_fun=self.sync_all)

        transparent_coins = [coin for coin in sender.listunspent() if 'vout' in coin]
        assert len(transparent_coins) >= 2

        mweb_coin, = sender.listunspent(addresses=[mweb_funding_address])
        self.test_custom_change_fee_payer(sender, receiver, transparent_coins[0], mweb_coin)
        self.test_selective_fee_subtraction(sender, receiver, transparent_coins[0])
        self.test_mixed_fee_subtraction(sender, receiver, transparent_coins[0])
        custom_change = self.test_custom_mweb_change(sender, receiver, transparent_coins[1])
        self.test_mixed_send_from_mweb(sender, receiver, custom_change)
        self.test_sendmany_mweb_recipients(sender, receiver)
        self.test_sendall_mixed_recipients(sender, receiver)

    def test_custom_change_fee_payer(self, sender, receiver, transparent_coin, mweb_coin):
        self.log.info("Custom change preserves the selected MWEB fee payer at both requested positions")
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        canonical_recipient = receiver.getnewaddress(address_type='bech32')
        requested = Decimal('1')
        outputs = [{mweb_recipient: requested}, {canonical_recipient: requested}]
        mempool_before = sender.getrawmempool()
        inventory_before = sender.listunspent()

        def output_id(output):
            # Deployed output IDs hash the message and rangeproof separately;
            # MWEBOutput.hash instead hashes the complete wire serialization.
            return blake3(
                ser_pubkey(output.commitment) + ser_pubkey(output.sender_pubkey) + ser_pubkey(output.receiver_pubkey)
                + blake3(output.message.serialize()).serialize() + blake3(bytes(output.proof)).serialize()
                + ser_signature(output.signature)).to_hex()

        for source_is_mweb, coin in ((False, transparent_coin), (True, mweb_coin)):
            inputs = [{'mweb_out': coin['output_id']}] if source_is_mweb else [{'txid': coin['txid'], 'vout': coin['vout']}]
            change_amount = coin['amount'] - 2 * requested
            assert change_amount > 0
            for change_type in ('bech32', 'mweb'):
                change_address = sender.getnewaddress(address_type=change_type)
                assert sender.getaddressinfo(change_address)['ismine']
                for position in (0, 1):
                    self.log.debug("MWEB source=%s, change type=%s, requested position=%d", source_is_mweb, change_type, position)
                    funded = sender.walletcreatefundedpsbt(inputs, outputs, 0, {
                        'add_inputs': False,
                        'changeAddress': change_address,
                        'changePosition': position,
                        'fee_rate': 10,
                        'subtractFeeFromOutputs': [0],
                    })
                    fee = funded['fee']
                    assert fee > 0
                    assert_equal(sender.analyzepsbt(funded['psbt'])['fee'], fee)
                    processed = sender.walletprocesspsbt(funded['psbt'])
                    assert processed['complete']
                    unsigned = sender.decodepsbt(funded['psbt'])
                    signed = sender.decodepsbt(processed['psbt'])
                    for candidate in (unsigned, signed):
                        assert_equal(candidate['fee'], fee)
                        txin, = candidate['inputs']
                        if source_is_mweb:
                            assert_equal(txin['mweb']['output_id'], coin['output_id'])
                            assert_equal(txin['mweb']['amount'], self.to_sats(coin['amount']))
                        else:
                            assert 'mweb' not in txin
                            assert_equal((txin['previous_txid'], txin['previous_vout']), (coin['txid'], coin['vout']))
                        kernel, = candidate['kernels']
                        kernel_fee = Decimal(kernel['fee']) / COIN
                        mweb_outputs = [output for output in candidate['outputs'] if 'mweb' in output]
                        canonical_outputs = [output for output in candidate['outputs'] if 'mweb' not in output]
                        pegouts = kernel.get('pegouts', [])
                        payments = [(output['mweb']['address'], output['amount']) for output in mweb_outputs]
                        payments += [(output['script']['address'], output['amount']) for output in canonical_outputs
                                     if output['script']['type'] != 'witness_mweb_pegin']
                        payments += [(pegout['scriptPubKey']['address'], Decimal(pegout['amount']) / COIN) for pegout in pegouts]
                        # Caller index0 pays the whole fee, including both fee layers.
                        # Change insertion and canonical/MWEB regrouping must preserve it.
                        assert_equal(sorted(payments), sorted([
                            (mweb_recipient, requested - fee),
                            (canonical_recipient, requested),
                            (change_address, change_amount),
                        ]))
                        assert_equal(sum(amount for _, amount in payments) + fee, coin['amount'])
                        pegin = Decimal(kernel.get('pegin_amount', 0)) / COIN
                        assert_equal((coin['amount'] if source_is_mweb else 0) + pegin,
                                     sum(output['amount'] for output in mweb_outputs)
                                     + sum(Decimal(pegout['amount']) / COIN for pegout in pegouts) + kernel_fee)
                        canonical_fee = (0 if source_is_mweb else coin['amount']) - sum(output['amount'] for output in canonical_outputs)
                        assert_equal(canonical_fee + kernel_fee, fee)
                        if change_type == 'mweb':
                            # MWEB change follows its payee in PSBT output metadata;
                            # the caller's canonical change position does not relocate it.
                            assert_equal(funded['changepos'], len(candidate['outputs']) - 1)
                            assert_equal(candidate['outputs'][funded['changepos']]['mweb']['address'], change_address)
                        elif source_is_mweb:
                            # Native kernel peg-out change has no PSBT output index.
                            assert_equal(funded['changepos'], -1)
                            assert_equal([p['scriptPubKey']['address'] for p in pegouts], [canonical_recipient, change_address])
                        else:
                            assert_equal(funded['changepos'], position)
                            assert_equal(candidate['outputs'][position]['script']['address'], change_address)

                    finalized = sender.finalizepsbt(processed['psbt'])
                    assert finalized['complete']
                    tx = tx_from_hex(finalized['hex'])
                    assert_equal(tx.serialize_with_mweb().hex(), finalized['hex'])
                    raw = sender.decoderawtransaction(finalized['hex'])
                    assert_equal([vin['output_id'] for vin in raw['vin'] if vin['ismweb']], [coin['output_id']] if source_is_mweb else [])
                    assert_equal([(vin['txid'], vin['vout']) for vin in raw['vin'] if not vin['ismweb']],
                                 [] if source_is_mweb else [(coin['txid'], coin['vout'])])
                    # Compare output identities rather than assuming PSBT order is wire order.
                    expected_mweb = sorted((o['mweb']['output_commit'], o['mweb']['sender_pubkey'], o['mweb']['output_pubkey'])
                                           for o in signed['outputs'] if 'mweb' in o)
                    actual_mweb = sorted((o.commitment.to_bytes(33, 'little').hex(), o.sender_pubkey.to_bytes(33, 'little').hex(),
                                          o.receiver_pubkey.to_bytes(33, 'little').hex()) for o in tx.mweb_tx.body.outputs)
                    assert_equal(actual_mweb, expected_mweb)
                    assert_equal(sorted(vout['output_id'] for vout in raw['vout'] if vout['ismweb']),
                                 sorted(output_id(output) for output in tx.mweb_tx.body.outputs))
                    assert_equal([(o['scriptPubKey']['hex'], o['value']) for o in raw['vout'] if not o['ismweb']],
                                 [(o['script']['hex'], o['amount']) for o in signed['outputs'] if 'mweb' not in o])
                    raw_kernel, = raw['vkern']
                    signed_kernel, = signed['kernels']
                    assert_equal(raw_kernel['fee'], Decimal(signed_kernel['fee']) / COIN)
                    assert_equal(raw_kernel['pegin'], Decimal(signed_kernel.get('pegin_amount', 0)) / COIN)
                    assert_equal([(p['scriptPubKey']['hex'], p['value']) for p in raw_kernel['pegout']],
                                 [(p['scriptPubKey']['hex'], Decimal(p['amount']) / COIN) for p in signed_kernel.get('pegouts', [])])
                    accepted, = sender.testmempoolaccept([finalized['hex']])
                    assert accepted['allowed']
                    assert raw['txid'] not in sender.getrawmempool()

        assert_equal(sender.getrawmempool(), mempool_before)
        assert_equal(sender.listunspent(), inventory_before)

    def test_selective_fee_subtraction(self, sender, receiver, coin):
        self.log.info("A single fee payer follows caller positions through mixed output construction")
        recipients = [
            (receiver.getnewaddress(address_type='mweb'), Decimal('1')),
            (receiver.getnewaddress(address_type='bech32'), Decimal('2')),
        ]
        stealth_addresses = {recipients[0][0]}
        inputs = [{'txid': coin['txid'], 'vout': coin['vout']}]
        mempool_before = sender.getrawmempool()

        def create(rpc, outputs, selected, *, fee_rate=Decimal('10')):
            options = {'add_inputs': False, 'fee_rate': fee_rate}
            if rpc == 'send':
                return sender.send(outputs=outputs, options={
                    **options,
                    'inputs': inputs,
                    'add_to_wallet': False,
                    'psbt': True,
                    'subtract_fee_from_outputs': selected,
                })
            return sender.walletcreatefundedpsbt(inputs, outputs, 0, {
                **options,
                'subtractFeeFromOutputs': selected,
            })

        def output_address(output):
            return output.get('mweb', {}).get('address') or output.get('script', {}).get('address')

        def check_result(rpc, result, ordered, payers, *, with_data=False, require_odd=False):
            decoded = sender.decodepsbt(result['psbt'])
            fee = decoded['fee']
            assert fee > 0
            fee_sats = self.to_sats(fee)
            if require_odd:
                assert_equal(fee_sats % 2, 1)
            recipient_addresses = {address for address, _ in ordered}
            expected_change = coin['amount'] - sum(amount for _, amount in ordered) - (0 if payers else fee)
            assert expected_change > 0
            deductions = {address: fee_sats // len(payers) for address in payers}
            if payers:
                # Native fee remainder order is canonical outputs before stealth,
                # preserving caller order within each layer on this peg-in path.
                first = min((i for i, (address, _) in enumerate(ordered) if address in payers),
                            key=lambda i: (ordered[i][0] in stealth_addresses, i))
                deductions[ordered[first][0]] += fee_sats % len(payers)
            assert_equal(sender.analyzepsbt(result['psbt'])['fee'], fee)
            if rpc == 'send':
                assert result['complete']
            else:
                assert_equal(result['fee'], fee)

            processed = sender.walletprocesspsbt(result['psbt'])
            assert processed['complete']
            signed = sender.decodepsbt(processed['psbt'])
            assert_equal(signed['fee'], fee)
            for candidate in (decoded, signed):
                assert_equal(len(candidate['inputs']), 1)
                assert_equal(candidate['inputs'][0]['previous_txid'], coin['txid'])
                assert_equal(candidate['inputs'][0]['previous_vout'], coin['vout'])
                assert 'mweb' not in candidate['inputs'][0]
                assert_equal(len(candidate['kernels']), 1)
                assert 'pegin_amount' in candidate['kernels'][0]
                assert 'pegouts' not in candidate['kernels'][0]
                # Caller positions select the payer; canonical/stealth wire regrouping
                # and the inserted peg-in/change outputs do not change that selection.
                for address, requested in ordered:
                    expected = requested - Decimal(deductions.get(address, 0)) / COIN
                    assert_equal(self.output_for_address(candidate, address)['amount'], expected)

                changes = [
                    (index, output) for index, output in enumerate(candidate['outputs'])
                    if output_address(output) is not None and output_address(output) not in recipient_addresses
                ]
                assert_equal(len(changes), 1)
                change_index, change = changes[0]
                assert_equal(change['amount'], expected_change)
                assert sender.getaddressinfo(output_address(change))['ismine']
                if rpc == 'walletcreatefundedpsbt':
                    assert_equal(result['changepos'], change_index)

                pegin_outputs = [output for output in candidate['outputs']
                                 if output.get('script', {}).get('type') == 'witness_mweb_pegin']
                assert_equal(len(pegin_outputs), 1)
                data_outputs = [output for output in candidate['outputs']
                                if output.get('script', {}).get('type') == 'nulldata']
                assert_equal(len(data_outputs), int(with_data))
                if with_data:
                    assert_equal(data_outputs[0]['script']['hex'], '6a03010203')
                    assert_equal(data_outputs[0]['amount'], 0)
                assert_equal(len(candidate['outputs']), len(ordered) + 2 + int(with_data))
                payments = sum(output['amount'] for output in candidate['outputs'] if output not in pegin_outputs)
                assert_equal(coin['amount'] - payments, fee)

            finalized = sender.finalizepsbt(processed['psbt'])
            assert finalized['complete']
            raw = sender.decoderawtransaction(finalized['hex'])
            assert_equal([(txin['txid'], txin['vout']) for txin in raw['vin']], [(coin['txid'], coin['vout'])])
            if rpc == 'send':
                assert_equal(raw['txid'], result['txid'])
                assert_equal(finalized['hex'], result['hex'])
            assert raw['txid'] not in sender.getrawmempool()

        for ordered in (recipients, list(reversed(recipients))):
            for outputs in ([{address: amount} for address, amount in ordered], dict(ordered)):
                for fee_payer in (0, 1):
                    for rpc in ('send', 'walletcreatefundedpsbt'):
                        check_result(rpc, create(rpc, outputs, [fee_payer]), ordered, [ordered[fee_payer][0]])

        self.log.info("OP_RETURN counts in fee-payer positions; later change does not")
        outputs = [{recipients[0][0]: Decimal('1')}, {'data': '010203'}, {recipients[1][0]: Decimal('2')}]
        for rpc in ('send', 'walletcreatefundedpsbt'):
            for selected, message in (([-1], 'negative position'), ([3], 'position too large'), ([0, 0], 'duplicated position')):
                assert_raises_rpc_error(-8, message, create, rpc, outputs, selected)
            # Index1 selects the zero-valued data output itself, so funding
            # cannot deduct its fee from either adjacent addressed recipient.
            assert_raises_rpc_error(-4, "too small", create, rpc, outputs, [1])
            for selected, payer in ((0, recipients[0][0]), (2, recipients[1][0])):
                check_result(rpc, create(rpc, outputs, [selected]), recipients, [payer], with_data=True)

        self.log.info("Four distinct recipients preserve every caller fee index across all24 orders")
        four = recipients + [
            (receiver.getnewaddress(address_type='mweb'), Decimal('3')),
            (receiver.getnewaddress(address_type='bech32'), Decimal('4')),
        ]
        stealth_addresses.add(four[2][0])
        # Exercise nonzero remainders for both two-payer and four-payer cases.
        for fee_rate in map(Decimal, ('10.001', '10.003', '10.007', '10.011', '10.013', '10.017', '10.019', '10.023')):
            probe = create('walletcreatefundedpsbt', dict(four), [0, 1, 2, 3], fee_rate=fee_rate)
            if self.to_sats(probe['fee']) % 2:
                break
        else:
            raise AssertionError("No fee rate produced an odd four-recipient fee")
        for ordered in permutations(four):
            for outputs in ([{address: amount} for address, amount in ordered], dict(ordered)):
                for selected in ([0], [1], [2], [3], [0, 2], [1, 3], [0, 1, 2, 3], []):
                    payers = [ordered[i][0] for i in selected]
                    for rpc in ('send', 'walletcreatefundedpsbt'):
                        result = create(rpc, outputs, selected, fee_rate=fee_rate)
                        check_result(rpc, result, ordered, payers, require_odd=True)

        assert_equal(sender.getrawmempool(), mempool_before)
        assert sender.gettxout(coin['txid'], coin['vout']) is not None

    def test_mixed_fee_subtraction(self, sender, receiver, coin):
        self.log.info("walletcreatefundedpsbt splits the fee across transparent and MWEB recipients")
        transparent_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        transparent_requested = coin['amount'] / 2
        mweb_requested = coin['amount'] - transparent_requested

        funded = sender.walletcreatefundedpsbt(
            [{'txid': coin['txid'], 'vout': coin['vout']}],
            [{transparent_recipient: transparent_requested}, {mweb_recipient: mweb_requested}],
            0,
            {
                'add_inputs': False,
                'fee_rate': 10,
                'subtractFeeFromOutputs': [0, 1],
            },
        )
        assert_equal(funded['changepos'], -1)
        assert funded['fee'] > 0

        decoded = sender.decodepsbt(funded['psbt'])
        transparent_output = self.output_for_address(decoded, transparent_recipient)
        mweb_output = self.output_for_address(decoded, mweb_recipient)
        # The canonical payee takes the remainder when the two shares differ by a satoshi.
        fee = self.to_sats(funded['fee'])
        assert_equal(self.to_sats(transparent_output['amount']), self.to_sats(transparent_requested) - fee // 2 - fee % 2)
        assert_equal(self.to_sats(mweb_output['amount']), self.to_sats(mweb_requested) - fee // 2)
        assert_equal(transparent_output['amount'] + mweb_output['amount'], coin['amount'] - funded['fee'])
        assert_equal(sender.analyzepsbt(funded['psbt'])['next'], 'signer')

    def test_custom_mweb_change(self, sender, receiver, coin):
        self.log.info("walletcreatefundedpsbt pays and reports a custom MWEB change address")
        transparent_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        change_address = sender.getnewaddress(address_type='mweb')

        funded = sender.walletcreatefundedpsbt(
            [{'txid': coin['txid'], 'vout': coin['vout']}],
            [{transparent_recipient: Decimal('1')}, {mweb_recipient: Decimal('2')}],
            0,
            {
                'add_inputs': False,
                'changeAddress': change_address,
                'changePosition': 0,
                'fee_rate': 10,
            },
        )
        decoded = sender.decodepsbt(funded['psbt'])
        change_position = funded['changepos']
        assert change_position != 0
        assert_equal(decoded['outputs'][change_position]['mweb']['address'], change_address)

        change_amount = coin['amount'] - Decimal('3') - funded['fee']
        assert_equal(decoded['outputs'][change_position]['amount'], change_amount)
        assert_equal(self.output_for_address(decoded, transparent_recipient)['amount'], Decimal('1'))
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('2'))
        assert all('mweb' not in txin for txin in decoded['inputs'])
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' in decoded['kernels'][0]
        assert 'pegouts' not in decoded['kernels'][0]

        txid = self.broadcast_psbt(sender, funded['psbt'])
        self.generate(sender, 1, sync_fun=self.sync_all)
        assert_equal(sender.gettransaction(txid)['confirmations'], 1)
        assert_equal(receiver.listunspent(addresses=[transparent_recipient])[0]['amount'], Decimal('1'))
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('2'))

        change = sender.listunspent(addresses=[change_address])
        assert_equal(len(change), 1)
        assert_equal(change[0]['amount'], change_amount)
        assert 'output_id' in change[0]
        return change[0]

    def test_mixed_send_from_mweb(self, sender, receiver, change):
        self.log.info("send pays mixed recipients from one selected MWEB input")
        transparent_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        sent = sender.send(
            outputs=[{transparent_recipient: Decimal('0.4')}, {mweb_recipient: Decimal('0.6')}],
            options={
                'add_inputs': False,
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [{'mweb_out': change['output_id']}],
                'psbt': True,
            },
        )
        assert sent['complete']
        decoded = sender.decodepsbt(sent['psbt'])
        assert_equal([txin['mweb']['output_id'] for txin in decoded['inputs']], [change['output_id']])
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('0.6'))
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' not in decoded['kernels'][0]
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)
        assert_equal(decoded['kernels'][0]['pegouts'][0]['amount'], self.to_sats(Decimal('0.4')))
        assert_equal(decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], transparent_recipient)

        receiver_balance = self.wallet_total(receiver)
        assert_equal(sender.sendrawtransaction(sent['hex'], 0), sent['txid'])
        self.sync_mempools()
        self.generate(sender, 1, sync_fun=self.sync_all)
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('0.6'))
        assert_equal(self.wallet_total(receiver) - receiver_balance, Decimal('1'))

    def test_sendmany_mweb_recipients(self, sender, receiver):
        self.log.info("sendmany pays several MWEB recipients in one transaction")
        recipient1 = receiver.getnewaddress(address_type='mweb')
        recipient2 = receiver.getnewaddress(address_type='mweb')
        txid = sender.sendmany('', {recipient1: Decimal('0.3'), recipient2: Decimal('0.7')})
        self.sync_mempools()
        self.generate(sender, 1, sync_fun=self.sync_all)

        assert_equal(sender.gettransaction(txid)['confirmations'], 1)
        assert_equal(receiver.listunspent(addresses=[recipient1])[0]['amount'], Decimal('0.3'))
        assert_equal(receiver.listunspent(addresses=[recipient2])[0]['amount'], Decimal('0.7'))

    def test_sendall_mixed_recipients(self, sender, receiver):
        self.log.info("sendall sweeps combined transparent and MWEB inputs to mixed recipients")
        transparent_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        swept = sender.sendall(
            recipients=[transparent_recipient, {mweb_recipient: Decimal('0.25')}],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'psbt': True,
            },
        )
        assert swept['complete']
        decoded = sender.decodepsbt(swept['psbt'])
        assert any('mweb' in txin for txin in decoded['inputs'])
        assert any('mweb' not in txin for txin in decoded['inputs'])
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('0.25'))
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' in decoded['kernels'][0]
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)
        assert_equal(decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], transparent_recipient)

        pegout_amount = Decimal(decoded['kernels'][0]['pegouts'][0]['amount']) / COIN
        receiver_balance = self.wallet_total(receiver)
        assert_equal(sender.sendrawtransaction(swept['hex'], 0), swept['txid'])
        self.sync_mempools()
        self.generate(sender, 1, sync_fun=self.sync_all)
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('0.25'))
        assert_equal(self.wallet_total(receiver) - receiver_balance, Decimal('0.25') + pegout_amount)

    def broadcast_psbt(self, wallet, psbt):
        processed = wallet.walletprocesspsbt(psbt)
        assert processed['complete']
        finalized = wallet.finalizepsbt(processed['psbt'])
        assert finalized['complete']
        txid = wallet.sendrawtransaction(finalized['hex'], 0)
        self.sync_mempools()
        return txid

    def output_for_address(self, decoded, address):
        matching = [
            output
            for output in decoded['outputs']
            if output.get('mweb', {}).get('address') == address
            or output.get('script', {}).get('address') == address
        ]
        assert_equal(len(matching), 1)
        return matching[0]

    def to_sats(self, amount):
        return int(amount * COIN)

    def wallet_total(self, wallet):
        balances = wallet.getbalances()['mine']
        return balances['trusted'] + balances['immature']


if __name__ == '__main__':
    MWEBWalletRecipientsTest(__file__).main()
