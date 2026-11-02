#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sendall with MWEB inputs and recipients."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import get_mweb_account_descriptor, init_mweb_wallet, setup_mweb_chain, mweb_extra_args
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletSendallMWEBTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        self.log.info("Setting up an active MWEB chain with both transparent and MWEB funds on node0")
        setup_mweb_chain(node0, self)
        node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), 10)
        self.generate(node0, 1, sync_fun=self.sync_all)
        assert any('output_id' in u for u in node0.listunspent())
        assert any('vout' in u for u in node0.listunspent())

        self.log.info("Sweep node0's mixed transparent and MWEB balance to a node1 MWEB address")
        node0_balance = node0.getbalances()["mine"]["trusted"]
        node1_mweb = node1.getnewaddress(address_type='mweb')
        sendall_to_mweb = node0.sendall(recipients=[node1_mweb])
        node0_send_tx = node0.gettransaction(sendall_to_mweb["txid"])
        expected_node1_balance = node0_balance + node0_send_tx["fee"]

        self.sync_mempools()
        self.generate(node1, 1, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], expected_node1_balance)
        assert_equal([u for u in node0.listunspent() if u['confirmations'] > 0 and 'output_id' in u], [])

        self.log.info("Sweep node1's MWEB balance back out to a node0 transparent address")
        node1_balance = node1.getbalances()["mine"]["trusted"]
        node0_balances_before_pegout = node0.getbalances()["mine"]
        node0_total_before_pegout = node0_balances_before_pegout["trusted"] + node0_balances_before_pegout["immature"]
        node0_l1 = node0.getnewaddress()
        sendall_to_l1 = node1.sendall(recipients=[node0_l1])
        node1_send_tx = node1.gettransaction(sendall_to_l1["txid"])
        expected_pegout_amount = node1_balance + node1_send_tx["fee"]

        self.sync_mempools()
        self.generate(node1, 1, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], 0)
        node0_balances_after_pegout = node0.getbalances()["mine"]
        node0_total_after_pegout = node0_balances_after_pegout["trusted"] + node0_balances_after_pegout["immature"]
        assert_equal(node0_total_after_pegout, node0_total_before_pegout + expected_pegout_amount)
        node0_received = node0.listreceivedbyaddress(minconf=0, address_filter=node0_l1)
        assert_equal(len(node0_received), 1)
        assert_equal(node0_received[0]["amount"], expected_pegout_amount)
        assert_equal(node0_received[0]["confirmations"], 1)
        receipt, = node0.listwallettransactions(txid=sendall_to_l1['txid'])
        assert_equal((receipt['type'], receipt['address'], receipt['amount'], receipt['net'], receipt['confirmations']),
                     ('RecvWithAddress', node0_l1, expected_pegout_amount, expected_pegout_amount, 1))
        kernel, = node1.decoderawtransaction(node1_send_tx['hex'])['vkern']
        assert_equal(receipt['pegout'], f'{kernel["kernel_id"]}:0')
        assert 'fee' not in receipt

        self.log.info("Mine pegout maturity and verify the swept amount stays with node0")
        self.generate(node1, 5, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], 0)
        node0_balances_final = node0.getbalances()["mine"]
        node0_total_final = node0_balances_final["trusted"] + node0_balances_final["immature"]
        assert_equal(node0_total_final, node0_total_after_pegout)
        node0_received = node0.listreceivedbyaddress(minconf=0, address_filter=node0_l1)
        assert_equal(node0_received[0]["amount"], expected_pegout_amount)
        assert_equal(node0_received[0]["confirmations"], 6)
        mature, = node0.listwallettransactions(txid=sendall_to_l1['txid'])
        assert_equal((mature['type'], mature['address'], mature['amount'], mature['net'], mature['pegout']),
                     tuple(receipt[key] for key in ('type', 'address', 'amount', 'net', 'pegout')))
        assert_equal(mature['confirmations'], 6)
        assert 'fee' not in mature

        self.log.info("Sweep a transparent-only wallet to an MWEB address as one peg-in")
        node0.createwallet(wallet_name='l1_only')
        l1_only = node0.get_wallet_rpc('l1_only')
        default = node0.get_wallet_rpc(self.default_wallet_name)
        default.sendtoaddress(l1_only.getnewaddress(), 2)
        default.sendtoaddress(l1_only.getnewaddress(), 1)
        self.generate(node0, 1, sync_fun=self.sync_all)
        node1_mweb = node1.getnewaddress(address_type='mweb')
        swept = l1_only.sendall(recipients=[node1_mweb])
        fee = l1_only.gettransaction(swept["txid"])["fee"]
        self.sync_mempools()
        self.generate(node0, 1, sync_fun=self.sync_all)
        assert_equal(l1_only.getbalances()["mine"]["trusted"], 0)
        assert_equal([u['amount'] for u in node1.listunspent(addresses=[node1_mweb])], [Decimal('3') + fee])

        self.log.info("Split an MWEB sweep between a fixed amount and the remainder recipients")
        node0.createwallet(wallet_name='split')
        split = node0.get_wallet_rpc('split')
        default.sendtoaddress(split.getnewaddress(address_type='mweb'), Decimal('1.00000001'))
        default.sendtoaddress(split.getnewaddress(), 1)
        self.generate(node0, 1, sync_fun=self.sync_all)
        fixed, first, second = (node1.getnewaddress(address_type='mweb') for _ in range(3))
        assert_raises_rpc_error(-6, "Assigned more value to outputs than available funds.",
                                split.sendall, [{fixed: Decimal('2.1')}, first])
        # The transparent coin makes the sweep a peg-in, whose transparent fee follows the
        # fee rate; use a rate that makes the whole fee odd, so it does not split evenly.
        for fee_rate in [Decimal('10.001'), Decimal('10.003'), Decimal('10.007'), Decimal('10.011'), Decimal('10.013')]:
            swept = split.sendall(recipients=[{fixed: Decimal('0.3')}, first, second],
                                  options={'add_to_wallet': False, 'psbt': True, 'fee_rate': fee_rate})
            decoded = split.decodepsbt(swept['psbt'])
            paid = {o['mweb']['address']: int(o['amount'] * COIN) for o in decoded['outputs'] if 'mweb' in o}
            fee = 200_000_001 - sum(paid.values())
            if fee % 2:
                break
        assert_equal(fee % 2, 1)
        # The remainder recipients share the fee; the first also gets the odd satoshi of
        # the remainder and pays the odd satoshi of the fee. No change is left over.
        assert_equal(paid, {
            fixed: 30_000_000,
            first: 85_000_001 - fee // 2 - fee % 2,
            second: 85_000_000 - fee // 2,
        })

        self.log.info("A sweep refuses a remainder peg-out left as dust after its share of the fee")
        mweb_coin, = [u for u in split.listunspent() if 'output_id' in u]
        sweep_options = {'inputs': [{'mweb_out': mweb_coin['output_id']}], 'add_to_wallet': False, 'psbt': True, 'fee_rate': 10}
        remainder = node1.getnewaddress()
        swept = split.sendall(recipients=[{fixed: Decimal('0.5')}, remainder], options=sweep_options)
        fee = int(split.decodepsbt(swept['psbt'])['fee'] * COIN)
        assert_raises_rpc_error(-4, "The transaction amount is too small to send after the fee has been deducted",
                                split.sendall, recipients=[{fixed: Decimal(100_000_001 - fee - 100) / COIN}, remainder],
                                options=sweep_options)

        self.log.info("An unlocked wallet sweeps MWEB coins it received while locked")
        node0.createwallet(wallet_name='encrypted', passphrase='pass')
        encrypted = node0.get_wallet_rpc('encrypted')
        encrypted.walletpassphrase('pass', 600)
        addresses = [encrypted.getnewaddress(address_type='mweb') for _ in range(2)]
        encrypted.walletlock()
        for address in addresses:
            default.sendtoaddress(address, 1)
        self.generate(node0, 1, sync_fun=self.sync_all)
        unsigned = encrypted.sendall([node1.getnewaddress(address_type='mweb')])
        assert not unsigned['complete']
        assert_equal(len(encrypted.decodepsbt(unsigned['psbt'])['inputs']), 2)
        encrypted.walletpassphrase('pass', 600)
        encrypted.sendall([node1.getnewaddress(address_type='mweb')])
        assert_equal([u for u in encrypted.listunspent(minconf=0) if 'output_id' in u], [])

        self.log.info("A wallet that can sign sweeps only the MWEB coins it can spend")
        node0.createwallet(wallet_name='with_watched_account')
        with_watched = node0.get_wallet_rpc('with_watched_account')
        spendable = with_watched.getnewaddress(address_type='mweb')
        watched_account = get_mweb_account_descriptor(split)
        result = with_watched.importdescriptors([{'desc': watched_account['desc'], 'timestamp': 'now', 'active': True}])
        assert result[0]['success'], result
        watched = with_watched.getnewaddress(address_type='mweb')
        default.sendtoaddress(spendable, 1)
        default.sendtoaddress(watched, 2)
        self.generate(node0, 1, sync_fun=self.sync_all)
        assert_equal([u['spendable'] for u in with_watched.listunspent(addresses=[watched])], [False])
        with_watched.sendall([node1.getnewaddress(address_type='mweb')])
        # The import's rescan also found split's unswept coin, through the account's lookahead.
        assert_equal(sorted((u['address'], u['amount']) for u in with_watched.listunspent(minconf=0) if 'output_id' in u),
                     sorted([(watched, 2), (mweb_coin['address'], mweb_coin['amount'])]))


if __name__ == '__main__':
    WalletSendallMWEBTest(__file__).main()
