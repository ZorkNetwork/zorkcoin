#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet tracking when a spent MWEB output_id is recreated in a later block."""

from decimal import Decimal

from test_framework.address import byte_to_base58
from test_framework.descriptors import descsum_create
from test_framework.mweb_util import (
    get_mweb_account_descriptor,
    init_mweb_wallet,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def wif(scalar: int) -> str:
    return byte_to_base58(scalar.to_bytes(32, 'big') + b'\x01', 239)


class MWEBWalletRepeatedOutputIdTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1', '-mwebdeterministicsenders=1'],
            ['-whitelist=noban@127.0.0.1', '-mwebdeterministicsenders=1'],
        )

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        miner = self.nodes[0]
        node1 = self.nodes[1]

        self.log.info("Activate MWEB and fund two wallets sharing a master scan secret")
        setup_mweb_chain(miner, self)

        scan_wif = wif(21)
        spend_a_wif = wif(22)
        spend_b_wif = wif(23)

        node1.createwallet(wallet_name='sender_a', blank=True)
        node1.createwallet(wallet_name='sender_b', blank=True)
        node1.createwallet(wallet_name='receiver', blank=True)
        sender_a = node1.get_wallet_rpc('sender_a')
        sender_b = node1.get_wallet_rpc('sender_b')
        receiver = node1.get_wallet_rpc('receiver')

        for wallet, spend_wif in ((sender_a, spend_a_wif), (sender_b, spend_b_wif), (receiver, wif(24))):
            res = wallet.importdescriptors([{
                'desc': descsum_create(f'mweb({scan_wif if wallet != receiver else wif(25)},{spend_wif},*)'),
                'timestamp': 'now',
                'active': True,
            }])
            assert res[0]['success'], res[0].get('error')

        addr_a = sender_a.getnewaddress(address_type='mweb')
        addr_b = sender_b.getnewaddress(address_type='mweb')
        recipient_addr = receiver.getnewaddress(address_type='mweb')
        sink_addr = miner.getnewaddress(address_type='mweb')

        miner.sendtoaddress(addr_a, Decimal('5.0'))
        miner.sendtoaddress(addr_b, Decimal('5.0'))
        self.sync_mempools()
        self.generate(miner, 1)
        self.sync_all()

        self.log.info("First sender creates output_id at recipient_addr; receiver spends it")
        txid_create_1 = sender_a.sendtoaddress(recipient_addr, Decimal('1.0'))
        self.sync_mempools()
        self.generate(miner, 1)
        self.sync_all()

        utxos_1 = receiver.listunspent(addresses=[recipient_addr])
        assert_equal(len(utxos_1), 1)
        repeated_oid = utxos_1[0]['output_id']
        assert_equal(utxos_1[0]['amount'], Decimal('1.0'))

        txid_spend_1 = receiver.send(
            outputs={sink_addr: Decimal('0.5')},
            options={'inputs': [{'output_id': repeated_oid}], 'add_inputs': False},
        )['txid']
        self.sync_mempools()
        self.generate(miner, 1)
        self.sync_all()
        assert_equal(receiver.listunspent(addresses=[recipient_addr]), [])

        self.log.info("Second sender with shared scan secret recreates the exact same output_id")
        txid_create_2 = sender_b.sendtoaddress(recipient_addr, Decimal('1.0'))
        assert txid_create_2 != txid_create_1
        self.sync_mempools()
        self.generate(miner, 1)
        self.sync_all()

        utxos_2 = receiver.listunspent(addresses=[recipient_addr])
        assert_equal(len(utxos_2), 1)
        assert_equal(utxos_2[0]['output_id'], repeated_oid)
        assert_equal(utxos_2[0]['amount'], Decimal('1.0'))
        assert_equal(utxos_2[0]['txid'], txid_create_2)

        self.log.info("Rescanning both sender and receiver wallets preserves both occurrences")
        sender_a.rescanblockchain(0)
        receiver.rescanblockchain(0)
        utxos_after_rescan = receiver.listunspent(addresses=[recipient_addr])
        assert_equal(len(utxos_after_rescan), 1)
        assert_equal(utxos_after_rescan[0]['output_id'], repeated_oid)
        assert_equal(utxos_after_rescan[0]['txid'], txid_create_2)

        self.log.info("Restoring receiver into a fresh wallet via extension-block rescan discovers both lives")
        recv_desc = get_mweb_account_descriptor(receiver, private=True)['desc']
        node1.createwallet(wallet_name='receiver_restored', blank=True)
        restored = node1.get_wallet_rpc('receiver_restored')
        res = restored.importdescriptors([{'desc': recv_desc, 'timestamp': 0, 'active': True}])
        assert res[0]['success'], res[0].get('error')

        restored_utxos = restored.listunspent(addresses=[recipient_addr])
        assert_equal(len(restored_utxos), 1)
        assert_equal(restored_utxos[0]['output_id'], repeated_oid)
        assert_equal(restored_utxos[0]['amount'], Decimal('1.0'))

        recv_txs = [
            tx for tx in restored.listtransactions('*', 100)
            if tx.get('category') == 'receive' and tx.get('address') == recipient_addr
        ]
        assert_equal(len(recv_txs), 2)
        assert_equal(len({tx['txid'] for tx in recv_txs}), 2)

        self.log.info("Spending the recreated output_id succeeds and clears receiver inventory")
        txid_spend_2 = receiver.send(
            outputs={sink_addr: Decimal('0.5')},
            options={'inputs': [{'output_id': repeated_oid}], 'add_inputs': False},
        )['txid']
        assert txid_spend_2 != txid_spend_1
        self.sync_mempools()
        self.generate(miner, 1)
        self.sync_all()
        assert_equal(receiver.listunspent(addresses=[recipient_addr]), [])


if __name__ == '__main__':
    MWEBWalletRepeatedOutputIdTest(__file__).main()
