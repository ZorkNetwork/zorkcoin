#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test separate L1 / MWEB mempool markets (-maxmempoolmweb).

Checks getmempoolinfo market fields, -maxmempoolmweb validation, and that L1
pressure does not evict a base-fee MWEB-only transaction or raise mwebminfee.
MWEB-market trimming and the mwebminfee bump are covered by unit tests in
mweb_mempool_market_tests.
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.mweb_util import generate, init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    create_lots_of_big_transactions,
    gen_return_txouts,
)
from test_framework.wallet import MiniWallet


class MWEBMempoolLimitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(['-maxmempool=5', '-persistmempool=0'])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def test_rpc_fields_and_share(self):
        node = self.nodes[0]
        info = node.getmempoolinfo()
        for key in ('mwebusage', 'maxmempoolmweb', 'mwebminfee'):
            assert key in info, f'missing getmempoolinfo.{key}'
        assert_equal(info['maxmempool'], 5 * 1000 * 1000)
        assert_equal(info['maxmempoolmweb'], int(info['maxmempool'] * 0.8))
        assert_equal(info['mwebusage'], 0)
        assert_equal(info['mwebminfee'], Decimal('0.00000000'))

        self.restart_node(0, extra_args=self.extra_args[0] + ['-maxmempoolmweb=50'])
        info = node.getmempoolinfo()
        assert_equal(info['maxmempoolmweb'], int(info['maxmempool'] * 0.5))

        self.stop_node(0)
        node.assert_start_raises_init_error(
            self.extra_args[0] + ['-maxmempoolmweb=101'],
            "Error: -maxmempoolmweb must be between 0 and 100 (got 101)",
        )
        self.start_node(0, extra_args=self.extra_args[0])

    def test_l1_pressure_keeps_mweb(self):
        node = self.nodes[0]
        self.restart_node(0, extra_args=self.extra_args[0])
        setup_mweb_chain(node)

        # MiniWallet cannot rescan a mempool that already holds MWEB-only txs
        # (ismweb vins have no txid). Build its UTXOs while the mempool is empty.
        self.log.info("Prepare L1 flood UTXOs before any MWEB mempool entry")
        mini = MiniWallet(node, tag_name="mweb_mempool_limit_l1")
        tx_batch_size = 1
        num_of_batches = 75
        self.generate(mini, 1 + num_of_batches * tx_batch_size)
        self.generate(node, COINBASE_MATURITY - 1)
        confirmed_utxos = [mini.get_utxo(confirmed_only=True) for _ in range(num_of_batches * tx_batch_size)]

        self.log.info("Fund an MWEB UTXO and create a base-fee MWEB-only spend")
        node.sendtoaddress(node.getnewaddress(address_type='mweb'), 10)
        generate(node, 1)
        mweb_txid = node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)
        assert mweb_txid in node.getrawmempool()
        assert_greater_than(node.getmempoolinfo()['mwebusage'], 0)

        self.log.info("Flood L1 until eviction; MWEB-only tx must survive")
        txouts = gen_return_txouts()
        minrelayfee = node.getnetworkinfo()['relayfee']
        base_fee = minrelayfee * 130
        for i in range(num_of_batches):
            fee = (i + 1) * base_fee
            utxos = confirmed_utxos[:tx_batch_size]
            create_lots_of_big_transactions(mini, node, fee, tx_batch_size, txouts, utxos)
            del confirmed_utxos[:tx_batch_size]
            if node.getmempoolinfo()['mempoolminfee'] > node.getmempoolinfo()['minrelaytxfee']:
                break

        assert mweb_txid in node.getrawmempool()
        info = node.getmempoolinfo()
        assert_greater_than(info['mwebusage'], 0)
        assert_equal(info['mwebminfee'], Decimal('0.00000000'))
        assert_greater_than(info['mempoolminfee'], info['minrelaytxfee'])

    def run_test(self):
        self.test_rpc_fields_and_share()
        self.test_l1_pressure_keeps_mweb()


if __name__ == '__main__':
    MWEBMempoolLimitTest(__file__).main()
