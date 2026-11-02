#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Litecoin-compatible MWEB fields on verbose mempool RPCs.

Checks getmempoolentry / getrawmempool(verbose) expose additive MWEB weight
fields and a nested mweb object for extension-body txs, keep Bitcoin cluster
fields, and wire MWEB parents into depends.
"""

from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBMempoolRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'])
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_bitcoin_cluster_fields(self, entry):
        for key in (
            'vsize', 'weight', 'time', 'height', 'descendantcount', 'descendantsize',
            'ancestorcount', 'ancestorsize', 'chunkweight', 'wtxid', 'fees', 'depends',
            'spentby', 'unbroadcast',
        ):
            assert key in entry, f'missing Bitcoin mempool field {key}'
        for key in ('base', 'modified', 'ancestor', 'descendant', 'chunk'):
            assert key in entry['fees'], f'missing fees.{key}'

    def assert_mweb_weight_fields(self, entry, *, expect_mweb_body):
        for key in ('mwebweight', 'descendantmwebweight', 'ancestormwebweight'):
            assert key in entry, f'missing {key}'
            assert isinstance(entry[key], int)
            assert entry[key] >= 0
        if expect_mweb_body:
            assert_greater_than(entry['mwebweight'], 0)
            assert 'mweb' in entry
            mweb = entry['mweb']
            assert_equal(mweb['weight']['base'], entry['mwebweight'])
            assert_equal(mweb['weight']['ancestor'], entry['ancestormwebweight'])
            assert_equal(mweb['weight']['descendant'], entry['descendantmwebweight'])
            for key in ('fee', 'lock_height', 'pegins', 'pegouts', 'inputs', 'outputs'):
                assert key in mweb, f'missing mweb.{key}'
        else:
            assert_equal(entry['mwebweight'], 0)
            assert 'mweb' not in entry

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)

        self.log.info("L1-only mempool entry keeps cluster fields and zero MWEB weights")
        l1_addr = node.getnewaddress()
        l1_txid = node.sendtoaddress(l1_addr, 1)
        l1_entry = node.getmempoolentry(l1_txid)
        self.assert_bitcoin_cluster_fields(l1_entry)
        self.assert_mweb_weight_fields(l1_entry, expect_mweb_body=False)
        verbose = node.getrawmempool(True)
        assert l1_txid in verbose
        self.assert_bitcoin_cluster_fields(verbose[l1_txid])
        self.assert_mweb_weight_fields(verbose[l1_txid], expect_mweb_body=False)
        self.generate(node, 1)

        self.log.info("MWEB send exposes nested mweb object and positive weights")
        mweb_addr = node.getnewaddress(address_type='mweb')
        parent_txid = node.sendtoaddress(mweb_addr, 1)
        parent = node.getmempoolentry(parent_txid)
        self.assert_bitcoin_cluster_fields(parent)
        self.assert_mweb_weight_fields(parent, expect_mweb_body=True)
        assert_equal(parent['ancestormwebweight'], parent['mwebweight'])
        assert_equal(parent['descendantmwebweight'], parent['mwebweight'])
        assert isinstance(parent['mweb']['outputs'], list)
        assert_greater_than(len(parent['mweb']['outputs']), 0)

        self.log.info("Child MWEB spend lists parent in depends and aggregates ancestor weight")
        child_addr = node.getnewaddress(address_type='mweb')
        child_txid = node.sendtoaddress(child_addr, 0.25)
        child = node.getmempoolentry(child_txid)
        self.assert_bitcoin_cluster_fields(child)
        self.assert_mweb_weight_fields(child, expect_mweb_body=True)
        assert parent_txid in child['depends']
        assert_equal(
            child['ancestormwebweight'],
            parent['mwebweight'] + child['mwebweight'],
        )
        parent_after = node.getmempoolentry(parent_txid)
        assert child_txid in parent_after['spentby']
        assert_equal(
            parent_after['descendantmwebweight'],
            parent['mwebweight'] + child['mwebweight'],
        )

        verbose = node.getrawmempool(True)
        assert_equal(set(verbose.keys()), {parent_txid, child_txid})
        self.assert_mweb_weight_fields(verbose[child_txid], expect_mweb_body=True)
        assert parent_txid in verbose[child_txid]['depends']


if __name__ == '__main__':
    MWEBMempoolRPCTest(__file__).main()
