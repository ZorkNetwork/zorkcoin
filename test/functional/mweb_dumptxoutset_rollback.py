#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""dumptxoutset rollback must match a latest dump at the same MWEB height."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import generate, init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.util import assert_equal


class MWEBDumptxoutsetRollbackTest(BitcoinTestFramework):
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
        generate(node, 3)

        tip_before_latest = node.getbestblockhash()
        height = node.getblockcount()
        latest = node.dumptxoutset('mweb_latest.dat', 'latest')
        assert_equal(latest['base_height'], height)
        assert_equal(latest['base_hash'], tip_before_latest)
        assert 'mweb_hash' in latest

        latest2 = node.dumptxoutset('mweb_latest2.dat', 'latest')
        assert_equal(latest2['txoutset_hash'], latest['txoutset_hash'])
        assert_equal(latest2['mweb_hash'], latest['mweb_hash'])

        generate(node, 4)
        assert node.getblockcount() > height
        tip_after_mine = node.getbestblockhash()

        rolled = node.dumptxoutset('mweb_rollback.dat', 'rollback', {'rollback': height})
        assert_equal(node.getbestblockhash(), tip_after_mine)
        assert_equal(node.getblockcount(), height + 4)
        assert_equal(rolled['base_height'], height)
        assert_equal(rolled['base_hash'], latest['base_hash'])
        assert_equal(rolled['txoutset_hash'], latest['txoutset_hash'])
        assert_equal(rolled['mweb_hash'], latest['mweb_hash'])
        assert_equal(rolled['coins_written'], latest['coins_written'])
        assert_equal(rolled['mweb_coins_written'], latest['mweb_coins_written'])
        assert_equal(rolled['nchaintx'], latest['nchaintx'])
        # The temporary rollback dir holds cloned MWEB files and must be fully cleaned up.
        temp_db_path = node.chain_path / f"temp_utxo_{height}"
        assert not temp_db_path.exists()

        rolled_mem = node.dumptxoutset('mweb_rollback_mem.dat', 'rollback', {'rollback': height, 'in_memory': True})
        assert_equal(node.getbestblockhash(), tip_after_mine)
        assert_equal(rolled_mem['txoutset_hash'], latest['txoutset_hash'])
        assert_equal(rolled_mem['mweb_hash'], latest['mweb_hash'])
        assert not temp_db_path.exists()


if __name__ == '__main__':
    MWEBDumptxoutsetRollbackTest(__file__).main()
