#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Served PMMR segments must commit to the header before and after a coin spend."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import generate, mweb_extra_args, setup_mweb_chain
from test_framework.mweb_stress_mega_util import fetch_mweb_utxo_page, verify_utxo_proofs


class MWEBP2PProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        tip = node.getbestblockhash()
        before = fetch_mweb_utxo_page(node, tip, num_requested=64)
        verify_utxo_proofs(self, node, tip, before)

        # Explicitly spend a confirmed coin; incidental wallet L1 selection must
        # not turn this into an all-unspent peg-in-only proof control.
        coin = next(u for u in node.listunspent(1) if u.get('output_id') and u['amount'] > 0.1)
        node.send(outputs={node.getnewaddress(address_type='mweb'): 0.01 for _ in range(5)}, options={
            'inputs': [{'output_id': coin['output_id']}], 'add_inputs': False,
        })
        generate(node, 1)
        tip = node.getbestblockhash()
        after = fetch_mweb_utxo_page(node, tip, num_requested=64)
        assert {u.leaf_index for u in before.utxos} - {u.leaf_index for u in after.utxos}
        verify_utxo_proofs(self, node, tip, after)

        # Restart must still serve a tip page that binds to the header root.
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        tip = node.getbestblockhash()
        after_restart = fetch_mweb_utxo_page(node, tip, num_requested=64)
        verify_utxo_proofs(self, node, tip, after_restart)

        # Historical tip (not the live tip) must also bind independently.
        historical = tip
        generate(node, 2)
        assert node.getbestblockhash() != historical
        historical_page = fetch_mweb_utxo_page(node, historical, num_requested=64)
        verify_utxo_proofs(self, node, historical, historical_page)


if __name__ == '__main__':
    MWEBP2PProofTest(__file__).main()
