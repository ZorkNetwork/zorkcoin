#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a node without MWEB follows the MWEB chain, and that MWEB nodes
don't accept a peg-in relayed by it without its MWEB data.

Port of Litecoin Core's mweb_node_compatibility.py, which uses Litecoin Core
0.18.1. The node without MWEB here is a previous release of the Bitcoin Core
node this one is built on. Needs previous releases (test/get_previous_releases.py).
"""

import time

from test_framework.messages import CTransaction, FromHex, NODE_MWEB
from test_framework.mweb_util import setup_mweb_chain, with_mweb_vbparams
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PRE_MWEB_RELEASE = 310000


class MWEBNodeCompatibilityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [with_mweb_vbparams([]), with_mweb_vbparams([]), []]
        self.wallet_names = [self.default_wallet_name]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args, versions=[None, None, PRE_MWEB_RELEASE])
        self.start_nodes()
        self.import_deterministic_coinbase_privkeys()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)

    def run_test(self):
        node_a = self.nodes[0]
        node_b = self.nodes[1]
        node_c_pre_mweb = self.nodes[2]

        self.log.info("The node without MWEB follows the chain past MWEB activation")
        setup_mweb_chain(node_a, self)
        self.sync_all()
        height = node_a.getblockcount()
        assert_equal(node_b.getblockcount(), height)
        assert_equal(node_c_pre_mweb.getblockcount(), height)

        self.log.info("A peg-in relayed by the node without MWEB is not accepted without its MWEB data")
        self.disconnect_nodes(0, 1)
        peers = node_b.getpeerinfo()
        assert_equal(len(peers), 1)
        old_peer = peers[0]
        assert_equal(old_peer['subver'], node_c_pre_mweb.getnetworkinfo()['subversion'])
        assert_equal(int(old_peer['services'], 16) & NODE_MWEB, 0)
        log_start = node_b.debug_log_size(encoding='utf-8')
        pegin_txid = node_a.sendtoaddress(node_a.getnewaddress(address_type='mweb'), 100)
        full = FromHex(CTransaction(), node_a.getrawtransaction(pegin_txid))
        assert full.mweb_tx is not None
        self.sync_mempools([node_a, node_c_pre_mweb])
        assert_equal(set(node_a.getrawmempool()), {pegin_txid})
        assert_equal(set(node_c_pre_mweb.getrawmempool()), {pegin_txid})
        stripped_hex = node_c_pre_mweb.getrawtransaction(pegin_txid)
        stripped = FromHex(CTransaction(), stripped_hex)
        assert stripped.mweb_tx is None
        assert_equal(stripped_hex, full.serialize_with_witness().hex())
        assert_equal(stripped.txid_hex, pegin_txid)

        # Observe throughout the relay interval, rather than only checking the
        # final pool after an earlier transient acceptance could have disappeared.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert_equal(node_b.getrawmempool(), [])
            time.sleep(0.05)
        assert_equal(node_b.getrawmempool(), [])

        # Tie the actual rejected transaction body to the sole old peer. Pool
        # emptiness alone could also mean it never announced or delivered it.
        rejection = (
            f'{pegin_txid} (wtxid={stripped.wtxid_hex}) from peer={old_peer["id"]} was not accepted:'
        )

        def received_stripped_body():
            with open(node_b.debug_log_path, encoding='utf-8') as log:
                log.seek(log_start)
                return rejection in log.read()

        self.wait_until(received_stripped_body, timeout=10)


if __name__ == '__main__':
    MWEBNodeCompatibilityTest(__file__).main()
