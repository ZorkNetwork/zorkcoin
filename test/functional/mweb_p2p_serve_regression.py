#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Peg-in-heavy MWEB serve parity gate (P-01 plan V2 §2.3 / §9 S1-S2)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    mweb_extra_args,
)
from test_framework.mweb_stress_mega_util import (
    assert_historical_serve,
    paginate_mweb_utxos,
)
from test_framework.util import assert_greater_than

DEFAULT_POST_MWEB_BLOCKS = 250


class MWEBP2PServeRegressionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [mweb_extra_args([])[0]]

    def add_options(self, parser):
        parser.add_argument(
            '--post-mweb-blocks',
            type=int,
            default=DEFAULT_POST_MWEB_BLOCKS,
            help=f'Post-MWEB blocks to mine after activation (default: {DEFAULT_POST_MWEB_BLOCKS})',
        )
        parser.add_argument(
            '--reindex-chainstate',
            action='store_true',
            default=False,
            help='Restart with -reindex-chainstate before serve checks',
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def count_wallet_mweb(self, wallet):
        return sum(
            1 for u in wallet.listunspent(0)
            if u.get('address', '').startswith(('tmweb', 'mweb'))
        )

    def assert_serve_floor(self, node, block_hash, label):
        wallet_utxos = self.count_wallet_mweb(node.get_wallet_rpc('serve_recv'))
        paged = paginate_mweb_utxos(node, block_hash, page_size=64, max_pages=200)
        self.log.info('%s: wallet=%d paginated=%d', label, wallet_utxos, paged)
        assert_greater_than(wallet_utxos, 10)
        assert_greater_than(paged, wallet_utxos // 2)

    def run_test(self):
        node = self.nodes[0]
        post_blocks = self.options.post_mweb_blocks

        # Receive on a dedicated wallet that never spends. Smallest-first MWEB
        # selection (doc/mweb/descriptors.md "Selection algorithm") would
        # otherwise consolidate the sender's own MWEB coins on every send and
        # the served UTXO set would never grow.
        w_send = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name='serve_recv', load_on_startup=True)
        w_recv = node.get_wallet_rpc('serve_recv')

        generate(node, 120)
        w_send.sendtoaddress(w_send.getnewaddress(), 10)
        generate(node, 1)
        remaining = FIRST_MWEB_HEIGHT - 1 - node.getblockcount()
        if remaining > 0:
            generate(node, remaining)
        w_send.sendtoaddress(w_recv.getnewaddress(address_type='mweb'), 1)
        generate(node, 1)

        recv_addrs = [w_recv.getnewaddress(address_type='mweb') for _ in range(8)]
        for height in range(post_blocks):
            w_send.sendtoaddress(recv_addrs[height % len(recv_addrs)], 0.01)
            if height > 10 and height % 4 == 0:
                w_send.sendtoaddress(recv_addrs[(height // 4) % len(recv_addrs)], 0.005)
            generate(node, 1)

        tip_hash = node.getbestblockhash()
        self.log.info('S1: tip serve parity')
        self.assert_serve_floor(node, tip_hash, 'tip')
        assert_historical_serve(self, node, tip_hash=tip_hash, hist_hash=tip_hash)

        if self.options.reindex_chainstate:
            self.log.info('Restart with -reindex-chainstate')
            self.restart_node(0, extra_args=mweb_extra_args(['-reindex-chainstate'])[0])

        self.log.info('S2: restart + serve at tip-1')
        self.restart_node(0, extra_args=self.extra_args[0])
        tip_height = node.getblockcount()
        hist_hash = node.getblockhash(max(FIRST_MWEB_HEIGHT, tip_height - 1))
        self.assert_serve_floor(node, hist_hash, 'tip-1')
        assert_historical_serve(self, node, tip_hash=tip_hash, hist_hash=hist_hash)

        self.log.info('S2: serve at tip-10 after restart')
        hist10_height = max(FIRST_MWEB_HEIGHT, tip_height - 10)
        hist10_hash = node.getblockhash(hist10_height)
        self.assert_serve_floor(node, hist10_hash, 'tip-10')
        assert_historical_serve(self, node, tip_hash=tip_hash, hist_hash=hist10_hash)

        self.log.info('=== MWEB P2P serve regression: ALL PASSED ===')


if __name__ == '__main__':
    MWEBP2PServeRegressionTest(__file__).main()
