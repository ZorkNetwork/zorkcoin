#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Single-node wallet scale test for MWEB fee budgeting under forced density.

Reproduces the mega-chain failure mode where sustained peg-in-heavy growth
eventually hit "MWEB change calculation failed" / fee-budget errors around
~1500 post-MWEB blocks.

Uses a funder → many recipient wallets/accounts/addresses so the leafset
actually grows (doc/mweb/testing.md). Production consolidation is not altered.

Default: 1600 post-MWEB blocks. Pass --extended for 16000.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    init_mweb_wallet,
    mweb_extra_args,
)
from test_framework.mweb_density_util import (
    SPEND_SCALE_CONFIG,
    complete_testing_fail,
    count_all_wallet_mweb_utxos,
    grow_mweb_chain_density,
    verify_density_complete,
    funder_forced_pegin,
)
from test_framework.util import assert_greater_than


class MWEBWalletSpendScaleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def add_options(self, parser):
        parser.add_argument("--extended", dest="extended", default=False, action="store_true",
                            help="Run 10x scale (16000 post-MWEB blocks instead of 1600)")

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        cfg = SPEND_SCALE_CONFIG['extended' if self.options.extended else 'default']

        self.log.info(
            "Growing MWEB density chain: %d post-MWEB blocks, %d wallets x %d accounts "
            "x %d keys (fee-budget scale gate%s)",
            cfg['post_mweb_blocks'],
            cfg['recipient_wallets'],
            cfg['accounts_per_wallet'],
            cfg['mweb_keys_per_account'],
            ", extended" if self.options.extended else "",
        )
        parties = grow_mweb_chain_density(self, node, cfg=cfg)

        def _paginate(n, block_hash):
            # Spend-scale has no P2P serve peers required; approximate via wallet sum
            # plus a cheap gettxoutsetinfo is L1-only — use recipient wallet totals and
            # require paginated-equivalent via listunspent across recipients.
            return count_all_wallet_mweb_utxos(n, parties['recipient_names'])

        # For spend_scale, chain floor is wallet-visible MWEB UTXOs (same node).
        height = node.getblockcount()
        assert_greater_than(height, FIRST_MWEB_HEIGHT + cfg['post_mweb_blocks'] - 2)
        result = verify_density_complete(
            self, node, parties,
            min_utxos=cfg['min_mweb_utxos'],
            paginate_fn=_paginate,
        )
        self.log.info(
            "Scale gate complete: height=%d wallet_mweb_utxos=%d",
            height, result['wallet_total'],
        )

        # One more forced peg-in after the long growth must still succeed.
        addr = node.get_wallet_rpc(parties['recipient_names'][0]).getnewaddress(address_type='mweb')
        try:
            txid = funder_forced_pegin(parties['funder'], addr, 0.01)
        except Exception as e:
            complete_testing_fail(f"post-growth forced peg-in failed: {e}")
        if not txid:
            complete_testing_fail("post-growth forced peg-in returned empty txid")
        self.log.info("Post-growth forced peg-in succeeded: %s", txid)


if __name__ == '__main__':
    MWEBWalletSpendScaleTest(__file__).main()
