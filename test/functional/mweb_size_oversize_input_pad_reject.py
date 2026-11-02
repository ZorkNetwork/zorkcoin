#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""1.1 Oversized block via weightless MWEB input pad — reject on v1.

Builds a real production-cap-filled block (same economy as max-cap accept), then
appends synthetic weightless MWEB inputs past MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB.
Submit over v1; DUT must return bad-blk-serialized-size and leave tips unchanged.

The pad is intentionally contrived (size gate runs before MWEB crypto).

Run: cd build && test/functional/test_runner.py --extended mweb_size_oversize_input_pad_reject.py
"""

from test_framework.mweb_cap_block_plan import CAP_HOST_WALLETS
from test_framework.mweb_size_util import (
    MINER_TX_DIVISOR,
    MINER_WALLET_COUNT,
    MWEB_ENVELOPE,
    MWEBSizeTestMixin,
    assemble_solved_block_from_gbt_with_timeout,
    pad_mweb_block_past_envelope,
    reject_block_via_p2p,
)
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBSizeOversizeInputPadReject(MWEBSizeTestMixin, BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.rpc_timeout = 7200
        wallet_args = ["-spendzeroconfchange=0", "-checkmempool=0", "-v2transport=0"]
        self.extra_args = mweb_extra_args(wallet_args, wallet_args, wallet_args)

    def setup_nodes(self):
        mine_max = self.require_mine_binary("max")
        base = self.get_binaries()
        self.extra_init = [
            {"binaries": base.with_bitcoind(mine_max)},
            {"binaries": base},
            {"binaries": base},
        ]
        super().setup_nodes()

    def run_test(self):
        builder, wallet_host, validator = self.nodes[0], self.nodes[1], self.nodes[2]
        setup_mweb_chain(builder, self)

        parties = self.prepare_size_economy(
            builder,
            wallet_host=wallet_host,
            miner_wallets=MINER_WALLET_COUNT,
            host_wallets=CAP_HOST_WALLETS,
            miner_tx_divisor=MINER_TX_DIVISOR,
            precreate_nodes=2,
            exclude_wallet_hosts={validator},
        )

        tip_before = validator.getbestblockhash()
        height_before = validator.getblockcount()
        builder_height = builder.getblockcount()

        gbt_est, diag, plan = self.flood_cap_fill_pack(builder, parties)
        self.log.info(
            "Cap-fill base GBT: est=%d mweb_in=%d plan=%s",
            gbt_est, diag["mweb_inputs"], plan.describe(),
        )

        block = assemble_solved_block_from_gbt_with_timeout(
            builder, rpc_timeout=builder.rpc_timeout,
        )
        base_s = len(block.serialize())
        assert base_s <= MWEB_ENVELOPE, base_s
        assert_greater_than(base_s, 10_000_000)

        block, final_s, n_extra, _ = pad_mweb_block_past_envelope(block)
        self.log.info(
            "Padded past envelope: base=%d final=%d extra_inputs=%d envelope=%d",
            base_s, final_s, n_extra, MWEB_ENVELOPE,
        )
        assert_greater_than(final_s, MWEB_ENVELOPE)

        # Hex submitblock would exceed HTTP MAX_SIZE; reject via v1 P2P + debug log.
        reject_block_via_p2p(
            validator, block,
            reject_msgs=["bad-blk-serialized-size"],
            tip_before=tip_before, height_before=height_before,
        )
        assert_equal(builder.getblockcount(), builder_height)


if __name__ == "__main__":
    MWEBSizeOversizeInputPadReject(__file__).main()
