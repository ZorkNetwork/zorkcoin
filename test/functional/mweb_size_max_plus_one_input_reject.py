#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""2.1 Block with MAX_NUM_INPUTS+1 MWEB inputs — consensus input-limit reject.

Builds inventory via the shared size economy, swaps the builder to
bitcoind-mine-test, then submits *only* MWEB consolidations that sum to
50_001 inputs (999x50-in/1-out + 1x51-in/1-out). No L1 pads, no MWEB
weight-fill. DUT (stock bitcoind) must reject bad-blk-mweb.

Run: cd build && test/functional/test_runner.py --extended mweb_size_max_plus_one_input_reject.py
"""

from test_framework.mweb_cap_block_plan import CAP_HOST_WALLETS
from test_framework.mweb_size_util import (
    MINER_TX_DIVISOR,
    MINER_WALLET_COUNT,
    MWEB_ENVELOPE,
    PLUS_ONE_INPUT_TARGET,
    MWEBSizeTestMixin,
    assemble_solved_block_from_gbt_with_timeout,
    reject_block_via_p2p,
)
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBSizeMaxPlusOneInputReject(MWEBSizeTestMixin, BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.rpc_timeout = 7200
        wallet_args = ["-spendzeroconfchange=0", "-checkmempool=0", "-v2transport=0"]
        self.extra_args = mweb_extra_args(wallet_args, wallet_args, wallet_args)

    def setup_nodes(self):
        mine_max = self.require_mine_binary("max")
        self.require_mine_binary("test")
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

        # Economy only supplies confirmed MWEB coins; the reject block itself
        # does not fill L1 weight or MWEB weight.
        parties = self.prepare_size_economy(
            builder,
            wallet_host=wallet_host,
            miner_wallets=MINER_WALLET_COUNT,
            host_wallets=CAP_HOST_WALLETS,
            miner_tx_divisor=MINER_TX_DIVISOR,
            precreate_nodes=2,
            exclude_wallet_hosts={validator},
        )
        builder = self.swap_miner_mine_binary(
            builder, "test", parties, label="plus-one reject GBT",
        )

        tip_before = validator.getbestblockhash()
        height_before = validator.getblockcount()
        builder_height = builder.getblockcount()

        gbt_est, diag, meta = self.flood_plus_one_input_pack(builder, parties)
        self.log.info(
            "Plus-one-input GBT: est=%d mweb_in=%d kernels=%d queued_txs=%d",
            gbt_est, diag["mweb_inputs"], diag["mweb_kernels"], meta["n_txs"],
        )
        assert_equal(diag["mweb_inputs"], PLUS_ONE_INPUT_TARGET)
        assert_equal(meta["inputs"], PLUS_ONE_INPUT_TARGET)
        assert_greater_than(diag["mweb_inputs"], 50_000)

        block = assemble_solved_block_from_gbt_with_timeout(
            builder, rpc_timeout=builder.rpc_timeout,
        )
        S = len(block.serialize())
        self.log.info("Assembled S=%d envelope=%d", S, MWEB_ENVELOPE)
        assert S <= MWEB_ENVELOPE, S

        reject_block_via_p2p(
            validator, block,
            reject_msgs=["bad-blk-mweb"],
            tip_before=tip_before, height_before=height_before,
            timeout=300,
        )
        self.log.info("p2p reject observed (input limit / bad-blk-mweb)")
        assert_equal(builder.getblockcount(), builder_height)


if __name__ == "__main__":
    MWEBSizeMaxPlusOneInputReject(__file__).main()
