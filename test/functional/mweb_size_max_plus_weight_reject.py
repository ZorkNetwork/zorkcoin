#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""2.2 Near-max block slightly over MWEB weight — consensus weight reject + under-cap accept.

Builder runs Phase 6 on bitcoind-mine-max (consensus-safe generate), then swaps
to bitcoind-mine-test so the reject GBT can pack past MAX_BLOCK_WEIGHT. DUT:
stock bitcoind.

Pack strategy (minimal MWEB inputs):
  - Fill with normal L1 pad txs
  - Queue 1-in/2-out MWEB partials just under 200k weight
  - RBF a single MWEB tx adding one output (+18 weight) and a tiny peg-out
    (+1 weight, pays the 1.5x MWEB replacement fee rate) to exceed the cap
  - GBT-check after RBF; assemble only when weight > 200k and wire ≤ envelope
  - DUT rejects overweight (bad-blk-mweb)
  - RBF the same input to an MWEB+L1 hybrid (higher package fee, weight under
    200k) and submit — DUT accepts

FOLLOW-UP (2026-09-15): assertions reached under-cap accept, but shutdown hung —
node1 (384 wallets) connected the accept tip during stop while TRACE wallet
logging (-debug + -loglevel=trace from TestNode) flooded AddToWallet. Re-run
after isolating wallet host / dialing back wallet debug; until then results are
not observable as a pass. See /tmp/mweb_cap_logs/FOLLOWUPS.md.

Run: cd build && test/functional/test_runner.py --extended mweb_size_max_plus_weight_reject.py
"""

from test_framework.mweb_cap_block_plan import CAP_HOST_WALLETS
from test_framework.mweb_size_util import (
    MINER_TX_DIVISOR,
    MINER_WALLET_COUNT,
    MWEB_ENVELOPE,
    PLUS_WEIGHT_CAP,
    MWEBSizeTestMixin,
    assemble_solved_block_from_gbt_with_timeout,
    reject_block_via_p2p,
    submit_solved_block,
)
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBSizeMaxPlusWeightReject(MWEBSizeTestMixin, BitcoinTestFramework):
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
            builder, "test", parties, label="plus-weight reject GBT",
        )

        tip_before = validator.getbestblockhash()
        height_before = validator.getblockcount()
        builder_height = builder.getblockcount()

        gbt_est, diag, meta = self.flood_plus_weight_rbf_pack(builder, parties)
        self.log.info(
            "Plus-weight GBT: est=%d mweb_wt≈%d mweb_in=%d kernels=%d "
            "modeled_after=%d adj=%s→%s",
            gbt_est, diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_kernels"], meta["modeled_weight_after"],
            meta["adj_old_txid"], meta["adj_new_txid"],
        )
        assert_greater_than(diag["mweb_weight_est"], PLUS_WEIGHT_CAP)
        assert gbt_est <= MWEB_ENVELOPE, gbt_est

        block = assemble_solved_block_from_gbt_with_timeout(
            builder, rpc_timeout=builder.rpc_timeout,
        )
        S = len(block.serialize())
        self.log.info("Assembled overweight S=%d envelope=%d", S, MWEB_ENVELOPE)
        assert S <= MWEB_ENVELOPE, S

        reject_block_via_p2p(
            validator, block,
            reject_msgs=["bad-blk-mweb"],
            tip_before=tip_before, height_before=height_before,
            timeout=300,
        )
        self.log.info("p2p reject observed (weight / bad-blk-mweb)")
        assert_equal(builder.getblockcount(), builder_height)
        assert_equal(validator.getblockcount(), height_before)

        # Same mempool: RBF adjustable tx back to 2 outs → valid near-max block.
        gbt_est, diag, meta = self.plus_weight_rbf_back_under_cap(
            builder, parties, meta,
        )
        self.log.info(
            "Plus-weight under-cap GBT: est=%d mweb_wt≈%d mweb_in=%d kernels=%d "
            "adj_under=%s",
            gbt_est, diag["mweb_weight_est"], diag["mweb_inputs"],
            diag["mweb_kernels"], meta["adj_under_txid"],
        )
        assert diag["mweb_weight_est"] <= PLUS_WEIGHT_CAP, diag
        assert gbt_est <= MWEB_ENVELOPE, gbt_est

        good = assemble_solved_block_from_gbt_with_timeout(
            builder, rpc_timeout=builder.rpc_timeout,
        )
        S_ok = len(good.serialize())
        self.log.info("Assembled under-cap S=%d envelope=%d", S_ok, MWEB_ENVELOPE)
        assert S_ok <= MWEB_ENVELOPE, S_ok

        tip = submit_solved_block(validator, good, timeout=1800)
        assert_equal(validator.getbestblockhash(), tip)
        assert_equal(validator.getblockcount(), height_before + 1)
        self.log.info(
            "under-cap accept OK: S=%d tip=%s mweb_wt≈%d",
            S_ok, tip, diag["mweb_weight_est"],
        )


if __name__ == "__main__":
    MWEBSizeMaxPlusWeightReject(__file__).main()
