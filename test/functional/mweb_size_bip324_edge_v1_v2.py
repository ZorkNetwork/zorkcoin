#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""3.0 BIP324-edge block: full L1 + normal MWEB; both v1 and v2 succeed.

Shared size economy packs toward MAX_BLOCK_SERIALIZED_SIZE_BIP324. The solved
block is introduced on the builder (v2 disabled), then relays through a hub
that speaks both transports:

  builder --v1--> Hub(v2 enabled) --v1--> V1Peer
                       |
                       +------v2------> V2Peer

Because S ≤ BIP324, both legs must deliver the body. Wallet host is isolated
during tip relay.

Run: cd build && test/functional/test_runner.py --extended mweb_size_bip324_edge_v1_v2.py
"""

from test_framework.mweb_cap_block_plan import (
    BIP324_CAP,
    CAP_HOST_WALLETS,
    compute_bip324_edge_plan,
    model_plan_wire,
)
from test_framework.mweb_size_util import (
    MINER_TX_DIVISOR,
    MINER_WALLET_COUNT,
    MWEBSizeTestMixin,
    block_wire_bytes,
    submit_block_via_p2p,
)
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBSizeBIP324EdgeV1V2(MWEBSizeTestMixin, BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.rpc_timeout = 7200
        wallet_args = ["-spendzeroconfchange=0", "-checkmempool=0"]
        lean = ["-checkmempool=0"]
        self.extra_args = mweb_extra_args(
            wallet_args + ["-v2transport=0"],  # 0 builder (mine budget = BIP324)
            wallet_args + ["-v2transport=0"],  # 1 wallet host
            lean + ["-v2transport=1"],         # 2 hub: mixed transports
            lean + ["-v2transport=0"],         # 3 V1Peer
            lean + ["-v2transport=1"],         # 4 V2Peer
        )

    def setup_nodes(self):
        # Default bitcoind: mine budget == BIP324 — correct for this edge.
        base = self.get_binaries()
        self.options.v2transport = False
        self.extra_init = [
            {"binaries": base, "v2transport": False},
            {"binaries": base, "v2transport": False},
            {"binaries": base, "v2transport": True},
            {"binaries": base, "v2transport": False},
            {"binaries": base, "v2transport": True},
        ]
        super().setup_nodes()

    def run_test(self):
        builder = self.nodes[0]
        wallet_host = self.nodes[1]
        hub = self.nodes[2]
        v1peer = self.nodes[3]
        v2peer = self.nodes[4]
        setup_mweb_chain(builder, self)

        parties = self.prepare_size_economy(
            builder,
            wallet_host=wallet_host,
            miner_wallets=MINER_WALLET_COUNT,
            host_wallets=CAP_HOST_WALLETS,
            miner_tx_divisor=MINER_TX_DIVISOR,
            precreate_nodes=2,
            exclude_wallet_hosts={hub, v1peer, v2peer},
        )

        plan = compute_bip324_edge_plan()
        wire_est, _ = model_plan_wire(plan)
        self.log.info("BIP324-edge plan wire≈%d cap=%d %s", wire_est, BIP324_CAP, plan.describe())
        assert wire_est <= BIP324_CAP, wire_est
        assert_greater_than(wire_est, BIP324_CAP // 2)

        gbt_est, diag, plan = self.flood_cap_fill_pack(builder, parties, plan=plan)
        self.log.info(
            "BIP324-edge GBT: est=%d mweb_in=%d l1_txs=%d",
            gbt_est, diag["mweb_inputs"], diag["l1_txs"],
        )
        assert_greater_than(diag["l1_txs"], 80)

        block, S = self.assemble_and_trim_to_size(
            builder, parties,
            target_s=min(BIP324_CAP, max(gbt_est, wire_est)),
        )
        if S < BIP324_CAP:
            try:
                block, S = self.assemble_and_trim_to_size(
                    builder, parties, target_s=BIP324_CAP,
                )
            except AssertionError as e:
                self.log.warning("Exact BIP324 trim not reached (%s); using S=%d", e, S)

        assert S <= BIP324_CAP, S
        assert_greater_than(S, BIP324_CAP // 2)
        self.log.info("BIP324-edge assembled S=%d", S)

        height_before = hub.getblockcount()

        self.disconnect_all_peers()
        self.connect_nodes(0, 2, peer_advertises_v2=False)  # builder→hub v1
        self.connect_nodes(2, 3, peer_advertises_v2=False)  # hub→V1Peer v1
        self.connect_nodes(2, 4, peer_advertises_v2=True)   # hub→V2Peer v2
        self.assert_transport(builder, hub, "v1")
        self.assert_transport(hub, v1peer, "v1")
        self.assert_transport(hub, v2peer, "v2")

        tip = submit_block_via_p2p(builder, block)
        assert_equal(builder.getbestblockhash(), tip)

        # Both transports must deliver (S ≤ BIP324).
        self.wait_for_tip(
            [hub, v1peer, v2peer], tip, timeout=1800, label="bip324-edge relay",
        )
        assert_equal(hub.getblockcount(), height_before + 1)
        assert_equal(v1peer.getblockcount(), height_before + 1)
        assert_equal(v2peer.getblockcount(), height_before + 1)
        assert_equal(block_wire_bytes(hub, tip), S)
        assert_equal(block_wire_bytes(v1peer, tip), S)
        assert_equal(block_wire_bytes(v2peer, tip), S)
        self.assert_transport(hub, v1peer, "v1")
        self.assert_transport(hub, v2peer, "v2")
        self.assert_nodes_alive([builder, hub, v1peer, v2peer])
        self.log.info("BIP324-edge OK: S=%d tip=%s via v1 and v2", S, tip)


if __name__ == "__main__":
    MWEBSizeBIP324EdgeV1V2(__file__).main()
