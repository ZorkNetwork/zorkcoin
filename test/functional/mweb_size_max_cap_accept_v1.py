#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""1.2 Valid production-cap-filled MWEB block: accept + mixed v1/v2 relay.

Builder (mine-max, v2 disabled) packs a real wallet-built block with S above
BIP324 and ≤ MWEB envelope. The block is introduced on the builder (harness
P2P — JSON-RPC submitblock cannot carry ~21 MB hex under HTTP MAX_SIZE), then
propagates over a deliberate transport graph:

  builder --v1--> DUT(v2 enabled) --v1--> V1Peer
                       |                    |
                       +------v2------> V2Peer
                       V1Peer --v1--> V2Peer (side-path)

DUT must deliver the body to V1Peer over v1, refuse the body on the v2 link to
V2Peer (BIP324 payload limit), and V2Peer must still reach the same tip via the
v1 side-path. DUT→V2Peer uses persistent ``addnode add`` (not onetry) so after
DUT disconnects V2Peer for requesting the body over v2, the v2 session can come
back before the final transport assert. Wallet host is isolated during
propagation so 384-wallet callbacks do not stall tip relay.

High-bandwidth compact-block test peers on DUT check that the compact block
(announced, or requested at depths 0 and 3) and the full block sent for a deep
compact-block request reach a v1 peer, while a v2 peer is announced the block
with headers, and a v2 peer requesting it is refused and disconnected instead
of stalling the connection.

Also records Issue E dumptxoutset timing and Issue A AssumeUTXO warm measurement
(A1 — measurement only, no scheduler fix).

Run: cd build && test/functional/test_runner.py --extended mweb_size_max_cap_accept_v1.py
"""

from pathlib import Path
import time

from test_framework.mweb_cap_block_plan import CAP_HOST_WALLETS, BIP324_CAP
from test_framework.mweb_size_util import (
    MINER_TX_DIVISOR,
    MINER_WALLET_COUNT,
    MWEB_ENVELOPE,
    MWEBSizeTestMixin,
    assemble_solved_block_from_gbt_with_timeout,
    block_wire_bytes,
    submit_block_via_p2p,
)
from test_framework.messages import (
    CInv,
    MSG_CMPCT_BLOCK,
    msg_getdata,
    msg_getheaders,
    msg_sendcmpct,
)
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.p2p import P2P_SERVICES_MWEB, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

# Substring from CanSendBlockBodyOnPeer when a v2 peer requests an oversize body.
BIP324_REFUSE_LOG = "body exceeds BIP324 limit"
CMPCTBLOCKS_VERSION_MWEB = 3
MAX_CMPCTBLOCK_DEPTH = 5


def block_msg_counts(peer):
    """Caller holds p2p_lock, as a wait_until predicate does."""
    return peer.message_count["cmpctblock"], peer.message_count["block"]


def locked_block_msg_counts(peer):
    with p2p_lock:
        return block_msg_counts(peer)


def wait_for_cmpctblock(peer, blockhash, *, timeout):
    peer.wait_until(
        lambda: "cmpctblock" in peer.last_message
        and peer.last_message["cmpctblock"].header_and_shortids.header.hash == blockhash,
        timeout=timeout,
    )


class MWEBSizeMaxCapAcceptV1(MWEBSizeTestMixin, BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.rpc_timeout = 7200
        wallet_args = ["-spendzeroconfchange=0", "-checkmempool=0"]
        lean = ["-checkmempool=0"]
        self.extra_args = mweb_extra_args(
            wallet_args + ["-v2transport=0"],  # 0 builder: v1 only (not a true prod source)
            wallet_args + ["-v2transport=0"],  # 1 wallet host
            lean + ["-v2transport=1"],         # 2 DUT: v2 enabled (mixed peers)
            lean + ["-v2transport=0"],         # 3 V1Peer
            lean + ["-v2transport=1"],         # 4 V2Peer
        )

    def setup_nodes(self):
        mine_max = self.require_mine_binary("max")
        base = self.get_binaries()
        self.options.v2transport = False
        self.extra_init = [
            {"binaries": base.with_bitcoind(mine_max), "v2transport": False},
            {"binaries": base, "v2transport": False},
            {"binaries": base, "v2transport": True},
            {"binaries": base, "v2transport": False},
            {"binaries": base, "v2transport": True},
        ]
        super().setup_nodes()

    def run_test(self):
        builder = self.nodes[0]
        wallet_host = self.nodes[1]
        dut = self.nodes[2]
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
            exclude_wallet_hosts={dut, v1peer, v2peer},
        )

        # Issue E: dump at bank scale before Phase 8 spends consume UTXOs.
        dump_path = str(Path(builder.datadir_path) / "cap_fill_utxo.dat")
        self.measure_dumptxoutset_scale(builder, dump_path=dump_path)

        # Issue A (A1): load on V2Peer, measure warm, restart clean for relay checks.
        self.measure_assumeutxo_warm(v2peer, dump_path)
        self.restart_node(4)

        tip_before = dut.getbestblockhash()
        height_before = dut.getblockcount()

        gbt_est, diag, plan = self.flood_cap_fill_pack(builder, parties)
        self.log.info(
            "Cap-fill GBT: est=%d mweb_in=%d l1_txs=%d plan=%s",
            gbt_est, diag["mweb_inputs"], diag["l1_txs"], plan.describe(),
        )
        assert_greater_than(diag["mweb_inputs"], 40_000)
        assert diag["mweb_inputs"] <= 50_000 + plan.extra_mweb_inputs

        block0 = assemble_solved_block_from_gbt_with_timeout(
            builder, rpc_timeout=builder.rpc_timeout,
        )
        S_max = len(block0.serialize())
        self.log.info(
            "Achieved max wire S_max=%d (BIP324=%d envelope=%d)",
            S_max, BIP324_CAP, MWEB_ENVELOPE,
        )
        assert_greater_than(S_max, BIP324_CAP)
        assert S_max <= MWEB_ENVELOPE, S_max

        block, S = self.assemble_and_trim_to_size(builder, parties, target_s=S_max)
        assert_equal(S, S_max)

        # Explicit transport mesh; isolate wallet host from 21 MB tip relay.
        # Start WITHOUT the V1Peer→V2Peer side-path so V2Peer must ask DUT over
        # v2 (and get refused) before we prove the v1 side-path still works.
        # DUT→V2Peer is persistent addnode: DUT disconnects V2Peer when it refuses
        # the body over v2; onetry would not come back, but add retries (~60s)
        # so the final v2 transport assert holds.
        self.disconnect_all_peers()
        self.connect_nodes(0, 2, peer_advertises_v2=False)   # builder→DUT v1
        self.connect_nodes(2, 3, peer_advertises_v2=False)   # DUT→V1Peer v1
        self.connect_nodes_persistent(2, 4, peer_advertises_v2=True)  # DUT→V2Peer v2
        self.assert_transport(builder, dut, "v1")
        self.assert_transport(dut, v1peer, "v1")
        self.assert_transport(dut, v2peer, "v2")
        self.log.info(
            "max-cap mesh (no v1 side-path yet): builder--v1-->DUT--v1-->V1Peer; "
            "DUT--v2-->V2Peer (persistent addnode)"
        )

        # High-bandwidth compact-block peers on DUT, one per transport. Each
        # syncs headers to the current tip so DUT announces the next block.
        hb_v1 = dut.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB, supports_v2_p2p=False)
        hb_v2 = dut.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB, supports_v2_p2p=True)
        for hb in (hb_v1, hb_v2):
            hb.send_and_ping(msg_sendcmpct(announce=True, version=CMPCTBLOCKS_VERSION_MWEB))
            getheaders = msg_getheaders()
            getheaders.locator.vHave = [int(dut.getbestblockhash(), 16)]
            hb.send_and_ping(getheaders)

        # Harness-only: land the solved block on builder (HTTP submitblock too small).
        tip = submit_block_via_p2p(builder, block)
        assert_equal(builder.getbestblockhash(), tip)
        assert_equal(builder.getblockcount(), height_before + 1)
        self.assert_nodes_alive([builder])

        # Phase A: DUT + V1Peer take the tip over v1; DUT refuses body on v2.
        # assert_debug_log waits after the body for the refuse line (V2Peer getdata).
        with dut.assert_debug_log(expected_msgs=[BIP324_REFUSE_LOG], timeout=1800):
            self.wait_for_tip([dut, v1peer], tip, timeout=1800, label="max-cap v1 path")
            # Leave a window for V2Peer to request the body from DUT over v2.
            time.sleep(15)
            assert v2peer.getbestblockhash() != tip, (
                "V2Peer reached tip over DUT v2 link — BIP324 refuse did not hold"
            )

        self.log.info(
            "BIP324 refuse observed; V2Peer still behind at height=%d (dut=%d)",
            v2peer.getblockcount(), dut.getblockcount(),
        )
        assert v2peer.getbestblockhash() != tip

        # Phase B: open V1Peer--v1-->V2Peer side-path; V2Peer must catch the tip.
        self.connect_nodes(3, 4, peer_advertises_v2=False)
        self.assert_transport(v1peer, v2peer, "v1")
        self.wait_for_tip([v2peer], tip, timeout=1800, label="max-cap v1 side-path")

        assert_equal(dut.getbestblockhash(), tip)
        assert_equal(v1peer.getbestblockhash(), tip)
        assert_equal(v2peer.getbestblockhash(), tip)
        assert_equal(dut.getblockcount(), height_before + 1)
        assert_equal(v1peer.getblockcount(), height_before + 1)
        assert_equal(v2peer.getblockcount(), height_before + 1)
        assert_equal(block_wire_bytes(dut, tip), S)
        assert_equal(block_wire_bytes(v1peer, tip), S)
        assert_equal(block_wire_bytes(v2peer, tip), S)

        # Transports still as wired (no silent downgrade/upgrade).
        # DUT↔V2 may have dropped during the refuse/stall window; wait for the
        # persistent addnode retry before asserting v2 is back.
        self.assert_transport(builder, dut, "v1")
        self.assert_transport(dut, v1peer, "v1")
        self.wait_for_transport(
            dut, v2peer, "v2", timeout=180, label="DUT↔V2 after stall reconnect"
        )
        self.assert_transport(v1peer, v2peer, "v1")

        # Phase C: compact blocks for the oversize block. Over v1 the compact
        # block carries the MWEB block; over v2 it doesn't fit, so DUT announces
        # with headers, and refuses requests and disconnects instead of stalling.
        wait_for_cmpctblock(hb_v1, tip, timeout=600)
        with p2p_lock:
            assert hb_v1.last_message["cmpctblock"].header_and_shortids.mweb_block is not None
        hb_v2.wait_for_header(tip, timeout=600)
        hb_v2.sync_with_ping()
        assert_equal(locked_block_msg_counts(hb_v2), (0, 0))
        self.log.info("Oversize announcement: v1 cmpctblock with MWEB block, v2 headers")

        def request_compact(hb, blockhash):
            hb.send_without_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, int(blockhash, 16))]))

        def assert_v2_request_refused(blockhash):
            peer = dut.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB, supports_v2_p2p=True)
            with dut.assert_debug_log(expected_msgs=[BIP324_REFUSE_LOG], timeout=600):
                request_compact(peer, blockhash)
                peer.wait_for_disconnect(timeout=600)
            assert_equal(locked_block_msg_counts(peer), (0, 0))

        def mine_on_dut(n):
            new_tip = self.generate(dut, n, sync_fun=lambda: self.sync_blocks([builder, dut, v1peer, v2peer]))[-1]
            wait_for_cmpctblock(hb_v1, new_tip, timeout=600)
            hb_v1.sync_with_ping()

        # Depth 0 (DUT's most recent compact block) and depth 3 (built on request).
        for depth in (0, 3):
            if depth:
                mine_on_dut(depth)
            cmpct_v1, block_v1 = locked_block_msg_counts(hb_v1)
            request_compact(hb_v1, tip)
            hb_v1.wait_until(lambda: block_msg_counts(hb_v1) == (cmpct_v1 + 1, block_v1), timeout=600)
            wait_for_cmpctblock(hb_v1, tip, timeout=600)
            assert_v2_request_refused(tip)
            self.log.info("getdata(cmpctblock) at depth %d: v1 cmpctblock, v2 refused and disconnected", depth)

        # Deeper than MAX_CMPCTBLOCK_DEPTH: the full block is sent instead.
        mine_on_dut(MAX_CMPCTBLOCK_DEPTH + 1 - 3)
        cmpct_v1, block_v1 = locked_block_msg_counts(hb_v1)
        request_compact(hb_v1, tip)
        hb_v1.wait_for_block(int(tip, 16), timeout=600)
        assert_equal(locked_block_msg_counts(hb_v1), (cmpct_v1, block_v1 + 1))
        assert_v2_request_refused(tip)
        self.log.info("Deep getdata(cmpctblock): v1 full block, v2 refused and disconnected")
        dut.disconnect_p2ps()

        self.assert_nodes_alive([builder, dut, v1peer, v2peer])
        assert tip_before != tip
        self.log.info(
            "max-cap accept OK: S=%d tip=%s "
            "(DUT+V1+V2 tips equal; v2 body refused; v1 side-path delivered; "
            "DUT↔V2 v2 reconnected; compact blocks checked)",
            S, tip,
        )


if __name__ == "__main__":
    MWEBSizeMaxCapAcceptV1(__file__).main()
