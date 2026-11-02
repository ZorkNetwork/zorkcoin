#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""BIP324 / MWEB wire-size packing coverage (see doc/mweb/wire-size-and-bip324.md).

Primary architected fill / NO_GAP / NEAR_CAP proofs (including >80k UTXO
size-binding and max-output BatchVerify) live in unit test
mweb_block_packing_tests with MEGA_EXTENDED_TEST=1. This functional covers:
  - soft-cap-adjacent packing already stressed by mweb_weight.py
  - a smaller 4x-style oversubscription smoke via RPC pegins
  - consensus rejects block above max MWEB envelope
  - block above BIP324 below max MWEB does not hit bad-blk-serialized-size
  - mined MWEB block relays over v2transport
  - denser pegin block toward BIP324 cap (mega/extended only)

This script is listed in MEGA_SCRIPTS; the default test_runner runs it only
with --mega. The default path (through v2 relay and size-gate checks) typically
takes ~5-15 minutes. The denser pegin / BIP324-cap section runs when --mega
(MEGA_EXTENDED_TEST=1) or --extended is used and takes significantly longer.

Run: test/functional/test_runner.py --mega mweb_block_packing.py
"""

import copy
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CBlock,
    FromHex,
    Hash,
    msg_block,
)
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal, assert_greater_than


BIP324_CAP = 16_777_214
# Litecoin-compatible consensus envelope (MAX_BLOCK_SERIALIZED_SIZE + mw::MAX_BLOCK_BYTES).
MWEB_ENVELOPE = 25_800_195
# Soft-cap-adjacent v2 relay floor (~532 pegins). Extended denser section must
# clear a much larger wire size so v2 relay is exercised closer to the BIP324 cap.
V2_RELAY_MIN_WIRE = 100_000
DENSER_PEGIN_MIN_WIRE = 1_000_000  # ≥ ~6% of BIP324; unit EXTENDED owns true NEAR_CAP


class MWEBBlockPackingTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--extended",
            dest="extended",
            action="store_true",
            help="Run the additional denser pegin block (pass directly to this script)",
        )

    def set_test_params(self):
        self.setup_clean_chain = True
        env = os.getenv("MEGA_EXTENDED_TEST", "")
        self.packing_extended = bool(getattr(self.options, "extended", False) or (env and env != "0"))
        self.rpc_timeout = 600 if self.packing_extended else 240
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(
            ["-spendzeroconfchange=0", "-v2transport=1"],
            ["-spendzeroconfchange=0", "-v2transport=1"],
        )

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_pegin_batch(self, miner, dest_addr, count, amount):
        for _ in range(count):
            miner.sendtoaddress(dest_addr, amount)
        assert_equal(len(miner.getrawmempool()), count)
        blockhash = self.generate(miner, 1)[0]
        self.sync_all()
        assert_equal(len(miner.getrawmempool()), 0)
        tip_bytes = len(miner.getblock(blockhash, 0)) // 2
        self.log.info("Mined block wire size: %d (%.2f%% of BIP324 cap)", tip_bytes, 100.0 * tip_bytes / BIP324_CAP)
        assert tip_bytes <= BIP324_CAP, tip_bytes
        return blockhash, tip_bytes

    def run_test(self):
        self.log.info("Activate MWEB")
        setup_mweb_chain(self.nodes[0], self)
        self.sync_all()
        self.generate(self.nodes[1], 700)
        self.sync_all()

        batch = 532
        self.log.info("queue pegins above old MAX_MINE_WEIGHT soft-cap: %d pegins", batch)
        addr = self.nodes[0].getnewaddress(address_type="mweb")
        blockhash, tip_bytes = self.mine_pegin_batch(self.nodes[1], addr, batch, 0.01)
        assert_greater_than(len(self.nodes[0].listunspent(addresses=[addr])), 512)

        batch2 = 200
        self.log.info("second irregular pegin batch clears without exceeding cap: %d pegins", batch2)
        addr2 = self.nodes[0].getnewaddress(address_type="mweb")
        self.generate(self.nodes[1], 200)  # mature more coinbases for spendzeroconfchange=0
        self.sync_all()
        blockhash2, tip2 = self.mine_pegin_batch(self.nodes[1], addr2, batch2, 0.01)

        self.generate(self.nodes[1], 600)
        self.sync_all()
        batch3 = 532
        self.log.info("mined MWEB block relays over v2transport: mine %d pegins", batch3)
        addr3 = self.nodes[0].getnewaddress(address_type="mweb")
        large_hash, large_bytes = self.mine_pegin_batch(self.nodes[1], addr3, batch3, 0.01)
        assert_greater_than(large_bytes, V2_RELAY_MIN_WIRE)
        assert_equal(self.nodes[0].getbestblockhash(), large_hash)
        assert_equal(self.nodes[1].getbestblockhash(), large_hash)
        peerinfo = self.nodes[0].getpeerinfo()
        assert any(p.get("transport_protocol_type") == "v2" for p in peerinfo), peerinfo
        assert all(p.get("synced_headers", -1) >= 0 for p in peerinfo)

        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        tip_block = FromHex(CBlock(), self.nodes[0].getblock(large_hash, 0))
        peer.send_and_ping(msg_block(tip_block))
        assert_equal(self.nodes[0].getbestblockhash(), large_hash)

        # BIP324-capped mining is not the consensus size; pad past MWEB_ENVELOPE.
        # Send over v1 P2P so BIP324 framing cannot drop it before CheckBlock.
        self.log.info("consensus rejects block above max MWEB envelope")
        from test_framework.messages import MWEBInput
        oversize = copy.deepcopy(tip_block)
        assert oversize.mweb_block is not None
        need = MWEB_ENVELOPE - large_bytes + 10_000
        n_extra = need // 196 + 100
        self.log.info("Appending %d synthetic MWEB inputs for oversize (base=%d)", n_extra, large_bytes)
        for i in range(n_extra):
            inp = MWEBInput()
            inp.features = 0x01
            inp.output_id = Hash(i + 2)
            inp.commitment = 1
            inp.output_pubkey = 2
            inp.input_pubkey = 3
            inp.signature = 4
            oversize.mweb_block.body.inputs.append(inp)
        over_len = len(oversize.serialize())
        assert_greater_than(over_len, MWEB_ENVELOPE)
        assert over_len < 32_000_000  # still under v1 MAX_PROTOCOL_MESSAGE_LENGTH
        v1_peer = self.nodes[0].add_p2p_connection(P2PInterface(), supports_v2_p2p=False)
        with self.nodes[0].assert_debug_log(expected_msgs=["bad-blk-serialized-size"], timeout=180):
            v1_peer.send_without_ping(msg_block(oversize))
        assert_equal(self.nodes[0].getbestblockhash(), large_hash)

        # Size in (BIP324, WITH_MWEB]: synthetic pad is not a valid tip. Unit test
        # checkblock_tests_above_bip324_below_max_mweb_no_bad_blk_serialized_size owns
        # the bad-blk-serialized-size assert; here only deliver mid-size over v1.
        self.log.info(
            "block above BIP324 below max MWEB does not hit bad-blk-serialized-size (>%d, ≤%d)",
            BIP324_CAP,
            MWEB_ENVELOPE,
        )
        mid = copy.deepcopy(tip_block)
        assert mid.mweb_block is not None
        mid_need = BIP324_CAP - large_bytes + 50_000
        n_mid = max(mid_need // 196 + 50, 1)
        for i in range(n_mid):
            inp = MWEBInput()
            inp.features = 0x01
            inp.output_id = Hash(i + 9_000_000)
            inp.commitment = 1
            inp.output_pubkey = 2
            inp.input_pubkey = 3
            inp.signature = 4
            mid.mweb_block.body.inputs.append(inp)
        mid_len = len(mid.serialize())
        assert_greater_than(mid_len, BIP324_CAP)
        assert mid_len <= MWEB_ENVELOPE, mid_len
        v1_mid = self.nodes[0].add_p2p_connection(P2PInterface(), supports_v2_p2p=False)
        prev_log = self.nodes[0].debug_log_size(encoding="utf-8")
        v1_mid.send_without_ping(msg_block(mid))

        def mid_received():
            with open(self.nodes[0].debug_log_path, encoding="utf-8", errors="replace") as dl:
                dl.seek(prev_log)
                return f"received: block ({mid_len} bytes)" in dl.read()

        self.wait_until(mid_received, timeout=120)
        v1_mid.peer_disconnect()
        self.nodes[0].disconnect_p2ps()

        if self.packing_extended:
            batch_ext = 2000
            self.log.info(
                "denser pegin block toward BIP324 cap (extended only): mine %d pegins",
                batch_ext,
            )
            # One send per mature coinbase (spendzeroconfchange=0); leave headroom past maturity.
            # Chunk generates so sync_blocks(60s) cannot time out on a single 2k+ burst.
            remaining = batch_ext + 300
            while remaining > 0:
                n = min(200, remaining)
                self.generate(self.nodes[1], n, sync_fun=lambda: self.sync_blocks(timeout=180))
                remaining -= n
            addr_ext = self.nodes[0].getnewaddress(address_type="mweb")
            # Tip is deep (many halvings); keep amounts dust-sized — denser wire size
            # comes from pegin count, not value.
            ext_hash, ext_bytes = self.mine_pegin_batch(self.nodes[1], addr_ext, batch_ext, 0.0001)
            assert_greater_than(ext_bytes, DENSER_PEGIN_MIN_WIRE)
            assert_greater_than(ext_bytes, large_bytes)
            assert_equal(self.nodes[0].getbestblockhash(), ext_hash)
            assert_equal(self.nodes[1].getbestblockhash(), ext_hash)
            peerinfo_ext = self.nodes[0].getpeerinfo()
            assert any(p.get("transport_protocol_type") == "v2" for p in peerinfo_ext), peerinfo_ext
            peer_ext = self.nodes[0].add_p2p_connection(P2PInterface())
            tip_ext = FromHex(CBlock(), self.nodes[0].getblock(ext_hash, 0))
            peer_ext.send_and_ping(msg_block(tip_ext))
            assert_equal(self.nodes[0].getbestblockhash(), ext_hash)
            self.log.info(
                "denser pegin wire=%d (%.2f%% of BIP324); unit MEGA_EXTENDED_TEST owns true NEAR_CAP",
                ext_bytes,
                100.0 * ext_bytes / BIP324_CAP,
            )
        else:
            self.log.info(
                "denser pegin block toward BIP324 cap skipped; pass --mega (or MEGA_EXTENDED_TEST=1); "
                "unit mweb_block_packing_tests with MEGA_EXTENDED_TEST=1 covers "
                "architected NEAR_CAP and max-output BatchVerify"
            )


if __name__ == "__main__":
    MWEBBlockPackingTest(__file__).main()
