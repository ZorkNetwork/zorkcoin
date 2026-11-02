#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Background MWEB serve rotates across peers with pending jobs (Issue B)."""

import time

from test_framework.messages import (
    MWEB_UTXO_FORMAT_HASH_ONLY,
    NODE_MWEB_LIGHT_CLIENT,
)
from test_framework.p2p import P2P_SERVICES_MWEB
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    generate,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.mweb_stress_mega_util import (
    MWEBServeLogStats,
    MockLightClientBase,
    first_unspent_mweb_leaf,
)
from test_framework.util import assert_equal, assert_greater_than

MAX_MWEB_SERVE_JOBS_PER_PEER = 8
MWEB_LIGHT_CLIENT_SERVICES = P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT
ROTATION_WAIT = 180


class MWEBP2PServePeerRotationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [mweb_extra_args(['-debug=net'])[0]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        for _ in range(40):
            node.sendtoaddress(node.getnewaddress(address_type='mweb'), 0.01)
            generate(node, 1)

        tip = node.getblockcount()
        # Blocks must be within MAX_MWEB_LEAFSET_DEPTH of tip for serve policy.
        cold_hashes = [node.getblockhash(tip - 9 + i) for i in range(9)]
        high_hash = cold_hashes[-1]
        low_hashes = cold_hashes[:MAX_MWEB_SERVE_JOBS_PER_PEER]
        leaves = {block_hash: first_unspent_mweb_leaf(node, block_hash) for block_hash in cold_hashes}
        node.disconnect_p2ps()

        node.clearmwebhistoricalcache()

        stats = MWEBServeLogStats(node.debug_log_path)
        stats.mark_log_end()

        p_low = node.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)
        p_high = node.add_p2p_connection(
            MockLightClientBase(), services=MWEB_LIGHT_CLIENT_SERVICES)

        peer_ids = sorted(p['id'] for p in node.getpeerinfo())
        assert_equal(len(peer_ids), 2)
        p_low_id, p_high_id = peer_ids[0], peer_ids[1]
        assert_greater_than(p_high_id, p_low_id)
        self.log.info("Serve rotation peers: low=%d high=%d", p_low_id, p_high_id)

        # Start one cold miss on the low-NodeId peer, then queue the high peer
        # before filling the low peer's job cap with more distinct cold blocks.
        p_low.request_mweb_utxos(low_hashes[0], leaves[low_hashes[0]], num_requested=64,
                                 output_format=MWEB_UTXO_FORMAT_HASH_ONLY)
        p_high.request_mweb_utxos(high_hash, leaves[high_hash], num_requested=64,
                                  output_format=MWEB_UTXO_FORMAT_HASH_ONLY)
        for block_hash in low_hashes[1:]:
            p_low.request_mweb_utxos(block_hash, leaves[block_hash], num_requested=64,
                                     output_format=MWEB_UTXO_FORMAT_HASH_ONLY)

        deadline = time.monotonic() + ROTATION_WAIT
        seen = set()
        while time.monotonic() < deadline:
            seen |= stats.background_serve_peer_ids_since()
            if p_low_id in seen and p_high_id in seen and p_high.responses_received > 0:
                break
            time.sleep(0.25)

        self.log.info(
            "Background serve peer ids seen=%s high_responses=%d low_responses=%d",
            sorted(seen), p_high.responses_received, p_low.responses_received,
        )
        assert p_low_id in seen, (
            f"low NodeId peer {p_low_id} never received background serve steps")
        assert p_high_id in seen, (
            f"high NodeId peer {p_high_id} starved by lowest-NodeId bias")
        assert_greater_than(p_high.responses_received, 0)

        node.disconnect_p2ps()
        self.log.info("Serve peer rotation: PASSED")


if __name__ == '__main__':
    MWEBP2PServePeerRotationTest(__file__).main()
