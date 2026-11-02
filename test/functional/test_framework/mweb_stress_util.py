#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for MWEB P2P stress / liveness functional tests."""

import time

from test_framework.messages import (
    CInv,
    Hash,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    MSG_MWEB_LEAFSET,
    msg_getdata,
    msg_getheaders,
    msg_getmwebutxos,
    msg_ping,
    NODE_MWEB_LIGHT_CLIENT,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB, p2p_lock
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    setup_mweb_chain,
)

MAX_MWEB_LEAFSET_DEPTH = 10
MAX_REQUESTED_MWEB_UTXOS = 4096
MWEB_LIGHT_CLIENT_SERVICES = P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT


def anchor_hashes_for_tip(node, tip_height=None, max_depth=10):
    """Return anchor block hashes at tip and recent depths (up to max_depth)."""
    tip_height = tip_height or node.getblockcount()
    tip_hash = node.getblockhash(tip_height)
    anchors = [tip_hash]
    for offset in (1, 5, 10):
        if offset > max_depth:
            continue
        height = tip_height - offset
        if height >= FIRST_MWEB_HEIGHT:
            anchors.append(node.getblockhash(height))
    return anchors


def grow_mweb_chain(test, node, *, post_blocks, wallets=8, pegin_interval=10, log_interval=500, reconnect_peers=True):
    """Activate MWEB then extend the chain with periodic pegins to grow the UTXO set."""
    if test is not None:
        test.log.info("Activating MWEB on node (height %d)...", FIRST_MWEB_HEIGHT)
    if test is not None and reconnect_peers:
        setup_mweb_chain(node, test)
    else:
        setup_mweb_chain(node)
    if test is not None:
        test.log.info("MWEB active at height %d; growing %d post-MWEB blocks", node.getblockcount(), post_blocks - 1)
    addresses = [node.getnewaddress(address_type='mweb') for _ in range(wallets)]
    for height in range(1, post_blocks):
        if height % pegin_interval == 0:
            addr = addresses[height % wallets]
            node.sendtoaddress(addr, 0.01)
        if test is not None:
            test.generate(node, 1, sync_fun=test.no_op)
        else:
            generate(node, 1)
        if test is not None and log_interval and height % log_interval == 0:
            test.log.info("  post-MWEB progress: %d / %d blocks", height, post_blocks - 1)
    if test is not None:
        test.log.info("Chain growth complete at height %d", node.getblockcount())


class MWEBFloodPeer(P2PInterface):
    """Rotates getmwebutxos / leafset requests at varying depths."""

    def __init__(self, anchor_hashes, start_leaves):
        """start_leaves maps each anchor hash to an unspent leaf index there."""
        super().__init__()
        self.anchor_hashes = anchor_hashes
        self.start_leaves = start_leaves
        self._cursor = 0
        self.requests_sent = 0
        self.responses_received = 0

    def send_next_mweb_request(self):
        block_hash = self.anchor_hashes[self._cursor % len(self.anchor_hashes)]
        self._cursor += 1
        self.requests_sent += 1
        if self._cursor % 2 == 0:
            want = msg_getdata([CInv(MSG_MWEB_LEAFSET, int(block_hash, 16))])
            self.send_without_ping(want)
        else:
            self.send_without_ping(msg_getmwebutxos(
                block_hash=Hash.from_hex(block_hash),
                start_index=self.start_leaves[block_hash],
                num_requested=16,
                output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
            ))

    def _note_response(self):
        self.responses_received += 1

    def on_mwebutxos(self, message):
        self._note_response()

    def on_mwebleafset(self, message):
        self._note_response()


class MWEBInvalidPeer(P2PInterface):
    """Sends policy-violating LIP-0006 requests (expect disconnect)."""

    def __init__(self, tip_hash, deep_hash):
        super().__init__()
        self.tip_hash = tip_hash
        self.deep_hash = deep_hash
        self._step = 0

    def send_next_mweb_request(self):
        step = self._step % 3
        self._step += 1
        if step == 0:
            self.send_without_ping(msg_getmwebutxos(
                block_hash=Hash.from_hex(self.tip_hash),
                start_index=0,
                num_requested=MAX_REQUESTED_MWEB_UTXOS + 1,
                output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
            ))
        elif step == 1:
            self.send_without_ping(msg_getmwebutxos(
                block_hash=Hash.from_hex(self.tip_hash),
                start_index=0,
                num_requested=1,
                output_format=0xff,
            ))
        else:
            self.send_without_ping(msg_getdata([
                CInv(MSG_MWEB_LEAFSET, int(self.deep_hash, 16)),
            ]))


class MWEBUploadAbusePeer(P2PInterface):
    """Keeps sending LIP-0006 requests after the upload budget is exhausted."""

    def __init__(self, tip_hash, start_index):
        super().__init__()
        self.tip_hash = tip_hash
        self.start_index = start_index

    def send_next_mweb_request(self):
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(self.tip_hash),
            start_index=self.start_index,
            num_requested=64,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))


class BenignProbePeer(P2PInterface):
    """Ping probe for liveness under MWEB flood."""

    def __init__(self):
        super().__init__()
        self.rtts = []
        self._ping_sent_at = {}

    def send_ping_probe(self):
        self.last_ping_nonce = self.ping_counter
        self._ping_sent_at[self.ping_counter] = time.time()
        self.send_without_ping(msg_ping(self.ping_counter))
        self.ping_counter += 1

    def on_pong(self, message):
        sent_at = self._ping_sent_at.pop(message.nonce, None)
        if sent_at is not None:
            self.rtts.append(time.time() - sent_at)

    def rtt_p95(self):
        with p2p_lock:
            if not self.rtts:
                return float('inf')
            sorted_rtts = sorted(self.rtts)
            idx = max(0, int(len(sorted_rtts) * 0.95) - 1)
            return sorted_rtts[idx]


class BlockFetchPeer(P2PInterface):
    """Fetches the witness block at tip via getdata."""

    def __init__(self, tip_hash):
        super().__init__()
        self.tip_hash = tip_hash
        self.received = False

    def request_tip_block(self):
        self.send_without_ping(msg_getdata([
            CInv(MSG_BLOCK | MSG_WITNESS_FLAG, int(self.tip_hash, 16)),
        ]))

    def on_block(self, message):
        self.received = True


class HeadersProbePeer(P2PInterface):
    """Requests headers through the victim tip."""

    def __init__(self, locator_hashes):
        super().__init__()
        self.locator_hashes = locator_hashes
        self.headers = []

    def request_headers(self):
        msg = msg_getheaders()
        msg.locator.vHave = list(self.locator_hashes)
        msg.hashstop = 0
        self.send_without_ping(msg)

    def on_headers(self, message):
        self.headers = list(message.headers)


def flood_victim(victim_peers, stop_event, rate_per_peer):
    interval = 1.0 / max(rate_per_peer, 1.0)
    while not stop_event.is_set():
        for peer in victim_peers:
            if stop_event.is_set():
                break
            if peer.is_connected:
                peer.send_next_mweb_request()
        if stop_event.wait(timeout=interval):
            break
