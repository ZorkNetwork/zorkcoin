#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB P2P light-client operator policy tests (P-01 plan V2 §2.3 / §8)."""

import time

from test_framework.messages import (
    CInv,
    Hash,
    MSG_BLOCK,
    MSG_MWEB_HEADER,
    MSG_WITNESS_FLAG,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    MSG_MWEB_LEAFSET,
    NODE_MWEB_LIGHT_CLIENT,
    msg_getdata,
    msg_getmwebutxos,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    get_hogex_tx,
    get_mweb_header,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.mweb_stress_mega_util import first_unspent_mweb_leaf
from test_framework.mweb_stress_util import MWEBUploadAbusePeer
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

MWEB_LIGHT_CLIENT_SERVICES = P2P_SERVICES_MWEB | NODE_MWEB_LIGHT_CLIENT
UPLOAD_LIMIT_ARGS = ['-maxuploadtarget=100k']
# Regtest chain work stays below mainnet minimum, so IBD latch never clears on a fresh node.
IBD_MIN_CHAINWORK = "0x0000000000000000000000000000000000000001128750f82f4c366153a3a030"


class MWEBLightClientPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.mwebutxos = {}
        self.utxo_responses = 0
        self.mwebheaders = {}

    def request_mweb_utxos(self, block_hash, start_index, num_requested=1):
        self.send_without_ping(msg_getmwebutxos(
            block_hash=Hash.from_hex(block_hash),
            start_index=start_index,
            num_requested=num_requested,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        ))

    def on_mwebutxos(self, message):
        self.utxo_responses += 1
        self.mwebutxos[message.block_hash] = message

    def on_mwebheader(self, message):
        self.mwebheaders[message.header_hash()] = message.merkleblockwithmweb

    def wait_for_mwebutxos(self, block_hash, timeout=30):
        expected = Hash.from_hex(block_hash)
        self.wait_until(lambda: expected in self.mwebutxos, timeout=timeout)


class MWEBP2PRateLimitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [mweb_extra_args([])[0], mweb_extra_args([])[0]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def activate_mweb(self, node, extra_pegins=0):
        if node.getblockcount() < FIRST_MWEB_HEIGHT:
            generate(node, 101)
            node.sendtoaddress(node.getnewaddress(), 10)
            generate(node, 1)
            remaining = FIRST_MWEB_HEIGHT - 1 - node.getblockcount()
            if remaining > 0:
                generate(node, remaining)
            node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)
            generate(node, 1)
        for _ in range(extra_pegins):
            node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)
            generate(node, 1)
        return node.getbestblockhash()

    def localservices_has_light_client(self, node):
        services = int(node.getnetworkinfo()['localservices'], 16)
        return bool(services & NODE_MWEB_LIGHT_CLIENT)

    def upload_target_reached(self, node):
        return node.getnettotals()['uploadtarget']['target_reached']

    def exhaust_upload_budget(self, node, tip_hash, disconnect_after=True):
        """Pull blocks until -maxuploadtarget is reached."""
        peer = node.add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        tip_int = int(tip_hash, 16)
        for _ in range(10000):
            if self.upload_target_reached(node):
                break
            peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, tip_int)]))
            peer.sync_with_ping(timeout=10)
        assert self.upload_target_reached(node)
        if disconnect_after:
            node.disconnect_p2ps()

    def reduce_upload_budget(self, node, tip_hash, max_bytes_left):
        """Pull blocks until bytes_left <= max_bytes_left and return that peer.

        The next message has to go out on this connection. A new inbound peer
        records another handshake on the same cycle, and a v2 responder may
        send up to 4095 bytes of BIP324 garbage before version. That was
        enough to exhaust a remainder of this size, so TryEnqueue disconnected
        for the hard upload limit instead of serving a partial mwebutxos.
        """
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        tip_int = int(tip_hash, 16)
        for _ in range(10000):
            left = node.getnettotals()['uploadtarget']['bytes_left_in_cycle']
            if left <= max_bytes_left:
                break
            peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, tip_int)]))
            peer.sync_with_ping(timeout=10)
        left = node.getnettotals()['uploadtarget']['bytes_left_in_cycle']
        # Partial UTXO serve needs 256 <= bytes_left < 64 * 256. Below 256 the
        # node disconnects; at 0 it takes the hard upload-limit path.
        assert not self.upload_target_reached(node)
        assert_greater_than(left, 255)
        assert left <= max_bytes_left
        return peer

    def test_blocksonly_no_serve(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(['-blocksonly'])[0])
        assert not self.localservices_has_light_client(self.nodes[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        time.sleep(1)
        with p2p_lock:
            assert_equal(len(peer.mwebutxos), 0)
        self.nodes[0].disconnect_p2ps()

    def test_blocksonly_override(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(['-blocksonly', '-mwebserveinblocksonly=1'])[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        peer.wait_for_mwebutxos(tip_hash)
        self.nodes[0].disconnect_p2ps()

    def test_mwebserve_off(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(['-mwebserve=0'])[0])
        assert not self.localservices_has_light_client(self.nodes[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        time.sleep(1)
        with p2p_lock:
            assert_equal(len(peer.mwebutxos), 0)
        self.nodes[0].disconnect_p2ps()

    def test_upload_limit_disconnect(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS)[0])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        peer.wait_for_disconnect(timeout=10)

    def test_download_bypass(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS + ['-whitelist=download@127.0.0.1'])[0])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        peer.wait_for_mwebutxos(tip_hash)
        self.nodes[0].disconnect_p2ps()

    def test_partial_utxo(self, tip_hash):
        # Prove natural exhaustion cannot explain the later short response.
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf, num_requested=64)
        peer.wait_for_mwebutxos(tip_hash)
        with p2p_lock:
            assert_equal(len(peer.mwebutxos[Hash.from_hex(tip_hash)].utxos), 64)
        node.disconnect_p2ps()
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS)[0])
        # Leave enough budget for a few UTXOs (256-byte estimate each) but not 64.
        peer = self.reduce_upload_budget(self.nodes[0], tip_hash, max_bytes_left=2000)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf, num_requested=64)
        peer.wait_for_mwebutxos(tip_hash)
        with p2p_lock:
            msg = peer.mwebutxos[Hash.from_hex(tip_hash)]
            assert_greater_than(len(msg.utxos), 0)
            assert len(msg.utxos) < 64
        self.nodes[0].disconnect_p2ps()

    def test_service_bit_refresh(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS)[0])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        # Force a msghand pass so service bits refresh.
        peer = self.nodes[0].add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.sync_with_ping()
        assert not self.localservices_has_light_client(self.nodes[0])
        self.nodes[0].disconnect_p2ps()
        # FORCE restores the light-client service bit even with a low upload target.
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS + ['-mwebserve=1'])[0])
        peer = self.nodes[0].add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.sync_with_ping()
        assert self.localservices_has_light_client(self.nodes[0])
        self.nodes[0].disconnect_p2ps()

    def test_force_serve_at_limit(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS + ['-mwebserve=1'])[0])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf)
        peer.wait_for_mwebutxos(tip_hash)
        self.nodes[0].disconnect_p2ps()

    def test_cpu_credit_exhaustion(self, tip_hash):
        # Restart clears the historical serve cache, so the first request pays
        # MWEB_SERVE_MATERIALIZE_SURCHARGE (500) + num_requested. Burst must
        # clear that once; keep it low enough that follow-up spam still denies.
        self.restart_node(0, extra_args=mweb_extra_args(['-mwebserveburst=600', '-debug=net'])[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, self.tip_leaf, num_requested=1)
        peer.wait_for_mwebutxos(tip_hash)
        initial_responses = peer.utxo_responses
        followup_requests = 0
        with self.nodes[0].assert_debug_log(['MWEB serve credit deny:']):
            for _ in range(20):
                if not peer.is_connected:
                    break
                try:
                    peer.request_mweb_utxos(tip_hash, self.tip_leaf, num_requested=10)
                    followup_requests += 1
                except OSError:
                    break
            peer.wait_for_disconnect(timeout=30)
        with p2p_lock:
            extra = peer.utxo_responses - initial_responses
            assert extra < followup_requests
        self.nodes[0].disconnect_p2ps()

    def test_upload_abuse_peer(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS)[0])
        node = self.nodes[0]
        node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        self.exhaust_upload_budget(node, tip_hash, disconnect_after=False)
        abuse = node.add_p2p_connection(MWEBUploadAbusePeer(tip_hash, self.tip_leaf), services=MWEB_LIGHT_CLIENT_SERVICES)
        abuse.send_next_mweb_request()
        abuse.wait_for_disconnect(timeout=10)

    def test_leafset_upload_disconnect(self, tip_hash):
        self.restart_node(0, extra_args=mweb_extra_args(UPLOAD_LIMIT_ARGS)[0])
        self.exhaust_upload_budget(self.nodes[0], tip_hash)
        peer = self.nodes[0].add_p2p_connection(P2PInterface(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.send_without_ping(msg_getdata([CInv(MSG_MWEB_LEAFSET, int(tip_hash, 16))]))
        peer.wait_for_disconnect(timeout=10)

    def test_inactive_chain_ignore(self, tip_hash):
        node = self.nodes[0]
        self.restart_node(0, extra_args=self.extra_args[0])
        stale = generate(node, 1)[0]
        node.invalidateblock(stale)
        node.generatetoaddress(nblocks=2, address=node.getnewaddress(), called_by_framework=True)
        node.reconsiderblock(stale)
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(stale, self.tip_leaf)
        peer.sync_with_ping(timeout=10)
        with p2p_lock:
            assert Hash.from_hex(stale) not in peer.mwebutxos
            assert peer.is_connected
        serve_hash = node.getbestblockhash()
        peer.request_mweb_utxos(serve_hash, first_unspent_mweb_leaf(node, serve_hash))
        peer.wait_for_mwebutxos(serve_hash)
        node.disconnect_p2ps()

    def test_credit_disconnect(self, tip_hash):
        """T-11: sustained credit denial disconnects abusive peer."""
        self.log.info("T-11: credit denial disconnect")
        node = self.nodes[0]
        tip_hash = node.getbestblockhash()
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        self.restart_node(0, extra_args=mweb_extra_args(['-mwebserveburst=5'])[0])
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        # U-12 / I15: 9 denials leave peer connected; the 10th triggers disconnect.
        for _ in range(9):
            peer.request_mweb_utxos(tip_hash, tip_leaf, num_requested=100)
            peer.sync_with_ping(timeout=5)
        peer.request_mweb_utxos(tip_hash, tip_leaf, num_requested=100)
        peer.wait_for_disconnect(timeout=30)
        node.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])

    def test_fresh_peer_after_credit_deny(self, tip_hash):
        """A new connection is served after credit-deny disconnect.

        Every new connection has a fresh credit bucket, regardless of how any
        previous connection ended. This case exercises service after a previous
        connection closes for repeated credit refusals. Refusals are silent;
        the repeated requests below trigger server closure at its threshold.
        Burst 600 can pay one cold UTXO serve (materialize surcharge plus one
        output) and still refuse follow-up spam, matching test_cpu_credit_exhaustion.
        See doc/mweb/light-clients.md, Connection resource allowance.
        """
        self.log.info("Fresh peer after credit-deny disconnect")
        node = self.nodes[0]
        tip_hash = node.getbestblockhash()
        tip_leaf = first_unspent_mweb_leaf(node, tip_hash)
        self.restart_node(0, extra_args=mweb_extra_args(['-mwebserveburst=600', '-debug=net'])[0])
        abusive = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        abusive.request_mweb_utxos(tip_hash, tip_leaf, num_requested=1)
        abusive.wait_for_mwebutxos(tip_hash)
        with node.assert_debug_log(['MWEB serve credit deny:']):
            for _ in range(20):
                if not abusive.is_connected:
                    break
                try:
                    abusive.request_mweb_utxos(tip_hash, tip_leaf, num_requested=10)
                except OSError:
                    break
            abusive.wait_for_disconnect(timeout=30)
        node.disconnect_p2ps()
        fresh = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        fresh.request_mweb_utxos(tip_hash, tip_leaf, num_requested=1)
        fresh.wait_for_mwebutxos(tip_hash)
        with p2p_lock:
            message = fresh.mwebutxos[Hash.from_hex(tip_hash)]
            assert_greater_than(len(message.utxos), 0)
        assert fresh.is_connected
        node.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])

    def test_header_queued(self, tip_hash):
        """T-12: mwebheader requests are queued and served under load."""
        self.log.info("T-12: mwebheader queued serve")
        node = self.nodes[0]
        tip_hash = node.getbestblockhash()
        peer = node.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        for _ in range(20):
            peer.send_without_ping(msg_getdata([CInv(MSG_MWEB_HEADER, int(tip_hash, 16))]))
        peer.wait_until(lambda: tip_hash in peer.mwebheaders, timeout=30)
        with p2p_lock:
            header = peer.mwebheaders[tip_hash]
            assert_equal(header.mweb_header, get_mweb_header(node, tip_hash))
            assert_equal(header.hogex, get_hogex_tx(node, tip_hash))
        peer.sync_with_ping(timeout=30)
        assert peer.is_connected
        node.disconnect_p2ps()

    def test_ibd_silent_ignore(self):
        helper = self.nodes[1]
        setup_mweb_chain(helper)
        generate(helper, 25)
        helper_height = helper.getblockcount()

        victim = self.nodes[0]
        self.stop_node(0)
        self.cleanup_folder(victim.blocks_path)
        self.cleanup_folder(victim.chain_path / "chainstate")
        victim.blocks_path.mkdir(parents=True, exist_ok=True)
        ibd_args = mweb_extra_args([
            '-connect=0',
            f'-minimumchainwork={IBD_MIN_CHAINWORK}',
        ])[0]
        self.start_node(0, extra_args=ibd_args)
        setup_mweb_chain(victim)
        assert victim.getblockchaininfo()['initialblockdownload']
        self.connect_nodes(0, 1)
        self.wait_until(lambda: victim.getblockcount() < helper_height, timeout=5)
        assert victim.getblockcount() < helper_height
        tip_hash = victim.getbestblockhash()
        peer = victim.add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.request_mweb_utxos(tip_hash, 0)
        peer.sync_with_ping(timeout=10)
        with p2p_lock:
            assert Hash.from_hex(tip_hash) not in peer.mwebutxos
            assert peer.is_connected
        victim.disconnect_p2ps()
        self.restart_node(0, extra_args=self.extra_args[0])

    def test_historical_after_restart(self, tip_hash):
        node = self.nodes[0]
        tip_height = node.getblockcount()
        hist_hash = node.getblockhash(max(FIRST_MWEB_HEIGHT, tip_height - 1))
        hist_leaf = first_unspent_mweb_leaf(node, hist_hash)
        self.restart_node(0, extra_args=self.extra_args[0])
        peer = self.nodes[0].add_p2p_connection(MWEBLightClientPeer(), services=MWEB_LIGHT_CLIENT_SERVICES)
        peer.wait_for_connect(timeout=30)
        peer.request_mweb_utxos(hist_hash, hist_leaf)
        peer.wait_for_mwebutxos(hist_hash, timeout=120)
        self.nodes[0].disconnect_p2ps()

    def run_test(self):
        tip_hash = self.activate_mweb(self.nodes[0], extra_pegins=3)
        # Grow a few more blocks so historical tip-1 exists.
        for _ in range(3):
            self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 0.1)
            generate(self.nodes[0], 1)
        # Enough live outputs for the 64-item unlimited budget control.
        node = self.nodes[0]
        node.sendmany('', {node.getnewaddress(address_type='mweb'): 0.01 for _ in range(64)})
        generate(node, 1)
        tip_hash = self.nodes[0].getbestblockhash()
        self.tip_leaf = first_unspent_mweb_leaf(self.nodes[0], tip_hash)

        self.log.info("Historical serve after restart")
        self.test_historical_after_restart(tip_hash)

        self.log.info("D1: blocksonly")
        self.test_blocksonly_no_serve(tip_hash)

        self.log.info("D2: blocksonly override")
        self.test_blocksonly_override(tip_hash)

        self.log.info("D3: mwebserve=0")
        self.test_mwebserve_off(tip_hash)

        self.log.info("D4: force serve at upload limit")
        self.test_force_serve_at_limit(tip_hash)

        self.log.info("C7: download bypass")
        self.test_download_bypass(tip_hash)

        self.log.info("C6: upload limit disconnect")
        self.test_upload_limit_disconnect(tip_hash)

        self.log.info("D5: partial UTXO")
        self.test_partial_utxo(tip_hash)

        self.log.info("D6: service bit / force")
        self.test_service_bit_refresh(tip_hash)

        self.log.info("C8: CPU credit exhaustion")
        self.test_cpu_credit_exhaustion(tip_hash)

        self.log.info("C5: inactive chain hash")
        self.test_inactive_chain_ignore(tip_hash)

        self.log.info("C6b: upload abuse peer")
        self.test_upload_abuse_peer(tip_hash)

        self.log.info("F2: leafset upload disconnect")
        self.test_leafset_upload_disconnect(tip_hash)

        self.log.info("C9: IBD silent ignore")
        self.test_ibd_silent_ignore()

        self.log.info("T-11: credit disconnect")
        self.test_credit_disconnect(tip_hash)

        self.log.info("New connections have a fresh credit bucket")
        self.test_fresh_peer_after_credit_deny(tip_hash)

        self.log.info("T-12: header queued")
        self.test_header_queued(tip_hash)

        self.log.info("=== MWEB P2P rate limit: ALL PASSED ===")


if __name__ == '__main__':
    MWEBP2PRateLimitTest(__file__).main()
