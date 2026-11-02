#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Ensure rejected MWEB variants do not censor valid same-wtxid transactions.

Canonical txid/wtxid exclude the MWEB payload and HogEx marker. Pure MWEB
transactions use their first kernel's ID, which does not commit to the rest
of the body. Caching a rejection by those IDs could let an invalid variant
suppress an honest transaction with the same IDs.
"""

from test_framework.messages import (
    CInv,
    CTransaction,
    FromHex,
    Hash,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.mweb_util import (
    init_mweb_wallet,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class TxPeer(P2PInterface):
    def __init__(self, serve_tx, wtxid):
        super().__init__()
        self.serve_tx = serve_tx
        self.request = (MSG_WTX, wtxid)
        self.getdata_requests = []
        self.served_requests = []

    def on_getdata(self, message):
        for inv in message.inv:
            request = (inv.type, inv.hash)
            self.getdata_requests.append(request)
            if request == self.request:
                self.send_without_ping(msg_tx(self.serve_tx))
                self.served_requests.append(request)


class MWEBWtxidRecentRejectsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1', '-walletbroadcast=0'],
            ['-whitelist=noban@127.0.0.1', '-walletbroadcast=0'],
        )

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_invalid_variants_do_not_censor(self, node, invalid_variants, honest_tx,
                                            wtxid, txid):
        before = set(node.getrawmempool())
        assert txid not in before
        request = (MSG_WTX, wtxid)
        for invalid_tx, reject_reason in invalid_variants:
            attacker = node.add_p2p_connection(TxPeer(invalid_tx, wtxid), services=P2P_SERVICES_MWEB)
            with node.assert_debug_log(expected_msgs=[reject_reason], timeout=20):
                attacker.send_without_ping(msg_inv([CInv(MSG_WTX, wtxid)]))
                attacker.wait_until(lambda: attacker.served_requests == [request], timeout=30)
                attacker.sync_with_ping()
            with p2p_lock:
                assert_equal(attacker.getdata_requests, [request])
                assert_equal(attacker.served_requests, [request])
            assert_equal(set(node.getrawmempool()), before)
            attacker.peer_disconnect()
            attacker.wait_for_disconnect()

        # Only this fresh peer supplies the honest body, after an exact request.
        honest = node.add_p2p_connection(TxPeer(honest_tx, wtxid), services=P2P_SERVICES_MWEB)
        honest.send_without_ping(msg_inv([CInv(MSG_WTX, wtxid)]))
        honest.wait_until(lambda: honest.served_requests == [request], timeout=30)
        honest.sync_with_ping()
        self.wait_until(lambda: txid in node.getrawmempool(), timeout=30)
        with p2p_lock:
            assert_equal(honest.getdata_requests, [request])
            assert_equal(honest.served_requests, [request])
        assert_equal(set(node.getrawmempool()), before | {txid})
        assert_equal(node.getrawtransaction(txid), honest_tx.serialize().hex())
        honest.peer_disconnect()
        honest.wait_for_disconnect()

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("Set up MWEB and fund isolated MWEB and base-coin wallets")
        setup_mweb_chain(node0, self)
        self.sync_all()
        node0.sendtoaddress(node1.getnewaddress(address_type='mweb'), 0.9)
        node0.sendtoaddress(node2.getnewaddress(), 1.0)
        node0.sendtoaddress(node2.getnewaddress(), 2.0)
        self.generate(node0, 1)

        self.log.info("Create an honest MWEB-only transaction without broadcasting it")
        txid = node1.sendtoaddress(node0.getnewaddress(address_type='mweb'), 0.3)
        tx_hex = node1.gettransaction(txid=txid)['hex']
        honest_tx = FromHex(CTransaction(), tx_hex)
        assert honest_tx.mweb_tx is not None
        assert len(honest_tx.vin) == 0 and len(honest_tx.vout) == 0

        # Native pure-MWEB txid/wtxid use the first kernel, unlike the Python
        # CTransaction helper's canonical-only hash. Changing only the offset
        # leaves that kernel intact but invalidates the balance equation.
        mutated_tx = FromHex(CTransaction(), tx_hex)
        mutated_tx.mweb_tx.kernel_offset = Hash(mutated_tx.mweb_tx.kernel_offset.val ^ 1)
        assert mutated_tx.serialize() != honest_tx.serialize()
        wtxid = int.from_bytes(honest_tx.mweb_tx.body.kernels[0].hash.to_byte_arr(), 'little')
        assert_equal(wtxid, int(txid, 16))
        assert_equal(mutated_tx.mweb_tx.body.kernels[0].serialize(), honest_tx.mweb_tx.body.kernels[0].serialize())

        self.log.info("An invalid MWEB body must not censor its honest same-wtxid body")
        self.assert_invalid_variants_do_not_censor(
            node0, [(mutated_tx, "bad-mweb-txn")], honest_tx, wtxid, txid)

        self.log.info("Create independent ordinary and pegin transactions")
        ordinary_txid = node2.sendtoaddress(node0.getnewaddress(), 0.2)
        ordinary_hex = node2.gettransaction(txid=ordinary_txid)['hex']
        ordinary_tx = FromHex(CTransaction(), ordinary_hex)
        assert ordinary_tx.mweb_tx is None

        pegin_txid = node2.sendtoaddress(node0.getnewaddress(address_type='mweb'), 0.4)
        pegin_hex = node2.gettransaction(txid=pegin_txid)['hex']
        pegin_tx = FromHex(CTransaction(), pegin_hex)
        assert pegin_tx.mweb_tx is not None
        assert len(pegin_tx.vin) > 0 and len(pegin_tx.vout) > 0

        # A pegin whose MWEB body was stripped has the same txid/wtxid as the
        # honest pegin. It must still be recognized as an MWEB relay variant.
        stripped_pegin = FromHex(CTransaction(), pegin_hex)
        stripped_pegin.mweb_tx = None
        assert stripped_pegin.serialize() != pegin_tx.serialize()
        pegin_wtxid = pegin_tx.calc_sha256(with_witness=True)
        assert pegin_wtxid == stripped_pegin.calc_sha256(with_witness=True)
        assert_equal(stripped_pegin.calc_sha256(), int(pegin_txid, 16))

        bad_signature = FromHex(CTransaction(), pegin_hex)
        bad_signature.mweb_tx.body.outputs[0].signature ^= 1
        bad_signature.mweb_tx.body.outputs[0].rehash()
        # Preserve structure ordering so the attached variant reaches crypto
        # verification with unchanged canonical bytes and kernel identifiers.
        bad_signature.mweb_tx.body.outputs.sort(key=lambda output: output.hash.to_byte_arr())
        assert bad_signature.serialize() != pegin_tx.serialize()
        assert_equal(bad_signature.serialize_with_witness(), pegin_tx.serialize_with_witness())
        assert_equal(bad_signature.calc_sha256(), int(pegin_txid, 16))
        assert_equal(bad_signature.calc_sha256(with_witness=True), pegin_wtxid)

        self.log.info("Stripped and bad-signature pegin variants must not censor the honest pegin")
        self.assert_invalid_variants_do_not_censor(
            node0,
            [(stripped_pegin, "pegin-count-mismatch"), (bad_signature, "bad-mweb-txn")],
            pegin_tx, pegin_wtxid, pegin_txid)

        # The HogEx marker is also excluded from txid/wtxid. Injecting it into
        # an ordinary transaction must not poison that transaction's IDs.
        marked_tx = FromHex(CTransaction(), ordinary_hex)
        marked_tx.hogex = True
        assert marked_tx.serialize() != ordinary_tx.serialize()
        ordinary_wtxid = ordinary_tx.calc_sha256(with_witness=True)
        assert ordinary_wtxid == marked_tx.calc_sha256(with_witness=True)

        self.log.info("An injected HogEx marker must not censor the honest transaction")
        self.assert_invalid_variants_do_not_censor(
            node0, [(marked_tx, "hogex")], ordinary_tx, ordinary_wtxid, ordinary_txid)


if __name__ == '__main__':
    MWEBWtxidRecentRejectsTest(__file__).main()
