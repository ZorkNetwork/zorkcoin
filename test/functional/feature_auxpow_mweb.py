#!/usr/bin/env python3
# Copyright (c) 2026 The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/license/mit-license.php.
"""AuxPoW + MWEB composition after versionbits activation.

Pre-MWEB AuxPoW coverage stays in feature_auxpow.py (MWEB NEVER_ACTIVE).
This file turns MWEB on and submits bit-8 + CAuxPow + HogEx + mweb_block.
"""

from test_framework.auxpow import build_solo_auxpow_for_block, make_auxpow_nonce, make_auxpow_version
from test_framework.blocktools import add_witness_commitment, create_coinbase, NORMAL_GBT_REQUEST_PARAMS
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    CTransaction,
    FromHex,
    HeaderAndShortIDs,
    MWEBBlock,
    msg_cmpctblock,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    MWEB_GBT_REQUEST_PARAMS,
    assert_exact_mweb_inputs,
    decode_wallet_tx,
    get_hogex_tx,
    init_mweb_wallet,
    mweb_extra_args,
    pegout_payments,
    setup_mweb_chain,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES_MWEB
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AuxPoWMWEBTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args([], [])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def run_test(self):
        setup_mweb_chain(self.nodes[0], test=self)
        assert_equal(self.nodes[0].getblockcount(), FIRST_MWEB_HEIGHT)
        self.sync_all()

        self.test_auxpow_without_hogex_rejected()
        self.test_submit_auxpow_hogex_mweb()
        self.test_compact_v3_and_headers()
        self.test_two_node_sync()
        self.test_native_hogex_still_works()
        self.test_mixed_content_auxpow_block()
        self.test_native_auxpow_mweb_reorg()

    def _build_auxpow_mweb_block(self, node):
        """Copy the node's GBT HogEx + MWEB body; attach AuxPoW on a local header."""
        gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        assert "mweb" in gbt
        mweb_block = FromHex(MWEBBlock(), gbt["mweb"])
        template_txs = []
        for entry in gbt["transactions"]:
            tx = FromHex(CTransaction(), entry["data"])
            tx.rehash()
            template_txs.append(tx)
        hogex_tx = next(tx for tx in template_txs if tx.hogex)
        others = [tx for tx in template_txs if not tx.hogex]

        block = CBlock()
        block.nVersion = make_auxpow_version(gbt["version"])
        assert block.nVersion & 0x100
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = make_auxpow_nonce()
        block.vtx = [create_coinbase(height=int(gbt["height"]))] + others + [hogex_tx]
        block.mweb_block = mweb_block
        add_witness_commitment(block)
        block.auxpow = build_solo_auxpow_for_block(block)
        assert block.vtx[-1].hogex
        assert block.vtx[-1].mweb_tx is None  # HogEx tx flag 8 is not nVersion AuxPoW bit 8
        return block

    def test_auxpow_without_hogex_rejected(self):
        """AuxPoW-valid coinbase-only block still fails MWEB contextual checks."""
        node = self.nodes[0]
        gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        block = CBlock()
        block.nVersion = make_auxpow_version(gbt["version"])
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = make_auxpow_nonce()
        block.vtx = [create_coinbase(height=gbt["height"])]
        block.hashMerkleRoot = block.calc_merkle_root()
        block.auxpow = build_solo_auxpow_for_block(block)
        res = node.submitblock(block.serialize().hex())
        assert res not in (None, "inconclusive"), res
        assert_equal(node.getblockcount(), FIRST_MWEB_HEIGHT)

    def test_submit_auxpow_hogex_mweb(self):
        node = self.nodes[0]
        self.disconnect_nodes(0, 1)
        block = self._build_auxpow_mweb_block(node)
        assert len(CBlockHeader(block).serialize()) > 88
        res = node.submitblock(block.serialize().hex())
        assert_equal(res, None)
        tip = node.getblock(node.getbestblockhash())
        assert tip["version"] & 0x100
        hogex = get_hogex_tx(node)
        assert_equal(tip["tx"][-1], hogex.hash)
        self._aux_tip = block.hash

    def test_compact_v3_and_headers(self):
        node = self.nodes[0]
        block = self._build_auxpow_mweb_block(node)
        header = CBlockHeader(block)
        assert len(header.serialize()) > 88
        assert block.mweb_block is not None

        peer = node.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB)
        peer.send_and_ping(msg_sendcmpct(announce=True, version=3))
        peer.send_and_ping(msg_headers([header]))
        indexed = node.getblockheader(block.hash)
        assert_equal(indexed["confirmations"], -1)

        cmpct = HeaderAndShortIDs()
        cmpct.initialize_from_block(block, use_witness=True, version=3, prefill_list=list(range(len(block.vtx))))
        assert len(cmpct.header.serialize()) > 88
        assert cmpct.mweb_block is not None
        peer.send_and_ping(msg_cmpctblock(cmpct.to_p2p()))
        assert_equal(node.getbestblockhash(), block.hash)
        peer.peer_disconnect()

    def test_two_node_sync(self):
        """Node 1 was disconnected before the AuxPoW+MWEB blocks; it must catch up."""
        self.connect_nodes(0, 1)
        self.sync_all()
        tip = self.nodes[0].getbestblockhash()
        assert_equal(self.nodes[1].getbestblockhash(), tip)
        blk = self.nodes[1].getblock(tip)
        assert blk["version"] & 0x100
        self.nodes[1].getblock(self._aux_tip)

    def test_native_hogex_still_works(self):
        node = self.nodes[0]
        native = self.generate(node, 1)[0]
        self.sync_all()
        tip = node.getblock(native)
        assert_equal(tip["version"] & 0x100, 0)
        hogex = get_hogex_tx(node, native)
        assert_equal(tip["tx"][-1], hogex.hash)
        assert_equal(self.nodes[1].getbestblockhash(), native)

    def _send_from(self, node, dest, amount, inputs):
        res = node.send(outputs={dest: amount}, options={"inputs": inputs, "add_inputs": False})
        assert_equal(res["complete"], True)
        return res["txid"]

    def test_mixed_content_auxpow_block(self):
        """One AuxPoW block carrying SegWit, Taproot, peg-in, peg-out and MWEB-to-MWEB spends."""
        node0, node1 = self.nodes
        # Node 1's wallet holds only these coins, so each spend below uses exactly its pinned input.
        assert_equal(node1.listunspent(0), [])
        segwit_addr = node1.getnewaddress(address_type="bech32")
        taproot_addr = node1.getnewaddress(address_type="bech32m")
        assert_equal(node1.getaddressinfo(taproot_addr)["witness_version"], 1)
        pegin_src_addr = node1.getnewaddress(address_type="bech32")
        funding = {
            "segwit": node0.sendtoaddress(segwit_addr, 10),
            "taproot": node0.sendtoaddress(taproot_addr, 10),
            "pegin": node0.sendtoaddress(pegin_src_addr, 10),
        }
        node0.sendtoaddress(node1.getnewaddress(address_type="mweb"), 7)
        node0.sendtoaddress(node1.getnewaddress(address_type="mweb"), 8)
        self.generate(node0, 1)

        def l1_input(txid, address):
            utxo = next(u for u in node1.listunspent(1) if u.get("address") == address)
            assert_equal(utxo["txid"], txid)
            return {"txid": txid, "vout": utxo["vout"]}

        def mweb_coin(amount):
            return next(u["output_id"] for u in node1.listunspent(1)
                        if u.get("output_id") and u["amount"] == amount)

        oid_a, oid_b = mweb_coin(7), mweb_coin(8)
        spends = {
            "segwit": self._send_from(node1, node0.getnewaddress(address_type="bech32"), 3,
                                      [l1_input(funding["segwit"], segwit_addr)]),
            "taproot": self._send_from(node1, node0.getnewaddress(address_type="bech32"), 3,
                                       [l1_input(funding["taproot"], taproot_addr)]),
            "pegin": self._send_from(node1, node0.getnewaddress(address_type="mweb"), 4,
                                     [l1_input(funding["pegin"], pegin_src_addr)]),
            "pegout": self._send_from(node1, node0.getnewaddress(address_type="bech32"), 2,
                                      [{"mweb_out": oid_a}]),
            "mweb": self._send_from(node1, node0.getnewaddress(address_type="mweb"), 2,
                                    [{"mweb_out": oid_b}]),
        }
        segwit_wit = node1.getrawtransaction(spends["segwit"], True)["vin"][0]["txinwitness"]
        assert_equal([len(w) for w in segwit_wit], [len(segwit_wit[0]), 66])
        taproot_wit = node1.getrawtransaction(spends["taproot"], True)["vin"][0]["txinwitness"]
        assert_equal([len(w) for w in taproot_wit], [128])  # key-path Schnorr signature
        assert_exact_mweb_inputs(decode_wallet_tx(node1, spends["pegout"]), {oid_a})
        assert pegout_payments(decode_wallet_tx(node1, spends["pegout"]))
        assert_exact_mweb_inputs(decode_wallet_tx(node1, spends["mweb"]), {oid_b})
        self.sync_mempools()
        assert_equal(set(spends.values()) - set(node0.getrawmempool()), set())

        block = self._build_auxpow_mweb_block(node0)
        vtx_ids = {tx.hash for tx in block.vtx}
        for kind in ("segwit", "taproot", "pegin"):
            assert spends[kind] in vtx_ids, kind

        # Node 1 rebuilds the block from its mempool; only coinbase and HogEx are prefilled.
        self.disconnect_nodes(0, 1)
        peer = node1.add_p2p_connection(P2PInterface(), services=P2P_SERVICES_MWEB)
        peer.send_and_ping(msg_sendcmpct(announce=True, version=3))
        peer.send_and_ping(msg_headers([CBlockHeader(block)]))
        cmpct = HeaderAndShortIDs()
        cmpct.initialize_from_block(block, use_witness=True, version=3, prefill_list=[0, len(block.vtx) - 1])
        assert len(cmpct.header.serialize()) > 88
        peer.send_and_ping(msg_cmpctblock(cmpct.to_p2p()))
        assert "getblocktxn" not in peer.last_message
        assert_equal(node1.getbestblockhash(), block.hash)
        peer.peer_disconnect()

        assert_equal(node0.submitblock(block.serialize().hex()), None)
        self.connect_nodes(0, 1)
        self.sync_all()
        for kind, txid in spends.items():
            assert_equal((kind, node1.gettransaction(txid)["blockhash"]), (kind, block.hash))
        assert node1.getblock(block.hash)["version"] & 0x100

    def test_native_auxpow_mweb_reorg(self):
        """Reorg between a native+MWEB block and an AuxPoW+MWEB block at the same height."""
        node0, node1 = self.nodes
        parent = node0.getbestblockhash()
        mweb_tx = node0.sendtoaddress(node0.getnewaddress(address_type="mweb"), 3)
        self.sync_mempools()

        aux_block = self._build_auxpow_mweb_block(node0)
        assert_equal(node0.submitblock(aux_block.serialize().hex()), None)
        assert_equal(node0.getbestblockhash(), aux_block.hash)
        assert_equal(node0.gettransaction(mweb_tx)["blockhash"], aux_block.hash)

        node0.invalidateblock(aux_block.hash)
        assert_equal(node0.getbestblockhash(), parent)
        self.wait_until(lambda: mweb_tx in node0.getrawmempool())
        native = self.generate(node0, 1)[0]
        assert_equal(node0.getblock(native)["version"] & 0x100, 0)
        assert_equal(node0.gettransaction(mweb_tx)["blockhash"], native)
        assert_equal(node0.getblock(native)["height"], node0.getblock(parent)["height"] + 1)

        # Equal height: the native block keeps the tip once the AuxPoW block is valid again.
        node0.reconsiderblock(aux_block.hash)
        assert_equal(node0.getbestblockhash(), native)

        self.log.info("Reorg native+MWEB -> AuxPoW+MWEB")
        node0.invalidateblock(native)
        assert_equal(node0.getbestblockhash(), aux_block.hash)
        assert_equal(node0.gettransaction(mweb_tx)["blockhash"], aux_block.hash)
        get_hogex_tx(node0, aux_block.hash)
        assert node0.verifychain(4, 3)

        self.log.info("Reorg AuxPoW+MWEB -> native+MWEB")
        node0.reconsiderblock(native)
        assert_equal(node0.getbestblockhash(), native)
        assert_equal(node0.gettransaction(mweb_tx)["blockhash"], native)
        assert node0.verifychain(4, 3)

        tip = self.generate(node0, 1)[0]
        assert_equal(node1.getbestblockhash(), tip)


if __name__ == "__main__":
    AuxPoWMWEBTest(__file__).main()
