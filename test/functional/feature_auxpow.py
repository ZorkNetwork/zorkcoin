#!/usr/bin/env python3
# Copyright (c) 2026 The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Kaspa AuxPoW acceptance on regtest."""

from test_framework.auxpow import (
    build_solo_auxpow_for_block,
    build_two_leaf_auxpow_for_block,
    get_expected_index,
    kaspa_hash_from_u64,
    make_auxpow_nonce,
    make_auxpow_version,
    serialize_auxpow,
    serialize_block_with_auxpow,
    serialize_kaspa_header_wire,
    write_kaspa_coinbase_tx,
    REGTEST_AUXPOW_CHAIN_ID,
)
from test_framework.blocktools import create_block, create_coinbase, NORMAL_GBT_REQUEST_PARAMS
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    HeaderAndShortIDs,
    deser_compact_size,
    msg_cmpctblock,
    msg_headers,
    ser_compact_size,
)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

from io import BytesIO


class AuxPoWTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1)

        # Native block still works
        tip_before = node.getbestblockhash()
        self.generate(node, 1)
        assert_equal(node.getblockcount(), 2)
        assert tip_before != node.getbestblockhash()

        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        coinbase = create_coinbase(height=tmpl["height"])
        block = CBlock()
        block.nVersion = make_auxpow_version()
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = tmpl["curtime"]
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = make_auxpow_nonce()
        block.vtx = [coinbase]
        block.hashMerkleRoot = block.calc_merkle_root()

        aux = build_solo_auxpow_for_block(block)
        block.auxpow = aux
        assert len(CBlockHeader(block).serialize()) > 88
        res = node.submitblock(block.serialize().hex())
        assert_equal(res, None)
        assert_equal(node.getblockcount(), 3)

        tip = node.getblock(node.getbestblockhash())
        assert tip["version"] & 0x100

        # Flag set without AuxPoW header extension must fail deserialize / reject
        bad = CBlock()
        bad.nVersion = make_auxpow_version()
        bad.hashPrevBlock = int(node.getbestblockhash(), 16)
        bad.nTime = tip["time"] + 1
        bad.nBits = int(tmpl["bits"], 16)
        bad.nNonce = make_auxpow_nonce()
        bad.vtx = [create_coinbase(height=tmpl["height"] + 1)]
        bad.hashMerkleRoot = bad.calc_merkle_root()
        # Serialize as if native (no AuxPoW header extension) despite AuxPoW bit
        assert_raises_rpc_error(-22, None, node.submitblock, bad.serialize().hex())

        self.test_header_and_compact_block()
        self.test_malformed_auxpow_p2p()
        self.test_two_leaf_auxpow()
        self.test_auxpow_nonce()
        self.test_p2p_auxpow_mutations()
        self.test_first_seen_headers_mismatch()
        self.test_three_way_same_height()

    def _submit(self, raw_hex):
        res = self.nodes[0].submitblock(raw_hex)
        # Valid side-chain blocks may return 'inconclusive' rather than null.
        assert res in (None, "inconclusive"), res

    def _native_block(self, prev_hash, height, ntime, label):
        block = create_block(
            hashprev=int(prev_hash, 16),
            coinbase=create_coinbase(height=height, extra_output_script=CScript([OP_RETURN, label])),
            ntime=ntime,
        )
        block.solve()
        return block

    def _aux_block(self, prev_hash, height, ntime, label, extra_parents=0, nonce=None):
        block = create_block(
            hashprev=int(prev_hash, 16),
            coinbase=create_coinbase(height=height, extra_output_script=CScript([OP_RETURN, label])),
            ntime=ntime,
            version=make_auxpow_version(),
        )
        block.nNonce = make_auxpow_nonce() if nonce is None else nonce
        aux = build_solo_auxpow_for_block(block, extra_parents=extra_parents)
        return block, aux

    def test_header_and_compact_block(self):
        """Bit-8 headers carry CAuxPow; compact blocks must not drop it."""
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        parent = node.getbestblockhash()
        height = node.getblockcount() + 1
        t = node.getblock(parent)["time"]

        # Grind both proofs before announcing anything: the node requests the
        # announced block and would drop this peer if it stalled grinding.
        hdr_block, hdr_aux = self._aux_block(parent, height, t + 100, b"hdr")
        hdr_block.auxpow = hdr_aux
        cmpct_block, cmpct_aux = self._aux_block(parent, height, t + 200, b"cmp")
        cmpct_block.auxpow = cmpct_aux

        header = CBlockHeader(hdr_block)
        assert len(header.serialize()) > 88
        assert len(header._serialize_header()) == 88
        peer.send_and_ping(msg_headers([header]))
        indexed = node.getblockheader(hdr_block.hash)
        assert_equal(indexed["confirmations"], -1)
        peer.wait_for_getdata([hdr_block.sha256])

        cmpct = HeaderAndShortIDs()
        cmpct.initialize_from_block(cmpct_block, use_witness=True)
        assert len(cmpct.header.serialize()) > 88
        peer.send_and_ping(msg_cmpctblock(cmpct.to_p2p()))
        assert_equal(node.getbestblockhash(), cmpct_block.hash)
        peer.peer_disconnect()

    def test_malformed_auxpow_p2p(self):
        """Bit-8 headers without CAuxPow must not be indexed and must not kill the node."""
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        parent = node.getbestblockhash()
        height = node.getblockcount() + 1
        t = node.getblock(parent)["time"]
        bad, _ = self._aux_block(parent, height, t + 50, b"bad")
        bad.auxpow = None
        header = CBlockHeader(bad)
        assert_equal(len(header.serialize()), 88)
        peer.send_and_ping(msg_headers([header]))
        assert_raises_rpc_error(-5, None, node.getblockheader, bad.hash)
        peer.peer_disconnect()

    def _aux_template_block(self, label, nonce=None):
        node = self.nodes[0]
        parent = node.getbestblockhash()
        height = node.getblockcount() + 1
        t = node.getblock(parent)["time"]
        return self._aux_block(parent, height, t + 50, label, nonce=nonce)

    def test_auxpow_nonce(self):
        """nNonce is locked to the "AuxPoW" marker plus the chain ID."""
        node = self.nodes[0]
        tip = node.getbestblockhash()
        assert node.getblockheader(tip)["version"] & 0x100
        assert_equal(node.getblockheader(tip)["nonce"], make_auxpow_nonce())
        assert_equal(bytes.fromhex(node.getblockheader(tip, False))[80:88], b"ZRAuxPoW")

        wrong_nonces = {
            b"nmk": make_auxpow_nonce() ^ (1 << 40),
            b"nid": make_auxpow_nonce(int.from_bytes(b"ZK", "little")),
            b"nz": 0,
        }
        for label, nonce in wrong_nonces.items():
            # The proof commits to the header with this nonce, so only the nonce is wrong.
            block, aux = self._aux_template_block(label, nonce=nonce)
            block.auxpow = aux
            assert_equal(node.submitblock(block.serialize().hex()), "bad-auxpow")
            assert_equal(node.getbestblockhash(), tip)

    def test_two_leaf_auxpow(self):
        """Valid 2-leaf aux-chain; wrong LCG index is rejected."""
        node = self.nodes[0]
        block, _ = self._aux_template_block(b"2lf")
        aux = build_two_leaf_auxpow_for_block(block, merkle_nonce=7)
        block.auxpow = aux
        self._submit(block.serialize().hex())
        assert_equal(node.getbestblockhash(), block.hash)

        bad_block, _ = self._aux_template_block(b"2bad")
        expected = get_expected_index(7, REGTEST_AUXPOW_CHAIN_ID, 1)
        bad_aux = build_two_leaf_auxpow_for_block(
            bad_block, merkle_nonce=7, n_chain_index=1 - expected
        )
        bad_block.auxpow = bad_aux
        res = node.submitblock(bad_block.serialize().hex())
        assert res not in (None, "inconclusive"), res
        assert_raises_rpc_error(-5, None, node.getblock, bad_block.hash)

    def _send_raw_headers(self, peer, payload):
        class RawHeaders:
            msgtype = b"headers"

            def serialize(self_inner):
                return payload

        try:
            peer.send_and_ping(RawHeaders())
        except Exception:
            pass
        # Node must stay up even if the peer is dropped for a malformed message.
        self.nodes[0].getblockcount()

    def _headers_payload(self, hashed_88, auxpow_bytes):
        return ser_compact_size(1) + hashed_88 + auxpow_bytes

    def test_p2p_auxpow_mutations(self):
        """Truncated / oversize / parseable-invalid AuxPoW must not be indexed."""
        node = self.nodes[0]
        block, aux = self._aux_template_block(b"mut")
        hashed = CBlockHeader(block)._serialize_header()
        assert block.nVersion & 0x100

        peer = node.add_p2p_connection(P2PInterface())

        # Truncated CAuxPow after bit 8.
        self._send_raw_headers(peer, self._headers_payload(hashed, aux[:8]))
        assert_raises_rpc_error(-5, None, node.getblockheader, block.hash)

        # CompactSize over each component cap, plus total 1280.
        f = BytesIO(aux)
        version = f.read(4)
        hdr_len = deser_compact_size(f)
        hdr = f.read(hdr_len)
        tx_len = deser_compact_size(f)
        tx = f.read(tx_len)

        oversize = {
            "peer": version + ser_compact_size(721),
            "coinbase": version + ser_compact_size(hdr_len) + hdr + ser_compact_size(401),
            "tx_merkle": version + ser_compact_size(hdr_len) + hdr + ser_compact_size(tx_len) + tx + ser_compact_size(9),
            "chain_merkle": version
            + ser_compact_size(hdr_len)
            + hdr
            + ser_compact_size(tx_len)
            + tx
            + ser_compact_size(0)
            + ser_compact_size(6),
        }
        for blob in oversize.values():
            self._send_raw_headers(peer, self._headers_payload(hashed, blob))
            assert_raises_rpc_error(-5, None, node.getblockheader, block.hash)

        fat_parents = [kaspa_hash_from_u64(1)] + [kaspa_hash_from_u64(200 + i) for i in range(14)]
        fat_peer = serialize_kaspa_header_wire(
            hash_merkle_root=kaspa_hash_from_u64(2),
            timestamp=1,
            bits=0x207FFFFF,
            nonce=0,
            parents=fat_parents,
        )
        fat_cb = write_kaspa_coinbase_tx(payload=b"\xab" * 300)
        fat_aux = serialize_auxpow(
            peer_header=fat_peer,
            coinbase_tx=fat_cb,
            tx_merkle_branch=[b"\x11" * 32] * 8,
            chain_merkle_branch=[b"\x22" * 32] * 5,
        )
        assert len(fat_aux) > 1280
        self._send_raw_headers(peer, self._headers_payload(hashed, fat_aux))
        assert_raises_rpc_error(-5, None, node.getblockheader, block.hash)

        # Parseable CAuxPow that fails CheckAuxPow (no merged-mining record).
        peer_header = serialize_kaspa_header_wire(
            hash_merkle_root=kaspa_hash_from_u64(2),
            timestamp=1_700_000_000_000,
            bits=0x207FFFFF,
            nonce=0,
        )
        invalid = serialize_auxpow(
            peer_header=peer_header,
            coinbase_tx=write_kaspa_coinbase_tx(payload=b"\x00" * 19),
        )
        self._send_raw_headers(peer, self._headers_payload(hashed, invalid))
        assert_raises_rpc_error(-5, None, node.getblockheader, block.hash)
        if peer.is_connected:
            peer.peer_disconnect()

    def test_first_seen_headers_mismatch(self):
        """First verified CAuxPow is pinned; a different proof for the same 88-byte hash is rejected."""
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        block, lean_aux = self._aux_template_block(b"pin")
        fat_aux = build_solo_auxpow_for_block(block, extra_parents=2)
        assert lean_aux != fat_aux
        block.auxpow = lean_aux
        header = CBlockHeader(block)
        peer.send_and_ping(msg_headers([header]))
        indexed = node.getblockheader(block.hash)
        assert_equal(indexed["confirmations"], -1)

        mismatch = CBlockHeader(block)
        mismatch.auxpow = fat_aux
        try:
            peer.send_and_ping(msg_headers([mismatch]))
        except Exception:
            pass
        still = node.getblockheader(block.hash)
        assert_equal(still["confirmations"], -1)
        node.getblockcount()
        if peer.is_connected:
            peer.peer_disconnect()

    def test_three_way_same_height(self):
        """Native vs min-size AuxPoW vs large-header AuxPoW at the same height."""
        node = self.nodes[0]
        parent = node.getbestblockhash()
        height = node.getblockcount() + 1
        t = node.getblock(parent)["time"]

        fat_block, fat_aux = self._aux_block(parent, height, t + 1000, b"fat", extra_parents=12)
        lean_block, lean_aux = self._aux_block(parent, height, t + 2000, b"lean", extra_parents=0)
        native = self._native_block(parent, height, t + 3000, b"nat")

        fat_raw = serialize_block_with_auxpow(fat_block, fat_aux)
        lean_raw = serialize_block_with_auxpow(lean_block, lean_aux)
        assert len(lean_raw) < len(fat_raw)
        # AuxPoW header extension is after the 88-byte hashed fields; fat parent list must enlarge it.
        assert len(fat_aux) > len(lean_aux) + 300

        self._submit(fat_raw.hex())
        assert_equal(node.getbestblockhash(), fat_block.hash)
        self._submit(lean_raw.hex())
        # Regtest native work is 2 and AuxPoW of any allowed size discounts to 1,
        # so lean does not replace fat. Native still wins.
        assert_equal(node.getbestblockhash(), fat_block.hash)
        self._submit(native.serialize().hex())
        assert_equal(node.getbestblockhash(), native.hash)

        fat_hash, lean_hash, native_hash = fat_block.hash, lean_block.hash, native.hash
        assert_equal(node.getblock(fat_hash)["height"], height)
        assert_equal(node.getblock(lean_hash)["height"], height)
        assert_equal(node.getblock(native_hash)["height"], height)

        # Native child on each fork. Extend the current best first so one extra
        # native block on a weaker fork cannot reorg yet (W_aux + W_n < 2*W_n).
        native_child = self._native_block(native_hash, height + 1, t + 4000, b"natc")
        lean_child = self._native_block(lean_hash, height + 1, t + 5000, b"leanc")
        fat_child = self._native_block(fat_hash, height + 1, t + 6000, b"fatc")
        self._submit(native_child.serialize().hex())
        assert_equal(node.getbestblockhash(), native_child.hash)
        self._submit(lean_child.serialize().hex())
        assert_equal(node.getbestblockhash(), native_child.hash)
        self._submit(fat_child.serialize().hex())
        assert_equal(node.getbestblockhash(), native_child.hash)

        # A further native block only on the fat (losing) fork has more work, so it is used.
        fat_gc = self._native_block(fat_child.hash, height + 2, t + 7000, b"fatgc")
        self._submit(fat_gc.serialize().hex())
        assert_equal(node.getbestblockhash(), fat_gc.hash)

        # Side branches remain available; they are not discarded.
        node.getblock(native_child.hash)
        node.getblock(lean_child.hash)
        tips = {t["hash"]: t["status"] for t in node.getchaintips()}
        assert_equal(tips[fat_gc.hash], "active")
        assert tips[native_child.hash] in ("valid-fork", "valid-headers")
        assert tips[lean_child.hash] in ("valid-fork", "valid-headers")


if __name__ == "__main__":
    AuxPoWTest(__file__).main()
