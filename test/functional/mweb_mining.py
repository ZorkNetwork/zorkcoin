#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs for MWEB blocks"""

from decimal import Decimal

from test_framework.blocktools import create_coinbase
from test_framework.messages import (CBlock, MWEBBlock, from_hex, tx_from_hex)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    MWEB_GBT_REQUEST_PARAMS,
    create_hogex,
    generatetoaddress,
    get_hogex_tx,
    get_mweb_header,
    init_mweb_wallet,
    reconnect_mweb_peers,
    with_mweb_vbparams,
)

class MWEBMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [with_mweb_vbparams([])] * 3
        self.setup_clean_chain = True
        self.supports_cli = False

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("getblocktemplate: mweb rule is required before activation")
        assert_raises_rpc_error(
            -8,
            "getblocktemplate must be called with the segwit & mweb rule sets",
            node.getblocktemplate,
            {'rules': ['segwit']},
        )

        self.log.info("Mine first MWEB block")
        self.generate(node, FIRST_MWEB_HEIGHT - 1)
        reconnect_mweb_peers(self)
        first_pegin_txid = node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)

        self.log.info("getblocktemplate: mweb rule is required for MWEB templates")
        assert_raises_rpc_error(
            -8,
            "getblocktemplate must be called with the segwit & mweb rule sets",
            node.getblocktemplate,
            {'rules': ['segwit']},
        )

        first_template = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        assert "mweb" in first_template
        assert "mweb" in first_template["rules"]

        first_mweb_block = self.generate(node, 1)[0]
        first_hogex = get_hogex_tx(node, first_mweb_block)
        assert_equal(len(first_hogex.vin), 1)
        assert_equal(first_hogex.vin[0].prevout.hash, int(first_pegin_txid, 16))
        self.sync_all()

        self.test_noncanonical_kernel_features_rejected(node)

        # Call getblocktemplate
        generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        next_height = int(gbt["height"])

        # Build MWEB block
        mweb_header = get_mweb_header(node)
        mweb_header.height = next_height
        mweb_header.rehash()
        mweb_block = MWEBBlock(mweb_header)

        # Build coinbase and HogEx txs
        coinbase_tx = create_coinbase(height=next_height)
        hogex_tx = create_hogex(node, mweb_header.hash)
        vtx = [coinbase_tx, hogex_tx]

        # Build block proposal
        block = CBlock()
        block.nVersion = gbt["version"]
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = 0
        block.vtx = vtx
        block.mweb_block = mweb_block
        block.hashMerkleRoot = block.calc_merkle_root()

        # Call getblocktemplate with the block proposal
        self.log.info("getblocktemplate: Test valid block")
        rsp = node.getblocktemplate(template_request={
            'data': block.serialize().hex(),
            'mode': 'proposal',
            'rules': ['mweb', 'segwit'],
        })
        assert_equal(rsp, None)

        self.test_generateblock(node)
        self.test_mining_to_mweb_refused(node)

        self.log.info("Mine many pegins in one block")
        self.mine_many_pegins()

        self.log.info("Mine many pegouts in one block")
        self.mine_many_pegouts()

        self.log.info("Mine after MWEB mempool spend becomes stale across a reorg")
        self.mine_after_stale_mweb_spend_reorg()

    def test_generateblock(self, node):
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        address = wallet.getnewaddress()

        self.log.info("generateblock: an empty block still gets its HogEx")
        empty_hash = self.generateblock(node, address, [])["hash"]
        empty_block = node.getblock(empty_hash)
        assert_equal(len(empty_block["tx"]), 2)
        assert_equal(empty_block["tx"][-1], get_hogex_tx(node, empty_hash).hash)

        self.log.info("generateblock: L1 transactions go before the HogEx")
        utxo = next(u for u in wallet.listunspent() if "vout" in u)
        raw_tx = wallet.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {wallet.getnewaddress(address_type="bech32"): utxo["amount"] - Decimal("0.001")},
        )
        l1_hex = wallet.signrawtransactionwithwallet(raw_tx)["hex"]
        l1_txid = node.decoderawtransaction(l1_hex)["txid"]
        l1_hash = self.generateblock(node, address, [l1_hex])["hash"]
        l1_block = node.getblock(l1_hash)
        assert_equal(l1_block["tx"][1:], [l1_txid, get_hogex_tx(node, l1_hash).hash])

        self.log.info("generateblock: transactions with MWEB data are refused")
        mweb_txid = wallet.sendtoaddress(wallet.getnewaddress(address_type="mweb"), 1)
        assert_raises_rpc_error(-8, "has MWEB data, which generateblock cannot include", self.generateblock, node, address, [mweb_txid])
        self.generate(node, 1)

    def test_mining_to_mweb_refused(self, node):
        self.log.info("Mining RPCs refuse MWEB addresses and descriptors")
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        mweb_address = wallet.getnewaddress(address_type="mweb")
        descriptors = [
            node.getdescriptorinfo(f"addr({mweb_address})")["descriptor"],
            wallet.getaddressinfo(mweb_address)["desc"],
            *[d["desc"] for d in wallet.listdescriptors()["descriptors"] if d["desc"].startswith("mweb(")],
        ]
        height = node.getblockcount()
        error = "Cannot mine to an MWEB address"
        assert_raises_rpc_error(-5, "Error: Invalid address", node.generatetoaddress, 1, mweb_address, called_by_framework=True)
        assert_raises_rpc_error(-5, error, node.generateblock, mweb_address, [], called_by_framework=True)
        for descriptor in descriptors:
            assert_raises_rpc_error(-5, error, node.generatetodescriptor, 1, descriptor, called_by_framework=True)
            assert_raises_rpc_error(-5, error, node.generateblock, descriptor, [], called_by_framework=True)
        assert_equal(node.getblockcount(), height)

    def test_noncanonical_kernel_features_rejected(self, node):
        self.log.info("Reject an uncommitted empty pegout feature as mutated")
        node.sendtoaddress(node.getnewaddress(address_type='mweb'), Decimal("0.1"))

        gbt = node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        mweb_block = from_hex(MWEBBlock(), gbt["mweb"])
        kernel = next(kernel for kernel in mweb_block.body.kernels if not kernel.features & 4)

        block = CBlock()
        block.nVersion = gbt["version"]
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(gbt["height"])), *[tx_from_hex(tx["data"]) for tx in gbt["transactions"]]]
        block.mweb_block = mweb_block
        block.hashMerkleRoot = block.calc_merkle_root()

        def propose():
            return node.getblocktemplate(template_request={
                'data': block.serialize().hex(),
                'mode': 'proposal',
                'rules': ['mweb', 'segwit'],
            })

        assert_equal(propose(), None)

        kernel.features |= 4
        kernel.pegouts = []
        kernel.rehash()
        assert_equal(propose(), 'bad-blk-mweb')

        self.log.info("Reject uncommitted empty extra data as mutated")
        kernel.features &= ~4
        kernel.pegouts = None
        kernel.features |= 32
        kernel.extradata = b""
        kernel.rehash()
        assert_equal(propose(), 'bad-blk-mweb')

        self.generate(node, 1)

    def mine_many_pegins(self):
        miner = self.nodes[1]
        funder = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        pegin_wallets = []
        pegin_addrs = []
        pegin_funds = {}
        for i in range(8):
            wallet_name = f"pegin_batch_{i}"
            miner.createwallet(wallet_name=wallet_name, load_on_startup=True)
            pegin_wallet = miner.get_wallet_rpc(wallet_name)
            pegin_wallets.append(pegin_wallet)
            addr = pegin_wallet.getnewaddress()
            pegin_addrs.append(addr)
            pegin_funds[addr] = Decimal("0.2")
        funder.sendmany("", pegin_funds)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        pegin_txids = []
        mweb_addr = funder.getnewaddress(address_type='mweb')
        for pegin_wallet, addr in zip(pegin_wallets, pegin_addrs):
            pegin_utxos = pegin_wallet.listunspent(minconf=1, addresses=[addr])
            assert_equal(len(pegin_utxos), 1)
            pegin_txids.append(pegin_wallet.sendtoaddress(mweb_addr, Decimal("0.1")))

        assert_equal(set(pegin_txids).issubset(set(miner.getrawmempool())), True)

        template = miner.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        assert template["transactions"][-1]["fee"] > 0

        block_hash = self.generate(miner, 1)[0]
        block = miner.getblock(block_hash)
        hogex = get_hogex_tx(miner, block_hash)

        assert_equal(len(hogex.vin), len(pegin_txids) + 1)
        for txid in pegin_txids:
            assert txid in block["tx"]

        self.sync_all()

    def mine_many_pegouts(self):
        funder = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        spender = self.nodes[2].get_wallet_rpc(self.default_wallet_name)

        funder.sendtoaddress(spender.getnewaddress(address_type='mweb'), 1)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        pegout_txids = []
        for _ in range(6):
            pegout_txids.append(spender.sendtoaddress(funder.getnewaddress(), Decimal("0.05")))

        assert_equal(set(pegout_txids).issubset(set(self.nodes[2].getrawmempool())), True)

        block_hash = self.generate(self.nodes[2], 1)[0]
        block = self.nodes[2].getblock(block_hash)
        hogex = get_hogex_tx(self.nodes[2], block_hash)

        assert_equal(block["tx"][-1], hogex.hash)
        assert_equal(len(hogex.vout), len(pegout_txids) + 1)
        for txid in pegout_txids:
            assert txid not in block["tx"]

        self.sync_all()

    def mine_after_stale_mweb_spend_reorg(self):
        miner = self.nodes[0]
        fork_miner = self.nodes[1]
        miner_wallet = miner.get_wallet_rpc(self.default_wallet_name)

        miner.createwallet(wallet_name="reorg_funding")
        miner.createwallet(wallet_name="reorg_stale")
        funding = miner.get_wallet_rpc("reorg_funding")
        stale_wallet = miner.get_wallet_rpc("reorg_stale")

        miner_wallet.sendtoaddress(funding.getnewaddress(), Decimal("5"))
        self.generate(miner, 1)
        self.sync_all()

        funding_utxos = funding.listunspent(minconf=1)
        assert_equal(len(funding_utxos), 1)
        funding_utxo = funding_utxos[0]

        conflict_amount = funding_utxo["amount"] - Decimal("0.001")
        raw_conflict = miner.createrawtransaction(
            [{"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]}],
            {funding.getnewaddress(): conflict_amount},
        )
        signed_conflict = funding.signrawtransactionwithwallet(raw_conflict)["hex"]
        conflict_txid = miner.decoderawtransaction(signed_conflict)["txid"]

        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)

        pegin_txid = funding.sendtoaddress(stale_wallet.getnewaddress(address_type='mweb'), Decimal("1"))
        pegin_tx = miner.getrawtransaction(pegin_txid, True)
        assert {"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]} in [
            {"txid": vin["txid"], "vout": vin["vout"]} for vin in pegin_tx["vin"]
        ]

        pegin_block = self.generate(miner, 1, sync_fun=self.no_op)[0]
        assert pegin_txid in miner.getblock(pegin_block)["tx"]

        stale_txid = stale_wallet.sendtoaddress(stale_wallet.getnewaddress(address_type='mweb'), Decimal("0.25"))
        assert stale_txid in miner.getrawmempool()

        fork_miner.sendrawtransaction(signed_conflict)
        fork_blocks = self.generate(fork_miner, 2, sync_fun=self.no_op)
        assert conflict_txid in fork_miner.getblock(fork_blocks[0])["tx"]

        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)
        self.sync_blocks()
        assert_equal(miner.getbestblockhash(), fork_blocks[-1])

        stale_remained = stale_txid in miner.getrawmempool()
        if stale_remained:
            with miner.assert_debug_log(expected_msgs=["Failed to add MWEB transaction"], timeout=10):
                miner.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)
        else:
            miner.getblocktemplate(MWEB_GBT_REQUEST_PARAMS)

        mined_hash = self.generate(miner, 1)[0]
        mined_block = miner.getblock(mined_hash)
        hogex = get_hogex_tx(miner, mined_hash)
        assert_equal(mined_block["tx"][-1], hogex.hash)


if __name__ == '__main__':
    MWEBMiningTest(__file__).main()
