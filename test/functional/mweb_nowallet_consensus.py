#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB consensus on a node built without a wallet.

The chain and the MWEB transactions come from the precomputed fixture
(load_mweb_fixture); MiniWallet spends the peg-out.
"""

from test_framework.mweb_util import load_mweb_fixture, mweb_extra_args
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# Matches consensus/consensus.h PEGOUT_MATURITY.
PEGOUT_MATURITY = 6


class MWEBNoWalletConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def run_test(self):
        node = self.nodes[0]
        fixture = load_mweb_fixture(self, node)
        txs = fixture["txs"]
        miniwallet = MiniWallet(node)
        assert node.getdeploymentinfo()["deployments"]["mweb"]["active"]

        self.log.info("MWEB-only, peg-in and peg-out transactions enter the mempool")
        for name in ("mweb_to_mweb", "pegin", "pegout"):
            assert_equal(node.sendrawtransaction(txs[name]["hex"]), txs[name]["txid"])
        assert_equal(sorted(node.getrawmempool()), sorted(txs[n]["txid"] for n in ("mweb_to_mweb", "pegin", "pegout")))

        self.log.info("A second spend of the same MWEB coin is refused")
        res = node.testmempoolaccept([txs["mweb_conflict"]["hex"]])[0]
        assert_equal(res["allowed"], False)
        # Full RBF treats it as a replacement that doesn't pay more.
        assert_equal(res["reject-reason"], "insufficient fee")

        self.log.info("A block confirms them")
        block_hash = self.generatetoaddress(node, 1, miniwallet.get_address())[0]
        block = node.getblock(block_hash, 2)
        assert_equal(node.getrawmempool(), [])
        assert txs["pegin"]["txid"] in [tx["txid"] for tx in block["tx"]]
        # An MWEB-only transaction's txid is its first kernel ID, in uint256 byte order.
        kernel_txids = [bytes.fromhex(k["kernel_id"])[::-1].hex() for k in block["mweb"]["kernels"]]
        for name in ("mweb_to_mweb", "pegout"):
            assert txs[name]["txid"] in kernel_txids

        self.log.info("The conflicting spend is refused once the coin is spent in a block")
        res = node.testmempoolaccept([txs["mweb_conflict"]["hex"]])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "missing-inputs")

        self.log.info("Disconnecting the block returns its transactions to the mempool")
        node.invalidateblock(block_hash)
        assert_equal(sorted(node.getrawmempool()), sorted(txs[n]["txid"] for n in ("mweb_to_mweb", "pegin", "pegout")))
        node.reconsiderblock(block_hash)
        assert_equal(node.getbestblockhash(), block_hash)
        assert_equal(node.getrawmempool(), [])

        self.log.info("The peg-out can't be spent before maturity")
        miniwallet.rescan_utxos()
        hogex_txid = block["tx"][-1]["txid"]
        pegout_utxo = miniwallet.get_utxo(txid=hogex_txid, mark_as_spent=False)
        assert_equal(pegout_utxo["value"], 3)
        spend = miniwallet.create_self_transfer(utxo_to_spend=pegout_utxo)
        self.generatetoaddress(node, PEGOUT_MATURITY - 2, miniwallet.get_address())
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-pegout", node.sendrawtransaction, spend["hex"])
        self.generatetoaddress(node, 1, miniwallet.get_address())
        assert_equal(node.sendrawtransaction(spend["hex"]), spend["txid"])
        self.generatetoaddress(node, 1, miniwallet.get_address())

        self.log.info("The MWEB chain state is rebuilt from the blocks")
        tip = node.getbestblockhash()
        # The template's MWEB block is built from the MWEB coin state, not from stored blocks.
        template_rules = {"rules": ["segwit", "mweb"]}
        mweb_template = node.getblocktemplate(template_rules)["mweb"]
        utxo_hash = node.gettxoutsetinfo()["hash_serialized_3"]
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex-chainstate"])
        node.setmocktime(fixture["mocktime"] + 600)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getblocktemplate(template_rules)["mweb"], mweb_template)
        assert_equal(node.gettxoutsetinfo()["hash_serialized_3"], utxo_hash)
        res = node.testmempoolaccept([txs["mweb_conflict"]["hex"]])[0]
        assert_equal(res["reject-reason"], "missing-inputs")
        self.generatetoaddress(node, 1, miniwallet.get_address())


if __name__ == "__main__":
    MWEBNoWalletConsensusTest(__file__).main()
