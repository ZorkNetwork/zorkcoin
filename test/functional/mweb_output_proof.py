#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""TXO PMMR inclusion proofs for MWEB outputs (getmweboutputproof / verifymweboutputproof)."""

from copy import deepcopy

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBOutputProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        # Single-node: do not pass test= (reconnect_mweb_peers needs peers).
        setup_mweb_chain(node)

        addr = node.getnewaddress(address_type="mweb")
        node.sendtoaddress(addr, 1)
        self.generate(node, 1)
        utxos = [u for u in node.listunspent() if u.get("address", "").startswith("tmweb") and u["amount"] == 1]
        assert_equal(len(utxos), 1)
        assert "output_id" in utxos[0]
        output_id = utxos[0]["output_id"]
        inclusion_block = node.getbestblockhash()

        self.log.info("Unspent inclusion proof verifies")
        proof = node.getmweboutputproof(output_id)
        assert_equal(proof["output_id"], output_id)
        assert node.verifymweboutputproof(proof)

        tampered = deepcopy(proof)
        assert tampered["segment"]["hashes"]
        tampered["segment"]["hashes"][0] = "00" * 32
        assert_equal(node.verifymweboutputproof(tampered), False)

        self.log.info("Spend the output and prove at inclusion height")
        other = node.getnewaddress(address_type="mweb")
        node.sendtoaddress(other, 0.5)
        self.generate(node, 1)

        spent_proof = node.getmweboutputproof(output_id)
        assert_equal(spent_proof["blockhash"], inclusion_block)
        assert node.verifymweboutputproof(spent_proof)
        # Tip leafset must not silently prove a spent leaf.
        tip = node.getbestblockhash()
        assert_raises_rpc_error(-5, "not unspent", node.getmweboutputproof, output_id, tip)

        self.log.info("Tamper output_id vs output body")
        bad = deepcopy(spent_proof)
        bad["output_id"] = "11" * 32
        assert_equal(node.verifymweboutputproof(bad), False)


if __name__ == "__main__":
    MWEBOutputProofTest(__file__).main()
