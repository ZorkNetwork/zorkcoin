#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject peg-in scriptPubKeys that lack a matching MWEB body.

Without this check, an L1-only tx with a witness-v9 peg-in output can enter
the mempool and poison every CreateNewBlock attempt (HogEx never consumes it).
"""

from test_framework.mweb_util import init_mweb_wallet, generatetoaddress, setup_mweb_chain, with_mweb_vbparams
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import CScript, OP_9
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBOrphanPeginTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [with_mweb_vbparams([])]
        self.setup_clean_chain = True
        self.supports_cli = False

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Activate MWEB")
        setup_mweb_chain(node)

        self.log.info("Fund a mature coin for the orphan peg-in attempt")
        generatetoaddress(node, 1, wallet.getnewaddress())
        utxo = next(
            u for u in wallet.listunspent()
            if u["spendable"]
            and not u.get("address", "").startswith("bcrt1m")
            and u["confirmations"] > 0
            and int(u["amount"] * COIN) > COIN
        )

        # Witness v9 peg-in scriptPubKey with a fake kernel id and no mweb_tx.
        fake_kernel = bytes(32)
        pegin_script = CScript([OP_9, fake_kernel])
        fee = 10_000
        input_amount = int(utxo["amount"] * COIN)
        change_script = CScript(bytes.fromhex(
            wallet.getaddressinfo(wallet.getrawchangeaddress())["scriptPubKey"]
        ))

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [
            CTxOut(COIN, pegin_script),
            CTxOut(input_amount - COIN - fee, change_script),
        ]
        tx.rehash()

        signed = wallet.signrawtransactionwithwallet(tx.serialize().hex())
        assert signed["complete"]
        signed_hex = signed["hex"]

        self.log.info("testmempoolaccept must reject orphan peg-in (no MWEB body)")
        result = node.testmempoolaccept([signed_hex])[0]
        assert_equal(result["allowed"], False)
        # Policy rejects first with kernel-mismatch; consensus would use
        # pegin-count-mismatch if policy were bypassed.
        assert result["reject-reason"] in ("kernel-mismatch", "pegin-count-mismatch"), result

        self.log.info("sendrawtransaction must also reject")
        # Mempool acceptance may surface the consensus reject reason before policy.
        assert_raises_rpc_error(-26, "pegin-count-mismatch", node.sendrawtransaction, signed_hex)

        self.log.info("Mempool remains empty; getblocktemplate still works")
        assert_equal(node.getrawmempool(), [])
        gbt = node.getblocktemplate({"rules": ["mweb", "segwit"]})
        assert "mweb" in gbt


if __name__ == "__main__":
    MWEBOrphanPeginTest(__file__).main()
