#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end MWEB payment proofs via contrib/mweb/mweb_payment_proof.py."""

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif


class MWEBPaymentProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(["-mwebdeterministicsenders=1"], [])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wallet_rpc_url(self, node, wallet_name):
        # node.url is http://user:pass@host:port/wallet/<default>
        base = node.url.rsplit("/wallet/", 1)[0]
        return f"{base}/wallet/{wallet_name}"

    def run_tool(self, *args, rpc_url):
        script = Path(__file__).resolve().parents[2] / "contrib" / "mweb" / "mweb_payment_proof.py"
        env = os.environ.copy()
        env["MWEB_RPC_URL"] = rpc_url
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, str(script), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"tool failed ({proc.returncode}): {proc.stderr}\n{proc.stdout}")
        return proc.stdout

    def run_test(self):
        funder, receiver = self.nodes[0], self.nodes[1]
        setup_mweb_chain(funder, test=self)
        self.sync_all()

        scan_secret = bytes.fromhex("11" * 32)
        spend_secret = bytes.fromhex("22" * 32)
        default_wallet = funder.get_wallet_rpc(self.default_wallet_name)
        funder.createwallet(wallet_name="proofwallet", blank=True)
        pw = funder.get_wallet_rpc("proofwallet")
        desc = descsum_create(
            f"mweb({bytes_to_wif(scan_secret)},{bytes_to_wif(spend_secret)},*)"
        )
        res = pw.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])
        assert res[0]["success"], res[0].get("error")

        pw_addr = pw.getnewaddress(address_type="mweb")
        default_wallet.sendtoaddress(pw_addr, 3)
        self.generate(funder, 1)
        self.sync_all()

        dest = receiver.getnewaddress(address_type="mweb")
        send_amount = Decimal("0.75")
        pw.sendtoaddress(dest, send_amount)
        self.generate(funder, 1)
        self.sync_all()

        dest_utxos = [u for u in receiver.listunspent() if u.get("address") == dest]
        assert_equal(len(dest_utxos), 1)
        oid = dest_utxos[0]["output_id"]
        # Inclusion RPCs are node-level (no wallet path required).
        rpc_url = funder.url.rsplit("/wallet/", 1)[0]

        proof_path = Path(self.options.tmpdir) / "payment_proof.json"
        self.log.info("Create payment proof (scan secret resolves K_s index)")
        self.run_tool(
            "create",
            "--output-id",
            oid,
            "--address",
            dest,
            "--amount",
            str(int(send_amount * 100_000_000)),
            "--scan-secret",
            scan_secret.hex(),
            "--output",
            str(proof_path),
            rpc_url=rpc_url,
        )
        with open(proof_path, encoding="utf-8") as f:
            proof = json.load(f)
        assert proof["amount"] == int(send_amount * 100_000_000)
        # Index 0 may be consumed by change; any resolved index is fine.
        assert isinstance(proof["sender_index"], int)
        assert proof["sender_index"] >= 0

        self.log.info("Verify payment proof")
        assert "valid" in self.run_tool("verify", "--proof", str(proof_path), rpc_url=rpc_url)

        self.log.info("Negative: wrong amount")
        try:
            self.run_tool(
                "create",
                "--output-id",
                oid,
                "--address",
                dest,
                "--amount",
                "1",
                "--scan-secret",
                scan_secret.hex(),
                "--output",
                str(Path(self.options.tmpdir) / "bad.json"),
                rpc_url=rpc_url,
            )
            raise AssertionError("expected create to fail for wrong amount")
        except AssertionError as e:
            assert "mismatch" in str(e).lower() or "failed" in str(e).lower()

        self.log.info("Recreate after 'wipe' using only scan secret + on-chain K_s")
        proof_path2 = Path(self.options.tmpdir) / "payment_proof_rescan.json"
        self.run_tool(
            "create",
            "--output-id",
            oid,
            "--address",
            dest,
            "--amount",
            str(int(send_amount * 100_000_000)),
            "--scan-secret",
            scan_secret.hex(),
            "--output",
            str(proof_path2),
            rpc_url=rpc_url,
        )
        assert "valid" in self.run_tool("verify", "--proof", str(proof_path2), rpc_url=rpc_url)


if __name__ == "__main__":
    MWEBPaymentProofTest(__file__).main()
