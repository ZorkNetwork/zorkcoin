#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test spending MWEB coins of a watch-only wallet with the SeedSigner MWEB signer.

Set ADGL_MWEB_SIGNER to a command that takes `<Fn> '<json>'` like the signer's
`mweb` CLI (for example the SeedSigner fork's contrib/mweb-signer-docker.sh).
The test is skipped otherwise.
"""

import base64
import json
import os
import subprocess

from test_framework.mweb_device import MWEBDeviceFlow
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


def b64(data):
    return base64.b64encode(data).decode()


class MWEBPSBTSeedSignerInteropTest(MWEBDeviceFlow, BitcoinTestFramework):
    def set_test_params(self):
        self.set_device_test_params()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not os.getenv("ADGL_MWEB_SIGNER"):
            raise SkipTest("ADGL_MWEB_SIGNER is not set")

    def run_test(self):
        self.next_index = 2
        self.setup_coordinator()
        self.run_flow("seedsigner")

    def signer(self, fn, request):
        result = subprocess.run([os.environ["ADGL_MWEB_SIGNER"], fn, json.dumps({**request, "Network": "regtest"})],
                                capture_output=True, text=True, timeout=300)
        assert_equal((result.returncode, result.stderr), (0, ""))
        return json.loads(result.stdout)

    def device_has_display(self):
        return True

    def device_address(self):
        index, self.next_index = self.next_index, self.next_index + 1
        response = self.signer("Addresses", {"Scan": b64(self.device.scan_secret), "SpendPub": b64(self.device.spend_pubkey),
                                             "From": index, "To": index + 1})
        address, = response["Address"]
        return address

    def device_review(self, psbt, recipients, fee):
        response = self.signer("PsbtGetRecipients", {"PsbtB64": psbt})
        assert_equal([{"address": r["Address"], "value": r["Value"]} for r in response["Recipient"]], recipients)
        assert_equal(response["Fee"], fee)

    def device_sign(self, psbt):
        response = self.signer("PsbtSign", {"PsbtB64": psbt, "Scan": b64(self.device.scan_secret), "Spend": b64(self.device.spend_secret)})
        return response["PsbtB64"]


if __name__ == '__main__':
    MWEBPSBTSeedSignerInteropTest(__file__).main()
