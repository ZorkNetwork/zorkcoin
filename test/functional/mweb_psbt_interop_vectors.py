#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the committed MWEB PSBT interop vectors (src/test/data/mweb_psbt_interop).

Each vector is an unsigned PSBT a watch-only coordinator funded. A node with no
chain decodes it to the recipients and fee recorded with it, and signs and
finalizes it with the device keys recorded in the file.
"""

from decimal import Decimal
import json
import os

from test_framework.messages import COIN
from test_framework.mweb_device import MWEBDevice, MWEBDeviceFlow
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBPSBTInteropVectorsTest(MWEBDeviceFlow, BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        path = os.path.join(self.config["environment"]["SRCDIR"], "src", "test", "data", "mweb_psbt_interop", "vectors.json")
        with open(path, encoding="utf8") as f:
            data = json.load(f)
        assert_equal(data["network"], "regtest")

        self.log.info("The recorded device keys are those of the recorded mnemonic")
        device = MWEBDevice(data["mnemonic"])
        assert_equal(data["fingerprint"], device.fingerprint)
        assert_equal(data["scan_secret"], device.scan_secret.hex())
        assert_equal(data["spend_secret"], device.spend_secret.hex())
        assert_equal(data["spend_pubkey"], device.spend_pubkey.hex())
        assert_equal(data["descriptor"], device.public_descriptor())

        assert_equal(len(data["vectors"]), 6)
        for vector in data["vectors"]:
            self.log.info(f"{vector['name']}: decodes to the recorded recipients and fee, and signs")
            decoded = node.decodepsbt(vector["psbt"])
            assert_equal(self.recipients(decoded), vector["recipients"])
            assert_equal(sum(k["fee"] for k in decoded["kernels"]), vector["fee"])
            assert_equal(decoded["fee"], Decimal(vector["fee"]) / COIN)

            unsigned = node.finalizepsbt(vector["psbt"])
            assert_equal(unsigned["complete"], False)
            signed = node.descriptorprocesspsbt(psbt=vector["psbt"], descriptors=[{"desc": device.private_descriptor(), "range": 100}], finalize=False)
            assert_equal(signed["complete"], True)
            final = node.finalizepsbt(signed["psbt"])
            assert_equal(final["complete"], True)
            assert final["hex"]


if __name__ == '__main__':
    MWEBPSBTInteropVectorsTest(__file__).main()
