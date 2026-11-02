#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test spending MWEB coins of a watch-only wallet with an air-gapped signer.

The signer runs on a node that is never connected and has no chain. It first
signs as a wallet holding the device's private account descriptor, then with
descriptorprocesspsbt and the descriptor supplied, without a wallet.
"""

from test_framework.mweb_device import MWEBDeviceFlow
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBPSBTWatchOnlySignerTest(MWEBDeviceFlow, BitcoinTestFramework):
    def set_test_params(self):
        self.set_device_test_params()

    def run_test(self):
        self.setup_coordinator()
        self.signer = self.nodes[1]
        assert_equal(self.signer.getblockcount(), 0)
        assert_equal(self.signer.getconnectioncount(), 0)

        self.signer.createwallet(wallet_name="device", blank=True)
        self.device_wallet = self.signer.get_wallet_rpc("device")
        result = self.device_wallet.importdescriptors([{"desc": self.device.private_descriptor(), "timestamp": "now", "active": True}])
        assert result[0]["success"], result
        self.sign_with = self.sign_with_wallet
        self.run_flow("wallet")

        self.signer.unloadwallet("device")
        self.sign_with = self.sign_with_descriptor
        self.run_flow("descriptor")

        assert_equal(self.signer.getblockcount(), 0)
        assert_equal(self.signer.getconnectioncount(), 0)
        self.write_vectors()

    def device_has_display(self):
        return self.sign_with == self.sign_with_wallet

    def device_address(self):
        return self.device_wallet.getnewaddress(address_type="mweb")

    def device_sign(self, psbt):
        return self.sign_with(psbt)

    def sign_with_wallet(self, psbt):
        result = self.device_wallet.walletprocesspsbt(psbt=psbt, finalize=False)
        assert_equal(result["complete"], True)
        return result["psbt"]

    def sign_with_descriptor(self, psbt):
        result = self.signer.descriptorprocesspsbt(psbt=psbt, descriptors=[{"desc": self.device.private_descriptor(), "range": 100}], finalize=False)
        assert_equal(result["complete"], True)
        return result["psbt"]


if __name__ == '__main__':
    MWEBPSBTWatchOnlySignerTest(__file__).main()
