#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB address generation across wallet and keypool lifecycles."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletAddressLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(['-keypool=2', '-mwebkeypool=2'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.test_blank_wallet(node)
        self.test_private_keys_disabled_wallet(node)
        self.test_mweb_keypool_policy(node)

    def assert_no_addresses(self, wallet):
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            wallet.getnewaddress,
            address_type='mweb',
        )
        assert_raises_rpc_error(
            -12,
            "No mweb addresses available",
            wallet.getrawchangeaddress,
            address_type='mweb',
        )

    def reload_wallet(self, node, wallet_name):
        node.get_wallet_rpc(wallet_name).unloadwallet()
        node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def test_blank_wallet(self, node):
        self.log.info("Blank wallets do not invent MWEB keys")
        wallet_name = 'mweb_blank'
        node.createwallet(wallet_name=wallet_name, blank=True)
        wallet = node.get_wallet_rpc(wallet_name)

        assert wallet.getwalletinfo()['private_keys_enabled']
        self.assert_no_addresses(wallet)
        assert_raises_rpc_error(-4, "Error refreshing keypool", wallet.keypoolrefill, 2)

        self.log.info("Blank-wallet behavior survives reload")
        wallet = self.reload_wallet(node, wallet_name)
        self.assert_no_addresses(wallet)

    def test_private_keys_disabled_wallet(self, node):
        self.log.info("Private-keys-disabled wallets start without MWEB keys")
        wallet_name = 'mweb_private_keys_disabled'
        node.createwallet(wallet_name=wallet_name, disable_private_keys=True)
        wallet = node.get_wallet_rpc(wallet_name)

        assert_equal(wallet.getwalletinfo()['private_keys_enabled'], False)
        self.assert_no_addresses(wallet)

        self.log.info("Private-keys-disabled behavior survives reload")
        wallet = self.reload_wallet(node, wallet_name)
        assert_equal(wallet.getwalletinfo()['private_keys_enabled'], False)
        self.assert_no_addresses(wallet)

    def test_mweb_keypool_policy(self, node):
        self.log.info("Test MWEB address generation while an encrypted wallet is locked")
        wallet_name = 'mweb_keypool'
        passphrase = 'mweb-keypool-passphrase'
        node.createwallet(wallet_name=wallet_name, passphrase=passphrase)
        wallet = node.get_wallet_rpc(wallet_name)

        self.log.info("Descriptor wallets extend MWEB addresses from cached public derivation data")
        receives = [wallet.getnewaddress(address_type='mweb') for _ in range(3)]
        changes = [wallet.getrawchangeaddress(address_type='mweb') for _ in range(2)]
        assert_equal(len(set(receives)), 3)
        # This tree uses one fixed change subaddress per account. LTC24's
        # rotating descriptor change branch is a different wallet contract.
        assert_equal(changes[0], changes[1])
        assert changes[0] not in receives
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)

        wallet = self.reload_wallet(node, wallet_name)
        next_address = wallet.getnewaddress(address_type='mweb')
        assert next_address not in receives + changes
        assert_equal(wallet.getrawchangeaddress(address_type='mweb'), changes[0])
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)



if __name__ == '__main__':
    MWEBWalletAddressLifecycleTest(__file__).main()
