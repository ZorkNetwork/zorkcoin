#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test recovering the MWEB coins of a Litecoin Core HD seed.

Litecoin Core 0.21 derives the MWEB account of its HD seed at m/0'/100': scan
key 0', spend key 1'. Litecoin Core 24.x keeps that account for receiving and
sends change to a second account with the same scan key and spend key 2'. A
wallet given the seed's account descriptors finds and spends the coins of both.
"""

from decimal import Decimal
import hashlib
import hmac

from test_framework.address import base58_to_byte, byte_to_base58
from test_framework.descriptors import descsum_create
from test_framework.mweb_device import MWEBDevice
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, generate, get_mweb_account_descriptor, init_mweb_wallet, list_mweb_account_checksums, mweb_extra_args
from test_framework.segwit_addr import CHARSET, Encoding, bech32_encode, bech32_verify_checksum
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

TPRV_VERSION = bytes.fromhex("04358394")
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
LTC021_HDSEED = "cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW"
# Litecoin Core 0.21.4 on regtest: `sethdseed true LTC021_HDSEED`, then `getnewaddress "" mweb` three times.
LTC021_ADDRESSES = [
    "tmweb1qqvyz36uvequuca8jd4mdjhxkjj6saetnseqhyps54ms5vnn4kteavqnpuuld9avmr8pfgenhgu04kmey3mgg8qy9uaudplta52z87yfgjqwfh2kr",
    "tmweb1qqwfq3n2tv7wsrqqm0r0l8fn0m405e3ytp55mg6th48pm6ag9jwgmsqjdsem93grhx8f6z9usp937aywndelp9gs6z8mxkzfjd52jcca24ynqq07c",
    "tmweb1qqv2c9x8psvsqw2fu9kgjscqxlg7hyz3aqtdwf0uavjen4v055c60cqh3j4chfwl3rz7rn574aglset3h52385jjxhq9wjttj0kuf0sej2s896rn0",
]


def master_tprv(hdseed_wif):
    seed = base58_to_byte(hdseed_wif)[0][:32]
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return byte_to_base58(b"\x00" + b"\x00" * 4 + b"\x00" * 4 + digest[32:] + b"\x00" + digest[:32], TPRV_VERSION)


def with_hrp(address, hrp):
    """The same MWEB address under another human-readable part."""
    pos = address.rfind("1")
    data = [CHARSET.find(c) for c in address[pos + 1:]]
    assert_equal(bech32_verify_checksum(address[:pos], data), Encoding.BECH32)
    return bech32_encode(Encoding.BECH32, hrp, data[:-6])


class MWEBWalletRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(["-keypool=100"])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self):
        self.generate(self.nodes[0], 1)

    def run_test(self):
        node = self.nodes[0]
        generate(node, FIRST_MWEB_HEIGHT - 1)
        funding = node.get_wallet_rpc(self.default_wallet_name)
        hrp = funding.getnewaddress(address_type="mweb").rsplit("1", 1)[0]
        tprv = master_tprv(LTC021_HDSEED)

        self.log.info("A wallet with the seed's receive account hands out the addresses Litecoin Core 0.21 does")
        node.createwallet(wallet_name="recovered", blank=True)
        recovered = node.get_wallet_rpc("recovered")
        receive = descsum_create(f"mweb({tprv}/0h/100h/0h,{tprv}/0h/100h/1h,*)")
        assert recovered.importdescriptors([{"desc": receive, "timestamp": "now", "active": True}])[0]["success"]
        expected = [with_hrp(address, hrp) for address in LTC021_ADDRESSES]
        assert_equal([recovered.getnewaddress(address_type="mweb") for _ in expected], expected)

        self.log.info("It finds and spends a coin paid to a Litecoin Core 0.21 address")
        funding.sendtoaddress(expected[-1], 2)
        self.mine()
        coin, = recovered.listunspent()
        assert_equal((coin["address"], coin["amount"]), (expected[-1], Decimal("2")))
        payee = funding.getnewaddress(address_type="mweb")
        recovered.sendtoaddress(payee, 1)
        self.mine()
        assert_equal([c["amount"] for c in funding.listunspent(addresses=[payee])], [Decimal("1")])

        self.log.info("Change of a Litecoin Core 24.x wallet goes to the account with spend key m/0'/100'/2'")
        change_account = descsum_create(f"mweb({tprv}/0h/100h/0h,{tprv}/0h/100h/2h,*)")
        node.createwallet(wallet_name="ltc24_change", blank=True)
        ltc24_change = node.get_wallet_rpc("ltc24_change")
        assert ltc24_change.importdescriptors([{"desc": change_account, "timestamp": "now", "active": True}])[0]["success"]
        change_address = ltc24_change.getnewaddress(address_type="mweb")
        assert change_address not in expected
        funding.sendtoaddress(change_address, 3)
        self.mine()
        balance = recovered.getbalances()["mine"]["trusted"]
        assert_equal(recovered.listunspent(addresses=[change_address]), [])

        self.log.info("Imported next to the receive account and rescanned, the change account's coin is found and spent")
        before = set(list_mweb_account_checksums(recovered))
        assert recovered.importdescriptors([{"desc": change_account, "timestamp": "now", "active": False}])[0]["success"]
        checksum, = set(list_mweb_account_checksums(recovered)) - before
        # The import's rescan of recent blocks finds it through the account's lookahead.
        assert_equal([c["amount"] for c in recovered.listunspent(addresses=[change_address])], [Decimal("3")])
        recovered.mwebrescan(checksum, 0, 100)
        coin, = recovered.listunspent(addresses=[change_address])
        assert_equal(coin["amount"], Decimal("3"))
        assert_equal(recovered.getbalances()["mine"]["trusted"], balance + 3)
        payee = funding.getnewaddress(address_type="mweb")
        recovered.send(outputs=[{payee: 2}], inputs=[{"mweb_out": coin["output_id"]}], add_inputs=False)
        self.mine()
        assert_equal([c["amount"] for c in funding.listunspent(addresses=[payee])], [Decimal("2")])

        self.log.info("A restore finds coins past index 1000 when an index near the end of the first 1000 was used")
        device = MWEBDevice(MNEMONIC)
        node.createwallet(wallet_name="issuer", blank=True)
        issuer = node.get_wallet_rpc("issuer")
        assert issuer.importdescriptors([{"desc": device.private_descriptor(), "timestamp": "now", "active": True}])[0]["success"]
        # 1095 is past the 100-address lookahead (-keypool=100) that the coin at 990 opens.
        issued = [None, None] + [issuer.getnewaddress(address_type="mweb") for _ in range(2, 1097)]
        paid = {index: issued[index] for index in (990, 1095)}
        for address in paid.values():
            funding.sendtoaddress(address, 1)
        self.mine()
        node.createwallet(wallet_name="restored", blank=True)
        restored = node.get_wallet_rpc("restored")
        assert restored.importdescriptors([{"desc": device.private_descriptor(), "timestamp": 0, "active": True}])[0]["success"]
        assert_equal(sorted(c["address"] for c in restored.listunspent()), sorted(paid.values()))
        assert_equal(restored.getnewaddress(address_type="mweb"), issued[1096])

        self.log.info("Past the lookahead of the coins found, scanning goes past the first 1000 indices only if one of its last 20 was used")
        # 1081 is just past the 100-address lookahead (-keypool=100) that the coin at 980 opens.
        issued, restored = self.restore_with_coins_at("boundary", [980, 1081])
        assert_equal([c["address"] for c in restored.listunspent()], [issued[980]])
        assert_equal(restored.getnewaddress(address_type="mweb"), issued[981])

        self.log.info("Each pass that finds a coin near its end starts another")
        issued, restored = self.restore_with_coins_at("multipass", [981, 1970, 2500])
        assert_equal(sorted(c["address"] for c in restored.listunspent()), sorted(issued[i] for i in (981, 1970, 2500)))
        assert_equal(restored.getnewaddress(address_type="mweb"), issued[2501])

    def restore_with_coins_at(self, name, indices):
        """Pay a new wallet's MWEB addresses at these indices, then restore its account into a blank wallet."""
        node = self.nodes[0]
        node.createwallet(wallet_name=f"{name}_issuer")
        issuer = node.get_wallet_rpc(f"{name}_issuer")
        issued = [None, None] + [issuer.getnewaddress(address_type="mweb") for _ in range(2, max(indices) + 2)]
        funding = node.get_wallet_rpc(self.default_wallet_name)
        for index in indices:
            funding.sendtoaddress(issued[index], 1)
        self.mine()
        account = get_mweb_account_descriptor(issuer, private=True)["desc"]
        node.createwallet(wallet_name=f"{name}_restored", blank=True)
        restored = node.get_wallet_rpc(f"{name}_restored")
        assert restored.importdescriptors([{"desc": account, "timestamp": 0, "active": True}])[0]["success"]
        return issued, restored


if __name__ == '__main__':
    MWEBWalletRecoveryTest(__file__).main()
