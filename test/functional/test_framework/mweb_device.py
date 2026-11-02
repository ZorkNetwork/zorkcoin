#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Air-gapped MWEB signing workflow shared by the signer tests.

A watch-only "coordinator" wallet on the chain node holds only the public
account descriptor a signing device exports. It funds MWEB PSBTs, a device
signs them from PSBT data alone, and the coordinator finalizes and broadcasts.
Subclasses provide the device step.
"""

from decimal import Decimal
import hashlib
import hmac
import json
import os
import re

from test_framework.descriptors import descsum_create
from test_framework.key import ECKey
from test_framework.messages import COIN
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    generate,
    get_mweb_account_descriptor,
    init_mweb_wallet,
    mweb_extra_args,
)
from test_framework.script import hash160
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif

DEVICE_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DEVICE_SCAN_PATH = (1000, 1000, 0, 0)
DEVICE_SPEND_PATH = (1000, 1000, 0, 1)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Matches consensus/consensus.h PEGOUT_MATURITY.
PEGOUT_MATURITY = 9


def sats(amount):
    return int(Decimal(str(amount)) * COIN)


def pubkey(secret):
    key = ECKey()
    key.set(secret, True)
    return key.get_pubkey().get_bytes()


def derive_hardened(seed, path):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in path:
        data = b"\x00" + key + (index | 0x80000000).to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key = ((int.from_bytes(digest[:32], "big") + int.from_bytes(key, "big")) % SECP256K1_ORDER).to_bytes(32, "big")
        chain = digest[32:]
    return key


class MWEBDevice:
    """The MWEB account of a BIP39 seed, derived as the signing device does."""

    def __init__(self, mnemonic=DEVICE_MNEMONIC):
        self.mnemonic = mnemonic
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
        self.fingerprint = hash160(pubkey(derive_hardened(seed, ())))[:4].hex()
        self.scan_secret = derive_hardened(seed, DEVICE_SCAN_PATH)
        self.spend_secret = derive_hardened(seed, DEVICE_SPEND_PATH)
        self.spend_pubkey = pubkey(self.spend_secret)
        self.scan_origin = self.origin(DEVICE_SCAN_PATH)
        self.spend_origin = self.origin(DEVICE_SPEND_PATH)
        self.scan_wif = bytes_to_wif(self.scan_secret)

    def origin(self, path):
        return "[" + self.fingerprint + "".join(f"/{i}'" for i in path) + "]"

    def public_descriptor(self):
        """The account export: scan secret and spend pubkey, with origins."""
        return descsum_create(f"mweb({self.scan_origin}{self.scan_wif},{self.spend_origin}{self.spend_pubkey.hex()},*)")

    def private_descriptor(self):
        return descsum_create(f"mweb({self.scan_origin}{self.scan_wif},{self.spend_origin}{bytes_to_wif(self.spend_secret)},*)")

    def address_descriptor(self, index):
        """The single-address descriptor a coordinator writes for an input of this account."""
        return descsum_create(f"mweb({self.scan_origin}{self.scan_wif},{self.spend_origin}{self.spend_pubkey.hex()},{index})")


def descriptor_index(descriptor):
    return int(descriptor.split("#")[0].rsplit(",", 1)[1].rstrip(")"))


class MWEBDeviceFlow:
    """Mixed into a BitcoinTestFramework test. Node 0 holds the chain, a funding
    wallet and the coordinator. Node 1 is never connected and has no chain; it
    is the device for tests that sign on a node."""

    def add_options(self, parser):
        parser.add_argument("--dumpvectors", dest="dumpvectors", default=None,
                            help="Write the unsigned PSBTs, device keys and expected recipients to this directory")

    def set_device_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(["-keypool=100"], [])

    def setup_network(self):
        self.setup_nodes()

    def init_wallet(self, *, node):
        if node == 0:
            init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def device_has_display(self):
        return False

    def device_address(self):
        """Return a new receiving address shown by the device."""
        raise NotImplementedError

    def device_sign(self, psbt):
        """Return the device-signed PSBT."""
        raise NotImplementedError

    def device_review(self, psbt, recipients, fee):
        """Check what the device shows for the PSBT before it signs."""

    def mine(self, blocks=1):
        self.generate(self.chain_node, blocks, sync_fun=self.no_op)

    def setup_coordinator(self):
        self.chain_node = self.nodes[0]
        self.device = MWEBDevice()
        self.vectors = []
        generate(self.chain_node, FIRST_MWEB_HEIGHT - 1)
        self.funding = self.chain_node.get_wallet_rpc(self.default_wallet_name)
        self.funding.sendtoaddress(self.funding.getnewaddress(address_type="mweb"), 1)
        self.mine()

        self.chain_node.createwallet(wallet_name="coordinator", disable_private_keys=True, blank=True)
        self.coordinator = self.chain_node.get_wallet_rpc("coordinator")
        result = self.coordinator.importdescriptors([{"desc": self.device.public_descriptor(), "timestamp": "now", "active": True}])
        assert result[0]["success"], result
        assert_equal(get_mweb_account_descriptor(self.coordinator)["desc"], self.device.public_descriptor())

    def receive(self, amount, *, from_device):
        """Pay the account. The coordinator's lookahead finds a payment to an
        address the device handed out as soon as it is mined."""
        if from_device:
            address = self.device_address()
        else:
            address = self.coordinator.getnewaddress(address_type="mweb")
        self.funding.sendtoaddress(address, amount)
        self.mine()
        coin, = self.coordinator.listunspent(addresses=[address])
        assert_equal(coin["amount"], amount)
        return coin

    def check_input_fields(self, decoded):
        coins = {c["output_id"]: c for c in self.coordinator.listunspent()}
        for vin in decoded["inputs"]:
            mweb = vin["mweb"]
            coin = coins[mweb["output_id"]]
            for field in ("output_commit", "output_pubkey"):
                assert re.fullmatch("[0-9a-f]{66}", mweb[field]), (field, mweb)
            assert_equal(mweb["amount"], sats(coin["amount"]))
            assert "shared_secret" in mweb or "key_exchange_pk" in mweb, mweb
            index = descriptor_index(mweb["address_descriptor"])
            assert_equal(mweb["address_descriptor"], self.device.address_descriptor(index))
            assert_equal(self.coordinator.getaddressinfo(coin["address"])["ismine"], True)

    def recipients(self, decoded):
        """Every output and peg-out, in the order a device lists them."""
        found = []
        for out in decoded["outputs"]:
            address = out["mweb"]["address"] if "mweb" in out else out["scriptPubKey"]["address"]
            found.append({"address": address, "value": sats(out["amount"])})
        for kernel in decoded["kernels"]:
            for pegout in kernel.get("pegouts", []):
                found.append({"address": pegout["scriptPubKey"]["address"], "value": pegout["amount"]})
        return found

    def spend(self, name, funded_psbt, expected_spent):
        """Carry a coordinator PSBT to the device and back; broadcast and mine it."""
        decoded = self.coordinator.decodepsbt(funded_psbt)
        self.check_input_fields(decoded)
        # These spends have no transparent inputs, so the kernel fees are the whole fee.
        fee = sum(k["fee"] for k in decoded["kernels"]) / Decimal(COIN)
        assert_equal(self.coordinator.analyzepsbt(funded_psbt)["fee"], fee)
        self.vectors.append({"name": name, "psbt": funded_psbt, "recipients": self.recipients(decoded), "fee": sats(fee)})
        assert_equal(self.coordinator.walletprocesspsbt(funded_psbt)["complete"], False)

        balance = self.coordinator.getbalances()["mine"]["trusted"]
        self.device_review(funded_psbt, self.recipients(decoded), sats(fee))
        signed = self.device_sign(funded_psbt)
        final = self.coordinator.finalizepsbt(signed)
        assert_equal(final["complete"], True)
        txid = self.coordinator.sendrawtransaction(final["hex"])
        self.mine()
        assert_equal(self.coordinator.gettransaction(txid)["confirmations"], 1)
        assert_equal(self.coordinator.getbalances()["mine"]["trusted"], balance - expected_spent - fee)
        return txid

    def run_flow(self, label):
        from_device = self.device_has_display()
        if from_device:
            self.log.info(f"{label}: the device gives an address and the chain pays it")
        else:
            self.log.info(f"{label}: the coordinator gives an address and the chain pays it")
        coin = self.receive(Decimal("6"), from_device=from_device)

        self.log.info(f"{label}: MWEB to MWEB")
        recipient = self.funding.getnewaddress(address_type="mweb")
        funded = self.coordinator.walletcreatefundedpsbt([{"mweb_out": coin["output_id"]}], [{recipient: 1}], 0, {"add_inputs": False})
        decoded = self.coordinator.decodepsbt(funded["psbt"])
        descriptor = decoded["inputs"][0]["mweb"]["address_descriptor"]
        assert descriptor_index(descriptor) >= 2, descriptor
        known = {c["output_id"] for c in self.coordinator.listunspent()}
        self.spend(f"{label}_mweb_to_mweb", funded["psbt"], Decimal("1"))
        assert_equal([c["amount"] for c in self.funding.listunspent(addresses=[recipient])], [1])

        change, = [c for c in self.coordinator.listunspent() if c["output_id"] not in known]
        assert_equal(self.coordinator.getrawchangeaddress("mweb"), change["address"])
        self.log.info(f"{label}: peg-out from the change coin")
        transparent = self.funding.getnewaddress()
        funded = self.coordinator.walletcreatefundedpsbt([{"mweb_out": change["output_id"]}], [{transparent: Decimal("1.5")}], 0, {"add_inputs": False})
        decoded = self.coordinator.decodepsbt(funded["psbt"])
        assert_equal(decoded["inputs"][0]["mweb"]["address_descriptor"], self.device.address_descriptor(0))
        assert_equal([p["amount"] for k in decoded["kernels"] for p in k.get("pegouts", [])], [sats("1.5")])
        self.spend(f"{label}_pegout_from_change", funded["psbt"], Decimal("1.5"))
        self.mine(PEGOUT_MATURITY + 1)
        assert_equal([c["amount"] for c in self.funding.listunspent(addresses=[transparent])], [Decimal("1.5")])

        self.log.info(f"{label}: change-only spend sweeps the account to its own change address")
        self.receive(Decimal("2"), from_device=False)
        coins = self.coordinator.listunspent()
        swept = self.coordinator.sendall([change["address"]])
        assert_equal(swept["complete"], False)
        decoded = self.coordinator.decodepsbt(swept["psbt"])
        assert_equal(sorted(i["mweb"]["output_id"] for i in decoded["inputs"]), sorted(c["output_id"] for c in coins))
        assert_equal(len(decoded["outputs"]), 1)
        self.spend(f"{label}_change_only", swept["psbt"], Decimal("0"))
        swept_coin, = self.coordinator.listunspent()
        assert_equal(swept_coin["address"], change["address"])

    def write_vectors(self):
        if not self.options.dumpvectors:
            return
        os.makedirs(self.options.dumpvectors, exist_ok=True)
        data = {
            "network": "regtest",
            "mnemonic": self.device.mnemonic,
            "fingerprint": self.device.fingerprint,
            "scan_secret": self.device.scan_secret.hex(),
            "spend_secret": self.device.spend_secret.hex(),
            "spend_pubkey": self.device.spend_pubkey.hex(),
            "descriptor": self.device.public_descriptor(),
            "vectors": self.vectors,
        }
        with open(os.path.join(self.options.dumpvectors, "vectors.json"), "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
