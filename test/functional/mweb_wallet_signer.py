#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test an external signer wallet with an MWEB account.

The mock signer (mocks/mweb_signer.py) forwards to a "device" wallet on node 1,
which holds the private keys and is never connected to the chain node.
"""

from decimal import Decimal
import hashlib
import hmac
import json
import os
import sys

from test_framework.address import byte_to_base58
from test_framework.descriptors import descsum_create
from test_framework.mweb_device import MWEBDevice, PEGOUT_MATURITY, pubkey
from test_framework.mweb_util import FIRST_MWEB_HEIGHT, generate, list_mweb_account_checksums, mweb_extra_args
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

TPRV_VERSION = bytes.fromhex("04358394")


def master_tprv(mnemonic):
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return byte_to_base58(b"\x00" + b"\x00" * 4 + b"\x00" * 4 + digest[32:] + b"\x00" + digest[:32], TPRV_VERSION)


class MWEBWalletSignerTest(BitcoinTestFramework):
    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'mweb_signer.py')
        return sys.executable + " " + path

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args([f"-signer={self.mock_signer_path()}", "-keypool=100"], [])

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def init_wallet(self, *, node):
        if node == 0:
            super().init_wallet(node=node)

    def mine(self, blocks=1):
        generate(self.nodes[0], blocks)

    def call_lines(self):
        path = os.path.join(self.nodes[0].cwd, "mweb_signer_calls.log")
        if not os.path.exists(path):
            return []
        with open(path, "r") as f:
            return f.read().splitlines()

    def calls(self):
        return [line.split()[0] for line in self.call_lines()]

    def write_config(self, **overrides):
        conf = dict(self.signer_conf, **overrides)
        with open(os.path.join(self.nodes[0].cwd, "mweb_signer.json"), "w") as f:
            json.dump(conf, f)

    def run_test(self):
        node = self.nodes[0]
        self.funding = node.get_wallet_rpc(self.default_wallet_name)
        self.mine(FIRST_MWEB_HEIGHT - 1)
        self.funding.sendtoaddress(self.funding.getnewaddress(address_type="mweb"), 1)
        self.mine()

        self.setup_device()
        self.test_create()
        self.test_receive_and_display()
        self.test_mweb_send()
        self.test_pegout()
        self.test_tampered_psbt()
        self.test_foreign_psbt()
        self.test_pegin()
        self.test_reload()
        self.test_secrets_over_stdin()
        self.test_other_account()
        self.test_create_variants()

        with open(node.debug_log_path, "r", encoding="utf-8") as f:
            assert self.device.scan_wif not in f.read()

    def setup_device(self):
        self.log.info("Set up the device wallet that the mock signer uses")
        self.device = MWEBDevice()
        signer_node = self.nodes[1]
        signer_node.createwallet(wallet_name="device", blank=True)
        self.device_wallet = signer_node.get_wallet_rpc("device")
        tprv = master_tprv(self.device.mnemonic)
        result = self.device_wallet.importdescriptors([
            {"desc": self.device.private_descriptor(), "timestamp": "now", "active": True},
            {"desc": descsum_create(f"wpkh({tprv}/84h/1h/0h/0/*)"), "timestamp": "now", "active": True, "internal": False},
            {"desc": descsum_create(f"wpkh({tprv}/84h/1h/0h/1/*)"), "timestamp": "now", "active": True, "internal": True},
        ])
        assert all(r["success"] for r in result), result

        public = self.device_wallet.listdescriptors()["descriptors"]
        wpkh = {d["internal"]: d["desc"] for d in public if d["desc"].startswith("wpkh(")}
        self.device_addresses = [self.device_wallet.getnewaddress(address_type="mweb") for _ in range(4)]
        addresses = {self.device_wallet.getaddressinfo(a)["desc"]: a for a in self.device_addresses}
        self.signer_conf = {
            "fingerprint": self.device.fingerprint,
            "receive": [self.device.public_descriptor(), wpkh[False]],
            "internal": [wpkh[True]],
            "addresses": addresses,
            "rpc_argv": signer_node.binaries.rpc_argv() + [f"-datadir={signer_node.datadir_path}", "-rpcwallet=device"],
        }
        self.write_config()

    def test_create(self):
        self.log.info("Create the wallet from the signer's descriptors")
        node = self.nodes[0]
        node.createwallet(wallet_name="hww", disable_private_keys=True, external_signer=True)
        self.hww = node.get_wallet_rpc("hww")
        assert "getdescriptors" in self.calls()
        mweb = [d for d in self.hww.listdescriptors()["descriptors"] if d["desc"].startswith("mweb(") and ",*)#" in d["desc"]]
        assert_equal([d["desc"] for d in mweb], [self.device.public_descriptor()])
        assert_equal(mweb[0]["active"], True)

    def test_receive_and_display(self):
        self.log.info("Receive to an address the device confirms")
        self.address = self.hww.getnewaddress(address_type="mweb")
        assert_equal(self.address, self.device_addresses[0])
        assert_equal(self.hww.walletdisplayaddress(self.address), {"address": self.address})
        assert_equal(self.calls()[-1], "displayaddress")

        unknown = self.hww.getnewaddress(address_type="mweb")
        self.write_config(addresses={})
        assert_raises_rpc_error(-1, "Signer returned error: Unexpected descriptor", self.hww.walletdisplayaddress, unknown)
        self.write_config()

        self.funding.sendtoaddress(self.address, 6)
        self.mine()
        coin, = self.hww.listunspent(addresses=[self.address])
        assert_equal(coin["amount"], 6)

    def test_mweb_send(self):
        self.log.info("MWEB to MWEB send signed by the device")
        recipient = self.funding.getnewaddress(address_type="mweb")
        res = self.hww.send(outputs=[{recipient: 1}])
        assert_equal(res["complete"], True)
        assert_equal(self.calls()[-1], "signtx")
        self.mweb_txid = res["txid"]
        self.mine()
        assert_equal([c["amount"] for c in self.funding.listunspent(addresses=[recipient])], [1])
        assert_equal(self.hww.gettransaction(self.mweb_txid)["confirmations"], 1)
        change, = self.hww.listunspent()
        assert Decimal("4.999") < change["amount"] < 5, change

    def test_pegout(self):
        self.log.info("Peg-out signed by the device")
        transparent = self.funding.getnewaddress()
        res = self.hww.send(outputs=[{transparent: Decimal("1.5")}])
        assert_equal(res["complete"], True)
        self.mine(PEGOUT_MATURITY + 1)
        assert_equal([c["amount"] for c in self.funding.listunspent(addresses=[transparent])], [Decimal("1.5")])

    def test_tampered_psbt(self):
        self.log.info("A signer that returns a different transaction fails the send")
        recipient = self.funding.getnewaddress(address_type="mweb")
        other = self.hww.walletcreatefundedpsbt([], [{recipient: Decimal("0.3")}])["psbt"]
        self.write_config(replace_psbt=other)
        balance = self.hww.getbalances()["mine"]["trusted"]
        with self.nodes[0].assert_debug_log(["the signer returned a PSBT that does not match the transaction"]):
            assert_raises_rpc_error(-25, "External signer failed to sign", self.hww.send, outputs=[{recipient: Decimal("0.2")}])
        self.write_config()
        assert_equal(self.hww.getbalances()["mine"]["trusted"], balance)
        assert_equal(self.nodes[0].getrawmempool(), [])

    def test_foreign_psbt(self):
        self.log.info("A PSBT with no inputs of this wallet does not run the signer")
        coin, = [c for c in self.funding.listunspent() if "output_id" in c][:1]
        funded = self.funding.walletcreatefundedpsbt([{"mweb_out": coin["output_id"]}], [{self.funding.getnewaddress(address_type="mweb"): Decimal("0.1")}], 0, {"add_inputs": False})
        calls = self.calls()
        assert_equal(self.hww.walletprocesspsbt(funded["psbt"])["complete"], False)
        assert_equal(self.calls(), calls)

    def test_pegin(self):
        self.log.info("Peg-in from the device's transparent coins")
        transparent = self.hww.getnewaddress(address_type="bech32")
        self.funding.sendtoaddress(transparent, 3)
        self.mine()
        utxo, = self.hww.listunspent(addresses=[transparent])
        mweb_address = self.hww.getnewaddress(address_type="mweb")
        res = self.hww.send(outputs=[{mweb_address: 2}], inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}], add_inputs=False)
        assert_equal(res["complete"], True)
        self.mine()
        assert_equal([c["amount"] for c in self.hww.listunspent(addresses=[mweb_address])], [2])

    def test_reload(self):
        self.log.info("After a restart the wallet still scans and gives addresses")
        unspent = sorted(c["amount"] for c in self.hww.listunspent())
        self.restart_node(0)
        self.nodes[0].loadwallet("hww")
        self.hww = self.nodes[0].get_wallet_rpc("hww")
        self.funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        assert_equal(sorted(c["amount"] for c in self.hww.listunspent()), unspent)
        assert_equal(self.hww.gettransaction(self.mweb_txid)["txid"], self.mweb_txid)

        address = self.hww.getnewaddress(address_type="mweb")
        assert_equal(address, self.device_addresses[3])
        self.funding.sendtoaddress(address, Decimal("0.7"))
        self.mine()
        assert_equal([c["amount"] for c in self.hww.listunspent(addresses=[address])], [Decimal("0.7")])

    def test_secrets_over_stdin(self):
        self.log.info("Commands carrying the scan secret reach the signer over stdin")
        self.hww.walletdisplayaddress(self.address)
        assert_equal(self.call_lines()[-1], "displayaddress stdin")
        assert "signtx stdin" in self.call_lines()
        assert "signtx argv" not in self.call_lines()
        assert "displayaddress argv" not in self.call_lines()

    def test_other_account(self):
        self.log.info("Another account in the wallet is neither displayed nor signed by the signer")
        other = MWEBDevice("legal winner thank year wave sausage worth useful legal winner thank yellow")
        assert other.fingerprint != self.device.fingerprint
        signer_node = self.nodes[1]
        signer_node.createwallet(wallet_name="other_device", blank=True)
        other_wallet = signer_node.get_wallet_rpc("other_device")
        assert other_wallet.importdescriptors([{"desc": other.private_descriptor(), "timestamp": "now", "active": True}])[0]["success"]
        checksums = list_mweb_account_checksums(self.hww)
        result = self.hww.importdescriptors([{"desc": other.public_descriptor(), "timestamp": "now", "active": False, "range": [0, 20]}])
        assert result[0]["success"], result
        other_checksum, = set(list_mweb_account_checksums(self.hww)) - set(checksums)

        address = other_wallet.getnewaddress(address_type="mweb")
        self.funding.sendtoaddress(address, Decimal("0.4"))
        self.mine()
        self.hww.mwebrescan(other_checksum, 0, 100)
        coin, = self.hww.listunspent(addresses=[address])

        calls = self.calls()
        assert_raises_rpc_error(-1, "The external signer does not hold the keys of this MWEB address", self.hww.walletdisplayaddress, address)
        funded = self.hww.walletcreatefundedpsbt([{"mweb_out": coin["output_id"]}], [{self.funding.getnewaddress(address_type="mweb"): Decimal("0.1")}], 0, {"add_inputs": False})
        assert_equal(self.hww.walletprocesspsbt(funded["psbt"])["complete"], False)
        new_calls = self.calls()[len(calls):]
        assert "displayaddress" not in new_calls
        assert "signtx" not in new_calls
        self.test_mixed_inputs(other, coin)

    def test_mixed_inputs(self, other, other_coin):
        self.log.info("A spend mixing the signer's coin with another account's coin hides that account's scan secret")
        own_coin = next(c for c in self.hww.listunspent() if "output_id" in c and c["output_id"] != other_coin["output_id"])
        inputs = [{"mweb_out": own_coin["output_id"]}, {"mweb_out": other_coin["output_id"]}]
        funded = self.hww.walletcreatefundedpsbt(inputs, [{self.funding.getnewaddress(address_type="mweb"): Decimal("0.2")}], 0, {"add_inputs": False})
        descriptors = {i["mweb"]["output_id"]: i["mweb"].get("address_descriptor") for i in self.hww.decodepsbt(funded["psbt"])["inputs"]}
        assert other.scan_wif in descriptors[other_coin["output_id"]]

        calls = self.calls()
        assert_equal(self.hww.walletprocesspsbt(funded["psbt"])["complete"], False)
        assert_equal(self.calls()[len(calls):].count("signtx"), 1)
        with open(os.path.join(self.nodes[0].cwd, "mweb_signer_last_psbt"), "r") as f:
            sent = self.hww.decodepsbt(f.read())
        sent_descriptors = {i["mweb"]["output_id"]: i["mweb"].get("address_descriptor") for i in sent["inputs"]}
        assert_equal(sent_descriptors[other_coin["output_id"]], None)
        assert self.device.scan_wif in sent_descriptors[own_coin["output_id"]]

    def test_create_variants(self):
        self.log.info("An MWEB descriptor in the signer's internal list is skipped")
        node = self.nodes[0]
        self.write_config(internal=self.signer_conf["internal"] + [self.device.public_descriptor()])
        with node.assert_debug_log(["Skipping an external signer MWEB descriptor that is not a receive account"]):
            node.createwallet(wallet_name="hww_internal", disable_private_keys=True, external_signer=True)
        hww_internal = node.get_wallet_rpc("hww_internal")
        mweb = [d for d in hww_internal.listdescriptors()["descriptors"] if d["desc"].startswith("mweb(") and ",*)#" in d["desc"]]
        assert_equal([(d["desc"], d["internal"]) for d in mweb], [(self.device.public_descriptor(), False)])

        self.log.info("An MWEB account without its scan secret is refused")
        scan_pubkey = pubkey(self.device.scan_secret).hex()
        public_scan = descsum_create(f"mweb({self.device.scan_origin}{scan_pubkey},{self.device.spend_origin}{self.device.spend_pubkey.hex()},*)")
        self.write_config(receive=[public_scan])
        assert_raises_rpc_error(None, "has no scan private key", node.createwallet, wallet_name="hww_no_scan", disable_private_keys=True, external_signer=True)
        self.write_config()


if __name__ == '__main__':
    MWEBWalletSignerTest(__file__).main()
