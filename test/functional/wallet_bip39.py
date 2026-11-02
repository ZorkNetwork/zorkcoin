#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test addhdkey_mnemonic RPC (BIP39 generate and import)."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletBIP39Test(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=2"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_generate_and_import(self):
        self.log.info("Generate mnemonic master and import into a blank wallet")
        self.nodes[0].createwallet(wallet_name="bip39_gen")
        w = self.nodes[0].get_wallet_rpc("bip39_gen")

        before = len(w.gethdkeys())
        res = w.addhdkey_mnemonic()
        assert "xpub" in res
        assert "mnemonic" in res
        words = res["mnemonic"].split()
        assert_equal(len(words), 24)
        assert_equal(len(w.gethdkeys()), before + 1)
        xpub = res["xpub"]

        # Mnemonic must not be persisted in wallet descriptor listings
        for d in w.listdescriptors(private=True)["descriptors"]:
            assert res["mnemonic"] not in d["desc"]
        debug_log = (self.nodes[0].datadir_path / "regtest" / "debug.log").read_text(encoding="utf-8", errors="replace")
        assert res["mnemonic"] not in debug_log

        self.nodes[0].createwallet(wallet_name="bip39_imp", blank=True)
        wi = self.nodes[0].get_wallet_rpc("bip39_imp")
        imp = wi.addhdkey_mnemonic(passphrase="", mnemonic=res["mnemonic"])
        assert_equal(imp["xpub"], xpub)
        assert "mnemonic" not in imp

        # Same mnemonic again should fail as duplicate master
        assert_raises_rpc_error(-4, "HD key already exists", wi.addhdkey_mnemonic, "", res["mnemonic"])

        # addhdkey_mnemonic only installs unused(xprv); create active descriptors
        # so getnewaddress works (same follow-up as after addhdkey).
        self.log.info("createwalletdescriptor after mnemonic enables getnewaddress")
        for addr_type in ["legacy", "p2sh-segwit", "bech32", "bech32m"]:
            wi.createwalletdescriptor(type=addr_type, hdkey=xpub)
        assert wi.getnewaddress()
        assert wi.getnewaddress(address_type="bech32m")

    def test_wordcount_and_language(self):
        self.log.info("Generate with custom wordcount")
        self.nodes[0].createwallet(wallet_name="bip39_wc", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_wc")
        res = w.addhdkey_mnemonic(wordcount=12, language="english")
        assert_equal(len(res["mnemonic"].split()), 12)

        assert_raises_rpc_error(-8, "wordcount must be one of", w.addhdkey_mnemonic, wordcount=13)
        assert_raises_rpc_error(-8, "Unknown language", w.addhdkey_mnemonic, language="klingon")

    def test_invalid_mnemonic(self):
        self.log.info("Reject invalid checksum mnemonic")
        self.nodes[0].createwallet(wallet_name="bip39_bad", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_bad")
        bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        assert_raises_rpc_error(-8, "Invalid mnemonic", w.addhdkey_mnemonic, "", bad)

    def test_empty_mnemonic(self):
        self.log.info("Reject empty and whitespace-only mnemonic")
        self.nodes[0].createwallet(wallet_name="bip39_empty", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_empty")
        assert_raises_rpc_error(-8, "Empty mnemonic", w.addhdkey_mnemonic, "", "")
        assert_raises_rpc_error(-8, "Empty mnemonic", w.addhdkey_mnemonic, "", "   ")

    def test_unknown_word_not_logged(self):
        self.log.info("Unknown import word is not written to debug.log")
        self.nodes[0].createwallet(wallet_name="bip39_unk", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_unk")
        bad_token = "notawordzzzz"
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " + bad_token
        assert_raises_rpc_error(-8, "Invalid mnemonic", w.addhdkey_mnemonic, "", phrase)
        debug_log = (self.nodes[0].datadir_path / "regtest" / "debug.log").read_text(encoding="utf-8", errors="replace")
        assert bad_token not in debug_log

    def test_descriptor_idempotent(self):
        self.log.info("createwalletdescriptor after mnemonic is idempotent for existing types")
        self.nodes[0].createwallet(wallet_name="bip39_idem", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_idem")
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        xpub = w.addhdkey_mnemonic(passphrase="", mnemonic=mnemonic)["xpub"]
        w.createwalletdescriptor(type="bech32", hdkey=xpub)
        # Second call for same type fails at RPC level; GUI install skips this error.
        assert_raises_rpc_error(-4, "Descriptor already exists", w.createwalletdescriptor, type="bech32", hdkey=xpub)
        assert w.getnewaddress()

    def test_noprivs(self):
        self.log.info("Unavailable without private keys")
        self.nodes[0].createwallet(wallet_name="bip39_nopriv", disable_private_keys=True)
        w = self.nodes[0].get_wallet_rpc("bip39_nopriv")
        assert_raises_rpc_error(-4, "not available for wallets without private keys", w.addhdkey_mnemonic)

    def test_passphrase_changes_master(self):
        self.log.info("Different BIP39 passphrase yields different xpub")
        self.nodes[0].createwallet(wallet_name="bip39_pass", blank=True)
        w = self.nodes[0].get_wallet_rpc("bip39_pass")
        # Known 12-word English mnemonic (BIP39 test vector)
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        a = w.addhdkey_mnemonic(passphrase="", mnemonic=mnemonic)
        self.nodes[0].createwallet(wallet_name="bip39_pass2", blank=True)
        w2 = self.nodes[0].get_wallet_rpc("bip39_pass2")
        b = w2.addhdkey_mnemonic(passphrase="TREZOR", mnemonic=mnemonic)
        assert a["xpub"] != b["xpub"]

        # Edged spaces on passphrase are significant (NFKD only; no trim).
        self.nodes[0].createwallet(wallet_name="bip39_pass3", blank=True)
        w3 = self.nodes[0].get_wallet_rpc("bip39_pass3")
        c = w3.addhdkey_mnemonic(passphrase=" x ", mnemonic=mnemonic)
        self.nodes[0].createwallet(wallet_name="bip39_pass4", blank=True)
        w4 = self.nodes[0].get_wallet_rpc("bip39_pass4")
        d = w4.addhdkey_mnemonic(passphrase="x", mnemonic=mnemonic)
        assert c["xpub"] != d["xpub"]

    def test_descriptor_recovery(self):
        self.log.info("Restoring a mnemonic preserves L1 descriptors and address sequences")
        node = self.nodes[0]
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "TREZOR"
        address_types = ["legacy", "p2sh-segwit", "bech32", "bech32m"]
        wallets = []
        masters = []
        active_descriptors = []
        for name in ["bip39_original", "bip39_restored"]:
            node.createwallet(wallet_name=name, blank=True)
            wallet = node.get_wallet_rpc(name)
            xpub = wallet.addhdkey_mnemonic(passphrase=passphrase, mnemonic=mnemonic)["xpub"]
            for address_type in address_types:
                wallet.createwalletdescriptor(type=address_type, hdkey=xpub)

            active = [d for d in wallet.listdescriptors()["descriptors"] if d["active"]]
            # Four L1 receive/change pairs use the mnemonic master.
            assert_equal(len(active), 8)
            hdkey, = wallet.gethdkeys(active_only=True)
            assert_equal(hdkey["xpub"], xpub)
            assert_equal(hdkey["has_private"], True)
            assert_equal({d["desc"] for d in hdkey["descriptors"]},
                         {d["desc"] for d in active})
            assert all(d["active"] for d in hdkey["descriptors"])

            wallets.append(wallet)
            masters.append(xpub)
            active_descriptors.append({d["desc"] for d in active})

        original, restored = wallets
        assert_equal(*masters)
        assert_equal(*active_descriptors)
        issued = []
        for _ in range(2):
            addresses = {address_type: original.getnewaddress(address_type=address_type) for address_type in address_types}
            assert_equal(addresses, {address_type: restored.getnewaddress(address_type=address_type) for address_type in address_types})
            issued.append(addresses)

        self.log.info("Reloading a restored mnemonic wallet preserves ownership and the next address indices")
        node.unloadwallet("bip39_restored")
        node.loadwallet("bip39_restored")
        assert_equal({d["desc"] for d in restored.listdescriptors()["descriptors"] if d["active"]}, active_descriptors[0])
        assert_equal(restored.gethdkeys(active_only=True), original.gethdkeys(active_only=True))
        for addresses in issued:
            for address in addresses.values():
                assert_equal(restored.getaddressinfo(address)["ismine"], True)
        for address_type in address_types:
            next_address = original.getnewaddress(address_type=address_type)
            assert_equal(restored.getnewaddress(address_type=address_type), next_address)
            assert all(next_address != addresses[address_type] for addresses in issued)

    def test_funded_history_recovery(self):
        self.log.info("Recover confirmed canonical funds before reporting recovery complete")
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "funded historical recovery"
        address_types = ["legacy", "p2sh-segwit", "bech32", "bech32m"]
        node.createwallet(wallet_name="bip39_history_original", blank=True)
        original = node.get_wallet_rpc("bip39_history_original")
        master = original.addhdkey_mnemonic(passphrase=passphrase, mnemonic=words)["xpub"]
        for address_type in address_types:
            original.createwalletdescriptor(type=address_type, hdkey=master)
        addresses = {t: original.getnewaddress(address_type=t) for t in address_types}
        # No wallet containing this master is loaded when the payments arrive.
        node.unloadwallet("bip39_history_original")
        for address in addresses.values():
            funder.sendtoaddress(address, 1)
        self.generate(node, 6)

        node.createwallet(wallet_name="bip39_history_restored", blank=True, load_on_startup=True)
        restored = node.get_wallet_rpc("bip39_history_restored")
        assert_equal(restored.addhdkey_mnemonic(passphrase=passphrase, mnemonic=words)["xpub"], master)
        # The RPC master-import primitive intentionally installs no active scripts.
        # The GUI Restore installer performs this descriptor setup followed by the
        # same rescan; scanning before creating the descriptors would recover nothing.
        for address_type in address_types:
            restored.createwalletdescriptor(type=address_type, hdkey=master)
        assert_equal(restored.getbalance(), 0)
        assert_equal(restored.getwalletinfo()["txcount"], 0)
        scan = restored.rescanblockchain(0)
        assert_equal(scan, {"start_height": 0, "stop_height": node.getblockcount()})
        assert_equal(restored.getbalance(), 4)
        coins = restored.listunspent()
        assert_equal({c["address"]: c["amount"] for c in coins},
                     {a: Decimal(1) for a in addresses.values()})
        assert all(c["spendable"] for c in coins)
        assert_equal(restored.getwalletinfo()["scanning"], False)
        history = restored.listtransactions(count=100)
        assert_equal({r["address"] for r in history if r["category"] == "receive"}, set(addresses.values()))

        self.restart_node(0)
        node = self.nodes[0]
        restored = node.get_wallet_rpc("bip39_history_restored")
        funder = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(restored.getbalance(), 4)
        assert_equal({c["address"]: c["amount"] for c in restored.listunspent()},
                     {c["address"]: c["amount"] for c in coins})

        self.log.info("Spend every recovered canonical address type")
        l1_inputs = [{"txid": c["txid"], "vout": c["vout"]} for c in coins]
        assert_equal(len(l1_inputs), 4)
        raw = restored.createrawtransaction(l1_inputs, [{funder.getnewaddress(): Decimal("3.9999")}])
        signed = restored.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        l1_spend = node.sendrawtransaction(signed["hex"])
        assert l1_spend in set(node.getrawmempool())
        self.generate(node, 1)
        assert_equal(restored.gettransaction(l1_spend)["confirmations"], 1)
        assert all(c["address"] not in addresses.values() for c in restored.listunspent())

    def test_extended_phrase_import(self):
        self.log.info("Preserve intentionally supported checksum-valid short phrase import")
        self.nodes[0].createwallet(wallet_name="bip39_short_import", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("bip39_short_import")
        result = wallet.addhdkey_mnemonic(mnemonic="abandon abandon ability")
        assert_equal(wallet.gethdkeys()[0]["xpub"], result["xpub"])

    def run_test(self):
        self.test_generate_and_import()
        self.test_wordcount_and_language()
        self.test_invalid_mnemonic()
        self.test_empty_mnemonic()
        self.test_unknown_word_not_logged()
        self.test_descriptor_idempotent()
        self.test_noprivs()
        self.test_passphrase_changes_master()
        self.test_descriptor_recovery()
        self.test_extended_phrase_import()
        self.test_funded_history_recovery()


if __name__ == "__main__":
    WalletBIP39Test(__file__).main()
