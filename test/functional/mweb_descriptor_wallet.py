#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB descriptor wallet functional tests.

Architecture under test:
- Ranged account SPKM: mweb(master_scan,master_spend,*)
- Per-index internals: mweb(A_i,B_i,i,acct_cksum)
- mweb(<hex>,<hex>) is the single-subaddress form with a public scan key, imported only
  when the wallet holds that scan secret; payments use the bech32 MWEB address
- Watch-only viewing via mweb(scan_priv,spend_pub,*) (no mweb_scan_secret)
- Indexed mweb(scan,spend,i) and LIP two-arg mweb(a,B_i) import isolation
- Private account re-import peg-out; watch-only cannot mint
- Multi-account selection and change routing: doc/mweb/descriptors.md
  "Spending across accounts" and "Wallet encryption"
"""

from decimal import Decimal
import re

from test_framework.address import base58_to_byte, byte_to_base58
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey, ORDER
from test_framework.messages import blake3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    get_mweb_account_descriptor,
    get_mweb_account_checksum,
    get_mweb_account_desc_for_address,
    get_mweb_account_public_text,
    get_mweb_internal_descriptor_for_address,
    get_mweb_internal_descriptors,
    get_mweb_internal_index_for_address,
    init_mweb_wallet,
    is_mweb_account_desc_body,
    list_mweb_account_checksums,
    make_mweb_indexed_watchonly_descriptor,
    make_mweb_single_subaddr_descriptor,
    make_mweb_watchonly_account_descriptor,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.util import (
    JSONRPCException,
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


class MWEBDescriptorWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1', '-keypool=1', '-mwebdescriptorthreshold=2', '-mwebdescriptorinactivity=0'],
            ['-whitelist=noban@127.0.0.1', '-keypool=1', '-mwebdescriptorthreshold=2', '-mwebdescriptorinactivity=0'],
        )
        self.wallet_names = [self.default_wallet_name, self.default_wallet_name]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def test_account_and_internal_structure(self, wallet):
        self.log.info("Check MWEB account + internal descriptor model")
        account = get_mweb_account_descriptor(wallet, private=True)
        assert account is not None
        assert account['desc'].startswith('mweb(')
        body = account['desc'].split('#')[0]
        assert is_mweb_account_desc_body(body)
        assert '/0h/100h/0h,' in body or "/0'/100'/0'," in body
        assert '/0h/100h/1h,*' in body or "/0'/100'/1',*" in body
        assert_equal(account.get('internal'), False)
        # Account may expose a keypool-style range for mint-index tracking.
        if 'range' in account:
            assert_equal(len(account['range']), 2)

        internals = get_mweb_internal_descriptors(wallet)
        assert_greater_than(len(internals), 0)
        for entry in internals:
            assert entry['desc'].startswith('mweb(')
            assert entry['desc'].split('#')[0].count(',') == 3
            assert_equal(entry.get('active'), False)
            assert 'range' not in entry

        public = wallet.listdescriptors()
        # Public listing includes the neutered account form (no private KEY material).
        public_accounts = [
            d for d in public['descriptors']
            if is_mweb_account_desc_body(d['desc'].split('#')[0])
        ]
        assert_equal(len(public_accounts), 1)
        assert 'tprv' not in public_accounts[0]['desc']
        assert 'xprv' not in public_accounts[0]['desc']

        info = wallet.getwalletinfo()
        assert_equal(info['descriptors'], True)

    def test_receive_reload_and_spend(self, miner, receiver):
        self.log.info("Receive MWEB on descriptor wallet")
        recv_addr = receiver.getnewaddress(address_type='mweb')

        txid = miner.sendtoaddress(recv_addr, 5)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        coins = receiver.listunspent(addresses=[recv_addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], 5)

        self.log.info("Reload wallet and verify MWEB state survives")
        wallet_name = receiver.getwalletinfo()['walletname']
        self.nodes[1].unloadwallet(wallet_name)
        self.nodes[1].loadwallet(wallet_name)
        receiver = self.nodes[1].get_wallet_rpc(wallet_name)

        coins_after = receiver.listunspent(addresses=[recv_addr])
        assert_equal(len(coins_after), 1)
        assert_equal(coins_after[0]['amount'], 5)
        assert_equal(coins_after[0]['address'], recv_addr)
        assert_equal(coins_after[0]['confirmations'], 1)

        tx = receiver.gettransaction(txid)
        assert_equal(tx['confirmations'], 1)

        self.log.info("Spend MWEB after reload")
        spend_addr = miner.getnewaddress(address_type='mweb')
        spend_txid = receiver.sendtoaddress(spend_addr, 2)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        assert_equal(miner.gettransaction(spend_txid)['confirmations'], 1)

    def test_external_descriptor_rejected_on_import(self, wallet):
        self.log.info("A pubkey pair mweb(A_i,B_i) is a public-scan descriptor the wallet has no scan secret for")
        internals = get_mweb_internal_descriptors(wallet)
        assert internals
        internal_desc = internals[0]['desc']
        body = internal_desc.split('#')[0]
        parts = body[body.index('(') + 1:body.rindex(')')].split(',')
        pubkey_pair = descsum_create(f"mweb({parts[0]},{parts[1]})")
        result = wallet.importdescriptors([{'desc': pubkey_pair, 'timestamp': 'now'}])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['message'], "Cannot import mweb() descriptor: the wallet has no scan secret for its scan key")

        self.log.info("deriveaddresses refuses MWEB descriptors")
        account = get_mweb_account_descriptor(wallet, private=False)['desc']
        assert_raises_rpc_error(-5, "deriveaddresses does not support MWEB descriptors", self.nodes[1].deriveaddresses, account)
        assert_raises_rpc_error(-5, "deriveaddresses does not support MWEB descriptors", self.nodes[1].deriveaddresses, pubkey_pair)

    def test_public_scan_key_import(self, node1):
        self.log.info("A public scan key imports when the wallet holds the matching scan secret")
        node1.createwallet(wallet_name='mweb_public_scan')
        wallet = node1.get_wallet_rpc('mweb_public_scan')
        addr = wallet.getnewaddress(address_type='mweb')
        info = wallet.getaddressinfo(addr)
        account_body = get_mweb_account_descriptor(wallet, private=False)['desc'].split('#')[0]
        scan_wif = account_body[account_body.index('(') + 1:].split(',')[0]
        if scan_wif.startswith('['):
            scan_wif = scan_wif[scan_wif.index(']') + 1:]
        payload, _version = base58_to_byte(scan_wif)
        scan_key = ECKey()
        scan_key.set(payload[:32], True)
        scan_pub_hex = scan_key.get_pubkey().get_bytes().hex()

        single = descsum_create(f"mweb({scan_pub_hex},{info['spend_pubkey']})")
        assert_equal(self.nodes[1].getdescriptorinfo(single)['hasprivatekeys'], False)
        result = wallet.importdescriptors([{'desc': single, 'timestamp': 'now'}])
        assert_equal(result[0]['success'], True)
        assert_equal(result[0]['mweb_scan_account'], get_mweb_account_checksum(wallet))

        other = ECKey()
        other.generate()
        unknown = descsum_create(f"mweb({other.get_pubkey().get_bytes().hex()},{info['spend_pubkey']})")
        result = wallet.importdescriptors([{'desc': unknown, 'timestamp': 'now'}])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['message'], "Cannot import mweb() descriptor: the wallet has no scan secret for its scan key")
        wallet.unloadwallet()

    def test_max_index_import(self, node1):
        self.log.info("Importing the largest index saturates the next index instead of wrapping")
        node1.createwallet(wallet_name='mweb_max_index')
        wallet = node1.get_wallet_rpc('mweb_max_index')
        max_index = 2147483647
        indexed = make_mweb_indexed_watchonly_descriptor(
            get_mweb_account_descriptor(wallet, private=True)['desc'],
            get_mweb_account_descriptor(wallet, private=False)['desc'],
            max_index)
        result = wallet.importdescriptors([{'desc': indexed, 'timestamp': 'now'}])
        assert_equal(result[0]['success'], True)
        bad = indexed.split('#')[0].replace(f",{max_index})", f",{max_index + 1})")
        result = wallet.importdescriptors([{'desc': descsum_create(bad), 'timestamp': 'now'}])
        assert_equal(result[0]['success'], False)
        assert "2147483647" in result[0]['error']['message']
        assert_raises_rpc_error(-12, "", wallet.getnewaddress, address_type='mweb')
        wallet.unloadwallet()
        node1.loadwallet('mweb_max_index')
        assert any(e['desc'].split('#')[0].split(',')[2] == str(max_index) for e in get_mweb_internal_descriptors(wallet))
        wallet.unloadwallet()

    def test_external_descriptor_send_and_addressinfo(self, miner, receiver):
        self.log.info("sendtoaddress takes the MWEB address, not an mweb(...) string; getaddressinfo describes the address")
        recv_addr = receiver.getnewaddress(address_type='mweb')
        info = receiver.getaddressinfo(recv_addr)
        index = get_mweb_internal_index_for_address(receiver, recv_addr)
        scan, spend = get_mweb_account_descriptor(receiver)['desc'].split('#')[0][5:-3].split(',')
        assert_equal(info['desc'], descsum_create(f"mweb({scan},{spend},{index})"))
        assert_equal(info['parent_desc'], get_mweb_account_descriptor(receiver)['desc'])
        assert_equal(info['solvable'], True)
        assert_equal(info['ismine'], True)
        assert_equal(info['ismweb'], True)
        assert_equal(info['isscript'], False)
        assert_equal(info['iswitness'], False)
        assert 'scriptPubKey' not in info
        assert 'mweb_desc' not in info and 'mweb_account_desc' not in info
        assert_equal(info['hdkeypath'], f"x/{index}")
        assert_equal(info['hdmasterfingerprint'], scan[1:9])

        assert_raises_rpc_error(-5, "Invalid", miner.sendtoaddress, info['desc'], 3)
        miner.sendtoaddress(recv_addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        coins = receiver.listunspent(addresses=[recv_addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], 3)

    def test_multi_account_descriptors(self, wallet):
        self.log.info("Multiple MWEB account descriptors can coexist in one wallet")
        checksums = list_mweb_account_checksums(wallet, private=True)
        assert_equal(len(checksums), 1)

        add_res = wallet.addhdkey()
        wallet.createwalletdescriptor('mweb', {'hdkey': add_res['xpub']})

        checksums = list_mweb_account_checksums(wallet, private=True)
        assert_equal(len(checksums), 2)
        assert_equal(len(set(checksums)), 2)

        public = wallet.listdescriptors()
        public_accounts = [
            d['desc'].split('#')[0]
            for d in public['descriptors']
            if is_mweb_account_desc_body(d['desc'].split('#')[0])
        ]
        assert_equal(len(public_accounts), 2)
        for body in public_accounts:
            assert 'tprv' not in body and 'xprv' not in body

    def test_legacy_ranged_descriptor_rejected(self, wallet):
        self.log.info("Legacy ranged mweb(xpub/.../*) and old account forms are rejected on import")
        xpub = wallet.gethdkeys()[0]['xpub']
        for legacy in (
            descsum_create(f"mweb({xpub}/100h/0h/0h/0/*)"),
            descsum_create(f"mweb({xpub}/0h/100h)"),
        ):
            result = wallet.importdescriptors([{'desc': legacy, 'timestamp': 'now'}])
            assert_equal(result[0]['success'], False)

    def test_prune_spent_internal_descriptor(self, miner, receiver):
        self.log.info("Prune removes spent internal descriptors when over threshold")
        recv_addr = receiver.getnewaddress(address_type='mweb')
        before = len(get_mweb_internal_descriptors(receiver))
        assert_greater_than(before, 2)

        miner.sendtoaddress(recv_addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(len(receiver.listunspent(addresses=[recv_addr])), 1)

        spend_addr = miner.getnewaddress(address_type='mweb')
        receiver.sendtoaddress(spend_addr, 2)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        after = len(get_mweb_internal_descriptors(receiver))
        assert_greater_than(before, after)

    def test_reuse_address_after_prune(self, miner, node1):
        """Pruning must not hide later payments to a reused stealth address."""
        self.log.info("Reused MWEB address stays detectable after its internal descriptor is pruned")
        node1.createwallet(wallet_name='mweb_reuse_prune', load_on_startup=False)
        receiver = node1.get_wallet_rpc('mweb_reuse_prune')

        # threshold=2 on these nodes: reserved 0/1 plus one receive → prune on spend.
        recv_addr = receiver.getnewaddress(address_type='mweb')
        for _ in range(2):
            receiver.getnewaddress(address_type='mweb')
        recv_index = get_mweb_internal_index_for_address(receiver, recv_addr)

        self.fund_mweb(miner, recv_addr, Decimal('2'))

        spend_addr = miner.getnewaddress(address_type='mweb')
        receiver.sendtoaddress(spend_addr, Decimal('1'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        for node in self.nodes:
            node.syncwithvalidationinterfacequeue()

        pruned = [
            d for d in get_mweb_internal_descriptors(receiver)
            if f",{recv_index}," in d['desc'].split('#')[0]
        ]
        assert_equal(len(pruned), 0)
        assert_equal(receiver.getaddressinfo(recv_addr)['ismine'], True)

        self.fund_mweb(miner, recv_addr, Decimal('1.5'))

        assert_equal(len(receiver.listunspent(minconf=1, addresses=[recv_addr])), 1)
        # Detection re-persists the internal descriptor for the active index.
        restored = [
            d for d in get_mweb_internal_descriptors(receiver)
            if f",{recv_index}," in d['desc'].split('#')[0]
        ]
        assert_equal(len(restored), 1)
        node1.unloadwallet('mweb_reuse_prune')

    def test_mwebkeep_prevents_prune(self, miner, receiver):
        self.log.info("mwebkeep prevents pruning of a spent internal descriptor")
        acct_cksum = get_mweb_account_checksum(receiver)

        kept_addr = receiver.getnewaddress(address_type='mweb')
        kept_index = get_mweb_internal_index_for_address(receiver, kept_addr)
        prune_addr = receiver.getnewaddress(address_type='mweb')
        prune_index = get_mweb_internal_index_for_address(receiver, prune_addr)

        miner.sendtoaddress(kept_addr, 2)
        miner.sendtoaddress(prune_addr, 2)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        receiver.mwebkeep(acct_cksum, kept_index)

        spend_addr = miner.getnewaddress(address_type='mweb')
        # Spend an amount that requires both 2-LTC coins so the non-kept
        # descriptor is actually spent (and eligible to prune). Selecting only
        # the kept coin left prune_index unspent and made this assert flake.
        receiver.sendtoaddress(spend_addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        kept = [
            d for d in get_mweb_internal_descriptors(receiver)
            if f",{kept_index}," in d['desc'].split('#')[0]
        ]
        pruned = [
            d for d in get_mweb_internal_descriptors(receiver)
            if f",{prune_index}," in d['desc'].split('#')[0]
        ]
        assert_equal(len(kept), 1)
        assert_equal(len(pruned), 0)

    def test_mwebrescan(self, receiver):
        self.log.info("mwebrescan RPC scans an index window on an account")
        acct_cksum = get_mweb_account_checksum(receiver)
        assert acct_cksum is not None
        result = receiver.mwebrescan(acct_cksum, 0, 2)
        assert_equal(result['start_index'], 0)
        assert_equal(result['end_index'], 2)
        assert_equal(result['indices_scanned'], 3)

    # MWEB fee constants (doc/mweb/descriptors.md "Selection algorithm"):
    # kernel weight 3 + output weight 18 each, at 100 sat per weight unit.
    MWEB_FEE_NO_CHANGE = Decimal('0.00002100')   # output + kernel (21 units)
    MWEB_FEE_WITH_CHANGE = Decimal('0.00003900') # + change output (39 units)
    MWEB_CHANGELESS_WINDOW = Decimal('0.00001800')

    def fund_mweb(self, miner, addr, amount):
        miner.sendtoaddress(addr, amount)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        # Wallet block notifications are asynchronous; drain them so the
        # funds are selectable as soon as this returns (avoids flaky
        # "Insufficient funds" under parallel test-runner load).
        for node in self.nodes:
            node.syncwithvalidationinterfacequeue()

    def keep_mweb_address(self, wallet, addr):
        """Protect a handed-out address from the aggressive descriptor pruning
        these nodes run with (-mwebdescriptorthreshold=2 -mwebdescriptorinactivity=0)."""
        internal = get_mweb_internal_descriptor_for_address(wallet, addr)
        body = internal['desc'].split('#')[0]
        parts = body[body.index('(') + 1:body.rindex(')')].split(',')
        # mweb(A_i,B_i,i,acct_cksum)
        wallet.mwebkeep(parts[3], int(parts[2]))

    def test_multi_account_selection_and_change_routing(self, miner, node1):
        self.log.info("Selection drains non-active accounts first; change routes to the active account")
        node1.createwallet(wallet_name='mweb_multi')
        wallet = node1.get_wallet_rpc('mweb_multi')

        # Account A is the wallet's initial active account. Creating B, then C,
        # makes each new account active in turn; C ends up active. Addresses
        # that receive again later are protected with mwebkeep because these
        # nodes prune aggressively.
        addr_a = wallet.getnewaddress(address_type='mweb')
        acct_a = get_mweb_account_desc_for_address(wallet, addr_a)
        self.keep_mweb_address(wallet, addr_a)
        self.fund_mweb(miner, addr_a, Decimal('0.3'))

        wallet.createwalletdescriptor('mweb', {'hdkey': wallet.addhdkey()['xpub']})
        addr_b = wallet.getnewaddress(address_type='mweb')
        acct_b = get_mweb_account_desc_for_address(wallet, addr_b)
        self.keep_mweb_address(wallet, addr_b)
        self.fund_mweb(miner, addr_b, Decimal('0.4'))

        wallet.createwalletdescriptor('mweb', {'hdkey': wallet.addhdkey()['xpub']})
        addr_c = wallet.getnewaddress(address_type='mweb')
        acct_c = get_mweb_account_desc_for_address(wallet, addr_c)
        self.fund_mweb(miner, addr_c, Decimal('1.0'))
        assert_equal(len({acct_a, acct_b, acct_c}), 3)

        def acct_balances():
            balances = {acct_a: Decimal('0'), acct_b: Decimal('0'), acct_c: Decimal('0')}
            for utxo in wallet.listunspent(minconf=1):
                acct = wallet.getaddressinfo(utxo['address']).get('parent_desc')
                assert acct in balances
                balances[acct] += utxo['amount']
            return balances

        assert_equal(acct_balances(),
                     {acct_a: Decimal('0.3'), acct_b: Decimal('0.4'), acct_c: Decimal('1.0')})

        # Spend 0.5: the non-active accounts A and B drain first (smallest coin
        # first) and run to zero; the active account C keeps its coin and
        # receives the change.
        miner_addr = miner.getnewaddress(address_type='mweb')
        wallet.sendtoaddress(miner_addr, Decimal('0.5'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        change_1 = Decimal('0.7') - Decimal('0.5') - self.MWEB_FEE_WITH_CHANGE
        assert_equal(acct_balances(),
                     {acct_a: Decimal('0'), acct_b: Decimal('0'),
                      acct_c: Decimal('1.0') + change_1})

        # Refund A and B, then spend more than any two accounts hold: inputs
        # from all three accounts combine in a single transaction.
        self.fund_mweb(miner, addr_a, Decimal('0.3'))
        self.fund_mweb(miner, addr_b, Decimal('0.4'))
        total = Decimal('0.7') + Decimal('1.0') + change_1
        assert_equal(acct_balances(),
                     {acct_a: Decimal('0.3'), acct_b: Decimal('0.4'),
                      acct_c: Decimal('1.0') + change_1})
        wallet.sendtoaddress(miner_addr, Decimal('1.5'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        change_2 = total - Decimal('1.5') - self.MWEB_FEE_WITH_CHANGE
        assert_equal(acct_balances(),
                     {acct_a: Decimal('0'), acct_b: Decimal('0'), acct_c: change_2})

    def test_changeless_window(self, miner, node1):
        self.log.info("Selection eliminates the change output inside the 1800-sat window")
        node1.createwallet(wallet_name='mweb_changeless')
        wallet = node1.get_wallet_rpc('mweb_changeless')

        def send_and_confirm(amount):
            dest = miner.getnewaddress(address_type='mweb')
            wallet.sendtoaddress(dest, amount)
            self.sync_mempools()
            self.generate(self.nodes[0], 1)
            self.sync_all()
            received = sum(u['amount'] for u in miner.listunspent(minconf=1, addresses=[dest]))
            assert_equal(received, amount)

        def wallet_total():
            return sum((u['amount'] for u in wallet.listunspent(minconf=1)), Decimal('0'))

        # The address receives repeatedly (running to zero in between), so keep
        # it from being pruned while it has no unspent coins.
        addr = wallet.getnewaddress(address_type='mweb')
        self.keep_mweb_address(wallet, addr)

        # Bottom of the window: total equals the no-change target exactly.
        self.fund_mweb(miner, addr, Decimal('1.0'))
        send_and_confirm(Decimal('1.0') - self.MWEB_FEE_NO_CHANGE)
        assert_equal(wallet_total(), Decimal('0'))

        # Top edge of the window: excess of exactly 1800 sat is committed as
        # kernel fee (equal to what the with-change path would have cost).
        self.fund_mweb(miner, addr, Decimal('1.0'))
        send_and_confirm(Decimal('1.0') - self.MWEB_FEE_NO_CHANGE - self.MWEB_CHANGELESS_WINDOW)
        assert_equal(wallet_total(), Decimal('0'))

        # One satoshi past the window: the with-change path produces a change
        # output of exactly one satoshi.
        self.fund_mweb(miner, addr, Decimal('1.0'))
        send_and_confirm(Decimal('1.0') - self.MWEB_FEE_WITH_CHANGE - Decimal('0.00000001'))
        coins = wallet.listunspent(minconf=1)
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], Decimal('0.00000001'))

    def test_encryption_migration(self, miner, node1):
        self.log.info("Encryption rotates the seed; old-account funds stay spendable and migrate")
        node1.createwallet(wallet_name='mweb_enc_migrate')
        wallet = node1.get_wallet_rpc('mweb_enc_migrate')
        passphrase = 'migrate-pass'

        addr_old = wallet.getnewaddress(address_type='mweb')
        acct_old = get_mweb_account_desc_for_address(wallet, addr_old)
        old_change = wallet.getrawchangeaddress('mweb')
        assert_equal(wallet.getaddressinfo(old_change)['ischange'], True)
        self.fund_mweb(miner, addr_old, Decimal('0.3'))
        self.fund_mweb(miner, addr_old, Decimal('0.4'))

        checksums_before = list_mweb_account_checksums(wallet)
        wallet.encryptwallet(passphrase)

        # Seed rotation added a new MWEB account; the old one remains.
        checksums_after = list_mweb_account_checksums(wallet)
        assert_greater_than(len(checksums_after), len(checksums_before))
        assert all(cksum in checksums_after for cksum in checksums_before)
        assert_equal(wallet.getaddressinfo(old_change)['ischange'], True)
        assert_equal(wallet.getaddressinfo(old_change)['parent_desc'], acct_old)

        # New addresses come from the new (active) account.
        with WalletUnlock(wallet, passphrase):
            addr_new = wallet.getnewaddress(address_type='mweb')
        acct_new = get_mweb_account_desc_for_address(wallet, addr_new)
        assert acct_new != acct_old

        # Pre-encryption coins remain visible, and a payment to a previously
        # handed-out address is detected while the wallet is locked.
        assert_equal(len(wallet.listunspent(minconf=1)), 2)
        self.fund_mweb(miner, addr_old, Decimal('0.1'))
        assert_equal(len(wallet.listunspent(minconf=1)), 3)

        miner_addr = miner.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, miner_addr, Decimal('0.5'))

        # Unlock and spend: all three old-account coins are consumed (smallest
        # first) and the change lands on the new active account.
        with WalletUnlock(wallet, passphrase):
            wallet.sendtoaddress(miner_addr, Decimal('0.5'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        coins = wallet.listunspent(minconf=1)
        assert_equal(len(coins), 1)
        assert_equal(wallet.getaddressinfo(coins[0]['address'])['parent_desc'], acct_new)
        change_1 = Decimal('0.8') - Decimal('0.5') - self.MWEB_FEE_WITH_CHANGE
        assert_equal(coins[0]['amount'], change_1)

        # The old account has run to zero; further spending works from the new
        # account alone and its change stays on the new account.
        with WalletUnlock(wallet, passphrase):
            wallet.sendtoaddress(miner_addr, Decimal('0.1'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        coins = wallet.listunspent(minconf=1)
        assert_equal(len(coins), 1)
        assert_equal(wallet.getaddressinfo(coins[0]['address'])['parent_desc'], acct_new)
        assert_equal(coins[0]['amount'], change_1 - Decimal('0.1') - self.MWEB_FEE_WITH_CHANGE)

    def test_mixed_mweb_l1_funding(self, miner, node1):
        self.log.info("Mixed funding: partial MWEB selection plus L1 remainder in one spend")
        node1.createwallet(wallet_name='mweb_mixed')
        wallet = node1.get_wallet_rpc('mweb_mixed')

        mweb_addr = wallet.getnewaddress(address_type='mweb')
        self.keep_mweb_address(wallet, mweb_addr)
        self.fund_mweb(miner, mweb_addr, Decimal('3'))
        l1_addr = wallet.getnewaddress()
        miner.sendtoaddress(l1_addr, 5)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # 7 exceeds both the L1 balance (5) and the MWEB balance (3), so the
        # wallet must take the mixed path: spend the MWEB coins (partial
        # selection, doc/mweb/descriptors.md "Selection algorithm") and fund
        # the remainder from L1.
        dest = miner.getnewaddress()
        txid = wallet.sendtoaddress(dest, 7)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(wallet.gettransaction(txid)['confirmations'], 1)
        mweb_utxos = [u for u in wallet.listunspent(minconf=0)
                      if u.get('address', '').startswith(('tmweb', 'mweb')) and u['address'] == mweb_addr]
        assert_equal(mweb_utxos, [])

    def test_mixed_recipients_allowed_multi_recipient(self, miner, node1):
        self.log.info("Multi-recipient with MWEB dest is allowed (uncommon privacy-compromising path)")
        node1.createwallet(wallet_name='mweb_mixed_recipients')
        wallet = node1.get_wallet_rpc('mweb_mixed_recipients')

        # Fund enough on both sides so success is policy-driven, not balance-driven.
        mweb_addr = wallet.getnewaddress(address_type='mweb')
        self.keep_mweb_address(wallet, mweb_addr)
        self.fund_mweb(miner, mweb_addr, Decimal('3'))
        l1_addr = wallet.getnewaddress()
        miner.sendtoaddress(l1_addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        l1_dest = miner.getnewaddress()
        mweb_addr = miner.getnewaddress(address_type='mweb')
        mweb_dest = mweb_addr

        # sendmany with mixed recipient classes must succeed (MWEB inputs → peg-out path).
        # Dict order should not matter for GetTxType after multi-recipient support.
        txid = wallet.sendmany("", {l1_dest: Decimal('1.0'), mweb_dest: Decimal('1.0')})
        assert txid
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # walletcreatefundedpsbt funds the same mixed recipients as an MWEB PSBT the wallet then signs.
        funded = wallet.walletcreatefundedpsbt([], [{l1_dest: 0.1}, {mweb_dest: 0.1}], 0, {"add_inputs": True})
        processed = wallet.walletprocesspsbt(funded['psbt'])
        assert_equal(processed['complete'], True)
        final = wallet.finalizepsbt(processed['psbt'])
        assert_equal(final['complete'], True)
        wallet.sendrawtransaction(final['hex'])
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

    def test_locked_wallet_funds_psbt(self, miner, node1):
        self.log.info("Locked wallet funds an MWEB PSBT; signing it needs the passphrase")
        node1.createwallet(wallet_name='mweb_lockedmsg')
        wallet = node1.get_wallet_rpc('mweb_lockedmsg')

        addr = wallet.getnewaddress(address_type='mweb')
        self.keep_mweb_address(wallet, addr)
        self.fund_mweb(miner, addr, Decimal('2'))
        wallet.encryptwallet('lockedmsg')
        receive_cursor = get_mweb_account_descriptor(wallet)['next_index']

        # A locked wallet funds an unsigned PSBT from its MWEB coins; signing it
        # needs the passphrase.
        l1_addr = miner.getnewaddress()
        # Unlocking cannot help when the coins cannot also pay the fee.
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.walletcreatefundedpsbt, [], [{l1_addr: 2}], 0, {"add_inputs": True})
        funded = wallet.walletcreatefundedpsbt([], [{l1_addr: 1}], 0, {"add_inputs": True})
        decoded = wallet.decodepsbt(funded['psbt'])
        assert_equal(len(decoded['inputs']), 1)
        assert 'mweb' in decoded['inputs'][0]
        assert_equal(decoded['kernels'][0]['pegouts'][0]['amount'], 100000000)
        assert_equal(get_mweb_account_descriptor(wallet)['next_index'], receive_cursor)
        # The input's address descriptor names the account's scan key while locked.
        def scan_key(desc):
            return desc.removeprefix('mweb(').split(',')[0]
        account_scan_keys = [scan_key(d['desc']) for d in wallet.listdescriptors()['descriptors'] if d['desc'].startswith('mweb(')]
        assert scan_key(decoded['inputs'][0]['mweb']['address_descriptor']) in account_scan_keys
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.walletprocesspsbt, funded['psbt'])
        wallet.walletpassphrase('lockedmsg', 60)
        processed = wallet.walletprocesspsbt(funded['psbt'])
        assert_equal(processed['complete'], True)
        final = wallet.finalizepsbt(processed['psbt'])
        assert_equal(final['complete'], True)
        wallet.sendrawtransaction(final['hex'])
        wallet.walletlock()
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

    def test_multi_account_unlock_spend_inactive(self, miner, receiver):
        self.log.info("Unlock restores spend keys for inactive MWEB account")
        self.generate(self.nodes[0], 2)
        addr_a = receiver.getnewaddress(address_type='mweb')
        miner.sendtoaddress(addr_a, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        add_res = receiver.addhdkey()
        receiver.createwalletdescriptor('mweb', {'hdkey': add_res['xpub']})
        receiver.encryptwallet('multiacct')

        miner_addr = miner.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(-13, "passphrase", receiver.sendtoaddress, miner_addr, 1)
        receiver.walletpassphrase('multiacct', 60)
        receiver.sendtoaddress(miner_addr, 1)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        receiver.walletlock()

    def test_watchonly_internal_import(self, miner, receiver, node1):
        self.log.info("Watch-only wallet imports mweb(scan_priv,spend_pub,*) + internal and sees UTXO")
        addr = receiver.getnewaddress(address_type='mweb')
        miner.sendtoaddress(addr, 2)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        internal = get_mweb_internal_descriptor_for_address(receiver, addr)
        public_account = get_mweb_account_public_text(receiver)
        private_account = get_mweb_account_descriptor(receiver, private=True)
        assert private_account is not None
        assert 'mweb_scan_secret' not in private_account
        watch_account = make_mweb_watchonly_account_descriptor(
            private_account['desc'], public_account)

        node1.createwallet(wallet_name='mweb_watch', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_watch')
        results = watch.importdescriptors([
            {
                'desc': watch_account,
                'timestamp': 0,
                'active': True,
            },
            {'desc': internal['desc'], 'timestamp': 0},
        ])
        assert results[0]['success'], results[0].get('error')
        assert results[1]['success'], results[1].get('error')

        info = watch.getaddressinfo(addr)
        assert_equal(info['ismine'], True)
        assert_equal(info.get('iswatchonly'), True)

        coins = watch.listunspent(addresses=[addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], 2)

        # A hardened spend path under an xpub hides the master spend pubkey, so
        # this account selects its coins but cannot derive MWEB change.
        l1_addr = miner.getnewaddress()
        assert_raises_rpc_error(-4, "Failed to retrieve change stealth address",
                                watch.walletcreatefundedpsbt, [], [{l1_addr: 1}], 0,
                                {"add_inputs": True})

        # Mismatched acct_cksum must fail even with a single account present.
        body = internal['desc'].split('#')[0]
        parts = body[body.index('(') + 1:body.rindex(')')].split(',')
        # mweb(A_i,B_i,i,acct_cksum) — corrupt the trailing checksum.
        parts[3] = 'deadbeef'
        bad_internal = descsum_create(f"mweb({','.join(parts)})")
        bad = watch.importdescriptors([{'desc': bad_internal, 'timestamp': 'now'}])
        assert_equal(bad[0]['success'], False)

    def test_watchonly_same_root_warns(self, receiver, node1):
        self.log.info("A watch-only import whose spend key derives from the scan key's private root warns")
        warning = ("The private key given for the scan key also derives the spend key. This wallet has private keys disabled "
                   "and keeps only the scan secret; to watch every address, import the account as listdescriptors shows it "
                   "without private keys")
        private_account = get_mweb_account_descriptor(receiver, private=True)['desc']
        public_spend = make_mweb_watchonly_account_descriptor(private_account, get_mweb_account_public_text(receiver))
        public_export = get_mweb_account_descriptor(receiver)['desc']
        for name, desc, warns in (('private', private_account, True), ('public_spend', public_spend, True),
                                  ('public_export', public_export, False)):
            node1.createwallet(wallet_name=f'mweb_same_root_{name}', blank=True, disable_private_keys=True)
            watch = node1.get_wallet_rpc(f'mweb_same_root_{name}')
            res = watch.importdescriptors([{'desc': desc, 'timestamp': 'now', 'active': True}])
            assert res[0]['success'], res[0].get('error')
            assert_equal(warning in res[0].get('warnings', []), warns)
        indexed = descsum_create(private_account.split('#')[0].replace(',*)', ',5)'))
        res = watch.importdescriptors([{'desc': indexed, 'timestamp': 'now'}])
        assert res[0]['success'], res[0].get('error')
        assert warning in res[0].get('warnings', [])

    def test_watchonly_public_export(self, miner, receiver, node1):
        self.log.info("Watch-only wallet from the public account export mints, receives and funds MWEB PSBTs")
        public = get_mweb_account_descriptor(receiver)
        body = public['desc'].split('#')[0]
        scan, spend, rng = body[len('mweb('):-1].split(',')
        assert scan.startswith('[') and scan.split(']')[0].endswith('/0h/100h/0h'), scan
        assert spend.startswith('[') and spend.split(']')[0].endswith('/0h/100h/1h'), spend
        assert_equal(len(spend.split(']')[1]), 66)
        assert_equal(rng, '*')
        assert 'tprv' not in body and 'tpub' not in body

        node1.createwallet(wallet_name='mweb_watch_public', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_watch_public')
        result = watch.importdescriptors([{'desc': public['desc'], 'timestamp': 'now', 'active': True}])
        assert result[0]['success'], result[0].get('error')
        assert_equal(get_mweb_internal_descriptors(watch) != [], True)
        assert_equal(get_mweb_account_descriptor(watch)['desc'], public['desc'])

        # Native receive cursors belong to each wallet. Compare the owner's
        # exported next index after explicitly advancing the viewer to it.
        exported_next = public['next_index']
        assert_equal(public['next'], exported_next)
        viewer_next = get_mweb_account_descriptor(watch)['next_index']
        assert viewer_next <= exported_next
        for _ in range(viewer_next, exported_next):
            watch.getnewaddress(address_type='mweb')
        assert_equal(get_mweb_account_descriptor(watch)['next_index'], exported_next)
        expected_address = receiver.getnewaddress(address_type='mweb')
        addr = watch.getnewaddress(address_type='mweb')
        assert_equal(addr, expected_address)
        assert_equal(get_mweb_internal_index_for_address(receiver, addr), exported_next)
        assert_equal(get_mweb_internal_index_for_address(watch, addr), exported_next)
        assert_equal(watch.getaddressinfo(addr)['ismine'], True)
        # The account's earlier coins are found at import.
        start_balance = watch.getbalances()['mine']['trusted']
        miner.sendtoaddress(addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        coins = watch.listunspent(addresses=[addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], 3)
        assert_equal(watch.getbalances()['mine']['trusted'], start_balance + 3)

        # Fund with MWEB change, sign with the private account, finalize and broadcast.
        l1_addr = miner.getnewaddress()
        funded = watch.walletcreatefundedpsbt([{'mweb_out': coins[0]['output_id']}], [{l1_addr: 1}], 0, {"add_inputs": False})
        decoded = watch.decodepsbt(funded['psbt'])
        assert_equal([i['mweb']['output_id'] for i in decoded['inputs']], [coins[0]['output_id']])
        assert_equal(len(decoded['outputs']), 1)
        assert 'mweb' in decoded['outputs'][0]
        assert_equal(watch.walletprocesspsbt(funded['psbt'])['complete'], False)
        private_account = get_mweb_account_descriptor(receiver, private=True)
        signed = receiver.descriptorprocesspsbt(funded['psbt'], [{'desc': private_account['desc'], 'range': 1000}])
        assert_equal(signed['complete'], True)
        final = watch.finalizepsbt(signed['psbt'])
        assert_equal(final['complete'], True)
        watch.sendrawtransaction(final['hex'])
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        spent = start_balance + 3 - watch.getbalances()['mine']['trusted']
        assert Decimal('1') < spent < Decimal('1.01'), spent

        # A rescanning import finds coins sent to addresses beyond the
        # watch-only wallet's own (keypool=1) lookahead.
        far_addr = receiver.getnewaddress(address_type='mweb')
        miner.sendtoaddress(far_addr, Decimal('0.7'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        node1.createwallet(wallet_name='mweb_watch_rescan', blank=True, disable_private_keys=True)
        rescan = node1.get_wallet_rpc('mweb_watch_rescan')
        result = rescan.importdescriptors([{'desc': public['desc'], 'timestamp': 0, 'active': True}])
        assert result[0]['success'], result[0].get('error')
        assert_equal([c['amount'] for c in rescan.listunspent(addresses=[far_addr])], [Decimal('0.7')])
        rescan_ids = {c['output_id'] for c in rescan.listunspent()}
        assert {c['output_id'] for c in watch.listunspent()} <= rescan_ids
        # Discovered indices are stored with the wallet.
        node1.unloadwallet('mweb_watch_rescan')
        node1.loadwallet('mweb_watch_rescan')
        assert_equal({c['output_id'] for c in rescan.listunspent()}, rescan_ids)
        assert_equal(rescan.getaddressinfo(far_addr)['ismine'], True)
        node1.unloadwallet('mweb_watch_rescan')

        watch.keypoolrefill(50)

        # The spend pubkey comes back from the stored descriptor on load.
        balance = watch.getbalances()['mine']['trusted']
        node1.unloadwallet('mweb_watch_public')
        node1.loadwallet('mweb_watch_public')
        assert_equal(watch.getbalances()['mine']['trusted'], balance)
        assert_equal(watch.getaddressinfo(watch.getnewaddress(address_type='mweb'))['ismine'], True)
        assert_equal(get_mweb_account_descriptor(watch)['desc'], public['desc'])

    def test_watchonly_cannot_mint(self, miner, receiver, node1):
        self.log.info("Watch-only mweb(scan_priv,xpub/hardened spend,*) cannot getnewaddress(mweb)")
        addr = receiver.getnewaddress(address_type='mweb')
        miner.sendtoaddress(addr, 1)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        private_account = get_mweb_account_descriptor(receiver, private=True)
        assert private_account is not None
        public_account = get_mweb_account_public_text(receiver)
        internal = get_mweb_internal_descriptor_for_address(receiver, addr)
        watch_account = make_mweb_watchonly_account_descriptor(
            private_account['desc'], public_account)

        node1.createwallet(wallet_name='mweb_watch_nomint', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_watch_nomint')
        results = watch.importdescriptors([
            {'desc': watch_account, 'timestamp': 0, 'active': True},
            {'desc': internal['desc'], 'timestamp': 0},
        ])
        assert results[0]['success'], results[0].get('error')
        assert results[1]['success'], results[1].get('error')

        info = watch.getwalletinfo()
        assert_equal(info['private_keys_enabled'], False)

        internals_before = get_mweb_internal_descriptors(watch)
        before_descs = {d['desc'] for d in internals_before}

        # CanGetAddresses is false without spend secret → RPC refuses before minting.
        assert_raises_rpc_error(-4, "no available keys",
                                watch.getnewaddress, '', 'mweb')

        internals_after = get_mweb_internal_descriptors(watch)
        assert_equal({d['desc'] for d in internals_after}, before_descs)
        assert_equal(len(internals_after), len(internals_before))

    def test_indexed_import_sees_only_that_index(self, miner, receiver, node1):
        """An indexed import creates/reuses its account and preserves single-index scope."""
        self.log.info("Indexed import creates a supporting account without sibling discovery")
        a_i = receiver.getnewaddress(address_type='mweb')
        a_j = receiver.getnewaddress(address_type='mweb')
        idx_i = get_mweb_internal_index_for_address(receiver, a_i)
        idx_j = get_mweb_internal_index_for_address(receiver, a_j)
        assert idx_i != idx_j

        miner.sendtoaddress(a_i, Decimal('2.5'))
        miner.sendtoaddress(a_j, Decimal('3.5'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        private_account = get_mweb_account_descriptor(receiver, private=True)
        assert private_account is not None
        public_account = get_mweb_account_public_text(receiver)
        watch_account = make_mweb_watchonly_account_descriptor(
            private_account['desc'], public_account)
        indexed = make_mweb_indexed_watchonly_descriptor(
            private_account['desc'], public_account, idx_i)

        node1.createwallet(wallet_name='mweb_index_isolate', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_index_isolate')
        result = watch.importdescriptors([{'desc': indexed, 'timestamp': 0}])
        assert result[0]['success'], result[0].get('error')
        account_checksum = result[0]['mweb_scan_account']
        assert_equal(list_mweb_account_checksums(watch), [account_checksum])
        assert_equal(len(get_mweb_internal_descriptors(watch)), 1)
        assert_equal(get_mweb_internal_index_for_address(watch, a_i), idx_i)
        assert_equal(get_mweb_account_descriptor(watch)['active'], False)
        assert_raises_rpc_error(-4, "no available keys", watch.getnewaddress, '', 'mweb')

        info_i = watch.getaddressinfo(a_i)
        info_j = watch.getaddressinfo(a_j)
        assert_equal(info_i['ismine'], True)
        assert_equal(info_j['ismine'], False)

        coins_i = watch.listunspent(minconf=0, addresses=[a_i])
        coins_j = watch.listunspent(minconf=0, addresses=[a_j])
        assert_equal(len(coins_i), 1)
        assert_equal(coins_i[0]['amount'], Decimal('2.5'))
        assert_equal(coins_i[0]['spendable'], False)
        assert_equal(len(coins_j), 0)

        history = watch.listtransactions(count=1000)
        assert_equal(len(history), 1)
        assert_equal((history[0]['category'], history[0]['address'], history[0]['amount']),
                     ('receive', a_i, Decimal('2.5')))
        assert_equal(history[0]['mweb_out'], coins_i[0]['output_id'])
        assert 'involvesWatchonly' not in history[0]

        # Equivalent key material with omitted origins reuses the same account,
        # preserving its descriptor identity, registered index and next position.
        # Compare without timestamp: re-import with timestamp='now' may advance it.
        def without_timestamps(descs):
            return [{k: v for k, v in d.items() if k != 'timestamp'} for d in descs]

        initial_descriptors = without_timestamps(watch.listdescriptors()['descriptors'])
        equivalent = descsum_create(re.sub(r'\[[^]]*\]', '', indexed.split('#')[0]))
        for desc in (indexed, equivalent):
            repeated = watch.importdescriptors([{'desc': desc, 'timestamp': 'now'}])
            assert repeated[0]['success'], repeated[0].get('error')
            assert_equal(repeated[0]['mweb_scan_account'], account_checksum)
            assert_equal(without_timestamps(watch.listdescriptors()['descriptors']), initial_descriptors)

        node1.unloadwallet('mweb_index_isolate')
        node1.loadwallet('mweb_index_isolate')
        watch = node1.get_wallet_rpc('mweb_index_isolate')
        watch.rescanblockchain(0)
        watch.mwebscanutxoset()
        assert_equal(watch.getaddressinfo(a_i)['ismine'], True)
        assert_equal(watch.getaddressinfo(a_j)['ismine'], False)
        assert_equal(len(watch.listunspent(addresses=[a_i])), 1)
        assert_equal(len(get_mweb_internal_descriptors(watch)), 1)

        miner.sendtoaddress(a_j, Decimal('1.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(watch.getaddressinfo(a_j)['ismine'], False)
        assert_equal(len(watch.listunspent(minconf=0, addresses=[a_j])), 0)
        assert_equal(sum(c['amount'] for c in watch.listunspent(minconf=0, addresses=[a_i])), Decimal('2.5'))

        # Only an explicit account import enables broad discovery. Reuse the
        # same parent even though the input uses HD expressions rather than the
        # resolved keys stored for the supporting account.
        promoted = watch.importdescriptors([{'desc': watch_account, 'timestamp': 0}])
        assert promoted[0]['success'], promoted[0].get('error')
        assert_equal(promoted[0]['mweb_scan_account'], account_checksum)
        assert_equal(list_mweb_account_checksums(watch), [account_checksum])
        assert_equal(sum(c['amount'] for c in watch.listunspent(addresses=[a_j])), Decimal('4.5'))
        assert_equal(get_mweb_internal_index_for_address(watch, a_i), idx_i)
        node1.unloadwallet('mweb_index_isolate')
        node1.loadwallet('mweb_index_isolate')
        assert_equal(node1.get_wallet_rpc('mweb_index_isolate').getaddressinfo(a_j)['ismine'], True)

    def test_single_subaddr_import_reload_isolation(self, miner, receiver, node1):
        """SINGLE_SUBADDR merges into an account or creates a single-subaddr account."""
        self.log.info("Single-subaddr mweb(a,B_i): merge when account exists; create when scan is new")
        a_i = receiver.getnewaddress(address_type='mweb')
        a_j = receiver.getnewaddress(address_type='mweb')
        miner.sendtoaddress(a_i, Decimal('2.25'))
        miner.sendtoaddress(a_j, Decimal('1.75'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        private_account = get_mweb_account_descriptor(receiver, private=True)
        assert private_account is not None
        public_account = get_mweb_account_public_text(receiver)
        watch_account = make_mweb_watchonly_account_descriptor(
            private_account['desc'], public_account)
        spend_pub_i = receiver.getaddressinfo(a_i)['spend_pubkey']
        single_i = make_mweb_single_subaddr_descriptor(private_account['desc'], spend_pub_i)

        # Merge path: account present → attach internal for a_i only.
        node1.createwallet(wallet_name='mweb_single_merge', blank=True, disable_private_keys=True)
        merge = node1.get_wallet_rpc('mweb_single_merge')
        merge_res = merge.importdescriptors([
            {'desc': watch_account, 'timestamp': 0, 'active': True},
            {'desc': single_i, 'timestamp': 0},
        ])
        assert merge_res[0]['success'], merge_res[0].get('error')
        assert merge_res[1]['success'], merge_res[1].get('error')
        assert_equal(merge.getaddressinfo(a_i)['ismine'], True)
        assert_equal(merge.getaddressinfo(a_j)['ismine'], False)
        assert_equal(len(merge.listunspent(minconf=0, addresses=[a_i])), 1)
        assert_equal(len(merge.listunspent(minconf=0, addresses=[a_j])), 0)

        # Create path: no matching account → new single-subaddr account.
        node1.createwallet(wallet_name='mweb_single_create', blank=True, disable_private_keys=True)
        created = node1.get_wallet_rpc('mweb_single_create')
        create_res = created.importdescriptors([{'desc': single_i, 'timestamp': 0}])
        assert create_res[0]['success'], create_res[0].get('error')
        assert_equal(created.getaddressinfo(a_i)['ismine'], True)
        assert_equal(created.getaddressinfo(a_j)['ismine'], False)
        coins = created.listunspent(minconf=0, addresses=[a_i])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], Decimal('2.25'))

        history = created.listtransactions(count=1000)
        assert_equal(len(history), 1)
        assert_equal((history[0]['category'], history[0]['address'], history[0]['amount']),
                     ('receive', a_i, Decimal('2.25')))
        assert_equal(history[0]['mweb_out'], coins[0]['output_id'])
        assert 'involvesWatchonly' not in history[0]

        node1.unloadwallet('mweb_single_create')
        node1.loadwallet('mweb_single_create')
        created = node1.get_wallet_rpc('mweb_single_create')
        assert_equal(created.getaddressinfo(a_i)['ismine'], True)
        assert_equal(len(created.listunspent(minconf=0, addresses=[a_i])), 1)

        miner.sendtoaddress(a_i, Decimal('0.5'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        # Rescan so the re-fund is discovered after reload.
        tip = node1.getblockcount()
        created.rescanblockchain(0, tip)
        assert_equal(sum(c['amount'] for c in created.listunspent(minconf=1, addresses=[a_i])),
                     Decimal('2.75'))
        assert_equal(created.getaddressinfo(a_j)['ismine'], False)

        # Encrypted create path: SINGLE SPKM + encrypt → unload/load → unlock still IsMine.
        self.log.info("Single-subaddr create path survives encryptwallet unload/load")
        node1.createwallet(wallet_name='mweb_single_enc', blank=True, disable_private_keys=False)
        enc = node1.get_wallet_rpc('mweb_single_enc')
        enc_import = enc.importdescriptors([{'desc': single_i, 'timestamp': 0}])
        assert enc_import[0]['success'], enc_import[0].get('error')
        assert_equal(enc.getaddressinfo(a_i)['ismine'], True)
        passphrase = 'singleenc'
        enc.encryptwallet(passphrase)
        node1.unloadwallet('mweb_single_enc')
        node1.loadwallet('mweb_single_enc')
        enc = node1.get_wallet_rpc('mweb_single_enc')
        enc.walletpassphrase(passphrase, 60)
        assert_equal(enc.getaddressinfo(a_i)['ismine'], True)
        tip = node1.getblockcount()
        enc.rescanblockchain(0, tip)
        assert_greater_than(len(enc.listunspent(minconf=0, addresses=[a_i])), 0)
        assert_equal(enc.getaddressinfo(a_j)['ismine'], False)

    def test_mixed_spend_key_imports(self, miner, node1):
        """Imports pairing a wallet's scan key with another wallet's spend key stay separate."""
        self.log.info("Indexed and two-argument imports attach only addresses the account derives")
        node1.createwallet(wallet_name='mweb_mix_f', blank=True)
        node1.createwallet(wallet_name='mweb_mix_o', blank=True)
        own = node1.get_wallet_rpc('mweb_mix_f')
        other = node1.get_wallet_rpc('mweb_mix_o')
        # Fixed raw master keys let the two-key upgrade control independently
        # derive b_4, without depending on an indexed import's storage layout.
        def wif(value):
            return byte_to_base58(value.to_bytes(32, 'big') + b'\x01', 239)

        for wallet, scan, spend in ((own, 11, 12), (other, 14, 13)):
            imported = wallet.importdescriptors([{'desc': descsum_create(f'mweb({wif(scan)},{wif(spend)},*)'),
                                                  'timestamp': 'now', 'active': True}])
            assert imported[0]['success'], imported[0].get('error')
        own_addr2 = own.getnewaddress(address_type='mweb')
        assert_equal(get_mweb_internal_index_for_address(own, own_addr2), 2)
        own_cksum = get_mweb_account_checksum(own)

        # The public listing gives mweb([origin]<scan WIF>,[origin]<B hex>,*).
        own_scan, own_spend_pub = get_mweb_account_descriptor(own)['desc'].split('#')[0][5:-3].split(',')
        other_spend_pub = get_mweb_account_descriptor(other)['desc'].split('#')[0][5:-3].split(',')[1]
        other_spend_priv = get_mweb_account_descriptor(other, private=True)['desc'].split('#')[0][5:-3].split(',')[1]

        # A helper wallet derives the mixed addresses: the own scan key with the other spend key.
        node1.createwallet(wallet_name='mweb_mix_h', blank=True)
        helper = node1.get_wallet_rpc('mweb_mix_h')
        res = helper.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{other_spend_priv},*)"),
                                         'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        mixed = {}
        for _ in range(5):
            addr = helper.getnewaddress(address_type='mweb')
            mixed[get_mweb_internal_index_for_address(helper, addr)] = addr
        assert_equal(sorted(mixed), [2, 3, 4, 5, 6])

        def import_one(wallet, desc):
            res = wallet.importdescriptors([{'desc': descsum_create(desc), 'timestamp': 'now'}])
            assert res[0]['success'], res[0].get('error')
            return res[0]['mweb_scan_account']

        # Two-argument, mixed: a separate entry; the account's own index-2 record is untouched.
        spend_pub2 = helper.getaddressinfo(mixed[2])['spend_pubkey']
        assert import_one(own, f"mweb({own_scan},{spend_pub2})") != own_cksum
        assert_equal(get_mweb_internal_index_for_address(own, own_addr2), 2)
        # Indexed imports with a different master spend key form a distinct
        # supporting account. A master private key upgrades its registered indices.
        mixed_cksum = import_one(own, f"mweb({own_scan},{other_spend_pub},3)")
        assert mixed_cksum != own_cksum
        assert_equal(import_one(own, f"mweb({own_scan},{other_spend_priv},4)"), mixed_cksum)
        info3 = own.getaddressinfo(mixed[3])
        assert_equal(info3['desc'], descsum_create(f"mweb({own_scan},{other_spend_pub},3)"))
        assert_equal(info3['parent_desc'], descsum_create(f"mweb({own_scan},{other_spend_pub},*)"))
        assert_equal(info3['solvable'], True)
        assert 'hdkeypath' not in info3
        assert_equal(own.getaddressinfo(mixed[5])['ismine'], False)
        # Indexed, the account's own keys: attached to the account.
        assert_equal(import_one(own, f"mweb({own_scan},{own_spend_pub},6)"), own_cksum)
        assert 6 in [int(d['desc'].split('#')[0][5:-1].split(',')[2]) for d in get_mweb_internal_descriptors(own)]
        for index in (2, 3, 4):
            assert_equal(own.getaddressinfo(mixed[index])['ismine'], True)

        amounts = {own_addr2: Decimal('1.0'), mixed[2]: Decimal('1.25'), mixed[3]: Decimal('1.5'), mixed[4]: Decimal('5.0')}
        for addr, amount in amounts.items():
            miner.sendtoaddress(addr, amount)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        def check_received(wallet):
            for addr, amount in amounts.items():
                coins = wallet.listunspent(minconf=0, addresses=[addr])
                assert_equal([c['amount'] for c in coins], [amount])

        check_received(own)
        node1.unloadwallet('mweb_mix_f')
        node1.loadwallet('mweb_mix_f')
        own = node1.get_wallet_rpc('mweb_mix_f')
        check_received(own)
        assert_equal(own.listunspent(minconf=0, addresses=[mixed[4]])[0]['spendable'], True)
        assert_equal(own.listunspent(minconf=0, addresses=[mixed[3]])[0]['spendable'], True)
        assert_equal(own.listunspent(minconf=0, addresses=[own_addr2])[0]['spendable'], True)
        assert_equal(own.getaddressinfo(mixed[5])['ismine'], False)

        # Select the newly imported account's index explicitly, preserving this
        # spend control independently of other now-spendable registered indices.
        pay_to = miner.getnewaddress(address_type='mweb')
        coin4 = own.listunspent(addresses=[mixed[4]])[0]
        txid = own.send(outputs={pay_to: Decimal('4.0')},
                        options={'inputs': [{'output_id': coin4['output_id']}], 'add_inputs': False})['txid']
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(own.gettransaction(txid)['confirmations'], 1)
        assert_equal(own.listunspent(minconf=0, addresses=[mixed[4]]), [])

        self.log.info("A private indexed import needs explicit full-account opt-in for automatic change")
        node1.createwallet(wallet_name='mweb_index_private', blank=True, passphrase='indexed')
        indexed_private = node1.get_wallet_rpc('mweb_index_private')
        indexed_private.walletpassphrase('indexed', 60)
        indexed_checksum = import_one(indexed_private, f"mweb({own_scan},{other_spend_priv},3)")
        indexed_private.walletlock()
        node1.unloadwallet('mweb_index_private')
        node1.loadwallet('mweb_index_private')
        indexed_private = node1.get_wallet_rpc('mweb_index_private')
        assert_equal(indexed_private.getaddressinfo(mixed[3])['ismine'], True)
        assert_equal(indexed_private.getaddressinfo(mixed[5])['ismine'], False)
        assert_raises_rpc_error(-13, "walletpassphrase", indexed_private.listdescriptors, True)
        indexed_private.walletpassphrase('indexed', 60)
        indexed_private.rescanblockchain(0)
        assert_equal(indexed_private.listunspent(addresses=[mixed[3]])[0]['spendable'], True)
        assert_equal(indexed_private.getaddressinfo(mixed[5])['ismine'], False)
        assert_raises_rpc_error(-4, "no available keys", indexed_private.getnewaddress, '', 'mweb')
        assert_raises_rpc_error(-6, "Failed to retrieve change stealth address",
                                indexed_private.sendtoaddress, pay_to, Decimal('1.0'))
        indexed_coin, = indexed_private.listunspent(addresses=[mixed[3]])
        inventory_before = indexed_private.listunspent()
        locks_before = indexed_private.listlockunspent()
        mempool_before = set(node1.getrawmempool())
        self.log.info("A limited indexed import signs changeless or explicitly directed change without full-account promotion")
        for custom_change in (False, True):
            options = {'add_inputs': False, 'fee_rate': 10}
            amount = Decimal('1') if custom_change else indexed_coin['amount']
            if custom_change:
                options['changeAddress'] = mixed[3]
            else:
                options['subtractFeeFromOutputs'] = [0]
            funded = indexed_private.walletcreatefundedpsbt(
                [{'mweb_out': indexed_coin['output_id']}], [{pay_to: amount}], 0, options)
            decoded = indexed_private.decodepsbt(funded['psbt'])
            selected_input, = decoded['inputs']
            assert_equal(selected_input['mweb']['output_id'], indexed_coin['output_id'])
            assert_equal(funded['changepos'] == -1, not custom_change)
            assert_equal({output['mweb']['address']: output['amount'] for output in decoded['outputs']},
                         {pay_to: amount, mixed[3]: indexed_coin['amount'] - amount - funded['fee']}
                         if custom_change else {pay_to: amount - funded['fee']})
            signed = indexed_private.walletprocesspsbt(funded['psbt'])
            assert signed['complete']
            finalized = indexed_private.finalizepsbt(signed['psbt'])
            assert finalized['complete']
            admitted, = node1.testmempoolaccept([finalized['hex']])
            assert admitted['allowed'], admitted
            assert_equal(indexed_private.listunspent(), inventory_before)
            assert_equal(indexed_private.listlockunspent(), locks_before)
            assert_equal(set(node1.getrawmempool()), mempool_before)
        assert_raises_rpc_error(-6, "Failed to retrieve change stealth address",
                                indexed_private.sendtoaddress, pay_to, Decimal('1.0'))
        promoted = indexed_private.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{other_spend_priv},*)"),
                                                        'timestamp': 'now', 'active': True}])
        assert promoted[0]['success'], promoted[0].get('error')
        assert_equal(promoted[0]['mweb_scan_account'], indexed_checksum)
        txid = indexed_private.sendtoaddress(pay_to, Decimal('1.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(indexed_private.gettransaction(txid)['confirmations'], 1)
        assert_greater_than(indexed_private.getbalances()['mine']['trusted'], 0)

        self.log.info("A per-address spend key gives a public-spend account its master spend key")
        offset = int.from_bytes(blake3(b'A' + (4).to_bytes(4, 'little') + (11).to_bytes(32, 'big')).serialize(), 'big')
        assert 0 < offset < ORDER
        b4_value = (13 + offset) % ORDER
        b4_key = ECKey()
        b4_key.set(b4_value.to_bytes(32, 'big'), True)
        assert_equal(b4_key.get_pubkey().get_bytes().hex(), helper.getaddressinfo(mixed[4])['spend_pubkey'])
        b4 = wif(b4_value)
        node1.createwallet(wallet_name='mweb_mix_p', blank=True)
        public_spend = node1.get_wallet_rpc('mweb_mix_p')
        res = public_spend.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{other_spend_pub},*)"),
                                               'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        account_cksum = res[0]['mweb_scan_account']
        assert_equal(import_one(public_spend, f"mweb({own_scan},{b4})"), account_cksum)
        new_addr = public_spend.getnewaddress(address_type='mweb')
        assert_equal(new_addr, mixed[5])
        miner.sendtoaddress(new_addr, Decimal('2.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        txid = public_spend.sendtoaddress(pay_to, Decimal('1.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(public_spend.gettransaction(txid)['confirmations'], 1)

        self.log.info("A wallet with private keys disabled takes the scan key but no spend key")
        node1.createwallet(wallet_name='mweb_mix_wo', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_mix_wo')
        res = watch.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{own_spend_pub},*)"),
                                        'timestamp': 0, 'active': True}])
        assert res[0]['success'], res[0].get('error')
        assert import_one(watch, f"mweb({own_scan},{spend_pub2})") != res[0]['mweb_scan_account']
        assert_equal(watch.getaddressinfo(mixed[2])['ismine'], True)
        for desc in (f"mweb({own_scan},{other_spend_priv},4)", f"mweb({own_scan},{b4})",
                     f"mweb({own_scan},{other_spend_priv},*)"):
            res = watch.importdescriptors([{'desc': descsum_create(desc), 'timestamp': 'now'}])
            assert_equal(res[0]['success'], False)
            assert_equal(res[0]['error']['message'], "Cannot import private keys to a wallet with private keys disabled")

        self.log.info("An account imported after a separate entry for its address owns and spends that coin")
        miner.sendtoaddress(mixed[6], Decimal('3.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        node1.createwallet(wallet_name='mweb_mix_q', blank=True)
        later = node1.get_wallet_rpc('mweb_mix_q')
        spend_pub6 = helper.getaddressinfo(mixed[6])['spend_pubkey']
        res = later.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{spend_pub6})"), 'timestamp': 0}])
        assert res[0]['success'], res[0].get('error')
        assert_equal([(c['amount'], c['spendable']) for c in later.listunspent(minconf=0, addresses=[mixed[6]])],
                     [(Decimal('3.0'), False)])
        res = later.importdescriptors([{'desc': descsum_create(f"mweb({own_scan},{other_spend_pub},*)"),
                                        'timestamp': 0, 'active': True}])
        assert res[0]['success'], res[0].get('error')
        assert_equal(import_one(later, f"mweb({own_scan},{other_spend_priv},6)"), res[0]['mweb_scan_account'])
        node1.unloadwallet('mweb_mix_q')
        node1.loadwallet('mweb_mix_q')
        later = node1.get_wallet_rpc('mweb_mix_q')
        assert_equal([(c['amount'], c['spendable']) for c in later.listunspent(minconf=0, addresses=[mixed[6]])],
                     [(Decimal('3.0'), True)])
        txid = later.sendtoaddress(pay_to, Decimal('2.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(later.gettransaction(txid)['confirmations'], 1)

    def test_private_account_import_pegout(self, miner, receiver, node1):
        self.log.info("Private account export→import→peg-out; watch-only sees spentness")
        # Owner with prior MWEB spends so import must not select already-spent coins.
        node1.createwallet(wallet_name='mweb_pegout_owner', blank=False, disable_private_keys=False)
        owner = node1.get_wallet_rpc('mweb_pegout_owner')
        prior = owner.getnewaddress(address_type='mweb')
        miner.sendtoaddress(prior, Decimal('3.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        # Create a confirmed prior spend from this account (history that must not be re-selected).
        owner.sendtoaddress(miner.getnewaddress(address_type='mweb'), Decimal('1.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        a0 = owner.getnewaddress(address_type='mweb')
        a1 = owner.getnewaddress(address_type='mweb')
        miner.sendtoaddress(a0, Decimal('5.0'))
        miner.sendtoaddress(a1, Decimal('4.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        private_account = get_mweb_account_descriptor(owner, private=True)
        assert private_account is not None, "private ranged mweb() account must be exportable"
        public_account = get_mweb_account_public_text(owner)
        watch_account = make_mweb_watchonly_account_descriptor(
            private_account['desc'], public_account)
        # Watch the funded addresses (and any prior change/receive internals the owner has).
        internals = get_mweb_internal_descriptors(owner)

        node1.createwallet(wallet_name='mweb_pegout_watch', blank=True, disable_private_keys=True)
        watch = node1.get_wallet_rpc('mweb_pegout_watch')
        watch_imports = [{'desc': watch_account, 'timestamp': 0, 'active': True}]
        watch_imports += [{'desc': e['desc'], 'timestamp': 0} for e in internals]
        watch_res = watch.importdescriptors(watch_imports)
        assert all(r.get('success') for r in watch_res), watch_res
        bal_watch_before = watch.getbalances()['mine']['trusted']
        assert_greater_than(bal_watch_before, Decimal('0'))
        # listunspent: watch-only MWEB coins are not spendable, as in Litecoin.
        watch_coins = watch.listunspent()
        assert watch_coins and not any(c['spendable'] for c in watch_coins), watch_coins

        node1.createwallet(wallet_name='mweb_pegout_spender', blank=True, disable_private_keys=False)
        spender = node1.get_wallet_rpc('mweb_pegout_spender')
        spend_import = spender.importdescriptors([{
            'desc': private_account['desc'],
            'timestamp': 0,
            'active': True,
            'range': [0, max(get_mweb_internal_index_for_address(owner, a0),
                             get_mweb_internal_index_for_address(owner, a1)) + 5],
        }])
        assert spend_import[0]['success'], spend_import[0].get('error')
        assert all(c['spendable'] for c in spender.listunspent())

        bal_spend = spender.getbalances()['mine']['trusted']
        assert_greater_than(bal_spend, Decimal('0'))
        # Imported spendable set must match watch (spent history excluded).
        assert_equal(bal_spend, bal_watch_before)
        def coin_set(wallet):
            return {(c['output_id'], c['amount'], c['address']) for c in wallet.listunspent()}
        assert_equal(coin_set(spender), coin_set(watch))

        pegout_addr = miner.getnewaddress(address_type='bech32')
        spend_amt = Decimal('2.0')
        bal_spend_before = bal_spend
        txid = spender.sendtoaddress(pegout_addr, spend_amt)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        self.wait_until(lambda: spender.gettransaction(txid)['confirmations'] >= 1)

        received = miner.listreceivedbyaddress(minconf=0, address_filter=pegout_addr)
        assert_equal(len(received), 1)
        assert_equal(received[0]['amount'], spend_amt)
        assert_greater_than(received[0]['confirmations'], 0)

        bal_spend_after = spender.getbalances()['mine']['trusted']
        assert_greater_than(bal_spend_before, bal_spend_after)
        fee = -spender.gettransaction(txid)['fee']
        assert_equal(bal_spend_before - bal_spend_after, spend_amt + fee)
        # Check the independently imported viewer's live update before a rescan
        # could repair missing spend notification or change discovery.
        bal_watch_live = watch.getbalances()['mine']['trusted']
        assert_equal(bal_watch_before - bal_watch_live, spend_amt + fee)
        assert_equal(bal_watch_live, bal_spend_after)
        assert_equal(coin_set(spender), coin_set(watch))

        tip_height = node1.getblockcount()
        watch.rescanblockchain(0, tip_height)
        bal_watch_after = watch.getbalances()['mine']['trusted']
        assert_greater_than(bal_watch_before, bal_watch_after)
        assert_equal(bal_watch_after, bal_spend_after)
        spender.rescanblockchain(0, tip_height)
        assert_equal(coin_set(spender), coin_set(watch))

    def test_internal_import_rejects_wrong_derivation(self, miner, receiver, node1):
        self.log.info("importdescriptors rejects remapped MWEB internals; INDEXED refuses reserved indices")
        addr = receiver.getnewaddress(address_type='mweb')
        internal = get_mweb_internal_descriptor_for_address(receiver, addr)
        account = get_mweb_account_descriptor(receiver, private=True)
        assert account is not None

        node1.createwallet(wallet_name='mweb_import_guard', blank=True)
        importer = node1.get_wallet_rpc('mweb_import_guard')
        result = importer.importdescriptors([{
            'desc': account['desc'],
            'timestamp': 0,
            'active': True,
        }])
        assert result[0]['success'], result[0].get('error')

        # Remap a known (A_i,B_i) onto the wrong index with the real account checksum.
        # Spend-secret wallets must reject — otherwise index maps poison spend keys.
        body = internal['desc'].split('#')[0]
        parts = body[body.index('(') + 1:body.rindex(')')].split(',')
        assert_equal(len(parts), 4)
        # mweb(A_i,B_i,i,acct_cksum)
        wrong_index = descsum_create(f"mweb({parts[0]},{parts[1]},99,{parts[3]})")
        remapped = importer.importdescriptors([{'desc': wrong_index, 'timestamp': 'now'}])
        assert_equal(remapped[0]['success'], False)
        assert 'do not match account derivation' in remapped[0]['error']['message']

        # Remapping a receive (A_i,B_i) onto CHANGE_INDEX=0 must fail derivation checks
        # (poisoned index maps). Honest change/pegin internals remain importable.
        reserved_change = descsum_create(f"mweb({parts[0]},{parts[1]},0,{parts[3]})")
        change_import = importer.importdescriptors([{'desc': reserved_change, 'timestamp': 'now'}])
        assert_equal(change_import[0]['success'], False)
        assert 'do not match account derivation' in change_import[0]['error']['message']

        # INDEXED form must still refuse reserved indices (change/pegin are local-only).
        priv_body = account['desc'].split('#')[0]
        scan_priv, spend_priv = priv_body[priv_body.index('(')+1:priv_body.rindex(')')].split(',')[:2]
        indexed_change = descsum_create(f"mweb({scan_priv},{spend_priv},0)")
        indexed_res = importer.importdescriptors([{'desc': indexed_change, 'timestamp': 'now'}])
        assert_equal(indexed_res[0]['success'], False)
        assert 'reserved' in indexed_res[0]['error']['message'].lower() or \
               'change or peg-in' in indexed_res[0]['error']['message']

        # Honest internal for a known address still imports.
        honest = importer.importdescriptors([{'desc': internal['desc'], 'timestamp': 0}])
        assert honest[0]['success'], honest[0].get('error')

    def test_import_scan_above_1000(self, miner, receiver, node1):
        self.log.info("Account import scan persists internal descriptors above index 1000")
        high_index = 1001
        receiver.keypoolrefill(high_index + 2)
        high_addr = None
        for i in range(high_index + 2):
            addr = receiver.getnewaddress(address_type='mweb')
            if i == high_index + 1:
                high_addr = addr
        high_index = get_mweb_internal_index_for_address(receiver, high_addr)
        assert_greater_than(high_index, 1000)

        miner.sendtoaddress(high_addr, 1)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        account = get_mweb_account_descriptor(receiver, private=True)
        assert account is not None
        node1.createwallet(wallet_name='mweb_import_scan', blank=True)
        importer = node1.get_wallet_rpc('mweb_import_scan')
        result = importer.importdescriptors([{
            'desc': account['desc'],
            'timestamp': 0,
            'active': True,
            'range': high_index + 5,
        }])
        assert result[0]['success'], result[0].get('error')
        assert 'mweb_scan_account' in result[0]

        matched = [
            d for d in get_mweb_internal_descriptors(importer)
            if f",{high_index}," in d['desc'].split('#')[0]
        ]
        assert_equal(len(matched), 1)
        assert_equal(importer.getaddressinfo(high_addr)['ismine'], True)

    def test_encrypt_unlock_mweb(self, miner, wallet):
        self.log.info("Encrypt descriptor wallet and exercise MWEB receive/spend")
        passphrase = 'multiacct'
        try:
            wallet.encryptwallet('encrypttest')
            passphrase = 'encrypttest'
        except JSONRPCException as e:
            if e.error['code'] != -15:
                raise

        miner_addr = miner.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, miner_addr, 1)

        with WalletUnlock(wallet, passphrase):
            txid = wallet.sendtoaddress(miner_addr, 1)
            self.sync_mempools()
            self.generate(self.nodes[0], 1)
            assert_equal(wallet.gettransaction(txid)['confirmations'], 1)

        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, miner_addr, 1)

    def test_receive_while_locked_then_spend(self, miner, wallet):
        self.log.info("Receive MWEB while locked, then unlock and spend")
        passphrase = 'encrypttest'
        try:
            wallet.encryptwallet(passphrase)
        except JSONRPCException as e:
            if e.error['code'] != -15:
                raise
            # Already encrypted from a prior test; keep using encrypttest if that was set,
            # otherwise fall back to multiacct from multi-account tests.
            try:
                wallet.walletpassphrase('encrypttest', 1)
                wallet.walletlock()
                passphrase = 'encrypttest'
            except JSONRPCException:
                passphrase = 'multiacct'

        with WalletUnlock(wallet, passphrase):
            recv_addr = wallet.getnewaddress(address_type='mweb')

        # Ensure wallet is locked for the receive.
        try:
            wallet.walletlock()
        except JSONRPCException:
            pass

        miner.sendtoaddress(recv_addr, 2)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        coins = wallet.listunspent(addresses=[recv_addr])
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['amount'], 2)

        miner_addr = miner.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, miner_addr, 1)

        with WalletUnlock(wallet, passphrase):
            spend_txid = wallet.sendtoaddress(miner_addr, 1)
            self.sync_mempools()
            self.generate(self.nodes[0], 1)
            assert_equal(wallet.gettransaction(spend_txid)['confirmations'], 1)

    def test_restart_while_locked_spend_requires_unlock(self, miner, wallet):
        self.log.info("Restart locked encrypted wallet: balances visible, spend needs unlock")
        passphrase = 'encrypttest'
        try:
            wallet.encryptwallet(passphrase)
        except JSONRPCException as e:
            if e.error['code'] != -15:
                raise
            try:
                wallet.walletpassphrase('encrypttest', 1)
                wallet.walletlock()
                passphrase = 'encrypttest'
            except JSONRPCException:
                passphrase = 'multiacct'

        with WalletUnlock(wallet, passphrase):
            recv_addr = wallet.getnewaddress(address_type='mweb')

        miner.sendtoaddress(recv_addr, 3)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # Receive while unlocked so coin exists, then lock and restart.
        with WalletUnlock(wallet, passphrase):
            coins = wallet.listunspent(addresses=[recv_addr])
            assert_equal(len(coins), 1)

        wallet_name = wallet.getwalletinfo()['walletname']
        try:
            wallet.walletlock()
        except JSONRPCException:
            pass

        self.nodes[1].unloadwallet(wallet_name)
        self.nodes[1].loadwallet(wallet_name)
        wallet = self.nodes[1].get_wallet_rpc(wallet_name)

        coins_after = wallet.listunspent(addresses=[recv_addr])
        assert_equal(len(coins_after), 1)
        assert_equal(coins_after[0]['amount'], 3)

        miner_addr = miner.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, miner_addr, 1)

        with WalletUnlock(wallet, passphrase):
            spend_txid = wallet.sendtoaddress(miner_addr, 1)
            self.sync_mempools()
            self.generate(self.nodes[0], 1)
            assert_equal(wallet.gettransaction(spend_txid)['confirmations'], 1)

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        miner = node0.get_wallet_rpc(self.default_wallet_name)
        receiver = node1.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Activate MWEB on regtest chain")
        setup_mweb_chain(node0, self)
        self.sync_all()

        self.test_account_and_internal_structure(receiver)
        self.test_mwebrescan(receiver)
        self.test_external_descriptor_rejected_on_import(receiver)
        self.test_public_scan_key_import(node1)
        self.test_max_index_import(node1)
        self.test_prune_spent_internal_descriptor(miner, receiver)
        self.test_mwebkeep_prevents_prune(miner, receiver)
        self.test_reuse_address_after_prune(miner, node1)
        self.test_external_descriptor_send_and_addressinfo(miner, receiver)
        self.test_watchonly_internal_import(miner, receiver, node1)
        self.test_watchonly_same_root_warns(receiver, node1)
        self.test_watchonly_public_export(miner, receiver, node1)
        self.test_watchonly_cannot_mint(miner, receiver, node1)
        self.test_indexed_import_sees_only_that_index(miner, receiver, node1)
        self.test_single_subaddr_import_reload_isolation(miner, receiver, node1)
        self.test_mixed_spend_key_imports(miner, node1)
        self.test_private_account_import_pegout(miner, receiver, node1)
        self.test_internal_import_rejects_wrong_derivation(miner, receiver, node1)
        self.test_import_scan_above_1000(miner, receiver, node1)
        self.test_multi_account_descriptors(receiver)
        self.test_legacy_ranged_descriptor_rejected(receiver)
        self.test_receive_reload_and_spend(miner, receiver)
        self.test_multi_account_selection_and_change_routing(miner, node1)
        self.test_changeless_window(miner, node1)
        self.test_mixed_mweb_l1_funding(miner, node1)
        self.test_mixed_recipients_allowed_multi_recipient(miner, node1)
        self.test_locked_wallet_funds_psbt(miner, node1)
        self.test_encryption_migration(miner, node1)
        self.test_multi_account_unlock_spend_inactive(miner, receiver)
        self.test_encrypt_unlock_mweb(miner, receiver)
        self.test_receive_while_locked_then_spend(miner, receiver)
        self.test_restart_while_locked_spend_requires_unlock(miner, receiver)


if __name__ == '__main__':
    MWEBDescriptorWalletTest(__file__).main()
