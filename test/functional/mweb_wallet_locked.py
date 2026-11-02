#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test an encrypted MWEB wallet scanning and making addresses while locked, and the checks on its records."""

import os
import sqlite3
from decimal import Decimal
from io import BytesIO

from test_framework.crypto.secp256k1 import GE
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey
from test_framework.messages import deser_string, ser_string
from test_framework.mweb_util import (
    get_mweb_account_descriptor,
    get_mweb_internal_descriptors,
    init_mweb_wallet,
    is_mweb_account_desc_body,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.segwit_addr import Encoding, bech32_encode, convertbits
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import bytes_to_wif

PASSPHRASE = 'locked-pass'
SCAN_KEY_PREFIX = ser_string(b'mwebscank')
INTERNAL_PREFIX = ser_string(b'mwebinternaldesc')
DESCRIPTOR_PREFIX = ser_string(b'walletdescriptor')
CACHE_PREFIX = ser_string(b'walletdescriptorcache')
LH_CACHE_PREFIX = ser_string(b'walletdescriptorlhcache')
SPEND_KEY_EXPRESSION = (1).to_bytes(4, 'little')


def mweb_address(hrp, scan_pubkey, spend_pubkey):
    return bech32_encode(Encoding.BECH32, hrp, [0] + convertbits(scan_pubkey + spend_pubkey, 8, 5))


def random_key():
    key = ECKey()
    key.generate()
    return key


class MWEBWalletLockedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wallet_db(self, name):
        return sqlite3.connect(self.nodes[1].wallets_path / name / self.wallet_data_filename)

    def records(self, name, prefix, entry_id=b''):
        conn = self.wallet_db(name)
        rows = [(k, v) for k, v in conn.execute('SELECT key, value FROM main') if k.startswith(prefix + entry_id)]
        conn.close()
        return rows

    def replace_records(self, name, replacements):
        conn = self.wallet_db(name)
        with conn:
            for key, value in replacements:
                if value is None:
                    conn.execute('DELETE FROM main WHERE key = ?', (key,))
                else:
                    conn.execute('UPDATE main SET value = ? WHERE key = ?', (value, key))
        conn.close()

    def mweb_account_ids(self, name):
        """The ids of the wallet's MWEB accounts, in the order the wallet checks them while locked."""
        ids = []
        for key, value in self.records(name, DESCRIPTOR_PREFIX):
            if is_mweb_account_desc_body(deser_string(BytesIO(value)).decode().split('#')[0]):
                ids.append(key[len(DESCRIPTOR_PREFIX):])
        return sorted(ids)

    def cached_spend_pubkey(self, name, entry_id):
        [(key, value)] = [(k, v) for k, v in self.records(name, CACHE_PREFIX, entry_id) if k.endswith(SPEND_KEY_EXPRESSION) and len(k) == len(CACHE_PREFIX) + 36]
        return key, value

    def internal_replacements(self, name, entry_id, attacker):
        """The entry's internal records, each rewritten with the attacker's record at the same index."""
        attacker_records = {}
        for entry in get_mweb_internal_descriptors(attacker):
            body = entry['desc'].split('#')[0]
            attacker_records[int(body.split(',')[2])] = body
        replacements = []
        for key, value in self.records(name, INTERNAL_PREFIX, entry_id):
            index = int.from_bytes(key[-4:], 'little')
            stream = BytesIO(value)
            account_cksum = deser_string(stream).decode().split('#')[0][:-1].split(',')[3]
            body = attacker_records[index][:-1].rsplit(',', 1)[0] + f",{account_cksum})"
            replacements.append((key, ser_string(descsum_create(body).encode()) + stream.read()))
        return replacements

    def fund(self, *payments):
        for address, amount in payments:
            self.nodes[0].sendtoaddress(address, amount)
        self.sync_mempools()
        self.generate(self.nodes[0], 1)

    def new_locked_wallet(self, name):
        self.nodes[1].createwallet(wallet_name=name, passphrase=PASSPHRASE)
        return self.nodes[1].get_wallet_rpc(name)

    def run_test(self):
        setup_mweb_chain(self.nodes[0], self)
        self.test_locked_restart()
        self.test_encrypted_later()
        self.test_imported_entries()
        self.test_records_written_at_unlock()
        self.test_scan_key_mismatch()
        self.test_replaced_scan_key()
        self.test_reimported_scan_key()
        self.test_replaced_spend_key()

    def test_locked_restart(self):
        self.log.info("An encrypted wallet restarted while locked scans and makes MWEB addresses")
        node1 = self.nodes[1]
        wallet = self.new_locked_wallet('locked')
        old_addr = wallet.getnewaddress(address_type='mweb')

        self.restart_node(1)
        self.connect_nodes(0, 1)
        node1.loadwallet('locked')
        wallet = node1.get_wallet_rpc('locked')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)

        new_addr = wallet.getnewaddress(address_type='mweb')
        assert new_addr != old_addr
        info = wallet.getaddressinfo(new_addr)
        assert_equal(info['ismine'], True)
        assert_equal(info['solvable'], True)
        assert info['desc'].startswith('mweb(['), info
        assert info['hdkeypath'].startswith('x/')
        assert_equal(info['parent_desc'], get_mweb_account_descriptor(wallet)['desc'])

        self.fund((old_addr, Decimal('1.5')), (new_addr, Decimal('2.5')))
        assert_equal(wallet.getbalances()['mine']['trusted'], Decimal('4.0'))
        assert_raises_rpc_error(-13, "passphrase", wallet.sendtoaddress, self.nodes[0].getnewaddress(address_type='mweb'), 1)

        wallet.walletpassphrase(PASSPHRASE, 60)
        txid = wallet.sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), Decimal('3.0'))
        self.sync_mempools()
        self.generate(self.nodes[0], 1)
        assert_equal(wallet.gettransaction(txid)['confirmations'], 1)
        wallet.walletlock()

    def test_encrypted_later(self):
        self.log.info("A wallet encrypted after creation scans with both its old and its new account while locked")
        node1 = self.nodes[1]
        node1.createwallet(wallet_name='enc_later')
        wallet = node1.get_wallet_rpc('enc_later')
        old_addr = wallet.getnewaddress(address_type='mweb')
        wallet.encryptwallet(PASSPHRASE)
        new_addr = wallet.getnewaddress(address_type='mweb')
        assert wallet.getaddressinfo(new_addr)['parent_desc'] != wallet.getaddressinfo(old_addr)['parent_desc']

        node1.unloadwallet('enc_later')
        node1.loadwallet('enc_later')
        wallet = node1.get_wallet_rpc('enc_later')
        self.fund((old_addr, Decimal('0.75')), (new_addr, Decimal('1.25')))
        assert_equal(wallet.getbalances()['mine']['trusted'], Decimal('2.0'))

    def test_imported_entries(self):
        self.log.info("Imported entries scan and make addresses while locked: an account with a hardened spend path, and a single address")
        node1 = self.nodes[1]
        wallet = self.new_locked_wallet('imported')
        node1.createwallet(wallet_name='imported_keys')
        xprv = node1.get_wallet_rpc('imported_keys').gethdkeys(private=True)[0]['xprv']

        own = wallet.getnewaddress(address_type='mweb')
        own_info = wallet.getaddressinfo(own)
        hrp = own.rsplit('1', 1)[0]
        assert_equal(mweb_address(hrp, bytes.fromhex(own_info['scan_pubkey']), bytes.fromhex(own_info['spend_pubkey'])), own)
        scan = random_key()
        spend_pubkey = random_key().get_pubkey().get_bytes()
        single = mweb_address(hrp, (scan.secret * GE.from_bytes(spend_pubkey)).to_bytes_compressed(), spend_pubkey)

        wallet.walletpassphrase(PASSPHRASE, 60)
        res = wallet.importdescriptors([
            {'desc': descsum_create(f"mweb({bytes_to_wif(random_key().get_bytes())},{xprv}/7h,*)"), 'timestamp': 'now', 'active': True},
            {'desc': descsum_create(f"mweb({bytes_to_wif(scan.get_bytes())},{spend_pubkey.hex()})"), 'timestamp': 'now'},
        ])
        assert all(r['success'] for r in res), res
        wallet.walletlock()

        node1.unloadwallet('imported')
        node1.loadwallet('imported')
        wallet = node1.get_wallet_rpc('imported')
        account_addr = wallet.getnewaddress(address_type='mweb')
        assert '/7h' in wallet.getaddressinfo(account_addr)['parent_desc']
        assert_equal(wallet.getaddressinfo(single)['ismine'], True)
        self.fund((account_addr, Decimal('0.5')), (single, Decimal('0.25')))
        assert_equal(wallet.getbalances()['mine']['trusted'], Decimal('0.75'))

    def test_records_written_at_unlock(self):
        self.log.info("A wallet without the scan key record and the descriptor cache gains both at its next unlock")
        node1 = self.nodes[1]
        wallet = self.new_locked_wallet('no_record')
        addr = wallet.getnewaddress(address_type='mweb')
        node1.unloadwallet('no_record')
        [entry_id] = self.mweb_account_ids('no_record')
        removed = {prefix: self.records('no_record', prefix, entry_id) for prefix in (SCAN_KEY_PREFIX, CACHE_PREFIX, LH_CACHE_PREFIX)}
        assert removed[SCAN_KEY_PREFIX] and removed[CACHE_PREFIX]
        self.replace_records('no_record', [(key, None) for rows in removed.values() for key, _ in rows])

        node1.loadwallet('no_record')
        wallet = node1.get_wallet_rpc('no_record')
        assert_raises_rpc_error(None, None, wallet.getnewaddress, address_type='mweb')
        wallet.walletpassphrase(PASSPHRASE, 60)
        wallet.walletlock()
        node1.unloadwallet('no_record')
        for prefix in (SCAN_KEY_PREFIX, CACHE_PREFIX):
            assert_equal(sorted(self.records('no_record', prefix, entry_id)), sorted(removed[prefix]))

        node1.loadwallet('no_record')
        wallet = node1.get_wallet_rpc('no_record')
        wallet.getnewaddress(address_type='mweb')
        self.fund((addr, Decimal('1.0')))
        assert_equal(wallet.getbalances()['mine']['trusted'], Decimal('1.0'))

    def test_scan_key_mismatch(self):
        self.log.info("A scan key record that does not match the wallet fails the load")
        node1 = self.nodes[1]
        wallet = self.new_locked_wallet('bad_scan')
        wallet.getnewaddress(address_type='mweb')
        node1.unloadwallet('bad_scan')
        self.replace_records('bad_scan', [(key, value[:-32] + os.urandom(32)) for key, value in self.records('bad_scan', SCAN_KEY_PREFIX)])
        with node1.assert_debug_log(["the internal record at index 0 does not match the account's keys"]):
            assert_raises_rpc_error(-4, "Wallet corrupted", node1.loadwallet, 'bad_scan')

        self.log.info("An unencrypted wallet checks the scan key record against its keys")
        node1.createwallet(wallet_name='bad_scan_plain')
        node1.unloadwallet('bad_scan_plain')
        self.replace_records('bad_scan_plain', [(key, value[:-32] + os.urandom(32)) for key, value in self.records('bad_scan_plain', SCAN_KEY_PREFIX)])
        with node1.assert_debug_log(["the scan key derived from the wallet's keys does not match the wallet's scan key record"]):
            assert_raises_rpc_error(-4, "Wallet corrupted", node1.loadwallet, 'bad_scan_plain')

    def test_replaced_scan_key(self):
        self.log.info("A scan key replaced along with consistent records loads locked, but the unlock refuses it")
        node1 = self.nodes[1]
        victim = self.new_locked_wallet('scan_victim')
        victim.getnewaddress(address_type='mweb')
        node1.createwallet(wallet_name='scan_donor')
        donor_account = get_mweb_account_descriptor(node1.get_wallet_rpc('scan_donor'), private=True)['desc']
        victim.walletpassphrase(PASSPHRASE, 60)
        res = victim.importdescriptors([{'desc': donor_account, 'timestamp': 'now'}])
        assert res[0]['success'], res[0].get('error')
        victim.walletlock()
        node1.unloadwallet('scan_victim')

        # The wallet checks its accounts in id order, so the second one fails after the first unlocked.
        _, target_id = self.mweb_account_ids('scan_victim')
        spend_pubkey = self.cached_spend_pubkey('scan_victim', target_id)[1][-33:]
        attacker_scan = random_key()
        node1.createwallet(wallet_name='scan_attacker', blank=True, disable_private_keys=True)
        attacker = node1.get_wallet_rpc('scan_attacker')
        res = attacker.importdescriptors([{'desc': descsum_create(f"mweb({bytes_to_wif(attacker_scan.get_bytes())},{spend_pubkey.hex()},*)"),
                                           'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        for _ in range(max(int.from_bytes(key[-4:], 'little') for key, _ in self.records('scan_victim', INTERNAL_PREFIX, target_id)) - 1):
            attacker.getnewaddress(address_type='mweb')
        replacements = self.internal_replacements('scan_victim', target_id, attacker)
        assert replacements
        replacements += [(key, value[:-32] + attacker_scan.get_bytes()) for key, value in self.records('scan_victim', SCAN_KEY_PREFIX, target_id)]
        self.replace_records('scan_victim', replacements)

        node1.loadwallet('scan_victim')
        victim = node1.get_wallet_rpc('scan_victim')
        self.fund((victim.getnewaddress(address_type='mweb'), Decimal('1.0')))
        message = "the scan key derived from the wallet's keys does not match the wallet's scan key record"
        with node1.assert_debug_log([message]):
            assert_raises_rpc_error(-4, message, victim.walletpassphrase, PASSPHRASE, 60)
        assert_equal(victim.getwalletinfo()['unlocked_until'], 0)
        assert_raises_rpc_error(-13, "passphrase", victim.sendtoaddress, self.nodes[0].getnewaddress(address_type='mweb'), Decimal('0.5'))
        assert_raises_rpc_error(-4, message, victim.walletpassphrasechange, PASSPHRASE, 'other-pass')
        assert_equal(victim.getwalletinfo()['unlocked_until'], 0)
        assert_raises_rpc_error(-14, "The wallet passphrase entered was incorrect", victim.walletpassphrase, 'wrong-pass', 60)
        assert_raises_rpc_error(-14, "The wallet passphrase entered was incorrect", victim.walletpassphrasechange, 'wrong-pass', 'other-pass')

    def test_reimported_scan_key(self):
        self.log.info("A watch-only entry refuses a re-imported scan key that differs from its scan key record")
        node1 = self.nodes[1]
        scan = random_key()
        spend_pubkey = random_key().get_pubkey().get_bytes()
        desc = descsum_create(f"mweb({bytes_to_wif(scan.get_bytes())},{spend_pubkey.hex()},*)")
        node1.createwallet(wallet_name='watch_victim', blank=True, disable_private_keys=True)
        victim = node1.get_wallet_rpc('watch_victim')
        res = victim.importdescriptors([{'desc': desc, 'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        victim.getnewaddress(address_type='mweb')
        node1.unloadwallet('watch_victim')

        [entry_id] = self.mweb_account_ids('watch_victim')
        attacker_scan = random_key()
        node1.createwallet(wallet_name='watch_attacker', blank=True, disable_private_keys=True)
        attacker = node1.get_wallet_rpc('watch_attacker')
        res = attacker.importdescriptors([{'desc': descsum_create(f"mweb({bytes_to_wif(attacker_scan.get_bytes())},{spend_pubkey.hex()},*)"),
                                           'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        attacker.getnewaddress(address_type='mweb')
        replacements = self.internal_replacements('watch_victim', entry_id, attacker)
        replacements += [(key, value[:-32] + attacker_scan.get_bytes()) for key, value in self.records('watch_victim', SCAN_KEY_PREFIX, entry_id)]
        self.replace_records('watch_victim', replacements)

        node1.loadwallet('watch_victim')
        victim = node1.get_wallet_rpc('watch_victim')
        message = "the imported scan key does not match the wallet's scan key record"
        res = victim.importdescriptors([{'desc': desc, 'timestamp': 'now', 'active': True}])
        assert not res[0]['success']
        assert message in res[0]['error']['message'], res[0]
        assert_raises_rpc_error(-4, "This wallet has no available keys", victim.getnewaddress, address_type='mweb')
        node1.unloadwallet('watch_victim')
        assert_equal([value[-32:] for _, value in self.records('watch_victim', SCAN_KEY_PREFIX, entry_id)], [attacker_scan.get_bytes()])

    def test_replaced_spend_key(self):
        self.log.info("Records replaced with another spend key fail the load unless the cached spend key is replaced too")
        node1 = self.nodes[1]
        victim = self.new_locked_wallet('victim')
        for _ in range(3):
            victim.getnewaddress(address_type='mweb')
        scan = get_mweb_account_descriptor(victim)['desc'].split('#')[0][len('mweb('):].split(',')[0]

        # The scan key is readable without the passphrase, so whoever can write the file can derive
        # consistent records for a spend key of their own.
        spend_key = random_key()
        node1.createwallet(wallet_name='attacker', blank=True)
        attacker = node1.get_wallet_rpc('attacker')
        res = attacker.importdescriptors([{'desc': descsum_create(f"mweb({scan},{bytes_to_wif(spend_key.get_bytes())},*)"),
                                           'timestamp': 'now', 'active': True}])
        assert res[0]['success'], res[0].get('error')
        for _ in range(3):
            attacker.getnewaddress(address_type='mweb')

        node1.unloadwallet('victim')
        [entry_id] = self.mweb_account_ids('victim')
        replacements = self.internal_replacements('victim', entry_id, attacker)
        assert_equal(len(replacements), 5)

        self.log.info("One replaced record fails the load")
        self.replace_records('victim', [(key, value) for key, value in replacements if int.from_bytes(key[-4:], 'little') == 3])
        with node1.assert_debug_log(["the internal record at index 3 does not match the account's keys"]):
            assert_raises_rpc_error(-4, "Wallet corrupted", node1.loadwallet, 'victim')

        self.log.info("Every record replaced still fails the load against the cached spend key")
        self.replace_records('victim', replacements)
        with node1.assert_debug_log(["the internal record at index 0 does not match the account's keys"]):
            assert_raises_rpc_error(-4, "Wallet corrupted", node1.loadwallet, 'victim')

        self.log.info("With the cached spend key replaced too, the wallet loads locked, but the unlock refuses it")
        cache_key, cache_value = self.cached_spend_pubkey('victim', entry_id)
        self.replace_records('victim', [(cache_key, cache_value[:-33] + spend_key.get_pubkey().get_bytes())])
        node1.loadwallet('victim')
        victim = node1.get_wallet_rpc('victim')
        planted = victim.getnewaddress(address_type='mweb')
        assert_equal(attacker.getnewaddress(address_type='mweb'), planted)
        assert_raises_rpc_error(-4, "the decrypted spend key does not match the spend public key used while the wallet was locked",
                                victim.walletpassphrase, PASSPHRASE, 60)
        assert_equal(victim.getwalletinfo()['unlocked_until'], 0)
        assert_raises_rpc_error(-12, "No addresses available", victim.getnewaddress, address_type='mweb')


if __name__ == '__main__':
    MWEBWalletLockedTest(__file__).main()
