#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Litecoin-shaped MWEB fields in TxToUniv / decoderawtransaction.

decoderawtransaction and verbose getrawtransaction expose ismweb/output_id on
vin/vout and vkern for extension bodies, while pure L1 txs only gain
ismweb=false and have no vkern.

Note: after mining, HogEx absorbs MWEB bodies into the extension block, so
block.vtx entries are L1-only; Phase 4 covers structured getblock mweb.
"""

from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class MWEBTxJSONTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'])
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_side(self, entry, *, expect_mweb):
        assert 'ismweb' in entry
        assert_equal(entry['ismweb'], expect_mweb)
        if expect_mweb:
            assert 'output_id' in entry
            assert isinstance(entry['output_id'], str)
            assert_equal(len(entry['output_id']), 64)
            assert 'txid' not in entry
            assert 'vout' not in entry
            assert 'value' not in entry
            assert 'n' not in entry
            assert 'scriptPubKey' not in entry
            assert 'sequence' not in entry
        else:
            assert 'output_id' not in entry

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)

        self.log.info("Pure L1 decode: ismweb=false on all sides, no vkern")
        l1_addr = node.getnewaddress()
        l1_txid = node.sendtoaddress(l1_addr, 1)
        l1 = node.decoderawtransaction(node.gettransaction(l1_txid)['hex'])
        assert 'vkern' not in l1
        assert_greater_than(len(l1['vin']), 0)
        assert_greater_than(len(l1['vout']), 0)
        for vin in l1['vin']:
            self.assert_side(vin, expect_mweb=False)
            assert 'txid' in vin or 'coinbase' in vin
            assert 'sequence' in vin
        for vout in l1['vout']:
            self.assert_side(vout, expect_mweb=False)
            assert 'value' in vout and 'n' in vout and 'scriptPubKey' in vout
        self.generate(node, 1)

        self.log.info("MWEB send decode: MWEB vouts + vkern present")
        mweb_addr = node.getnewaddress(address_type='mweb')
        mweb_txid = node.sendtoaddress(mweb_addr, 1)
        decoded = node.decoderawtransaction(node.gettransaction(mweb_txid)['hex'])
        assert 'vkern' in decoded
        assert_greater_than(len(decoded['vkern']), 0)
        for kern in decoded['vkern']:
            for key in ('kernel_id', 'fee', 'pegin', 'pegout'):
                assert key in kern, f'missing vkern.{key}'
            assert isinstance(kern['pegout'], list)

        mweb_vouts = [v for v in decoded['vout'] if v['ismweb']]
        assert_greater_than(len(mweb_vouts), 0)
        for vin in decoded['vin']:
            self.assert_side(vin, expect_mweb=vin['ismweb'])
        for vout in decoded['vout']:
            self.assert_side(vout, expect_mweb=vout['ismweb'])

        verbose = node.getrawtransaction(mweb_txid, True)
        assert 'vkern' in verbose
        assert_equal(len(verbose['vkern']), len(decoded['vkern']))
        assert any(v['ismweb'] for v in verbose['vout'])

        self.generate(node, 1)

        self.log.info("MWEB-to-MWEB spend: vin includes spent MWEB output_id")
        child_addr = node.getnewaddress(address_type='mweb')
        child_txid = node.sendtoaddress(child_addr, 0.25)
        child_hex = node.gettransaction(child_txid)['hex']
        child = node.decoderawtransaction(child_hex)
        assert 'vkern' in child
        child_mweb_vins = [v for v in child['vin'] if v['ismweb']]
        assert_greater_than(len(child_mweb_vins), 0)
        for vin in child_mweb_vins:
            self.assert_side(vin, expect_mweb=True)
        assert any(v['ismweb'] for v in child['vout'])
        # vkern always exposes Litecoin pegout array key (empty for MWEB_TO_MWEB).
        assert all(isinstance(k['pegout'], list) for k in child['vkern'])

        self.log.info("Peg-out from an MWEB-only wallet populates vkern.pegout")
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name='mweb_only')
        mweb_only = node.get_wallet_rpc('mweb_only')
        only_addr = mweb_only.getnewaddress(address_type='mweb')
        default_wallet.sendtoaddress(only_addr, 1)
        self.generate(node, 1)
        pegout_addr = mweb_only.getnewaddress()
        pegout_txid = mweb_only.sendtoaddress(pegout_addr, 0.25)
        pegout = node.decoderawtransaction(mweb_only.gettransaction(pegout_txid)['hex'])
        assert 'vkern' in pegout, 'peg-out should carry an MWEB body'
        assert any(len(k['pegout']) > 0 for k in pegout['vkern']), 'expected pegout array entries'
        for kern in pegout['vkern']:
            for peg in kern['pegout']:
                assert 'value' in peg and 'scriptPubKey' in peg



if __name__ == '__main__':
    MWEBTxJSONTest(__file__).main()
