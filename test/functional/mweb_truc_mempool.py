#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""TRUC (v3) mempool policy combined with MWEB extension bodies.

Covers admission, 1p1c topology across MWEB depends edges (including
submitpackage), the L1 child size cap, package min-relay, sibling eviction / RBF, and wallet
`send(version=3)` construction for MWEB destinations (no version-byte hacks).
"""

from decimal import Decimal

from test_framework.mweb_util import (
    assert_l1_inputs_include,
    assert_pegout_payments_include,
    decode_wallet_tx,
    init_mweb_wallet,
    mweb_extra_args,
    mweb_unspent_output_ids,
    mweb_vin_output_ids,
    setup_mweb_chain,
    with_mweb_vbparams,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    DEFAULT_FEE,
    MiniWallet,
)

TRUC_CHILD_MAX_VSIZE = 1000


class MWEBTRUCMempoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'])
        self.num_nodes = 1

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def clear_mempool(self):
        self.generate(self.nodes[0], 1)
        assert_equal(self.nodes[0].getrawmempool(), [])

    def wallet(self, name=None):
        node = self.nodes[0]
        return node.get_wallet_rpc(name or self.default_wallet_name)

    def assert_bitcoin_cluster_fields(self, entry):
        for key in (
            'vsize', 'weight', 'time', 'height', 'descendantcount', 'descendantsize',
            'ancestorcount', 'ancestorsize', 'chunkweight', 'wtxid', 'fees', 'depends',
            'spentby', 'unbroadcast',
        ):
            assert key in entry, f'missing Bitcoin mempool field {key}'
        for key in ('base', 'modified', 'ancestor', 'descendant', 'chunk'):
            assert key in entry['fees'], f'missing fees.{key}'

    def assert_mweb_weight_fields(self, entry, *, expect_mweb_body):
        for key in ('mwebweight', 'descendantmwebweight', 'ancestormwebweight'):
            assert key in entry, f'missing {key}'
            assert isinstance(entry[key], int)
            assert entry[key] >= 0
        if expect_mweb_body:
            assert_greater_than(entry['mwebweight'], 0)
            assert 'mweb' in entry
            assert isinstance(entry['mweb'], dict)
        else:
            assert_equal(entry['mwebweight'], 0)
            assert 'mweb' not in entry

    def assert_tx_version(self, txid, expected):
        decoded = decode_wallet_tx(self.nodes[0], txid)
        assert_equal(decoded['version'], expected)
        return decoded

    def send_mweb(self, amount, *, version=3, pegout=False, wallet=None, inputs=None,
                  add_to_wallet=True, expect_broadcast=True):
        """Build via wallet `send` to an MWEB or L1 dest; assert construction + optional mempool."""
        node = self.nodes[0]
        w = wallet if wallet is not None else self.wallet()
        if pegout:
            dest = self.wallet().getnewaddress()
        else:
            dest = w.getnewaddress(address_type='mweb')

        before_oids = mweb_unspent_output_ids(w, minconf=0)
        options = {"add_to_wallet": add_to_wallet}
        if inputs is not None:
            options["inputs"] = inputs
            only_mweb = all('output_id' in i for i in inputs)
            only_l1 = all(('txid' in i and 'vout' in i) for i in inputs)
            # Preset-only MWEB spends must not pull extra coins (keeps depends exact).
            # L1 peg-in presets may add more L1 for fees/amount.
            options["add_inputs"] = False if only_mweb else True
            assert only_mweb or only_l1, 'inputs must be all MWEB output_id or all L1 outpoints'

        res = w.send(outputs={dest: amount}, options=options, version=version)
        assert_equal(res['complete'], True)

        if add_to_wallet:
            assert 'txid' in res
            txid = res['txid']
        else:
            assert 'hex' in res
            txid = node.decoderawtransaction(res['hex'])['txid']
            if expect_broadcast:
                txid = node.sendrawtransaction(res['hex'])

        decoded = self.assert_tx_version(txid, version)
        has_mweb_vin = any(v.get('ismweb') for v in decoded.get('vin', []))
        has_mweb_vout = any(v.get('ismweb') for v in decoded.get('vout', []))
        has_vkern = bool(decoded.get('vkern'))
        assert has_mweb_vin or has_mweb_vout or has_vkern, 'expected MWEB body on send result'

        if pegout:
            assert_pegout_payments_include(decoded, [(dest, amount)])
            assert has_mweb_vin, 'peg-out must spend MWEB inputs'
        elif inputs is not None and all('output_id' in i for i in inputs):
            assert_equal(mweb_vin_output_ids(decoded), {i['output_id'] for i in inputs})
        elif inputs is None and not pegout:
            # Auto path with MWEB balance: confidential MWEB→MWEB spends some prior MWEB oid.
            spent = mweb_vin_output_ids(decoded)
            assert spent, 'MWEB→MWEB send must expose ismweb vins'
            assert spent <= before_oids, f'spent unknown oids {spent - before_oids}'

        if expect_broadcast and add_to_wallet:
            assert txid in node.getrawmempool(), 'send should have broadcast into mempool'
            entry = node.getmempoolentry(txid)
            self.assert_bitcoin_cluster_fields(entry)
            self.assert_mweb_weight_fields(entry, expect_mweb_body=True)
            assert_greater_than(entry['fees']['base'], 0)

        return {'txid': txid, 'dest': dest, 'decoded': decoded, 'res': res,
                'spent_oids': mweb_vin_output_ids(decoded)}

    def ensure_mweb_balance(self, amount=Decimal('50')):
        """Top up default wallet MWEB via sendtoaddress peg-in (allowed auto peg-in path)."""
        w = self.wallet()
        dest = w.getnewaddress(address_type='mweb')
        txid = w.sendtoaddress(dest, amount)
        assert txid
        self.generate(self.nodes[0], 1)
        assert_greater_than(len(mweb_unspent_output_ids(w)), 0)

    def unconfirmed_mweb_utxos(self, wallet=None):
        w = wallet if wallet is not None else self.wallet()
        return [u for u in w.listunspent(0)
                if u.get('output_id') and u.get('confirmations', 0) == 0]

    def pick_unconfirmed_oid(self, wallet=None, *, amount=None):
        utxos = self.unconfirmed_mweb_utxos(wallet)
        assert utxos, 'expected unconfirmed MWEB outputs'
        if amount is not None:
            matched = [u for u in utxos if u['amount'] == amount]
            assert matched, f'no unconfirmed MWEB utxo with amount={amount}; have {[u["amount"] for u in utxos]}'
            return matched[0]['output_id']
        # Prefer smallest (usually the payment output) for chained spends.
        return sorted(utxos, key=lambda u: u['amount'])[0]['output_id']

    def build_send_hex(self, amount, *, version, wallet=None, pegout=False, output_id=None):
        """Construct via `send` without broadcasting; return (hex, txid, decoded)."""
        node = self.nodes[0]
        w = wallet if wallet is not None else self.wallet()
        dest = self.wallet().getnewaddress() if pegout else w.getnewaddress(address_type='mweb')
        options = {"add_to_wallet": False}
        if output_id is not None:
            options["inputs"] = [{"output_id": output_id}]
            options["add_inputs"] = False
        res = w.send(outputs={dest: amount}, options=options, version=version)
        assert_equal(res['complete'], True)
        assert 'hex' in res
        decoded = node.decoderawtransaction(res['hex'])
        # Prefer getrawtransaction-shaped fields when possible after a temporary submit isn't done;
        # decoderawtransaction is OK here for version / ismweb vin checks on MWEB→MWEB.
        assert_equal(decoded['version'], version)
        txid = decoded['txid']
        return res['hex'], txid, decoded, dest

    def assert_mempool_rejects_truc(self, tx_hex, *, mempool_before):
        node = self.nodes[0]
        assert_raises_rpc_error(-26, 'TRUC-violation', node.sendrawtransaction, tx_hex)
        assert_equal(set(node.getrawmempool()), set(mempool_before))

    def mweb_receive_oid(self, wallet, txid, amount):
        """Return the mweb_out id for a wallet receive of `amount` in `txid`."""
        tx = wallet.gettransaction(txid)
        matched = [d for d in tx.get('details', [])
                   if d.get('category') == 'receive'
                   and d.get('amount') == amount
                   and d.get('mweb_out')]
        assert matched, f'no mweb receive {amount} in {txid}; details={tx.get("details")}'
        return matched[0]['mweb_out']

    def test_v3_mweb_admission(self):
        node = self.nodes[0]
        self.log.info("send(version=3) → MWEB is admitted with positive mwebweight")
        out = self.send_mweb(1, version=3)
        entry = node.getmempoolentry(out['txid'])
        assert_equal(entry['ancestormwebweight'], entry['mwebweight'])
        assert_equal(entry['descendantmwebweight'], entry['mwebweight'])
        assert_equal(entry['ancestorcount'], 1)
        assert_equal(entry['descendantcount'], 1)
        self.clear_mempool()

    def test_v3_mweb_1p1c_topology(self):
        node = self.nodes[0]
        w = self.wallet()
        self.log.info("v3 MWEB parent → v3 MWEB child forms 1p1c with MWEB depends")
        parent = self.send_mweb(2, version=3)
        parent_entry = node.getmempoolentry(parent['txid'])
        parent_oid = self.pick_unconfirmed_oid(w, amount=Decimal('2'))

        child = self.send_mweb(
            Decimal('0.5'),
            version=3,
            inputs=[{"output_id": parent_oid}],
        )
        assert_equal(child['spent_oids'], {parent_oid})
        child_entry = node.getmempoolentry(child['txid'])
        assert parent['txid'] in child_entry['depends'], child_entry['depends']
        assert_equal(child_entry['ancestorcount'], 2)
        assert_equal(
            child_entry['ancestormwebweight'],
            parent_entry['mwebweight'] + child_entry['mwebweight'],
        )
        parent_after = node.getmempoolentry(parent['txid'])
        assert child['txid'] in parent_after['spentby']
        assert_equal(parent_after['descendantcount'], 2)
        assert_equal(
            parent_after['descendantmwebweight'],
            parent_entry['mwebweight'] + child_entry['mwebweight'],
        )
        assert_greater_than(TRUC_CHILD_MAX_VSIZE, child_entry['vsize'])
        self.clear_mempool()

    def test_v3_mweb_parent_pegout_child(self):
        node = self.nodes[0]
        default = self.wallet()
        self.log.info("Fund MWEB-only wallet, then send(version=3) peg-out under TRUC")
        node.createwallet(wallet_name='mweb_holder', load_on_startup=True)
        holder = self.wallet('mweb_holder')
        fund_dest = holder.getnewaddress(address_type='mweb')
        # sendtoaddress peg-in (product-allowed); then version-flip is NOT used — mine as v2 fund.
        fund_txid = default.sendtoaddress(fund_dest, 5)
        self.assert_tx_version(fund_txid, 2)
        self.generate(node, 1)
        assert fund_txid not in node.getrawmempool()
        assert_greater_than(holder.getbalance(), 4)
        assert_greater_than(len(mweb_unspent_output_ids(holder)), 0)

        pegout = self.send_mweb(Decimal('0.25'), version=3, pegout=True, wallet=holder)
        entry = node.getmempoolentry(pegout['txid'])
        assert_greater_than(len(entry['mweb']['pegouts']), 0)
        self.clear_mempool()

        self.log.info("v3 MWEB parent → v3 peg-out child under TRUC 1p1c")
        parent = self.send_mweb(Decimal('1.0'), version=3, wallet=holder)
        parent_entry = node.getmempoolentry(parent['txid'])

        child = self.send_mweb(Decimal('0.25'), version=3, pegout=True, wallet=holder)
        child_entry = node.getmempoolentry(child['txid'])
        assert parent['txid'] in child_entry['depends']
        assert_equal(child_entry['ancestorcount'], 2)
        assert_greater_than(len(child_entry['mweb']['pegouts']), 0)
        assert_equal(
            child_entry['ancestormwebweight'],
            parent_entry['mwebweight'] + child_entry['mwebweight'],
        )
        self.clear_mempool()

    def test_v3_mweb_third_hop_rejected(self):
        node = self.nodes[0]
        w = self.wallet()
        self.log.info("Third unconfirmed v3 MWEB hop is a TRUC topology violation")
        parent_amt = Decimal('2')
        child_amt = Decimal('0.75')
        parent = self.send_mweb(parent_amt, version=3)
        parent_oid = self.pick_unconfirmed_oid(w, amount=parent_amt)
        child = self.send_mweb(
            child_amt,
            version=3,
            inputs=[{"output_id": parent_oid}],
        )
        assert parent['txid'] in node.getmempoolentry(child['txid'])['depends']
        assert_equal(child['spent_oids'], {parent_oid})
        mempool_before = set(node.getrawmempool())
        assert_equal(mempool_before, {parent['txid'], child['txid']})

        # Force the grandchild to spend the child's payment output (3rd hop).
        child_oid = self.pick_unconfirmed_oid(w, amount=child_amt)
        hex_, txid, decoded, _ = self.build_send_hex(
            Decimal('0.1'), version=3, output_id=child_oid)
        assert_equal(mweb_vin_output_ids(decoded), {child_oid})
        assert txid not in mempool_before
        self.assert_mempool_rejects_truc(hex_, mempool_before=mempool_before)
        self.clear_mempool()

    def test_version_inheritance_across_mweb(self):
        node = self.nodes[0]
        w = self.wallet()
        self.log.info("Unconfirmed v3/v2 MWEB parents cannot mix versions with children")
        parent_amt = Decimal('2')
        parent_v3 = self.send_mweb(parent_amt, version=3)
        assert_equal(set(node.getrawmempool()), {parent_v3['txid']})
        oid = self.pick_unconfirmed_oid(w, amount=parent_amt)

        hex_v2, _, decoded_v2, _ = self.build_send_hex(
            Decimal('0.2'), version=2, output_id=oid)
        assert_equal(decoded_v2['version'], 2)
        assert_equal(mweb_vin_output_ids(decoded_v2), {oid})
        self.assert_mempool_rejects_truc(hex_v2, mempool_before={parent_v3['txid']})
        self.clear_mempool()

        parent_v2 = self.send_mweb(parent_amt, version=2)
        assert_equal(self.assert_tx_version(parent_v2['txid'], 2)['version'], 2)
        oid = self.pick_unconfirmed_oid(w, amount=parent_amt)
        hex_v3, _, decoded_v3, _ = self.build_send_hex(
            Decimal('0.2'), version=3, output_id=oid)
        assert_equal(decoded_v3['version'], 3)
        assert_equal(mweb_vin_output_ids(decoded_v3), {oid})
        self.assert_mempool_rejects_truc(hex_v3, mempool_before={parent_v2['txid']})
        self.clear_mempool()

    def test_l1_truc_child_size_with_mweb_activated(self):
        node = self.nodes[0]
        self.log.info("TRUC L1 child size cap still enforced when MWEB is active")
        parent = self.miniwallet.send_self_transfer(from_node=node, version=3)
        self.assert_mweb_weight_fields(node.getmempoolentry(parent['txid']), expect_mweb_body=False)

        heavy = self.miniwallet.create_self_transfer(
            utxo_to_spend=parent['new_utxo'],
            target_vsize=TRUC_CHILD_MAX_VSIZE + 1,
            version=3,
        )
        assert_greater_than_or_equal(heavy['tx'].get_vsize(), TRUC_CHILD_MAX_VSIZE)
        assert_raises_rpc_error(-26, 'TRUC-violation', node.sendrawtransaction, heavy['hex'])
        assert_equal(set(node.getrawmempool()), {parent['txid']})
        self.assert_mweb_weight_fields(node.getmempoolentry(parent['txid']), expect_mweb_body=False)
        self.clear_mempool()

    def test_package_fees_with_mweb_weight(self):
        node = self.nodes[0]
        # Recreate MiniWallet after prior tests; package L1 cases need a fresh view.
        self.miniwallet = MiniWallet(node)
        self.generate(self.miniwallet, 10)

        self.log.info("submitpackage: TRUC 0-fee L1 parent works with MWEB activated")
        parent = self.miniwallet.create_self_transfer(fee=0, fee_rate=0, confirmed_only=True, version=3)
        child = self.miniwallet.create_self_transfer(
            utxo_to_spend=parent['new_utxo'],
            fee_rate=DEFAULT_FEE * 10,
            version=3,
        )
        result = node.submitpackage([parent['hex'], child['hex']], maxfeerate=0)
        assert_equal(result['package_msg'], 'success')
        assert parent['txid'] in node.getrawmempool()
        assert child['txid'] in node.getrawmempool()
        self.clear_mempool()

        self.log.info("submitpackage: maxfeerate rates a peg-in's L1 vsize, not its MWEB fee")
        w = self.wallet()
        l1_utxo = next(u for u in w.listunspent(1) if 'vout' in u and not u.get('output_id') and u['amount'] > 2)
        pegin = w.send(outputs={w.getnewaddress(address_type='mweb'): Decimal('1')}, fee_rate=2,
                       options={"inputs": [{"txid": l1_utxo['txid'], "vout": l1_utxo['vout']}], "add_inputs": False, "add_to_wallet": False})
        accept = node.testmempoolaccept([pegin['hex']])[0]
        assert_greater_than(accept['vsize'], 0)
        maxfeerate = Decimal('0.00005')
        assert_greater_than(accept['fees']['base'] / accept['vsize'], maxfeerate / 1000)
        result = node.submitpackage([pegin['hex']], maxfeerate=maxfeerate)
        assert_equal(result['package_msg'], 'success')
        assert pegin['txid'] in node.getrawmempool()
        self.clear_mempool()

        self.log.info("submitpackage: a peg-in paying more than maxfeerate x vsize plus the MWEB allowance is refused")
        l1_utxo = next(u for u in w.listunspent(1) if 'vout' in u and not u.get('output_id') and u['amount'] > 2)
        pegin = w.send(outputs={w.getnewaddress(address_type='mweb'): Decimal('1')}, fee_rate=50,
                       options={"inputs": [{"txid": l1_utxo['txid'], "vout": l1_utxo['vout']}], "add_inputs": False, "add_to_wallet": False})
        accept = node.testmempoolaccept([pegin['hex']], 0)[0]
        assert_equal(accept['allowed'], True)
        # At 1 sat/kvB the L1 part of the cap is about 0 sat, while the 50 sat/vB L1 fee is far above the
        # 1,800-sat change allowance on top of the MWEB fee.
        assert_greater_than(accept['vsize'] * 50, 1_800 * 2)
        result = node.submitpackage([pegin['hex']], maxfeerate=Decimal('0.00000001'))
        assert_equal(result['package_msg'], 'transaction failed')
        assert_equal(result['tx-results'][accept['wtxid']]['error'], 'max feerate exceeded')
        assert pegin['txid'] not in node.getrawmempool()
        result = node.submitpackage([pegin['hex']], maxfeerate=Decimal('0.0006'))
        assert_equal(result['package_msg'], 'success')
        assert pegin['txid'] in node.getrawmempool()
        self.clear_mempool()

        self.log.info("0-fee L1 TRUC package under minrelay is rejected")
        dust_parent = self.miniwallet.create_self_transfer(fee=0, fee_rate=0, confirmed_only=True, version=3)
        dust_child = self.miniwallet.create_self_transfer(
            utxo_to_spend=dust_parent['new_utxo'],
            fee=0,
            fee_rate=0,
            version=3,
        )
        fail_pkg = node.submitpackage([dust_parent['hex'], dust_child['hex']], maxfeerate=0)
        assert_equal(fail_pkg['package_msg'], 'transaction failed')
        assert_equal(node.getrawmempool(), [])

        self.log.info("submitpackage: v3 MWEB 1p1c linked by an MWEB output is accepted")
        # Build both hexes without broadcasting so neither is already in the mempool.
        # Note: with -walletbroadcast=0, new MWEB outputs are absent from listunspent
        # until broadcast; use gettransaction details' mweb_out instead.
        self.restart_node(0, extra_args=with_mweb_vbparams(
            ['-whitelist=noban@127.0.0.1', '-walletbroadcast=0']))
        w = self.wallet()
        parent_amt = Decimal('2')
        child_amt = Decimal('0.4')
        parent_res = w.send(outputs={w.getnewaddress(address_type='mweb'): parent_amt}, version=3)
        assert_equal(parent_res['complete'], True)
        parent_txid = parent_res['txid']
        parent_hex = w.gettransaction(parent_txid)['hex']
        assert parent_txid not in node.getrawmempool()
        parent_dec = node.decoderawtransaction(parent_hex)
        assert_equal(parent_dec['version'], 3)
        assert any(v.get('ismweb') for v in parent_dec.get('vin', [])) or parent_dec.get('vkern')
        parent_oid = self.mweb_receive_oid(w, parent_txid, parent_amt)

        child_res = w.send(
            outputs={w.getnewaddress(address_type='mweb'): child_amt},
            options={"inputs": [{"output_id": parent_oid}], "add_inputs": False},
            version=3,
        )
        assert_equal(child_res['complete'], True)
        child_txid = child_res['txid']
        child_hex = w.gettransaction(child_txid)['hex']
        assert child_txid not in node.getrawmempool()
        child_dec = node.decoderawtransaction(child_hex)
        assert_equal(child_dec['version'], 3)
        assert_equal(mweb_vin_output_ids(child_dec), {parent_oid})

        result = node.submitpackage([parent_hex, child_hex], maxfeerate=0)
        assert_equal(result['package_msg'], 'success')
        assert_equal(set(node.getrawmempool()), {parent_txid, child_txid})
        child_entry = node.getmempoolentry(child_txid)
        assert_equal(child_entry['ancestorcount'], 2)
        assert_greater_than(TRUC_CHILD_MAX_VSIZE * 4, child_entry['weight'] + child_entry['mwebweight'])

        # Restore broadcast; abandon drafts and mine so wallet UTXO set is consistent.
        self.restart_node(0, extra_args=with_mweb_vbparams(['-whitelist=noban@127.0.0.1']))
        w = self.wallet()
        for txid in (parent_txid, child_txid):
            try:
                w.abandontransaction(txid)
            except Exception:
                pass
        self.clear_mempool()
        self.ensure_mweb_balance(Decimal('20'))

        self.log.info("Sequential send(version=3) MWEB parent+child admits with mwebweight fees")
        parent = self.send_mweb(2, version=3)
        oid = self.pick_unconfirmed_oid(w, amount=Decimal('2'))
        child = self.send_mweb(Decimal('0.4'), version=3, inputs=[{"output_id": oid}])
        parent_entry = node.getmempoolentry(parent['txid'])
        child_entry = node.getmempoolentry(child['txid'])
        assert parent['txid'] in child_entry['depends']
        assert_equal(child['spent_oids'], {oid})
        assert_equal(
            child_entry['ancestormwebweight'],
            parent_entry['mwebweight'] + child_entry['mwebweight'],
        )
        assert_greater_than(parent_entry['fees']['base'], 0)
        assert_greater_than(child_entry['fees']['base'], 0)
        self.clear_mempool()

    def test_sibling_eviction_and_rbf(self):
        node = self.nodes[0]
        self.log.info("TRUC sibling eviction works with MWEB activated (L1 cluster)")
        parent = self.miniwallet.send_self_transfer_multi(from_node=node, num_outputs=2, version=3)
        child1 = self.miniwallet.send_self_transfer(
            from_node=node,
            utxo_to_spend=parent['new_utxos'][0],
            fee_rate=DEFAULT_FEE * 2,
            version=3,
        )
        assert child1['txid'] in node.getrawmempool()

        too_cheap = self.miniwallet.create_self_transfer(
            utxo_to_spend=parent['new_utxos'][1],
            fee_rate=DEFAULT_FEE,
            version=3,
        )
        assert_raises_rpc_error(
            -26,
            'insufficient fee (including sibling eviction)',
            node.sendrawtransaction,
            too_cheap['hex'],
        )
        assert_equal(set(node.getrawmempool()), {parent['txid'], child1['txid']})

        child2 = self.miniwallet.create_self_transfer(
            utxo_to_spend=parent['new_utxos'][1],
            fee_rate=DEFAULT_FEE * 10,
            version=3,
        )
        node.sendrawtransaction(child2['hex'])
        assert_equal(set(node.getrawmempool()), {parent['txid'], child2['txid']})
        self.clear_mempool()

        self.log.info("RBF replaces an unconfirmed v3 L1 tx with MWEB activated")
        utxo = self.miniwallet.get_utxo(confirmed_only=True)
        self.miniwallet.send_self_transfer(
            from_node=node, version=3, fee_rate=DEFAULT_FEE, utxo_to_spend=utxo)
        rbf = self.miniwallet.create_self_transfer(
            version=3, fee_rate=DEFAULT_FEE * 10, utxo_to_spend=utxo)
        node.sendrawtransaction(rbf['hex'])
        assert_equal(set(node.getrawmempool()), {rbf['txid']})
        self.clear_mempool()

    def test_wallet_truc_version_gates(self):
        node = self.nodes[0]
        w = self.wallet()
        self.log.info("send(version=3) works for L1 outputs under MWEB activation")
        l1 = w.getnewaddress()
        res = w.send(outputs={l1: 1}, version=3)
        assert_equal(res['complete'], True)
        decoded = self.assert_tx_version(res['txid'], 3)
        assert not any(v.get('ismweb') for v in decoded.get('vin', []))
        assert res['txid'] in node.getrawmempool()
        entry = node.getmempoolentry(res['txid'])
        self.assert_mweb_weight_fields(entry, expect_mweb_body=False)
        self.clear_mempool()

        self.log.info("send(version=3) → MWEB with explicit L1 inputs is implied peg-in")
        l1_utxos = [u for u in w.listunspent(1) if 'vout' in u and not u.get('output_id')]
        assert_greater_than(len(l1_utxos), 0)
        preset = {'txid': l1_utxos[0]['txid'], 'vout': l1_utxos[0]['vout']}
        out = self.send_mweb(
            Decimal('0.5'),
            version=3,
            inputs=[preset],
        )
        assert_l1_inputs_include(out['decoded'], {(preset['txid'], preset['vout'])})
        self.clear_mempool()

        self.log.info("send → MWEB with only L1 funds and no inputs is a hard error (not crash)")
        node.createwallet(wallet_name='l1_only_truc', load_on_startup=False)
        l1w = self.wallet('l1_only_truc')
        w.sendtoaddress(l1w.getnewaddress(), 10)
        self.generate(node, 1)
        assert_equal(len(mweb_unspent_output_ids(l1w)), 0)
        before = {t['txid'] for t in l1w.listtransactions("*", 10000) if 'txid' in t}
        dest = w.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(
            -4,
            'Insufficient MWEB funds for a confidential send',
            l1w.send,
            outputs={dest: Decimal('1.0')},
            version=3,
        )
        after = {t['txid'] for t in l1w.listtransactions("*", 10000) if 'txid' in t}
        assert_equal(after, before)
        assert_equal(node.getrawmempool(), [])
        node.unloadwallet('l1_only_truc')

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        self.ensure_mweb_balance(Decimal('50'))
        self.miniwallet = MiniWallet(node)
        self.generate(self.miniwallet, 120)

        self.test_v3_mweb_admission()
        self.test_v3_mweb_1p1c_topology()
        self.test_v3_mweb_parent_pegout_child()
        self.test_v3_mweb_third_hop_rejected()
        self.test_version_inheritance_across_mweb()
        # L1 MiniWallet cases before any node restart that would stale its UTXO set.
        self.test_l1_truc_child_size_with_mweb_activated()
        self.test_sibling_eviction_and_rbf()
        self.test_package_fees_with_mweb_weight()
        self.test_wallet_truc_version_gates()


if __name__ == '__main__':
    MWEBTRUCMempoolTest(__file__).main()
