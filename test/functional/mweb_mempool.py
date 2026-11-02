#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that relayed MWEB-only transactions are listed by every node's mempool RPCs,
that -rpcserialversion=1 leaves MWEB data out of raw output, and that locally
submitted packages follow MWEB parent-child links and MWEB input conflicts.

Ported from Litecoin Core's mweb_mempool.py. Litecoin also runs a node with
-rpcserialversion=0; Bitcoin Core removed that value, so here it is an init error.
"""

from decimal import Decimal
import http.client
import json
import urllib.parse

from test_framework.messages import COIN, CTransaction, Hash, MWEBTxBody, MWEBTransaction, blake3, tx_from_hex
from test_framework.mweb_util import generate, init_mweb_wallet, mweb_extra_args, mweb_unspent_output_ids, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

# secp256k1 group order (blinding-factor arithmetic)
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _pedersen_blind_sum(wire_blinds):
    """Sum MWEB blinding factors from their on-wire (BigInt) byte order."""
    accumulator = 0
    for blind in wire_blinds:
        scalar = int.from_bytes(blind, 'big')
        if scalar >= _SECP256K1_ORDER:
            return None
        accumulator = (accumulator + scalar) % _SECP256K1_ORDER
    return accumulator.to_bytes(32, 'big')


def _kernel_supply_change(kernel):
    pegin = kernel.pegin or 0
    fee = kernel.fee or 0
    pegout = sum(p.amount for p in (kernel.pegouts or []))
    return pegin - fee - pegout


def mweb_aggregate_txs(txs):
    """Aggregate independently signed MWEB bodies the way Aggregation::Aggregate does."""
    if not txs:
        return None
    if len(txs) == 1:
        return txs[0]

    inputs = []
    outputs = []
    kernels = []
    kernel_offsets = []
    stealth_offsets = []
    for tx in txs:
        inputs.extend(tx.body.inputs)
        outputs.extend(tx.body.outputs)
        kernels.extend(tx.body.kernels)
        kernel_offsets.append(tx.kernel_offset.to_byte_arr())
        stealth_offsets.append(tx.stealth_offset.to_byte_arr())

    kernel_offset = Hash.from_byte_arr(_pedersen_blind_sum(kernel_offsets))
    stealth_offset = Hash.from_byte_arr(_pedersen_blind_sum(stealth_offsets))

    inputs.sort(key=lambda inp: inp.output_id.to_byte_arr())
    outputs.sort(key=lambda out: out.hash.to_byte_arr())
    kernels.sort(key=lambda kern: (-_kernel_supply_change(kern), kern.hash.to_byte_arr()))

    body = MWEBTxBody()
    body.inputs = inputs
    body.outputs = outputs
    body.kernels = kernels
    aggregated = MWEBTransaction()
    aggregated.kernel_offset = kernel_offset
    aggregated.stealth_offset = stealth_offset
    aggregated.body = body
    aggregated.rehash()
    return aggregated


class MWEBMempoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1', '-rpcserialversion=1', '-rest'],
            ['-whitelist=noban@127.0.0.1'],
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def rest_get(self, node, path):
        url = urllib.parse.urlparse(node.url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request('GET', path)
        response = conn.getresponse()
        assert_equal(response.status, 200)
        return response.read()

    def rest_hex(self, node, path):
        return self.rest_get(node, path).decode('ascii').strip()

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("Setup MWEB chain")
        setup_mweb_chain(node0, self)

        self.log.info("Pegin some coins")
        node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), 10)
        generate(node0, 1)
        self.sync_all()

        self.log.info("Create an MWEB-to-MWEB transaction")
        txid = node0.sendtoaddress(node1.getnewaddress(address_type='mweb'), 2)
        self.sync_all()

        decoded = node0.getrawtransaction(txid, True)
        assert decoded['vin'] and decoded['vout']
        assert all(entry.get('ismweb') for entry in decoded['vin'] + decoded['vout']), decoded

        self.log.info("Every node lists the txid")
        for node in self.nodes:
            assert_equal([txid], node.getrawmempool())

        self.log.info("getmempoolentry refuses MWEB-only transactions under -rpcserialversion<2")
        assert node0.getmempoolentry(txid) is not None
        assert node2.getmempoolentry(txid) is not None
        assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", node1.getmempoolentry, txid)

        self.log.info("-rpcserialversion=1 leaves MWEB data out of raw transaction hex")
        full_tx_hex = node0.getrawtransaction(txid)
        stripped_tx_hex = node1.getrawtransaction(txid)
        assert_greater_than(len(full_tx_hex), len(stripped_tx_hex))
        assert_equal(node1.getrawtransaction(txid, True)['hex'], stripped_tx_hex)
        assert_equal(self.rest_hex(node1, f'/rest/tx/{txid}.hex'), stripped_tx_hex)
        assert_equal(self.rest_get(node1, f'/rest/tx/{txid}.bin'), bytes.fromhex(stripped_tx_hex))
        self.wait_until(lambda: txid in [tx['txid'] for tx in node1.listtransactions()])
        assert_equal(node1.gettransaction(txid)['hex'], stripped_tx_hex)

        self.log.info("-rpcserialversion=1 leaves the MWEB extension out of raw block hex")
        block_hash = generate(node0, 1)[0]
        self.sync_all()
        full_block_hex = node0.getblock(block_hash, 0)
        stripped_block_hex = node1.getblock(block_hash, 0)
        assert_greater_than(len(full_block_hex), len(stripped_block_hex))
        assert_equal(full_block_hex[:160], stripped_block_hex[:160])
        assert_equal(self.rest_hex(node1, f'/rest/block/{block_hash}.hex'), stripped_block_hex)
        assert_equal(self.rest_get(node1, f'/rest/block/{block_hash}.bin'), bytes.fromhex(stripped_block_hex))
        self.log.info("REST block JSON still describes the full block")
        rest_block = json.loads(self.rest_get(node1, f'/rest/block/{block_hash}.json'), parse_float=Decimal)
        rpc_block = node0.getblock(block_hash, 2)
        for key in ('size', 'weight', 'mweb'):
            assert_equal(rest_block[key], rpc_block[key])
        full_txs = node0.getblock(block_hash, 2)['tx']
        stripped_txs = node1.getblock(block_hash, 2)['tx']
        # Only the HogEx (last) changes: it loses its MWEB flag.
        assert_equal([tx['hex'] for tx in full_txs[:-1]], [tx['hex'] for tx in stripped_txs[:-1]])
        hogex_hex = stripped_txs[-1]['hex']
        assert_greater_than(len(full_txs[-1]['hex']), len(hogex_hex))
        assert_equal(node0.decoderawtransaction(hogex_hex)['txid'], full_txs[-1]['txid'])
        assert 'mweb' in node1.getblock(block_hash)

        self.log.info("generateblock hex follows -rpcserialversion")
        output = node0.getnewaddress()
        full_template_hex = self.generateblock(node0, output=output, transactions=[], submit=False, sync_fun=self.no_op)['hex']
        stripped_template_hex = self.generateblock(node1, output=output, transactions=[], submit=False, sync_fun=self.no_op)['hex']
        assert_greater_than(len(full_template_hex), len(stripped_template_hex))

        self.log.info("-rpcserialversion only accepts 1 or 2")
        self.stop_node(2)
        node2.assert_start_raises_init_error(['-rpcserialversion=0'], "Error: -rpcserialversion=0 (non-segwit serialization) is no longer supported.")
        node2.assert_start_raises_init_error(['-rpcserialversion=3'], "Error: Unknown rpcserialversion requested.")
        node2.assert_start_raises_init_error(['-rpcserialversion=-1'], "Error: Unknown rpcserialversion requested.")
        self.start_node(2, extra_args=self.extra_args[2])

        self.test_package_mweb_parent_child()
        self.test_package_conflicting_mweb_spends()
        self.test_mweb_block_conflict_removal()
        self.test_mweb_aggregation()
        self.test_reorg()

    def fund_mweb_wallet(self, wallet_name, amount):
        """Create a wallet on node 2 holding one confirmed MWEB coin (node 1 strips MWEB from raw hex)."""
        node0, node2 = self.nodes[0], self.nodes[2]
        node2.createwallet(wallet_name=wallet_name)
        wallet = node2.get_wallet_rpc(wallet_name)
        node0.sendtoaddress(wallet.getnewaddress(address_type='mweb'), amount)
        generate(node0, 1)
        self.sync_blocks()
        assert_equal(len(mweb_unspent_output_ids(wallet, minconf=1)), 1)
        assert_equal(node0.getrawmempool(), [])
        return wallet

    def test_package_mweb_parent_child(self):
        """A child spending an MWEB output of its package parent."""
        node0, node2 = self.nodes[0], self.nodes[2]
        wallet_name = "mweb_package"

        self.log.info("Fund a package wallet with a single confirmed MWEB coin")
        self.connect_nodes(2, 0)
        package_wallet = self.fund_mweb_wallet(wallet_name, Decimal('3'))

        self.log.info("Build an unrelayed MWEB parent and child on node 2")
        self.disconnect_nodes(2, 0)
        parent_txid = package_wallet.send(outputs=[{package_wallet.getnewaddress(address_type='mweb'): Decimal('2')}])["txid"]
        child_txid = package_wallet.send(
            outputs=[{node0.getnewaddress(address_type='mweb'): Decimal('1')}],
            options={"include_unsafe": True},
        )["txid"]
        parent_hex = node2.getrawtransaction(parent_txid)
        child_hex = node2.getrawtransaction(child_txid)

        self.log.info("The MWEB child alone is missing its unconfirmed parent output")
        child_result = node0.testmempoolaccept([child_hex])[0]
        assert_equal(child_result["allowed"], False)
        assert_equal(child_result["reject-reason"], "missing-inputs")

        self.log.info("The sorted MWEB parent-child package is accepted")
        package_result = node0.testmempoolaccept([parent_hex, child_hex])
        for tx_result in package_result:
            assert_equal(tx_result["allowed"], True)
            assert_greater_than(tx_result["mweb_weight"], 0)
            assert_greater_than(tx_result["fees"]["effective-feerate"], 0)

        self.log.info("The child-before-parent package is not sorted")
        unsorted = node0.testmempoolaccept([child_hex, parent_hex])
        assert_equal([r["package-error"] for r in unsorted], ["package-not-sorted"] * 2)

        submit_result = node0.submitpackage([parent_hex, child_hex])
        assert_equal(submit_result["package_msg"], "success")
        for tx_result in package_result:
            assert_greater_than(submit_result["tx-results"][tx_result["wtxid"]]["mweb_weight"], 0)
        assert_equal(set(node0.getrawmempool()), {parent_txid, child_txid})

        self.log.info("Mine the package and unload the temporary wallet")
        self.connect_nodes(2, 0)
        generate(node0, 1)
        self.sync_blocks()
        assert_equal(node0.getrawmempool(), [])
        node2.unloadwallet(wallet_name)

    def test_package_conflicting_mweb_spends(self):
        """Two package transactions spending the same MWEB output conflict, even before either is in the mempool."""
        node0, node2 = self.nodes[0], self.nodes[2]

        self.log.info("Clone a wallet holding one confirmed MWEB coin")
        wallet = self.fund_mweb_wallet("mweb_conflict", Decimal('3'))
        backup = node2.datadir_path / "mweb_conflict.bak"
        wallet.backupwallet(backup)
        node2.restorewallet("mweb_conflict_clone", backup)
        clone = node2.get_wallet_rpc("mweb_conflict_clone")
        [output_id] = mweb_unspent_output_ids(wallet, minconf=1)
        assert_equal(mweb_unspent_output_ids(clone, minconf=1), {output_id})

        self.log.info("Spend it twice without broadcasting")
        spends = []
        for w, amount in ((wallet, Decimal('1')), (clone, Decimal('2'))):
            spends.append(w.send(
                outputs=[{w.getnewaddress(address_type='mweb'): amount}],
                options={"inputs": [{"output_id": output_id}], "add_inputs": False, "add_to_wallet": False},
            )["hex"])

        self.log.info("Each spend is acceptable alone, but not together in one package")
        for hex_tx in spends:
            assert_equal(node0.testmempoolaccept([hex_tx])[0]["allowed"], True)
        package_result = node0.testmempoolaccept(spends)
        assert_equal([r["package-error"] for r in package_result], ["conflict-in-package"] * 2)
        assert all("allowed" not in r for r in package_result)
        assert_equal(node0.getrawmempool(), [])

        node2.unloadwallet("mweb_conflict")
        node2.unloadwallet("mweb_conflict_clone")

    def disconnect_all(self):
        """Drop the default chain topology (and any extra 2–0 link from earlier phases)."""
        for a, b in ((1, 0), (2, 1), (2, 0)):
            try:
                self.disconnect_nodes(a, b)
            except Exception:
                pass

    def test_mweb_block_conflict_removal(self):
        """An unknown mined winner has stable partial history across conflict, undo and reload."""
        node0, node1, node2 = self.nodes

        # Native partial IDs are BLAKE3(tag || output ID), displayed as uint256.
        def partial_id(tag, coin_id):
            return blake3(tag + bytes.fromhex(coin_id)).to_byte_arr()[::-1].hex()

        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)

        self.log.info("Clone a wallet holding one confirmed MWEB coin onto a second peer")
        node1.createwallet(wallet_name="mweb_block_conflict")
        wallet = node1.get_wallet_rpc("mweb_block_conflict")
        funding_send_txid = node0.sendtoaddress(wallet.getnewaddress(address_type='mweb'), Decimal('2'))
        generate(node0, 1)
        self.sync_all()
        node1.syncwithvalidationinterfacequeue()
        funding_coin, = wallet.listunspent()
        output_id = funding_coin['output_id']
        funding_txid = funding_coin['txid']
        assert_equal((funding_coin['amount'], funding_coin['confirmations']), (Decimal('2'), 1))
        funding = wallet.gettransaction(funding_txid)
        assert_equal((funding['amount'], funding['confirmations']), (Decimal('2'), 1))
        # Immediate mining can deliver this first receipt only through the block.
        # Pin its actual local identity before copying the wallet database.
        if funding_txid == funding_send_txid:
            assert 'partial_mweb' not in funding
        else:
            assert_equal(funding_txid, partial_id(b'R', output_id))
            assert_equal(funding['partial_mweb'], {'received': {'output_id': output_id, 'amount': 2 * COIN}})
            assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", wallet.gettransaction, funding_send_txid)
        funding_row, = wallet.listwallettransactions()
        assert_equal((funding_row['txid'], funding_row['mweb_out'], funding_row['type'], funding_row['amount']),
                     (funding_txid, output_id, 'RecvWithAddress', Decimal('2')))
        backup = node1.datadir_path / "mweb_block_conflict.bak"
        wallet.backupwallet(backup)
        node2.restorewallet("mweb_block_conflict_clone", backup)
        clone = node2.get_wallet_rpc("mweb_block_conflict_clone")
        assert_equal(mweb_unspent_output_ids(wallet, minconf=1), {output_id})
        assert_equal(mweb_unspent_output_ids(clone, minconf=1), {output_id})
        cloned_funding, = clone.listunspent()
        assert_equal((cloned_funding['txid'], cloned_funding['output_id']), (funding_txid, output_id))

        self.log.info("Spend the same MWEB coin differently on disconnected peers")
        self.disconnect_all()
        stale_txid = wallet.send(
            outputs=[{wallet.getnewaddress(address_type='mweb'): Decimal('0.5')}],
        )["txid"]
        winner_txid = clone.send(
            outputs=[{clone.getnewaddress(address_type='mweb'): Decimal('0.6')}],
        )["txid"]
        assert stale_txid != winner_txid
        assert_equal(node1.getrawmempool(), [stale_txid])
        assert_equal(node2.getrawmempool(), [winner_txid])
        node2.syncwithvalidationinterfacequeue()
        winner_outputs = {coin['output_id']: coin for coin in clone.listunspent(minconf=0)
                          if coin['txid'] == winner_txid}
        assert_equal(len(winner_outputs), 2)
        expected_balance = Decimal('2') + clone.gettransaction(winner_txid)['fee']
        assert_equal(sorted(coin['amount'] for coin in winner_outputs.values()),
                     sorted([Decimal('0.6'), expected_balance - Decimal('0.6')]))
        assert_equal({output['output_id'] for output in node2.getrawtransaction(winner_txid, True)['vout']},
                     set(winner_outputs))
        stale_outputs = {coin['output_id'] for coin in wallet.listunspent(minconf=0) if coin['txid'] == stale_txid}
        assert_equal(len(stale_outputs), 2)
        assert stale_outputs.isdisjoint(winner_outputs)

        spend_id = partial_id(b'S', output_id)
        receive_ids = {coin_id: partial_id(b'R', coin_id) for coin_id in winner_outputs}
        partial_ids = {spend_id, *receive_ids.values()}
        assert_equal(len(partial_ids), 3)
        expected_wallet_ids = {funding_txid, stale_txid, *partial_ids}

        self.log.info("Mine the winner; reconnecting must evict the stale mempool spend")
        conflict_block = generate(node2, 1)[0]
        assert_equal(node2.getrawmempool(), [])
        self.connect_nodes(1, 2)
        self.sync_blocks([node1, node2])
        assert_equal(node1.getbestblockhash(), conflict_block)
        self.wait_until(lambda: stale_txid not in node1.getrawmempool())
        assert_equal(node1.getrawmempool(), [])
        mined = node2.getblock(conflict_block, 1)
        assert_greater_than(len(mined['mweb']['kernels']), 0)
        previous_block = mined['previousblockhash']

        def assert_confirmed_conflict():
            node1.syncwithvalidationinterfacequeue()
            stale = wallet.gettransaction(stale_txid)
            assert_equal(stale['confirmations'], -1)
            assert_equal(stale['walletconflicts'], [spend_id])
            assert_equal(stale['trusted'], False)
            spend = wallet.gettransaction(spend_id)
            assert_equal(spend['confirmations'], 1)
            assert_equal(spend['blockhash'], conflict_block)
            assert_equal(spend['walletconflicts'], [stale_txid])
            assert_equal(spend['partial_mweb'], {'spent': {'output_id': output_id}})
            # gettransaction excludes its inferred fee from amount; this input-only
            # record's exact known debit is asserted in listwallettransactions below.
            assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", wallet.gettransaction, winner_txid)
            for coin_id, txid in receive_ids.items():
                coin = winner_outputs[coin_id]
                receive = wallet.gettransaction(txid)
                assert_equal(receive['confirmations'], 1)
                assert_equal(receive['blockhash'], conflict_block)
                assert_equal(receive['walletconflicts'], [])
                assert_equal(receive['amount'], coin['amount'])
                assert_equal(receive['partial_mweb'], {'received': {
                    'output_id': coin_id, 'amount': int(coin['amount'] * COIN)}})

            history = wallet.listwallettransactions()
            assert_equal(len(history), 5)
            assert_equal({row['txid'] for row in history}, expected_wallet_ids)
            stale_row, = [row for row in history if row['txid'] == stale_txid]
            assert_equal(stale_row['confirmations'], -1)
            components = [row for row in history if row['txid'] in partial_ids]
            assert_equal(len(components), 3)
            assert all(row['blockhash'] == conflict_block and row['confirmations'] == 1 for row in components)
            spend_row, = [row for row in components if row['txid'] == spend_id]
            # The native history schema presents an owned-input-only partial as SendToSelf.
            assert_equal((spend_row['type'], spend_row['amount'], spend_row['net']),
                         ('SendToSelf', Decimal('-2'), Decimal('-2')))
            for row in (row for row in components if row['txid'] != spend_id):
                coin_id = row['mweb_out']
                coin = winner_outputs[coin_id]
                assert_equal(row['txid'], receive_ids[coin_id])
                assert_equal((row['type'], row['amount'], row['net'], row['address']),
                             ('RecvWithAddress', coin['amount'], coin['amount'], coin['address']))
            mine = wallet.getbalances()['mine']
            assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (expected_balance, 0, 0))
            unspent = wallet.listunspent(include_unsafe=False)
            assert_equal(len(unspent), 2)
            assert_equal({coin['output_id'] for coin in unspent}, set(winner_outputs))
            assert_equal(sum(coin['amount'] for coin in unspent), expected_balance)
            for coin in unspent:
                assert_equal(coin['txid'], receive_ids[coin['output_id']])
                assert_equal(coin['confirmations'], 1)
            return history, [(row['txid'], row.get('mweb_out')) for row in components]

        self.log.info("The unknown winner has exact partial spend/receive IDs and balances")
        confirmed_history, component_order = assert_confirmed_conflict()

        self.log.info("Restart isolated with wallet rebroadcast disabled, preserving confirmed history")
        self.restart_node(1, extra_args=self.extra_args[1] + ['-walletbroadcast=0'])
        if 'mweb_block_conflict' not in node1.listwallets():
            node1.loadwallet('mweb_block_conflict')
        wallet = node1.get_wallet_rpc('mweb_block_conflict')
        assert_equal(assert_confirmed_conflict(), (confirmed_history, component_order))

        self.log.info("Undo preserves native inactive partial identities and restores the funding coin")
        node1.invalidateblock(conflict_block)
        assert_equal(node1.getbestblockhash(), previous_block)
        assert_equal(node1.getrawmempool(), [])

        def assert_disconnected_conflict():
            node1.syncwithvalidationinterfacequeue()
            for txid in {stale_txid, *partial_ids}:
                tx = wallet.gettransaction(txid)
                assert_equal(tx['confirmations'], 0)
                assert_equal(tx['trusted'], False)
                assert 'blockhash' not in tx
            # Bitcoin-derived wallet history retains known inactive conflicts.
            assert_equal(wallet.gettransaction(stale_txid)['walletconflicts'], [spend_id])
            assert_equal(wallet.gettransaction(spend_id)['walletconflicts'], [stale_txid])
            history = wallet.listwallettransactions()
            assert_equal(len(history), 5)
            assert_equal({row['txid'] for row in history}, expected_wallet_ids)
            assert_equal([(row['txid'], row.get('mweb_out')) for row in history if row['txid'] in partial_ids],
                         component_order)
            mine = wallet.getbalances()['mine']
            assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (Decimal('2'), 0, 0))
            funding, = wallet.listunspent()
            assert_equal((funding['txid'], funding['output_id'], funding['amount'], funding['confirmations']),
                         (funding_txid, output_id, Decimal('2'), 1))
            return history

        disconnected_history = assert_disconnected_conflict()
        # The stale send and the inactive spend can share a receive time; the
        # spend, added to the wallet later, lists first.
        history_txids = [row['txid'] for row in disconnected_history]
        assert history_txids.index(spend_id) < history_txids.index(stale_txid)
        # Each load salts mapWallet differently; history order must not change.
        for _ in range(8):
            node1.unloadwallet('mweb_block_conflict')
            node1.loadwallet('mweb_block_conflict')
            wallet = node1.get_wallet_rpc('mweb_block_conflict')
            assert_equal(assert_disconnected_conflict(), disconnected_history)

        self.log.info("Reconsider and reload restore the same partial identities, history order and balances")
        node1.reconsiderblock(conflict_block)
        assert_equal(node1.getbestblockhash(), conflict_block)
        assert_equal(assert_confirmed_conflict(), (confirmed_history, component_order))
        self.restart_node(1, extra_args=self.extra_args[1])
        if 'mweb_block_conflict' not in node1.listwallets():
            node1.loadwallet('mweb_block_conflict')
        wallet = node1.get_wallet_rpc('mweb_block_conflict')
        assert_equal(assert_confirmed_conflict(), (confirmed_history, component_order))

        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        self.sync_all()
        node1.unloadwallet("mweb_block_conflict")
        node2.unloadwallet("mweb_block_conflict_clone")

    def test_mweb_aggregation(self):
        """Independently signed MWEB transfers aggregate; three peers mine the same kernel set."""
        node0, node1, node2 = self.nodes

        self.log.info("Ensure nodes 0 and 2 hold confirmed MWEB coins (node 1 strips raw MWEB hex)")
        # Prior phase leaves the chain topology connected; connect_nodes requires a clear peer slot.
        self.sync_all()
        node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), Decimal('2'))
        node0.sendtoaddress(node2.getnewaddress(address_type='mweb'), Decimal('2'))
        generate(node0, 1)
        self.sync_all()

        self.log.info("Restart disconnected so each peer keeps an independent mempool view")
        self.stop_nodes()
        self.start_nodes()

        self.log.info("Create independent signed MWEB transfers on two peers")
        n0_txid = node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), Decimal('1'))
        n0_tx = tx_from_hex(node0.getrawtransaction(n0_txid))
        n2_txid = node2.sendtoaddress(node2.getnewaddress(address_type='mweb'), Decimal('1'))
        n2_tx = tx_from_hex(node2.getrawtransaction(n2_txid))
        assert n0_tx.mweb_tx is not None and n2_tx.mweb_tx is not None

        self.log.info("Aggregate the two bodies; originals conflict with the aggregate")
        assert_equal(node0.getrawmempool(), [n0_txid])
        assert_equal(node2.getrawmempool(), [n2_txid])
        assert_equal(node1.getrawmempool(), [])
        aggregated = CTransaction()
        aggregated.mweb_tx = mweb_aggregate_txs([n0_tx.mweb_tx, n2_tx.mweb_tx])
        assert_equal(len(aggregated.mweb_tx.body.inputs), 2)
        assert_equal(len(aggregated.mweb_tx.body.kernels), 2)
        agg_hex = aggregated.serialize_with_mweb().hex()
        expected_kernels = {kernel.hash.to_hex() for kernel in aggregated.mweb_tx.body.kernels}
        assert_equal(len(expected_kernels), 2)
        # A pure-MWEB txid displays its first kernel's bytes in uint256 order.
        # The same-id original triggers duplicate detection; the other original
        # triggers RBF, whose required 1.5x fee rate the aggregate does not pay.
        aggregate_txid = aggregated.mweb_tx.body.kernels[0].hash.to_byte_arr()[::-1].hex()
        assert aggregate_txid in (n0_txid, n2_txid)
        for node, original_txid in ((node0, n0_txid), (node2, n2_txid)):
            aggregate_accept = node.testmempoolaccept([agg_hex])[0]
            assert_equal(aggregate_accept['allowed'], False)
            expected_reason = 'txn-already-in-mempool' if aggregate_txid == original_txid else 'insufficient fee'
            assert_equal(aggregate_accept['reject-reason'], expected_reason)
        assert_equal(node1.testmempoolaccept([agg_hex])[0]['allowed'], True)
        assert_equal(node1.sendrawtransaction(agg_hex), aggregate_txid)
        for original_txid, original_tx in ((n0_txid, n0_tx), (n2_txid, n2_tx)):
            original_accept = node1.testmempoolaccept([original_tx.serialize_with_mweb().hex()])[0]
            assert_equal(original_accept['allowed'], False)
            # The non-colliding original also underpays the aggregate's total
            # fee, so it fails the replacement fee check in this direction.
            expected_reason = 'txn-already-in-mempool' if original_txid == aggregate_txid else 'insufficient fee'
            assert_equal(original_accept['reject-reason'], expected_reason)
        # Cross-admit the non-conflicting originals so mining joins the same kernel set.
        node2.sendrawtransaction(n0_tx.serialize_with_mweb().hex())
        node0.sendrawtransaction(n2_tx.serialize_with_mweb().hex())

        self.log.info("Each peer mines its mempool view to the same kernel-ID union")
        for node in (node0, node1, node2):
            block_hash = generate(node, 1)[0]
            # Verbosity 1 lists kernel commitments; kernel_id strings need verbosity 2.
            mined_kernels = {k['kernel_id'] for k in node.getblock(block_hash, 2)['mweb']['kernels']}
            assert_equal(mined_kernels, expected_kernels)
            assert_equal(node.getrawmempool(), [])

    def test_reorg(self):
        """A cached pure-MWEB transfer returns when a longer peer chain displaces its block."""
        node0, node2 = self.nodes[0], self.nodes[2]

        self.log.info("Restart disconnected so node 2 can mine a strictly longer fork")
        self.stop_nodes()
        self.start_nodes()

        self.log.info("Create a pure MWEB transfer on node 0 and mine it")
        # Restart before creating the transfer: mining retains its full body in
        # the in-process recent-by-kernel cache. This tests cache-hit replay,
        # not reconstruction from an aggregate after a post-mining restart.
        # Fund if the default wallet spent its MWEB coins in earlier phases.
        if len(mweb_unspent_output_ids(node0, minconf=1)) == 0:
            # Nodes are disconnected; mine the pegin locally on node 0.
            node0.sendtoaddress(node0.getnewaddress(address_type='bech32'), Decimal('5'))
            generate(node0, 1)
            node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), Decimal('2'))
            generate(node0, 1)
        mweb_txid = node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), Decimal('1'))
        assert_equal(node0.getrawmempool(), [mweb_txid])
        assert_equal(node0.getmempoolentry(mweb_txid)['weight'], 0)
        generate(node0, 1)
        assert_equal(node0.getrawmempool(), [])

        self.log.info("Mine a longer chain on node 2 and reconnect; the transfer must resurrect")
        n2_tip = generate(node2, 5)[-1]
        self.connect_nodes(2, 0)
        self.sync_blocks([node0, node2])
        assert_equal(node0.getbestblockhash(), n2_tip)
        assert_equal(node0.getrawmempool(), [mweb_txid])


if __name__ == '__main__':
    MWEBMempoolTest(__file__).main()
