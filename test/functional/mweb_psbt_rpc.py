#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Node RPCs for MWEB PSBTs and wallet rejection of miner-only HogEx hex.

createpsbt / createrawtransaction / converttopsbt MWEB handling, utxoupdatepsbt
MWEB metadata lookup, descriptorprocesspsbt MWEB signing, decodepsbt MWEB fields,
analyzepsbt MWEB role and weight, and finalizepsbt of signed MWEB vectors.
"""

import json
import os
import struct
from decimal import Decimal

from test_framework.messages import CBlock, CTransaction, FromHex
from test_framework.mweb_util import (
    get_mweb_account_descriptor,
    get_mweb_internal_index_for_address,
    init_mweb_wallet,
    mweb_extra_args,
    setup_mweb_chain,
)
from test_framework.psbt import PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT, PSBTMap
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

RANGEPROOF_SIZE = 675
PSBT_IN_MWEB_ADDR_DESCRIPTOR = 0x96


class DuplicateKeys(dict):
    """Preserve duplicate JSON object keys for RPC parser tests."""

    def __init__(self, items):
        super().__init__(items)
        self._items = items

    def items(self):
        return self._items


class MWEBPSBTRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], [])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'rpc_psbt.json'), encoding='utf-8') as f:
            self.vectors = json.load(f)['mweb_signed']

        self.node0, self.node1 = self.nodes
        self.log.info("Set up an MWEB chain and give node1 an MWEB coin")
        setup_mweb_chain(self.node0, self)
        self.mweb_addr = self.node1.getnewaddress(address_type='mweb')
        self.funding_txid = self.node0.sendtoaddress(self.mweb_addr, 5)
        self.generate(self.node0, 1)
        mweb_utxos = [u for u in self.node1.listunspent() if u.get('output_id')]
        assert_equal(len(mweb_utxos), 1)
        self.output_id = mweb_utxos[0]['output_id']
        self.l1_utxo = next(u for u in self.node0.listunspent() if 'vout' in u and not u.get('output_id'))

        self.test_raw_hex_rejects_mweb()
        self.test_createpsbt()
        self.test_createpsbt_errors()
        self.test_utxoupdatepsbt()
        self.test_converttopsbt()
        self.test_non_mweb_output_unchanged()
        self.test_descriptorprocesspsbt()
        self.test_signed_vectors()
        self.test_wallet_hex_rpcs_reject_hogex()

    def test_wallet_hex_rpcs_reject_hogex(self):
        self.log.info("Funding, signing and PSBT conversion reject HogEx markers without changing inventory or locks")
        coin = max((u for u in self.node0.listunspent() if 'vout' in u and not u.get('output_id')),
                   key=lambda u: u['amount'])
        plain_hex = self.node0.createrawtransaction(
            [{'txid': coin['txid'], 'vout': coin['vout']}],
            {self.node0.getnewaddress(address_type='bech32'): 1})
        before = self.node0.listunspent()
        locks_before = self.node0.listlockunspent()
        control = self.node0.fundrawtransaction(plain_hex, {'add_inputs': False, 'fee_rate': 10})
        assert not FromHex(CTransaction(), control['hex']).hogex
        marked = FromHex(CTransaction(), plain_hex)
        marked.hogex = True
        marked_hex = marked.serialize().hex()
        assert FromHex(CTransaction(), marked_hex).hogex
        assert_equal(marked.calc_sha256(), FromHex(CTransaction(), plain_hex).calc_sha256())
        assert_equal(self.node0.listunspent(), before)
        assert_equal(self.node0.listlockunspent(), locks_before)

        for is_witness in (None, True):
            assert_raises_rpc_error(
                -8,
                "HogEx transactions are miner-only and cannot be funded by a wallet",
                self.node0.fundrawtransaction, marked_hex,
                {'add_inputs': False, 'fee_rate': 10, 'lockUnspents': True}, is_witness)
            assert_equal(self.node0.listunspent(), before)
            assert_equal(self.node0.listlockunspent(), locks_before)

        signed = self.node0.signrawtransactionwithwallet(control['hex'])
        assert signed['complete']
        assert not FromHex(CTransaction(), signed['hex']).hogex
        assert self.node0.testmempoolaccept([signed['hex']])[0]['allowed']
        signed_marked = FromHex(CTransaction(), signed['hex'])
        signed_marked.hogex = True

        # Read-only decoding must still inspect a genuine mined HogEx.
        block = FromHex(CBlock(), self.node0.getblock(self.node0.getbestblockhash(), 0))
        hogex = block.vtx[-1]
        assert hogex.hogex
        mined_hex = hogex.serialize().hex()
        assert_equal(self.node0.decoderawtransaction(mined_hex)['txid'], hogex.txid_hex)

        for raw in (marked_hex, signed_marked.serialize().hex(), mined_hex):
            assert FromHex(CTransaction(), raw).hogex
            assert_raises_rpc_error(
                -8, "HogEx transactions are miner-only and cannot be signed by a wallet",
                self.node0.signrawtransactionwithwallet, raw)
            for version in (0, 2):
                for permit_sigdata in (False, True):
                    for is_witness in (None, True):
                        assert_raises_rpc_error(
                            -8, "HogEx transactions are miner-only and cannot be converted to a PSBT",
                            self.node0.converttopsbt, raw, permit_sigdata, is_witness, version)
            assert_equal(self.node0.listunspent(), before)
            assert_equal(self.node0.listlockunspent(), locks_before)

        # Both PSBT versions still convert, sign and extract ordinary drafts,
        # including explicit removal of existing signature data.
        for version in (0, 2):
            for raw, permit_sigdata in ((control['hex'], False), (signed['hex'], True)):
                psbt = self.node0.converttopsbt(raw, permitsigdata=permit_sigdata, psbt_version=version)
                assert_equal(self.node0.decodepsbt(psbt)['psbt_version'], version)
                processed = self.node0.walletprocesspsbt(psbt)
                assert processed['complete']
                extracted = self.node0.finalizepsbt(processed['psbt'])
                assert extracted['complete']
                assert not FromHex(CTransaction(), extracted['hex']).hogex
                assert self.node0.testmempoolaccept([extracted['hex']])[0]['allowed']
        assert_equal(self.node0.listunspent(), before)
        assert_equal(self.node0.listlockunspent(), locks_before)

    def test_raw_hex_rejects_mweb(self):
        self.log.info("createrawtransaction rejects MWEB inputs and MWEB addresses")
        l1_addr = self.node0.getnewaddress(address_type='bech32')
        assert_raises_rpc_error(-8, "MWEB inputs cannot be represented in raw transaction hex; use createpsbt or walletcreatefundedpsbt",
                                self.node0.createrawtransaction, [{"mweb_out": self.output_id}], [{l1_addr: 1}])
        assert_raises_rpc_error(-8, "MWEB outputs cannot be represented in raw transaction hex; use createpsbt or walletcreatefundedpsbt for MWEB transaction drafts",
                                self.node0.createrawtransaction, [{"txid": self.l1_utxo['txid'], "vout": self.l1_utxo['vout']}], [{self.mweb_addr: 1}])

    def test_createpsbt(self):
        self.log.info("createpsbt places mweb_out inputs and MWEB addresses in the MWEB part")
        l1_addr = self.node0.getnewaddress(address_type='bech32')
        dest = self.node0.getnewaddress(address_type='mweb')
        psbt = self.node0.createpsbt(inputs=[{"mweb_out": self.output_id}], outputs=[{dest: 3}, {l1_addr: 1}])
        decoded = self.node0.decodepsbt(psbt)
        assert_equal(decoded['psbt_version'], 2)
        assert_equal(decoded['input_count'], 1)
        assert_equal(decoded['kernel_count'], 1)
        mweb_in = decoded['inputs'][0]
        assert 'previous_txid' not in mweb_in
        assert 'previous_vout' not in mweb_in
        assert_equal(mweb_in['mweb'], {'output_id': self.output_id})

        # With MWEB-only inputs the transparent destination is a kernel peg-out.
        assert_equal(decoded['output_count'], 1)
        out = decoded['outputs'][0]
        assert_equal(out['amount'], Decimal(3))
        assert 'script' not in out
        assert_equal(out['mweb'], {'address': dest})
        assert_equal(len(decoded['kernels']), 1)
        pegouts = decoded['kernels'][0]['pegouts']
        assert_equal(len(pegouts), 1)
        assert_equal(pegouts[0]['amount'], 100000000)
        assert_equal(pegouts[0]['scriptPubKey']['address'], l1_addr)
        assert 'fee' not in decoded

        analysis = self.node0.analyzepsbt(psbt)
        assert_equal(analysis['next'], 'updater')
        assert_equal(analysis['inputs'][0]['has_utxo'], False)
        assert_equal(analysis['inputs'][0]['next'], 'updater')
        assert 'fee' not in analysis
        assert 'estimated_mweb_weight' not in analysis

        self.log.info("createpsbt with only MWEB outputs and transparent inputs")
        psbt = self.node0.createpsbt(inputs=[{"txid": self.l1_utxo['txid'], "vout": self.l1_utxo['vout']}], outputs=[{dest: 1}])
        decoded = self.node0.decodepsbt(psbt)
        assert_equal(decoded['kernel_count'], 0)
        assert_equal(decoded['kernels'], [])
        assert_equal(decoded['outputs'][0]['mweb'], {'address': dest})
        assert 'mweb' not in decoded['inputs'][0]

    def test_createpsbt_errors(self):
        self.log.info("createpsbt rejects malformed and mixed MWEB drafts")
        node = self.node0
        dest = node.getnewaddress(address_type='mweb')
        l1_addr = node.getnewaddress(address_type='bech32')
        l1_in = {"txid": self.l1_utxo['txid'], "vout": self.l1_utxo['vout']}
        assert_raises_rpc_error(-8, "MWEB PSBTs require PSBT version 2", node.createpsbt, inputs=[{"mweb_out": self.output_id}], outputs=[{dest: 1}], psbt_version=0)
        assert_raises_rpc_error(-8, "MWEB PSBTs require PSBT version 2", node.createpsbt, inputs=[l1_in], outputs=[{dest: 1}], psbt_version=0)
        assert_raises_rpc_error(-8, "Mixed transparent and MWEB inputs require explicit peg-in or pegout metadata; use walletcreatefundedpsbt",
                                node.createpsbt, inputs=[l1_in, {"mweb_out": self.output_id}], outputs=[{dest: 1}])
        for field, value in [('txid', self.l1_utxo['txid']), ('vout', 0)]:
            assert_raises_rpc_error(-8, "Invalid parameter, specify either mweb_out or txid and vout",
                                    node.createpsbt, inputs=[{"mweb_out": self.output_id, field: value}], outputs=[{dest: 1}])
        for field in ('sequence', 'weight'):
            assert_raises_rpc_error(-8, "Invalid parameter, sequence and weight do not apply to MWEB inputs",
                                    node.createpsbt, inputs=[{"mweb_out": self.output_id, field: 1}], outputs=[{dest: 1}])
        for bad in ["", "0" * 63, "0" * 65, "00" * 31, "zz" * 32, 5]:
            assert_raises_rpc_error(-8, "Invalid parameter, mweb_out must be a 64-character hexadecimal string",
                                    node.createpsbt, inputs=[{"mweb_out": bad}], outputs=[{dest: 1}])
        assert_raises_rpc_error(-8, f"Invalid parameter, duplicated mweb_out: {self.output_id}",
                                node.createpsbt, inputs=[{"mweb_out": self.output_id}, {"mweb_out": self.output_id}], outputs=[{dest: 1}])
        assert_raises_rpc_error(-8, "Invalid parameter, data outputs cannot be pegged out from MWEB inputs",
                                node.createpsbt, inputs=[{"mweb_out": self.output_id}], outputs=[{dest: 1}, {"data": "00"}])
        for outputs in ([{dest: 1}, {dest: 2}], DuplicateKeys([(dest, 1), (dest, 2)])):
            assert_raises_rpc_error(-8, "Invalid parameter, duplicated address: " + dest,
                                    node.createpsbt, inputs=[{"mweb_out": self.output_id}], outputs=outputs)
        for outputs in ([{'data': '00'}, {'data': '01'}], DuplicateKeys([('data', '00'), ('data', '01')])):
            assert_raises_rpc_error(-8, "Invalid parameter, duplicate key: data", node.createpsbt, inputs=[], outputs=outputs)
        assert_raises_rpc_error(-8, "Invalid parameter, key-value pair must contain exactly one key",
                                node.createpsbt, inputs=[], outputs=[{dest: 1, l1_addr: 1}])
        # A plain transparent PSBT is still fine.
        node.createpsbt(inputs=[l1_in], outputs=[{l1_addr: 1}])

    def test_utxoupdatepsbt(self):
        self.log.info("utxoupdatepsbt fills MWEB input coin metadata by output id")
        dest = self.node0.getnewaddress(address_type='mweb')
        psbt = self.node0.createpsbt(inputs=[{"mweb_out": self.output_id}], outputs=[{dest: 4}])
        for node in self.nodes:
            updated = node.utxoupdatepsbt(psbt)
            mweb_in = node.decodepsbt(updated)['inputs'][0]['mweb']
            assert_equal(mweb_in['output_id'], self.output_id)
            for key in ('output_commit', 'output_pubkey', 'key_exchange_pk'):
                assert_equal(len(mweb_in[key]), 66)
            assert 'amount' not in mweb_in
            # The amount is still missing, so the Updater is still next.
            assert_equal(node.analyzepsbt(updated)['next'], 'updater')

        # The fields come from the chain's MWEB UTXO set.
        block_mweb = self.node0.getblock(self.node0.getbestblockhash(), 3)['mweb']
        utxo = next(o for o in block_mweb['outputs'] if o['output_id'] == self.output_id)
        updated = self.node0.utxoupdatepsbt(psbt)
        mweb_in = self.node0.decodepsbt(updated)['inputs'][0]['mweb']
        assert_equal(mweb_in['output_commit'], utxo['commit'])
        assert_equal(mweb_in['output_pubkey'], utxo['receiver_pubkey'])

        self.log.info("utxoupdatepsbt leaves unknown MWEB outputs untouched")
        unknown = self.node0.createpsbt(inputs=[{"mweb_out": "11" * 32}], outputs=[{dest: 1}])
        assert_equal(self.node0.utxoupdatepsbt(unknown), unknown)

        self.log.info("utxoupdatepsbt finds MWEB outputs still in the mempool")
        mempool_dest = self.node1.getnewaddress(address_type='mweb')
        self.node0.sendtoaddress(mempool_dest, 2)
        self.sync_mempools()
        mempool_ids = {u['output_id'] for u in self.node1.listunspent(0) if u.get('output_id')} - {self.output_id}
        assert_equal(len(mempool_ids), 1)
        mempool_id = mempool_ids.pop()
        updated = self.node1.utxoupdatepsbt(self.node1.createpsbt(inputs=[{"mweb_out": mempool_id}], outputs=[{dest: 1}]))
        assert 'output_commit' in self.node1.decodepsbt(updated)['inputs'][0]['mweb']

        self.log.info("utxoupdatepsbt skips MWEB inputs that already carry a previous transaction")
        two_inputs = PSBT.from_base64(self.node1.createpsbt(inputs=[{"mweb_out": self.output_id}, {"mweb_out": mempool_id}], outputs=[{dest: 1}]))
        two_inputs.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = bytes.fromhex(self.node0.gettransaction(self.l1_utxo['txid'])['hex'])
        updated = self.node1.decodepsbt(self.node1.utxoupdatepsbt(two_inputs.to_base64()))
        assert 'output_commit' not in updated['inputs'][0]['mweb']
        assert 'output_commit' in updated['inputs'][1]['mweb']
        self.generate(self.node0, 1)

        self.log.info("utxoupdatepsbt on a PSBT with unknown transparent inputs and an MWEB input")
        mixed = PSBT.from_base64(self.vectors['mixed'])
        mixed.i.append(PSBT.from_base64(self.node0.createpsbt(inputs=[{"mweb_out": self.output_id}], outputs=[{dest: 1}])).i[0])
        mixed_inputs = self.node0.decodepsbt(mixed.to_base64())['inputs']
        assert all('mweb' not in i for i in mixed_inputs[:-1])
        updated = self.node0.decodepsbt(self.node0.utxoupdatepsbt(mixed.to_base64()))['inputs']
        assert_equal(updated[:-1], mixed_inputs[:-1])
        assert 'output_commit' in updated[-1]['mweb']

    def test_converttopsbt(self):
        self.log.info("converttopsbt rejects MWEB transactions it cannot represent")
        raw = self.node0.gettransaction(self.funding_txid)['hex']
        assert_raises_rpc_error(-8, "MWEB PSBTs require PSBT version 2", self.node0.converttopsbt, hexstring=raw, permitsigdata=True, psbt_version=0)
        assert_raises_rpc_error(-8, "MWEB output amounts are not known from a serialized transaction; use createpsbt or walletcreatefundedpsbt",
                                self.node0.converttopsbt, hexstring=raw, permitsigdata=True)

    def test_non_mweb_output_unchanged(self):
        self.log.info("Non-MWEB PSBTs and transactions keep their upstream JSON")
        l1_addr = self.node0.getnewaddress(address_type='bech32')
        psbt = self.node0.createpsbt(inputs=[{"txid": self.l1_utxo['txid'], "vout": self.l1_utxo['vout']}], outputs=[{l1_addr: 1}])
        decoded = self.node0.decodepsbt(psbt)
        for key in ('kernel_count', 'kernels', 'mweb_tx_offset', 'mweb_stealth_offset'):
            assert key not in decoded
        assert 'script' in decoded['outputs'][0]
        assert 'estimated_mweb_weight' not in self.node0.analyzepsbt(psbt)
        raw = self.node0.createrawtransaction([{"txid": self.l1_utxo['txid'], "vout": self.l1_utxo['vout']}], [{l1_addr: 1}])
        assert 'mweb_weight' not in self.node0.decoderawtransaction(raw)
        assert 'mweb_weight' in self.node0.decoderawtransaction(self.node0.gettransaction(self.funding_txid)['hex'])

    def test_descriptorprocesspsbt(self):
        node = self.node0
        dest = node.getnewaddress(address_type='mweb')
        psbt = node.createpsbt(inputs=[{"mweb_out": self.output_id}], outputs=[{dest: Decimal('4.99')}])
        account = get_mweb_account_descriptor(self.node1, private=True)['desc']

        self.log.info("descriptorprocesspsbt without MWEB keys leaves MWEB inputs unsigned")
        unsigned = node.descriptorprocesspsbt(psbt, [])
        assert_equal(unsigned['complete'], False)
        mweb_in = node.decodepsbt(unsigned['psbt'])['inputs'][0]['mweb']
        assert 'output_commit' in mweb_in
        assert 'amount' not in mweb_in

        self.log.info("descriptorprocesspsbt signs MWEB inputs from a private mweb() account descriptor")
        signed = node.descriptorprocesspsbt(psbt, [account])
        assert_equal(signed['complete'], True)
        decoded = node.decodepsbt(signed['psbt'])
        assert_equal(decoded['inputs'][0]['mweb']['amount'], 500000000)
        assert 'signature' in decoded['inputs'][0]['mweb']
        assert_equal(decoded['kernels'][0]['fee'], 1000000)
        # The maxfeerate cap allows the base MWEB fee plus one output's MWEB fee
        # (scaled up by a maxfeerate above the default), far below this fee.
        assert_equal(node.testmempoolaccept([signed['hex']])[0]['reject-reason'], 'max-fee-exceeded')
        assert node.testmempoolaccept([signed['hex']], 0)[0]['allowed']
        assert_equal(node.finalizepsbt(signed['psbt'])['hex'], signed['hex'])
        index = get_mweb_internal_index_for_address(self.node1, self.mweb_addr)
        assert_equal(node.descriptorprocesspsbt(psbt, [{"desc": account, "range": [index, index]}])['complete'], True)
        assert_equal(node.descriptorprocesspsbt(psbt, [{"desc": account, "range": [index + 1, index + 5]}])['complete'], False)

        self.log.info("descriptorprocesspsbt signs an MWEB input from its private address descriptor")
        scan_priv, spend_priv = account.split('#')[0][len('mweb('):-len(',*)')].split(',')
        with_desc = PSBT.from_base64(psbt)
        with_desc.i[0].map[PSBT_IN_MWEB_ADDR_DESCRIPTOR] = f"mweb({scan_priv},{spend_priv},{index})".encode()
        signed = node.descriptorprocesspsbt(with_desc.to_base64(), [])
        assert_equal(signed['complete'], True)
        assert node.testmempoolaccept([signed['hex']], 0)[0]['allowed']

        with_desc.i[0].map[PSBT_IN_MWEB_ADDR_DESCRIPTOR] = f"mweb({scan_priv},{spend_priv},{index + 1})".encode()
        assert_raises_rpc_error(-8, "MWEB address descriptor does not match input's output pubkey",
                                node.descriptorprocesspsbt, with_desc.to_base64(), [])

        self.log.info("descriptorprocesspsbt rewinds MWEB inputs with a watch-only mweb() descriptor but cannot sign with it")
        public_account = get_mweb_account_descriptor(self.node1, private=False)['desc']
        public_result = node.descriptorprocesspsbt(psbt, [public_account])
        assert_equal(public_result['complete'], False)
        public_in = node.decodepsbt(public_result['psbt'])['inputs'][0]['mweb']
        assert_equal(public_in['amount'], 500000000)
        assert 'signature' not in public_in

        self.log.info("descriptorprocesspsbt does not sign transparent inputs while MWEB signing data is missing")
        l1_descs = [d['desc'] for d in node.listdescriptors(True)['descriptors'] if not d['desc'].startswith('mweb(')]
        l1_addr = node.getnewaddress(address_type='bech32')
        funding_txid = node.sendtoaddress(node.getnewaddress(address_type='bech32'), 2)
        self.generate(node, 1)
        l1_utxo = next(u for u in node.listunspent() if u['txid'] == funding_txid and u['desc'].startswith('wpkh('))
        plain = node.createpsbt(inputs=[{"txid": l1_utxo['txid'], "vout": l1_utxo['vout']}], outputs=[{l1_addr: 1}])

        def is_signed(psbt_input):
            return any(key in psbt_input for key in ('final_scriptwitness', 'final_scriptSig', 'partial_signatures'))

        plain_signed = node.descriptorprocesspsbt(plain, l1_descs)
        assert is_signed(node.decodepsbt(plain_signed['psbt'])['inputs'][0])
        assert_equal(plain_signed['complete'], True)

        mixed = PSBT.from_base64(plain)
        mixed.i.append(PSBT.from_base64(psbt).i[0])
        # A peg-in output whose script still carries the placeholder kernel ID.
        mixed.o.insert(0, PSBTMap({PSBT_OUT_AMOUNT: struct.pack('<q', 100000), PSBT_OUT_SCRIPT: bytes([0x59, 0x20]) + bytes(32)}))
        mixed_signed = node.descriptorprocesspsbt(mixed.to_base64(), l1_descs)
        assert_equal(mixed_signed['complete'], False)
        l1_in = node.decodepsbt(mixed_signed['psbt'])['inputs'][0]
        assert not is_signed(l1_in)
        assert 'witness_utxo' in l1_in or 'non_witness_utxo' in l1_in

        self.log.info("walletprocesspsbt does not sign transparent inputs while MWEB signing data is missing")
        assert is_signed(node.decodepsbt(node.walletprocesspsbt(plain)['psbt'])['inputs'][0])
        wallet_signed = node.walletprocesspsbt(mixed.to_base64())
        assert_equal(wallet_signed['complete'], False)
        assert not is_signed(node.decodepsbt(wallet_signed['psbt'])['inputs'][0])

    def test_signed_vectors(self):
        self.log.info("decodepsbt shows every MWEB field of a signed MWEB-to-MWEB PSBT")
        node = self.node0
        psbt = self.vectors['mweb_to_mweb']
        decoded = node.decodepsbt(psbt)
        assert_equal(decoded['kernel_count'], 1)
        assert_equal(len(decoded['mweb_tx_offset']), 64)
        assert_equal(len(decoded['mweb_stealth_offset']), 64)
        kernel = decoded['kernels'][0]
        assert_equal(sorted(kernel.keys()), ['commit', 'features', 'fee', 'signature', 'stealth_commit'])
        assert_equal(kernel['fee'], 10000)
        assert_equal(len(kernel['commit']), 66)
        assert_equal(len(kernel['signature']), 128)
        mweb_in = decoded['inputs'][0]['mweb']
        for key in ('output_id', 'output_commit', 'output_pubkey', 'input_pubkey', 'features', 'signature', 'amount'):
            assert key in mweb_in, key
        out = decoded['outputs'][0]
        mweb_out = out['mweb']
        assert mweb_out['address'].startswith('tmweb')
        assert_equal(len(mweb_out['rangeproof']), 2 * RANGEPROOF_SIZE)
        assert_equal(len(mweb_out['encrypted_value']), 16)
        assert_equal(len(mweb_out['encrypted_nonce']), 32)
        for key in ('output_commit', 'features', 'sender_pubkey', 'output_pubkey', 'key_exchange_pubkey', 'view_tag', 'sig'):
            assert key in mweb_out, key
        # The MWEB input amount counts toward the fee.
        assert_equal(decoded['fee'], Decimal('0.0001'))

        analysis = node.analyzepsbt(psbt)
        assert_equal(analysis['next'], 'extractor')
        assert_equal(analysis['inputs'][0], {'has_utxo': False, 'is_final': True, 'next': 'extractor'})
        assert_equal(analysis['fee'], decoded['fee'])
        assert analysis['estimated_mweb_weight'] > 0

        final = node.finalizepsbt(psbt)
        assert_equal(final['complete'], True)
        tx = node.decoderawtransaction(final['hex'])
        assert_equal(tx['mweb_weight'], analysis['estimated_mweb_weight'])
        assert_equal(len(tx['vkern']), 1)

        self.log.info("decodepsbt shows peg-out kernels")
        decoded = node.decodepsbt(self.vectors['pegout'])
        pegouts = decoded['kernels'][0]['pegouts']
        assert_equal(len(pegouts), 1)
        assert pegouts[0]['amount'] > 0
        assert 'hex' in pegouts[0]['scriptPubKey']
        assert_equal(decoded['fee'], Decimal('0.0001'))
        assert_equal(node.analyzepsbt(self.vectors['pegout'])['fee'], decoded['fee'])

        self.log.info("decodepsbt and analyzepsbt net the peg-in out of the fee")
        decoded = node.decodepsbt(self.vectors['mixed'])
        assert decoded['kernels'][0]['pegin_amount'] > 0
        assert_equal(decoded['fee'], Decimal('0.0002'))
        assert_equal(node.analyzepsbt(self.vectors['mixed'])['fee'], decoded['fee'])
        for name in ('pegin', 'mixed', 'pegout'):
            assert_equal(node.finalizepsbt(self.vectors[name])['complete'], True)


if __name__ == '__main__':
    MWEBPSBTRPCTest(__file__).main()
