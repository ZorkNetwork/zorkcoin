#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Known pure and mixed MWEB winners conflict a wallet's peg-out loser."""

from decimal import Decimal

from test_framework.messages import blake3
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletConflictsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args([])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        phases = []
        for name, mweb_amount, l1_amount, payment in [('pure', 5, 0, 2), ('mixed', 4, 2, 5)]:
            node.createwallet(wallet_name=name, load_on_startup=True)
            wallet = node.get_wallet_rpc(name)
            miner.sendtoaddress(wallet.getnewaddress(address_type='mweb'), mweb_amount)
            self.generate(node, 1)
            mweb, = wallet.listunspent()
            inputs = [{'mweb_out': mweb['output_id']}]
            if l1_amount:
                address = wallet.getnewaddress(address_type='bech32')
                miner.sendtoaddress(address, l1_amount)
                self.generate(node, 1)
                canonical, = wallet.listunspent(addresses=[address])
                inputs.append({'txid': canonical['txid'], 'vout': canonical['vout']})
            phases.append((name, inputs, Decimal(mweb_amount + l1_amount), Decimal(l1_amount), Decimal(payment)))
        node.createwallet(wallet_name='destinations', load_on_startup=True)
        # Retain each loser in the wallet without admitting it to the mempool.
        # Mining the winner then tests block conflicts independently of RBF policy.
        self.restart_node(0, extra_args=self.extra_args[0] + ['-walletbroadcast=0'])
        destinations = node.get_wallet_rpc('destinations')
        results = []
        for name, inputs, total, l1_amount, payment in phases:
            wallet = node.get_wallet_rpc(name)
            self.log.info("A known %s winner conflicts an inactive pure peg-out loser", name)
            loser = wallet.send(outputs={destinations.getnewaddress(address_type='bech32'): 1}, options={
                'inputs': [inputs[0]], 'add_inputs': False, 'fee_rate': 10,
            })['txid']
            assert_equal(node.getrawmempool(), [])
            assert_equal(wallet.gettransaction(loser)['confirmations'], 0)
            destination = destinations.getnewaddress(address_type='bech32' if l1_amount else 'mweb')
            draft = wallet.send(outputs={destination: payment}, options={
                'inputs': inputs, 'add_inputs': False, 'fee_rate': 10, 'add_to_wallet': False,
            })
            assert draft['complete']
            raw = node.decoderawtransaction(draft['hex'])
            assert_equal([vin['output_id'] for vin in raw['vin'] if vin['ismweb']], [inputs[0]['mweb_out']])
            assert_equal([(vin['txid'], vin['vout']) for vin in raw['vin'] if not vin['ismweb']],
                         [(inputs[1]['txid'], inputs[1]['vout'])] if l1_amount else [])
            kernel, = raw['vkern']
            canonical_outputs = [out for out in raw['vout'] if not out['ismweb']]
            fee = l1_amount - sum(out['value'] for out in canonical_outputs) + kernel['fee']
            assert fee > 0
            if l1_amount:
                bridge, = canonical_outputs
                assert_equal(bridge['scriptPubKey']['type'], 'witness_mweb_pegin')
                assert_equal(bridge['value'], kernel['pegin'])
                pegout, = kernel['pegout']
                assert_equal((pegout['scriptPubKey']['address'], pegout['value']), (destination, payment))
            else:
                assert_equal(canonical_outputs, [])
                assert_equal(kernel['pegout'], [])
            winner = node.sendrawtransaction(draft['hex'])
            node.syncwithvalidationinterfacequeue()
            assert_equal(wallet.gettransaction(winner)['hex'], draft['hex'])
            assert_equal(set(node.getrawmempool()), {winner})
            block, = self.generate(node, 1)
            result = (name, loser, winner, block, node.getblockcount(), destination,
                      payment, fee, total - payment - fee, wallet.getrawchangeaddress(address_type='mweb'),
                      kernel['kernel_id'], inputs[0]['mweb_out'], l1_amount != 0)
            results.append(result)
            self.check_winner(node, result)
        self.log.info("Both known winner/loser pairs and exact balances survive wallet reload")
        self.restart_node(0, extra_args=self.extra_args[0] + ['-walletbroadcast=0'])
        for result in results:
            self.check_winner(node, result)

    def check_winner(self, node, result):
        name, loser, winner, block, height, destination, payment, fee, change, change_address, kernel, source, mixed = result
        wallet = node.get_wallet_rpc(name)
        depth = node.getblockcount() - height + 1
        won, lost = wallet.gettransaction(winner), wallet.gettransaction(loser)
        assert 'partial_mweb' not in won
        assert_equal((won['fee'], won['confirmations'], won['blockhash']), (-fee, depth, block))
        assert_equal(won['amount'], -payment)
        assert_equal(won['walletconflicts'], [loser])
        assert_equal((lost['confirmations'], lost['trusted'], lost['walletconflicts']), (-depth, False, [winner]))
        # A known winner must not also acquire an input-only S placeholder.
        spend_id = blake3(b'S' + bytes.fromhex(source)).to_byte_arr()[::-1].hex()
        assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', wallet.gettransaction, spend_id)
        record, = wallet.listwallettransactions(txid=winner)
        assert_equal((record['type'], record['address'], record['amount'], record['fee'], record['net']),
                     ('SendToAddress', destination, -payment, -fee, -payment - fee))
        coin, = wallet.listunspent()
        assert_equal((coin['txid'], coin['amount'], coin['address'], coin['confirmations']),
                     (winner, change, change_address, depth))
        if mixed:
            assert_equal(record['pegout'], f'{kernel}:0')
            paid, = node.get_wallet_rpc('destinations').listreceivedbyaddress(minconf=0, address_filter=destination)
            assert_equal((paid['amount'], paid['confirmations']), (payment, depth))
        else:
            assert 'pegout' not in record
            assert record['mweb_out'] != coin['output_id']
        mine = wallet.getbalances()['mine']
        assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (change, 0, 0))
        self.log.info("Known %s winner at depth%d: gettransaction.amount=%s, expected=%s, fee=%s, "
                      "typed_amount=%s, typed_net=%s, trusted_change=%s, conflicts_correct=true",
                      name, depth, won['amount'], -payment, won['fee'], record['amount'], record['net'], mine['trusted'])


if __name__ == '__main__':
    MWEBWalletConflictsTest(__file__).main()
