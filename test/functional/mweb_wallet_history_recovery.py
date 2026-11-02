#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real block-only MWEB conflicts, replacement branches, rescan and full-body recovery."""

from decimal import Decimal

from test_framework.messages import blake3
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletHistoryRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = mweb_extra_args(['-persistmempool=0'])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name='source', load_on_startup=False)
        source = node.get_wallet_rpc('source')
        receive = source.getnewaddress(address_type='mweb')
        funding = miner.sendtoaddress(receive, 5)
        node.sendrawtransaction(miner.gettransaction(funding)['hex'])
        self.generate(node, 1)
        coin, = source.listunspent()
        self.extra_args[0].append('-walletbroadcast=0')
        self.restart_node(0, extra_args=self.extra_args[0])
        node.loadwallet('source', load_on_startup=False)
        source = node.get_wallet_rpc('source')
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.source_id = coin['output_id']
        self.funding = funding
        self.change_address = source.getrawchangeaddress('mweb')
        self.spend_id = blake3(b'S' + bytes.fromhex(self.source_id)).to_byte_arr()[::-1].hex()
        self.loser = source.send(outputs={miner.getnewaddress(): 1}, options={
            'inputs': [{'mweb_out': self.source_id}], 'add_inputs': False, 'fee_rate': 10,
        })['txid']
        assert_equal(node.getrawmempool(), [])
        backup = node.datadir_path / 'before_winners.bak'
        source.backupwallet(backup)
        winners = []
        for payment in (Decimal('1'), Decimal('1.5')):
            recipient = miner.getnewaddress(address_type='mweb')
            draft = source.send(outputs={recipient: payment}, options={
                'inputs': [{'mweb_out': self.source_id}], 'add_inputs': False,
                'fee_rate': 10, 'add_to_wallet': False,
            })
            assert draft['complete']
            raw = node.decoderawtransaction(draft['hex'])
            assert_equal(raw['vin'], [{'ismweb': True, 'output_id': self.source_id}])
            kernel, = raw['vkern']
            winners.append(dict(hex=draft['hex'], txid=raw['txid'], fee=kernel['fee'],
                                payment=payment, recipient=recipient,
                                change=Decimal(5) - payment - kernel['fee']))
        node.unloadwallet('source', load_on_startup=False)
        self.mining_time = node.getblockheader(node.getbestblockhash())['time'] + 100

        self.log.info('Mine an unknown winner, then restore two wallets with the same known loser')
        first_block = self.mine_winner(winners[0])
        self.names = ('history_live', 'history_rescan')
        for name in self.names:
            node.restorewallet(name, backup, load_on_startup=False)
        self.check_unknown(winners[0], first_block)
        rescanned = node.get_wallet_rpc(self.names[1])
        before = self.snapshot(rescanned)
        for _ in range(2):
            rescanned.rescanblockchain(0)
            assert_equal(self.snapshot(rescanned), before)

        self.log.info('Disconnect, replace, then reconfirm the original unknown winner')
        self.unload_history()
        node.invalidateblock(first_block)
        self.restart_node(0, extra_args=self.extra_args[0])
        self.load_history()
        for name in self.names:
            wallet = node.get_wallet_rpc(name)
            assert_equal(wallet.gettransaction(self.loser)['confirmations'], 0)
            assert_equal(wallet.gettransaction(self.spend_id)['confirmations'], 0)
            available, = wallet.listunspent()
            assert_equal((available['output_id'], available['amount']), (self.source_id, Decimal(5)))
        self.unload_history()
        replacement_block = self.mine_winner(winners[1])
        self.load_history()
        self.check_unknown(winners[1], replacement_block)
        self.unload_history()
        node.invalidateblock(replacement_block)
        self.restart_node(0, extra_args=self.extra_args[0])
        final_block = self.mine_winner(winners[0])
        self.load_history()
        self.check_unknown(winners[0], final_block)

        self.log.info('A real full body on rebroadcast replaces spend and change placeholders')
        node.invalidateblock(final_block)
        node.sendrawtransaction(winners[0]['hex'])
        node.syncwithvalidationinterfacequeue()
        node.reconsiderblock(final_block)
        node.syncwithvalidationinterfacequeue()
        for name in self.names:
            wallet = node.get_wallet_rpc(name)
            full = wallet.gettransaction(winners[0]['txid'])
            assert 'partial_mweb' not in full
            assert_equal((full['confirmations'], full['blockhash'], full['fee']),
                         (1, final_block, -winners[0]['fee']))
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', wallet.gettransaction, self.spend_id)
            receive_id = blake3(b'R' + bytes.fromhex(winners[0]['change_id'])).to_byte_arr()[::-1].hex()
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', wallet.gettransaction, receive_id)
            assert_equal(wallet.gettransaction(self.loser)['walletconflicts'], [winners[0]['txid']])
            unspent, = wallet.listunspent()
            assert_equal((unspent['txid'], unspent['output_id'], unspent['amount']),
                         (winners[0]['txid'], winners[0]['change_id'], winners[0]['change']))
            before = self.snapshot(wallet)
            wallet.rescanblockchain(0)
            assert_equal(self.snapshot(wallet), before)
        assert_equal(self.snapshot(node.get_wallet_rpc(self.names[0])), self.snapshot(node.get_wallet_rpc(self.names[1])))

    def mine_winner(self, winner):
        node = self.nodes[0]
        assert_equal(node.sendrawtransaction(winner['hex']), winner['txid'])
        node.syncwithvalidationinterfacequeue()
        miner = node.get_wallet_rpc(self.default_wallet_name)
        received, = miner.listunspent(minconf=0, addresses=[winner['recipient']])
        ids = {out['output_id'] for out in node.decoderawtransaction(winner['hex'])['vout']}
        change_id, = ids - {received['output_id']}
        winner['change_id'] = change_id
        # Re-mining an invalidated branch must produce a fresh block identity.
        node.setmocktime(self.mining_time)
        self.mining_time += 10
        return self.generate(node, 1)[0]

    def check_unknown(self, winner, block):
        node = self.nodes[0]
        snapshots = []
        for name in self.names:
            wallet = node.get_wallet_rpc(name)
            partial = wallet.gettransaction(self.spend_id)
            assert_equal(partial['partial_mweb'], {'spent': {'output_id': self.source_id}})
            assert_equal((partial['confirmations'], partial['blockhash']), (1, block))
            assert_equal((partial['amount'], partial['fee']), (Decimal(-5), Decimal(0)))
            record, = wallet.listwallettransactions(txid=self.spend_id)
            # Bitcoin's native all-owned-input/empty-output classification is
            # SendToSelf here. The debit/net is still the entire known input;
            # Litecoin's separate Other presentation is not imposed.
            assert_equal((record['type'], record['amount'], record['net'], record['fee']),
                         ('SendToSelf', Decimal(-5), Decimal(-5), Decimal(0)))
            assert not any(key in record for key in ('address', 'vout', 'mweb_out', 'pegout'))
            assert_equal(wallet.gettransaction(self.loser)['walletconflicts'], [self.spend_id])
            assert_equal(wallet.gettransaction(self.loser)['confirmations'], -1)
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', wallet.gettransaction, winner['txid'])
            change, = wallet.listunspent()
            assert_equal((change['output_id'], change['amount'], change['address'], change['confirmations']),
                         (winner['change_id'], winner['change'], self.change_address, 1))
            assert_equal(wallet.getbalances()['mine']['trusted'], winner['change'])
            receipt, = [row for row in wallet.listtransactions(count=1000)
                        if row.get('mweb_out') == winner['change_id'] and row['category'] == 'receive']
            assert_equal((receipt['txid'], receipt['amount']), (change['txid'], winner['change']))
            typed_receipt, = wallet.listwallettransactions(txid=change['txid'])
            assert_equal((typed_receipt['type'], typed_receipt['mweb_out'], typed_receipt['amount']),
                         ('RecvWithAddress', winner['change_id'], winner['change']))
            active_rows = [row['txid'] for row in wallet.listwallettransactions()
                           if row['confirmations'] > 0 and row['txid'] != self.funding]
            assert_equal(active_rows, [change['txid'], self.spend_id])
            snapshots.append(self.snapshot(wallet))
        assert_equal(*snapshots)

    def snapshot(self, wallet):
        coins = sorted((c['output_id'], c['amount'], c['address'], c['confirmations']) for c in wallet.listunspent())
        history = sorted((r['txid'], r['type'], r['amount'], r['net'], r['confirmations'], r.get('mweb_out'))
                         for r in wallet.listwallettransactions())
        return coins, history, wallet.getbalances()['mine'], wallet.getwalletinfo()['txcount']

    def unload_history(self):
        for name in self.names:
            self.nodes[0].unloadwallet(name, load_on_startup=False)

    def load_history(self):
        for name in self.names:
            self.nodes[0].loadwallet(name, load_on_startup=False)


if __name__ == '__main__':
    MWEBWalletHistoryRecoveryTest(__file__).main()
