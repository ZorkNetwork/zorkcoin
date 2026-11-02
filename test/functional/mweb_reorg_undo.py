#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB reorg undo consistency tests.

Exercises invalidateblock and multi-node fork reorgs after MWEB activation.
Verifies MWEB chainstate (balances, headers, spends) stays consistent — the
user-visible failure mode of skipped MWEB undo during disconnect.
"""

from test_framework.mweb_util import (
    generatetoaddress,
    get_mweb_header,
    mweb_extra_args,
    reconnect_mweb_peers,
    setup_mweb_chain,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _is_mweb_address(addr):
    return bool(addr) and addr.startswith(('tmweb', 'mweb'))


def mweb_balance(node):
    return sum(
        utxo['amount']
        for utxo in node.listunspent()
        if _is_mweb_address(utxo.get('address', ''))
    )


def mweb_utxo_count(node):
    return len([u for u in node.listunspent() if _is_mweb_address(u.get('address', ''))])


class MWEBReorgUndoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1'],
            [],
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.deep_invalidateblock_reorg_test()
        self.multi_node_fork_reorg_test()
        self.post_reorg_mweb_spend_test()
        self.verifychain_multiblock_mweb_test()
        self.coin_spend_undo_test()

    def coin_spend_undo_test(self):
        """Undo an actual coin spend, persist it, and restore the exact state."""
        node = self.nodes[0]
        self.sync_all()
        node.syncwithvalidationinterfacequeue()
        coin = next(u for u in node.listunspent(1) if u.get('output_id') and u['amount'] > 1)
        before_tip = node.getbestblockhash()
        before = node.dumptxoutset('coin_undo_before.dat', 'latest')['mweb_hash']
        spend = node.send(outputs={node.getnewaddress(address_type='mweb'): 1}, options={
            'inputs': [{'output_id': coin['output_id']}], 'add_inputs': False,
        })['txid']
        block = self.generate(node, 1)[0]
        after = node.dumptxoutset('coin_undo_after.dat', 'latest')['mweb_hash']
        assert before != after

        node.invalidateblock(block)
        assert_equal(node.getbestblockhash(), before_tip)
        assert spend in node.getrawmempool()
        assert_equal(node.dumptxoutset('coin_undo_disconnected.dat', 'latest')['mweb_hash'], before)
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), before_tip)
        assert_equal(node.dumptxoutset('coin_undo_restarted.dat', 'latest')['mweb_hash'], before)
        assert node.verifychain(4, 0)

        node.reconsiderblock(block)
        assert_equal(node.getbestblockhash(), block)
        assert spend not in node.getrawmempool()
        assert_equal(node.dumptxoutset('coin_undo_restored.dat', 'latest')['mweb_hash'], after)
        assert node.verifychain(4, 0)
        self.sync_all()

    def deep_invalidateblock_reorg_test(self):
        self.log.info("Deep invalidateblock reorg with MWEB peg-in chain")
        node = self.nodes[0]
        setup_mweb_chain(node, test=self)

        addr = node.getnewaddress(address_type='mweb')
        node.sendtoaddress(addr, 5)
        self.generate(node, 6)
        self.sync_all()

        balance_before = mweb_balance(node)
        assert balance_before > 0
        tip_hash = node.getbestblockhash()
        tip_header = get_mweb_header(node, tip_hash)
        assert tip_header is not None

        # Invalidate several MWEB blocks and build a longer competing branch.
        fork_hash = node.getblockhash(node.getblockcount() - 4)
        node.invalidateblock(fork_hash)
        reconnect_mweb_peers(self)
        assert node.getblockcount() < self.nodes[1].getblockcount()

        # Use a fresh payout address so the replacement chain is not byte-identical
        # to the invalidated blocks (see mweb_p2p.test_inactive_chain_requests).
        generatetoaddress(node, 8, node.getnewaddress())
        self.sync_blocks()

        balance_after = mweb_balance(node)
        assert_equal(balance_after, balance_before)

        new_tip = node.getbestblockhash()
        new_header = get_mweb_header(node, new_tip)
        assert new_header is not None
        assert new_tip != tip_hash

    def multi_node_fork_reorg_test(self):
        self.log.info("Multi-node fork reorg with MWEB activity")
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        setup_mweb_chain(node0, test=self)
        addr0 = node0.getnewaddress(address_type='mweb')
        addr1 = node1.getnewaddress(address_type='mweb')
        node0.sendtoaddress(addr0, 3)
        node0.sendtoaddress(addr1, 3)
        self.generate(node0, 8)
        self.sync_all()

        balance0 = mweb_balance(node0)
        balance1 = mweb_balance(node1)
        assert balance0 > 0
        assert balance1 > 0

        self.disconnect_nodes(0, 1)
        generatetoaddress(node0, 5, node0.getnewaddress())
        generatetoaddress(node1, 5, node1.getnewaddress())

        self.connect_nodes(0, 1)
        reconnect_mweb_peers(self)
        self.generate(node0, 1)
        self.sync_blocks()

        assert mweb_balance(node0) > 0
        assert mweb_balance(node1) >= 3

    def post_reorg_mweb_spend_test(self):
        self.log.info("MWEB spend after invalidateblock reorg")
        node = self.nodes[0]
        setup_mweb_chain(node, test=self)

        addr = node.getnewaddress(address_type='mweb')
        node.sendtoaddress(addr, 10)
        self.generate(node, 4)
        self.sync_all()

        utxos_before = mweb_utxo_count(node)
        assert utxos_before >= 1

        invalidate_target = node.getblockhash(node.getblockcount() - 2)
        node.invalidateblock(invalidate_target)
        reconnect_mweb_peers(self)

        generatetoaddress(node, 4, node.getnewaddress())
        self.sync_all()

        assert mweb_utxo_count(node) >= 1
        assert mweb_balance(node) > 0

        peer_addr = self.nodes[1].getnewaddress(address_type='mweb')
        node.sendtoaddress(peer_addr, 1)
        self.generate(node, 1)
        self.sync_all()

        peer_utxos = self.nodes[1].listunspent(addresses=[peer_addr])
        assert_equal(len(peer_utxos), 1)
        assert_equal(peer_utxos[0]['amount'], 1)

    def verifychain_multiblock_mweb_test(self):
        # Multi-block walker undo integrity: VerifyDB level >= 3 disconnects many blocks
        # through a single coins view. MWEB undo state must accumulate across
        # blocks; a per-block MWEB cache refresh corrupts the walk and reports
        # false chain corruption. The chain at this point contains many MWEB
        # blocks with peg-ins, transfers, and reorged history.
        self.log.info("verifychain level 4 across MWEB blocks (multi-block walker undo)")
        for node in self.nodes:
            assert node.verifychain(4, 30)
            assert node.verifychain(3, 0)


if __name__ == '__main__':
    MWEBReorgUndoTest(__file__).main()
