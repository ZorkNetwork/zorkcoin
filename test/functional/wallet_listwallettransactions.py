#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listwallettransactions API for MWEB transactions.

Ported from Litecoin Core. Also checks the entry keys: "vout" for L1 outputs,
"mweb_out" for MWEB outputs, "pegout" for peg-outs, and "fee" on sends.
"""
from decimal import Decimal

from test_framework.mweb_util import generate, init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_array_result, assert_equal, assert_greater_than, assert_raises_rpc_error


class ListWalletTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1'], ['-whitelist=noban@127.0.0.1'], [])  # immediate tx relay

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def mine(self, node):
        blockhash = generate(node, 1)[0]
        self.sync_all()
        return blockhash, node.getblockheader(blockhash)['height']

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        # Setup MWEB chain using node0 as miner
        setup_mweb_chain(node0, self)
        self.sync_all()

        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", node0.listwallettransactions, "00" * 32)

        # Simple send, 0 to 1:
        txid = node0.sendtoaddress(node1.getnewaddress(), 0.1)
        self.sync_all()
        assert_array_result(node0.listwallettransactions(txid),
                            {"txid": txid},
                            {"type": "SendToAddress", "amount": Decimal("-0.1"), "confirmations": 0})
        assert_array_result(node1.listwallettransactions(),
                            {"txid": txid},
                            {"type": "RecvWithAddress", "amount": Decimal("0.1"), "confirmations": 0})
        send, = node0.listwallettransactions(txid)
        assert_greater_than(Decimal(0), send['fee'])
        assert_equal(send['net'], send['amount'] + send['fee'])
        assert_equal((send['abandoned'], send['vout'] in (0, 1)), (False, True))

        # mine a block, confirmations should change:
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node0.listwallettransactions(),
                            {"txid": txid},
                            {"type": "SendToAddress", "amount": Decimal("-0.1"), "confirmations": 1, "blockhash": blockhash, "blockheight": blockheight})
        assert_array_result(node1.listwallettransactions(),
                            {"txid": txid},
                            {"type": "RecvWithAddress", "amount": Decimal("0.1"), "confirmations": 1, "blockhash": blockhash, "blockheight": blockheight})

        # send-to-self:
        txid = node0.sendtoaddress(node0.getnewaddress(), 0.2)
        assert_array_result(node0.listwallettransactions(),
                            {"txid": txid, "type": "SendToSelf"},
                            {"amount": Decimal("0.2")})

        # pegin to self
        node0_mweb_addr = node0.getnewaddress(address_type='mweb')
        txid = node0.sendtoaddress(node0_mweb_addr, 0.4)
        assert_array_result(node0.listwallettransactions(),
                            {"txid": txid, "type": "SendToSelf"},
                            {"amount": Decimal("0.4")})

        # mine a block, confirmations should change:
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node0.listwallettransactions(),
                            {"txid": txid, "type": "SendToSelf"},
                            {"amount": Decimal("0.4"), "confirmations": 1, "blockhash": blockhash, "blockheight": blockheight})

        # pegin from 0 to 1
        node1_mweb_addr = node1.getnewaddress(address_type='mweb')
        txid = node0.sendtoaddress(node1_mweb_addr, 5)
        self.sync_all()
        assert_array_result(node0.listwallettransactions(txid),
                            {"txid": txid},
                            {"type": "SendToAddress", "amount": Decimal("-5.0"), "confirmations": 0, "address": node1_mweb_addr})
        assert_array_result(node1.listwallettransactions(),
                            {"address": node1_mweb_addr},
                            {"type": "RecvWithAddress", "amount": Decimal("5.0"), "confirmations": 0})
        sent, = node0.listwallettransactions(txid)
        received, = [t for t in node1.listwallettransactions() if t.get("address") == node1_mweb_addr]
        assert_equal(sent['mweb_out'], received['mweb_out'])
        assert 'vout' not in sent and 'vout' not in received

        # mine a block, confirmations should change:
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node0.listwallettransactions(txid),
                            {"txid": txid},
                            {"type": "SendToAddress", "amount": Decimal("-5.0"), "confirmations": 1, "blockheight": blockheight, "address": node1_mweb_addr})
        assert_array_result(node1.listwallettransactions(),
                            {"address": node1_mweb_addr},
                            {"type": "RecvWithAddress", "amount": Decimal("5.0"), "confirmations": 1, "blockheight": blockheight})

        # pegout from 1 to 0 (node0 online)
        node0_addr = node0.getnewaddress()
        txid = node1.sendtoaddress(node0_addr, 3)
        self.sync_all()
        assert_array_result(node1.listwallettransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "type": "SendToAddress", "amount": Decimal("-3.0"), "confirmations": 0})
        assert_array_result(node0.listwallettransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "type": "RecvWithAddress", "amount": Decimal("3.0"), "confirmations": 0})
        sent, = [t for t in node1.listwallettransactions() if t.get("address") == node0_addr]
        received, = [t for t in node0.listwallettransactions() if t.get("address") == node0_addr]
        kernel_id, pos = sent['pegout'].split(':')
        assert_equal((len(kernel_id), pos), (64, '0'))
        assert_equal(received['pegout'], sent['pegout'])
        assert_greater_than(Decimal(0), sent['fee'])

        # mine a block, confirmations should change:
        blockhash, blockheight = self.mine(node0)
        assert_array_result(node1.listwallettransactions(),
                            {"address": node0_addr},
                            {"txid": txid, "type": "SendToAddress", "amount": Decimal("-3.0"), "confirmations": 1, "blockheight": blockheight})
        assert_array_result(node0.listwallettransactions(),
                            {"address": node0_addr},
                            {"type": "RecvWithAddress", "amount": Decimal("3.0"), "confirmations": 1, "blockheight": blockheight})
        # The HogEx output is listed through the MWEB transaction that pays it.
        assert_equal([t['txid'] for t in node0.listwallettransactions() if t.get("address") == node0_addr], [txid])

        # pegout from 1 to 2 and mine a block while node2 is offline
        # node2 won't see the original MWEB transaction; just the pegout kernel and hogex output.
        node2_addr = node2.getnewaddress()
        node2_mweb_addr = node2.getnewaddress(address_type='mweb')
        self.stop_node(2)
        txid = node1.sendtoaddress(node2_addr, 1)
        node1.sendtoaddress(node2_mweb_addr, Decimal("0.7"))
        blockhash = generate(node1, 1)[0]
        blockheight = node1.getblockheader(blockhash)['height']
        hogex_txid = node1.getblock(blockhash)['tx'][-1]
        self.start_node(2)
        self.connect_nodes(2, 0)
        self.connect_nodes(2, 1)
        self.sync_all()

        assert_array_result(node1.listwallettransactions(),
                            {"address": node2_addr},
                            {"txid": txid, "type": "SendToAddress", "amount": Decimal("-1.0"), "confirmations": 1, "blockheight": blockheight})
        assert_array_result(node2.listwallettransactions(),
                            {"address": node2_addr},
                            {"txid": hogex_txid, "type": "RecvWithAddress", "amount": Decimal("1.0"), "confirmations": 1, "blockheight": blockheight, "vout": 1})
        assert_array_result(node2.listwallettransactions(),
                            {"address": node2_mweb_addr},
                            {"type": "RecvWithAddress", "amount": Decimal("0.7"), "confirmations": 1, "blockheight": blockheight})

        # Entries are newest first.
        heights = [t.get('blockheight', 1 << 31) for t in node0.listwallettransactions()]
        assert_equal(heights, sorted(heights, reverse=True))


if __name__ == '__main__':
    ListWalletTransactionsTest(__file__).main()
