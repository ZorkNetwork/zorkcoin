#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""MWEB block weight / BIP324 packing test

Confirms templates may exceed Litecoin's old MAX_MINE_WEIGHT soft-cap
(~512 stealth pegins ≈ 20k weight) when consensus MWEB weight and the
BIP324 wire-size budget allow. This functional covers soft-cap removal at
~10-11% of max MWEB weight. Architected near-cap / NO_GAP packing proofs
live in unit test mweb_block_packing_tests (and EXTENDED mweb_block_packing.py).

Note: with -spendzeroconfchange=0 each unconfirmed send consumes a mature
UTXO, so batch size must stay below the mining node's mature coinbase count.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import init_mweb_wallet, mweb_extra_args, setup_mweb_chain
from test_framework.util import assert_equal, assert_greater_than

class MWEBWeightTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.rpc_timeout = 120
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(["-spendzeroconfchange=0"], ["-spendzeroconfchange=0"], ["-spendzeroconfchange=0"])

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Create pre-MWEB blocks and activate MWEB")
        setup_mweb_chain(self.nodes[0], self)
        self.sync_all()

        self.log.info("Pegin more coins for weight testing")
        addr = self.nodes[0].getnewaddress(address_type='mweb')
        self.nodes[0].sendtoaddress(addr, 1)
        self.sync_all()
        self.generate(self.nodes[1], 1)
        self.sync_all()

        # Mine enough blocks for coinbase maturity on all nodes
        self.generate(self.nodes[1], 700)
        self.sync_all()

        # Workaround for syncing issue
        self.generate(self.nodes[2], 1)
        self.sync_all()

        self.generate(self.nodes[2], 700)
        self.sync_all()

        # Former Litecoin soft-cap was MAX_MINE_WEIGHT/39 ≈ 512 pegins.
        old_mine_cap_pegins = 512
        # Stay above soft-cap but under ~700 mature coinbases on node 1
        # (spendzeroconfchange=0 prevents spending unconfirmed change).
        tx_over_old_mine_cap = old_mine_cap_pegins + 20  # 532

        self.log.info("Create %d pegins (above old MAX_MINE_WEIGHT soft-cap of ~%d)",
                      tx_over_old_mine_cap, old_mine_cap_pegins)
        addr = self.nodes[0].getnewaddress(address_type='mweb')
        for _ in range(tx_over_old_mine_cap):
            self.nodes[1].sendtoaddress(addr, 1)
        assert_equal(len(self.nodes[1].getrawmempool()), tx_over_old_mine_cap)

        self.log.info("Mine one block — all should fit (soft-cap removed)")
        blockhash = self.generate(self.nodes[1], 1)[0]
        self.sync_all()

        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        utxos = self.nodes[0].listunspent(addresses=[addr])
        assert_equal(len(utxos), tx_over_old_mine_cap)
        assert all(x['amount'] == 1 and x['spendable'] for x in utxos)
        assert_greater_than(len(utxos), old_mine_cap_pegins)

        tip_bytes = len(self.nodes[1].getblock(blockhash, 0)) // 2
        self.log.info("Mined block wire size: %d bytes", tip_bytes)
        assert tip_bytes <= 16_777_214, tip_bytes

        # Second node: another above-soft-cap batch must also clear in one block.
        # Use small amounts so node 2's mature UTXO count is not the limiter.
        batch2 = old_mine_cap_pegins + 50  # 562
        self.log.info("Node 2 queues %d small pegins (also above old soft-cap)", batch2)
        addr2 = self.nodes[0].getnewaddress(address_type='mweb')
        for _ in range(batch2):
            self.nodes[2].sendtoaddress(addr2, 0.01)
        assert_equal(len(self.nodes[2].getrawmempool()), batch2)

        blockhash2 = self.generate(self.nodes[2], 1)[0]
        self.sync_all()
        assert_equal(len(self.nodes[2].getrawmempool()), 0)

        utxos2 = self.nodes[0].listunspent(addresses=[addr2])
        assert_equal(len(utxos2), batch2)
        assert all(x['amount'] == Decimal('0.01') and x['spendable'] for x in utxos2)

        tip2_bytes = len(self.nodes[2].getblock(blockhash2, 0)) // 2
        assert tip2_bytes <= 16_777_214, tip2_bytes

if __name__ == '__main__':
    MWEBWeightTest(__file__).main()
