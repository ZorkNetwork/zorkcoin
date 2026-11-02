#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Peg-out spends must leave the mempool when a reorg re-immatures them.

Consensus rejects immature peg-out spends at ConnectBlock time, but
MaybeUpdateMempoolForReorg historically only re-checked coinbase maturity.
A peg-out spend that was valid at tip T could survive a disconnect that
makes the peg-out immature again and poison subsequent templates.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.mweb_util import (
    get_hogex_tx,
    generate,
    init_mweb_wallet,
    setup_mweb_chain,
    with_mweb_vbparams,
)

# Matches consensus/consensus.h PEGOUT_MATURITY.
PEGOUT_MATURITY = 6


class MWEBPegoutMaturityReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [with_mweb_vbparams([])]

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Activate MWEB")
        setup_mweb_chain(node)

        self.log.info("Fund a wallet that holds only MWEB coins (forces peg-out)")
        node.createwallet(wallet_name="mweb_only", load_on_startup=False)
        mweb_only = node.get_wallet_rpc("mweb_only")
        wallet.sendtoaddress(mweb_only.getnewaddress(address_type='mweb'), Decimal("25"))
        generate(node, 1)

        self.log.info("Peg out while the receiving wallet is unloaded")
        node.createwallet(wallet_name="late_receiver", load_on_startup=False)
        receiver = node.get_wallet_rpc("late_receiver")
        pegout_addr = receiver.getnewaddress(address_type='bech32')
        node.createwallet(wallet_name="watch_receiver", disable_private_keys=True, blank=True, load_on_startup=False)
        watch = node.get_wallet_rpc("watch_receiver")
        imported, = watch.importdescriptors([{
            'desc': receiver.getaddressinfo(pegout_addr)['desc'], 'timestamp': 0,
        }])
        assert_equal(imported['success'], True)
        assert_equal(watch.getwalletinfo()['private_keys_enabled'], False)
        node.unloadwallet("watch_receiver")
        assert_equal(receiver.listtransactions(), [])
        node.unloadwallet("late_receiver")
        assert "late_receiver" not in node.listwallets()
        source_txid = mweb_only.sendtoaddress(pegout_addr, Decimal("10"))
        pegout_block = generate(node, 1)[0]
        pegout_height = node.getblockcount()
        assert "late_receiver" not in node.listwallets()
        assert source_txid not in node.getrawmempool()

        hogex = get_hogex_tx(node, pegout_block)
        assert_equal(len(hogex.vout), 2)  # HogAddr + one peg-out
        # listunspent hides HogEx peg-outs until PEGOUT_MATURITY confirmations.
        pegout_outpoint = {'txid': hogex.hash, 'vout': 1}

        self.log.info("The late receiver learns only the historical HogEx receipt")
        node.loadwallet("late_receiver")
        receiver = node.get_wallet_rpc("late_receiver")
        assert_equal(receiver.rescanblockchain(0)['stop_height'], pegout_height)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id",
                               receiver.gettransaction, source_txid)
        receipt, = receiver.listtransactions()
        assert_equal((receipt['txid'], receipt['address'], receipt['amount'], receipt['category'], receipt['confirmations']),
                     (hogex.hash, pegout_addr, Decimal("10"), 'immature', 1))
        assert_equal(receiver.listunspent(addresses=[pegout_addr]), [])

        self.log.info("A public L1 descriptor observes the same historical HogEx peg-out")
        node.loadwallet("watch_receiver")
        watch = node.get_wallet_rpc("watch_receiver")
        assert_equal(watch.rescanblockchain(0)['stop_height'], pegout_height)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", watch.gettransaction, source_txid)
        assert_equal(len(watch.listwallettransactions()), 1)
        self.assert_watch_receipt(watch, hogex.hash, pegout_addr, confirmations=1, mature=False)

        # Peg-out coin is created in HogEx at height H. It is mature for
        # mempool acceptance when tip+1 - H >= PEGOUT_MATURITY,
        # i.e. tip >= H + PEGOUT_MATURITY - 1.
        self.log.info("Mine until the peg-out is mature for mempool spends")
        generate(node, PEGOUT_MATURITY - 1)
        assert_equal(node.getblockcount(), pegout_height + PEGOUT_MATURITY - 1)

        self.log.info("The wallet lists the peg-out once it can be spent in the next block")
        assert_equal([(u['txid'], u['vout']) for u in receiver.listunspent(minconf=1, addresses=[pegout_addr])],
                     [(hogex.hash, 1)])
        self.assert_watch_receipt(watch, hogex.hash, pegout_addr, confirmations=PEGOUT_MATURITY, mature=True)

        self.log.info("Spend the mature peg-out into the mempool")
        spend_addr = receiver.getnewaddress(address_type='bech32')
        raw = receiver.createrawtransaction(
            [pegout_outpoint],
            [{spend_addr: Decimal("9.99")}],
        )
        watch_signed = watch.signrawtransactionwithwallet(raw)
        assert_equal(watch_signed['complete'], False)
        error, = watch_signed['errors']
        assert_equal((error['txid'], error['vout']), (hogex.hash, 1))
        signed = receiver.signrawtransactionwithwallet(raw)
        assert signed['complete']
        spend_txid = node.sendrawtransaction(signed['hex'])
        assert spend_txid in node.getrawmempool()

        self.log.info("Disconnect one block so the peg-out is immature again")
        # tip was H+5; after invalidate tip is H+4 → spend height H+5 → depth 5 < 6.
        tip_hash = node.getbestblockhash()
        node.invalidateblock(tip_hash)
        assert_equal(node.getblockcount(), pegout_height + PEGOUT_MATURITY - 2)

        self.log.info("Immature peg-out spend must be removed from the mempool")
        assert spend_txid not in node.getrawmempool()
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-pegout", node.sendrawtransaction, signed['hex'])

        # Peg-out creating block itself remains valid on this shorter tip.
        assert_equal(node.getblock(pegout_block)['confirmations'], PEGOUT_MATURITY - 1)

        self.log.info("Undo data must restore the peg-out flag of a spent peg-out")
        node.reconsiderblock(tip_hash)
        assert_equal(node.getblockcount(), pegout_height + PEGOUT_MATURITY - 1)
        node.sendrawtransaction(signed['hex'])
        spend_block = generate(node, 1)[0]
        assert spend_txid in node.getblock(spend_block)['tx']
        assert spend_txid not in node.getrawmempool()

        # Disconnecting the spending block restores the peg-out coin from undo
        # data and returns the spend to the mempool (still mature at H+6).
        node.invalidateblock(spend_block)
        assert spend_txid in node.getrawmempool()

        # One more disconnect makes the restored peg-out immature again. This
        # only evicts the spend if the undo data kept the coin's peg-out flag.
        node.invalidateblock(tip_hash)
        assert_equal(node.getblockcount(), pegout_height + PEGOUT_MATURITY - 2)
        assert spend_txid not in node.getrawmempool()
        assert_equal(node.gettxout(hogex.hash, 1)['value'], Decimal("10"))
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-pegout", node.sendrawtransaction, signed['hex'])
        # The observer also retains the now-inactive spend it saw on the old
        # branch. It must not be mistaken for a duplicate receiving record.
        history = watch.listwallettransactions()
        assert_equal(len(history), 2)
        assert_equal({record['txid'] for record in history}, {hogex.hash, spend_txid})
        sent, = watch.listwallettransactions(txid=spend_txid)
        assert_equal((sent['type'], sent['amount'], sent['net'], sent['fee'], sent['confirmations'], sent['trusted']),
                     ('SendToAddress', Decimal("-9.99"), Decimal("-10"), Decimal("-0.01"), 0, False))
        self.assert_watch_receipt(watch, hogex.hash, pegout_addr,
                                  confirmations=PEGOUT_MATURITY - 1, mature=False)

        self.test_wallet_maturity(node, mweb_only)
        self.test_hogex_suppresses_only_known_mapping(node, mweb_only)

    def test_hogex_suppresses_only_known_mapping(self, node, sender):
        self.log.info("History suppresses only a known same-block peg-out mapping")
        node.createwallet(wallet_name="mapping_receiver", load_on_startup=False)
        receiver = node.get_wallet_rpc("mapping_receiver")
        address = receiver.getnewaddress(address_type='bech32')
        known_txid = sender.sendtoaddress(address, Decimal("1"))
        node.syncwithvalidationinterfacequeue()
        assert_equal(receiver.gettransaction(known_txid)['confirmations'], 0)
        known_kernel, = node.decoderawtransaction(sender.gettransaction(known_txid)['hex'])['vkern']
        backup = str(node.datadir_path / "mapping_receiver.bak")
        receiver.backupwallet(backup)
        node.unloadwallet("mapping_receiver")

        # The backup knows the first full body. A second kernel pays the same
        # address a different amount while this receiver is offline.
        unknown_txid = sender.sendtoaddress(address, Decimal("2"))
        blockhash = generate(node, 1)[0]
        hogex = get_hogex_tx(node, blockhash)
        assert_equal(sorted(output.nValue for output in hogex.vout[1:]), [100_000_000, 200_000_000])
        unknown_vout, = [i for i, output in enumerate(hogex.vout) if output.nValue == 200_000_000]

        node.restorewallet(wallet_name="mapping_restored", backup_file=backup, load_on_startup=False)
        receiver = node.get_wallet_rpc("mapping_restored")
        receiver.rescanblockchain(0)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", receiver.gettransaction, unknown_txid)
        known, = receiver.listwallettransactions(txid=known_txid)
        assert_equal((known['type'], known['address'], known['amount'], known['net'], known['pegout'], known['confirmations']),
                     ('RecvWithAddress', address, Decimal("1"), Decimal("1"), known_kernel['kernel_id'] + ':0', 1))
        unknown, = receiver.listwallettransactions(txid=hogex.hash)
        assert_equal((unknown['type'], unknown['address'], unknown['amount'], unknown['net'], unknown['vout'], unknown['confirmations']),
                     ('RecvWithAddress', address, Decimal("2"), Decimal("2"), unknown_vout, 1))
        history = receiver.listwallettransactions()
        assert_equal(len(history), 2)
        assert_equal({record['txid'] for record in history}, {known_txid, hogex.hash})
        listed, = receiver.listreceivedbyaddress(address_filter=address)
        assert_equal(listed['amount'], Decimal("3"))
        mine = receiver.getbalances()['mine']
        assert_equal((mine['trusted'], mine['untrusted_pending'], mine['immature']), (0, 0, Decimal("3")))
        node.unloadwallet("mapping_restored")
        node.loadwallet("mapping_restored")
        assert_equal(node.get_wallet_rpc("mapping_restored").listwallettransactions(), history)

    def assert_watch_receipt(self, watch, hogex_txid, address, *, confirmations, mature):
        assert_equal(watch.getwalletinfo()['private_keys_enabled'], False)
        record, = watch.listwallettransactions(txid=hogex_txid)
        assert_equal((record['type'], record['txid'], record['vout'], record['address'], record['amount'], record['net']),
                     ('RecvWithAddress', hogex_txid, 1, address, Decimal("10"), Decimal("10")))
        assert_equal(record['confirmations'], confirmations)
        assert 'fee' not in record
        # Native descriptor ownership is wallet-scoped. The legacy RPC watch-only
        # filter is deprecated, and both values retain the public descriptor's receipt.
        assert_equal(watch.listtransactions(include_watchonly=False), watch.listtransactions(include_watchonly=True))
        receipt, = [row for row in watch.listtransactions() if row['txid'] == hogex_txid]
        assert_equal((receipt['amount'], receipt['category']), (Decimal("10"), 'hogex' if mature else 'immature'))
        assert_equal(watch.gettransaction(hogex_txid)['amount'], Decimal("10"))
        mine = watch.getbalances()['mine']
        assert_equal(mine['trusted'], Decimal("10") if mature else 0)
        assert_equal(mine['immature'], 0 if mature else Decimal("10"))
        assert_equal(mine['untrusted_pending'], 0)
        coins = watch.listunspent(addresses=[address])
        assert_equal([(coin['txid'], coin['vout'], coin['amount']) for coin in coins],
                     [(hogex_txid, 1, Decimal("10"))] if mature else [])

    def test_wallet_maturity(self, node, mweb_only):
        self.log.info("The wallet counts a peg-out as immature until consensus maturity, as Litecoin does")
        node.createwallet(wallet_name="receiver", load_on_startup=False)
        receiver = node.get_wallet_rpc("receiver")
        mweb_only.sendtoaddress(receiver.getnewaddress(address_type='bech32'), Decimal("1"))
        generate(node, PEGOUT_MATURITY - 1)
        assert_equal(receiver.getbalances()['mine']['immature'], Decimal("1"))
        assert_equal(receiver.listunspent(query_options={'include_immature_coinbase': True}), [])

        generate(node, 1)
        assert_equal(receiver.getbalances()['mine']['immature'], 0)
        assert_equal([u['amount'] for u in receiver.listunspent()], [Decimal("1")])


if __name__ == '__main__':
    MWEBPegoutMaturityReorgTest(__file__).main()
