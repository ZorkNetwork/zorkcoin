#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB chainstate recovery after an interrupted coins DB flush."""

import errno
import http.client
from decimal import Decimal

from test_framework.mweb_util import init_mweb_wallet, generatetoaddress, setup_mweb_chain, with_mweb_vbparams
from test_framework.messages import COIN, CBlock, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBDBCrashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [with_mweb_vbparams([])]
        self.rpc_timeout = 120
        self.supports_cli = False

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_flush_crashes(self, node):
        try:
            node.gettxoutsetinfo()
        except (http.client.CannotSendRequest, http.client.RemoteDisconnected):
            node.wait_until_stopped(timeout=30)
            return
        except OSError as e:
            if e.errno not in [errno.EPIPE, errno.ECONNREFUSED, errno.ECONNRESET]:
                raise
            node.wait_until_stopped(timeout=30)
            return

        raise AssertionError("Expected gettxoutsetinfo to trigger -dbcrashratio=1")

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Set up MWEB and create an isolated MWEB-only funding wallet")
        setup_mweb_chain(node)
        node.createwallet(wallet_name="funder", load_on_startup=True)
        node.createwallet(wallet_name="spender", load_on_startup=True)
        funder = node.get_wallet_rpc("funder")
        spender = node.get_wallet_rpc("spender")

        funder_addr = funder.getnewaddress(address_type="mweb")
        miner.sendtoaddress(funder_addr, Decimal("1.0"))
        generatetoaddress(node, 1, miner.getnewaddress())
        funding_coins = funder.listunspent(addresses=[funder_addr])
        assert_equal(len(funding_coins), 1)
        funding_id = funding_coins[0]['output_id']

        self.log.info("Flush the pre-crash MWEB state to make the replay window precise")
        node.gettxoutsetinfo()
        clean_tip = node.getbestblockhash()
        clean_block = node.getblock(clean_tip, 2)
        previous_hogex = clean_block['tx'][-1]['txid']

        self.log.info("Restart with deterministic db crash simulation")
        self.restart_node(0, extra_args=with_mweb_vbparams(["-dbbatchsize=1", "-dbcrashratio=1"]))
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        funder = node.get_wallet_rpc("funder")
        spender = node.get_wallet_rpc("spender")
        assert_equal(node.getbestblockhash(), clean_tip)

        self.log.info("Mine a crash-window block that spends the funder's only MWEB coin")
        spender_addr = spender.getnewaddress(address_type="mweb")
        pegout_addr = miner.getnewaddress(address_type="bech32")
        pegout_amount = Decimal("0.1")
        crash_txid = funder.send(
            outputs=[{spender_addr: Decimal("0.5")}, {pegout_addr: pegout_amount}],
            options={'inputs': [{'output_id': funding_id}], 'add_inputs': False},
        )['txid']
        assert_equal(set(node.getrawmempool()), {crash_txid})
        crash_block_hash = generatetoaddress(node, 1, miner.getnewaddress())[0]
        crash_block = FromHex(CBlock(), node.getblock(crash_block_hash, 0))
        assert_equal([txin.output_id.to_hex() for txin in crash_block.mweb_block.body.inputs], [funding_id])
        crash_header = node.getblockheader(crash_block_hash)
        crash_height = crash_header['height']
        hogex = crash_block.vtx[-1]
        hogex.rehash()
        assert_equal(len(hogex.vout), 2)
        assert_equal([(txin.prevout.hash, txin.prevout.n) for txin in hogex.vin], [(int(previous_hogex, 16), 0)])
        assert_equal(hogex.vout[1].nValue, int(pegout_amount * COIN))
        pegout_script = miner.getaddressinfo(pegout_addr)['scriptPubKey']
        assert_equal(hogex.vout[1].scriptPubKey.hex(), pegout_script)
        assert_equal(crash_header['prev_mweb_amount'], clean_block['mweb_amount'])
        assert_equal(crash_header['mweb_amount'], clean_block['mweb_amount'] - int(pegout_amount * COIN)
                     - sum(kernel.fee or 0 for kernel in crash_block.mweb_block.body.kernels))
        assert_equal(crash_header['mweb_header']['height'], crash_height)
        assert_equal(crash_header['mweb_header']['num_txos'], clean_block['mweb_header']['num_txos'] + 2)
        received = spender.listunspent(addresses=[spender_addr])
        assert_equal(len(received), 1)
        received_id = received[0]['output_id']
        expected_outputs = {
            decoded['output_id']: output.serialize().hex()
            for decoded, output in zip(node.getblock(crash_block_hash, 2)['mweb']['outputs'],
                                       crash_block.mweb_block.body.outputs, strict=True)
        }
        change_coins = funder.listunspent()
        assert_equal(len(change_coins), 1)
        assert_equal(set(expected_outputs), {received_id, change_coins[0]['output_id']})

        def check_paired_state():
            assert_equal(node.getbestblockhash(), crash_block_hash)
            assert_equal(node.getblockheader(crash_block_hash), crash_header)
            assert_equal(funder.listunspent(addresses=[funder_addr]), [])
            coins = spender.listunspent(addresses=[spender_addr])
            assert_equal([(coin['output_id'], coin['amount'], coin['confirmations']) for coin in coins],
                         [(received_id, Decimal("0.5"), 1)])
            for output_id, output_hex in expected_outputs.items():
                # An explicit proof block checks both live roots against its header.
                proof = node.getmweboutputproof(output_id, crash_block_hash)
                assert_equal(proof['output_id'], output_id)
                assert_equal(proof['output'], output_hex)
                assert_equal(proof['blockhash'], crash_block_hash)
                assert_equal(proof['output_root'], crash_header['mweb_header']['output_root'])
                assert_equal(proof['num_leaves'], crash_header['mweb_header']['num_txos'])
                assert proof['leaf_index'] >= clean_block['mweb_header']['num_txos']
                assert node.verifymweboutputproof(proof)
            assert_raises_rpc_error(-5, "not unspent", node.getmweboutputproof, funding_id, crash_block_hash)
            assert_equal(node.getmweboutputproof(funding_id)['blockhash'], clean_tip)
            assert_equal(node.gettxout(previous_hogex, 0), None)
            for index, output in enumerate(hogex.vout):
                coin = node.gettxout(hogex.hash, index)
                assert_equal(coin['bestblock'], crash_block_hash)
                assert_equal(coin['confirmations'], 1)
                assert_equal(coin['coinbase'], False)
                assert_equal(coin['value'], Decimal(output.nValue) / COIN)
                assert_equal(coin['scriptPubKey']['hex'], output.scriptPubKey.hex())

        check_paired_state()

        self.log.info("Crash after the canonical partial batch but before MWEB state is durable")
        self.assert_flush_crashes(node)

        self.log.info("Restart and verify replay rolls MWEB state forward with the core UTXO set")
        self.start_node(0, extra_args=with_mweb_vbparams(["-dbbatchsize=1"]))
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        funder = node.get_wallet_rpc("funder")
        spender = node.get_wallet_rpc("spender")
        check_paired_state()

        # The recovered canonical coin must retain its pegout flag, observable
        # through the pegout-specific maturity check rather than a new RPC field.
        raw_pegout_spend = miner.createrawtransaction(
            [{'txid': hogex.hash, 'vout': 1}], [{miner.getnewaddress(): pegout_amount - Decimal("0.001")}])
        signed_pegout_spend = miner.signrawtransactionwithwallet(raw_pegout_spend)
        assert signed_pegout_spend['complete']
        pegout_result = node.testmempoolaccept([signed_pegout_spend['hex']])[0]
        assert_equal(pegout_result['allowed'], False)
        assert_equal(pegout_result['reject-reason'], 'bad-txns-premature-spend-of-pegout')

        self.log.info("Spend the crash-block MWEB output; stale replay state would reject this")
        post_replay_addr = spender.getnewaddress(address_type="mweb")
        post_replay_txid = spender.sendtoaddress(post_replay_addr, Decimal("0.25"))
        assert_equal(set(node.getrawmempool()), {post_replay_txid})
        post_replay_block_hash = generatetoaddress(node, 1, miner.getnewaddress())[0]
        post_replay_block = FromHex(CBlock(), node.getblock(post_replay_block_hash, 0))
        assert_equal([txin.output_id.to_hex() for txin in post_replay_block.mweb_block.body.inputs], [received_id])
        assert_equal(node.getbestblockhash(), post_replay_block_hash)
        assert_raises_rpc_error(-5, "not unspent", node.getmweboutputproof, received_id, post_replay_block_hash)
        # For spent outputs the default proof uses the persisted UTXO creation
        # height; it must resolve to the crash block, not the old durable tip.
        spent_proof = node.getmweboutputproof(received_id)
        assert_equal(spent_proof['blockhash'], crash_block_hash)
        assert_equal(node.getblockheader(spent_proof['blockhash'])['height'], crash_height)
        assert_equal(spent_proof['output'], expected_outputs[received_id])
        assert node.verifymweboutputproof(spent_proof)


if __name__ == '__main__':
    MWEBDBCrashTest(__file__).main()
