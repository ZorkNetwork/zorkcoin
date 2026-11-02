#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify exact requested MWEB recovery after mutation, restart and cached-child retention."""

import copy

from test_framework.mweb_util import init_mweb_wallet, generatetoaddress, setup_mweb_chain, mweb_extra_args
from test_framework.messages import CBlock, CBlockHeader, CInv, FromHex, Hash, MSG_BLOCK, MSG_MWEB_BLOCK, msg_block, msg_headers, msg_inv
from test_framework.p2p import P2PDataStore, P2P_SERVICES_MWEB, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

FROZEN_MWEB_OUTPUT_ID = "2f3a08d9f5ef5f388386c11efe935394b14b524220cff4ec5c81942b82e694f7"


class RecoveryPeer(P2PDataStore):
    def __init__(self, parent):
        super().__init__()
        self.block_store[parent.sha256] = parent
        self.last_block_hash = parent.sha256
        self.request = (MSG_MWEB_BLOCK, parent.sha256)
        self.requests = []
        self.served = []

    def on_getdata(self, message):
        for inv in message.inv:
            request = (inv.type, inv.hash)
            self.requests.append(request)
            if request == self.request:
                self.send_without_ping(msg_block(self.block_store[inv.hash]))
                self.served.append(request)


class MWEBP2PMutatedBlockSubmitBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.rpc_timeout = 120
        self.num_nodes = 3
        self.extra_args = mweb_extra_args(
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        )
        self.supports_cli = False

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_single_input_mweb_spend(self, wallet):
        return wallet.sendtoaddress(
            address=wallet.getnewaddress(address_type='mweb'),
            amount=2,
        )

    def send_mutated_parent_and_child(self, node, peer, valid_parent, valid_child, description, mutate_inputs, expected_reason):
        self.log.info("Mutate the parent MWEB body without changing its block hash: {}".format(description))
        mutated_parent = copy.deepcopy(valid_parent)
        mutated_inputs = mutated_parent.mweb_block.body.inputs
        assert_equal(len(mutated_inputs), 2)

        mutate_inputs(mutated_inputs)
        for mweb_input in mutated_inputs:
            mweb_input.rehash()

        mutated_parent.rehash()
        assert_equal(mutated_parent.sha256, valid_parent.sha256)

        # Announce both headers, then provide the child first so it is parked
        # until the parent data arrives. This exercises mutation cleanup with
        # an already-downloaded descendant.
        peer.send_and_ping(msg_headers([CBlockHeader(valid_parent), CBlockHeader(valid_child)]))
        peer.send_and_ping(msg_block(valid_child))

        with node.assert_debug_log(expected_msgs=[expected_reason], timeout=10):
            peer.send_and_ping(msg_block(mutated_parent))
        self.assert_discarded_parent_and_retained_child(node, valid_parent, valid_child)

    def assert_discarded_parent_and_retained_child(self, node, parent, child):
        assert_equal(node.getbestblockhash(), f"{parent.hashPrevBlock:064x}")
        parent_hash = f"{parent.sha256:064x}"
        child_hash = f"{child.sha256:064x}"
        assert_equal(node.getblockheader(parent_hash)['hash'], parent_hash)
        assert_equal(node.getblockheader(child_hash)['hash'], child_hash)
        assert_raises_rpc_error(-1, "Block not available", node.getblock, parent_hash, 0)
        assert_equal(node.getblock(child_hash, 0), child.serialize().hex())

    def run_test(self):
        node0, node1, node2 = self.nodes
        miner0 = node0.get_wallet_rpc(self.default_wallet_name)
        miner1 = node1.get_wallet_rpc(self.default_wallet_name)
        miner2 = node2.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Setup MWEB chain")
        setup_mweb_chain(node0, self)
        self.sync_blocks()

        self.log.info("Create one MWEB coin per spender wallet")
        node0.createwallet(wallet_name="funder")
        node0.createwallet(wallet_name="spender0")
        node1.createwallet(wallet_name="spender1")
        funder = node0.get_wallet_rpc("funder")
        spender0 = node0.get_wallet_rpc("spender0")
        spender1 = node1.get_wallet_rpc("spender1")

        funder_addr = funder.getnewaddress(address_type="mweb")
        miner0.sendtoaddress(funder_addr, 12)
        generatetoaddress(node0, 1, miner0.getnewaddress())
        self.sync_blocks()

        spender0_addr = spender0.getnewaddress(address_type="mweb")
        spender1_addr = spender1.getnewaddress(address_type="mweb")
        funder.sendtoaddress(spender0_addr, 5)
        funding_block_hash = generatetoaddress(node0, 1, miner0.getnewaddress())[0]
        self.sync_blocks()
        funder.sendtoaddress(spender1_addr, 5)
        generatetoaddress(node0, 1, miner0.getnewaddress())
        self.sync_blocks()

        assert_equal(len(spender0.listunspent(addresses=[spender0_addr])), 1)
        assert_equal(len(spender1.listunspent(addresses=[spender1_addr])), 1)

        self.log.info("Create two single-input MWEB spends")
        txid0 = self.create_single_input_mweb_spend(spender0)
        txid1 = self.create_single_input_mweb_spend(spender1)
        self.sync_mempools([node0, node1, node2])

        self.log.info("Split node1 and node2 so they can mine competing chains")
        original_tip = node0.getbestblockhash()
        original_height = node0.getblockcount()
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)

        assert_equal(set(node1.getrawmempool()), {txid0, txid1})
        assert_equal(set(node2.getrawmempool()), {txid0, txid1})

        self.log.info("Mine a valid block chain to submit later through node0's mining RPC")
        submit_hashes = generatetoaddress(node2, 3, miner2.getnewaddress())
        submit_blocks = [node2.getblock(block_hash, 0) for block_hash in submit_hashes]

        self.log.info("Mine the bad-block source parent and one child on node1")
        valid_parent_hash = generatetoaddress(node1, 1, miner1.getnewaddress())[0]
        valid_child_hash = generatetoaddress(node1, 1, miner1.getnewaddress())[0]
        valid_parent = FromHex(CBlock(), node1.getblock(valid_parent_hash, 0))
        valid_child = FromHex(CBlock(), node1.getblock(valid_child_hash, 0))
        valid_parent.rehash()
        valid_child.rehash()
        first_submit_block = FromHex(CBlock(), submit_blocks[0])
        first_submit_block.rehash()

        assert_equal(valid_parent.hashPrevBlock, int(original_tip, 16))
        assert_equal(valid_child.hashPrevBlock, valid_parent.sha256)
        assert_equal(first_submit_block.sha256, int(submit_hashes[0], 16))
        assert_equal(first_submit_block.hashPrevBlock, int(original_tip, 16))

        peer = node0.add_p2p_connection(P2PDataStore())

        def swap_commitments(mutated_inputs):
            assert mutated_inputs[0].commitment != mutated_inputs[1].commitment
            mutated_inputs[0].commitment, mutated_inputs[1].commitment = (
                mutated_inputs[1].commitment,
                mutated_inputs[0].commitment,
            )

        def swap_output_pubkeys(mutated_inputs):
            assert mutated_inputs[0].output_pubkey != mutated_inputs[1].output_pubkey
            mutated_inputs[0].output_pubkey, mutated_inputs[1].output_pubkey = (
                mutated_inputs[1].output_pubkey,
                mutated_inputs[0].output_pubkey,
            )

        def spend_frozen_output_id(mutated_inputs):
            assert mutated_inputs[0].output_id != Hash.from_rev_hex(FROZEN_MWEB_OUTPUT_ID)
            mutated_inputs[0].output_id = Hash.from_rev_hex(FROZEN_MWEB_OUTPUT_ID)

        # Input commitments are neither signed nor committed by the block hash,
        # so replacing one only unbalances the kernel sums (BLOCK_SUMS).
        funding_block = FromHex(CBlock(), node0.getblock(funding_block_hash, 0))
        spent_commitments = [mweb_input.commitment for mweb_input in valid_parent.mweb_block.body.inputs]
        foreign_commitment = next(output.commitment for output in funding_block.mweb_block.body.outputs if output.commitment not in spent_commitments)

        def replace_one_commitment(mutated_inputs):
            mutated_inputs[0].commitment = foreign_commitment

        self.log.info("Send mutated parents and their child to node0 over P2P")
        self.send_mutated_parent_and_child(node0, peer, valid_parent, valid_child, "commitment rebinding", swap_commitments, "mweb-connect-failed")
        self.send_mutated_parent_and_child(node0, peer, valid_parent, valid_child, "output pubkey rebinding", swap_output_pubkeys, "bad-blk-mweb")
        self.send_mutated_parent_and_child(node0, peer, valid_parent, valid_child, "frozen output id", spend_frozen_output_id, "bad-blk-mweb")
        self.send_mutated_parent_and_child(node0, peer, valid_parent, valid_child, "single commitment replacement", replace_one_commitment, "BLOCK_SUMS")

        self.log.info("Restart with the discarded parent and downloaded child in the block index")
        self.restart_node(0)
        self.assert_discarded_parent_and_retained_child(node0, valid_parent, valid_child)

        self.log.info("Request the honest same-hash parent from an enhanced peer and connect only its cached child")
        replacement_peer = node0.add_p2p_connection(RecoveryPeer(valid_parent), services=P2P_SERVICES_MWEB)
        replacement_peer.send_without_ping(msg_inv([CInv(MSG_BLOCK, valid_parent.sha256)]))
        replacement_peer.wait_until(lambda: replacement_peer.served == [replacement_peer.request], timeout=30)
        replacement_peer.sync_with_ping()
        self.wait_until(lambda: node0.getbestblockhash() == valid_child_hash)
        with p2p_lock:
            assert_equal(replacement_peer.requests, [replacement_peer.request])
            assert_equal(replacement_peer.served, [replacement_peer.request])
        assert_equal(node0.getblock(valid_parent_hash, 0), valid_parent.serialize().hex())
        assert_equal(node0.getblock(valid_child_hash, 0), valid_child.serialize().hex())

        self.log.info("Mine several new blocks on node0 via submitblock")
        for index, block in enumerate(submit_blocks):
            expected = None if index == len(submit_blocks) - 1 else "inconclusive"
            assert_equal(node0.submitblock(block), expected)

        assert_equal(node0.getblockcount(), original_height + 3)
        assert_equal(node0.getbestblockhash(), submit_hashes[-1])
        assert_equal(node0.getblockhash(original_height), original_tip)


if __name__ == '__main__':
    MWEBP2PMutatedBlockSubmitBlockTest(__file__).main()
