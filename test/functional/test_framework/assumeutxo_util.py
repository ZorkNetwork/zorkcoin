#!/usr/bin/env python3
# Copyright (c) 2021-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared AssumeUTXO regtest chain utilities.

The height-299 recipe matches test/functional/feature_assumeutxo.py and
test/functional/tool_bitcoin_chainstate.py: start from the functional-test
199-block cache, set mocktime once from the cache tip, mine one block at a time
to height 299 with a MiniWallet self-transfer every third block.

Post-MWEB AssumeUTXO testing extends this same chain in feature_assumeutxo.py
(see mweb_util.finish_assumeutxo_mweb_chain).
"""

from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# Functional-test on-disk cache tip (see test_framework.py _initialize_chain).
# setup_nodes mines one additional wall-clock block to leave IBD; assumeutxo
# builders invalidate that block so the chain from height 199 is deterministic.
ASSUMEUTXO_CACHE_HEIGHT = 199
ASSUMEUTXO_START_HEIGHT = 200  # after setup_nodes' extra block

# Committed in CRegTestParams::m_assumeutxo_data for feature_assumeutxo.py.
ASSUMEUTXO_BASE_HEIGHT = 299
ASSUMEUTXO_BASE_BLOCK_HASH = (
    "424c640f95920388bb73377b432301a035d40bcac1c22719597c164d21e2f58c"
)
ASSUMEUTXO_BASE_HASH_SERIALIZED = (
    "19f09db6d1dfaa004671b4eb1a09de9fd59d6b015a70d67d3475b5a902a0c2e9"
)
ASSUMEUTXO_BASE_CHAIN_TX_COUNT = 334


def build_assumeutxo_base_chain(test, node, *, sync_fun=None):
    """Mine the upstream assumeutxo chain through height 299.

    Requires setup_clean_chain=False (199-block cache) and MWEB disabled at
    the node (-vbparams=mweb:-2:0) so block hashes match chainparams.
    """
    sync = sync_fun if sync_fun is not None else test.sync_all

    # Drop the non-deterministic wall-clock block from setup_nodes when present.
    tip_height = node.getblockcount()
    if tip_height == ASSUMEUTXO_START_HEIGHT:
        node.invalidateblock(node.getbestblockhash())
    assert_equal(node.getblockcount(), ASSUMEUTXO_CACHE_HEIGHT)

    tip_ms = node.getblockheader(node.getbestblockhash())['time']
    node.setmocktime(tip_ms // 1000)

    mini_wallet = MiniWallet(node)
    blocks_to_mine = ASSUMEUTXO_BASE_HEIGHT - node.getblockcount()
    for i in range(blocks_to_mine):
        if i % 3 == 0:
            mini_wallet.send_self_transfer(from_node=node)
        test.generate(node, 1, sync_fun=test.no_op)

    sync()
    assert_equal(node.getblockcount(), ASSUMEUTXO_BASE_HEIGHT)
    assert_equal(node.getbestblockhash(), ASSUMEUTXO_BASE_BLOCK_HASH)
    return mini_wallet


def assert_assumeutxo_base_dump(dump):
    """Assert dumptxoutset output matches committed regtest AssumeutxoData at height 299."""
    assert_equal(dump['base_hash'], ASSUMEUTXO_BASE_BLOCK_HASH)
    assert_equal(dump['txoutset_hash'], ASSUMEUTXO_BASE_HASH_SERIALIZED)
    assert_equal(dump['nchaintx'], ASSUMEUTXO_BASE_CHAIN_TX_COUNT)
