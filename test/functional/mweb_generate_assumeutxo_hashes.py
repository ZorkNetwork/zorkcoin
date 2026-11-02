#!/usr/bin/env python3
"""Generate regtest AssumeUTXO hashes for MWEB snapshot at height 750.

Extends the upstream assumeutxo chain (199-block cache through height 299),
then mines with MWEB enabled to height 750. Run once after changing the chain
recipe, then update:
  - src/kernel/chainparams.cpp (height 750 entry)
  - test_framework/mweb_util.py ASSUMEUTXO_MWEB_* constants

Use --capture-pegin to print a new ASSUMEUTXO_MWEB_PEGIN_RAW_HEX after the
base-chain extension changes the funding coinbase at height 102.

Not part of the functional test suite.
"""
import sys

from test_framework.assumeutxo_util import (
    ASSUMEUTXO_BASE_HEIGHT,
    build_assumeutxo_base_chain,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mweb_util import (
    SNAPSHOT_BASE_MWEB,
    MWEB_VB_START_TIME,
    finish_assumeutxo_mweb_chain,
    restart_node_for_mweb_extension,
)
from test_framework.util import assert_equal

HASH_GEN_RANDOMSEED = 42
HASH_GEN_PORTSEED = 42
# feature_assumeutxo.py mines this far with MWEB enabled before the MWEB extension phase.
ASSUMEUTXO_PRE_EXTENSION_HEIGHT = 399


class GenerateMWEBAssumeutxoHashes(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1
        self.extra_args = [["-vbparams=mweb:-2:0"]]
        self.uses_wallet = True
        self.capture_pegin = False

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_argument(
            "--capture-pegin",
            action="store_true",
            help="Print pegin txid/raw hex for mweb_util.py instead of snapshot hashes",
        )

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.util import SkipTest
            raise SkipTest("wallet has not been compiled")

    def setup_network(self):
        """Match feature_assumeutxo.py: do not mine the extra IBD block to 200."""
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        self.capture_pegin = self.options.capture_pegin
        node = self.nodes[0]

        self.log.info("Phase 1: upstream assumeutxo chain through height %s", ASSUMEUTXO_BASE_HEIGHT)
        build_assumeutxo_base_chain(self, node)

        self.log.info("Phase 2: restart with MWEB enabled and mine to height %s (matches feature_assumeutxo.py)", ASSUMEUTXO_PRE_EXTENSION_HEIGHT)
        restart_node_for_mweb_extension(self)
        node.setmocktime(MWEB_VB_START_TIME)
        self.generate(node, nblocks=ASSUMEUTXO_PRE_EXTENSION_HEIGHT - ASSUMEUTXO_BASE_HEIGHT, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), ASSUMEUTXO_PRE_EXTENSION_HEIGHT)

        self.log.info("Phase 3: finish MWEB extension through height %s", SNAPSHOT_BASE_MWEB)

        if self.capture_pegin:
            # Print the deterministic wallet's MWEB receive address for this HRP.
            w = node.get_wallet_rpc('mweb_assumeutxo')
            print('ASSUMEUTXO_MWEB_PEGIN_ADDRESS', w.getnewaddress(address_type='mweb'))
            pegin_txid, raw_hex = finish_assumeutxo_mweb_chain(self, node, capture_pegin=True)
            print('ASSUMEUTXO_MWEB_PEGIN_TXID', pegin_txid)
            print('ASSUMEUTXO_MWEB_PEGIN_RAW_HEX', raw_hex)
            return

        finish_assumeutxo_mweb_chain(self, node)
        assert_equal(node.getblockcount(), SNAPSHOT_BASE_MWEB)

        dump = node.dumptxoutset('mweb_assumeutxo.dat', 'latest')

        print('SNAPSHOT_BASE_MWEB', SNAPSHOT_BASE_MWEB)
        print('blockhash', dump['base_hash'])
        print('hash_serialized', dump['txoutset_hash'])
        print('m_chain_tx_count', dump['nchaintx'])
        print('mweb_hash', dump.get('mweb_hash', 'MISSING'))
        print('mweb_coins_written', dump.get('mweb_coins_written', 0))


if __name__ == '__main__':
    if '--randomseed' not in sys.argv:
        sys.argv.extend([f'--randomseed={HASH_GEN_RANDOMSEED}'])
    if '--portseed' not in sys.argv:
        sys.argv.extend([f'--portseed={HASH_GEN_PORTSEED}'])
    GenerateMWEBAssumeutxoHashes(__file__).main()
