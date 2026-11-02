#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Litecoin-structured getblock mweb object + mweb_hex escape hatch.

verbosity 1 → id/commitment hex arrays; verbosity ≥ 2 → detail objects.
mweb_header remains; mweb_hex carries the former opaque extension-body hex.
getblockheader carries Litecoin's mweb_header, mweb_amount and prev_mweb_amount,
and strippedsize leaves out MWEB data, as in Litecoin.
"""

import http.client
import json
import urllib.parse

from test_framework.messages import COIN
from test_framework.mweb_util import mweb_extra_args, setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


HEADER_KEYS = (
    'hash', 'height', 'kernel_offset', 'stealth_offset',
    'num_kernels', 'num_txos', 'kernel_root', 'output_root', 'leaf_root',
)


class MWEBGetBlockMWEBTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = mweb_extra_args(['-whitelist=noban@127.0.0.1', '-rest'])
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_header_match(self, mweb, mweb_header):
        for key in HEADER_KEYS:
            assert key in mweb and key in mweb_header
            assert_equal(mweb[key], mweb_header[key])

    def run_test(self):
        node = self.nodes[0]
        setup_mweb_chain(node)

        self.log.info("Pre-MWEB tip has no mweb / mweb_hex / mweb_header")
        # setup_mweb_chain ends after activation + peg-in funding; tip should already be MWEB.
        # Check a pre-activation hash if available via height 0.
        genesis = node.getblock(node.getblockhash(0), 1)
        assert 'mweb' not in genesis
        assert 'mweb_hex' not in genesis
        assert 'mweb_header' not in genesis

        self.log.info("Create and mine an MWEB send so tip has extension data")
        addr = node.getnewaddress(address_type='mweb')
        node.sendtoaddress(addr, 0.5)
        tip = self.generate(node, 1)[0]

        self.log.info("verbosity 1: structured mweb with hex-string lists + mweb_hex")
        block1 = node.getblock(tip, 1)
        assert isinstance(block1['mweb'], dict)
        assert 'mweb_hex' in block1 and isinstance(block1['mweb_hex'], str)
        assert_greater_than(len(block1['mweb_hex']), 0)
        assert 'mweb_header' in block1
        self.assert_header_match(block1['mweb'], block1['mweb_header'])
        for key in ('inputs', 'outputs', 'kernels'):
            assert key in block1['mweb']
            assert isinstance(block1['mweb'][key], list)
        assert_greater_than(len(block1['mweb']['outputs']), 0)
        assert_greater_than(len(block1['mweb']['kernels']), 0)
        assert all(isinstance(x, str) for x in block1['mweb']['inputs'])
        assert all(isinstance(x, str) for x in block1['mweb']['outputs'])
        assert all(isinstance(x, str) for x in block1['mweb']['kernels'])

        self.log.info("verbosity 2: same keys with detail objects")
        block2 = node.getblock(tip, 2)
        assert isinstance(block2['mweb'], dict)
        assert_equal(block2['mweb_hex'], block1['mweb_hex'])
        self.assert_header_match(block2['mweb'], block2['mweb_header'])
        assert_equal(block2['mweb']['hash'], block1['mweb']['hash'])
        assert_greater_than(len(block2['mweb']['outputs']), 0)
        assert all(isinstance(x, dict) for x in block2['mweb']['outputs'])
        assert all(isinstance(x, dict) for x in block2['mweb']['kernels'])
        for out in block2['mweb']['outputs']:
            for key in ('output_id', 'commit', 'sender_pubkey', 'receiver_pubkey', 'range_proof', 'message'):
                assert key in out, f'missing output.{key}'
        for kern in block2['mweb']['kernels']:
            for key in ('kernel_id', 'features', 'commit', 'fee', 'lock_height', 'excess', 'signature'):
                assert key in kern, f'missing kernel.{key}'
        for inp in block2['mweb']['inputs']:
            assert isinstance(inp, dict)
            for key in ('output_id', 'commit', 'output_pubkey', 'sig'):
                assert key in inp, f'missing input.{key}'

        self.test_getblockheader(node, tip, block1, block2)
        self.test_strippedsize(block1)

    def test_getblockheader(self, node, tip, block1, block2):
        self.log.info("getblockheader: Litecoin's mweb_header, mweb_amount and prev_mweb_amount")
        genesis = node.getblockheader(node.getblockhash(0))
        for key in ('mweb_header', 'mweb_amount', 'prev_mweb_amount'):
            assert key not in genesis

        header = node.getblockheader(tip)
        assert_equal(header['mweb_header'], block1['mweb_header'])
        hogex = block2['tx'][-1]
        assert_equal(header['mweb_amount'], int(hogex['vout'][0]['value'] * COIN))
        prev = node.getblockheader(header['previousblockhash'])
        assert_equal(header['prev_mweb_amount'], prev['mweb_amount'])
        for key in ('mweb_amount', 'prev_mweb_amount'):
            assert_equal(block1[key], header[key])

        self.log.info("REST headers JSON carries the same MWEB fields")
        url = urllib.parse.urlparse(node.url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request('GET', f'/rest/headers/{tip}.json?count=1')
        response = conn.getresponse()
        assert_equal(response.status, 200)
        rest_header = json.loads(response.read())[0]
        for key in ('mweb_header', 'mweb_amount', 'prev_mweb_amount'):
            assert_equal(rest_header[key], header[key])

    def test_strippedsize(self, block):
        self.log.info("getblock: strippedsize leaves out witness and MWEB data")
        # weight = 3 * stripped size + total size without MWEB
        size_without_mweb = block['weight'] - 3 * block['strippedsize']
        assert_greater_than(size_without_mweb, 0)
        mweb_bytes = len(block['mweb_hex']) // 2
        # The rest is the MWEB presence byte and the HogEx's MWEB flag bytes.
        assert 0 < block['size'] - size_without_mweb - mweb_bytes <= 4


if __name__ == '__main__':
    MWEBGetBlockMWEBTest(__file__).main()
