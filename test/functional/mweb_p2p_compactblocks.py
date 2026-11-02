#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run p2p_compactblocks.py against a node that uses compact block version 3.

A node on a chain where MWEB can activate advertises NODE_MWEB and uses
compact block version 3, which carries the block's MWEB data after the
prefilled transactions. This runs every check in p2p_compactblocks.py,
unchanged, against such a node (MWEB defined but never started):
    - the test's peers advertise NODE_MWEB;
    - each version the test sends is one higher (2 becomes 3, the too-high 3
      becomes 4; 1 stays 1), and the version 3 the node sends is reported to
      the test as the 2 it expects;
    - compact blocks are serialized as version 3.

Keeping this out of p2p_compactblocks.py leaves the upstream file free of
merge conflicts.
"""
import p2p_compactblocks
from p2p_compactblocks import CompactBlocksTest, TestP2PConn
from test_framework.blocktools import create_block
from test_framework.messages import (
    HeaderAndShortIDs,
    P2PHeaderAndShortMWEBIDs,
    msg_sendcmpct,
)
from test_framework.mweb_util import MWEB_GBT_REQUEST_PARAMS
from test_framework.p2p import P2P_SERVICES_MWEB


def to_mweb_version(version):
    return version + 1 if version >= 2 else version


def from_mweb_version(version):
    return version - 1 if version >= 2 else version


class MWEBSendCmpct(msg_sendcmpct):
    __slots__ = ()

    def __init__(self, announce=False, version=2):
        super().__init__(announce=announce, version=to_mweb_version(version))


class MWEBTestP2PConn(TestP2PConn):
    def peer_connect(self, **kwargs):
        kwargs.setdefault("services", P2P_SERVICES_MWEB)
        return super().peer_connect(**kwargs)

    def peer_accept_connection(self, *args, **kwargs):
        kwargs.setdefault("services", P2P_SERVICES_MWEB)
        return super().peer_accept_connection(*args, **kwargs)

    def on_sendcmpct(self, message):
        # A version 2 from the node is reported as 1, so the upstream check fails.
        super().on_sendcmpct(msg_sendcmpct(announce=message.announce, version=from_mweb_version(message.version)))


class MWEBCompactBlocksTest(CompactBlocksTest):
    def set_test_params(self):
        super().set_test_params()
        # Define the MWEB deployment without starting it, so the node advertises NODE_MWEB.
        # DeploymentEnabled is true, so getblocktemplate requires the mweb rule.
        self.extra_args[0].append("-vbparams=mweb:9999999998000:9999999999000")

    def build_block_on_tip(self, node):
        # Upstream uses segwit-only GBT params. This node can still activate MWEB.
        block = create_block(tmpl=node.getblocktemplate(MWEB_GBT_REQUEST_PARAMS))
        block.solve()
        return block

    def run_test(self):
        super().run_test()


if __name__ == '__main__':
    setattr(p2p_compactblocks, "TestP2PConn", MWEBTestP2PConn)
    setattr(p2p_compactblocks, "msg_sendcmpct", MWEBSendCmpct)
    setattr(p2p_compactblocks, "P2PHeaderAndShortIDs", P2PHeaderAndShortMWEBIDs)
    HeaderAndShortIDs.serialize_mweb = True
    MWEBCompactBlocksTest(__file__).main()
