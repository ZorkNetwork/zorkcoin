#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regenerate vectors.json in this directory.

Runs the air-gapped signer functional test on regtest with the test device
seed and writes the coordinator's unsigned PSBTs, the device keys and the
recipients and fee each PSBT should show. Extra arguments go to the test,
e.g. --configfile=build/test/config.ini --tmpdir=... --portseed=...
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
TEST = os.path.join(ROOT, "test", "functional", "mweb_psbt_watchonly_signer.py")

if __name__ == "__main__":
    subprocess.run([sys.executable, TEST, f"--dumpvectors={HERE}", *sys.argv[1:]], check=True)
