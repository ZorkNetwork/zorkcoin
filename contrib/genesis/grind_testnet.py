#!/usr/bin/env python3
# Copyright (c) The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build Zorkcoin testnet/signet genesis coinbases and grind nNonce.

Coinbase scriptSig: BIP34 height 0, extra nonce 4361726C, /Genesis Fifty-Niner/,
miner_comment. Matches src/kernel/chainparams.cpp CreateZorkNetworkGenesisBlock.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "test", "functional"))

from test_framework.messages import (  # noqa: E402
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    uint256_from_compact,
    uint256_from_str,
)
from test_framework.script import CScript, OP_0, OP_CHECKSIG, OP_RETURN  # noqa: E402

SEQUENCE_FINAL = 0xFFFFFFFF
GENESIS_PUBKEY = bytes.fromhex(
    "040241e2ab92d48de2889fe28891ceb7cf84e28487d18f70c2aed19753e284ae"
    "24588d0429a6a46d555360b9f3b83a60a6c49895a62abad18fd8182c0009492308"
)
OPRET = b"LTC BLK:3159327 -> 30364f9302886379279692f4c6ec33ec2ae679be2016490b0096c29ddbe7347b"
NTIME = 1_786_609_421_000
NVERSION = 0x20000000
REWARD = 1 << 32
MINER_INFO = b"/Genesis Fifty-Niner/"
EXTRA_NONCE = bytes.fromhex("4361726C")

NETWORKS = {
    "testnet": {"comment": b"ad astra per aspera", "nbits": 0x1D15198E},
    "signet": {"comment": b"signature based network", "nbits": 0x1E0FFFF0},
}


def genesis_tx(miner_comment: bytes) -> CTransaction:
    tx = CTransaction()
    tx.version = 1
    tx.nLockTime = 0
    script_sig = CScript([OP_0, EXTRA_NONCE, MINER_INFO, miner_comment])
    tx.vin = [CTxIn(COutPoint(0, SEQUENCE_FINAL), script_sig, SEQUENCE_FINAL)]
    script_pub = CScript([GENESIS_PUBKEY, OP_CHECKSIG])
    opret = CScript([OP_RETURN, OPRET])
    tx.vout = [CTxOut(REWARD, script_pub), CTxOut(0, opret)]
    return tx


def txid_int(tx: CTransaction) -> int:
    return uint256_from_str(hash256(tx.serialize_without_witness()))


def make_header(merkle: int, nbits: int, nonce: int = 0) -> CBlockHeader:
    header = CBlockHeader()
    header.nVersion = NVERSION
    header.hashPrevBlock = 0
    header.hashMerkleRoot = merkle
    header.nTime = NTIME
    header.nBits = nbits
    header.nNonce = nonce
    return header


def grind_python(header: CBlockHeader) -> CBlockHeader:
    target = uint256_from_compact(header.nBits)
    t0 = time.time()
    nonce = 0
    while True:
        header.nNonce = nonce
        if header.pow_hash_int <= target:
            print(f"python grind found nonce={nonce} in {time.time() - t0:.1f}s")
            return header
        nonce += 1
        if nonce % 20_000 == 0:
            rate = nonce / max(time.time() - t0, 1e-6)
            print(f"... nonce={nonce} ({rate:.0f} H/s)", flush=True)


def grind_util(header: CBlockHeader, util: str) -> CBlockHeader:
    hex_in = header.serialize().hex()
    out = subprocess.check_output([util, "grind", hex_in], text=True).strip()
    solved = CBlockHeader()
    solved.deserialize(__import__("io").BytesIO(bytes.fromhex(out)))
    return solved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("network", choices=sorted(NETWORKS), nargs="?", default="testnet")
    parser.add_argument("--util", default="", help="path to zorkcoin-util (preferred grind)")
    parser.add_argument("--python-grind", action="store_true")
    args = parser.parse_args()
    spec = NETWORKS[args.network]
    tx = genesis_tx(spec["comment"])
    merkle = txid_int(tx)
    print(f"network={args.network}")
    print(f"scriptSig={bytes(tx.vin[0].scriptSig).hex()}")
    print(f"merkle={merkle:064x}")
    header = make_header(merkle, spec["nbits"])
    print(f"unsolved header hex:\n{header.serialize().hex()}")
    util = args.util or os.environ.get("ZORKCOIN_UTIL", "")
    if args.python_grind or os.environ.get("ZORK_GENESIS_PYTHON_GRIND") == "1":
        solved = grind_python(header)
    elif util:
        solved = grind_util(header, util)
    else:
        return
    print(f"nonce={solved.nNonce} (0x{solved.nNonce:x})")
    print(f"hash={solved.hash_hex}")
    print(f"pow={solved.pow_hash_bytes[::-1].hex()}")
    print(f"valid={solved.is_valid_pow()}")


if __name__ == "__main__":
    main()
