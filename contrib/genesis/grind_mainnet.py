#!/usr/bin/env python3
# Copyright (c) The Zorkcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Remine Zorkcoin mainnet genesis and pin src/kernel/genesis_mainnet.h.

Matches CreateZorkNetworkGenesisBlock: four-push scriptSig, OP_RETURN Litecoin
citation, reward 1<<32. Launch nTime is locked; the LTC cite is a placeholder
until T0 (2026-09-14 12:59:09.696 UTC).

T0 ceremony (freeze one Litecoin tip, do not chase later blocks):

    python3 contrib/genesis/grind_mainnet.py \\
        --fetch-ltc --write-pins --util ./build/bin/zorkcoin-util

Then incremental-rebuild zorkcoind / zorkcoin-cli / zorkcoin-qt / zorkcoin-util
and dual-verify getblockhash 0 before tagging.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from io import BytesIO

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
# Locked launch instant: 2026-11-21 21:25:29.728 UTC == 0x1A200000000
NTIME = 1_795_296_329_728
NVERSION = 0x20000000
NBITS = 0x1E0FFFF0
REWARD = 1 << 32
MINER_INFO = b"/Genesis Fifty-Niner/"
EXTRA_NONCE = bytes.fromhex("4361726C")
MINER_COMMENT = b"zork.network"
DEFAULT_OPRETURN = "The News International 31/Oct/2026 SpaceX Falcon 9 reaches 700th launch with Starlink satellites in historic feat"
# Engineering placeholder only — replace at T0 with the live Litecoin tip if --fetch-ltc is used.
PLACEHOLDER_LTC_HEIGHT = 3_158_477
PLACEHOLDER_LTC_HASH = "2e0962ab5028e67b83d6d7f240e2330b4ca58f6a7e28ceda3f371837a03f0d58"

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PIN_HEADER = os.path.join(REPO_ROOT, "src", "kernel", "genesis_mainnet.h")
KHEAVY_TEST = os.path.join(REPO_ROOT, "src", "test", "kheavyhash_tests.cpp")
QT_RPC_TEST = os.path.join(REPO_ROOT, "src", "qt", "test", "rpcnestedtests.cpp")


def ltc_opreturn(height: int, block_hash: str) -> bytes:
    h = block_hash.lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        sys.exit(f"Litecoin hash must be 64 hex chars, got {block_hash!r}")
    return f"LTC BLK:{height} -> {h}".encode("ascii")


def genesis_tx(opret: bytes) -> CTransaction:
    tx = CTransaction()
    tx.version = 1
    tx.nLockTime = 0
    script_sig = CScript([OP_0, EXTRA_NONCE, MINER_INFO, MINER_COMMENT])
    tx.vin = [CTxIn(COutPoint(0, SEQUENCE_FINAL), script_sig, SEQUENCE_FINAL)]
    script_pub = CScript([GENESIS_PUBKEY, OP_CHECKSIG])
    tx.vout = [CTxOut(REWARD, script_pub), CTxOut(0, CScript([OP_RETURN, opret]))]
    return tx


def txid_int(tx: CTransaction) -> int:
    return uint256_from_str(hash256(tx.serialize_without_witness()))


def make_header(merkle: int, nonce: int = 0) -> CBlockHeader:
    header = CBlockHeader()
    header.nVersion = NVERSION
    header.hashPrevBlock = 0
    header.hashMerkleRoot = merkle
    header.nTime = NTIME
    header.nBits = NBITS
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
    out = subprocess.check_output([util, "-regtest", "grind", hex_in], text=True).strip()
    solved = CBlockHeader()
    solved.deserialize(BytesIO(bytes.fromhex(out)))
    return solved


def fetch_ltc_tip(cli: str) -> tuple[int, str]:
    height = int(subprocess.check_output([cli, "getblockcount"], text=True).strip())
    block_hash = subprocess.check_output([cli, "getblockhash", str(height)], text=True).strip()
    return height, block_hash


def replace_one(path: str, pattern: str, replacement: str, flags: int = 0) -> None:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new, n = re.subn(pattern, replacement, text, count=1, flags=flags)
    if n != 1:
        sys.exit(f"{path}: expected 1 match for {pattern!r}, got {n}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)


def write_pins(opret: bytes, solved: CBlockHeader, merkle: int) -> None:
    merkle_hex = f"{merkle:064x}"
    genesis_hex = solved.hash_hex
    opret_txt = opret.decode("ascii")
    replace_one(
        PIN_HEADER,
        r'static constexpr uint64_t MAINNET_GENESIS_NTIME = \d+ULL;[^\n]*',
        f"static constexpr uint64_t MAINNET_GENESIS_NTIME = {NTIME}ULL; // 0x{NTIME:X}",
    )
    replace_one(
        PIN_HEADER,
        r'static constexpr uint64_t MAINNET_GENESIS_NONCE = \d+ULL;',
        f"static constexpr uint64_t MAINNET_GENESIS_NONCE = {solved.nNonce}ULL;",
    )
    replace_one(
        PIN_HEADER,
        r'inline constexpr const char MAINNET_GENESIS_HASH\[\] = "[0-9a-f]{64}";',
        f'inline constexpr const char MAINNET_GENESIS_HASH[] = "{genesis_hex}";',
    )
    replace_one(
        PIN_HEADER,
        r'inline constexpr const char MAINNET_GENESIS_MERKLE\[\] = "[0-9a-f]{64}";',
        f'inline constexpr const char MAINNET_GENESIS_MERKLE[] = "{merkle_hex}";',
    )
    replace_one(
        PIN_HEADER,
        r'inline constexpr const char MAINNET_GENESIS_LTC_OPRETURN\[\] = "[^"]+";',
        f'inline constexpr const char MAINNET_GENESIS_LTC_OPRETURN[] = "{opret_txt}";',
    )
    replace_one(
        KHEAVY_TEST,
        r'header\.hashMerkleRoot = uint256\{"[0-9a-f]{64}"\};\n    header\.nTime = \d+ULL;\n    header\.nBits = 0x1e0ffff0;\n    CheckGenesisPoW\(header, \d+\);',
        f'header.hashMerkleRoot = uint256{{"{merkle_hex}"}};\n    header.nTime = {NTIME}ULL;\n    header.nBits = 0x1e0ffff0;\n    CheckGenesisPoW(header, {solved.nNonce});',
    )
    replace_one(
        QT_RPC_TEST,
        r'QVERIFY\(result == "[0-9a-f]{64}"\);\n    QVERIFY\(filtered == "getblock\(getbestblockhash\(\)\)\[tx\]\[0\]"\);',
        f'QVERIFY(result == "{merkle_hex}");\n    QVERIFY(filtered == "getblock(getbestblockhash())[tx][0]");',
    )
    print(f"updated {PIN_HEADER}")
    print(f"updated {KHEAVY_TEST}")
    print(f"updated {QT_RPC_TEST}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opreturn", default=DEFAULT_OPRETURN, help="genesis OP_RETURN text")
    parser.add_argument("--ltc-height", type=int, default=None)
    parser.add_argument("--ltc-hash", default=None)
    parser.add_argument("--fetch-ltc", action="store_true", help="query live Litecoin tip via litecoin-cli")
    parser.add_argument("--ltc-cli", default=os.environ.get("LITECOIN_CLI", "litecoin-cli"))
    parser.add_argument("--util", default=os.environ.get("ZORKCOIN_UTIL", ""), help="path to zorkcoin-util")
    parser.add_argument("--python-grind", action="store_true")
    parser.add_argument("--write-pins", action="store_true", help="patch genesis_mainnet.h and test pins")
    args = parser.parse_args()

    if args.fetch_ltc:
        height, block_hash = fetch_ltc_tip(args.ltc_cli)
        print(f"fetched Litecoin tip height={height} hash={block_hash}")
        opret = ltc_opreturn(height, block_hash)
    elif args.ltc_height is not None and args.ltc_hash is not None:
        opret = ltc_opreturn(args.ltc_height, args.ltc_hash)
    else:
        opret = args.opreturn.encode("ascii")
    tx = genesis_tx(opret)
    merkle = txid_int(tx)
    print(f"nTime={NTIME} (0x{NTIME:x})")
    print(f"opreturn={opret.decode('ascii')}")
    print(f"scriptSig={bytes(tx.vin[0].scriptSig).hex()}")
    print(f"merkle={merkle:064x}")
    header = make_header(merkle)
    print(f"unsolved header hex:\n{header.serialize().hex()}")

    util = args.util
    if args.python_grind or os.environ.get("ZORK_GENESIS_PYTHON_GRIND") == "1":
        solved = grind_python(header)
    elif util:
        solved = grind_util(header, util)
    else:
        print("no grind requested (pass --util or --python-grind)")
        return

    print(f"nonce={solved.nNonce} (0x{solved.nNonce:x})")
    print(f"hash={solved.hash_hex}")
    print(f"pow={solved.pow_hash_bytes[::-1].hex()}")
    print(f"valid={solved.is_valid_pow()}")
    if not solved.is_valid_pow():
        sys.exit("solved header failed PoW check")
    if args.write_pins:
        write_pins(opret, solved, merkle)


if __name__ == "__main__":
    main()
