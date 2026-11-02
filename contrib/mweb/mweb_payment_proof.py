#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Create and verify MWEB payment proofs (see doc/mweb/payment-proofs.md).

When run under the functional test framework, import paths resolve via sys.path.
Standalone use: set PYTHONPATH to the test/functional directory, or pass
--rpcconnect / cookie auth matching bitcoin-cli.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

# Prefer the repo's test framework when this file lives in contrib/mweb/.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUNC = _REPO_ROOT / "test" / "functional"
if _FUNC.is_dir() and str(_FUNC) not in sys.path:
    sys.path.insert(0, str(_FUNC))

try:
    import blake3 as _blake3_mod  # type: ignore[import-not-found]
except ImportError:
    from test_framework.crypto import blake3 as _blake3_mod

from test_framework.crypto.secp256k1 import G, GE
from test_framework.segwit_addr import (
    CHARSET,
    Encoding,
    bech32_verify_checksum,
    convertbits,
)

SECP_ORDER = GE.ORDER
HASH_TO_SCALAR_TAG = b"MWEB hash-to-scalar"
# MWEB stealth addresses exceed BIP173's 90-character limit (CharLimit::MWEB).
MWEB_BECH32_LIMIT = 1023


def bech32_decode_mweb(bech: str):
    """Bech32 decode with MWEB address length allowance."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech) or (bech.lower() != bech and bech.upper() != bech):
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > MWEB_BECH32_LIMIT:
        return None, None, None
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return None, None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    encoding = bech32_verify_checksum(hrp, data)
    if encoding is None:
        return None, None, None
    return encoding, hrp, data[:-6]


def _blake3(data: bytes) -> bytes:
    return _blake3_mod.blake3(data).digest()


def tagged_hash(tag: int | bytes, *parts: bytes) -> bytes:
    if isinstance(tag, int):
        tag_b = bytes([tag])
    else:
        tag_b = tag
    return _blake3(tag_b + b"".join(parts))


def hash_to_scalar(digest32: bytes) -> bytes:
    """Match SecretKey::FromHash."""
    n = int.from_bytes(digest32, "big")
    if 1 <= n < SECP_ORDER:
        return digest32
    counter = 0
    while True:
        h = _blake3(HASH_TO_SCALAR_TAG + digest32 + struct.pack("<I", counter))
        n = int.from_bytes(h, "big")
        if 1 <= n < SECP_ORDER:
            return h
        counter += 1


def derive_sender_signing_key(scan_secret: bytes, index: int) -> bytes:
    root = hash_to_scalar(tagged_hash(ord("Q"), scan_secret))
    return hash_to_scalar(tagged_hash(ord("Q"), root + struct.pack("<Q", index)))


def derive_output_nonce(sender_key: bytes) -> bytes:
    return tagged_hash(ord("N"), sender_key)[:16]


def pubkey_from_secret(secret: bytes) -> bytes:
    return (int.from_bytes(secret, "big") * G).to_bytes_compressed()


def point_mul(pubkey33: bytes, secret: bytes) -> bytes:
    p = GE.from_bytes(pubkey33)
    return (int.from_bytes(secret, "big") * p).to_bytes_compressed()


def decode_mweb_address(addr: str) -> tuple[bytes, bytes]:
    encoding, hrp, data = bech32_decode_mweb(addr)
    if encoding is None or hrp is None or data is None or not data:
        raise ValueError(f"invalid MWEB address: {addr}")
    if encoding != Encoding.BECH32:
        raise ValueError("MWEB addresses must be Bech32 (not Bech32m)")
    if data[0] != 0:
        raise ValueError("unsupported MWEB address version")
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) != 66:
        raise ValueError("invalid MWEB address payload length")
    payload = bytes(decoded)
    return payload[:33], payload[33:]


def parse_output(output_hex: str) -> dict:
    raw = bytes.fromhex(output_hex)
    if len(raw) < 33 + 33 + 33 + 1 + 675 + 64:
        raise ValueError("output hex too short")
    off = 0
    commitment = raw[off : off + 33]
    off += 33
    sender_pk = raw[off : off + 33]
    off += 33
    receiver_pk = raw[off : off + 33]
    off += 33
    features = raw[off]
    off += 1
    if not (features & 0x01):
        raise ValueError("output missing standard fields")
    ke = raw[off : off + 33]
    off += 33
    view_tag = raw[off]
    off += 1
    masked_value = struct.unpack_from("<Q", raw, off)[0]
    off += 8
    masked_nonce = raw[off : off + 16]
    off += 16
    if features & 0x02:
        # compactSize
        size = raw[off]
        off += 1
        if size >= 0xFD:
            raise ValueError("unsupported extra_data compactSize")
        off += size
    # remainder is rangeproof + sig; not needed for field checks
    return {
        "commitment": commitment.hex(),
        "sender_pk": sender_pk.hex(),
        "receiver_pk": receiver_pk.hex(),
        "key_exchange_pk": ke.hex(),
        "view_tag": view_tag,
        "masked_value": masked_value,
        "masked_nonce": masked_nonce.hex(),
    }


def derive_send_key(Ai: bytes, Bi: bytes, amount: int, nonce16: bytes) -> bytes:
    digest = tagged_hash(ord("S"), Ai + Bi + struct.pack("<Q", amount) + nonce16)
    return hash_to_scalar(digest)


def shared_secret_from_send(Ai: bytes, s: bytes) -> bytes:
    sA = point_mul(Ai, s)
    return hash_to_scalar(tagged_hash(ord("D"), sA))


def masks_from_shared(e: bytes) -> tuple[int, bytes]:
    value_mask = struct.unpack("<Q", tagged_hash(ord("Y"), e)[:8])[0]
    nonce_mask = tagged_hash(ord("X"), e)[:16]
    return value_mask, nonce_mask


def verify_output_fields(output: dict, Ai: bytes, Bi: bytes, amount: int, nonce16: bytes) -> None:
    s = derive_send_key(Ai, Bi, amount, nonce16)
    e = shared_secret_from_send(Ai, s)
    sA = point_mul(Ai, s)
    view_tag = tagged_hash(ord("T"), sA)[0]
    out_key_tweak = hash_to_scalar(tagged_hash(ord("O"), e))
    ke = point_mul(Bi, s)
    ko = point_mul(Bi, out_key_tweak)
    value_mask, nonce_mask = masks_from_shared(e)
    masked_value = amount ^ value_mask
    masked_nonce = bytes(a ^ b for a, b in zip(nonce16, nonce_mask, strict=True))

    if view_tag != output["view_tag"]:
        raise ValueError("view tag mismatch")
    if ke.hex() != output["key_exchange_pk"]:
        raise ValueError("key exchange pubkey mismatch")
    if ko.hex() != output["receiver_pk"]:
        raise ValueError("output pubkey mismatch (multiplicative K_o)")
    if masked_value != output["masked_value"]:
        raise ValueError("masked value mismatch")
    if masked_nonce.hex() != output["masked_nonce"]:
        raise ValueError("masked nonce mismatch")


def resolve_sender_key(
    *,
    sender_key_hex: str | None,
    scan_secret_hex: str | None,
    sender_index: int | None,
    sender_pk_hex: str,
    lookahead: int,
) -> tuple[bytes, int | None]:
    if sender_key_hex:
        sk = bytes.fromhex(sender_key_hex)
        if pubkey_from_secret(sk).hex() != sender_pk_hex:
            raise ValueError("sender_key does not match output sender_pk")
        return sk, sender_index
    if not scan_secret_hex:
        raise ValueError("provide --sender-key or --scan-secret")
    scan = bytes.fromhex(scan_secret_hex)
    if sender_index is not None:
        sk = derive_sender_signing_key(scan, sender_index)
        if pubkey_from_secret(sk).hex() != sender_pk_hex:
            raise ValueError("derived sender key does not match output sender_pk")
        return sk, sender_index
    for i in range(lookahead + 1):
        sk = derive_sender_signing_key(scan, i)
        if pubkey_from_secret(sk).hex() == sender_pk_hex:
            return sk, i
    raise ValueError(f"no sender index in 0..{lookahead} matched K_s")


def rpc_from_env():
    from test_framework.authproxy import AuthServiceProxy

    url = os.environ.get("MWEB_RPC_URL")
    if url:
        return AuthServiceProxy(url)
    raise SystemExit("Set MWEB_RPC_URL (e.g. http://user:pass@127.0.0.1:port) for RPC access")


def cmd_create(args) -> int:
    rpc = rpc_from_env()
    if args.blockhash:
        inclusion = rpc.getmweboutputproof(args.output_id, args.blockhash)
    else:
        inclusion = rpc.getmweboutputproof(args.output_id)
    output = parse_output(inclusion["output"])
    Ai, Bi = decode_mweb_address(args.address)
    sender_key, index = resolve_sender_key(
        sender_key_hex=args.sender_key,
        scan_secret_hex=args.scan_secret,
        sender_index=args.sender_index,
        sender_pk_hex=output["sender_pk"],
        lookahead=args.lookahead,
    )
    nonce = derive_output_nonce(sender_key)
    amount = int(args.amount)
    if amount < 0:
        raise ValueError("amount must be non-negative satoshis")
    verify_output_fields(output, Ai, Bi, amount, nonce)

    proof = {
        "version": 1,
        "inclusion": inclusion,
        "amount": amount,
        "nonce": nonce.hex(),
        "address": args.address,
        "sender_index": index,
    }
    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    with out:
        json.dump(proof, out, indent=2)
        out.write("\n")
    return 0


def cmd_verify(args) -> int:
    with open(args.proof, encoding="utf-8") as f:
        proof = json.load(f)
    inclusion = proof["inclusion"]
    rpc = None
    try:
        rpc = rpc_from_env()
    except SystemExit:
        if not args.allow_offline:
            raise
    if rpc is not None:
        ok = rpc.verifymweboutputproof(inclusion)
        if not ok:
            raise SystemExit("inclusion proof failed verifymweboutputproof")
    else:
        print("warning: offline mode; skipped RPC inclusion verify", file=sys.stderr)

    output = parse_output(inclusion["output"])
    Ai, Bi = decode_mweb_address(proof["address"])
    nonce = bytes.fromhex(proof["nonce"])
    verify_output_fields(output, Ai, Bi, int(proof["amount"]), nonce)
    print("valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="Create a payment proof JSON")
    c.add_argument("--output-id", required=True)
    c.add_argument("--address", required=True, help="Recipient MWEB address")
    c.add_argument("--amount", required=True, help="Amount in satoshis (integer)")
    c.add_argument("--sender-key", help="32-byte hex sender signing key")
    c.add_argument("--scan-secret", help="32-byte hex master scan secret")
    c.add_argument("--sender-index", type=int, help="Sender key index (optional with --scan-secret)")
    c.add_argument("--lookahead", type=int, default=1000)
    c.add_argument("--blockhash", help="Optional inclusion block hash")
    c.add_argument("--output", default="-", help="Write proof JSON here (default stdout)")
    c.set_defaults(func=cmd_create)

    v = sub.add_parser("verify", help="Verify a payment proof JSON")
    v.add_argument("--proof", required=True)
    v.add_argument("--allow-offline", action="store_true", help="Skip RPC inclusion check")
    v.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
