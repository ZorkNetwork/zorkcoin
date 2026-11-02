#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""External signer mock backed by a wallet on another node.

The test writes mweb_signer.json into the calling node's working directory:
  fingerprint    the device fingerprint
  receive        descriptors returned by getdescriptors
  internal       change descriptors returned by getdescriptors
  addresses      descriptor -> address map for displayaddress
  rpc_argv       bitcoin-cli arguments that reach the device wallet
  replace_psbt   optional PSBT returned by signtx instead of signing
Each command is appended to mweb_signer_calls.log as "<command> stdin" or
"<command> argv", by where the command and its arguments arrived. The last
PSBT given to signtx is written to mweb_signer_last_psbt.
"""

import argparse
import json
import os
import subprocess
import sys


def config():
    with open(os.path.join(os.getcwd(), "mweb_signer.json"), "r") as f:
        return json.load(f)


def record(command, source):
    with open(os.path.join(os.getcwd(), "mweb_signer_calls.log"), "a") as f:
        f.write(f"{command} {source}\n")


def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": config()["fingerprint"], "type": "mock", "model": "mweb"}]))


def getdescriptors(args):
    conf = config()
    sys.stdout.write(json.dumps({"receive": conf["receive"], "internal": conf["internal"]}))


def displayaddress(args):
    conf = config()
    if args.fingerprint != conf["fingerprint"]:
        return sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))
    if args.desc not in conf["addresses"]:
        return sys.stdout.write(json.dumps({"error": "Unexpected descriptor", "desc": args.desc}))
    return sys.stdout.write(json.dumps({"address": conf["addresses"][args.desc]}))


def signtx(args):
    conf = config()
    if args.fingerprint != conf["fingerprint"]:
        return sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))
    with open(os.path.join(os.getcwd(), "mweb_signer_last_psbt"), "w") as f:
        f.write(args.psbt)
    if conf.get("replace_psbt"):
        return sys.stdout.write(json.dumps({"psbt": conf["replace_psbt"]}))
    result = json.loads(subprocess.check_output(conf["rpc_argv"] + ["walletprocesspsbt", args.psbt, "true", "ALL", "true", "false"]))
    sys.stdout.write(json.dumps({"psbt": result["psbt"]}))


parser = argparse.ArgumentParser(prog='./mweb_signer.py', description='External MWEB signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')

parser_displayaddress = subparsers.add_parser('displayaddress')
parser_displayaddress.add_argument('--desc', metavar='desc')
parser_displayaddress.set_defaults(func=displayaddress)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('psbt', metavar='psbt')
parser_signtx.set_defaults(func=signtx)

command_line = list(sys.argv)
if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()
record(args.command, "argv" if args.command in command_line else "stdin")
args.func(args)
