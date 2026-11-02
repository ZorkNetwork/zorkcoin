#!/usr/bin/env python3
# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validateaddress for main chain (Zorkcoin HRP zork)."""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import assert_equal

INVALID_DATA = [
    # Wrong HRP (Bitcoin/testnet BIP173/350 vectors remain unsupported on Zorkcoin)
    (
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        [],
    ),
    # Zorkcoin HRP vectors exercising the same Bech32/Bech32m error paths
    (
        "zork1qw508d6qejxtdg4y5r3zarvary0c5xw7krt6ld2",
        "Invalid Bech32 checksum",
        [43],
    ),
    (
        "zork1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqtpm4ps",
        "Version 1+ witness address must use Bech32m checksum",
        [],
    ),
    (
        "zork1qw508d6qejxtdg4y5r3zarvary0c5xw7kkh2ngu",
        "Version 0 witness address must use Bech32 checksum",
        [],
    ),
    (
        "ZORK1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KRT6Ld7",
        "Invalid character or mixed case",
        [42],
    ),
    (
        "zork1bw508d6qejxtdg4y5r3zarvary0c5xw7krt6ld7",
        "Invalid Base 32 character",
        [5],
    ),
    (
        "zork130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzf3m37",
        "Invalid Bech32 address witness version",
        [],
    ),
    (
        "zork1pqqm30zme",
        "Invalid Bech32 address program size (1 byte)",
        [],
    ),
    (
        "zork1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8q2kge",
        "Invalid Bech32 address program size (41 bytes)",
        [],
    ),
    (
        "zork1qqqqqqqqqqqqqqqqqqqqqqqqqqqfe6juh",
        "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
        [],
    ),
    (
        "zork1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07q3x4ag3",
        "Invalid padding in Bech32 data section",
        [],
    ),
    (
        "zork1rgyxad",
        "Empty Bech32 data section",
        [],
    ),
]
VALID_DATA = [
    # BIP 350 payloads re-encoded with Zorkcoin mainnet HRP
    (
        "ZORK1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KRT6LD7",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    (
        "zork1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qynks6v",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "zork1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kl4rq0w",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("ZORK1SW50QXD9SYE", "6002751e"),
    ("zork1zw508d6qejxtdg4y5r3zarvaryvcc32t8", "5210751e76e8199196d454941c45d1b3a323"),
    (
        "zork1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesg977mk",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "zork1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseszj7hr2",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "zork1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq7ateyj",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    # PayToAnchor(P2A)
    (
        "zork1pfees7r65cz",
        "51024e73",
    ),
]


class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]] * self.num_nodes

    def check_valid(self, addr, spk):
        info = self.nodes[0].validateaddress(addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["scriptPubKey"], spk)
        assert "error" not in info
        assert "error_locations" not in info

    def check_invalid(self, addr, error_str, error_locations):
        res = self.nodes[0].validateaddress(addr)
        assert_equal(res["isvalid"], False)
        assert_equal(res["error"], error_str)
        assert_equal(res["error_locations"], error_locations)

    def test_validateaddress(self):
        for (addr, error, locs) in INVALID_DATA:
            self.check_invalid(addr, error, locs)
        for (addr, spk) in VALID_DATA:
            self.check_valid(addr, spk)

    def run_test(self):
        self.test_validateaddress()


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
