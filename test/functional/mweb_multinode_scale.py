#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real multi-node MWEB density scale test (doc/mweb/testing.md Option C).

Brings up N economic nodes, each with multiple wallets/accounts and capped
MWEB receive keys. A funder on the miner node forces peg-ins onto
other nodes' MWEB addresses. Asserts complete-testing floors for multi-node
sync and leafset growth without the 16k-block mega cache path.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    init_mweb_wallet,
    mweb_extra_args,
    reconnect_mweb_peers,
)
from test_framework.mweb_density_util import (
    MULTINODE_SCALE_CONFIG,
    FUNDER_WALLET_NAME,
    activate_mweb_with_pegin,
    complete_testing_fail,
    count_all_wallet_mweb_utxos,
    count_wallet_mweb_utxos,
    setup_density_parties,
    setup_recipient_wallets,
    assert_funder_has_no_mweb,
    assert_distribution_floor,
    funder_forced_pegin,
)


class MWEBMultinodeScaleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Max of MULTINODE_SCALE_CONFIG sizes; run_test uses cfg['economic_nodes'].
        self.num_nodes = 8
        self.extra_args = mweb_extra_args(*([] for _ in range(self.num_nodes)))

    def add_options(self, parser):
        parser.add_argument(
            '--mweb-multinode-scale',
            default='quick',
            choices=['quick', 'full'],
            help='Multi-node density scale (default: quick)',
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        init_mweb_wallet(self, node=node)

    def setup_network(self):
        self.setup_nodes()
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                self.connect_nodes(i, j)

    def run_test(self):
        scale = self.options.mweb_multinode_scale
        cfg = MULTINODE_SCALE_CONFIG[scale]
        n_econ = cfg['economic_nodes']
        if len(self.nodes) < n_econ:
            complete_testing_fail(
                f"topology node floor: started {len(self.nodes)} nodes, need ≥{n_econ}"
            )

        miner = self.nodes[0]
        self.log.info(
            "Multi-node density: %d nodes, %d wallets/node, %d accounts, %d keys, "
            "%d post-MWEB blocks",
            n_econ, cfg['wallets_per_node'], cfg['accounts_per_wallet'],
            cfg['mweb_keys_per_account'], cfg['post_mweb_blocks'],
        )

        parties_by_node = []
        all_destinations = []
        all_recipient_names = []  # (node_idx, wallet_name)

        miner_parties = setup_density_parties(
            miner,
            recipient_wallets=cfg['wallets_per_node'],
            accounts_per_wallet=cfg['accounts_per_wallet'],
            mweb_keys_per_account=cfg['mweb_keys_per_account'],
            funder_name=FUNDER_WALLET_NAME,
            recipient_prefix='n0_recv_',
        )
        parties_by_node.append(miner_parties)
        all_destinations.extend(miner_parties['destinations'])
        for name in miner_parties['recipient_names']:
            all_recipient_names.append((0, name))

        for ni in range(1, n_econ):
            node = self.nodes[ni]
            p = setup_recipient_wallets(
                node,
                recipient_wallets=cfg['wallets_per_node'],
                accounts_per_wallet=cfg['accounts_per_wallet'],
                mweb_keys_per_account=cfg['mweb_keys_per_account'],
                recipient_prefix=f'n{ni}_recv_',
            )
            parties_by_node.append(p)
            all_destinations.extend(p['destinations'])
            for name in p['recipient_names']:
                all_recipient_names.append((ni, name))

        funder = miner_parties['funder']
        activate_mweb_with_pegin(
            self, miner, funder, all_destinations[0],
            amount=1,
            drain_addr=all_destinations[1] if len(all_destinations) > 1 else all_destinations[0],
        )
        reconnect_mweb_peers(self)
        self.sync_blocks()
        assert_funder_has_no_mweb(funder)

        expected_addrs = (
            n_econ * cfg['wallets_per_node']
            * cfg['accounts_per_wallet'] * cfg['mweb_keys_per_account']
        )
        if len(all_destinations) < expected_addrs:
            complete_testing_fail(
                f"topology address floor: got {len(all_destinations)}, need ≥{expected_addrs}"
            )

        post_blocks = cfg['post_mweb_blocks']
        pegins = cfg['pegins_per_block']
        cross_interval = cfg['cross_spend_interval']
        log_interval = cfg['log_interval']
        early_at = max(1, int(post_blocks * cfg['early_gate_fraction']))
        early_min = cfg['early_gate_min_utxos']
        dest_i = 0

        for i in range(post_blocks):
            height = i + 1
            for _ in range(pegins):
                addr = all_destinations[dest_i % len(all_destinations)]
                dest_i += 1
                try:
                    funder_forced_pegin(funder, addr, 0.01)
                except JSONRPCException as e:
                    complete_testing_fail(f"forced peg-in failed at post-height {height}: {e}")

            if cross_interval and height > 20 and height % cross_interval == 0 and len(all_recipient_names) >= 2:
                src_ni, src_name = all_recipient_names[height % len(all_recipient_names)]
                dst_ni, dst_name = all_recipient_names[(height + 1) % len(all_recipient_names)]
                if (src_ni, src_name) != (dst_ni, dst_name):
                    src = self.nodes[src_ni].get_wallet_rpc(src_name)
                    dst = self.nodes[dst_ni].get_wallet_rpc(dst_name)
                    if count_wallet_mweb_utxos(src) > 0:
                        try:
                            src.sendtoaddress(dst.getnewaddress(address_type='mweb'), 0.002)
                        except JSONRPCException:
                            pass

            self.generate(miner, 1, sync_fun=self.no_op)
            if height % 10 == 0 or height == post_blocks:
                self.sync_blocks()

            if height == early_at:
                assert_funder_has_no_mweb(funder)
                total = sum(
                    count_wallet_mweb_utxos(self.nodes[ni].get_wallet_rpc(name))
                    for ni, name in all_recipient_names
                )
                self.log.info(
                    "Early multi-node growth gate at %d/%d: wallet_mweb_utxos=%d (min %d)",
                    height, post_blocks, total, early_min,
                )
                if total <= early_min:
                    complete_testing_fail(
                        f"early growth gate: wallet MWEB UTXOs={total} ≤ {early_min}"
                    )

            if log_interval and height % log_interval == 0:
                self.log.info("  post-MWEB progress: %d / %d blocks", height, post_blocks)

        self.sync_blocks()
        assert_funder_has_no_mweb(funder)
        assert_distribution_floor(
            self, miner, miner_parties['recipient_names'], min_funded_fraction=0.5,
        )

        total = 0
        funded_nodes = 0
        for ni in range(n_econ):
            names = parties_by_node[ni]['recipient_names']
            n_utxo = count_all_wallet_mweb_utxos(self.nodes[ni], names)
            total += n_utxo
            if n_utxo > 0:
                funded_nodes += 1
        self.log.info(
            "Multi-node density complete: height=%d wallet_mweb_utxos=%d funded_nodes=%d/%d",
            miner.getblockcount(), total, funded_nodes, n_econ,
        )
        if funded_nodes < max(2, n_econ // 2):
            complete_testing_fail(
                f"node distribution floor: only {funded_nodes}/{n_econ} nodes hold MWEB UTXOs"
            )
        if total <= cfg['min_mweb_utxos']:
            complete_testing_fail(
                f"chain UTXO floor: wallet_mweb_utxos={total} ≤ min_mweb_utxos={cfg['min_mweb_utxos']}"
            )
        assert miner.getblockcount() > FIRST_MWEB_HEIGHT + post_blocks - 2


if __name__ == '__main__':
    MWEBMultinodeScaleTest(__file__).main()
