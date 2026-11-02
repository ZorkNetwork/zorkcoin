#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Forced density growth for MWEB scale / mega / multi-node tests.

See doc/mweb/testing.md. Production wallets consolidate; tests use a funder
paying many separate recipient wallets/accounts/addresses so the leafset grows.
The funder may hold MWEB change (production peg-in default); density comes from
recipients that rarely spend.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.mweb_util import (
    FIRST_MWEB_HEIGHT,
    list_mweb_account_checksums,
)
from test_framework.util import wallet_importprivkey

FUNDER_WALLET_NAME = 'mweb_l1_funder'
RECIPIENT_WALLET_PREFIX = 'mweb_recv_'

# Builder-hosted density for mega serve / spend_scale (doc/mweb/testing.md).
MEGA_SCALE_CONFIG = {
    'quick': {
        'post_mweb_blocks': 800,
        'recipient_wallets': 4,
        'accounts_per_wallet': 4,
        'mweb_keys_per_account': 16,
        'pegins_per_block': 4,
        'cross_spend_interval': 25,
        'min_mweb_utxos': 1700,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 80,
        'abuse_seconds': 1.5,
        'n_abuse': 2,
        'n_sync': 4,
        'abuse_rate': 20,
        'log_interval': 100,
    },
    'full': {
        'post_mweb_blocks': 8000,
        'recipient_wallets': 8,
        'accounts_per_wallet': 8,
        'mweb_keys_per_account': 32,
        'pegins_per_block': 4,
        'cross_spend_interval': 25,
        'min_mweb_utxos': 6000,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 600,
        'abuse_seconds': 3.0,
        'n_abuse': 6,
        'n_sync': 8,
        'abuse_rate': 40,
        'log_interval': 500,
    },
    'extended': {
        'post_mweb_blocks': 16000,
        'recipient_wallets': 8,
        'accounts_per_wallet': 8,
        'mweb_keys_per_account': 64,
        'pegins_per_block': 4,
        'cross_spend_interval': 25,
        'min_mweb_utxos': 6000,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 600,
        'abuse_seconds': 5.0,
        'n_abuse': 8,
        'n_sync': 12,
        'abuse_rate': 50,
        'log_interval': 500,
    },
}

SPEND_SCALE_CONFIG = {
    'default': {
        'post_mweb_blocks': 1600,
        'recipient_wallets': 4,
        'accounts_per_wallet': 4,
        'mweb_keys_per_account': 16,
        'pegins_per_block': 4,
        'cross_spend_interval': 25,
        'min_mweb_utxos': 1000,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 100,
        'log_interval': 200,
    },
    'extended': {
        'post_mweb_blocks': 16000,
        'recipient_wallets': 8,
        'accounts_per_wallet': 8,
        'mweb_keys_per_account': 64,
        'pegins_per_block': 4,
        'cross_spend_interval': 25,
        'min_mweb_utxos': 10000,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 600,
        'log_interval': 500,
    },
}

MULTINODE_SCALE_CONFIG = {
    'quick': {
        'economic_nodes': 4,
        'wallets_per_node': 2,
        'accounts_per_wallet': 2,
        'mweb_keys_per_account': 16,
        'post_mweb_blocks': 200,
        'pegins_per_block': 4,
        'cross_spend_interval': 20,
        'min_mweb_utxos': 400,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 40,
        'log_interval': 50,
    },
    'full': {
        'economic_nodes': 8,
        'wallets_per_node': 4,
        'accounts_per_wallet': 4,
        'mweb_keys_per_account': 32,
        'post_mweb_blocks': 800,
        'pegins_per_block': 4,
        'cross_spend_interval': 20,
        'min_mweb_utxos': 1700,
        'early_gate_fraction': 0.10,
        'early_gate_min_utxos': 160,
        'log_interval': 100,
    },
}


def complete_testing_fail(msg):
    raise AssertionError(f"Complete testing requirements not met: {msg}")


def count_wallet_mweb_utxos(wallet_rpc):
    return len([u for u in wallet_rpc.listunspent(0) if u.get('address', '').startswith('bcrt1m')])


def count_all_wallet_mweb_utxos(node, wallet_names):
    total = 0
    for name in wallet_names:
        try:
            total += count_wallet_mweb_utxos(node.get_wallet_rpc(name))
        except JSONRPCException:
            continue
    return total


def _create_or_load_wallet(node, wallet_name, *, blank=False):
    try:
        node.createwallet(wallet_name=wallet_name, blank=blank, load_on_startup=True)
    except JSONRPCException as e:
        if e.error['code'] == -4:
            if wallet_name not in node.listwallets():
                node.loadwallet(wallet_name)
        elif e.error['code'] != -35:
            raise
    return node.get_wallet_rpc(wallet_name)


def _mint_account_addresses(wallet_rpc, accounts_needed, keys_per_account):
    """Mint keys_per_account MWEB addresses on each of accounts_needed accounts."""
    def mint_one():
        try:
            return wallet_rpc.getnewaddress(address_type='mweb')
        except JSONRPCException:
            add_res = wallet_rpc.addhdkey()
            wallet_rpc.createwalletdescriptor('mweb', {'hdkey': add_res['xpub']})
            return wallet_rpc.getnewaddress(address_type='mweb')

    addresses = [mint_one() for _ in range(keys_per_account)]
    for _ in range(1, accounts_needed):
        add_res = wallet_rpc.addhdkey()
        wallet_rpc.createwalletdescriptor('mweb', {'hdkey': add_res['xpub']})
        for _k in range(keys_per_account):
            addresses.append(wallet_rpc.getnewaddress(address_type='mweb'))

    checksums = list_mweb_account_checksums(wallet_rpc, private=True)
    if len(checksums) < accounts_needed:
        complete_testing_fail(
            f"expected ≥{accounts_needed} MWEB accounts, got {len(checksums)}"
        )
    expected = accounts_needed * keys_per_account
    if len(addresses) < expected:
        complete_testing_fail(
            f"expected ≥{expected} keyed MWEB addresses, got {len(addresses)}"
        )
    return addresses


def setup_density_parties(node, *, recipient_wallets, accounts_per_wallet, mweb_keys_per_account,
                          funder_name=FUNDER_WALLET_NAME, recipient_prefix=RECIPIENT_WALLET_PREFIX):
    """Create funder + recipient wallets with capped MWEB address fanout."""
    funder = _create_or_load_wallet(node, funder_name)
    try:
        wallet_importprivkey(funder, node.get_deterministic_priv_key().key, 0, label="coinbase")
    except JSONRPCException:
        pass

    destinations = []
    recipient_names = []
    for i in range(recipient_wallets):
        name = f"{recipient_prefix}{i}"
        w = _create_or_load_wallet(node, name)
        recipient_names.append(name)
        destinations.extend(
            _mint_account_addresses(w, accounts_per_wallet, mweb_keys_per_account)
        )

    expected_addrs = recipient_wallets * accounts_per_wallet * mweb_keys_per_account
    if len(destinations) < expected_addrs:
        complete_testing_fail(
            f"topology address floor: got {len(destinations)} keyed MWEB addresses, "
            f"need ≥{expected_addrs}"
        )
    if len(recipient_names) < recipient_wallets:
        complete_testing_fail(
            f"topology wallet floor: got {len(recipient_names)} recipients, "
            f"need ≥{recipient_wallets}"
        )
    # Destinations must not be ismine for the funder — otherwise peg-in/drain
    # just recirculates funder-owned MWEB and density collapses.
    for addr in destinations[: min(8, len(destinations))]:
        info = funder.getaddressinfo(addr)
        if info.get('ismine') or info.get('iswatchonly'):
            complete_testing_fail(
                f"funder ismine/watch on recipient address {addr}; "
                f"wallets are not isolated (info={info})"
            )
    return {
        'funder': funder,
        'funder_name': funder_name,
        'recipient_names': recipient_names,
        'destinations': destinations,
    }


def setup_recipient_wallets(node, *, recipient_wallets, accounts_per_wallet, mweb_keys_per_account,
                            recipient_prefix=RECIPIENT_WALLET_PREFIX):
    """Create recipient wallets with capped MWEB fanout (no funder)."""
    destinations = []
    recipient_names = []
    for i in range(recipient_wallets):
        name = f"{recipient_prefix}{i}"
        w = _create_or_load_wallet(node, name)
        recipient_names.append(name)
        destinations.extend(
            _mint_account_addresses(w, accounts_per_wallet, mweb_keys_per_account)
        )
    expected = recipient_wallets * accounts_per_wallet * mweb_keys_per_account
    if len(destinations) < expected:
        complete_testing_fail(
            f"topology address floor: got {len(destinations)} keyed MWEB addresses, "
            f"need ≥{expected}"
        )
    return {
        'recipient_names': recipient_names,
        'destinations': destinations,
    }


def load_density_parties(node, *, recipient_wallets, funder_name=FUNDER_WALLET_NAME,
                         recipient_prefix=RECIPIENT_WALLET_PREFIX):
    """Reload funder + recipients after cache restore (addresses not required for serve)."""
    funder = _create_or_load_wallet(node, funder_name)
    recipient_names = []
    for i in range(recipient_wallets):
        name = f"{recipient_prefix}{i}"
        _create_or_load_wallet(node, name)
        recipient_names.append(name)
    return {
        'funder': funder,
        'funder_name': funder_name,
        'recipient_names': recipient_names,
        'destinations': [],
    }


def assert_funder_has_no_mweb(funder):
    """Deprecated check: funder may hold MWEB change (IsChangeOnMWEB for PEGIN).

    Density comes from separate recipient wallets that do not spend. Kept as a
    no-op so call sites remain valid.
    """
    return


def assert_distribution_floor(test, node, recipient_names, *, min_funded_fraction=0.5):
    funded = 0
    totals = []
    for name in recipient_names:
        n = count_wallet_mweb_utxos(node.get_wallet_rpc(name))
        totals.append(n)
        if n > 0:
            funded += 1
    if not recipient_names:
        complete_testing_fail("no recipient wallets configured for distribution check")
    frac = funded / len(recipient_names)
    test.log.info(
        "Distribution: funded_wallets=%d/%d fraction=%.2f utxos_per_wallet=%s",
        funded, len(recipient_names), frac, totals,
    )
    if frac < min_funded_fraction:
        complete_testing_fail(
            f"distribution floor: only {funded}/{len(recipient_names)} recipient wallets "
            f"hold MWEB UTXOs (need ≥{min_funded_fraction:.0%})"
        )
    if sum(totals) > 0 and max(totals) > 0.9 * sum(totals) and len(recipient_names) > 1:
        complete_testing_fail(
            f"distribution monopoly: one wallet holds {max(totals)}/{sum(totals)} MWEB UTXOs"
        )


def funder_forced_pegin(funder, mweb_addr, amount, *, drain_addr=None):
    """Send from funder to an external MWEB address (peg-in or MWEB_TO_MWEB).

    Density comes from paying *separate recipient wallets* that do not spend.
    The funder may accumulate MWEB change (production IsChangeOnMWEB for PEGIN);
    that is fine — subsequent sends still create outputs on the recipients.
    drain_addr is ignored (API compat).
    """
    return funder.sendtoaddress(mweb_addr, amount)


def activate_mweb_with_pegin(test, node, funder, pegin_addr, *, amount=1, drain_addr=None):
    """Mine to pre-MWEB tip, send a peg-in to pegin_addr, mine activation block."""
    if node.getblockcount() >= FIRST_MWEB_HEIGHT:
        return
    test.log.info("Activating MWEB via forced peg-in (height %d)...", FIRST_MWEB_HEIGHT)
    while node.getblockcount() < FIRST_MWEB_HEIGHT - 1:
        test.generate(node, 1, sync_fun=test.no_op)
    try:
        funder_forced_pegin(funder, pegin_addr, amount)
    except JSONRPCException as e:
        complete_testing_fail(f"activation peg-in failed: {e}")
    test.generate(node, 1, sync_fun=test.no_op)
    if node.getblockcount() < FIRST_MWEB_HEIGHT:
        complete_testing_fail(
            f"MWEB activation failed: tip={node.getblockcount()} < {FIRST_MWEB_HEIGHT}"
        )


def drain_funder_mweb(funder, drain_addr):
    """Optional drain of funder MWEB to drain_addr (rarely needed; change is OK)."""
    while count_wallet_mweb_utxos(funder) > 0:
        try:
            # Send most of balance as MWEB; change may remain — loop until clear.
            bal = funder.getbalance()
            if bal <= 0:
                break
            send_amt = min(bal, 1)
            if send_amt < 0.001:
                break
            funder.sendtoaddress(drain_addr, send_amt)
        except JSONRPCException:
            break
    # Caller must mine to confirm drains when needed.


def grow_mweb_chain_density(test, node, *, cfg, parties=None, paginate_fn=None,
                            ensure_wallet_fn=None):
    """Activate MWEB and grow via funder → many recipient destinations.

    paginate_fn(node, block_hash) -> int is required for early/end gates when
    provided; otherwise wallet UTXO sums are used for early gate only.
    """
    post_blocks = cfg['post_mweb_blocks']
    pegins_per_block = cfg['pegins_per_block']
    cross_interval = cfg.get('cross_spend_interval', 0)
    log_interval = cfg.get('log_interval', 100)
    early_frac = cfg.get('early_gate_fraction', 0.10)
    early_min = cfg.get('early_gate_min_utxos', 10)

    if ensure_wallet_fn is not None and node.getblockcount() < FIRST_MWEB_HEIGHT:
        ensure_wallet_fn(test, node)

    if parties is None:
        parties = setup_density_parties(
            node,
            recipient_wallets=cfg['recipient_wallets'],
            accounts_per_wallet=cfg['accounts_per_wallet'],
            mweb_keys_per_account=cfg['mweb_keys_per_account'],
        )

    funder = parties['funder']
    destinations = parties['destinations']
    recipient_names = parties['recipient_names']
    if not destinations:
        complete_testing_fail("density parties have no destination addresses")

    # Activate without pegging into the funder (unlike setup_mweb_chain).
    if node.getblockcount() < FIRST_MWEB_HEIGHT:
        activate_mweb_with_pegin(test, node, funder, destinations[0], amount=1)
        # Confirm any residual; funder must remain MWEB-empty.
        if count_wallet_mweb_utxos(funder) > 0:
            drain_funder_mweb(funder, destinations[0])
            test.generate(node, 1, sync_fun=test.no_op)

    assert_funder_has_no_mweb(funder)

    target_height = FIRST_MWEB_HEIGHT + post_blocks - 1
    blocks_to_mine = target_height - node.getblockcount()
    if blocks_to_mine <= 0:
        test.log.info("Chain already at target height %d", node.getblockcount())
        return parties

    test.log.info(
        "MWEB density growth: %d post-MWEB blocks, %d recipient wallets, "
        "%d destinations, %d pegins/block (funder → separate recipients)",
        blocks_to_mine, len(recipient_names), len(destinations), pegins_per_block,
    )

    dest_i = 0
    early_gate_at = max(1, int(blocks_to_mine * early_frac))
    start_post_idx = node.getblockcount() - FIRST_MWEB_HEIGHT

    for i in range(blocks_to_mine):
        height = start_post_idx + i + 1
        for _ in range(pegins_per_block):
            addr = destinations[dest_i % len(destinations)]
            dest_i += 1
            try:
                funder_forced_pegin(funder, addr, 0.01)
            except JSONRPCException as e:
                complete_testing_fail(
                    f"forced peg-in send failed at post-height {height}: {e}"
                )

        if cross_interval and height > 50 and height % cross_interval == 0 and len(recipient_names) >= 2:
            src_name = recipient_names[height % len(recipient_names)]
            dst_name = recipient_names[(height + 1) % len(recipient_names)]
            if src_name != dst_name:
                src = node.get_wallet_rpc(src_name)
                dst = node.get_wallet_rpc(dst_name)
                if count_wallet_mweb_utxos(src) > 0:
                    try:
                        src.sendtoaddress(dst.getnewaddress(address_type='mweb'), 0.002)
                    except JSONRPCException:
                        pass

        test.generate(node, 1, sync_fun=test.no_op)

        if (i + 1) == early_gate_at:
            assert_funder_has_no_mweb(funder)
            if paginate_fn is not None:
                observed = paginate_fn(node, node.getbestblockhash())
                label = 'paginated'
            else:
                observed = count_all_wallet_mweb_utxos(node, recipient_names)
                label = 'wallet'
            test.log.info(
                "Early growth gate at %d/%d post-blocks: %s=%d (min %d)",
                i + 1, blocks_to_mine, label, observed, early_min,
            )
            if observed <= early_min:
                complete_testing_fail(
                    f"early growth gate: {label} MWEB UTXOs={observed} ≤ {early_min} after "
                    f"{i + 1} post-MWEB blocks (consolidation / peg-in forcing broken)"
                )

        if log_interval and height % log_interval == 0:
            test.log.info("  post-MWEB progress: %d / %d blocks", height, post_blocks - 1)

    assert_funder_has_no_mweb(funder)
    test.log.info("Density growth complete at height %d", node.getblockcount())
    return parties


def verify_density_complete(test, node, parties, *, min_utxos, paginate_fn):
    assert_funder_has_no_mweb(parties['funder'])
    assert_distribution_floor(test, node, parties['recipient_names'])
    tip_hash = node.getbestblockhash()
    paged = paginate_fn(node, tip_hash)
    test.log.info("Chain UTXO floor check: paginated=%d min=%d", paged, min_utxos)
    if paged <= min_utxos:
        complete_testing_fail(
            f"chain UTXO floor: paginated={paged} ≤ min_mweb_utxos={min_utxos}"
        )
    wallet_total = count_all_wallet_mweb_utxos(node, parties['recipient_names'])
    test.log.info(
        "Density complete: paginated=%d wallet_mweb_utxos=%d min=%d",
        paged, wallet_total, min_utxos,
    )
    if wallet_total <= 0:
        complete_testing_fail("recipient wallets report 0 MWEB UTXOs after density growth")
    return {'paged': paged, 'wallet_total': wallet_total}
