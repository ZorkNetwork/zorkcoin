#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compatibility shim — cap-fill plan lives in mweb_cap_block_plan."""

from test_framework.mweb_cap_block_plan import *  # noqa: F401,F403
from test_framework.mweb_cap_block_plan import (  # noqa: F401
    CAP_HOST_WALLETS as ENVELOPE_HOST_WALLETS,
    CapBlockPlan as EnvelopeBlockPlan,
    compute_cap_fill_plan as compute_envelope_block_plan,
)
