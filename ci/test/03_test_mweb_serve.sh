#!/usr/bin/env bash
#
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# MWEB P2P serve unit tests + §7.1 coverage gate (V3 plan).
export LC_ALL=C.UTF-8

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export BUILD_DIR="${ROOT}/build-coverage"
exec "${ROOT}/ci/scripts/mweb_serve_coverage.sh"
