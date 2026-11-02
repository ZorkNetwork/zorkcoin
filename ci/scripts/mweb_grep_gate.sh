#!/usr/bin/env bash
# P-01 V3 §10 grep gate: no full Materialize in owned serve paths.
export LC_ALL=C.UTF-8
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# Peer-request paths only. Node-internal freezes (block connect, AssumeUTXO
# activation, cache warm-up in mweb_historical_cache.cpp) are out of scope; the
# serve path reaches MWEBHistoricalViewCache::Store() only with views it already
# copied in steps, which Store() keeps without copying.
OWNED=(
  src/node/mweb_serve.cpp
  src/node/mweb_serve_coordinator.cpp
  src/node/mweb_serve_step_budget.cpp
)

FAIL=0
for f in "${OWNED[@]}"; do
  if grep -nE 'CoinsViewMemory::Materialize\(|MaterializeAssumeUTXOSnapshot\(' "$f" 2>/dev/null; then
    echo "mweb_grep_gate: forbidden full Materialize in $f" >&2
    FAIL=1
  fi
done

if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
echo "mweb_grep_gate: OK"
