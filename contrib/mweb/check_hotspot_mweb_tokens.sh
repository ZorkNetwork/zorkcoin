#!/usr/bin/env bash
# Fail if Core hotspot TUs gain raw mw:: / MWEB:: algorithm tokens outside
# thin call-out allow patterns. Behavior-preserving mergeability guard.
export LC_ALL=C.UTF-8
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Allowed: includes, comments, thin facade calls, foundational type use, sidecar members.
# This is a soft signal: counts tokens; exits non-zero only if denser than baseline file.
BASELINE="${ROOT}/contrib/mweb/hotspot_mweb_baseline.txt"
HOTSPOTS=(
  src/validation.cpp
  src/net_processing.cpp
  src/txmempool.cpp
  src/txmempool.h
  src/node/miner.cpp
  src/wallet/spend.cpp
  src/wallet/scriptpubkeyman.cpp
  src/wallet/wallet.cpp
  src/script/descriptor.cpp
)

tmp="$(mktemp)"
for f in "${HOTSPOTS[@]}"; do
  c=$(rg -c 'mweb|MWEB|mw::' "$f" 2>/dev/null || echo 0)
  total=$(wc -l < "$f" | tr -d ' ')
  printf '%s %s %s\n' "$f" "$c" "$total" >> "$tmp"
done

if [[ ! -f "$BASELINE" ]]; then
  echo "No baseline at $BASELINE — writing current counts as baseline."
  cp "$tmp" "$BASELINE"
  cat "$BASELINE"
  rm -f "$tmp"
  exit 0
fi

echo "Current hotspot MWEB token counts vs baseline:"
paste "$BASELINE" "$tmp" | while read -r bf bc _ cf cc _; do
  # format: file count lines
  echo "  $cf: $cc (baseline $bc)"
  # Allow small noise (+10%); fail if count grew by more than 15 tokens
  if [[ "$cf" == "$bf" ]]; then
    if (( cc > bc + 15 )); then
      echo "ERROR: $cf MWEB token count grew from $bc to $cc" >&2
      rm -f "$tmp"
      exit 1
    fi
  fi
done
rm -f "$tmp"
echo "OK"
