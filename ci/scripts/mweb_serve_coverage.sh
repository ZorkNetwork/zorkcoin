#!/usr/bin/env bash
# P-01 V3 §7.2: 100% line+branch coverage gate on owned serve modules.
# Uses a dedicated BUILD_DIR so the developer's normal build is not corrupted.
export LC_ALL=C.UTF-8
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-${ROOT}/build-coverage}"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

"${ROOT}/ci/scripts/mweb_grep_gate.sh"

echo "mweb_serve_coverage: configuring ${BUILD}"
# Avoid Debug's -ftrapv / ABORT_ON_FAILED_ASSUME — they make coverage functionals flaky.
cmake -B "${BUILD}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_FLAGS='--coverage -O1 -g' \
  -DCMAKE_C_FLAGS='--coverage -O1 -g' \
  -DBUILD_TESTS=ON

echo "mweb_serve_coverage: building test_bitcoin + bitcoind"
cmake --build "${BUILD}" --target test_bitcoin bitcoind -j"${JOBS}"

# Fresh counters for this run
find "${BUILD}" -name '*.gcda' -delete 2>/dev/null || true

echo "mweb_serve_coverage: running mweb_serve_tests"
"${BUILD}/bin/test_bitcoin" --run_test=mweb_serve_tests,mweb_serve_tests_chain

# Functional paths exercise ProcessOneStep / enqueue that units cannot fully cover.
COV_CONFIG="${BUILD}/coverage_test_config.ini"
sed "s|^BUILDDIR=.*|BUILDDIR=${BUILD}|" "${ROOT}/test/config.ini" > "${COV_CONFIG}"
echo "mweb_serve_coverage: running assumeutxo + rate_limit functionals (BUILDDIR=${BUILD})"
"${ROOT}/test/functional/mweb_p2p_assumeutxo_serve.py" --configfile="${COV_CONFIG}"
"${ROOT}/test/functional/mweb_p2p_rate_limit.py" --configfile="${COV_CONFIG}"
"${ROOT}/test/functional/mweb_p2p.py" --configfile="${COV_CONFIG}"
"${ROOT}/test/functional/mweb_p2p_serve_regression.py" --configfile="${COV_CONFIG}" --post-mweb-blocks=50
"${ROOT}/test/functional/mweb_p2p_serve_peer_rotation.py" --configfile="${COV_CONFIG}"

if ! command -v lcov >/dev/null 2>&1; then
  echo "mweb_serve_coverage: ERROR: lcov is required for the coverage gate" >&2
  exit 1
fi

echo "mweb_serve_coverage: capturing lcov"
lcov --capture --directory "${BUILD}" --output-file "${BUILD}/coverage.info" \
  --ignore-errors mismatch,gcov,source,inconsistent,deprecated,format,count --rc branch_coverage=1

FILTERED="${BUILD}/mweb_serve_filtered.info"
lcov --extract "${BUILD}/coverage.info" \
  '*/node/mweb_historical_cache.cpp' \
  '*/node/mweb_serve.cpp' \
  '*/node/mweb_serve_coordinator.cpp' \
  '*/node/mweb_serve_step_budget.cpp' \
  --output-file "${FILTERED}" \
  --ignore-errors unused,mismatch,inconsistent,deprecated,format,count --rc branch_coverage=1

echo "mweb_serve_coverage: summary"
lcov --summary "${FILTERED}" --ignore-errors inconsistent,deprecated,format,count --rc branch_coverage=1

SUMMARY="$(lcov --summary "${FILTERED}" --ignore-errors inconsistent,deprecated,format,count --rc branch_coverage=1 2>&1)"
echo "${SUMMARY}"
LINES_PCT="$(echo "${SUMMARY}" | awk '/lines/ {print $2}' | tr -d '%' | head -n1)"
BRANCH_PCT="$(echo "${SUMMARY}" | awk '/branches/ {print $2}' | tr -d '%' | head -n1)"

MIN_LINE="${MWEB_COVERAGE_MIN_LINE:-100}"
MIN_BRANCH="${MWEB_COVERAGE_MIN_BRANCH:-100}"

awk -v lines="${LINES_PCT}" -v branches="${BRANCH_PCT}" -v minl="${MIN_LINE}" -v minb="${MIN_BRANCH}" 'BEGIN {
  if (lines == "" || branches == "") { print "failed to parse coverage percents"; exit 1 }
  if (lines+0 < minl+0) { printf "line coverage %.2f%% < %s%%\n", lines, minl; exit 1 }
  if (branches+0 < minb+0) { printf "branch coverage %.2f%% < %s%%\n", branches, minb; exit 1 }
}'

echo "mweb_serve_coverage: OK (lines=${LINES_PCT}% branches=${BRANCH_PCT}%)"
