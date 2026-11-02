#!/usr/bin/env bash
# Local pre-push smoke gate for configs that recently bit CI but are runnable
# without the full GitHub matrix (Windows MSVC / native macOS runners excluded).
#
# Usage (from repo root):
#   ./ci/local-smoke.sh              # native + cmake + optional docker jobs
#   SKIP_DOCKER=1 ./ci/local-smoke.sh
#   ONLY=native ./ci/local-smoke.sh  # native Autotools only
#   ONLY=cmake ./ci/local-smoke.sh
#   ONLY=docker ./ci/local-smoke.sh
#
# Docker jobs need Docker and build ci/linux-debian.Dockerfile once (cached as
# secp256k1-ci-local). They remount this tree and re-run ./ci/ci.sh. This script
# distcleans before each docker preset so HOST/CC changes do not link stale
# objects from a prior arch. Expect a dirty tree afterward (last docker HOST/CC
# wins; re-run native configure before local make).
#
# Env:
#   JOBS            parallel make/cmake jobs (default: nproc or 4)
#   TEST_ITERS      SECP256K1_TEST_ITERS for smoke (default: 2)
#   SKIP_DOCKER=1   skip Valgrind / UBSan / s390x docker presets
#   DOCKER_IMAGE    image tag (default: secp256k1-ci-local)
#   ONLY            native|cmake|docker|all (default: all)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JOBS="${JOBS:-$(command -v nproc >/dev/null && nproc || echo 4)}"
TEST_ITERS="${TEST_ITERS:-2}"
DOCKER_IMAGE="${DOCKER_IMAGE:-secp256k1-ci-local}"
ONLY="${ONLY:-all}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"

FAILED=0
pass() { printf 'OK  %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILED=1; }
section() { printf '\n==> %s\n' "$*"; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 1
    }
}

# Baseline env matching .github/workflows/ci.yml defaults (ZKP modules stay at
# configure.ac defaults: on). Override per docker preset below.
ci_base_env() {
    cat <<EOF
WERROR_CFLAGS=-Werror -pedantic-errors
MAKEFLAGS=-j${JOBS}
BUILD=check
ECMULTWINDOW=15
ECMULTGENKB=86
ASM=no
WIDEMUL=auto
WITH_VALGRIND=yes
EXTRAFLAGS=
EXPERIMENTAL=no
ECDH=yes
RECOVERY=yes
EXTRAKEYS=yes
MUSIG=yes
SCHNORRSIG=yes
ELLSWIFT=yes
SILENTPAYMENTS=yes
SECP256K1_TEST_ITERS=${TEST_ITERS}
BENCH=yes
SECP256K1_BENCH_ITERS=2
CTIMETESTS=no
SYMBOL_CHECK=yes
EXAMPLES=yes
HOST=
WRAPPER_CMD=
EOF
}

run_trailing_whitespace() {
    section "trailing whitespace (ZKP sources)"
    need_cmd rg
    if rg -n ' +$' \
        src/modules/aggsig \
        src/modules/bulletproofs \
        src/modules/commitment \
        src/modules/generator \
        src/modules/schnorrsig_mw \
        src/modules/zkp*.h \
        include/secp256k1_scratch.h \
        include/secp256k1_bulletproofs.h \
        include/secp256k1_aggsig.h \
        include/secp256k1_commitment.h \
        include/secp256k1_generator.h \
        include/secp256k1_schnorrsig_mw.h \
        2>/dev/null
    then
        fail "trailing whitespace present"
    else
        pass "no trailing whitespace"
    fi
}

run_native() {
    section "native Autotools: ZKP off"
    need_cmd make
    ./autogen.sh >/dev/null
    ./configure \
        --enable-module-generator=no \
        --enable-module-commitment=no \
        --enable-module-bulletproof=no \
        --enable-module-aggsig=no \
        --enable-module-schnorrsig-mw=no
    make -j"${JOBS}" clean >/dev/null || true
    if make -j"${JOBS}" check SECP256K1_TEST_ITERS="${TEST_ITERS}"; then
        pass "ZKP-off make check"
    else
        fail "ZKP-off make check"
    fi

    section "native Autotools: ZKP on (defaults)"
    ./configure
    make -j"${JOBS}" clean >/dev/null || true
    if make -j"${JOBS}" check SECP256K1_TEST_ITERS="${TEST_ITERS}"; then
        pass "ZKP-on make check"
    else
        fail "ZKP-on make check"
    fi
}

run_cmake_shared() {
    section "CMake shared + ctest (DLL-export smoke)"
    need_cmd cmake
    rm -rf build-smoke
    cmake -B build-smoke -DBUILD_SHARED_LIBS=ON -DSECP256K1_BUILD_BENCHMARK=ON
    cmake --build build-smoke -j"${JOBS}"
    if ctest --test-dir build-smoke -j"${JOBS}" --output-on-failure; then
        pass "cmake shared ctest"
    else
        fail "cmake shared ctest"
    fi
    # Ensure the ZKP bench that previously failed to link against scratch exports exists.
    if find build-smoke -name 'bench_bulletproof*' | grep -q .; then
        pass "bench_bulletproof linked"
    else
        fail "bench_bulletproof missing (shared link / ZKP benches)"
    fi
}

ensure_docker_image() {
    need_cmd docker
    if ! docker image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1; then
        section "building Docker image ${DOCKER_IMAGE}"
        docker build -t "${DOCKER_IMAGE}" -f ci/linux-debian.Dockerfile .
    fi
}

run_docker_ci() {
    local name="$1"
    shift
    local envfile
    section "docker ci/ci.sh: ${name}"
    ensure_docker_image

    # Wipe in-tree build products before each preset. Sequential docker jobs
    # share this checkout; without distclean, s390x (etc.) links leftover
    # objects from the previous HOST/CC and fails with "file in wrong format".
    if [ -f Makefile ]; then
        make distclean >/dev/null 2>&1 || true
    fi

    envfile="$(mktemp)"
    ci_base_env >"${envfile}"
    # Extra --env args (KEY=VAL) override the env-file.
    if docker run --rm \
        --ulimit nofile=32768 \
        -v "${ROOT}:${ROOT}" \
        -w "${ROOT}" \
        --env-file "${envfile}" \
        "$@" \
        "${DOCKER_IMAGE}" \
        bash -c "git config --global --add safe.directory '${ROOT}' && ./ci/ci.sh"
    then
        pass "docker ${name}"
        rm -f "${envfile}"
    else
        fail "docker ${name}"
        rm -f "${envfile}"
    fi
}

run_docker_presets() {
    if [ "${SKIP_DOCKER}" = "1" ]; then
        section "docker presets skipped (SKIP_DOCKER=1)"
        return 0
    fi
    if ! command -v docker >/dev/null 2>&1; then
        section "docker not found; skipping Valgrind / UBSan / s390x"
        return 0
    fi

    # Valgrind memcheck (VERIFY builds via check / exhaustive) — caught scalar_clear misuse.
    run_docker_ci "valgrind" \
        --env 'WRAPPER_CMD=valgrind --error-exitcode=42' \
        --env CC=clang \
        --env WITH_VALGRIND=yes \
        --env CTIMETESTS=no \
        --env 'ECMULTWINDOW=2' \
        --env 'ECMULTGENKB=2'

    # UBSan/ASan — caught rands64 signed overflow.
    # ASan exports __odr_asan_gen_* markers for the library's exported variables,
    # which symbol-check.py rejects; upstream CI disables the check for this job too.
    run_docker_ci "ubsan-asan" \
        --env CC=clang \
        --env 'CFLAGS=-fsanitize=undefined,address -fno-sanitize-recover=undefined,address -g' \
        --env WITH_VALGRIND=no \
        --env CTIMETESTS=no \
        --env SYMBOL_CHECK=no \
        --env 'UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1' \
        --env 'ASAN_OPTIONS=detect_leaks=1'

    # Big-endian via QEMU — caught pubkey.data endian assumption.
    run_docker_ci "s390x" \
        --env HOST=s390x-linux-gnu \
        --env 'WRAPPER_CMD=qemu-s390x' \
        --env WITH_VALGRIND=no \
        --env CTIMETESTS=no \
        --env CC=s390x-linux-gnu-gcc
}

case "${ONLY}" in
    all)
        run_trailing_whitespace
        run_native
        run_cmake_shared
        run_docker_presets
        ;;
    native)
        run_trailing_whitespace
        run_native
        ;;
    cmake)
        run_cmake_shared
        ;;
    docker)
        run_docker_presets
        ;;
    *)
        echo "unknown ONLY=${ONLY} (use all|native|cmake|docker)" >&2
        exit 2
        ;;
esac

printf '\n'
if [ "${FAILED}" -ne 0 ]; then
    echo "local-smoke: FAILURES present"
    exit 1
fi
echo "local-smoke: all selected checks passed"
echo "Note: this is not the full GitHub matrix (no MSVC/clang-cl/macOS-runner/gcc-snapshot)."
