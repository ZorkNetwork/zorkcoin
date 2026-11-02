#!/usr/bin/env bash
#
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:26.04"
export CONTAINER_NAME=ci_native_mweb_mega_quick
export APT_LLVM_V="22"
export PACKAGES="clang-${APT_LLVM_V} llvm-${APT_LLVM_V} python3-zmq"
export NO_DEPENDS=1
export RUN_UNIT_TESTS=true
export RUN_FUNCTIONAL_TESTS=true
export RUN_FUZZ_TESTS=false
export GOAL="all"
export BITCOIN_CONFIG="-DCMAKE_CXX_FLAGS=--coverage -DCMAKE_C_FLAGS=--coverage"
export TEST_RUNNER_EXTRA="--extended"
export TEST_RUNNER_TESTS="mweb_p2p.py mweb_p2p_rate_limit.py mweb_p2p_serve_regression.py --post-mweb-blocks=50"
