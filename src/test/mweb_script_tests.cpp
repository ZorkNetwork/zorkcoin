// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/hash.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mweb_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(script_mweb_pegin)
{
    const mw::Hash kernel_id{m_rng.randbytes(32)};
    CScript script;
    script << OP_9 << kernel_id.vec();

    mw::Hash kernel_id2;
    BOOST_CHECK(script.IsMWEBPegin(&kernel_id2));
    BOOST_CHECK(kernel_id == kernel_id2);
}

BOOST_AUTO_TEST_SUITE_END()
