// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>
#include <script/script.h>

#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

#include <boost/test/unit_test.hpp>

using namespace MWEB;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_tests, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(psbt_strip_mweb_on_serialize)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(1'000'000, CScript() << OP_RETURN);
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(1'000'000).GetTransaction());
    BOOST_CHECK(!mtx.mweb_tx.IsNull());

    PartiallySignedTransaction psbt(mtx, /*version=*/0);

    DataStream ss{};
    ss << psbt;

    PartiallySignedTransaction psbt2(deserialize, ss);
    const std::optional<CMutableTransaction> unsigned_tx = psbt2.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_tx);
    BOOST_CHECK(unsigned_tx->mweb_tx.IsNull());
    BOOST_CHECK(!unsigned_tx->m_hogEx);
    BOOST_CHECK_EQUAL(unsigned_tx->vout.size(), mtx.vout.size());
    BOOST_CHECK_EQUAL(unsigned_tx->vout[0].nValue, mtx.vout[0].nValue);
}

BOOST_AUTO_TEST_SUITE_END()
