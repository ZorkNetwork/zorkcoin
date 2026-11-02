// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <mweb/mweb_coins_lifecycle.h>
#include <mw/file/file_path.h>
#include <test/util/coins.h>
#include <txdb.h>
#include <boost/test/unit_test.hpp>

namespace {
void AttachMWEB(CCoinsViewDB& base, const fs::path& datadir)
{
    MWEB::CoinsLifecycle::AttachView(base, FilePath{datadir}, nullptr);
    BOOST_REQUIRE(base.GetMWEBView());
}
} // namespace

BOOST_AUTO_TEST_SUITE(mweb_coins_tests)
BOOST_AUTO_TEST_CASE(coins_cache_dbbase_simulation_with_mweb)
{
    test::RunCoinsCacheSimulation(AttachMWEB);
}
BOOST_AUTO_TEST_CASE(ccoins_flush_behavior_with_mweb_view)
{
    test::RunCoinsCacheFlush(AttachMWEB, [](CCoinsViewCache& view) {
        BOOST_REQUIRE(view.GetMWEBCacheView());
    });
}
BOOST_AUTO_TEST_SUITE_END()
