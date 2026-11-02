// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <mweb/mweb_policy.h>
#include <primitives/transaction_identifier.h>
#include <util/feefrac.h>

#include <boost/test/unit_test.hpp>

#include <limits>

using MWEB::Policy;

BOOST_AUTO_TEST_SUITE(mweb_policy_tests)

BOOST_AUTO_TEST_CASE(replacement_fee_rate_step)
{
    const Txid replaced_txid{};
    const auto passes = [&](FeeFrac replacement, bool replacement_has_mweb, FeeFrac replaced, bool replaced_has_mweb) {
        return !Policy::CheckReplacementFeeRate(replacement, replacement_has_mweb, replaced, replaced_has_mweb, replaced_txid);
    };

    // A 2-output MWEB-only transaction pays 100 per weight unit (3,900 over 39).
    const FeeFrac original{3'900, 39};

    // The same rate at a larger weight (the wallet's 3-output version) is not enough.
    BOOST_CHECK(!passes({5'700, 57}, true, original, true));
    // Exactly 1.5x passes; one satoshi less fails.
    BOOST_CHECK(passes({5'850, 39}, true, original, true));
    BOOST_CHECK(!passes({5'849, 39}, true, original, true));
    BOOST_CHECK(passes({8'550, 57}, true, original, true));
    BOOST_CHECK(!passes({8'549, 57}, true, original, true));

    // Each step compounds: 100, then 150, then 225.
    BOOST_CHECK(passes({8'775, 39}, true, {5'850, 39}, true));
    BOOST_CHECK(!passes({8'774, 39}, true, {5'850, 39}, true));

    // MWEB data on either side triggers the rule; neither side leaves L1 replacements alone.
    BOOST_CHECK(!passes({1'000, 400}, false, original, true));
    BOOST_CHECK(!passes({1'000, 400}, true, {1'000, 400}, false));
    BOOST_CHECK(passes({1'000, 400}, false, {1'000, 400}, false));
    BOOST_CHECK(passes({1'001, 400}, true, {1'000, 600}, false));

    // Peg-out hybrid: 124 L1 weight plus 58 MWEB weight at fee_rate 1,000 replaces the original.
    BOOST_CHECK(passes({36'800, 124 + 58}, true, original, true));
    // And needs fee_rate 2,000 (not 1,000) to be replaced again by a 40-weight hybrid.
    BOOST_CHECK(!passes({35'000, 124 + 40}, true, {36'800, 124 + 58}, true));
    BOOST_CHECK(passes({66'000, 124 + 40}, true, {36'800, 124 + 58}, true));

    // Large fees don't overflow the comparison.
    const int64_t max_fee{std::numeric_limits<int64_t>::max() / 3};
    BOOST_CHECK(!passes({max_fee, 2}, true, {max_fee, 1}, true));
    BOOST_CHECK(passes({max_fee, 1}, true, {max_fee / 2, 1}, true));

    // Degenerate or overflowing sizes are refused rather than misjudged.
    BOOST_CHECK(!passes({1'000'000, 0}, true, original, true));
    BOOST_CHECK(!passes({1'000'000, 39}, true, {3'900, 0}, true));
    BOOST_CHECK(!passes({std::numeric_limits<int64_t>::max() / 3, std::numeric_limits<int32_t>::max()}, true, original, true));

    // The error names the replaced transaction.
    const auto err{Policy::CheckReplacementFeeRate({5'700, 57}, true, original, true, replaced_txid)};
    BOOST_REQUIRE(err);
    BOOST_CHECK(err->find(replaced_txid.ToString()) != std::string::npos);
    BOOST_CHECK(err->find("1.5x") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(mweb_fee_saturates_without_overflow)
{
    // MWEB: an oversized MWEB weight saturates instead of overflowing.
    const uint64_t oversized_mweb_weight = uint64_t(std::numeric_limits<CAmount>::max() / 100) + 1;
    BOOST_CHECK_EQUAL(CFeeRate::GetMWEBFee(oversized_mweb_weight), std::numeric_limits<CAmount>::max());
    BOOST_CHECK_EQUAL(CFeeRate(CAmount(1000)).GetTotalFee(1000, 2), CAmount(1200));
    BOOST_CHECK_EQUAL(CFeeRate(CAmount(1000)).GetTotalFee(1000, oversized_mweb_weight), std::numeric_limits<CAmount>::max());
}

BOOST_AUTO_TEST_SUITE_END()
