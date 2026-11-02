// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/mmr_util.h>
#include <unordered_set>

#include <test_framework/test_mweb.h>

using namespace mmr;

BOOST_FIXTURE_TEST_SUITE(TestMWEBCompactionMask, MWEBTestingSetup)

// Empty MMRs need no compaction; fully spent trees retain their peaks and never compact a node beyond the horizon.
BOOST_AUTO_TEST_CASE(Compaction_EmptyAndSpentTrees)
{
    BOOST_CHECK_EQUAL(MMRUtil::BuildCompactBitSet(0, mw::DynamicBitSet{}).size(), 0U);
    for (uint64_t n = 1; n <= 64; ++n) {
        const auto mask = MMRUtil::BuildCompactBitSet(n, mw::DynamicBitSet(n));
        const auto nodes = LeafIndex::At(n).GetPosition();
        const auto peaks = MMRUtil::CalcPeakIndices(nodes);
        BOOST_CHECK_EQUAL(mask.count(), nodes - peaks.size());
        for (const auto& peak : peaks) BOOST_CHECK(!mask.test(peak.GetPosition()));
        for (uint64_t i = nodes; i < mask.size(); ++i) BOOST_CHECK(!mask.test(i));
        mw::DynamicBitSet unspent(n);
        unspent.set(0, n, true);
        BOOST_CHECK_EQUAL(MMRUtil::BuildCompactBitSet(n, unspent).count(), 0U);
    }
}

#define REQUIRE_NEXT(iter, expected_pos) \
    BOOST_REQUIRE(iter.Next()); \
    BOOST_REQUIRE(iter.GetPosition() == expected_pos);

BOOST_AUTO_TEST_SUITE_END()
