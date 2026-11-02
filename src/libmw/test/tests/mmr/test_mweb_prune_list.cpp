// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/prune_list.h>
#include <mw/file/file.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestMWEBPruneList, MWEBTestingSetup)

// Cached ranks agree with a direct count across interval boundaries, byte padding and reopened files.
BOOST_AUTO_TEST_CASE(PruneList_LargeRanks)
{
    mw::DynamicBitSet bits(1027);
    for (uint64_t i = 0; i < bits.size(); ++i) if (i % 3 == 0) bits.set(i);
    auto list = PruneList::Open(GetDataDir(), 0);
    list->Commit(1, bits);
    for (const auto& candidate : {list, PruneList::Open(GetDataDir(), 1)}) {
        for (uint64_t i = 0; i < 1100; ++i) {
            if (!bits.test(i)) BOOST_CHECK_EQUAL(candidate->GetShift(mmr::Index::At(i)), bits.rank(i));
        }
    }
    list->Commit(2, mw::DynamicBitSet{});
    BOOST_CHECK_EQUAL(list->GetShift(mmr::Index::At(1026)), 0U);
    BOOST_CHECK_EQUAL(PruneList::Open(GetDataDir(), 0)->GetTotalShift(), 0U);
    BOOST_CHECK_THROW(PruneList::Open(GetDataDir(), 3), FileException);
}

// Retrying an unpublished generation replaces its mask, including shorter and empty replacements.
BOOST_AUTO_TEST_CASE(PruneList_ReplacesOrphan)
{
    auto list = PruneList::Open(GetDataDir(), 0);
    mw::DynamicBitSet original(1027);
    original.set(1026);
    list->Commit(1, original);

    mw::DynamicBitSet replacement(16);
    replacement.set(3);
    replacement.set(9);
    for (int retry = 0; retry < 2; ++retry) {
        list->Commit(1, replacement);
        BOOST_CHECK(File(PruneList::GetPath(GetDataDir(), 1)).ReadBytes() == replacement.bytes());
        const auto reopened = PruneList::Open(GetDataDir(), 1);
        BOOST_CHECK_EQUAL(reopened->GetTotalShift(), 2U);
        BOOST_CHECK_EQUAL(reopened->GetShift(mmr::Index::At(16)), 2U);
    }

    list->Commit(1, mw::DynamicBitSet{});
    BOOST_CHECK_EQUAL(File(PruneList::GetPath(GetDataDir(), 1)).GetSize(), 0U);
    BOOST_CHECK_EQUAL(PruneList::Open(GetDataDir(), 1)->GetTotalShift(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
