// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <core_memusage.h>
#include <node/txorphanage.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mweb_orphanage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(orphan_usage_includes_mweb)
{
    // Orphanage MWEB size accounting: orphan/compact-extra memory proxies must charge MWEB bytes.
    CMutableTransaction mtx_mweb_only;
    mtx_mweb_only.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    const CTransactionRef mweb_only = MakeTransactionRef(mtx_mweb_only);
    BOOST_REQUIRE(mweb_only->HasMWEBTx());
    BOOST_REQUIRE(mweb_only->vin.empty());

    const int64_t l1_weight{GetTransactionWeight(*mweb_only)};
    const int64_t mweb_bytes{static_cast<int64_t>(::GetSerializeSize(mweb_only->mweb_tx))};
    const int64_t usage{node::OrphanageTxUsage(*mweb_only)};
    BOOST_CHECK_EQUAL(l1_weight, 0);
    BOOST_CHECK_GT(mweb_bytes, 0);
    BOOST_CHECK_EQUAL(usage, mweb_bytes);
    BOOST_CHECK_GT(usage, l1_weight);
    BOOST_CHECK_EQUAL(RecursiveDynamicUsage(*mweb_only), static_cast<size_t>(mweb_bytes));

    // L1 weight alone would admit at the standard limit; attaching MWEB bytes must reject.
    // Peg-in bodies also add 164 L1 weight via GetTransactionWeight — leave headroom so L1
    // weight alone stays within MAX_STANDARD_TX_WEIGHT while OrphanageTxUsage exceeds it.
    std::unique_ptr<node::TxOrphanage> orphanage{node::MakeTxOrphanage()};
    CMutableTransaction tx_at_limit;
    tx_at_limit.vin.resize(1);
    BulkTransaction(tx_at_limit, MAX_STANDARD_TX_WEIGHT - 200);
    tx_at_limit.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(2 * COIN).GetTransaction());
    const CTransactionRef oversized_with_mweb = MakeTransactionRef(tx_at_limit);
    BOOST_CHECK_LE(GetTransactionWeight(*oversized_with_mweb), MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_GT(node::OrphanageTxUsage(*oversized_with_mweb), MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK(!orphanage->AddTx(oversized_with_mweb, /*peer=*/0));

    // Mixed L1+MWEB under the limit still enters, but usage includes MWEB bytes.
    CMutableTransaction tx_mixed;
    tx_mixed.vin.resize(1);
    BulkTransaction(tx_mixed, /*target_weight=*/10'000);
    tx_mixed.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(3 * COIN).GetTransaction());
    const CTransactionRef mixed = MakeTransactionRef(tx_mixed);
    const int64_t mixed_usage{node::OrphanageTxUsage(*mixed)};
    BOOST_CHECK_EQUAL(mixed_usage, GetTransactionWeight(*mixed) + static_cast<int64_t>(::GetSerializeSize(mixed->mweb_tx)));
    BOOST_CHECK_LT(mixed_usage, MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK(orphanage->AddTx(mixed, /*peer=*/1));
    BOOST_CHECK_EQUAL(orphanage->TotalOrphanUsage(), mixed_usage);
    BOOST_CHECK_GE(RecursiveDynamicUsage(*mixed), ::GetSerializeSize(mixed->mweb_tx));
}

BOOST_AUTO_TEST_SUITE_END()
