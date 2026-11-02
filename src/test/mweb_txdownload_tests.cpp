// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <mweb/mweb_policy.h>
#include <net_processing.h>
#include <node/txdownloadman_impl.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/util/common.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <array>
#include <boost/test/unit_test.hpp>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

namespace {
static bool CheckOrphanBehavior(node::TxDownloadManagerImpl& txdownload_impl, const CTransactionRef& tx, const node::RejectedTxTodo& ret, std::string& err_msg,
                                bool expect_orphan, bool expect_keep, unsigned int expected_parents)
{
    // Missing inputs can never result in a PackageToValidate.
    if (ret.m_package_to_validate.has_value()) {
        err_msg = strprintf("returned a PackageToValidate on missing inputs");
        return false;
    }

    if (expect_orphan != txdownload_impl.m_orphanage->HaveTx(tx->GetWitnessHash())) {
        err_msg = strprintf("unexpectedly %s tx in orphanage", expect_orphan ? "did not find" : "found");
        return false;
    }
    if (expect_keep != ret.m_should_add_extra_compact_tx) {
        err_msg = strprintf("unexpectedly returned %s add to vExtraTxnForCompact", expect_keep ? "should not" : "should");
        return false;
    }
    if (expected_parents != ret.m_unique_parents.size()) {
        err_msg = strprintf("expected %u unique_parents, got %u", expected_parents, ret.m_unique_parents.size());
        return false;
    }
    return true;
}

static CTransactionRef CreatePlaceholderTx(bool segwit)
{
    // Each tx returned from here spends the previous one.
    static Txid prevout_hash{};

    CMutableTransaction mtx;
    mtx.vin.emplace_back(prevout_hash, 0);
    // This makes txid != wtxid
    if (segwit) mtx.vin[0].scriptWitness.stack.push_back({1});
    mtx.vout.emplace_back(CENT, CScript());
    auto ptx = MakeTransactionRef(mtx);
    prevout_hash = ptx->GetHash();
    return ptx;
}

} // namespace

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(mweb_txdownload_tests)

BOOST_FIXTURE_TEST_CASE(mweb_only_missing_inputs_not_orphaned, TestChain100Setup)
{
    // Orphanage MWEB size accounting: MWEB payload with no L1 parents must not enter the orphanage.
    CTxMemPool& pool = *Assert(m_node.mempool);
    node::TxDownloadOptions opts{.m_mempool = pool, .m_deterministic_txrequest = true};
    node::TxDownloadManagerImpl txdownload_impl{opts};
    NodeId nodeid{1};
    node::TxDownloadConnectionInfo conn{/*m_preferred=*/false, /*m_relay_permissions=*/false, /*m_wtxid_relay=*/true};
    txdownload_impl.ConnectedPeer(nodeid, conn);

    CMutableTransaction mtx;
    // Peg-in body is enough to set HasMWEBTx; empty vin/vout => IsMWEBOnly / no L1 parents.
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    const CTransactionRef mweb_only = MakeTransactionRef(mtx);
    BOOST_REQUIRE(mweb_only->HasMWEBTx());
    BOOST_REQUIRE(mweb_only->vin.empty());
    BOOST_REQUIRE(mweb_only->IsMWEBOnly());

    TxValidationState state;
    state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "");
    const auto ret = txdownload_impl.MempoolRejectedTx(mweb_only, state, nodeid, /*first_time_failure=*/true);

    std::string err_msg;
    const bool ok = CheckOrphanBehavior(txdownload_impl, mweb_only, ret, err_msg,
                                        /*expect_orphan=*/false, /*expect_keep=*/false, /*expected_parents=*/0);
    BOOST_CHECK_MESSAGE(ok, err_msg);

    // Classic L1 missing-parent orphan still works on the same manager.
    const auto l1_orphan = CreatePlaceholderTx(/*segwit=*/true);
    TxValidationState state_l1;
    state_l1.Invalid(TxValidationResult::TX_MISSING_INPUTS, "");
    const auto ret_l1 = txdownload_impl.MempoolRejectedTx(l1_orphan, state_l1, nodeid, /*first_time_failure=*/true);
    BOOST_CHECK(CheckOrphanBehavior(txdownload_impl, l1_orphan, ret_l1, err_msg,
                                    /*expect_orphan=*/true, /*expect_keep=*/true, /*expected_parents=*/1));
}

BOOST_FIXTURE_TEST_CASE(mweb_uncommitted_payload_rejections_not_cached, TestChain100Setup)
{
    // txid/wtxid do not commit to MWEB data or the HogEx marker, so caching a
    // rejection would let an invalid relay variant censor a valid one.
    CTxMemPool& pool = *Assert(m_node.mempool);
    node::TxDownloadOptions opts{.m_mempool = pool, .m_deterministic_txrequest = true};
    NodeId nodeid{1};
    node::TxDownloadConnectionInfo conn{/*m_preferred=*/false, /*m_relay_permissions=*/false, /*m_wtxid_relay=*/true};

    CMutableTransaction mweb_only_mtx;
    mweb_only_mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    CMutableTransaction hogex_mtx{*CreatePlaceholderTx(/*segwit=*/true)};
    hogex_mtx.m_hogEx = true;
    CMutableTransaction stripped_pegin_mtx{*CreatePlaceholderTx(/*segwit=*/true)};
    stripped_pegin_mtx.vout.emplace_back(CENT, GetScriptForPegin(mw::Hash{}));
    // Non-final attach: Finalized() drops the body but sticky HadAttachedMWEB remains.
    CMutableTransaction nonfinal_mtx{*CreatePlaceholderTx(/*segwit=*/true)};
    {
        mw::MutableInput input(mw::Hash{});
        input.features = 0;
        input.commitment = Commitment{};
        input.output_pubkey = PublicKey{};
        input.signature = Signature{};
        nonfinal_mtx.mweb_tx.inputs.push_back(std::move(input));
        nonfinal_mtx.mweb_tx.kernels.push_back(mw::MutableKernel{});
    }
    const CTransactionRef nonfinal_tx{MakeTransactionRef(nonfinal_mtx)};
    BOOST_REQUIRE(nonfinal_tx->HadAttachedMWEB());
    BOOST_REQUIRE(!nonfinal_tx->HasMWEBTx());
    const std::array<CTransactionRef, 4> uncommitted{
        MakeTransactionRef(mweb_only_mtx), MakeTransactionRef(hogex_mtx), MakeTransactionRef(stripped_pegin_mtx), nonfinal_tx};

    for (const auto& result : {TxValidationResult::TX_CONSENSUS, TxValidationResult::TX_WITNESS_MUTATED,
                               TxValidationResult::TX_RECONSIDERABLE, TxValidationResult::TX_INPUTS_NOT_STANDARD}) {
        for (const auto& ptx : uncommitted) {
            BOOST_REQUIRE(MWEB::Policy::HasUncommittedMWEBPayload(*ptx));
            node::TxDownloadManagerImpl txdownload_impl{opts};
            txdownload_impl.ConnectedPeer(nodeid, conn);
            TxValidationState state;
            state.Invalid(result, "");
            txdownload_impl.MempoolRejectedTx(ptx, state, nodeid, /*first_time_failure=*/true);
            for (const uint256& id : {ptx->GetHash().ToUint256(), ptx->GetWitnessHash().ToUint256()}) {
                BOOST_CHECK(!txdownload_impl.RecentRejectsFilter().contains(id));
                BOOST_CHECK(!txdownload_impl.RecentRejectsReconsiderableFilter().contains(id));
            }
        }
    }

    // Ordinary transactions are still cached, and so are packages without MWEB data.
    const auto ordinary = CreatePlaceholderTx(/*segwit=*/true);
    BOOST_REQUIRE(!MWEB::Policy::HasUncommittedMWEBPayload(*ordinary));
    node::TxDownloadManagerImpl txdownload_impl{opts};
    txdownload_impl.ConnectedPeer(nodeid, conn);
    TxValidationState state;
    state.Invalid(TxValidationResult::TX_CONSENSUS, "");
    txdownload_impl.MempoolRejectedTx(ordinary, state, nodeid, /*first_time_failure=*/true);
    BOOST_CHECK(txdownload_impl.RecentRejectsFilter().contains(ordinary->GetWitnessHash().ToUint256()));

    const auto child = CreatePlaceholderTx(/*segwit=*/true);
    const Package ordinary_package{ordinary, child};
    txdownload_impl.MempoolRejectedPackage(ordinary_package);
    BOOST_CHECK(txdownload_impl.RecentRejectsReconsiderableFilter().contains(GetPackageHash(ordinary_package)));

    const Package mweb_package{uncommitted[2], child};
    txdownload_impl.MempoolRejectedPackage(mweb_package);
    BOOST_CHECK(!txdownload_impl.RecentRejectsReconsiderableFilter().contains(GetPackageHash(mweb_package)));
}

BOOST_AUTO_TEST_SUITE_END()
