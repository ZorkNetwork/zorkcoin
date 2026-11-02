// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <key.h>
#include <mw/crypto/secret_keys.h>
#include <mweb/mweb_mempool_accept.h>
#include <node/txdownloadman.h>
#include <node/txdownloadman_impl.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/truc_policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <script/standard.h>
#include <sync.h>
#include <test/util/mweb_mempool_setup.h>
#include <test/util/mweb_setup.h>
#include <test/util/setup_common.h>
#include <test_framework/models/tx.h>
#include <test_framework/tx_builder.h>
#include <txmempool.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <tuple>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mweb_package_tests, MWEBPackageSetup)

// Two package parents spending the same MWEB output conflict, even when neither can be
// accepted alone and a child spending both makes them a valid package topology.
BOOST_AUTO_TEST_CASE(package_rejects_hybrid_parents_spending_same_mweb_output)
{
    constexpr CAmount pegin{COIN};
    const auto make_parent = [&] {
        const test::Tx mweb = test::TxBuilder()
                                  .AddInput(m_mweb_coins[0])
                                  .AddPeginKernel(pegin, /*fee=*/std::nullopt)
                                  .AddOutput(m_mweb_coins[0].GetAmount() + pegin)
                                  .Build();
        return MakeHybrid(mweb, pegin, /*l1_fee=*/0);
    };
    const CTransactionRef tx_a = make_parent();
    const CTransactionRef tx_b = make_parent();
    const CTransactionRef tx_c = MakeL1Child({tx_a, tx_b}, /*fee=*/COIN / 10);

    const PackageMempoolAcceptResult result = SubmitPackage({tx_a, tx_b, tx_c});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "conflict-in-package");
    CheckPool({}, /*absent=*/{tx_a, tx_b, tx_c});
}

// A package dry run resolves the parent's temporary MWEB output, but that output is unavailable outside the package.
BOOST_AUTO_TEST_CASE(package_dry_run_does_not_leak_mweb_outputs)
{
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    const auto result = SubmitPackage({parent, child}, /*test_accept=*/true);
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_CHECK(result.m_tx_results.at(parent->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(result.m_tx_results.at(child->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    CheckPool({}, /*absent=*/{parent, child});
    BOOST_CHECK(!HaveConfirmedMWEBCoin(parent_mweb.GetOutputs().front().GetOutputID()));
    Reject(child, TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto submitted = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(submitted.m_state.IsValid(), submitted.m_state.ToString());
    CheckPool({parent, child});
}

// A fee-paying MWEB child can bring a zero-fee peg-in parent into the mempool as one package.
BOOST_AUTO_TEST_CASE(package_child_pays_for_pegin_parent)
{
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, /*l1_fee=*/0);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    Reject(parent, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_CHECK_EQUAL(result.m_tx_results.at(parent->GetWitnessHash()).m_base_fees.value(), 0);
    BOOST_CHECK_EQUAL(result.m_tx_results.at(child->GetWitnessHash()).m_base_fees.value(), MWEB_FEE);
    CheckPool({parent, child});
    CheckGraph(parent, /*ancestors=*/{parent}, /*descendants=*/{parent, child});
    CheckGraph(child, /*ancestors=*/{parent, child}, /*descendants=*/{child});
}

// Package fee accounting also works when both parent and child are MWEB-only, with no L1 vsize.
BOOST_AUTO_TEST_CASE(package_child_pays_for_pure_mweb_parent)
{
    const test::Tx parent_mweb = Spend(m_mweb_coins[0], /*fee=*/0);
    const auto parent = MakeMWEBOnly(parent_mweb);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*parent) + GetVirtualTransactionSize(*child), 0);
    Reject(parent, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({parent, child});
    CheckGraph(child, /*ancestors=*/{parent, child}, /*descendants=*/{child});
    LOCK(Pool().cs);
    BOOST_CHECK_EQUAL(Pool().GetTotalFee(), MWEB_FEE);
}

// A package whose total fee is below the MWEB weight charge admits neither its unpaid parent nor its child.
BOOST_AUTO_TEST_CASE(package_mweb_fee_shortfall_is_rejected)
{
    const test::Tx parent_mweb = Spend(m_mweb_coins[0], /*fee=*/0);
    const auto parent = MakeMWEBOnly(parent_mweb);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front(), /*fee=*/1));
    const auto result = SubmitPackage({parent, child});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_TX);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "transaction failed");
    const auto& child_result = result.m_tx_results.at(child->GetWitnessHash());
    BOOST_CHECK(child_result.m_state.GetResult() == TxValidationResult::TX_RECONSIDERABLE);
    BOOST_CHECK_EQUAL(child_result.m_state.GetRejectReason(), "mempool min fee not met");
    CheckPool({}, /*absent=*/{parent, child});
}

// A joining transaction can spend MWEB outputs from two package parents, with both ancestors accounted for once.
BOOST_AUTO_TEST_CASE(package_resolves_multiple_mweb_parents)
{
    const test::Tx first_mweb = Pegin(2 * COIN);
    const test::Tx second_mweb = Pegin(3 * COIN);
    const auto first = MakeHybrid(first_mweb, 2 * COIN, /*l1_fee=*/0);
    const auto second = MakeHybrid(second_mweb, 3 * COIN, /*l1_fee=*/0);
    const auto child = MakeMWEBOnly(Spend({first_mweb.GetOutputs()[0], second_mweb.GetOutputs()[0]}));
    const auto result = SubmitPackage({first, second, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({first, second, child});
    CheckGraph(first, /*ancestors=*/{first}, /*descendants=*/{first, child});
    CheckGraph(second, /*ancestors=*/{second}, /*descendants=*/{second, child});
    CheckGraph(child, /*ancestors=*/{first, second, child}, /*descendants=*/{child});
}

// Resubmitting an existing parent in a package does not duplicate its entry or charge its fee a second time.
BOOST_AUTO_TEST_CASE(package_deduplicates_existing_mweb_parent)
{
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    Accept(parent, L1_FEE);
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    const auto& parent_result = result.m_tx_results.at(parent->GetWitnessHash());
    BOOST_CHECK(parent_result.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
    BOOST_CHECK_EQUAL(parent_result.m_mweb_weight.value(), parent->mweb_tx.GetMWEBWeight());
    BOOST_CHECK(result.m_tx_results.at(child->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    CheckPool({parent, child});
    CheckGraph(child, /*ancestors=*/{parent, child}, /*descendants=*/{child});
    LOCK(Pool().cs);
    BOOST_CHECK_EQUAL(Pool().GetTotalFee(), L1_FEE + MWEB_FEE);
}

// MWEB output IDs determine package ordering just like L1 outpoints; a child-before-parent package is rejected.
BOOST_AUTO_TEST_CASE(package_requires_mweb_parent_before_child)
{
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    const auto result = SubmitPackage({child, parent});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "package-not-sorted");
    BOOST_CHECK(result.m_tx_results.empty());
    CheckPool({}, /*absent=*/{parent, child});
}

// Two transactions spending the same MWEB output conflict within a package, without affecting an unrelated pool entry.
BOOST_AUTO_TEST_CASE(package_rejects_conflicting_mweb_spends)
{
    const auto first = MakeMWEBOnly(Spend(m_mweb_coins[0]));
    const auto second = MakeMWEBOnly(Spend(m_mweb_coins[0], 2 * MWEB_FEE));
    const auto independent = MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE);
    Accept(independent, L1_FEE);
    const auto result = SubmitPackage({first, second});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "conflict-in-package");
    CheckPool({independent}, /*absent=*/{first, second});
}

// A failed dry run must discard temporary parent outputs even when the child fails after successfully finding them.
BOOST_AUTO_TEST_CASE(failed_package_discards_temporary_mweb_coins)
{
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto& output = parent_mweb.GetOutputs().front();
    const auto wrong_key = test::TxBuilder()
                               .AddInput(output.GetAmount(), SecretKey::Random(), output.GetBlind(), output.GetOutputID())
                               .AddOutput(output.GetAmount() - MWEB_FEE)
                               .AddPlainKernel(MWEB_FEE)
                               .Build();
    const auto invalid_child = MakeMWEBOnly(wrong_key);
    const auto result = SubmitPackage({parent, invalid_child}, /*test_accept=*/true);
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_TX);
    BOOST_REQUIRE_EQUAL(result.m_tx_results.count(invalid_child->GetWitnessHash()), 1U);
    const auto& child_state = result.m_tx_results.at(invalid_child->GetWitnessHash()).m_state;
    BOOST_CHECK(child_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(child_state.GetRejectReason(), "bad-txns-input-mismatch");
    CheckPool({}, /*absent=*/{parent, invalid_child});
    BOOST_CHECK(!HaveConfirmedMWEBCoin(output.GetOutputID()));
    const auto valid_child = MakeMWEBOnly(Spend(output));
    Reject(valid_child, TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto retry = SubmitPackage({parent, valid_child});
    BOOST_REQUIRE_MESSAGE(retry.m_state.IsValid(), retry.m_state.ToString());
    CheckPool({parent, valid_child});
}

// The context-free package checks follow MWEB output links as well as L1 outpoints.
BOOST_AUTO_TEST_CASE(context_free_checks_follow_mweb_links)
{
    const test::Tx parent_mweb = Spend(m_mweb_coins[0]);
    const auto parent = MakeMWEBOnly(parent_mweb);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    const auto unrelated = MakeMWEBOnly(Spend(m_mweb_coins[1]));

    BOOST_CHECK(IsTopoSortedPackage({parent, child}));
    BOOST_CHECK(!IsTopoSortedPackage({child, parent}));
    BOOST_CHECK(IsConsistentPackage({parent, child, unrelated}));
    BOOST_CHECK(!IsConsistentPackage({parent, MakeMWEBOnly(Spend(m_mweb_coins[0], 2 * MWEB_FEE))}));
    BOOST_CHECK(!IsConsistentPackage({parent, MakeTransactionRef(CMutableTransaction{})}));
    BOOST_CHECK(IsChildWithParents({parent, child}));
    BOOST_CHECK(!IsChildWithParents({unrelated, child}));
    BOOST_CHECK(IsChildWithParentsTree({parent, child}));

    // A tree's parents may not depend on each other through MWEB outputs either.
    const test::Tx middle_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto middle = MakeMWEBOnly(middle_mweb);
    const auto joining = MakeMWEBOnly(Spend({parent_mweb.GetOutputs().front(), middle_mweb.GetOutputs().front()}));
    BOOST_CHECK(IsChildWithParents({parent, middle, joining}));
    BOOST_CHECK(!IsChildWithParentsTree({parent, middle, joining}));
}

// A 1-parent-1-child MWEB-only package can replace a mempool transaction. Both chunk fee rates
// are rated over adjusted weight; by L1 vsize they would both be empty and the replacement refused.
BOOST_AUTO_TEST_CASE(package_rbf_replaces_mweb_only_transaction)
{
    const auto original = MakeMWEBOnly(Spend(m_mweb_coins[0]));
    Accept(original, MWEB_FEE);

    const test::Tx parent_mweb = Spend(m_mweb_coins[0], /*fee=*/0);
    const auto parent = MakeMWEBOnly(parent_mweb);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front(), 10 * MWEB_FEE));
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({parent, child});
    const auto& replaced = result.m_tx_results.at(parent->GetWitnessHash()).m_replaced_transactions;
    BOOST_REQUIRE_EQUAL(replaced.size(), 1U);
    BOOST_CHECK(replaced.front()->GetHash() == original->GetHash());
}

// The effective fee rate rates MWEB fees over adjusted weight; transactions without MWEB keep upstream's fee rate.
BOOST_AUTO_TEST_CASE(effective_feerate_rates_mweb_by_adjusted_weight)
{
    BOOST_CHECK(MWEB::MempoolAccept::EffectiveFeeRate(1'000, 250, 0, 1'001) == CFeeRate(1'000, 250));
    BOOST_CHECK(MWEB::MempoolAccept::EffectiveFeeRate(1'000, 0, 21, 21) == CFeeRate(1'000, 6));
    BOOST_CHECK_EQUAL(MWEB::MempoolAccept::AdjustedVSize(250, 0, 1'001), 250);
    BOOST_CHECK_EQUAL(MWEB::MempoolAccept::AdjustedVSize(0, 21, 21), 6);

    // Accept() checks m_mweb_weight, which is 0 without MWEB data.
    const auto hybrid = MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE);
    Accept(hybrid, L1_FEE);
    Accept(MakeL1Child({hybrid}, L1_FEE), L1_FEE);

    const test::Tx parent_mweb = Spend(m_mweb_coins[0], /*fee=*/0);
    const auto parent = MakeMWEBOnly(parent_mweb);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());

    LOCK(Pool().cs);
    int64_t adjusted_weight{0};
    for (const auto& tx : {parent, child}) {
        const auto& tx_result = result.m_tx_results.at(tx->GetWitnessHash());
        BOOST_CHECK_EQUAL(tx_result.m_mweb_weight.value(), tx->mweb_tx.GetMWEBWeight());
        BOOST_CHECK_GT(tx_result.m_mweb_weight.value(), 0U);
        adjusted_weight += Pool().GetEntry(tx->GetHash())->GetAdjustedWeight();
    }
    const CFeeRate expected{MWEB_FEE, static_cast<int32_t>((adjusted_weight + 3) / 4)};
    for (const auto& tx : {parent, child}) {
        const auto& feerate = result.m_tx_results.at(tx->GetWitnessHash()).m_effective_feerate.value();
        BOOST_CHECK(feerate == expected);
        BOOST_CHECK_GT(feerate.GetFeePerK(), 0);
    }
}

// Peers find 1-parent-1-child packages only through L1 outpoints, but a pair found that way
// may carry MWEB data, and the child's MWEB link to the parent then resolves in the package.
BOOST_AUTO_TEST_CASE(p2p_1p1c_resolves_mweb_link_beside_l1_link)
{
    constexpr CAmount pegin{COIN};
    const test::Tx parent_mweb = Pegin();
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, /*l1_fee=*/0);
    const auto& parent_output = parent_mweb.GetOutputs().front();
    const test::Tx child_mweb = test::TxBuilder()
                                    .AddInput(parent_output)
                                    .AddPeginKernel(pegin, /*fee=*/std::nullopt)
                                    .AddOutput(parent_output.GetAmount() + pegin)
                                    .Build();
    CMutableTransaction child_mtx;
    child_mtx.vin.emplace_back(COutPoint{parent->GetHash(), 1});
    child_mtx.vout.emplace_back(pegin, GetScriptForPegin(child_mweb.GetPegInCoin().GetKernelID()));
    child_mtx.vout.emplace_back(parent->vout[1].nValue - pegin - COIN / 10, ChangeScript());
    child_mtx.mweb_tx = mw::MutableTx::From(*child_mweb.GetTransaction());
    Sign(child_mtx, {parent});
    const auto child = MakeTransactionRef(child_mtx);

    const node::TxDownloadOptions opts{.m_mempool = Pool(), .m_deterministic_txrequest = true};
    node::TxDownloadManagerImpl txdownload{opts};
    const NodeId peer{0};
    txdownload.ConnectedPeer(peer, {/*m_preferred=*/false, /*m_relay_permissions=*/false, /*m_wtxid_relay=*/true});

    // The child arrives first and is kept as an orphan for its missing L1 parent.
    const MempoolAcceptResult child_result{Submit(child)};
    BOOST_REQUIRE(child_result.m_state.GetResult() == TxValidationResult::TX_MISSING_INPUTS);
    const auto orphan_todo = txdownload.MempoolRejectedTx(child, child_result.m_state, peer, /*first_time_failure=*/true);
    BOOST_CHECK(orphan_todo.m_unique_parents == std::vector<Txid>{parent->GetHash()});

    // The parent is below the minimum fee, and its rejection pairs it with the orphan.
    const MempoolAcceptResult parent_result{Submit(parent)};
    BOOST_REQUIRE(parent_result.m_state.GetResult() == TxValidationResult::TX_RECONSIDERABLE);
    const auto parent_todo = txdownload.MempoolRejectedTx(parent, parent_result.m_state, peer, /*first_time_failure=*/true);
    BOOST_REQUIRE(parent_todo.m_package_to_validate.has_value());
    const Package& package{parent_todo.m_package_to_validate->m_txns};
    BOOST_REQUIRE_EQUAL(package.size(), 2U);
    BOOST_CHECK(package[0] == parent && package[1] == child);

    const auto result = SubmitPackage(package);
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({parent, child});
    CheckGraph(child, /*ancestors=*/{parent, child}, /*descendants=*/{child});
}

// TRUC finds in-package parents through MWEB outputs.
BOOST_AUTO_TEST_CASE(truc_package_follows_mweb_parents)
{
    {
        // A zero-fee v3 MWEB parent with a v3 MWEB child is a valid TRUC package.
        const test::Tx parent_mweb = Spend(m_mweb_coins[0], /*fee=*/0);
        const auto parent = MakeMWEBOnly(parent_mweb, TRUC_VERSION);
        const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()), TRUC_VERSION);
        const auto result = SubmitPackage({parent, child});
        BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
        CheckPool({parent, child});
        MineMWEBEraBlock();
        CheckPool({}, /*absent=*/{parent, child});
    }
    {
        // A v3 child with two v3 MWEB parents in the package has too many ancestors.
        const test::Tx first_mweb = Spend(m_mweb_coins[1], /*fee=*/0);
        const test::Tx second_mweb = Spend(m_mweb_coins[2], /*fee=*/0);
        const auto first = MakeMWEBOnly(first_mweb, TRUC_VERSION);
        const auto second = MakeMWEBOnly(second_mweb, TRUC_VERSION);
        const auto child = MakeMWEBOnly(Spend({first_mweb.GetOutputs()[0], second_mweb.GetOutputs()[0]}), TRUC_VERSION);
        const auto result = SubmitPackage({first, second, child});
        BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "TRUC-violation");
        BOOST_CHECK(result.m_state.GetDebugMessage().find("too many ancestors") != std::string::npos);
        CheckPool({}, /*absent=*/{first, second, child});

        // A non-v3 MWEB child cannot spend a v3 MWEB parent in the package.
        const auto v2_child = MakeMWEBOnly(Spend(first_mweb.GetOutputs()[0]));
        const auto v2_result = SubmitPackage({first, v2_child});
        BOOST_CHECK(v2_result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(v2_result.m_state.GetRejectReason(), "TRUC-violation");
        BOOST_CHECK(v2_result.m_state.GetDebugMessage().find("cannot spend from version=3") != std::string::npos);
        CheckPool({}, /*absent=*/{first, v2_child});
    }
}

// The TRUC child size limit counts MWEB weight for transactions with MWEB data.
BOOST_AUTO_TEST_CASE(truc_child_size_counts_mweb_weight)
{
    const auto parent = MakeHybrid(Pegin(), FUNDING_AMOUNT, L1_FEE, TRUC_VERSION);
    Accept(parent, L1_FEE);

    // The fee covers the MWEB weight, so only the TRUC size limit can refuse the child.
    constexpr CAmount child_fee{COIN / 100};
    const auto make_child = [&](size_t num_outputs) {
        constexpr CAmount pegin{COIN};
        test::TxBuilder builder;
        builder.AddPeginKernel(pegin, /*fee=*/std::nullopt);
        CAmount remaining{pegin};
        for (size_t i{0}; i < num_outputs; ++i) {
            const CAmount amount{i + 1 == num_outputs ? remaining : pegin / static_cast<CAmount>(num_outputs)};
            builder.AddOutput(amount);
            remaining -= amount;
        }
        const test::Tx mweb{builder.Build()};
        CMutableTransaction mtx;
        mtx.version = TRUC_VERSION;
        mtx.vin.emplace_back(COutPoint{parent->GetHash(), 1});
        mtx.vout.emplace_back(pegin, GetScriptForPegin(mweb.GetPegInCoin().GetKernelID()));
        mtx.vout.emplace_back(parent->vout[1].nValue - pegin - child_fee, ChangeScript());
        mtx.mweb_tx = mw::MutableTx::From(*mweb.GetTransaction());
        Sign(mtx, {parent});
        return MakeTransactionRef(mtx);
    };

    // Small by L1 vsize, but over TRUC_CHILD_MAX_VSIZE once its MWEB weight is counted.
    const auto heavy = make_child(200);
    BOOST_REQUIRE_LT(GetVirtualTransactionSize(*heavy), TRUC_CHILD_MAX_VSIZE);
    BOOST_REQUIRE_LE(heavy->mweb_tx.GetMWEBWeight(), 4'000U);
    const MempoolAcceptResult heavy_result{Submit(heavy)};
    BOOST_CHECK(heavy_result.m_state.GetResult() == TxValidationResult::TX_MEMPOOL_POLICY);
    BOOST_CHECK_EQUAL(heavy_result.m_state.GetRejectReason(), "TRUC-violation");
    BOOST_CHECK(heavy_result.m_state.GetDebugMessage().find("is too big") != std::string::npos);
    CheckPool({parent}, /*absent=*/{heavy});

    Accept(make_child(2), child_fee);
}

// Memory pressure evicts a low-fee peg-in and its MWEB child together, keeping the
// higher-fee independent transaction.
BOOST_AUTO_TEST_CASE(size_trimming_removes_mweb_package)
{
    const test::Tx parent_mweb{Pegin()};
    const auto parent = MakeHybrid(parent_mweb, FUNDING_AMOUNT, L1_FEE);
    const auto child = MakeMWEBOnly(Spend(parent_mweb.GetOutputs().front()));
    const auto high_fee = MakeHybrid(Pegin(2 * COIN), 2 * COIN, COIN);
    Accept(parent, L1_FEE);
    Accept(child, MWEB_FEE);
    Accept(high_fee, COIN);
    std::vector<COutPoint> unspent_inputs;
    {
        LOCK2(::cs_main, Pool().cs);
        Pool().TrimToSize(Pool().DynamicMemoryUsage() - 1, &unspent_inputs);
    }
    CheckPool({high_fee}, {parent, child});
    CheckGraph(high_fee, {high_fee}, {high_fee});
    BOOST_REQUIRE_EQUAL(unspent_inputs.size(), 1U);
    BOOST_CHECK(unspent_inputs.front() == parent->vin.front().prevout);
}

// Pure MWEB dependency edges participate in the current cluster-count policy.
BOOST_AUTO_TEST_CASE(mweb_chain_obeys_cluster_count_limit)
{
    const unsigned limit = Pool().m_opts.limits.cluster_count;
    BOOST_REQUIRE_EQUAL(limit, DEFAULT_CLUSTER_LIMIT);
    BOOST_REQUIRE_GT(limit, 5U);
    std::vector<CTransactionRef> chain;
    auto output = m_mweb_coins.front();
    for (unsigned i = 0; i < limit; ++i) {
        const auto body = Spend(output);
        const auto tx = MakeMWEBOnly(body);
        BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*tx), 0);
        Accept(tx, MWEB_FEE);
        chain.push_back(tx);
        output = body.GetOutputs().front();
    }
    CheckPool(chain);
    CheckGraph(chain.front(), {chain.front()}, chain);
    CheckGraph(chain.back(), chain, {chain.back()});

    const auto over_limit = MakeMWEBOnly(Spend(output));
    Reject(over_limit, TxValidationResult::TX_MEMPOOL_POLICY, "too-large-cluster");
    CheckPool(chain, {over_limit});
    CheckGraph(chain.back(), chain, {chain.back()});
}

BOOST_AUTO_TEST_SUITE_END()
