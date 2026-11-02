// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <mw/consensus/aggregation.h>
#include <mw/crypto/blinds.h>
#include <mw/crypto/key_derivation.h>
#include <mw/crypto/public_keys.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/node/coins_view.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test_framework/tx_builder.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr CAmount FUNDING_AMOUNT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr CAmount CANONICAL_FEE{20'000};
constexpr int64_t TEST_TIME{1'601'450'001};

CMutableTransaction WithMWEB(const test::Tx& mweb_tx)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx.GetTransaction());
    for (const PegInCoin& pegin : mweb_tx.GetPegIns()) {
        tx.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin.GetKernelID()));
    }
    if (!tx.vout.empty()) {
        tx.vin.emplace_back(Txid::FromUint256(uint256{mweb_tx.GetTransaction()->GetHash().vec()}), 0);
        tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
    }
    return tx;
}

CTransactionRef CanonicalSpend(const COutPoint& input, const CAmount amount)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(input);
    tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
    tx.vout.emplace_back(amount, P2WSH_OP_TRUE);
    return MakeTransactionRef(tx);
}

// Extra kernels are signed and their blinds are included in the offset, so
// feature and lock-height tests do not fail incidentally on invalid signatures.
test::Tx WithExtraKernel(const test::Tx& tx, const std::optional<int32_t> lock_height = std::nullopt,
                        const std::vector<uint8_t>& extra_data = {})
{
    const auto& original = tx.GetTransaction();
    const BlindingFactor blind = BlindingFactor::Random();
    auto kernels = original->GetKernels();
    kernels.push_back(Kernel::Create(blind, std::nullopt, 0, std::nullopt, {}, lock_height, extra_data));
    return test::Tx{mw::Transaction::Create(
        Blinds(original->GetKernelOffset()).Sub(blind).Total(), original->GetStealthOffset(),
        original->GetInputs(), original->GetOutputs(), std::move(kernels)), tx.GetOutputs()};
}

/**
 * Exercise real admission with standardness, fees, signatures, and consistency
 * checks enabled. Only initial funding is seeded into chainstate. A small
 * ancestor limit keeps the boundary tests readable without long artificial chains.
 */
class MWEBMempoolView : public CCoinsViewMemPool
{
public:
    using CCoinsViewMemPool::CCoinsViewMemPool;
    using CCoinsViewMemPool::mempool;
};

class MWEBMempoolTestingSetup : public TestingSetup
{
public:
    MWEBMempoolTestingSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {
              "-acceptnonstdtxn=0",
              "-vbparams=mweb:-1:9223372036854775807"}}},
          m_pool{*m_node.mempool},
          m_address{PublicKey::From(SecretKey::Random()), PublicKey::From(m_spend_key)}
    {
        LOCK(::cs_main);
        m_view = CoinsTip().GetMWEBCacheView();
        SetMockTime(std::chrono::seconds{TEST_TIME});
        BOOST_REQUIRE(m_pool.m_opts.require_standard);
    }

    CCoinsViewCache& CoinsTip() EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        AssertLockHeld(::cs_main);
        return Assert(m_node.chainman)->ActiveChainstate().CoinsTip();
    }

    // Standard hybrid transactions carry their fee on the peg-in kernel itself.
    test::Tx Pegin(const CAmount amount = FUNDING_AMOUNT, const CAmount fee = MWEB_FEE) const
    {
        const test::TxOutput output = test::TxOutput::Create(m_sender_key, m_address, amount - fee);
        const BlindingFactor kernel_blind = BlindingFactor::Random();
        const auto kernel = Kernel::Create(kernel_blind, std::nullopt, fee, amount, {}, std::nullopt, {});
        return test::Tx{mw::Transaction::Create(
            Blinds(output.GetBlind()).Sub(kernel_blind).Total(), m_sender_key,
            {}, {output.GetOutput()}, {kernel}), {output}};
    }

    SecretKey OutputKey(const test::TxOutput& output) const
    {
        return mw::DeriveOutputSpendKey(m_spend_key,
            mw::DeriveSharedSecret(m_sender_key, m_address, output.GetAmount()));
    }

    test::Tx Spend(const std::vector<test::TxOutput>& inputs, const CAmount fee = MWEB_FEE,
                   const std::vector<PegOutCoin>& pegouts = {}, const size_t num_outputs = 1) const
    {
        test::TxBuilder builder;
        CAmount change{-fee};
        for (const auto& input : inputs) {
            builder.AddInput(input.GetAmount(), OutputKey(input), input.GetBlind(), input.GetOutputID());
            change += input.GetAmount();
        }
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GT(change, 0);
        BOOST_REQUIRE_GT(num_outputs, 0U);
        const CAmount amount = change / num_outputs;
        for (size_t i = 0; i < num_outputs; ++i) {
            const CAmount output_amount = i + 1 == num_outputs ? change : amount;
            builder.AddOutput(output_amount, m_sender_key, m_address);
            change -= output_amount;
        }
        if (pegouts.empty()) {
            builder.AddPlainKernel(fee);
        } else {
            builder.AddPegoutKernel(pegouts, fee);
        }
        return builder.Build();
    }

    test::Tx Spend(const test::TxOutput& input, const CAmount fee = MWEB_FEE,
                   const std::vector<PegOutCoin>& pegouts = {}) const
    {
        return Spend(std::vector<test::TxOutput>{input}, fee, pegouts);
    }

    test::Tx FundMWEB()
    {
        LOCK(cs_main);
        const auto funding = Pegin(FUNDING_AMOUNT, 0);
        const auto block = mw::CoinsViewCache(m_view).BuildNextBlock(0, {funding.GetTransaction()});
        m_view->ApplyBlock(block);
        m_funded_amount += FUNDING_AMOUNT;
        return funding;
    }

    CTransactionRef FundPegin(const test::Tx& mweb_tx, const CAmount canonical_fee = CANONICAL_FEE,
                              const CAmount canonical_change = 0)
    {
        LOCK(cs_main);
        CMutableTransaction mutable_tx = WithMWEB(mweb_tx);
        if (canonical_change > 0) mutable_tx.vout.emplace_back(canonical_change, P2WSH_OP_TRUE);
        const auto tx = MakeTransactionRef(mutable_tx);
        BOOST_REQUIRE_EQUAL(tx->vin.size(), 1U);
        CoinsTip().AddCoin(tx->vin.front().prevout,
            Coin{CTxOut{tx->GetValueOut() + canonical_fee, P2WSH_OP_TRUE}, m_node.chainman->ActiveChain().Height(), false}, false);
        return tx;
    }

    MempoolAcceptResult Submit(const CTransactionRef& tx, const bool test_accept = false)
    {
        LOCK(cs_main);
        m_seen.push_back(tx);
        return m_node.chainman->ProcessTransaction(tx, test_accept);
    }

    void Accept(const CTransactionRef& tx, const CAmount fee = MWEB_FEE)
    {
        const auto result = Submit(tx);
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
        BOOST_REQUIRE(result.m_base_fees.has_value());
        BOOST_CHECK_EQUAL(*result.m_base_fees, fee);
        BOOST_REQUIRE(result.m_mweb_weight.has_value());
        BOOST_CHECK_EQUAL(*result.m_mweb_weight, tx->mweb_tx.GetMWEBWeight());
    }

    void Reject(const CTransactionRef& tx, const TxValidationResult error, const std::string& reason,
                const std::vector<CTransactionRef>& unchanged = {})
    {
        const auto result = Submit(tx);
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID, result.m_state.ToString());
        BOOST_CHECK(result.m_state.GetResult() == error);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), reason);
        CheckPool(unchanged);
    }

    // Check exact membership and both MWEB indexes, not just the transaction
    // count. The built-in consistency checker also validates cached graph totals.
    CTxMemPool& Pool() { return m_pool; }

    void CheckPool(const std::vector<CTransactionRef>& expected, const std::vector<CTransactionRef>& unused_absent = {})
    {
        LOCK2(::cs_main, Pool().cs);
        (void)unused_absent;
        std::vector<CTransactionRef> absent;
        for (const auto& tx : m_seen) if (std::find(expected.begin(), expected.end(), tx) == expected.end()) absent.push_back(tx);
        BOOST_REQUIRE_EQUAL(Pool().size(), expected.size());
        std::map<mw::Hash, Txid> creators, spenders;
        for (const auto& tx : expected) {
            BOOST_CHECK(Pool().exists(tx->GetWitnessHash()));
            BOOST_CHECK(Pool().get(tx->GetHash()) == tx);
            for (const auto& output_id : tx->mweb_tx.GetOutputIDs()) creators.emplace(output_id, tx->GetHash());
            for (const auto& spent_id : tx->mweb_tx.GetSpentIDs()) spenders.emplace(spent_id, tx->GetHash());
        }
        for (const auto& tx : absent) {
            // Different uncommitted bodies can share a first-kernel identity.
            // The expected body above must win; every absent body's output and
            // spend index is still checked below.
            if (std::none_of(expected.begin(), expected.end(), [&](const auto& present) {
                    return present->GetWitnessHash() == tx->GetWitnessHash();
                })) BOOST_CHECK(!Pool().exists(tx->GetWitnessHash()));
            for (const auto& output_id : tx->mweb_tx.GetOutputIDs()) creators.try_emplace(output_id);
            for (const auto& spent_id : tx->mweb_tx.GetSpentIDs()) spenders.try_emplace(spent_id);
        }
        for (const auto& [output_id, txid] : creators) {
            const CTransaction* creator{Pool().GetMWEBOutputTx(output_id)};
            BOOST_CHECK(txid.IsNull() ? creator == nullptr : creator && creator->GetHash() == txid);
        }
        for (const auto& [spent_id, txid] : spenders) {
            const CTransaction* spender{Pool().GetMWEBConflictTx(spent_id)};
            BOOST_CHECK(txid.IsNull() ? spender == nullptr : spender && spender->GetHash() == txid);
        }
        Pool().check(Assert(m_node.chainman)->ActiveChainstate().CoinsTip(),
                     Assert(m_node.chainman)->ActiveChain().Height() + 1, Params().GetConsensus());
    }

    //! Ancestor and descendant sets (each including tx) by count, MWEB weight and modified fees.
    void CheckGraph(const CTransactionRef& tx, const std::vector<CTransactionRef>& ancestors,
                    const std::vector<CTransactionRef>& descendants)
    {
        LOCK(Pool().cs);
        const CTxMemPoolEntry* entry{Pool().GetEntry(tx->GetHash())};
        BOOST_REQUIRE(entry);
        uint64_t ancestor_weight{0}, descendant_weight{0};
        CAmount ancestor_fees{0}, descendant_fees{0};
        for (const auto& ancestor : ancestors) {
            ancestor_weight += ancestor->mweb_tx.GetMWEBWeight();
            ancestor_fees += Assert(Pool().GetEntry(ancestor->GetHash()))->GetModifiedFee();
        }
        for (const auto& descendant : descendants) {
            descendant_weight += descendant->mweb_tx.GetMWEBWeight();
            descendant_fees += Assert(Pool().GetEntry(descendant->GetHash()))->GetModifiedFee();
        }
        const auto ancestor_data = Pool().CalculateAncestorData(*entry);
        const auto descendant_data = Pool().CalculateDescendantData(*entry);
        BOOST_CHECK_EQUAL(std::get<0>(ancestor_data), ancestors.size());
        BOOST_CHECK_EQUAL(std::get<0>(descendant_data), descendants.size());
        BOOST_CHECK_EQUAL(Pool().CalculateAncestorMWEBWeight(*entry), ancestor_weight);
        BOOST_CHECK_EQUAL(Pool().CalculateDescendantMWEBWeight(*entry), descendant_weight);
        BOOST_CHECK_EQUAL(std::get<2>(ancestor_data), ancestor_fees);
        BOOST_CHECK_EQUAL(std::get<2>(descendant_data), descendant_fees);
    }

    void Remove(const CTransactionRef& tx, const MemPoolRemovalReason reason = MemPoolRemovalReason::EXPIRY)
    {
        LOCK(m_pool.cs);
        m_pool.removeRecursive(*tx, reason);
    }

    // Apply coins and deliver the block fields consumed by removeForBlock.
    // Header/PoW/HogEx validation belongs to the node and miner suites.
    void Confirm(const std::vector<CTransactionRef>& transactions)
    {
        LOCK2(cs_main, m_pool.cs);
        CBlock block;
        std::vector<mw::Transaction::CPtr> mweb_transactions;
        for (const auto& tx : transactions) {
            BOOST_REQUIRE(tx->HasMWEBTx());
            mweb_transactions.push_back(tx->mweb_tx.m_transaction);
            if (!tx->IsMWEBOnly()) {
                CMutableTransaction stripped{*tx};
                stripped.mweb_tx.SetNull();
                block.vtx.push_back(MakeTransactionRef(stripped));
            }
        }
        const int height = m_view->GetBestHeader() ? m_view->GetBestHeader()->GetHeight() + 1 : 1;
        block.mweb_block = MWEB::Block{mw::CoinsViewCache(m_view).BuildNextBlock(height, mweb_transactions)};
        m_view->ApplyBlock(block.mweb_block.m_block);
        for (const auto& tx : block.vtx) {
            for (const auto& input : tx->vin) BOOST_REQUIRE(CoinsTip().SpendCoin(input.prevout));
            AddCoins(CoinsTip(), *tx, height);
        }
        // Match Chainstate::ConnectTip's actual removal order.
        m_pool.removeMWEBConflictsForBlock(block.vtx, block.mweb_block);
        m_pool.removeForBlock(block.vtx);
        m_pool.removeForMWEBKernels(block.mweb_block.GetKernelIDs());
    }

    CTxMemPool& m_pool;
    mw::CoinsViewCache::Ptr m_view;
    SecretKey m_spend_key{SecretKey::Random()};
    SecretKey m_sender_key{SecretKey::Random()};
    StealthAddress m_address;
    CAmount m_funded_amount{0};
    std::vector<CTransactionRef> m_seen;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_mempool_lifecycle_tests, MWEBMempoolTestingSetup)

// A standard peg-in records both fee components and indexes its MWEB output without adding it to chainstate.
BOOST_AUTO_TEST_CASE(admit_pegin_with_canonical_and_mweb_fees)
{
    const auto pegin = FundPegin(Pegin());
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    CheckPool({pegin});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), CANONICAL_FEE + MWEB_FEE);
    const auto output_id = *pegin->mweb_tx.GetOutputIDs().begin();
    const CTransaction* creator = m_pool.GetMWEBOutputTx(output_id);
    BOOST_REQUIRE(creator);
    BOOST_CHECK(creator->GetHash() == pegin->GetHash());
    BOOST_CHECK(!m_view->HasCoin(output_id));
}

// A pure MWEB transfer needs no canonical inputs or outputs and reserves its confirmed input in the mempool.
BOOST_AUTO_TEST_CASE(admit_transfer_of_confirmed_output)
{
    const auto funding = FundMWEB();
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE(transfer->IsMWEBOnly());
    Accept(transfer);
    CheckPool({transfer});
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
}

// A peg-out is admitted as MWEB data; its destination is not yet a spendable canonical mempool output.
BOOST_AUTO_TEST_CASE(admit_pegout_with_mweb_change)
{
    const auto funding = FundMWEB();
    const auto pegout = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
        {{3 * COIN, P2WSH_OP_TRUE}})));
    Accept(pegout);
    CheckPool({pegout});
    BOOST_CHECK(pegout->vout.empty());
    LOCK2(::cs_main, m_pool.cs);
    MWEBMempoolView view{&CoinsTip(), m_pool};
    BOOST_CHECK(!view.GetCoin(COutPoint{pegout->GetHash(), 0}));
}

// Test-only admission validates the transaction and reports its fees, but reserves no inputs and creates no indexes.
BOOST_AUTO_TEST_CASE(test_accept_does_not_change_mempool_or_chainstate)
{
    const auto funding = FundMWEB();
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    const auto header = m_view->GetBestHeader();
    const auto leafset = m_view->GetLeafSet()->Root();
    const auto result = Submit(transfer, /*test_accept=*/true);
    BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
    BOOST_REQUIRE(result.m_base_fees.has_value());
    BOOST_CHECK_EQUAL(*result.m_base_fees, MWEB_FEE);
    CheckPool({});
    BOOST_CHECK(m_view->GetBestHeader() == header);
    BOOST_CHECK(m_view->GetLeafSet()->Root() == leafset);
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
    Accept(transfer);
    CheckPool({transfer});
}

// A duplicate submission is rejected without duplicating the transaction, fee total, or MWEB indexes.
BOOST_AUTO_TEST_CASE(duplicate_submission_preserves_existing_entry)
{
    const auto pegin = FundPegin(Pegin());
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    Reject(pegin, TxValidationResult::TX_CONFLICT, "txn-already-in-mempool", {pegin});
}

// A mismatched canonical peg-in amount is rejected without reserving its input, allowing the correct transaction later.
BOOST_AUTO_TEST_CASE(pegin_mismatch_does_not_poison_retry)
{
    const auto pegin = FundPegin(Pegin());
    CMutableTransaction invalid{*pegin};
    --invalid.vout.front().nValue;
    Reject(MakeTransactionRef(invalid), TxValidationResult::TX_WITNESS_MUTATED, "pegin-mismatch");
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    CheckPool({pegin});
}

// A signed input using the wrong receiver key fails the UTXO metadata check, not signature validation.
BOOST_AUTO_TEST_CASE(input_receiver_key_must_match_confirmed_coin)
{
    const auto funding = FundMWEB();
    const auto& output = funding.GetOutputs().front();
    const auto wrong_key = test::TxBuilder()
        .AddInput(output.GetAmount(), SecretKey::Random(), output.GetBlind(), output.GetOutputID())
        .AddOutput(output.GetAmount() - MWEB_FEE).AddPlainKernel(MWEB_FEE).Build();
    BOOST_REQUIRE(!wrong_key.GetTransaction()->GetValidationError());
    Reject(MakeTransactionRef(WithMWEB(wrong_key)), TxValidationResult::TX_CONSENSUS, "bad-txns-input-mismatch");
    const auto valid = MakeTransactionRef(WithMWEB(Spend(output)));
    Accept(valid);
    CheckPool({valid});
}

// A signed input committing to the wrong amount is rejected even if it names a real output and uses its receiver key.
BOOST_AUTO_TEST_CASE(input_commitment_must_match_confirmed_coin)
{
    const auto funding = FundMWEB();
    const auto& output = funding.GetOutputs().front();
    const auto wrong_amount = test::TxBuilder()
        .AddInput(output.GetAmount() + 1, OutputKey(output), output.GetBlind(), output.GetOutputID())
        .AddOutput(output.GetAmount() + 1 - MWEB_FEE).AddPlainKernel(MWEB_FEE).Build();
    BOOST_REQUIRE(!wrong_amount.GetTransaction()->GetValidationError());
    Reject(MakeTransactionRef(WithMWEB(wrong_amount)), TxValidationResult::TX_CONSENSUS, "bad-txns-input-mismatch");
    const auto valid = MakeTransactionRef(WithMWEB(Spend(output)));
    Accept(valid);
    CheckPool({valid});
}

// The minimum relay fee includes MWEB weight even for a transaction with zero canonical virtual size.
BOOST_AUTO_TEST_CASE(mweb_relay_fee_boundary)
{
    const auto funding = FundMWEB();
    const auto probe = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*probe), 0);
    const CAmount minimum_fee = m_pool.m_opts.min_relay_feerate.GetTotalFee(0, probe->mweb_tx.GetMWEBWeight());
    const auto below = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), minimum_fee - 1)));
    Reject(below, TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met");
    const auto at_limit = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), minimum_fee)));
    Accept(at_limit, minimum_fee);
    CheckPool({at_limit});
}

// Consensus-valid extra kernel data remains nonstandard relay policy and must not leave mempool state behind.
BOOST_AUTO_TEST_CASE(nonstandard_kernel_features_are_rejected)
{
    const auto funding = FundMWEB();
    const auto extra_data = WithExtraKernel(Spend(funding.GetOutputs().front()), std::nullopt, {1});
    BOOST_REQUIRE(!extra_data.GetTransaction()->GetValidationError());
    Reject(MakeTransactionRef(WithMWEB(extra_data)), TxValidationResult::TX_NOT_STANDARD, "non-standard-mweb-tx");
}

// A hybrid cannot carry unrelated aggregated kernels even when its signatures and peg-in amounts are valid.
BOOST_AUTO_TEST_CASE(hybrid_aggregation_is_not_standard)
{
    const auto aggregated = WithExtraKernel(Pegin());
    BOOST_REQUIRE(!aggregated.GetTransaction()->GetValidationError());
    const auto pegin = FundPegin(aggregated);
    Reject(pegin, TxValidationResult::TX_NOT_STANDARD, "kernel-mismatch");
}

// An invalid output signature must not reserve the input or prevent resubmission of the original valid transfer.
BOOST_AUTO_TEST_CASE(invalid_signature_does_not_poison_retry)
{
    const auto funding = FundMWEB();
    const auto valid = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    CMutableTransaction invalid{*valid};
    invalid.mweb_tx.outputs.front().signature = Signature{};
    Reject(MakeTransactionRef(invalid), TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn");
    Accept(valid);
    CheckPool({valid});
}

// A diamond-shaped MWEB graph counts its shared ancestor once and retains the other branch after recursive removal.
BOOST_AUTO_TEST_CASE(diamond_graph_tracks_shared_ancestors_and_branch_removal)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend({funding.GetOutputs().front()}, MWEB_FEE, {}, 2);
    const auto left_mweb = Spend(parent_mweb.GetOutputs()[0]);
    const auto right_mweb = Spend(parent_mweb.GetOutputs()[1]);
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto left = MakeTransactionRef(WithMWEB(left_mweb));
    const auto right = MakeTransactionRef(WithMWEB(right_mweb));
    const auto join = MakeTransactionRef(WithMWEB(Spend({left_mweb.GetOutputs()[0], right_mweb.GetOutputs()[0]})));
    Accept(parent);
    Accept(left);
    Accept(right);
    Accept(join);
    CheckPool({parent, left, right, join});
    CheckGraph(parent, {parent}, {parent, left, right, join});
    CheckGraph(left, {parent, left}, {left, join});
    CheckGraph(right, {parent, right}, {right, join});
    CheckGraph(join, {parent, left, right, join}, {join});

    Remove(left);
    CheckPool({parent, right});
    CheckGraph(parent, {parent}, {parent, right});
    CheckGraph(right, {parent, right}, {right});
}

// A hybrid parent can have both canonical and MWEB children; removing it recursively clears both kinds of dependency.
BOOST_AUTO_TEST_CASE(hybrid_parent_tracks_both_canonical_and_mweb_children)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb, CANONICAL_FEE, COIN);
    const auto canonical_child = CanonicalSpend(COutPoint{parent->GetHash(), 1}, COIN - CANONICAL_FEE);
    const auto mweb_child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto independent = FundPegin(Pegin(2 * COIN));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(canonical_child, CANONICAL_FEE);
    Accept(mweb_child);
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    CheckPool({parent, canonical_child, mweb_child, independent});
    CheckGraph(parent, {parent}, {parent, canonical_child, mweb_child});
    CheckGraph(canonical_child, {parent, canonical_child}, {canonical_child});
    CheckGraph(mweb_child, {parent, mweb_child}, {mweb_child});

    Remove(parent);
    CheckPool({independent});
    CheckGraph(independent, {independent}, {independent});
}

// Prioritising an MWEB parent updates descendant ancestor-fees without changing the fees actually paid by the pool.
BOOST_AUTO_TEST_CASE(prioritisation_updates_mweb_ancestor_fees)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    m_pool.PrioritiseTransaction(parent->GetHash(), 50'000);
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), CANONICAL_FEE + 2 * MWEB_FEE);
    BOOST_CHECK_EQUAL(std::get<2>(m_pool.CalculateAncestorData(*m_pool.GetEntry(child->GetHash()))),
                      CANONICAL_FEE + 2 * MWEB_FEE + 50'000);
}

// The coins overlay hides spent MWEB outputs, exposes unspent outputs with their metadata, and reveals them after removal.
BOOST_AUTO_TEST_CASE(coins_overlay_tracks_mweb_spends_and_removal)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent);
    LOCK2(::cs_main, m_pool.cs);
    MWEBMempoolView view{&CoinsTip(), m_pool};
    Output coin;
    const auto& parent_output = parent_mweb.GetOutputs().front();
    BOOST_CHECK(!view.GetMWEBCoin(funding.GetOutputs().front().GetOutputID(), coin));
    BOOST_REQUIRE(view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    BOOST_CHECK(coin.GetCommitment() == parent_output.GetCommitment());
    BOOST_CHECK(coin.GetReceiverPubKey() == parent_output.GetOutput().GetReceiverPubKey());

    Accept(child);
    BOOST_CHECK(!view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    BOOST_CHECK(!view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    Remove(child);
    BOOST_CHECK(view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    BOOST_CHECK(view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    CheckPool({parent});
}

// Expiring an old MWEB parent also removes its newer child, while an unrelated recent transaction remains.
BOOST_AUTO_TEST_CASE(expiration_removes_mweb_descendants)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    SetMockTime(std::chrono::seconds{TEST_TIME + 60});
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto independent = FundPegin(Pegin(2 * COIN));
    Accept(child);
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    LOCK2(cs_main, m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.Expire(std::chrono::seconds{TEST_TIME + 1}), 2);
    CheckPool({independent});
    for (const auto& id : parent->mweb_tx.GetKernelIDs()) BOOST_CHECK(!m_pool.HasCachedMWEBTxByKernel(id));
}

// Removing a parent no longer in the pool still finds and recursively removes its MWEB children.
BOOST_AUTO_TEST_CASE(remove_absent_parent_finds_mweb_descendants)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    Confirm({parent});
    const auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    const auto grandchild = MakeTransactionRef(WithMWEB(Spend(child_mweb.GetOutputs().front())));
    Accept(child);
    Accept(grandchild);
    Remove(parent, MemPoolRemovalReason::REORG);
    CheckPool({});
}

// A standard transaction at the relay weight limit is accepted; adding another valid kernel makes it too large.
BOOST_AUTO_TEST_CASE(standard_mweb_weight_limit_is_inclusive)
{
    const auto funding = FundMWEB();
    const size_t weight_limit = mw::MAX_BLOCK_WEIGHT / 50;
    const size_t num_outputs = (weight_limit - 2 * mw::BASE_KERNEL_WEIGHT) / mw::STANDARD_OUTPUT_WEIGHT;
    const auto at_limit_mweb = WithExtraKernel(Spend({funding.GetOutputs().front()}, COIN, {}, num_outputs));
    BOOST_REQUIRE_EQUAL(at_limit_mweb.GetTransaction()->CalcWeight(), weight_limit);
    const auto oversized = WithExtraKernel(at_limit_mweb);
    BOOST_REQUIRE(!oversized.GetTransaction()->GetValidationError());
    Reject(MakeTransactionRef(WithMWEB(oversized)), TxValidationResult::TX_NOT_STANDARD, "mweb-txn-oversize");
    const auto at_limit = MakeTransactionRef(WithMWEB(at_limit_mweb));
    Accept(at_limit, COIN);
    CheckPool({at_limit});
}

// At the input-count limit an otherwise valid transaction reaches coin lookup; one extra input is rejected by relay policy first.
BOOST_AUTO_TEST_CASE(standard_mweb_input_count_boundary)
{
    const size_t input_limit = mw::MAX_NUM_INPUTS / 50;
    const auto unfunded_spend = [](const size_t num_inputs) {
        test::TxBuilder builder;
        for (size_t i = 0; i < num_inputs; ++i) builder.AddInput(COIN);
        return builder.AddOutput((num_inputs - 1) * COIN).AddPlainKernel(COIN).Build();
    };
    const auto at_limit = unfunded_spend(input_limit);
    BOOST_REQUIRE(!at_limit.GetTransaction()->GetValidationError());
    Reject(MakeTransactionRef(WithMWEB(at_limit)), TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto oversized = unfunded_spend(input_limit + 1);
    Reject(MakeTransactionRef(WithMWEB(oversized)), TxValidationResult::TX_NOT_STANDARD, "mweb-txn-too-many-inputs");
}

BOOST_AUTO_TEST_SUITE_END()
