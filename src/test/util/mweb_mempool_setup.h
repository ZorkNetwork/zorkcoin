// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MWEB_MEMPOOL_SETUP_H
#define BITCOIN_TEST_UTIL_MWEB_MEMPOOL_SETUP_H

#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <key.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <sync.h>
#include <test/util/mweb_setup.h>
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

inline constexpr CAmount MWEB_FEE{10'000};
inline constexpr CAmount L1_FEE{20'000};
inline constexpr CAmount FUNDING_AMOUNT{10 * COIN};

/**
 * Real MWEB chain: MWEB activates on a mined regtest chain and the funding
 * MWEB outputs are confirmed in a mined block, so admission runs with
 * standardness, fees, MWEB crypto and mempool consistency checks enabled.
 */
struct MWEBPackageSetup : public MWEBRegtest100Setup {
    //! Confirmed MWEB outputs the tests can spend.
    std::vector<test::TxOutput> m_mweb_coins;
    size_t m_next_coinbase{0};

    MWEBPackageSetup()
    {
        MineToMWEBActivation();
        m_mweb_coins = FundMWEB(3);
    }

    CTxMemPool& Pool() { return *Assert(m_node.mempool); }

    CScript ChangeScript() const { return GetScriptForRawPubKey(coinbaseKey.GetPubKey()); }

    CTransactionRef NextCoinbase() { return m_coinbase_txns.at(m_next_coinbase++); }

    //! Signs every L1 input with coinbaseKey. prevs must create all spent outputs.
    void Sign(CMutableTransaction& mtx, const std::vector<CTransactionRef>& prevs) const
    {
        FillableSigningProvider keystore;
        keystore.AddKey(coinbaseKey);
        std::map<COutPoint, Coin> coins;
        for (const auto& prev : prevs) {
            for (uint32_t n{0}; n < prev->vout.size(); ++n) {
                coins.emplace(COutPoint{prev->GetHash(), n}, Coin{prev->vout[n], 1, false});
            }
        }
        std::map<int, bilingual_str> errors;
        BOOST_REQUIRE(SignTransaction(mtx, &keystore, coins, {.sighash_type = SIGHASH_ALL}, errors));
    }

    //! L1 transaction spending a fresh mature coinbase that pegs `pegin` into `mweb`
    //! and pays `l1_fee`, returning the rest as change at vout 1.
    CTransactionRef MakeHybrid(const test::Tx& mweb, CAmount pegin, CAmount l1_fee,
                               decltype(CTransaction::version) version = CTransaction::CURRENT_VERSION)
    {
        const CTransactionRef coinbase = NextCoinbase();
        CMutableTransaction mtx;
        mtx.version = version;
        mtx.vin.emplace_back(COutPoint{coinbase->GetHash(), 0});
        mtx.vout.emplace_back(pegin, GetScriptForPegin(mweb.GetPegInCoin().GetKernelID()));
        mtx.vout.emplace_back(coinbase->vout[0].nValue - pegin - l1_fee, ChangeScript());
        mtx.mweb_tx = mw::MutableTx::From(*mweb.GetTransaction());
        Sign(mtx, {coinbase});
        return MakeTransactionRef(mtx);
    }

    //! Zero-fee peg-in body, so the L1 transaction carries the whole fee.
    static test::Tx Pegin(CAmount amount = FUNDING_AMOUNT) { return test::Tx::CreatePegIn(amount); }

    static CTransactionRef MakeMWEBOnly(const test::Tx& mweb, decltype(CTransaction::version) version = CTransaction::CURRENT_VERSION)
    {
        CMutableTransaction mtx;
        mtx.version = version;
        mtx.mweb_tx = mw::MutableTx::From(*mweb.GetTransaction());
        return MakeTransactionRef(mtx);
    }

    //! MWEB body spending inputs into num_outputs outputs with a plain fee kernel.
    static test::Tx Spend(const std::vector<test::TxOutput>& inputs, CAmount fee = MWEB_FEE, size_t num_outputs = 1)
    {
        test::TxBuilder builder;
        CAmount change{-fee};
        for (const auto& input : inputs) {
            builder.AddInput(input);
            change += input.GetAmount();
        }
        BOOST_REQUIRE_GT(change, 0);
        const CAmount amount{change / static_cast<CAmount>(num_outputs)};
        for (size_t i{0}; i < num_outputs; ++i) {
            const CAmount output_amount{i + 1 == num_outputs ? change : amount};
            builder.AddOutput(output_amount);
            change -= output_amount;
        }
        builder.AddPlainKernel(fee);
        return builder.Build();
    }

    static test::Tx Spend(const test::TxOutput& input, CAmount fee = MWEB_FEE)
    {
        return Spend(std::vector<test::TxOutput>{input}, fee);
    }

    //! Pegs in `count` MWEB outputs and mines them.
    std::vector<test::TxOutput> FundMWEB(size_t count)
    {
        std::vector<test::TxOutput> outputs;
        std::vector<CTransactionRef> txs;
        for (size_t i{0}; i < count; ++i) {
            const test::Tx mweb{Pegin()};
            txs.push_back(MakeHybrid(mweb, FUNDING_AMOUNT, L1_FEE));
            Accept(txs.back(), L1_FEE);
            outputs.push_back(mweb.GetOutputs().front());
        }
        MineMWEBEraBlock();
        for (const auto& tx : txs) BOOST_REQUIRE(!Pool().exists(tx->GetHash()));
        return outputs;
    }

    //! L1 child spending vout 1 of each parent.
    CTransactionRef MakeL1Child(const std::vector<CTransactionRef>& parents, CAmount fee,
                                decltype(CTransaction::version) version = CTransaction::CURRENT_VERSION)
    {
        CMutableTransaction mtx;
        mtx.version = version;
        CAmount in_value{0};
        for (const auto& parent : parents) {
            mtx.vin.emplace_back(COutPoint{parent->GetHash(), 1});
            in_value += parent->vout[1].nValue;
        }
        mtx.vout.emplace_back(in_value - fee, ChangeScript());
        Sign(mtx, parents);
        return MakeTransactionRef(mtx);
    }

    MempoolAcceptResult Submit(const CTransactionRef& tx, bool test_accept = false)
    {
        LOCK(::cs_main);
        return Assert(m_node.chainman)->ProcessTransaction(tx, test_accept);
    }

    void Accept(const CTransactionRef& tx, CAmount fee)
    {
        const MempoolAcceptResult result{Submit(tx)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
        BOOST_CHECK_EQUAL(result.m_base_fees.value(), fee);
        BOOST_CHECK_EQUAL(result.m_mweb_weight.value(), tx->mweb_tx.GetMWEBWeight());
    }

    void Reject(const CTransactionRef& tx, TxValidationResult error, const std::string& reason)
    {
        const MempoolAcceptResult result{Submit(tx)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID, result.m_state.ToString());
        BOOST_CHECK(result.m_state.GetResult() == error);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), reason);
    }

    PackageMempoolAcceptResult SubmitPackage(const Package& package, bool test_accept = false)
    {
        LOCK(::cs_main);
        return ProcessNewPackage(Assert(m_node.chainman)->ActiveChainstate(), Pool(), package,
                                 test_accept, /*client_maxfeerate=*/{});
    }

    //! Exact membership, both MWEB mempool indexes, and the mempool consistency check.
    //! The MWEB indexes must also hold nothing for the `absent` transactions' outputs and spends.
    void CheckPool(const std::vector<CTransactionRef>& expected, const std::vector<CTransactionRef>& absent = {})
    {
        LOCK2(::cs_main, Pool().cs);
        BOOST_REQUIRE_EQUAL(Pool().size(), expected.size());
        std::map<mw::Hash, Txid> creators, spenders;
        for (const auto& tx : expected) {
            BOOST_CHECK(Pool().exists(tx->GetWitnessHash()));
            for (const auto& output_id : tx->mweb_tx.GetOutputIDs()) creators.emplace(output_id, tx->GetHash());
            for (const auto& spent_id : tx->mweb_tx.GetSpentIDs()) spenders.emplace(spent_id, tx->GetHash());
        }
        for (const auto& tx : absent) {
            BOOST_CHECK(!Pool().exists(tx->GetWitnessHash()));
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

    bool HaveConfirmedMWEBCoin(const mw::Hash& output_id)
    {
        LOCK(::cs_main);
        Output coin;
        return Assert(m_node.chainman)->ActiveChainstate().CoinsTip().GetMWEBCoin(output_id, coin);
    }

    //! Every kernel of tx is in the mempool's recent-by-kernel cache (reorg replay).
    void CheckCached(const CTransactionRef& tx)
    {
        LOCK(Pool().cs);
        for (const mw::Hash& kernel_id : tx->mweb_tx.GetKernelIDs()) {
            BOOST_CHECK(Pool().HasCachedMWEBTxByKernel(kernel_id));
        }
    }

    void InvalidateBlock(CBlockIndex* block)
    {
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(state, block), state.ToString());
    }

    CBlockIndex* Tip() { return WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip()); }

    void InvalidateTip() { InvalidateBlock(Tip()); }
};

#endif // BITCOIN_TEST_UTIL_MWEB_MEMPOOL_SETUP_H
