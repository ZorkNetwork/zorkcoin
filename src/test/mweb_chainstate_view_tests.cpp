// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <node/warnings.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <mw/crypto/blinds.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/key_derivation.h>
#include <mw/db/mmr_info_db.h>
#include <mw/file/file.h>
#include <mw/mmr/leaf_set.h>
#include <mweb/mweb_coins_lifecycle.h>
#include <primitives/transaction.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/mining.h>
#include <test_framework/tx_builder.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/time.h>
#include <util/signalinterrupt.h>
#include <validation.h>
#include <validationinterface.h>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>

namespace {
constexpr CAmount DEPOSIT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr size_t DB_CACHE_BYTES{1 << 20};
struct Transactions
{
    SecretKey spend_key{SecretKey::Random()};
    SecretKey sender_key{SecretKey::Random()};
    StealthAddress address{PublicKey::From(SecretKey::Random()), PublicKey::From(spend_key)};

    test::Tx Pegin(const CAmount amount = DEPOSIT) const
    {
        const auto output = test::TxOutput::Create(sender_key, address, amount - MWEB_FEE);
        const auto blind = BlindingFactor::Random();
        const auto kernel = Kernel::Create(blind, std::nullopt, MWEB_FEE, amount, {}, std::nullopt, {});
        return test::Tx{mw::Transaction::Create(Blinds(output.GetBlind()).Sub(blind).Total(), sender_key,
            {}, {output.GetOutput()}, {kernel}), {output}};
    }

    test::Tx Spend(const test::TxOutput& output, const std::vector<PegOutCoin>& pegouts = {}) const
    {
        const auto key = mw::DeriveOutputSpendKey(spend_key, mw::DeriveSharedSecret(sender_key, address, output.GetAmount()));
        test::TxBuilder builder;
        builder.AddInput(output.GetAmount(), key, output.GetBlind(), output.GetOutputID());
        CAmount change = output.GetAmount() - MWEB_FEE;
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GE(change, 0);
        if (change > 0) builder.AddOutput(change, sender_key, address);
        if (pegouts.empty()) builder.AddPlainKernel(MWEB_FEE);
        else builder.AddPegoutKernel(pegouts, MWEB_FEE);
        return builder.Build();
    }
};

void CheckCoin(const CCoinsView& view, const test::TxOutput& output, const int height)
{
    Output decoded;
    BOOST_REQUIRE(view.GetMWEBCoin(output.GetOutputID(), decoded));
    BOOST_CHECK(decoded.Serialized() == output.GetOutput().Serialized());
    BOOST_REQUIRE(view.GetMWEBView());
    const auto coin = view.GetMWEBView()->GetUTXO(output.GetOutputID());
    BOOST_REQUIRE(coin);
    BOOST_CHECK_EQUAL(coin->GetBlockHeight(), height);
    BOOST_CHECK(coin->GetOutput().Serialized() == output.GetOutput().Serialized());
    BOOST_CHECK(view.GetMWEBView()->GetLeafSet()->Contains(coin->GetLeafIndex()));
}
void CheckMissing(const CCoinsView& view, const test::TxOutput& output)
{
    Output decoded;
    BOOST_CHECK(!view.GetMWEBCoin(output.GetOutputID(), decoded));
    if (auto mweb = view.GetMWEBView()) BOOST_CHECK(!mweb->HasCoin(output.GetOutputID()));
}

void CheckRoots(const CCoinsView& view, const mw::Header::CPtr& header)
{
    const auto mweb = view.GetMWEBView();
    BOOST_REQUIRE(mweb);
    if (header) {
        BOOST_REQUIRE(mweb->GetBestHeader());
        BOOST_CHECK(*mweb->GetBestHeader() == *header);
        BOOST_CHECK(mweb->GetOutputPMMR()->Root() == header->GetOutputRoot());
        BOOST_CHECK_EQUAL(mweb->GetOutputPMMR()->GetNumLeaves(), header->GetNumTXOs());
        BOOST_CHECK(mweb->GetLeafSet()->Root() == header->GetLeafsetRoot());
    } else {
        BOOST_CHECK(!mweb->GetBestHeader());
        BOOST_CHECK_EQUAL(mweb->GetOutputPMMR()->GetNumLeaves(), 0U);
        BOOST_CHECK(mweb->GetLeafSet()->Root() == Hashed(std::vector<uint8_t>{}));
    }
}

struct AppliedBlock
{
    mw::Block::CPtr block;
    mw::BlockUndo::CPtr undo;
    uint256 Hash() const { return uint256{block->GetHash().vec()}; }
};

AppliedBlock Apply(CCoinsViewCache& view, const std::vector<test::Tx>& transactions)
{
    const auto mweb = view.GetMWEBCacheView();
    const int height = mweb->GetBestHeader() ? mweb->GetBestHeader()->GetHeight() + 1 : 100;
    std::vector<mw::Transaction::CPtr> txs;
    for (const auto& tx : transactions) txs.push_back(tx.GetTransaction());
    const auto block = mw::CoinsViewCache(mweb).BuildNextBlock(height, txs);
    const auto undo = mweb->ApplyBlock(block);
    view.SetBestBlock(uint256{block->GetHash().vec()});
    return {block, undo};
}

class MWEBViewTestingSetup : public BasicTestingSetup
{
public:
    MWEBViewTestingSetup() : BasicTestingSetup{ChainType::REGTEST} { Reopen(nullptr); }
    void Reopen(const mw::Header::CPtr& header)
    {
        m_cache.reset();
        m_db.reset();
        m_db = std::make_unique<CCoinsViewDB>(DBParams{
            .path = m_path_root / "coins", .cache_bytes = DB_CACHE_BYTES}, CoinsViewOptions{});
        MWEB::CoinsLifecycle::AttachView(*m_db, FilePath{m_path_root / "mweb"}, header);
        m_cache = std::make_unique<CCoinsViewCache>(m_db.get());
    }
    COutPoint AddCanonical(CCoinsViewCache& view, const bool pegout = false)
    {
        const COutPoint outpoint{Txid::FromUint256(m_rng.rand256()), 0};
        view.AddCoin(outpoint, Coin{CTxOut{COIN, P2WSH_OP_TRUE}, 100, false, pegout}, false);
        return outpoint;
    }
    Transactions m_txs;
    std::unique_ptr<CCoinsViewDB> m_db;
    std::unique_ptr<CCoinsViewCache> m_cache;
};

struct MinedBlock
{
    CBlockIndex* index;
    CBlock block;
};

// Use the real activation boundary and mature signed funding, rather than a
// synthetic genesis HogAddr. Keep the coin database on disk for reopen checks.
class MWEBChainstateTestingSetup : public TestChain100Setup
{
    static constexpr int64_t MWEB_START_TIME{1601450001LL * 1000};
    static constexpr int64_t MWEB_START_TIME_SEC{1601450001};
    static constexpr int FIRST_MWEB_HEIGHT{432};
    static constexpr CAmount CANONICAL_FEE{20'000};
    size_t m_funding_index{0};

public:
    MWEBChainstateTestingSetup()
        : TestChain100Setup(ChainType::REGTEST, {
              .extra_args = {"-vbparams=mweb:1601450001000:9999999999000"},
              .coins_db_in_memory = false})
    {
        SetMockTime(std::chrono::seconds{MWEB_START_TIME_SEC});
        while (WITH_LOCK(cs_main, return State().m_chain.Height()) < FIRST_MWEB_HEIGHT - 1) Mine();
    }

    Chainstate& State() { return Assert(m_node.chainman)->ActiveChainstate(); }

    CTransactionRef FundPegin(const test::Tx& deposit)
    {
        const auto& funding = m_coinbase_txns.at(m_funding_index++);
        const CScript change_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        auto tx = CreateValidTransaction({funding}, {COutPoint{funding->GetHash(), 0}}, 1, {coinbaseKey},
            {CTxOut{deposit.GetPegInCoin().GetAmount(), GetScriptForPegin(deposit.GetPegInCoin().GetKernelID())},
             CTxOut{funding->vout[0].nValue - deposit.GetPegInCoin().GetAmount() - CANONICAL_FEE, change_script}},
            std::nullopt, std::nullopt).first;
        tx.mweb_tx = mw::MutableTx::From(*deposit.GetTransaction());
        return MakeTransactionRef(std::move(tx));
    }

    void Submit(const CTransactionRef& tx)
    {
        LOCK2(cs_main, Assert(m_node.mempool)->cs);
        const auto result = Assert(m_node.chainman)->ProcessTransaction(tx);
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
    }

    MinedBlock Mine(const std::vector<CTransactionRef>& transactions = {})
    {
        for (const auto& tx : transactions) Submit(tx);
        auto block = PrepareBlock(m_node, {.coinbase_output_script = P2WSH_OP_TRUE});
        {
            LOCK(cs_main);
            block->nTime = std::max<int64_t>(State().m_chain.Tip()->GetMedianTimePast() + 1, MWEB_START_TIME);
        }
        block->hashMerkleRoot = BlockMerkleRoot(*block);
        node::RegenerateCommitments(*block, *Assert(m_node.chainman));
        while (!CheckProofOfWork(block->GetPoWHash(), block->nBits, Params().GetConsensus())) ++block->nNonce;
        BOOST_REQUIRE(!ProcessBlock(m_node, block).IsNull());
        LOCK(cs_main);
        CBlock stored;
        auto* index = State().m_chain.Tip();
        BOOST_REQUIRE(State().m_blockman.ReadBlock(stored, *index));
        BOOST_REQUIRE(stored.GetHash() == block->GetHash());
        return {index, std::move(stored)};
    }

    void CheckTip(const MinedBlock& mined) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        AssertLockHeld(cs_main);
        const auto& view = State().CoinsTip();
        BOOST_REQUIRE(State().m_chain.Tip() == mined.index);
        BOOST_CHECK(view.GetBestBlock() == mined.index->GetBlockHash());
        BOOST_CHECK(mined.index->nStatus & BLOCK_HAVE_MWEB);
        BOOST_REQUIRE(mined.index->mweb_header);
        BOOST_REQUIRE(mined.block.GetHogEx());
        BOOST_CHECK(*mined.index->mweb_header == *mined.block.mweb_block.GetMWEBHeader());
        BOOST_CHECK(mined.index->hogex_hash == mined.block.GetHogEx()->GetHash());
        BOOST_CHECK_EQUAL(mined.index->mweb_amount, mined.block.GetHogEx()->vout.front().nValue);
        CheckRoots(view, mined.index->mweb_header);
        const Coin& hogaddr = view.AccessCoin(COutPoint{mined.index->hogex_hash, 0});
        BOOST_REQUIRE(!hogaddr.IsSpent());
        BOOST_CHECK(!hogaddr.IsPegout());
        BOOST_CHECK(!hogaddr.IsCoinBase());
        BOOST_CHECK_EQUAL(hogaddr.nHeight, mined.index->nHeight);
        BOOST_CHECK(hogaddr.out == mined.block.GetHogEx()->vout.front());
    }

    void ReopenCoins() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        AssertLockHeld(cs_main);
        State().ForceFlushStateToDisk(/*wipe_cache=*/false);
        State().ResetCoinsViews();
        State().InitCoinsDB(DB_CACHE_BYTES, /*in_memory=*/false, /*should_wipe=*/false);
        State().InitCoinsCache(DB_CACHE_BYTES);
    }

    Transactions m_txs;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_chainstate_view_tests, MWEBViewTestingSetup)

BOOST_AUTO_TEST_CASE(canonical_only_view_handles_mweb_lookups)
{
    CCoinsView& base = CoinsViewEmpty::Get();
    CCoinsViewCache cache(&base);
    const auto tx = m_txs.Pegin();
    BOOST_CHECK(!cache.GetMWEBView());
    CheckMissing(cache, tx.GetOutputs().front());
}

BOOST_AUTO_TEST_CASE(unflushed_changes_are_visible_only_in_cache)
{
    const auto tx = m_txs.Pegin();
    const auto applied = Apply(*m_cache, {tx});
    const auto canonical = AddCanonical(*m_cache);
    CheckCoin(*m_cache, tx.GetOutputs().front(), 100);
    CheckMissing(*m_db, tx.GetOutputs().front());
    BOOST_CHECK(m_cache->HaveCoin(canonical));
    BOOST_CHECK(!m_db->HaveCoin(canonical));
    BOOST_CHECK(m_cache->GetBestBlock() == applied.Hash());
    BOOST_CHECK(m_db->GetBestBlock().IsNull());
    CheckRoots(*m_cache, applied.block->GetHeader());
}

BOOST_AUTO_TEST_CASE(nested_flush_updates_both_coin_views_and_tip)
{
    const auto tx = m_txs.Pegin();
    CCoinsViewCache child(m_cache.get());
    const auto applied = Apply(child, {tx});
    const auto canonical = AddCanonical(child);
    CheckMissing(*m_cache, tx.GetOutputs().front());
    child.Flush();
    CheckCoin(*m_cache, tx.GetOutputs().front(), 100);
    BOOST_CHECK(m_cache->HaveCoin(canonical));
    BOOST_CHECK(m_cache->GetBestBlock() == applied.Hash());
    CheckMissing(*m_db, tx.GetOutputs().front());
    BOOST_CHECK(!m_db->HaveCoin(canonical));
    CheckRoots(*m_cache, applied.block->GetHeader());
}

BOOST_AUTO_TEST_CASE(discarded_child_does_not_publish_spends)
{
    const auto parent = m_txs.Pegin();
    const auto first = Apply(*m_cache, {parent});
    const auto spend = m_txs.Spend(parent.GetOutputs().front());
    {
        CCoinsViewCache child(m_cache.get());
        Apply(child, {spend});
        CheckMissing(child, parent.GetOutputs().front());
        CheckCoin(child, spend.GetOutputs().front(), 101);
    }
    CheckCoin(*m_cache, parent.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    BOOST_CHECK(m_cache->GetBestBlock() == first.Hash());
    CheckRoots(*m_cache, first.block->GetHeader());
}

BOOST_AUTO_TEST_CASE(mweb_spend_tombstone_prevents_read_through)
{
    const auto tx = m_txs.Pegin();
    Apply(*m_cache, {tx});
    m_cache->Flush();
    const auto& output = tx.GetOutputs().front();
    CheckCoin(*m_db, output, 100);
    m_cache->GetMWEBCacheView()->AddTx(m_txs.Spend(output).GetTransaction());
    CCoinsViewCache child(m_cache.get());
    CheckMissing(*m_cache, output);
    CheckMissing(child, output);
    // MWEB has a separate cache API here; L1 Uncache takes only COutPoint.
    CheckMissing(child, output);
    CheckCoin(*m_db, output, 100);
}

BOOST_AUTO_TEST_CASE(backend_switch_replaces_mweb_overlay)
{
    const auto tx = m_txs.Pegin();
    Apply(*m_cache, {tx});
    CCoinsViewCache overlay(m_cache.get());
    CheckCoin(overlay, tx.GetOutputs().front(), 100);
    CCoinsView& canonical_only = CoinsViewEmpty::Get();
    overlay.SetBackend(canonical_only);
    BOOST_CHECK(!overlay.GetMWEBView());
    CheckMissing(overlay, tx.GetOutputs().front());
    overlay.SetBackend(*m_cache);
    CheckCoin(overlay, tx.GetOutputs().front(), 100);
}

BOOST_AUTO_TEST_CASE(add_coins_distinguishes_hogaddr_from_pegouts)
{
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    hogex.vout = {{5 * COIN, CScript() << OP_8 << std::vector<uint8_t>(32, 1)},
                 {COIN, P2WSH_OP_TRUE}, {2 * COIN, P2WSH_OP_TRUE}};
    const CTransaction tx{hogex};
    AddCoins(*m_cache, tx, 100);
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& coin = m_cache->AccessCoin(COutPoint{tx.GetHash(), static_cast<uint32_t>(i)});
        BOOST_REQUIRE(!coin.IsSpent());
        BOOST_CHECK_EQUAL(coin.IsPegout(), i > 0);
        BOOST_CHECK(!coin.IsCoinBase());
        BOOST_CHECK_EQUAL(coin.nHeight, 100U);
    }
}

BOOST_AUTO_TEST_CASE(in_block_spend_and_undo_restore_empty_view)
{
    const auto parent = m_txs.Pegin();
    const auto child = m_txs.Spend(parent.GetOutputs().front());
    const auto applied = Apply(*m_cache, {parent, child});
    CheckMissing(*m_cache, parent.GetOutputs().front());
    CheckCoin(*m_cache, child.GetOutputs().front(), 100);
    BOOST_REQUIRE_EQUAL(applied.undo->GetCoinsAdded().size(), 2U);
    BOOST_REQUIRE_EQUAL(applied.undo->GetCoinsSpent().size(), 1U);
    m_cache->GetMWEBCacheView()->UndoBlock(applied.undo);
    CheckMissing(*m_cache, parent.GetOutputs().front());
    CheckMissing(*m_cache, child.GetOutputs().front());
    CheckRoots(*m_cache, nullptr);
}

BOOST_AUTO_TEST_CASE(flush_and_reopen_preserve_paired_chainstate)
{
    const auto tx = m_txs.Pegin();
    const auto applied = Apply(*m_cache, {tx});
    const auto canonical = AddCanonical(*m_cache, /*pegout=*/true);
    m_cache->Flush();
    Reopen(applied.block->GetHeader());
    BOOST_CHECK(m_db->GetBestBlock() == applied.Hash());
    BOOST_CHECK(m_db->GetHeadBlocks().empty());
    CheckRoots(*m_db, applied.block->GetHeader());
    CheckCoin(*m_db, tx.GetOutputs().front(), 100);
    const auto recovered_coin = m_db->GetCoin(canonical);
    BOOST_REQUIRE(recovered_coin);
    const Coin& coin = *recovered_coin;
    BOOST_CHECK(coin.IsPegout());
    BOOST_CHECK_EQUAL(coin.nHeight, 100U);
    BOOST_CHECK_EQUAL(coin.out.nValue, COIN);
}

BOOST_AUTO_TEST_CASE(persisted_spend_survives_reopen)
{
    const auto deposit = m_txs.Pegin();
    Apply(*m_cache, {deposit});
    m_cache->Flush();
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto applied = Apply(*m_cache, {spend});
    const auto expected_coin = m_cache->GetMWEBView()->GetUTXO(spend.GetOutputs().front().GetOutputID());
    BOOST_REQUIRE(expected_coin);
    m_cache->Flush();
    Reopen(applied.block->GetHeader());
    CheckMissing(*m_cache, deposit.GetOutputs().front());
    CheckCoin(*m_cache, spend.GetOutputs().front(), 101);
    const auto recovered = m_db->GetMWEBView()->GetUTXO(spend.GetOutputs().front().GetOutputID());
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(recovered->GetLeafIndex() == expected_coin->GetLeafIndex());
    CheckRoots(*m_cache, applied.block->GetHeader());
}

BOOST_AUTO_TEST_CASE(persisted_undo_restores_original_coin_and_roots)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Apply(*m_cache, {deposit});
    const auto original = m_cache->GetMWEBView()->GetUTXO(deposit.GetOutputs().front().GetOutputID());
    m_cache->Flush();
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto second = Apply(*m_cache, {spend});
    m_cache->Flush();
    Reopen(second.block->GetHeader());
    m_cache->GetMWEBCacheView()->UndoBlock(second.undo);
    m_cache->SetBestBlock(first.Hash());
    m_cache->Flush();
    Reopen(first.block->GetHeader());
    CheckCoin(*m_cache, deposit.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    BOOST_CHECK(m_cache->GetMWEBView()->GetUTXO(deposit.GetOutputs().front().GetOutputID())->GetLeafIndex() == original->GetLeafIndex());
    BOOST_CHECK(m_db->GetBestBlock() == first.Hash());
    CheckRoots(*m_cache, first.block->GetHeader());
}

BOOST_AUTO_TEST_CASE(rewinding_first_mweb_block_persists_empty_state)
{
    const auto tx = m_txs.Pegin();
    const auto first = Apply(*m_cache, {tx});
    m_cache->Flush();
    m_cache->GetMWEBCacheView()->UndoBlock(first.undo);
    m_cache->SetBestBlock(uint256::ONE);
    m_cache->Flush();
    Reopen(nullptr);
    CheckMissing(*m_db, tx.GetOutputs().front());
    CheckRoots(*m_db, nullptr);
    BOOST_CHECK(m_db->GetBestBlock() == uint256::ONE);
    const auto replacement = m_txs.Pegin(2 * COIN);
    const auto next = Apply(*m_cache, {replacement});
    m_cache->Flush();
    Reopen(next.block->GetHeader());
    CheckCoin(*m_db, replacement.GetOutputs().front(), 100);
    CheckMissing(*m_db, tx.GetOutputs().front());
}

BOOST_AUTO_TEST_CASE(failed_mweb_apply_is_atomic)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Apply(*m_cache, {deposit});
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto valid = mw::CoinsViewCache(m_cache->GetMWEBView()).BuildNextBlock(101, {spend.GetTransaction()});
    const auto bad_header = mw::MutHeader{valid->GetHeader()}.SetOutputRoot(mw::Hash{}).Build();
    const auto invalid = std::make_shared<mw::Block>(bad_header, valid->GetTxBody());
    const size_t usage = m_cache->DynamicMemoryUsage();
    BOOST_CHECK_EXCEPTION(m_cache->GetMWEBCacheView()->ApplyBlock(invalid), ValidationException,
        [](const auto& error) { return error.GetType() == EConsensusError::MMR_MISMATCH; });
    BOOST_CHECK_EQUAL(m_cache->DynamicMemoryUsage(), usage);
    CheckCoin(*m_cache, deposit.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    CheckRoots(*m_cache, first.block->GetHeader());
    m_cache->GetMWEBCacheView()->ApplyBlock(valid);
    CheckMissing(*m_cache, deposit.GetOutputs().front());
    CheckCoin(*m_cache, spend.GetOutputs().front(), 101);
    CheckRoots(*m_cache, valid->GetHeader());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_chainstate_connection_tests, MWEBChainstateTestingSetup)

BOOST_AUTO_TEST_CASE(first_pegin_and_empty_successor_update_paired_metadata)
{
    const auto deposit = m_txs.Pegin();
    const auto tx = FundPegin(deposit);
    const auto first = Mine({tx});
    {
        LOCK(cs_main);
        CheckTip(first);
        BOOST_CHECK_EQUAL(first.index->mweb_amount, DEPOSIT - MWEB_FEE);
        CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), first.index->nHeight);
        BOOST_CHECK(!State().CoinsTip().HaveCoin(tx->vin.front().prevout));
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{tx->GetHash(), 0}));
        BOOST_REQUIRE_EQUAL(first.block.vtx.size(), 3U);
        BOOST_CHECK(first.block.vtx[1]->GetHash() == tx->GetHash());
        BOOST_CHECK(!first.block.vtx[1]->HasMWEBTx());
        const auto& change = State().CoinsTip().AccessCoin(COutPoint{tx->GetHash(), 1});
        BOOST_REQUIRE(!change.IsSpent());
        BOOST_CHECK(change.out == tx->vout[1]);
        BOOST_CHECK(!change.IsCoinBase());
        BOOST_CHECK(!change.IsPegout());
        BOOST_CHECK_EQUAL(change.nHeight, first.index->nHeight);
    }

    const auto empty = Mine();
    LOCK(cs_main);
    CheckTip(empty);
    BOOST_REQUIRE(empty.block.mweb_block.m_block->GetInputs().empty());
    BOOST_REQUIRE(empty.block.mweb_block.m_block->GetOutputs().empty());
    BOOST_REQUIRE(empty.block.mweb_block.m_block->GetKernels().empty());
    BOOST_CHECK_EQUAL(empty.index->mweb_amount, first.index->mweb_amount);
    BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{first.index->hogex_hash, 0}));
    CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), first.index->nHeight);
}

BOOST_AUTO_TEST_CASE(pegout_disk_undo_reopen_disconnect_and_reconnect_preserve_both_coin_sets)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto original_coin = WITH_LOCK(cs_main,
        return State().CoinsTip().GetMWEBView()->GetUTXO(deposit.GetOutputs().front().GetOutputID()));
    BOOST_REQUIRE(original_coin);
    constexpr CAmount WITHDRAWAL{3 * COIN};
    const auto withdrawal = m_txs.Spend(deposit.GetOutputs().front(), {{WITHDRAWAL, P2WSH_OP_TRUE}});
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*withdrawal.GetTransaction());
    const auto second = Mine({MakeTransactionRef(std::move(tx))});
    const COutPoint pegout{second.index->hogex_hash, 1};
    const auto check_withdrawal = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        CheckTip(second);
        BOOST_CHECK_EQUAL(second.index->mweb_amount, first.index->mweb_amount - WITHDRAWAL - MWEB_FEE);
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        CheckCoin(State().CoinsTip(), withdrawal.GetOutputs().front(), second.index->nHeight);
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{first.index->hogex_hash, 0}));
        const Coin& coin = State().CoinsTip().AccessCoin(pegout);
        BOOST_REQUIRE(!coin.IsSpent());
        BOOST_CHECK(coin.IsPegout());
        BOOST_CHECK(!coin.IsCoinBase());
        BOOST_CHECK_EQUAL(coin.nHeight, second.index->nHeight);
        BOOST_CHECK_EQUAL(coin.out.nValue, WITHDRAWAL);
        BOOST_CHECK(coin.out.scriptPubKey == P2WSH_OP_TRUE);
    };
    {
        LOCK(cs_main);
        check_withdrawal();
        ReopenCoins();
        check_withdrawal();
        BOOST_CHECK(State().CoinsDB().GetHeadBlocks().empty());
        CBlockUndo undo;
        BOOST_REQUIRE(State().m_blockman.ReadBlockUndo(undo, *second.index));
        BOOST_REQUIRE(undo.mwundo);
        BOOST_REQUIRE(undo.mwundo->GetPreviousHeader());
        BOOST_CHECK(*undo.mwundo->GetPreviousHeader() == *first.index->mweb_header);
        BOOST_REQUIRE_EQUAL(undo.mwundo->GetCoinsSpent().size(), 1U);
        BOOST_CHECK(undo.mwundo->GetCoinsSpent().front().Serialized() == original_coin->Serialized());
        BOOST_REQUIRE_EQUAL(undo.mwundo->GetCoinsAdded().size(), 1U);
        BOOST_CHECK(undo.mwundo->GetCoinsAdded().front() == withdrawal.GetOutputs().front().GetOutputID());
        BOOST_REQUIRE_EQUAL(undo.vtxundo.size(), 1U);
        BOOST_REQUIRE_EQUAL(undo.vtxundo.front().vprevout.size(), 1U);
        const Coin& previous_hogaddr = undo.vtxundo.front().vprevout.front();
        BOOST_CHECK(previous_hogaddr.out == first.block.GetHogEx()->vout.front());
        BOOST_CHECK_EQUAL(previous_hogaddr.nHeight, first.index->nHeight);
        BOOST_CHECK(!previous_hogaddr.IsCoinBase());
        BOOST_CHECK(!previous_hogaddr.IsPegout());
    }

    BlockValidationState invalidation;
    BOOST_REQUIRE_MESSAGE(State().InvalidateBlock(invalidation, second.index), invalidation.ToString());
    {
        LOCK(cs_main);
        CheckTip(first);
        CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), first.index->nHeight);
        CheckMissing(State().CoinsTip(), withdrawal.GetOutputs().front());
        BOOST_CHECK(!State().CoinsTip().HaveCoin(pegout));
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{second.index->hogex_hash, 0}));
        BOOST_CHECK(State().CoinsTip().GetMWEBView()->GetUTXO(original_coin->GetOutputID())->Serialized() == original_coin->Serialized());
        State().ResetBlockFailureFlags(second.index);
        Assert(m_node.chainman)->RecalculateBestHeader();
    }
    BlockValidationState reactivation;
    BOOST_REQUIRE_MESSAGE(State().ActivateBestChain(reactivation), reactivation.ToString());
    LOCK(cs_main);
    check_withdrawal();
}

BOOST_AUTO_TEST_CASE(full_withdrawal_and_empty_successor_preserve_valid_zero_supply)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const CAmount amount = DEPOSIT - 2 * MWEB_FEE;
    const auto withdrawal = m_txs.Spend(deposit.GetOutputs().front(), {{amount, P2WSH_OP_TRUE}});
    BOOST_REQUIRE(withdrawal.GetOutputs().empty());
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*withdrawal.GetTransaction());
    const auto zero = Mine({MakeTransactionRef(std::move(tx))});
    {
        LOCK(cs_main);
        CheckTip(zero);
        BOOST_CHECK_EQUAL(zero.index->mweb_amount, 0);
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        BOOST_CHECK_EQUAL(State().CoinsTip().GetMWEBView()->GetLeafSet()->ToDynamicBitSet().count(), 0U);
        const Coin& pegout = State().CoinsTip().AccessCoin(COutPoint{zero.index->hogex_hash, 1});
        BOOST_REQUIRE(!pegout.IsSpent());
        BOOST_CHECK_EQUAL(pegout.out.nValue, amount);
        BOOST_CHECK(pegout.IsPegout());
        BOOST_CHECK_EQUAL(zero.index->mweb_header->GetNumTXOs(), first.index->mweb_header->GetNumTXOs());
    }
    const auto empty = Mine();
    LOCK(cs_main);
    CheckTip(empty);
    BOOST_CHECK_EQUAL(empty.index->mweb_amount, 0);
    BOOST_CHECK(empty.block.mweb_block.m_block->GetOutputs().empty());
    BOOST_CHECK(empty.block.mweb_block.m_block->GetKernels().empty());
    BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{zero.index->hogex_hash, 0}));
    BOOST_CHECK_EQUAL(empty.index->mweb_header->GetNumTXOs(), first.index->mweb_header->GetNumTXOs());
    CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
    BOOST_CHECK_EQUAL(State().CoinsTip().GetMWEBView()->GetLeafSet()->ToDynamicBitSet().count(), 0U);
}

BOOST_AUTO_TEST_CASE(full_block_validity_checks_do_not_publish_paired_state)
{
    const auto original_deposit = m_txs.Pegin();
    const auto anchor = Mine({FundPegin(original_deposit)});
    const auto deposit = m_txs.Pegin(2 * COIN);
    const auto tx = FundPegin(deposit);
    Submit(tx);
    const auto candidate = PrepareBlock(m_node, {.coinbase_output_script = P2WSH_OP_TRUE});
    BOOST_REQUIRE(candidate->GetHogEx());
    BOOST_REQUIRE_EQUAL(candidate->mweb_block.m_block->GetOutputs().size(), 1U);
    BOOST_REQUIRE(candidate->mweb_block.m_block->GetOutputs().front().GetOutputID() == deposit.GetOutputs().front().GetOutputID());
    LOCK(cs_main);
    const auto check_unpublished = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        CheckTip(anchor);
        CheckCoin(State().CoinsTip(), original_deposit.GetOutputs().front(), anchor.index->nHeight);
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        BOOST_CHECK(State().CoinsTip().HaveCoin(tx->vin.front().prevout));
        BOOST_CHECK(State().CoinsTip().AccessCoin(tx->vin.front().prevout).out == m_coinbase_txns.at(1)->vout.front());
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{tx->GetHash(), 0}));
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{tx->GetHash(), 1}));
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{candidate->GetHogEx()->GetHash(), 0}));
        BOOST_CHECK(State().m_blockman.LookupBlockIndex(candidate->GetHash()) == nullptr);
    };
    check_unpublished();
    const auto valid = TestBlockValidity(State(), *candidate, /*check_pow=*/false, /*check_merkle_root=*/true);
    BOOST_REQUIRE_MESSAGE(valid.IsValid(), valid.ToString());
    check_unpublished();
    CBlock missing_extension = *candidate;
    missing_extension.mweb_block.SetNull();
    const auto invalid = TestBlockValidity(State(), missing_extension, /*check_pow=*/false, /*check_merkle_root=*/true);
    BOOST_REQUIRE(!invalid.IsValid());
    BOOST_CHECK_EQUAL(invalid.GetRejectReason(), "mweb-missing");
    check_unpublished();
}

BOOST_AUTO_TEST_CASE(arbitrary_ancestor_view_restores_exact_coins_without_publishing)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto first_spend = m_txs.Spend(deposit.GetOutputs().front(), {{3 * COIN, P2WSH_OP_TRUE}});
    CMutableTransaction first_tx;
    first_tx.mweb_tx = mw::MutableTx::From(*first_spend.GetTransaction());
    const auto second = Mine({MakeTransactionRef(std::move(first_tx))});
    const auto second_spend = m_txs.Spend(first_spend.GetOutputs().front(), {{COIN, P2WSH_OP_TRUE}});
    CMutableTransaction second_tx;
    second_tx.mweb_tx = mw::MutableTx::From(*second_spend.GetTransaction());
    const auto third = Mine({MakeTransactionRef(std::move(second_tx))});

    LOCK(cs_main);
    const auto first_status = first.index->nStatus;
    const auto second_status = second.index->nStatus;
    const auto third_status = third.index->nStatus;
    const auto check_live = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        CheckTip(third);
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        CheckMissing(State().CoinsTip(), first_spend.GetOutputs().front());
        CheckCoin(State().CoinsTip(), second_spend.GetOutputs().front(), third.index->nHeight);
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{first.index->hogex_hash, 0}));
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{second.index->hogex_hash, 0}));
        BOOST_CHECK(State().CoinsTip().HaveCoin(COutPoint{second.index->hogex_hash, 1}));
        BOOST_CHECK(State().CoinsTip().HaveCoin(COutPoint{third.index->hogex_hash, 1}));
        BOOST_CHECK_EQUAL(first.index->nStatus, first_status);
        BOOST_CHECK_EQUAL(second.index->nStatus, second_status);
        BOOST_CHECK_EQUAL(third.index->nStatus, third_status);
    };
    check_live();
    {
        CCoinsViewCache historical{&State().CoinsTip()};
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(ActivateArbitraryChain(state, historical, State(), first.index), state.ToString());
        BOOST_CHECK(historical.GetBestBlock() == first.index->GetBlockHash());
        CheckRoots(historical, first.index->mweb_header);
        CheckCoin(historical, deposit.GetOutputs().front(), first.index->nHeight);
        CheckMissing(historical, first_spend.GetOutputs().front());
        CheckMissing(historical, second_spend.GetOutputs().front());
        const Coin& hogaddr = historical.AccessCoin(COutPoint{first.index->hogex_hash, 0});
        BOOST_REQUIRE(!hogaddr.IsSpent());
        BOOST_CHECK(hogaddr.out == first.block.GetHogEx()->vout.front());
        BOOST_CHECK_EQUAL(hogaddr.nHeight, first.index->nHeight);
        BOOST_CHECK(!hogaddr.IsCoinBase());
        BOOST_CHECK(!hogaddr.IsPegout());
        BOOST_CHECK(!historical.HaveCoin(COutPoint{second.index->hogex_hash, 0}));
        BOOST_CHECK(!historical.HaveCoin(COutPoint{second.index->hogex_hash, 1}));
        BOOST_CHECK(!historical.HaveCoin(COutPoint{third.index->hogex_hash, 0}));
        BOOST_CHECK(!historical.HaveCoin(COutPoint{third.index->hogex_hash, 1}));
        check_live();
    }
    check_live();
}

BOOST_AUTO_TEST_CASE(mweb_write_exception_is_fatal_without_successful_flush_publication)
{
    struct FlushSubscriber final : CValidationInterface {
        std::atomic<unsigned> count{0};
        void ChainStateFlushed(const kernel::ChainstateRole&, const CBlockLocator&) override { ++count; }
    };

    const auto first_deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(first_deposit)});
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto subscriber = std::make_shared<FlushSubscriber>();
    m_node.validation_signals->RegisterSharedValidationInterface(subscriber);
    BlockValidationState initial_flush;
    BOOST_REQUIRE_MESSAGE(State().FlushStateToDisk(initial_flush, FlushStateMode::FORCE_SYNC), initial_flush.ToString());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(subscriber->count.load(), 1U);

    const auto second_deposit = m_txs.Pegin(2 * COIN);
    const auto second_tx = FundPegin(second_deposit);
    const auto second = Mine({second_tx});
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(subscriber->count.load(), 1U);

    {
        LOCK(cs_main);
        CheckTip(second);
        BOOST_REQUIRE(State().GetLastFlushedBlock() == first.index);
        BOOST_REQUIRE(!static_cast<bool>(*m_node.shutdown_signal));
        BOOST_REQUIRE_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        auto& db = State().CoinsDB();
        const auto mweb_db = db.GetMWEBView()->GetDatabase();
        const auto generation = MMRInfoDB{mweb_db.get()}.GetLatest();
        BOOST_REQUIRE(generation);
        const auto previous_leaf = LeafSet::GetPath(FilePath{State().StoragePath()}, generation->index);
        const auto previous_bytes = File{previous_leaf}.ReadBytes();
        const auto blocked_leaf = LeafSet::GetPath(FilePath{State().StoragePath()}, generation->index + 1);
        BOOST_REQUIRE(!blocked_leaf.Exists());
        // Remove() can delete direct children, so a nonempty nested directory makes
        // the next generation's copy fail on every platform without permission tricks.
        blocked_leaf.GetChild("nested").GetChild("keep").CreateDir();

        BlockValidationState failed_flush;
        BOOST_CHECK(!State().FlushStateToDisk(failed_flush, FlushStateMode::FORCE_SYNC));
        BOOST_CHECK(failed_flush.IsError());
        BOOST_CHECK(failed_flush.GetRejectReason().starts_with("System error while flushing:"));
        BOOST_CHECK(failed_flush.GetRejectReason().find(blocked_leaf.ToString()) != std::string::npos);
        BOOST_CHECK(static_cast<bool>(*m_node.shutdown_signal));
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
        const auto warnings = m_node.warnings->GetMessages();
        BOOST_CHECK(std::any_of(warnings.begin(), warnings.end(), [&](const auto& warning) {
            return warning.original == failed_flush.GetRejectReason();
        }));
        BOOST_CHECK(State().GetLastFlushedBlock() == first.index);
        // This small flush has not committed a partial canonical batch. The old
        // durable tip and MWEB generation therefore remain intact on the fatal path.
        BOOST_CHECK(db.GetBestBlock() == first.index->GetBlockHash());
        BOOST_CHECK(db.GetHeadBlocks().empty());
        const auto durable_generation = MMRInfoDB{mweb_db.get()}.GetLatest();
        BOOST_REQUIRE(durable_generation);
        BOOST_CHECK(durable_generation->Serialized() == generation->Serialized());
        BOOST_CHECK(File{previous_leaf}.ReadBytes() == previous_bytes);
        BOOST_CHECK(db.HaveCoin(second_tx->vin.front().prevout));
        BOOST_CHECK(!db.HaveCoin(COutPoint{second_tx->GetHash(), 1}));
        Output durable_output;
        BOOST_REQUIRE(db.GetMWEBCoin(first_deposit.GetOutputs().front().GetOutputID(), durable_output));
        BOOST_CHECK(durable_output.Serialized() == first_deposit.GetOutputs().front().GetOutput().Serialized());
        CheckMissing(db, second_deposit.GetOutputs().front());
    }
    // The failed cache is indeterminate and must be discarded, not retried.
    // Drain callbacks outside cs_main before fixture teardown destroys the views.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(subscriber->count.load(), 1U);
    m_node.validation_signals->UnregisterSharedValidationInterface(subscriber);
}

BOOST_AUTO_TEST_SUITE_END()
