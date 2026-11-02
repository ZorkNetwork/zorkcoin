// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Verify candidate packing against L1 weight, MWEB weight/input count and
// serialized BIP324 limits. Check near-cap fills and reject packing gaps when
// an excluded transaction at an equal or better fee rate still fits. Failures
// report the remaining budgets and identify the first fitting excluded tx.

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <mw/consensus/params.h>
#include <mw/consensus/weight.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/tx_body.h>
#include <mweb/mweb_miner.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <util/feefrac.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <consensus/tx_verify.h>
#include <script/standard.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <validation.h>
#include <crypto/common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace node;

namespace {

struct MWEBRegtest100Setup : public TestChain100Setup {
    MWEBRegtest100Setup()
        : TestChain100Setup(ChainType::REGTEST, {.extra_args = {"-vbparams=mweb:1601450001:9999999999"}}) {}
};

/** Real admission is part of this test; leave ordinary packing fixtures alone. */
struct MWEBCompetingPackingSetup : public TestChain100Setup {
    MWEBCompetingPackingSetup()
        : TestChain100Setup(ChainType::REGTEST, {.extra_args = {
              "-vbparams=mweb:1601450001:9999999999", "-acceptnonstdtxn=0",
              // 32-bit hosts reject -maxmempool above 500 MB (see node/mempool_args.cpp).
              sizeof(void*) == 4 ? "-maxmempool=500" : "-maxmempool=1000"}}) {}
};

constexpr uint32_t MWEB_VB_START_TIME = 1601450001;
constexpr int FIRST_MWEB_HEIGHT = 432;

uint256 Uint64Hash(uint64_t n)
{
    uint256 out;
    std::memset(out.begin(), 0, out.size());
    WriteLE64(out.begin(), n);
    return out;
}

/** Near-cap slack allowances; serialized checks also bound slack below one filler. */
constexpr uint64_t SLACK_MWEB = 39;
constexpr uint64_t SLACK_SER = 64 * 1024;

/** Hard requirement for size-binding EXTENDED cases. */
constexpr size_t MIN_EXTENDED_UTXOS = 80'001;

/** Opt-in gate for heavy (>80k UTXO) packing proofs. Default ctest skips them. */
bool MegaExtendedTestEnabled()
{
    const char* e = std::getenv("MEGA_EXTENDED_TEST");
    return e != nullptr && std::string(e) != "" && std::string(e) != "0";
}

boost::test_tools::assertion_result MegaExtendedTestPrecondition(boost::unit_test::test_unit_id)
{
    if (MegaExtendedTestEnabled()) {
        return true;
    }
    boost::test_tools::assertion_result res(false);
    res.message() << "set MEGA_EXTENDED_TEST=1 to run mega packing tests";
    return res;
}

#define SKIP_IF_NOT_EXTENDED()                                                                 \
    do {                                                                                       \
        if (!MegaExtendedTestEnabled()) {                                                      \
            BOOST_TEST_MESSAGE("Skipping mega packing case (set MEGA_EXTENDED_TEST=1)");       \
            return;                                                                            \
        }                                                                                      \
    } while (0)

struct LeftoverBudgets {
    int64_t rem_l1{0};
    int64_t rem_mweb{0};
    int64_t rem_ser{0};
    int64_t rem_inputs{0}; //!< mw::MAX_NUM_INPUTS − staged MWEB inputs
};

struct PackingStopInfo {
    bool triggered{false};
    std::string reason;
    int64_t rem_l1{0};
    int64_t rem_mweb{0};
    int64_t rem_ser{0};
    std::string first_excluded_fit{};
    bool consecutive_failure_suspicion{false};
    bool prefer_fewer_inputs_gap{false};
};

std::string g_last_stop_report;

void MineMwebEraBlock(NodeContext& node, const CScript& coinbase_script)
{
    std::shared_ptr<CBlock> block = PrepareBlock(node, {.coinbase_output_script = coinbase_script});
    {
        LOCK(::cs_main);
        const uint32_t mtp = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast();
        block->nTime = std::max({mtp + 1, MWEB_VB_START_TIME});
    }
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    RegenerateCommitments(*block, *Assert(node.chainman));
    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }
    ProcessBlock(node, block);
}

void MineToMwebChain(TestChain100Setup& setup, NodeContext& node, int post_activation_blocks = 2)
{
    const CScript coinbase_script{CScript() << OP_TRUE};
    SetMockTime(std::chrono::seconds{MWEB_VB_START_TIME});

    int height{WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight())};
    while (height < FIRST_MWEB_HEIGHT - 1) {
        MineMwebEraBlock(node, coinbase_script);
        height = WITH_LOCK(::cs_main, return Assert(node.chainman)->ActiveHeight());
    }

    // One real pegin so the tip has an MWEB header / coins view history.
    test::Tx mweb_pegin = test::Tx::CreatePegIn(COIN);
    const auto pegin_coin = mweb_pegin.GetPegInCoin();
    const CScript pegin_script = GetScriptForPegin(pegin_coin.GetKernelID());
    const CTransactionRef& coinbase = setup.m_coinbase_txns.at(0);
    const CAmount fee{10'000};
    const CAmount change = coinbase->vout[0].nValue - COIN - fee;
    const CScript change_script = CScript() << ToByteVector(setup.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction mtx = setup.CreateValidTransaction(
                                  {coinbase},
                                  {COutPoint{coinbase->GetHash(), 0}},
                                  1,
                                  {setup.coinbaseKey},
                                  {CTxOut{COIN, pegin_script}, CTxOut{change, change_script}},
                                  std::nullopt,
                                  std::nullopt)
                                  .first;
    mtx.mweb_tx = mw::MutableTx::From(*mweb_pegin.GetTransaction());
    {
        LOCK2(::cs_main, Assert(node.mempool)->cs);
        const MempoolAcceptResult result = Assert(node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              result.m_state.ToString());
    }
    for (int i = 0; i < post_activation_blocks; ++i) {
        MineMwebEraBlock(node, coinbase_script);
    }
}

CMutableTransaction MakePeginTx(CAmount amount, CAmount mweb_fee, uint64_t uniq)
{
    test::Tx mweb = test::Tx::CreatePegIn(amount, mweb_fee);
    const PegInCoin coin = mweb.GetPegInCoin();

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint{Txid::FromUint256(Uint64Hash(uniq + 1)), 0};
    mtx.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    mtx.vout.emplace_back(amount, GetScriptForPegin(coin.GetKernelID()));
    mtx.mweb_tx = mw::MutableTx::From(*mweb.GetTransaction());
    return mtx;
}

/** MWEB-only consolidation spending on-chain (or previously mined) TxOutputs. */
CMutableTransaction MakeConsolidation(const std::vector<test::TxOutput>& inputs, int plain_kernels, CAmount fee_per_kernel)
{
    BOOST_REQUIRE(!inputs.empty());
    BOOST_REQUIRE(plain_kernels >= 1);

    CAmount in_sum = 0;
    for (const auto& in : inputs) in_sum += in.GetAmount();
    const CAmount total_fee = static_cast<CAmount>(plain_kernels) * fee_per_kernel;
    BOOST_REQUIRE(in_sum > total_fee);

    test::TxBuilder builder;
    for (const auto& in : inputs) {
        builder.AddInput(in);
    }
    builder.AddOutput(in_sum - total_fee);
    for (int i = 0; i < plain_kernels; ++i) {
        builder.AddPlainKernel(fee_per_kernel, /*add_stealth_excess=*/false);
    }
    test::Tx built = builder.Build();

    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*built.GetTransaction());
    return mtx;
}

/** Oversized / mid-size synthetic MWEB-only body (size-gate testing; not crypto-valid).
 *  `uniq` must differ per submission so txids do not collide in the mempool.
 *  Prefer `fat_extra_bytes` over huge `n_inputs` when many distinct monsters are needed
 *  (avoids multi-GB mempool allocations). */
CMutableTransaction MakeSyntheticMonster(size_t n_inputs, CAmount entry_fee_hint, uint64_t uniq,
                                         size_t fat_extra_bytes = 0)
{
    (void)entry_fee_hint;
    std::vector<uint8_t> uniq_bytes(32, 0);
    WriteLE64(uniq_bytes.data(), uniq);
    WriteLE64(uniq_bytes.data() + 8, n_inputs);
    WriteLE64(uniq_bytes.data() + 16, fat_extra_bytes);
    const mw::Hash uniq_hash(uniq_bytes);
    const Input sample(
        /*features=*/0x01,
        uniq_hash,
        Commitment{},
        PublicKey{},
        PublicKey{},
        Signature{});
    std::vector<Input> inputs(n_inputs, sample);
    std::vector<uint8_t> extra(std::max<size_t>(8, fat_extra_bytes), static_cast<uint8_t>(uniq & 0xff));
    WriteLE64(extra.data(), uniq);
    // Unique fee-bearing kernel so each monster has a distinct txid.
    Kernel fee_kernel(
        Kernel::FEE_FEATURE_BIT | Kernel::EXTRA_DATA_FEATURE_BIT,
        /*fee=*/CAmount{1} + static_cast<CAmount>(uniq % 10'000),
        /*pegin=*/std::nullopt,
        /*pegouts=*/std::vector<PegOutCoin>{},
        /*lockHeight=*/std::nullopt,
        /*stealthExcess=*/std::nullopt,
        /*extraData=*/std::move(extra),
        Commitment{},
        Signature{});
    BlindingFactor off{uniq_bytes.data()};
    auto mwtx = std::make_shared<mw::Transaction>(
        off, BlindingFactor{},
        TxBody(std::move(inputs), {}, {std::move(fee_kernel)}));

    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*mwtx);
    return mtx;
}

CMutableTransaction MakeL1Filler(uint64_t uniq, CAmount fee)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint{Txid::FromUint256(Uint64Hash(uniq + 42)), 0};
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = COIN - fee;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

/** Heavy L1 tx: many outputs so weight is large while staying under the serialized BIP324 cap alone. */
CMutableTransaction MakeHeavyL1(uint64_t uniq, size_t n_outs, CAmount fee)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint{Txid::FromUint256(Uint64Hash(uniq + 99'000)), 0};
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(n_outs);
    const CAmount each = std::max<CAmount>(1, (COIN - fee) / static_cast<CAmount>(n_outs));
    for (size_t i = 0; i < n_outs; ++i) {
        mtx.vout[i].nValue = each;
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
    }
    return mtx;
}

void Submit(CTxMemPool& pool, const CMutableTransaction& mtx, CAmount fee, unsigned height = 1)
{
    // Assembler min-fee check uses GetTotalFee which always adds GetMWEBFee(weight).
    const uint64_t mw = MWEB::Tx(mtx.mweb_tx).GetMWEBWeight();
    const CAmount need = CFeeRate::GetMWEBFee(mw);
    if (fee < need) fee = need;
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(fee).Height(height).Time(NodeSeconds{}).FromTx(mtx));
}

std::unique_ptr<CBlockTemplate> BuildTemplate(Chainstate& chainstate, CTxMemPool& pool)
{
    BlockCreateOptions options;
    options.test_block_validity = false;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    return BlockAssembler{chainstate, &pool, options}.CreateNewBlock();
}

size_t ExactBlockSize(const CBlock& block)
{
    return ::GetSerializeSize(TX_WITH_WITNESS(block));
}

uint64_t BlockMWEBWeight(const CBlock& block)
{
    if (block.mweb_block.IsNull() || !block.mweb_block.m_block) return 0;
    return Weight::Calculate(block.mweb_block.m_block->GetTxBody());
}

size_t BlockMWEBInputCount(const CBlock& block)
{
    if (block.mweb_block.IsNull() || !block.mweb_block.m_block) return 0;
    return block.mweb_block.m_block->GetTxBody().GetInputs().size();
}

LeftoverBudgets LeftoverBudgetsOf(const CBlock& block, uint64_t block_max_weight = MAX_BLOCK_WEIGHT)
{
    LeftoverBudgets b;
    b.rem_l1 = static_cast<int64_t>(block_max_weight) - static_cast<int64_t>(GetBlockWeight(block));
    b.rem_mweb = static_cast<int64_t>(mw::MAX_BLOCK_WEIGHT) - static_cast<int64_t>(BlockMWEBWeight(block));
    b.rem_ser = static_cast<int64_t>(MAX_BLOCK_SERIALIZED_SIZE_BIP324) - static_cast<int64_t>(ExactBlockSize(block));
    b.rem_inputs = static_cast<int64_t>(mw::MAX_NUM_INPUTS) - static_cast<int64_t>(BlockMWEBInputCount(block));
    return b;
}

uint64_t TxMWEBWeight(const CTransaction& tx)
{
    return tx.HasMWEBTx() ? tx.mweb_tx.GetMWEBWeight() : 0;
}

size_t EstimateWouldFitDelta(const CTransaction& tx)
{
    size_t delta = 0;
    const size_t l1 = MWEB::Miner::EstimateTxL1StubBytes(tx);
    if (l1 > 0) delta += l1 + 9;
    if (tx.HasMWEBTx()) {
        delta += MWEB::Miner::EstimateTxMWEBBodyBytes(tx);
        delta += MWEB::Miner::EstimateTxHogExDeltaBytes(tx);
    }
    return delta;
}

bool WouldFit(const CTransaction& tx, const LeftoverBudgets& rem, uint64_t /*block_max_weight*/ = MAX_BLOCK_WEIGHT)
{
    if (GetTransactionWeight(tx) > rem.rem_l1) return false;
    if (static_cast<int64_t>(TxMWEBWeight(tx)) > rem.rem_mweb) return false;
    if (static_cast<int64_t>(EstimateWouldFitDelta(tx)) > rem.rem_ser) return false;
    if (tx.HasMWEBTx()) {
        if (static_cast<int64_t>(MWEB::Miner::CountTxMWEBInputs(tx)) > rem.rem_inputs) return false;
    }
    return true;
}

void AssertNeverExceed(const CBlock& block)
{
    // Assembler mirror: production BlockAssembler caps wire size at the BIP324 mine gate.
    BOOST_CHECK_LE(ExactBlockSize(block), MAX_BLOCK_SERIALIZED_SIZE_BIP324);
    BOOST_CHECK_LE(BlockMWEBWeight(block), mw::MAX_BLOCK_WEIGHT);
    BOOST_CHECK_LE(GetBlockWeight(block), MAX_BLOCK_WEIGHT);
}

std::string FormatStop(const PackingStopInfo& info)
{
    std::ostringstream oss;
    oss << "STOP packing defect: " << info.reason
        << " rem_l1=" << info.rem_l1
        << " rem_mweb=" << info.rem_mweb
        << " rem_ser=" << info.rem_ser
        << " consecutive_failure_suspicion=" << (info.consecutive_failure_suspicion ? "yes" : "no")
        << " prefer_fewer_inputs_gap_implicated=" << (info.prefer_fewer_inputs_gap ? "yes" : "no");
    if (!info.first_excluded_fit.empty()) {
        oss << " first_excluded_tx_that_still_fits=" << info.first_excluded_fit;
    }
    return oss.str();
}

void TriggerStop(PackingStopInfo info)
{
    info.triggered = true;
    g_last_stop_report = FormatStop(info);
    BOOST_REQUIRE_MESSAGE(false, g_last_stop_report);
}

void AssertNearCapWeight(const LeftoverBudgets& rem, uint64_t filler_weight, const std::string& ctx)
{
    if (rem.rem_mweb < 0) {
        TriggerStop({.reason = ctx + ": rem_mweb negative", .rem_l1 = rem.rem_l1, .rem_mweb = rem.rem_mweb, .rem_ser = rem.rem_ser});
    }
    if (static_cast<uint64_t>(rem.rem_mweb) > filler_weight && static_cast<uint64_t>(rem.rem_mweb) > SLACK_MWEB) {
        TriggerStop({
            .reason = ctx + ": NEAR_CAP(MWEB) failed (rem_mweb larger than filler/slack)",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .consecutive_failure_suspicion = rem.rem_ser > static_cast<int64_t>(SLACK_SER) && rem.rem_mweb > static_cast<int64_t>(SLACK_MWEB),
            .prefer_fewer_inputs_gap = true,
        });
    }
}

void AssertNearCapSer(const LeftoverBudgets& rem, size_t filler_ser, const std::string& ctx)
{
    if (rem.rem_ser < 0) {
        TriggerStop({.reason = ctx + ": rem_ser negative", .rem_l1 = rem.rem_l1, .rem_mweb = rem.rem_mweb, .rem_ser = rem.rem_ser});
    }
    // Exact leftover within the coinbase estimate pad (+ CompactSize headroom)
    // means residual already exhausted the assembler's serialized budget.
    constexpr int64_t ESTIMATE_PAD =
        static_cast<int64_t>(MWEB::BLOCK_SERIALIZED_COINBASE_RESERVE) + 2048;
    if (rem.rem_ser > 0 && rem.rem_ser <= ESTIMATE_PAD) {
        return;
    }
    // Slack must stay below one deliberately left-out filler when that filler is larger than SLACK_SER.
    const uint64_t slack = std::min<uint64_t>(SLACK_SER, filler_ser > 0 ? filler_ser - 1 : SLACK_SER);
    if (static_cast<uint64_t>(rem.rem_ser) >= filler_ser && static_cast<uint64_t>(rem.rem_ser) > slack) {
        TriggerStop({
            .reason = ctx + ": NEAR_CAP(SER) failed",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .consecutive_failure_suspicion = true,
            .prefer_fewer_inputs_gap = true,
        });
    }
}

struct TrackedTx {
    Txid hash;
    CTransactionRef tx;
    CAmount fee;
    bool is_monster{false};
    bool is_filler{false};
};

bool TemplateContainsMWEBTx(const CBlock& block, const CTransaction& needle)
{
    if (!needle.HasMWEBTx() || block.mweb_block.IsNull() || !block.mweb_block.m_block) return false;
    const auto& body = block.mweb_block.m_block->GetTxBody();
    // Match on first kernel id when present.
    if (needle.mweb_tx.m_transaction->GetKernels().empty()) return false;
    const mw::Hash kid = needle.mweb_tx.m_transaction->GetKernels().front().GetKernelID();
    for (const auto& k : body.GetKernels()) {
        if (k.GetKernelID() == kid) return true;
    }
    return false;
}

std::set<Txid> IncludedHashes(const CBlock& block)
{
    std::set<Txid> out;
    for (const auto& tx : block.vtx) {
        if (tx) out.insert(tx->GetHash());
    }
    return out;
}

void AssertNoGap(const CBlock& block,
                 const CTxMemPool& pool,
                 const std::vector<TrackedTx>& mempool_txs,
                 const std::set<Txid>& included,
                 const std::string& ctx)
{
    LOCK(pool.cs);
    auto is_included = [&](const TrackedTx& t) {
        return t.tx->IsMWEBOnly() ? TemplateContainsMWEBTx(block, *t.tx) : included.contains(t.hash);
    };
    // Read the actual staged fee (Submit can raise it to the MWEB floor), and
    // use one consistent weight denominator for both sides of every comparison.
    std::optional<std::pair<CAmount, int64_t>> floor;
    for (const auto& t : mempool_txs) {
        if (t.is_monster || !t.is_filler || !is_included(t)) continue;
        const auto* entry = pool.GetEntry(t.hash);
        BOOST_REQUIRE(entry);
        const int64_t weight = std::max<int64_t>(1, entry->GetAdjustedWeight());
        if (!floor || entry->GetModifiedFee() * floor->second < floor->first * weight) {
            floor = {entry->GetModifiedFee(), weight};
        }
    }
    BOOST_REQUIRE_MESSAGE(floor, ctx + ": no included filler establishes the fee floor");
    const LeftoverBudgets rem = LeftoverBudgetsOf(block);
    // Exact rem within the assembler's coinbase size reserve (+ CompactSize
    // headroom) is estimate pad, not stranded mempool capacity: residual already
    // filled until the running serialized estimate was exhausted.
    constexpr int64_t ESTIMATE_PAD =
        static_cast<int64_t>(MWEB::BLOCK_SERIALIZED_COINBASE_RESERVE) + 2048;
    if (rem.rem_ser > 0 && rem.rem_ser <= ESTIMATE_PAD) {
        return;
    }
    for (const auto& t : mempool_txs) {
        if (is_included(t) || t.is_monster) continue;
        const auto* entry = pool.GetEntry(t.hash);
        BOOST_REQUIRE(entry);
        const int64_t weight = std::max<int64_t>(1, entry->GetAdjustedWeight());
        if (entry->GetModifiedFee() * floor->second < floor->first * weight) continue;
        if (WouldFit(*t.tx, rem)) {
            TriggerStop({
                .reason = ctx + ": NO_GAP failed — excluded equal-or-better tx still fits",
                .rem_l1 = rem.rem_l1,
                .rem_mweb = rem.rem_mweb,
                .rem_ser = rem.rem_ser,
                .first_excluded_fit = t.hash.ToString(),
                .consecutive_failure_suspicion = rem.rem_ser > static_cast<int64_t>(2'000'000) ||
                                                 (rem.rem_ser < static_cast<int64_t>(MWEB::BLOCK_SERIALIZED_SIZE_PRESSURE) &&
                                                  rem.rem_mweb > static_cast<int64_t>(SLACK_MWEB)),
                .prefer_fewer_inputs_gap = true,
            });
        }
    }
}

size_t CountIncludedTracked(const CBlock& block, const std::vector<TrackedTx>& tracked, bool fillers_only)
{
    size_t n = 0;
    for (const auto& t : tracked) {
        if (fillers_only && !t.is_filler) continue;
        if (t.is_monster) continue;
        if (t.tx->IsMWEBOnly()) {
            if (TemplateContainsMWEBTx(block, *t.tx)) ++n;
        } else if (IncludedHashes(block).contains(t.hash)) {
            ++n;
        }
    }
    return n;
}

size_t CountIncludedMonsters(const CBlock& block, const std::vector<TrackedTx>& tracked)
{
    size_t n = 0;
    for (const auto& t : tracked) {
        if (!t.is_monster) continue;
        if (TemplateContainsMWEBTx(block, *t.tx)) ++n;
    }
    return n;
}

void DrainMempool(NodeContext& node)
{
    CTxMemPool& pool = *Assert(node.mempool);
    LOCK2(::cs_main, pool.cs);
    while (!pool.mapTx.empty()) {
        pool.removeRecursive(pool.mapTx.begin()->GetTx(), MemPoolRemovalReason::BLOCK);
    }
}

/** Mine pegins into the tip so their outputs exist on the MWEB coins view. */
std::vector<test::TxOutput> MinePegins(TestChain100Setup& setup, NodeContext& node, size_t count, CAmount amount = COIN)
{
    std::vector<test::TxOutput> outs;
    outs.reserve(count);
    CTxMemPool& pool = *Assert(node.mempool);
    BlockCreateOptions mine_opts;
    mine_opts.coinbase_output_script = P2WSH_OP_TRUE;
    mine_opts.test_block_validity = false;
    mine_opts.block_min_fee_rate = CFeeRate{0};

    // Create and mature P2WSH_OP_TRUE coinbases to fund pegins.
    std::vector<COutPoint> coinbases;
    coinbases.reserve(count + COINBASE_MATURITY);
    for (size_t i = 0; i < count + COINBASE_MATURITY; ++i) {
        COutPoint o = MineBlock(node, mine_opts);
        BOOST_REQUIRE(!o.IsNull());
        coinbases.push_back(o);
    }

    DrainMempool(node);

    std::vector<test::Tx> pegs;
    pegs.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        CAmount available = 0;
        {
            LOCK(::cs_main);
            const Coin& coin = Assert(node.chainman)->ActiveChainstate().CoinsTip().AccessCoin(coinbases[i]);
            BOOST_REQUIRE_MESSAGE(!coin.IsSpent(), strprintf("coinbase %u spent", i));
            available = coin.out.nValue;
        }
        // CreatePegIn already randomizes blinds; keep amounts ≤ coinbase after fees.
        const CAmount l1_fee_pad = 20'000;
        BOOST_REQUIRE_GT(available, l1_fee_pad + 1);
        const CAmount peg_amount = std::min(amount, available - l1_fee_pad);
        test::Tx peg = test::Tx::CreatePegIn(peg_amount, /*fee=*/0);
        pegs.push_back(peg);

        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = coinbases[i];
        mtx.vin[0].scriptWitness.stack = {std::vector<unsigned char>{OP_TRUE}};
        mtx.vout.emplace_back(peg_amount, GetScriptForPegin(peg.GetPegInCoin().GetKernelID()));
        const CAmount l1_fee = std::max<CAmount>(10'000, CFeeRate::GetMWEBFee(peg.GetTransaction()->CalcWeight()) + 1000);
        BOOST_REQUIRE_MESSAGE(available > peg_amount + l1_fee,
                              strprintf("available=%d peg=%d fee=%d i=%u", available, peg_amount, l1_fee, i));
        mtx.vout.emplace_back(available - peg_amount - l1_fee, P2WSH_OP_TRUE);
        mtx.mweb_tx = mw::MutableTx::From(*peg.GetTransaction());

        LOCK2(::cs_main, pool.cs);
        const MempoolAcceptResult result = Assert(node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              result.m_state.ToString());
    }

    int guard = 0;
    while (pool.size() > 0) {
        BOOST_REQUIRE_LT(++guard, 200);
        MineBlock(node, mine_opts);
    }

    for (auto& peg : pegs) {
        BOOST_REQUIRE(!peg.GetOutputs().empty());
        outs.push_back(peg.GetOutputs().front());
    }
    (void)setup;
    return outs;
}

/** Fan one UTXO into n_outs equal-ish re-spendable outputs (crypto-valid). */
CMutableTransaction MakeFanOut(const test::TxOutput& input, size_t n_outs, CAmount fee, std::vector<test::TxOutput>& new_outs)
{
    BOOST_REQUIRE_GE(n_outs, 2u);
    BOOST_REQUIRE_GT(input.GetAmount(), fee + static_cast<CAmount>(n_outs));

    test::TxBuilder builder;
    builder.AddInput(input);
    CAmount remaining = input.GetAmount() - fee;
    for (size_t i = 0; i < n_outs; ++i) {
        const size_t left = n_outs - i;
        const CAmount piece = (i + 1 == n_outs) ? remaining : (remaining / static_cast<CAmount>(left));
        BOOST_REQUIRE_GT(piece, 0);
        builder.AddOutput(piece);
        remaining -= piece;
    }
    BOOST_REQUIRE_EQUAL(remaining, 0);
    builder.AddPlainKernel(fee, /*add_stealth_excess=*/false);
    test::Tx built = builder.Build();
    new_outs = built.GetOutputs();
    BOOST_REQUIRE_EQUAL(new_outs.size(), n_outs);

    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*built.GetTransaction());
    return mtx;
}

void MineUntilMempoolEmpty(NodeContext& node, int max_blocks = 2'000)
{
    CTxMemPool& pool = *Assert(node.mempool);
    BlockCreateOptions mine_opts;
    mine_opts.coinbase_output_script = P2WSH_OP_TRUE;
    // Keep validity testing on for fan-outs so ProcessNewBlock failures surface early.
    mine_opts.test_block_validity = true;
    mine_opts.block_min_fee_rate = CFeeRate{0};
    int guard = 0;
    while (pool.size() > 0) {
        BOOST_REQUIRE_MESSAGE(++guard < max_blocks,
                              strprintf("MineUntilMempoolEmpty: mempool still has %u txs after %d blocks",
                                        pool.size(), guard));
        const size_t before = pool.size();
        auto block = PrepareBlock(node, mine_opts);
        BOOST_REQUIRE(block);
        const COutPoint mined = MineBlock(node, block);
        BOOST_REQUIRE_MESSAGE(!mined.IsNull(),
                              strprintf("MineUntilMempoolEmpty: ProcessNewBlock rejected template (mempool=%u)", before));
        if (pool.size() == before) {
            BOOST_REQUIRE_MESSAGE(false,
                                  strprintf("MineUntilMempoolEmpty: mining made no mempool progress (still %u txs)",
                                            pool.size()));
        }
    }
}

/**
 * Grow a crypto-valid on-chain MWEB UTXO bank past MIN_EXTENDED_UTXOS via
 * weight-limited fan-out (not one-coinbase-per-pegin MinePegins scaling).
 */
std::vector<test::TxOutput> MineFanoutUTXOs(TestChain100Setup& setup, NodeContext& node, size_t target_count)
{
    BOOST_REQUIRE_GE(target_count, MIN_EXTENDED_UTXOS);
    CTxMemPool& pool = *Assert(node.mempool);

    // Seeds large enough to fund >80k dust-ish outputs after fees.
    constexpr size_t N_SEEDS = 8;
    constexpr CAmount SEED_AMOUNT = 100 * COIN;
    std::vector<test::TxOutput> bank = MinePegins(setup, node, N_SEEDS, SEED_AMOUNT);
    DrainMempool(node);

    // Setup uses real relay admission: 200 outputs + one kernel weigh 3,602,
    // below the 4,000-WU transaction policy limit (distinct from the block limit).
    constexpr size_t FANOUT_BATCH = 200;
    // ATMP min fee scales with MWEB weight (~100 sat/WU); keep ample headroom.
    constexpr CAmount FANOUT_FEE = 1'000'000;
    size_t cursor = 0;
    int safety = 0;
    while (bank.size() < target_count) {
        BOOST_REQUIRE_LT(++safety, 10'000);
        // Prefer splitting the currently largest remaining output.
        size_t split_idx = cursor;
        for (size_t i = cursor; i < bank.size(); ++i) {
            if (bank[i].GetAmount() > bank[split_idx].GetAmount()) split_idx = i;
        }
        if (split_idx != cursor) std::swap(bank[cursor], bank[split_idx]);

        const test::TxOutput parent = bank[cursor];
        const size_t need = target_count - (bank.size() - 1); // after removing parent
        size_t n_outs = std::min(FANOUT_BATCH, std::max<size_t>(2, need));
        // Keep under one-tx weight max.
        const size_t max_outs_weight = (mw::MAX_BLOCK_WEIGHT - mw::BASE_KERNEL_WEIGHT) / mw::STANDARD_OUTPUT_WEIGHT;
        n_outs = std::min(n_outs, max_outs_weight);
        if (static_cast<CAmount>(parent.GetAmount()) <= FANOUT_FEE + static_cast<CAmount>(n_outs)) {
            ++cursor;
            BOOST_REQUIRE_MESSAGE(cursor < bank.size(), "fan-out stalled: no further splittable UTXOs");
            continue;
        }

        std::vector<test::TxOutput> children;
        CMutableTransaction mtx = MakeFanOut(parent, n_outs, FANOUT_FEE, children);
        {
            // Use full ATMP so invalid fan-outs fail here instead of at ProcessNewBlock.
            LOCK2(::cs_main, pool.cs);
            const MempoolAcceptResult result = Assert(node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                                  strprintf("fan-out ATMP failed: %s (n_outs=%u)", result.m_state.ToString(), n_outs));
        }
        bank.erase(bank.begin() + static_cast<std::ptrdiff_t>(cursor));
        MineUntilMempoolEmpty(node);
        bank.insert(bank.end(), children.begin(), children.end());
        if ((bank.size() % 2000) < FANOUT_BATCH) {
            BOOST_TEST_MESSAGE("MineFanoutUTXOs progress: bank_size=" << bank.size());
        }
    }

    BOOST_REQUIRE_GE(bank.size(), target_count);
    BOOST_TEST_MESSAGE("MineFanoutUTXOs: bank_size=" << bank.size());
    return bank;
}

void LogFillMetrics(const std::string& ctx, const CBlock& block, const LeftoverBudgets& rem,
                    size_t n_fill = 0, size_t S_f = 0)
{
    const size_t exact = ExactBlockSize(block);
    const uint64_t mw = BlockMWEBWeight(block);
    BOOST_TEST_MESSAGE(ctx << " fill metrics: n_fill=" << n_fill
                           << " S_f=" << S_f
                           << " exact_ser=" << exact << " ("
                           << (100.0 * exact / MAX_BLOCK_SERIALIZED_SIZE_BIP324) << "% of BIP324 cap) "
                           << "mweb_weight=" << mw << " (" << (100.0 * mw / mw::MAX_BLOCK_WEIGHT)
                           << "% of 200k) rem_ser=" << rem.rem_ser << " rem_mweb=" << rem.rem_mweb
                           << " mweb_inputs=" << BlockMWEBInputCount(block)
                           << " l1_weight=" << GetBlockWeight(block));
}

size_t EstimateSerDelta(const CTransaction& tx)
{
    return EstimateWouldFitDelta(tx);
}

void AssertTemplatesEquivalent(const CBlockTemplate& a, const CBlockTemplate& b, const std::string& ctx)
{
    BOOST_REQUIRE_MESSAGE(ExactBlockSize(a.block) == ExactBlockSize(b.block), ctx + ": exact size mismatch");
    BOOST_REQUIRE_MESSAGE(BlockMWEBWeight(a.block) == BlockMWEBWeight(b.block), ctx + ": mweb weight mismatch");
    BOOST_REQUIRE_MESSAGE(GetBlockWeight(a.block) == GetBlockWeight(b.block), ctx + ": l1 weight mismatch");
    BOOST_REQUIRE_EQUAL(a.m_package_feerates.size(), b.m_package_feerates.size());
    for (size_t i = 0; i < a.m_package_feerates.size(); ++i) {
        BOOST_REQUIRE_MESSAGE(a.m_package_feerates[i] == b.m_package_feerates[i],
                              ctx + ": package feerate order mismatch at " + util::ToString(i));
    }

    std::vector<Txid> ids_a, ids_b;
    for (const auto& tx : a.block.vtx) {
        if (!tx || tx->IsCoinBase()) continue;
        ids_a.push_back(tx->GetHash());
    }
    for (const auto& tx : b.block.vtx) {
        if (!tx || tx->IsCoinBase()) continue;
        ids_b.push_back(tx->GetHash());
    }
    BOOST_REQUIRE_MESSAGE(ids_a == ids_b, ctx + ": non-coinbase vtx set/order mismatch");

    if (!a.block.mweb_block.IsNull() && a.block.mweb_block.m_block) {
        BOOST_REQUIRE(!b.block.mweb_block.IsNull());
        const auto& ka = a.block.mweb_block.m_block->GetTxBody().GetKernels();
        const auto& kb = b.block.mweb_block.m_block->GetTxBody().GetKernels();
        BOOST_REQUIRE_EQUAL(ka.size(), kb.size());
        for (size_t i = 0; i < ka.size(); ++i) {
            BOOST_REQUIRE_MESSAGE(ka[i].GetKernelID() == kb[i].GetKernelID(),
                                  ctx + ": kernel identity mismatch at " + util::ToString(i));
        }
    }
}

void AssertPackageFeeratesNonIncreasing(const CBlockTemplate& tmpl, const std::string& ctx)
{
    const auto& rates = tmpl.m_package_feerates;
    for (size_t i = 1; i < rates.size(); ++i) {
        BOOST_REQUIRE_MESSAGE(ByRatio{rates[i - 1]} >= ByRatio{rates[i]},
                              ctx + ": package feerates increased at index " + util::ToString(i));
    }
}

/** Every equal-or-better non-monster leftover fails WouldFit (underfill OK only then). */
void AssertAllEligibleRemainingUnfittable(const CBlock& block,
                                          const CTxMemPool& pool,
                                          const std::vector<TrackedTx>& mempool_txs,
                                          CAmount min_num, CAmount min_den,
                                          const std::string& ctx)
{
    LOCK(pool.cs);
    const LeftoverBudgets rem = LeftoverBudgetsOf(block);
    const auto included = IncludedHashes(block);
    for (const auto& t : mempool_txs) {
        if (t.is_monster) continue;
        if (t.tx->IsMWEBOnly()) {
            if (TemplateContainsMWEBTx(block, *t.tx)) continue;
        } else if (included.contains(t.hash)) {
            continue;
        }
        const auto* entry = pool.GetEntry(t.hash);
        BOOST_REQUIRE(entry);
        const int64_t adj = std::max<int64_t>(1, entry->GetAdjustedWeight());
        if (min_den > 0 && entry->GetModifiedFee() * min_den < min_num * adj) continue;
        if (WouldFit(*t.tx, rem)) {
            TriggerStop({
                .reason = ctx + ": expected all leftover eligible txs unfittable, but one still fits",
                .rem_l1 = rem.rem_l1,
                .rem_mweb = rem.rem_mweb,
                .rem_ser = rem.rem_ser,
                .first_excluded_fit = t.hash.ToString(),
                .prefer_fewer_inputs_gap = true,
            });
        }
    }
}

size_t TakeBank(std::vector<test::TxOutput>& bank, size_t n, std::vector<test::TxOutput>& out)
{
    const size_t take = std::min(n, bank.size());
    out.clear();
    out.insert(out.end(), bank.end() - static_cast<std::ptrdiff_t>(take), bank.end());
    bank.erase(bank.end() - static_cast<std::ptrdiff_t>(take), bank.end());
    return take;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_block_packing_tests, MWEBRegtest100Setup, * boost::unit_test::precondition(MegaExtendedTestPrecondition))

BOOST_AUTO_TEST_CASE(t5_checkblock_accepts_near_200k_weight_under_cap)
{
    // Dense kernels, few inputs: weight near 200k but wire size under BIP324.
    std::vector<Kernel> kernels;
    kernels.reserve(99'000);
    for (size_t i = 0; i < 99'000; ++i) {
        kernels.emplace_back(
            Kernel::FEE_FEATURE_BIT,
            CAmount{1},
            std::nullopt,
            std::vector<PegOutCoin>{},
            std::nullopt,
            std::nullopt,
            std::vector<uint8_t>{},
            Commitment{},
            Signature{});
    }
    // 99000 * BASE_KERNEL_WEIGHT(2) = 198000 weight; no inputs.
    BOOST_REQUIRE_LE(Weight::Calculate(TxBody({}, {}, kernels)), mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE_GE(Weight::Calculate(TxBody({}, {}, kernels)), 190'000);

    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 50 * COIN;
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    // Non-empty vin required for CheckTransaction (oversize reject tests never reach this).
    hogex.vin.emplace_back(COutPoint{Txid::FromUint256(Uint64Hash(1)), 0}, CScript(), /*nSequence=*/0xffffffff);
    hogex.vout.emplace_back(0, CScript() << OP_8 << std::vector<unsigned char>(32, 0x00));
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));

    auto header = std::make_shared<mw::Header>(
        /*height=*/1,
        mw::Hash{}, mw::Hash{}, mw::Hash{},
        BlindingFactor{}, BlindingFactor{},
        /*outputMMRSize=*/0, /*kernelMMRSize=*/0);
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>(header, TxBody({}, {}, std::move(kernels))));

    BOOST_REQUIRE_LE(::GetSerializeSize(TX_WITH_WITNESS(block)), MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);
    BOOST_REQUIRE_GE(Weight::Calculate(block.mweb_block.m_block->GetTxBody()), 190'000);

    BlockValidationState state;
    BOOST_CHECK_MESSAGE(
        CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false),
        state.ToString());
}


BOOST_AUTO_TEST_CASE(t6_checkblock_rejects_50k_inputs_plus_heavy_weight)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 50 * COIN;
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vout.emplace_back(0, CScript() << OP_8 << std::vector<unsigned char>(32, 0x00));
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));

    const Input sample(0x01, mw::Hash{}, Commitment{}, PublicKey{}, PublicKey{}, Signature{});
    // Fee kernels alone stay well under the BIP324 envelope (MAX_BLOCK_BYTES is a
    // pessimistic bound). Weightless inputs dominate wire size: 132k * 196 B exceeds
    // MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB while L1 stays tiny (same approach as
    // mweb_validation_tests/checkblock_rejects_above_max_mweb_envelope).
    std::vector<Input> inputs(132'000, sample);

    std::vector<Kernel> kernels;
    kernels.reserve(100'000);
    for (size_t i = 0; i < 100'000; ++i) {
        kernels.emplace_back(
            Kernel::FEE_FEATURE_BIT, CAmount{1}, std::nullopt, std::vector<PegOutCoin>{},
            std::nullopt, std::nullopt, std::vector<uint8_t>{}, Commitment{}, Signature{});
    }
    BOOST_REQUIRE_EQUAL(Weight::Calculate(TxBody(inputs, {}, kernels)),
                        Weight::Calculate(TxBody({}, {}, kernels))); // inputs weightless
    BOOST_REQUIRE_EQUAL(Weight::Calculate(TxBody({}, {}, kernels)), 200'000);

    auto header = std::make_shared<mw::Header>(
        1, mw::Hash{}, mw::Hash{}, mw::Hash{}, BlindingFactor{}, BlindingFactor{}, 0, 0);
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>(header, TxBody(std::move(inputs), {}, std::move(kernels))));

    // Consensus envelope test (CheckBlock), not assembler BIP324 cap.
    BOOST_REQUIRE(::GetSerializeSize(TX_WITH_WITNESS(block)) > MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-serialized-size");
}

BOOST_AUTO_TEST_CASE(t4_softcap_regression_mweb_weight_above_20k)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // CreatePegIn weight is ~20; need >1000 to clear the old 20k soft-cap.
    constexpr size_t N = 1200;
    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakePeginTx(COIN + static_cast<CAmount>(i), /*mweb_fee=*/0, /*uniq=*/i + 100);
        const CAmount fee = 10'000;
        Submit(pool, mtx, fee);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), fee, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    const uint64_t w = BlockAssembler::m_last_block_mweb_weight.value_or(BlockMWEBWeight(tmpl->block));
    BOOST_REQUIRE_GT(w, 20'000);
    BOOST_REQUIRE_LE(w, mw::MAX_BLOCK_WEIGHT);
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t1b_weight_binding_architected_fill)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Dense fillers: 1 input + 1 output + many plain kernels (cheap vs bulletproofs).
    constexpr int KERNELS = 4000; // weight 2*4000 + 18 = 8018
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    // Submit raises an entry's fee to the MWEB relay charge. Pay at least that
    // charge in the signed kernels too, so entry and actual fees agree.
    const CAmount fee_per_kernel{(CFeeRate::GetMWEBFee(W_F) + KERNELS - 1) / KERNELS};
    const CAmount fee{KERNELS * fee_per_kernel};
    BOOST_REQUIRE_GE(fee, CFeeRate::GetMWEBFee(W_F));
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F; // floor → 24
    BOOST_REQUIRE_GT(N, 0u);
    BOOST_REQUIRE((N + 1) * W_F > mw::MAX_BLOCK_WEIGHT);

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N + 1 + 2, COIN);
    BOOST_REQUIRE_EQUAL(utxos.size(), N + 1 + 2);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    tracked.reserve(N + 1 + 2);

    for (size_t i = 0; i < N + 1; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, fee_per_kernel);
        BOOST_REQUIRE_EQUAL(TxMWEBWeight(CTransaction(mtx)), W_F);
        BOOST_REQUIRE_EQUAL(*MWEB::Tx(mtx.mweb_tx).GetFee(), fee);
        Submit(pool, mtx, fee);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), fee, false, true});
    }

    // K>=2 high-feerate synthetic monsters (unfittable alone via input count).
    for (int k = 0; k < 2; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(/*n_inputs=*/90'000, /*entry_fee_hint=*/1'000'000, static_cast<uint64_t>(k+1));
        const CAmount fee = 1'000'000; // higher than fillers
        Submit(pool, mon, fee);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), fee, true, false});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);

    const uint64_t w = BlockAssembler::m_last_block_mweb_weight.value_or(BlockMWEBWeight(tmpl->block));
    BOOST_REQUIRE_GT(w, 20'000);

    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, /*fillers_only=*/true);
    const size_t n_mon = CountIncludedMonsters(tmpl->block, tracked);
    BOOST_CHECK_EQUAL(n_mon, 0u);
    BOOST_CHECK_EQUAL(n_fill, N);

    // All selected fillers are pure MWEB. Cumulative weight selection must
    // pay their actual kernel fees once, on HogEx and in the coinbase reward.
    const CAmount selected_fees{static_cast<CAmount>(N) * fee};
    BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2U);
    BOOST_REQUIRE(tmpl->block.mweb_block.GetTotalFee().has_value());
    BOOST_CHECK_EQUAL(*tmpl->block.mweb_block.GetTotalFee(), selected_fees);
    BOOST_CHECK(tmpl->vTxFees == std::vector<CAmount>{selected_fees});
    BOOST_CHECK_EQUAL(tmpl->block.vtx.front()->GetValueOut(),
                      GetBlockSubsidy(chainstate.m_chain.Height() + 1, Params().GetConsensus()) + selected_fees);

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    {
        const size_t exact = ExactBlockSize(tmpl->block);
        const uint64_t mw = BlockMWEBWeight(tmpl->block);
        BOOST_TEST_MESSAGE("T1b fill metrics: exact_ser=" << exact << " ("
                           << (100.0 * exact / MAX_BLOCK_SERIALIZED_SIZE_BIP324) << "% of BIP324 cap) "
                           << "mweb_weight=" << mw << " (" << (100.0 * mw / mw::MAX_BLOCK_WEIGHT)
                           << "% of 200k) rem_ser=" << rem.rem_ser << " rem_mweb=" << rem.rem_mweb);
    }
    AssertNearCapWeight(rem, W_F, "T1b");

    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1b");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t1a_size_binding_architected_fill)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Size-oriented consolidations. Full BIP324 ceiling needs ~80k UTXOs; keep a
    // CI-friendly set and assert monsters excluded + NO_GAP / optional NEAR_CAP.
    constexpr size_t INPUTS_PER = 2;
    constexpr size_t TARGET_FILLERS = 12;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, INPUTS_PER * (TARGET_FILLERS + 1), COIN);
    DrainMempool(m_node);

    auto make_filler = [&](size_t idx) {
        std::vector<test::TxOutput> ins;
        ins.reserve(INPUTS_PER);
        for (size_t j = 0; j < INPUTS_PER; ++j) {
            ins.push_back(utxos[idx * INPUTS_PER + j]);
        }
        return MakeConsolidation(ins, /*plain_kernels=*/1, /*fee_per_kernel=*/1000);
    };

    CMutableTransaction probe = make_filler(0);
    const size_t S_f = MWEB::Miner::EstimateTxMWEBBodyBytes(CTransaction(probe)) +
                       MWEB::Miner::EstimateTxHogExDeltaBytes(CTransaction(probe));
    BOOST_REQUIRE_GT(S_f, 0u);

    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < TARGET_FILLERS + 1; ++i) {
        CMutableTransaction mtx = (i == 0) ? probe : make_filler(i);
        const CAmount fee = 1000;
        Submit(pool, mtx, fee);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), fee, false, true});
    }
    for (int k = 0; k < 2; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(90'000, 50'000, static_cast<uint64_t>(k + 100));
        Submit(pool, mon, /*fee=*/50'000);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 50'000, true, false});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);

    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, true);
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    {
        const size_t exact = ExactBlockSize(tmpl->block);
        const uint64_t mw = BlockMWEBWeight(tmpl->block);
        BOOST_TEST_MESSAGE("T1a fill metrics: n_fill=" << n_fill << " S_f=" << S_f
                           << " exact_ser=" << exact << " ("
                           << (100.0 * exact / MAX_BLOCK_SERIALIZED_SIZE_BIP324) << "% of BIP324 cap) "
                           << "mweb_weight=" << mw << " (" << (100.0 * mw / mw::MAX_BLOCK_WEIGHT)
                           << "% of 200k) rem_ser=" << rem.rem_ser << " rem_mweb=" << rem.rem_mweb);
    }

    const bool extra_excluded = n_fill == TARGET_FILLERS;
    const bool all_fit = n_fill == TARGET_FILLERS + 1;
    if (all_fit) {
        BOOST_TEST_MESSAGE("T1a note: injected fillers all fit under BIP324 (UTXO-limited set); "
                           "full size-ceiling NEAR_CAP needs EXTENDED UTXO scale.");
        AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1a");
    } else if (extra_excluded) {
        AssertNearCapSer(rem, S_f, "T1a");
        AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1a");
    } else {
        TriggerStop({
            .reason = "T1a: unexpected filler include count " + util::ToString(n_fill),
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .consecutive_failure_suspicion = true,
            .prefer_fewer_inputs_gap = true,
        });
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t7_estimate_vs_exact_after_create_new_block)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    for (size_t i = 0; i < 40; ++i) {
        Submit(pool, MakePeginTx(COIN + static_cast<CAmount>(i), 0, i + 500), /*fee=*/5000);
    }
    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    const size_t exact = ExactBlockSize(tmpl->block);
    BOOST_REQUIRE_LE(exact, MAX_BLOCK_SERIALIZED_SIZE_BIP324);

    // Recompute a pessimistic estimate from included extension components.
    size_t estimate = 80 + 9 + MWEB::BLOCK_SERIALIZED_COINBASE_RESERVE;
    if (!tmpl->block.mweb_block.IsNull()) {
        // Header/wrapper pad + body serialize + hogex present.
        estimate += 256;
        estimate += tmpl->block.mweb_block.m_block->GetTxBody().Serialized().size();
        estimate += 200; // hogex rough pad
    }
    for (const auto& tx : tmpl->block.vtx) {
        if (!tx || tx->IsCoinBase() || tx->IsHogEx()) continue;
        estimate += ::GetSerializeSize(TX_WITH_WITNESS(*tx)) + 9;
    }
    BOOST_CHECK_GE(estimate, exact);
}

BOOST_AUTO_TEST_CASE(t8_high_feerate_monsters_must_not_starve_fillers)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // High-feerate always-unfittable monsters (skip via size gate) must not prevent
    // packing lower-feerate fillers. Submit fillers first so mempool size limits do
    // not exclude them when large monster bodies are present.
    constexpr int N_MON = 8;
    constexpr int N_FILL = 80;
    std::vector<TrackedTx> tracked;

    for (int i = 0; i < N_FILL; ++i) {
        CMutableTransaction mtx = MakePeginTx(COIN + i, 0, static_cast<uint64_t>(i + 9000));
        Submit(pool, mtx, /*fee=*/50'000);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 50'000, false, true});
    }
    BOOST_REQUIRE_GE(pool.size(), static_cast<size_t>(N_FILL));

    for (int i = 0; i < N_MON; ++i) {
        CMutableTransaction mon = MakeSyntheticMonster(/*n_inputs=*/90'000, 100'000, static_cast<uint64_t>(i + 200));
        Submit(pool, mon, /*fee=*/100'000);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 100'000, true, false});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);

    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, true);
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    if (n_fill == 0) {
        TriggerStop({
            .reason = "T8: high-feerate monsters starved all fillers",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .consecutive_failure_suspicion = true,
            .prefer_fewer_inputs_gap = true,
        });
    }
    BOOST_REQUIRE_GT(n_fill, 0u);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);

    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T8");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t2_four_x_oversubscribed_stress)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    DrainMempool(m_node);

    constexpr int KERNELS = 4000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N_mweb_fit = mw::MAX_BLOCK_WEIGHT / W_F;
    const size_t n_mweb = 4 * N_mweb_fit;
    BOOST_REQUIRE_GE(n_mweb, 4u);

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, n_mweb, COIN);
    DrainMempool(m_node);
    std::vector<TrackedTx> tracked;

    for (size_t i = 0; i < n_mweb; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, /*fee=*/KERNELS);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), KERNELS, false, true});
    }

    constexpr size_t N_l1_fit_approx = 500;
    for (size_t i = 0; i < 4 * N_l1_fit_approx; ++i) {
        CMutableTransaction mtx = MakeL1Filler(i + 1, /*fee=*/1000);
        Submit(pool, mtx, 1000);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 1000, false, false});
    }

    for (int k = 0; k < 5; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(90'000, 500'000, static_cast<uint64_t>(k + 300));
        Submit(pool, mon, 500'000);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 500'000, true, false});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);
    BOOST_REQUIRE_GT(CountIncludedTracked(tmpl->block, tracked, true), 0u);

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    {
        const size_t exact = ExactBlockSize(tmpl->block);
        const uint64_t mw = BlockMWEBWeight(tmpl->block);
        BOOST_TEST_MESSAGE("T2 fill metrics: exact_ser=" << exact << " ("
                           << (100.0 * exact / MAX_BLOCK_SERIALIZED_SIZE_BIP324) << "% of BIP324 cap) "
                           << "mweb_weight=" << mw << " (" << (100.0 * mw / mw::MAX_BLOCK_WEIGHT)
                           << "% of 200k) rem_ser=" << rem.rem_ser << " rem_mweb=" << rem.rem_mweb
                           << " n_mweb_queued=" << n_mweb);
    }
    AssertNearCapWeight(rem, W_F, "T2");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T2");
    AssertPackageFeeratesNonIncreasing(*tmpl, "T2");

    auto tmpl2 = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl2);
    AssertNeverExceed(tmpl2->block);
    AssertTemplatesEquivalent(*tmpl, *tmpl2, "T2");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t3_randomized_packing_stress)
{
    MineToMwebChain(*this, m_node);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    CTxMemPool& pool = *Assert(m_node.mempool);

    constexpr uint32_t SEED = 0xC0FFEE42;
    constexpr int ITERS = 20;
    std::mt19937 rng(SEED);

    // Shared UTXO bank for consolidations / variable input counts.
    std::vector<test::TxOutput> bank = MinePegins(*this, m_node, 128, COIN);
    DrainMempool(m_node);
    size_t bank_cursor = 0;

    for (int iter = 0; iter < ITERS; ++iter) {
        DrainMempool(m_node);
        // Refresh bank periodically.
        if (bank_cursor + 64 > bank.size()) {
            bank = MinePegins(*this, m_node, 128, COIN);
            bank_cursor = 0;
            DrainMempool(m_node);
        }

        std::vector<TrackedTx> tracked;
        const int n_pegin = 40 + static_cast<int>(rng() % 40);
        const int n_cons = 5 + static_cast<int>(rng() % 10);

        for (int i = 0; i < n_pegin; ++i) {
            auto mtx = MakePeginTx(COIN + iter * 1000 + i, 0, static_cast<uint64_t>(iter * 10000 + i));
            const CAmount fee = 50'000 + static_cast<CAmount>(rng() % 5000);
            Submit(pool, mtx, fee);
            tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), fee, false, true});
        }
        for (int i = 0; i < n_cons; ++i) {
            const int n_in = 1 + static_cast<int>(rng() % 4);
            std::vector<test::TxOutput> ins;
            for (int j = 0; j < n_in && bank_cursor < bank.size(); ++j) {
                ins.push_back(bank[bank_cursor++]);
            }
            if (ins.empty()) break;
            const int kernels = 10 + static_cast<int>(rng() % 200);
            auto mtx = MakeConsolidation(ins, kernels, 1);
            Submit(pool, mtx, kernels);
            tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), kernels, false, true});
        }
        // One always-unfittable monster (same shape as T1/T8).
        {
            auto mon = MakeSyntheticMonster(/*n_inputs=*/90'000, 50'000, static_cast<uint64_t>(iter + 400));
            Submit(pool, mon, 50'000);
            tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 50'000, true, false});
        }

        std::unique_ptr<CBlockTemplate> tmpl;
        try {
            tmpl = BuildTemplate(chainstate, pool);
        } catch (const std::exception& e) {
            BOOST_REQUIRE_MESSAGE(false, "T3 seed=0x" << std::hex << SEED << " iter=" << std::dec << iter
                                                      << " CreateNewBlock threw: " << e.what());
        }
        BOOST_REQUIRE(tmpl);
        AssertNeverExceed(tmpl->block);
        BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);

        // Equal-feerate band NO_GAP_WEAK among pegins with fee>=1000.
        AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T3 seed=0xC0FFEE42 iter=" + util::ToString(iter));
    }
}

BOOST_AUTO_TEST_CASE(t1a_extended_size_binding_near_cap)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    std::vector<test::TxOutput> bank = MineFanoutUTXOs(*this, m_node, MIN_EXTENDED_UTXOS);
    BOOST_REQUIRE_GT(bank.size(), 80'000u);
    DrainMempool(m_node);

    // Size-binding larges + lower-fee small end-fillers (picked up by residual /
    // post-large primary walk). Keep end-fill input-light so the 50k cap does
    // not bind before BIP324.
    constexpr size_t INPUTS_PER = 1'200;
    constexpr int KERNELS = 1'700;
    constexpr CAmount FEE_PER_KERNEL = 1;
    constexpr CAmount FILLER_FEE = KERNELS * FEE_PER_KERNEL;
    constexpr size_t TAIL_INPUTS = 2;
    constexpr int TAIL_KERNELS = 1;
    constexpr CAmount TAIL_FEE = 1; // lower absolute fee → after larges
    constexpr size_t N_TAILS = 200;
    constexpr size_t INPUT_HEADROOM_FOR_TAILS = TAIL_INPUTS * N_TAILS;

    std::vector<test::TxOutput> probe_ins;
    BOOST_REQUIRE_EQUAL(TakeBank(bank, INPUTS_PER, probe_ins), INPUTS_PER);
    CMutableTransaction probe = MakeConsolidation(probe_ins, KERNELS, FEE_PER_KERNEL);
    const size_t S_f = EstimateSerDelta(CTransaction(probe));
    const uint64_t W_f = TxMWEBWeight(CTransaction(probe));
    BOOST_REQUIRE_GT(S_f, 64 * 1024u);
    BOOST_REQUIRE_LT(W_f, mw::MAX_BLOCK_WEIGHT);

    const size_t usable = MAX_BLOCK_SERIALIZED_SIZE_BIP324 - 32 * 1024;
    size_t n_large = usable / S_f;
    if (n_large < 2) n_large = 2;
    while (n_large > 1 && (n_large * INPUTS_PER + INPUT_HEADROOM_FOR_TAILS > mw::MAX_NUM_INPUTS ||
                           n_large * W_f > mw::MAX_BLOCK_WEIGHT)) {
        --n_large;
    }
    BOOST_REQUIRE_GE(n_large, 2u);
    BOOST_REQUIRE_LE(n_large * INPUTS_PER + INPUT_HEADROOM_FOR_TAILS, mw::MAX_NUM_INPUTS);

    std::vector<test::TxOutput> tail_probe_ins;
    BOOST_REQUIRE_EQUAL(TakeBank(bank, TAIL_INPUTS, tail_probe_ins), TAIL_INPUTS);
    CMutableTransaction tail_probe = MakeConsolidation(tail_probe_ins, TAIL_KERNELS, FEE_PER_KERNEL);
    const size_t S_tail = EstimateSerDelta(CTransaction(tail_probe));
    BOOST_REQUIRE_LT(S_tail, S_f);
    BOOST_REQUIRE_GT(S_tail, 0u);
    BOOST_REQUIRE_LT(TAIL_FEE, FILLER_FEE);

    std::vector<TrackedTx> tracked;
    tracked.push_back({probe.GetHash(), MakeTransactionRef(probe), FILLER_FEE, false, true});
    Submit(pool, probe, FILLER_FEE);

    for (size_t i = 1; i < n_large; ++i) {
        std::vector<test::TxOutput> ins;
        BOOST_REQUIRE_EQUAL(TakeBank(bank, INPUTS_PER, ins), INPUTS_PER);
        CMutableTransaction mtx = MakeConsolidation(ins, KERNELS, FEE_PER_KERNEL);
        Submit(pool, mtx, FILLER_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), FILLER_FEE, false, true});
    }

    Submit(pool, tail_probe, TAIL_FEE);
    tracked.push_back({tail_probe.GetHash(), MakeTransactionRef(tail_probe), TAIL_FEE, false, true});
    size_t n_tails = 1;
    for (size_t i = 1; i < N_TAILS; ++i) {
        std::vector<test::TxOutput> ins;
        if (TakeBank(bank, TAIL_INPUTS, ins) < TAIL_INPUTS) break;
        CMutableTransaction mtx = MakeConsolidation(ins, TAIL_KERNELS, FEE_PER_KERNEL);
        Submit(pool, mtx, TAIL_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), TAIL_FEE, false, true});
        ++n_tails;
    }
    BOOST_REQUIRE_GE(n_tails, 80u);

    for (int k = 0; k < 2; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(90'000, 500'000, static_cast<uint64_t>(k + 1200));
        Submit(pool, mon, 500'000);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 500'000, true, false});
    }

    BOOST_REQUIRE_GT(bank.size(), 0u); // leftover UTXOs prove >80k scale beyond spends

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);
    {
        const size_t inputs = BlockMWEBInputCount(tmpl->block);
        if (inputs > mw::MAX_NUM_INPUTS) {
            const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
            TriggerStop({
                .reason = "T1a-EXT: template exceeds mw::MAX_NUM_INPUTS (assembler missing input-count gate)",
                .rem_l1 = rem.rem_l1,
                .rem_mweb = rem.rem_mweb,
                .rem_ser = rem.rem_ser,
                .first_excluded_fit = strprintf("mweb_inputs=%u > %u", inputs, mw::MAX_NUM_INPUTS),
                .consecutive_failure_suspicion = false,
                .prefer_fewer_inputs_gap = true,
            });
        }
    }

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, true);
    LogFillMetrics("T1a-EXT", tmpl->block, rem, n_fill, S_f);

    // Serialized size must be the binding budget (weight still has room for another dense filler).
    BOOST_REQUIRE_MESSAGE(rem.rem_ser < static_cast<int64_t>(S_f) || rem.rem_ser < static_cast<int64_t>(S_tail) * 2,
                          "T1a-EXT: expected serialized size to bind");
    BOOST_REQUIRE_GT(n_fill, 0u);

    // One-typical-tx fullness on the small-tail scale.
    AssertNearCapSer(rem, S_tail, "T1a-EXT");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1a-EXT");

    // Estimate pessimism must not strand a fitting tail.
    size_t body_sum = 0;
    if (!tmpl->block.mweb_block.IsNull() && tmpl->block.mweb_block.m_block) {
        const size_t merged = tmpl->block.mweb_block.m_block->GetTxBody().Serialized().size();
        for (const auto& t : tracked) {
            if (!t.is_filler || t.is_monster) continue;
            if (TemplateContainsMWEBTx(tmpl->block, *t.tx)) {
                body_sum += MWEB::Miner::EstimateTxMWEBBodyBytes(*t.tx);
            }
        }
        BOOST_CHECK_GE(body_sum, merged);
    }

    auto tmpl2 = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl2);
    AssertTemplatesEquivalent(*tmpl, *tmpl2, "T1a-EXT");
    DrainMempool(m_node);
}

/**
 * A serialized-cap candidate must be chosen from genuinely eligible alternatives,
 * not a one-block recipe plus oversized synthetic transactions. Both fee markets
 * have work, and the same confirmed bank supports each independent backlog size.
 */
BOOST_FIXTURE_TEST_CASE(serialized_cap_with_two_three_five_blocks_of_eligible_alternatives, MWEBCompetingPackingSetup)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    CTxMemPool& pool = *Assert(m_node.mempool);
    BOOST_REQUIRE(pool.m_opts.require_standard);
    constexpr uint32_t SEED = 0x235B1F39;
    constexpr size_t BANK_SIZE = 250'000;
    constexpr size_t L1_BANK_SIZE = 2'000;
    constexpr size_t N_TAILS = 1'000;
    const std::vector<test::TxOutput> bank = MineFanoutUTXOs(*this, m_node, BANK_SIZE);
    DrainMempool(m_node);

    // Confirm three types of signable L1 funding outputs once. Taproot is also
    // represented among recipient outputs, without inventing another signer.
    FillableSigningProvider keys;
    keys.AddKey(coinbaseKey);
    const CPubKey pubkey = coinbaseKey.GetPubKey();
    const CScript wpkh = GetScriptForDestination(WitnessV0KeyHash{pubkey});
    keys.AddCScript(wpkh);
    const std::vector<CScript> input_scripts{
        GetScriptForDestination(PKHash{pubkey}), wpkh, GetScriptForDestination(ScriptHash{wpkh})};
    std::vector<CScript> recipient_scripts = input_scripts;
    recipient_scripts.push_back(GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{pubkey}}));
    constexpr CAmount L1_COIN = 9'000'000;
    constexpr CAmount FUND_FEE = 100'000;
    std::vector<CMutableTransaction> funding_txs;
    constexpr size_t FUNDING_BATCH = 500;
    for (size_t begin = 0; begin < L1_BANK_SIZE; begin += FUNDING_BATCH) {
        const CTransactionRef& coinbase = m_coinbase_txns.at(1 + begin / FUNDING_BATCH);
        {
            LOCK(::cs_main);
            const auto coin = chainstate.CoinsTip().GetCoin(COutPoint{coinbase->GetHash(), 0});
            BOOST_REQUIRE_MESSAGE(coin, "L1 funding coinbase was spent during MWEB bank setup");
            BOOST_REQUIRE(coin->fCoinBase);
            BOOST_REQUIRE_GT(coin->out.nValue, L1_COIN * FUNDING_BATCH + FUND_FEE);
        }
        std::vector<CTxOut> outputs;
        for (size_t i = begin; i < begin + FUNDING_BATCH; ++i) {
            outputs.emplace_back(L1_COIN, input_scripts[i % input_scripts.size()]);
        }
        outputs.emplace_back(coinbase->vout.at(0).nValue - L1_COIN * FUNDING_BATCH - FUND_FEE,
                             input_scripts.front());
        funding_txs.push_back(CreateValidTransaction(
            {coinbase}, {COutPoint{coinbase->GetHash(), 0}}, 1, {coinbaseKey},
            outputs, std::nullopt, std::nullopt).first);
    }
    const auto funding_outpoint = [&](size_t index) {
        return COutPoint{funding_txs.at(index / FUNDING_BATCH).GetHash(), static_cast<uint32_t>(index % FUNDING_BATCH)};
    };
    const auto funding_coin = [&](size_t index) -> const CTxOut& {
        return funding_txs.at(index / FUNDING_BATCH).vout.at(index % FUNDING_BATCH);
    };
    const auto admit = [&](const CMutableTransaction& tx) {
        LOCK2(::cs_main, pool.cs);
        const MempoolAcceptResult result = Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(tx));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              "real admission rejected " << tx.GetHash().ToString() << ": " << result.m_state.ToString());
    };
    for (const auto& tx : funding_txs) admit(tx);
    MineUntilMempoolEmpty(m_node);
    const int funding_height = WITH_LOCK(::cs_main, return chainstate.m_chain.Height());

    for (const size_t blocks : {2U, 3U, 5U}) {
        DrainMempool(m_node);
        std::mt19937 rng(SEED + blocks);
        std::vector<TrackedTx> tracked;
        std::map<Txid, std::set<Txid>> parents;
        std::map<Txid, std::pair<size_t, size_t>> l1_shapes;
        size_t queued_bytes{0}, l1_weight{0}, bank_cursor{0}, l1_cursor{0};
        size_t n_l1{0}, n_mweb{0};
        std::set<size_t> seen_input_types, seen_output_types, seen_return_counts, seen_return_lengths;
        const auto track = [&](const CMutableTransaction& tx, CAmount fee) {
            admit(tx);
            if (tx.HasMWEBTx()) {
                BOOST_REQUIRE(tx.IsMWEBOnly());
                CAmount kernel_fees{0};
                for (const auto& kernel : tx.mweb_tx.kernels) kernel_fees += kernel.fee.value_or(0);
                BOOST_REQUIRE_EQUAL(kernel_fees, fee);
            }
            queued_bytes += ::GetSerializeSize(TX_WITH_WITNESS(tx));
            tracked.push_back({tx.GetHash(), MakeTransactionRef(tx), fee, false, true});
        };
        // This fixture has only canonical and pure-MWEB transactions. Measure
        // their append costs directly, independently of the miner estimators.
        const auto would_fit = [](const CTransaction& tx, const LeftoverBudgets& rem) {
            int64_t l1{0}, mweb{0}, serialized{0}, inputs{0};
            if (tx.HasMWEBTx()) {
                BOOST_REQUIRE(tx.IsMWEBOnly());
                const auto& body = tx.mweb_tx.m_transaction->GetBody();
                BOOST_REQUIRE(body.GetPegIns().empty());
                BOOST_REQUIRE(body.GetPegOuts().empty());
                mweb = Weight::Calculate(body);
                inputs = body.GetInputs().size();
                // Per-body vector counts retain the declared pessimism; these
                // transactions change HogEx values without growing its encoding.
                serialized = body.Serialized().size();
            } else {
                const int64_t wire = ::GetSerializeSize(TX_WITH_WITNESS(tx));
                l1 = 3 * static_cast<int64_t>(::GetSerializeSize(TX_NO_WITNESS(tx))) + wire;
                serialized = wire + 9; // conservative block transaction-count growth
            }
            return l1 <= rem.rem_l1 && mweb <= rem.rem_mweb &&
                   serialized <= rem.rem_ser && inputs <= rem.rem_inputs;
        };
        const auto sign_l1 = [&](CMutableTransaction& tx, const COutPoint& prevout, const CTxOut& coin, int height) {
            std::map<COutPoint, Coin> coins{{prevout, Coin{coin, height, false}}};
            std::map<int, bilingual_str> errors;
            BOOST_REQUIRE(SignTransaction(tx, &keys, coins, {.sighash_type = SIGHASH_ALL}, errors));
            BOOST_REQUIRE(errors.empty());
        };

        // At least this many blocks of standard L1 weight participate too. Input
        // and output script types and one/two OP_RETURN payloads vary by seed.
        while (l1_weight < blocks * MAX_BLOCK_WEIGHT) {
            BOOST_REQUIRE_LT(l1_cursor, L1_BANK_SIZE);
            const size_t index = l1_cursor++;
            const size_t output_type = rng() % recipient_scripts.size();
            const size_t returns = 1 + rng() % 2;
            CMutableTransaction tx;
            const COutPoint prevout = funding_outpoint(index);
            tx.vin.emplace_back(prevout);
            tx.vout.emplace_back(L1_COIN, recipient_scripts[output_type]);
            for (size_t i = 0; i < returns; ++i) {
                const size_t length = 1'024 + rng() % 3'073;
                tx.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(length, static_cast<unsigned char>(rng())));
                seen_return_lengths.insert(length);
            }
            // Pay from actual inputs at a competing L1 rate. The bounded 600-WU
            // signature allowance covers all three signing forms without fee hints.
            const CAmount fee = (GetTransactionWeight(CTransaction(tx)) + 600) * (200 + rng() % 51);
            BOOST_REQUIRE_LT(fee, L1_COIN - 1'000);
            tx.vout.at(0).nValue -= fee;
            sign_l1(tx, prevout, funding_coin(index), funding_height);
            l1_weight += GetTransactionWeight(CTransaction(tx));
            track(tx, fee);
            l1_shapes.emplace(tx.GetHash(), std::pair{index % input_scripts.size(), output_type});
            seen_input_types.insert(index % input_scripts.size());
            seen_output_types.insert(output_type);
            seen_return_counts.insert(returns);
            ++n_l1;
        }

        // Add actual signed parent/child dependencies in the L1 market. The
        // parent's destination remains a known signing type for its child.
        for (size_t i = 0; i < 4; ++i) {
            BOOST_REQUIRE_LT(l1_cursor, L1_BANK_SIZE);
            const size_t index = l1_cursor++;
            CMutableTransaction parent;
            const COutPoint source = funding_outpoint(index);
            parent.vin.emplace_back(source);
            parent.vout.emplace_back(L1_COIN - 400'000, input_scripts.at(i % input_scripts.size()));
            sign_l1(parent, source, funding_coin(index), funding_height);
            track(parent, 400'000);
            CMutableTransaction child;
            const COutPoint parent_out{parent.GetHash(), 0};
            child.vin.emplace_back(parent_out);
            child.vout.emplace_back(L1_COIN - 800'000, recipient_scripts.at(i % recipient_scripts.size()));
            sign_l1(child, parent_out, parent.vout.at(0), MEMPOOL_HEIGHT);
            track(child, 400'000);
            parents[child.GetHash()].insert(parent.GetHash());
            n_l1 += 2;
        }

        // Real admitted MWEB bodies, each within the 1,000-input/4,000-weight
        // relay limits. One/two/three outputs exercise differing change shapes.
        while (queued_bytes < blocks * MAX_BLOCK_SERIALIZED_SIZE_BIP324) {
            const size_t n_inputs = 850 + rng() % 151;
            const int kernels = 1'500 + rng() % 401;
            const size_t n_outputs = 1 + rng() % 3;
            const CAmount per_kernel = 300 + rng() % 101;
            const CAmount fee = kernels * per_kernel;
            BOOST_REQUIRE_LE(bank_cursor + n_inputs + N_TAILS, bank.size());
            test::TxBuilder builder;
            CAmount amount{0};
            for (size_t j = 0; j < n_inputs; ++j) {
                const auto& coin = bank.at(bank_cursor++);
                builder.AddInput(coin);
                amount += coin.GetAmount();
            }
            BOOST_REQUIRE_GT(amount, fee + static_cast<CAmount>(n_outputs));
            CAmount remaining = amount - fee;
            for (size_t j = 0; j < n_outputs; ++j) {
                const CAmount part = remaining / static_cast<CAmount>(n_outputs - j);
                builder.AddOutput(part);
                remaining -= part;
            }
            for (int j = 0; j < kernels; ++j) builder.AddPlainKernel(per_kernel);
            CMutableTransaction tx;
            tx.mweb_tx = mw::MutableTx::From(*builder.Build().GetTransaction());
            BOOST_REQUIRE_LE(TxMWEBWeight(CTransaction(tx)), 4'000U);
            track(tx, fee);
            ++n_mweb;
        }
        std::set<Txid> tails;
        for (size_t i = 0; i < N_TAILS; ++i) {
            BOOST_REQUIRE_LT(bank_cursor, bank.size());
            constexpr CAmount TAIL_FEE = 2'100; // above admission floor, below bulk MWEB feerates
            CMutableTransaction tail = MakeConsolidation({bank.at(bank_cursor++)}, 1, TAIL_FEE);
            track(tail, TAIL_FEE);
            tails.insert(tail.GetHash());
            ++n_mweb;
        }
        BOOST_REQUIRE_GE(queued_bytes, blocks * MAX_BLOCK_SERIALIZED_SIZE_BIP324);
        BOOST_REQUIRE_EQUAL(seen_input_types.size(), input_scripts.size());
        BOOST_REQUIRE_EQUAL(seen_output_types.size(), recipient_scripts.size());
        BOOST_REQUIRE_EQUAL(seen_return_counts.size(), 2U);
        BOOST_REQUIRE_GT(seen_return_lengths.size(), 20U);
        BOOST_REQUIRE_EQUAL(pool.size(), tracked.size()); // no eviction or silent replacement

        BlockCreateOptions options;
        options.test_block_validity = true;
        options.coinbase_output_script = P2WSH_OP_TRUE;
        options.block_min_fee_rate = CFeeRate{0};
        std::unique_ptr<CBlockTemplate> candidate;
        BOOST_REQUIRE_NO_THROW(candidate = BlockAssembler(chainstate, &pool, options).CreateNewBlock());
        BOOST_REQUIRE(candidate);
        AssertNeverExceed(candidate->block);
        BOOST_REQUIRE_LE(BlockMWEBInputCount(candidate->block), mw::MAX_NUM_INPUTS);
        const LeftoverBudgets actual = LeftoverBudgetsOf(candidate->block);
        BOOST_REQUIRE_GT(actual.rem_inputs, 1'000); // serialized size, not the input count, binds MWEB
        BOOST_REQUIRE_GT(actual.rem_mweb, 4'000);
        BOOST_REQUIRE_EQUAL(pool.size(), tracked.size()); // template validation consumes no inventory
        {
            LOCK(pool.cs);
            for (const auto& tx : tracked) {
                const auto* entry = pool.GetEntry(tx.hash);
                BOOST_REQUIRE(entry);
                BOOST_REQUIRE_EQUAL(entry->GetFee(), tx.fee);
            }
        }
        BOOST_REQUIRE_EQUAL(WITH_LOCK(::cs_main, return chainstate.m_chain.Height()), funding_height);
        const auto included = IncludedHashes(candidate->block);
        const auto is_included = [&](const TrackedTx& tx) {
            return tx.tx->IsMWEBOnly() ? TemplateContainsMWEBTx(candidate->block, *tx.tx) : included.contains(tx.hash);
        };
        size_t selected_l1{0}, selected_mweb{0}, selected_tails{0}, selected_children{0}, excluded{0}, selected_body_sum{0};
        size_t selected_inputs{0}, selected_outputs{0}, selected_kernels{0};
        std::set<mw::Hash> expected_inputs, expected_outputs, expected_kernels;
        std::set<size_t> selected_input_types, selected_output_types;
        for (const auto& tx : tracked) {
            if (!is_included(tx)) continue;
            if (tx.tx->IsMWEBOnly()) {
                ++selected_mweb;
                const auto& body = tx.tx->mweb_tx.m_transaction->GetBody();
                selected_body_sum += body.Serialized().size();
                selected_inputs += body.GetInputs().size();
                selected_outputs += body.GetOutputs().size();
                selected_kernels += body.GetKernels().size();
                for (const auto& input : body.GetInputs()) expected_inputs.insert(input.GetOutputID());
                for (const auto& output : body.GetOutputs()) expected_outputs.insert(output.GetOutputID());
                for (const auto& kernel : body.GetKernels()) expected_kernels.insert(kernel.GetKernelID());
                selected_tails += tails.contains(tx.hash);
            } else {
                ++selected_l1;
                if (const auto shape = l1_shapes.find(tx.hash); shape != l1_shapes.end()) {
                    selected_input_types.insert(shape->second.first);
                    selected_output_types.insert(shape->second.second);
                }
            }
            if (auto it = parents.find(tx.hash); it != parents.end()) {
                ++selected_children;
                for (const auto& parent : it->second) BOOST_REQUIRE(included.contains(parent));
            }
        }
        BOOST_REQUIRE(candidate->block.mweb_block.m_block);
        BOOST_REQUIRE_EQUAL(candidate->block.vtx.size(), selected_l1 + 2); // coinbase and HogEx
        const auto& merged_body = candidate->block.mweb_block.m_block->GetTxBody();
        const auto actual_inputs = merged_body.GetSpentIDs();
        const auto actual_outputs = merged_body.GetOutputIDs();
        const auto actual_kernels = merged_body.GetKernelIDs();
        BOOST_REQUIRE_EQUAL(expected_inputs.size(), selected_inputs);
        BOOST_REQUIRE_EQUAL(expected_outputs.size(), selected_outputs);
        BOOST_REQUIRE_EQUAL(expected_kernels.size(), selected_kernels);
        BOOST_REQUIRE_EQUAL(actual_inputs.size(), selected_inputs);
        BOOST_REQUIRE_EQUAL(actual_outputs.size(), selected_outputs);
        BOOST_REQUIRE_EQUAL(actual_kernels.size(), selected_kernels);
        BOOST_REQUIRE((expected_inputs == std::set<mw::Hash>{actual_inputs.begin(), actual_inputs.end()}));
        BOOST_REQUIRE((expected_outputs == std::set<mw::Hash>{actual_outputs.begin(), actual_outputs.end()}));
        BOOST_REQUIRE((expected_kernels == std::set<mw::Hash>{actual_kernels.begin(), actual_kernels.end()}));
        const size_t merged_body_size = merged_body.Serialized().size();
        BOOST_REQUIRE_GE(selected_body_sum, merged_body_size);
        // Independent serialization measurements explain the declared pessimism:
        // coinbase reserve, 9 bytes per L1 append, unmerged MWEB vector counts,
        // and fixed header/wrapper/CompactSize allowances. No estimator seam or
        // exact-byte promise is added. Inputs are disjoint, so there is no cut-through.
        const int64_t serialized_headroom = MWEB::BLOCK_SERIALIZED_COINBASE_RESERVE + 9 * selected_l1 +
                                           (selected_body_sum - merged_body_size) + 512;
        const size_t tail_delta = tracked.back().tx->mweb_tx.m_transaction->GetBody().Serialized().size();
        BOOST_REQUIRE_LT(selected_tails, N_TAILS); // a real small alternative remains available
        BOOST_REQUIRE_MESSAGE(actual.rem_ser < serialized_headroom + static_cast<int64_t>(tail_delta),
                              "serialized-cap underfill beyond declared reserves and one available tail: "
                              << actual.rem_ser << " reserve=" << serialized_headroom << " tail=" << tail_delta);
        LeftoverBudgets usable = actual;
        usable.rem_ser = std::max<int64_t>(0, usable.rem_ser - serialized_headroom);
        bool sensitivity_control{false};
        for (const auto& tx : tracked) {
            if (is_included(tx)) continue;
            ++excluded;
            bool dependencies_satisfied{true};
            if (auto it = parents.find(tx.hash); it != parents.end()) {
                for (const auto& parent : it->second) dependencies_satisfied &= included.contains(parent);
            }
            if (!dependencies_satisfied) continue;
            // Dependency-eligible leftovers must fail at least one of the four
            // remaining budgets after the independently measured allowances.
            BOOST_REQUIRE_MESSAGE(!would_fit(*tx.tx, usable),
                                  "seed=" << SEED << " blocks=" << blocks << " fitting leftover=" << tx.hash.ToString()
                                  << " rem_l1=" << actual.rem_l1 << " rem_mweb=" << actual.rem_mweb
                                  << " rem_inputs=" << actual.rem_inputs << " rem_ser=" << actual.rem_ser);
            sensitivity_control |= would_fit(*tx.tx, {MAX_BLOCK_WEIGHT, mw::MAX_BLOCK_WEIGHT,
                                                      MAX_BLOCK_SERIALIZED_SIZE_BIP324, mw::MAX_NUM_INPUTS});
        }
        BOOST_REQUIRE_GT(selected_l1, 0U);
        BOOST_REQUIRE_EQUAL(selected_input_types.size(), input_scripts.size());
        BOOST_REQUIRE_EQUAL(selected_output_types.size(), recipient_scripts.size());
        BOOST_REQUIRE_GT(selected_mweb, 0U);
        BOOST_REQUIRE_GT(selected_children, 0U);
        BOOST_REQUIRE_GT(excluded, 0U);
        BOOST_REQUIRE(sensitivity_control); // residual oracle sees eligible alternatives when room exists
        BOOST_TEST_MESSAGE("competing-eligible seed=" << SEED << " blocks=" << blocks
                           << " queued_wire=" << queued_bytes << " queued_l1_weight=" << l1_weight
                           << " queued_l1=" << n_l1 << " queued_mweb=" << n_mweb << " bank_inputs=" << bank_cursor
                           << " selected_l1=" << selected_l1 << " selected_mweb=" << selected_mweb
                           << " selected_inputs=" << selected_inputs << " selected_outputs=" << selected_outputs
                           << " selected_kernels=" << selected_kernels << " selected_children=" << selected_children
                           << " excluded=" << excluded << " selected_tails=" << selected_tails
                           << " declared_ser_headroom=" << serialized_headroom);
        LogFillMetrics("competing-eligible", candidate->block, actual);
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t1c_mixed_size_and_weight_binders)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Weight-dense consolidations + size-oriented consolidations.
    constexpr int DENSE_K = 4000;
    constexpr uint64_t W_DENSE = 2 * DENSE_K + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t n_dense = mw::MAX_BLOCK_WEIGHT / W_DENSE; // 24
    constexpr size_t SIZE_INPUTS = 8;
    constexpr size_t n_size = 30;

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, n_dense + 1 + SIZE_INPUTS * (n_size + 1), COIN);
    DrainMempool(m_node);
    size_t cursor = 0;
    std::vector<TrackedTx> tracked;

    for (size_t i = 0; i < n_dense + 1; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[cursor++]}, DENSE_K, 1);
        Submit(pool, mtx, DENSE_K);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), DENSE_K, false, true});
    }
    for (size_t i = 0; i < n_size + 1; ++i) {
        std::vector<test::TxOutput> ins;
        ins.reserve(SIZE_INPUTS);
        for (size_t j = 0; j < SIZE_INPUTS; ++j) ins.push_back(utxos[cursor++]);
        CMutableTransaction mtx = MakeConsolidation(ins, 1, 1000);
        Submit(pool, mtx, 1000);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 1000, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    LogFillMetrics("T1c", tmpl->block, rem);

    // At least one binder is near-cap.
    const bool weight_bound = static_cast<uint64_t>(rem.rem_mweb) <= W_DENSE || static_cast<uint64_t>(rem.rem_mweb) <= SLACK_MWEB;
    const size_t S_size = EstimateSerDelta(CTransaction(MakeConsolidation(
        std::vector<test::TxOutput>(utxos.begin(), utxos.begin() + static_cast<std::ptrdiff_t>(SIZE_INPUTS)), 1, 1000)));
    // Use a representative size from included/excluded size-oriented txs instead of rebuilding.
    size_t S_rep = 0;
    for (const auto& t : tracked) {
        if (TxMWEBWeight(*t.tx) == W_DENSE) continue;
        S_rep = EstimateSerDelta(*t.tx);
        break;
    }
    if (S_rep == 0) S_rep = S_size;
    const bool ser_bound = static_cast<uint64_t>(rem.rem_ser) < S_rep || static_cast<uint64_t>(rem.rem_ser) <= SLACK_SER;
    BOOST_REQUIRE_MESSAGE(weight_bound || ser_bound, "T1c: neither weight nor serialized size near-cap");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1c");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t1d_all_remaining_individually_too_large)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Fill near weight cap with dense fillers, leave only always-unfittable monsters.
    constexpr int KERNELS = 4000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N, COIN);
    DrainMempool(m_node);
    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, KERNELS);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), KERNELS, false, true});
    }
    for (int k = 0; k < 5; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(90'000, 1'000'000, static_cast<uint64_t>(k + 500));
        Submit(pool, mon, 1'000'000);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 1'000'000, true, false});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);
    AssertNearCapWeight(LeftoverBudgetsOf(tmpl->block), W_F, "T1d");
    // rem_* may be non-tiny in other budgets; exception path: no eligible leftover fits.
    AssertAllEligibleRemainingUnfittable(tmpl->block, pool, tracked, KERNELS, static_cast<CAmount>(W_F), "T1d");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(i0_assembler_must_not_exceed_max_num_inputs)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Intentionally oversubscribe the 50k input cap with crypto-valid consolidations.
    std::vector<test::TxOutput> bank = MineFanoutUTXOs(*this, m_node, MIN_EXTENDED_UTXOS);
    DrainMempool(m_node);

    constexpr size_t INPUTS_PER = 1'250;
    constexpr size_t N = 42; // 42 * 1250 = 52500 > MAX_NUM_INPUTS
    BOOST_REQUIRE_GT(N * INPUTS_PER, mw::MAX_NUM_INPUTS);
    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < N; ++i) {
        std::vector<test::TxOutput> ins;
        BOOST_REQUIRE_EQUAL(TakeBank(bank, INPUTS_PER, ins), INPUTS_PER);
        CMutableTransaction mtx = MakeConsolidation(ins, /*plain_kernels=*/1, /*fee_per_kernel=*/100);
        Submit(pool, mtx, /*fee=*/100'000);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 100'000, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    const size_t inputs = BlockMWEBInputCount(tmpl->block);
    LogFillMetrics("I0", tmpl->block, LeftoverBudgetsOf(tmpl->block), CountIncludedTracked(tmpl->block, tracked, true));
    if (inputs > mw::MAX_NUM_INPUTS) {
        const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
        TriggerStop({
            .reason = "I0: CreateNewBlock exceeded mw::MAX_NUM_INPUTS — add input-count gate to TestChunkBlockLimits",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .first_excluded_fit = strprintf("mweb_inputs=%u", inputs),
            .prefer_fewer_inputs_gap = true,
        });
    }
    BOOST_REQUIRE_LE(inputs, mw::MAX_NUM_INPUTS);
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(i1_max_inputs_singleton_and_tails)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    std::vector<test::TxOutput> bank = MineFanoutUTXOs(*this, m_node, MIN_EXTENDED_UTXOS);
    DrainMempool(m_node);

    std::vector<test::TxOutput> big_ins;
    BOOST_REQUIRE_EQUAL(TakeBank(bank, mw::MAX_NUM_INPUTS, big_ins), mw::MAX_NUM_INPUTS);
    CMutableTransaction big = MakeConsolidation(big_ins, /*plain_kernels=*/1, /*fee_per_kernel=*/100);
    const size_t S_big = EstimateSerDelta(CTransaction(big));
    BOOST_REQUIRE_LT(S_big, MAX_BLOCK_SERIALIZED_SIZE_BIP324);
    BOOST_REQUIRE_EQUAL(MWEB::Miner::CountTxMWEBInputs(CTransaction(big)), mw::MAX_NUM_INPUTS);

    std::vector<TrackedTx> tracked;
    Submit(pool, big, /*fee=*/100'000);
    tracked.push_back({big.GetHash(), MakeTransactionRef(big), 100'000, false, true});

    constexpr size_t N_TAIL = 30;
    constexpr CAmount TAIL_FEE = 50'000;
    size_t S_tail = 0;
    for (size_t i = 0; i < N_TAIL; ++i) {
        std::vector<test::TxOutput> ins;
        if (TakeBank(bank, 1, ins) < 1) break;
        CMutableTransaction mtx = MakeConsolidation(ins, 1, 1);
        if (S_tail == 0) {
            S_tail = EstimateSerDelta(CTransaction(mtx));
        }
        Submit(pool, mtx, TAIL_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), TAIL_FEE, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    if (BlockMWEBInputCount(tmpl->block) > mw::MAX_NUM_INPUTS) {
        const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
        TriggerStop({
            .reason = "I1: 50k-input tx + tails exceeded MAX_NUM_INPUTS (missing assembler gate)",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .prefer_fewer_inputs_gap = true,
        });
    }
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    LogFillMetrics("I1", tmpl->block, rem);

    // Either the 50k-input tx is included (input budget exhausted) or skipped and tails pack.
    const bool big_in = TemplateContainsMWEBTx(tmpl->block, *tracked[0].tx);
    if (big_in) {
        BOOST_REQUIRE_EQUAL(BlockMWEBInputCount(tmpl->block), mw::MAX_NUM_INPUTS);
        // Input-bound: rem_ser may be large; tails must not WouldFit (rem_inputs==0).
    } else {
        BOOST_REQUIRE_GT(CountIncludedTracked(tmpl->block, tracked, true), 0u);
        if (S_tail > 0) AssertNearCapSer(rem, S_tail, "I1-skip-big");
    }
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "I1");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(l1_multiple_large_plus_tail_fillers)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Crypto-valid kernel-heavy "larges": each alone fits, but not all together (weight binds).
    constexpr int LARGE_KERNELS = 20'000; // weight 40018; ~ser dominated by kernels
    constexpr uint64_t W_LARGE = 2 * LARGE_KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t n_fit = mw::MAX_BLOCK_WEIGHT / W_LARGE; // 4
    constexpr size_t N_LARGE = 8;
    constexpr CAmount LARGE_FEE = LARGE_KERNELS;
    constexpr int N_TAIL = 40;
    constexpr CAmount TAIL_FEE = 5'000;

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N_LARGE + N_TAIL, COIN);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < N_LARGE; ++i) {
        CMutableTransaction large = MakeConsolidation({utxos[i]}, LARGE_KERNELS, 1);
        BOOST_REQUIRE_EQUAL(TxMWEBWeight(CTransaction(large)), W_LARGE);
        Submit(pool, large, LARGE_FEE);
        tracked.push_back({large.GetHash(), MakeTransactionRef(large), LARGE_FEE, false, false});
    }
    size_t S_tail = 0;
    for (int i = 0; i < N_TAIL; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[N_LARGE + i]}, 1, 1);
        if (S_tail == 0) {
            S_tail = EstimateSerDelta(CTransaction(mtx));
        }
        Submit(pool, mtx, TAIL_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), TAIL_FEE, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);

    size_t n_large = 0;
    for (size_t i = 0; i < N_LARGE; ++i) {
        if (TemplateContainsMWEBTx(tmpl->block, *tracked[i].tx)) ++n_large;
    }
    const size_t n_tail = CountIncludedTracked(tmpl->block, tracked, true);
    BOOST_REQUIRE_EQUAL(n_large, n_fit);
    BOOST_REQUIRE_GT(n_tail, 0u);

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    LogFillMetrics("L1", tmpl->block, rem, n_tail, S_tail);
    AssertNearCapWeight(rem, W_LARGE, "L1");
    // Tails may or may not fit residual weight; NO_GAP among equal-or-better eligible.
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "L1");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(l1_empty_mweb_size_binding)
{
    // Minimal L1 (coinbase + HogEx only): size-binding MWEB fillers must still
    // reach NEAR_CAP/NO_GAP on the BIP324 serialized budget.
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    std::vector<test::TxOutput> bank = MineFanoutUTXOs(*this, m_node, MIN_EXTENDED_UTXOS);
    DrainMempool(m_node);

    constexpr size_t INPUTS_PER = 1'200;
    constexpr int KERNELS = 1'700;
    constexpr CAmount FEE_PER_KERNEL = 1;
    constexpr CAmount FILLER_FEE = KERNELS * FEE_PER_KERNEL;
    constexpr size_t TAIL_INPUTS = 2;
    constexpr int TAIL_KERNELS = 1;
    constexpr CAmount TAIL_FEE = 1;
    constexpr size_t N_TAILS = 200;
    constexpr size_t INPUT_HEADROOM_FOR_TAILS = TAIL_INPUTS * N_TAILS;

    std::vector<test::TxOutput> probe_ins;
    BOOST_REQUIRE_EQUAL(TakeBank(bank, INPUTS_PER, probe_ins), INPUTS_PER);
    CMutableTransaction probe = MakeConsolidation(probe_ins, KERNELS, FEE_PER_KERNEL);
    const size_t S_f = EstimateSerDelta(CTransaction(probe));
    const uint64_t W_f = TxMWEBWeight(CTransaction(probe));
    BOOST_REQUIRE_GT(S_f, 64 * 1024u);
    BOOST_REQUIRE_LT(W_f, mw::MAX_BLOCK_WEIGHT);

    const size_t usable = MAX_BLOCK_SERIALIZED_SIZE_BIP324 - 32 * 1024;
    size_t n_large = usable / S_f;
    if (n_large < 2) n_large = 2;
    while (n_large > 1 && (n_large * INPUTS_PER + INPUT_HEADROOM_FOR_TAILS > mw::MAX_NUM_INPUTS ||
                           n_large * W_f > mw::MAX_BLOCK_WEIGHT)) {
        --n_large;
    }
    BOOST_REQUIRE_GE(n_large, 2u);

    std::vector<TrackedTx> tracked;
    Submit(pool, probe, FILLER_FEE);
    tracked.push_back({probe.GetHash(), MakeTransactionRef(probe), FILLER_FEE, false, true});
    for (size_t i = 1; i < n_large; ++i) {
        std::vector<test::TxOutput> ins;
        BOOST_REQUIRE_EQUAL(TakeBank(bank, INPUTS_PER, ins), INPUTS_PER);
        CMutableTransaction mtx = MakeConsolidation(ins, KERNELS, FEE_PER_KERNEL);
        Submit(pool, mtx, FILLER_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), FILLER_FEE, false, true});
    }

    std::vector<test::TxOutput> tail_probe_ins;
    BOOST_REQUIRE_EQUAL(TakeBank(bank, TAIL_INPUTS, tail_probe_ins), TAIL_INPUTS);
    CMutableTransaction tail_probe = MakeConsolidation(tail_probe_ins, TAIL_KERNELS, FEE_PER_KERNEL);
    const size_t S_tail = EstimateSerDelta(CTransaction(tail_probe));
    Submit(pool, tail_probe, TAIL_FEE);
    tracked.push_back({tail_probe.GetHash(), MakeTransactionRef(tail_probe), TAIL_FEE, false, true});
    size_t n_tails = 1;
    for (size_t i = 1; i < N_TAILS; ++i) {
        std::vector<test::TxOutput> ins;
        if (TakeBank(bank, TAIL_INPUTS, ins) < TAIL_INPUTS) break;
        CMutableTransaction mtx = MakeConsolidation(ins, TAIL_KERNELS, FEE_PER_KERNEL);
        Submit(pool, mtx, TAIL_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), TAIL_FEE, false, true});
        ++n_tails;
    }
    BOOST_REQUIRE_GE(n_tails, 80u);

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_REQUIRE_LE(BlockMWEBInputCount(tmpl->block), mw::MAX_NUM_INPUTS);
    // MWEB-only consolidations: L1 vtx is coinbase + HogEx only.
    BOOST_REQUIRE_MESSAGE(tmpl->block.vtx.size() <= 2,
                          "l1_empty: expected coinbase[+HogEx] only on L1");

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, true);
    LogFillMetrics("L1-empty", tmpl->block, rem, n_fill, S_f);
    BOOST_REQUIRE_GT(n_fill, 0u);
    BOOST_REQUIRE_MESSAGE(rem.rem_ser < static_cast<int64_t>(S_f) || rem.rem_ser < static_cast<int64_t>(S_tail) * 2,
                          "l1_empty: expected serialized size to bind");
    AssertNearCapSer(rem, S_tail, "L1-empty");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "L1-empty");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(l1_full_mweb_residual)
{
    // Fill L1 weight near max with heavy L1 fillers, then prove MWEB packing still
    // respects ser + input gates and does not leave WouldFit MWEB fillers when L1 is full.
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    constexpr int KERNELS = 2'000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N_MWEB = 30;
    constexpr CAmount MWEB_FEE = KERNELS;
    constexpr size_t N_TAIL = 40;
    constexpr CAmount TAIL_FEE = 50;
    constexpr int N_HEAVY_L1 = 80;
    constexpr size_t HEAVY_OUTS = 2'000; // ~8k weight each — binds L1 before all fit

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N_MWEB + N_TAIL, COIN);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    // High-feerate heavy L1 first so L1 weight binds.
    for (int i = 0; i < N_HEAVY_L1; ++i) {
        CMutableTransaction heavy = MakeHeavyL1(static_cast<uint64_t>(i + 90'000), HEAVY_OUTS, /*fee=*/1'000);
        Submit(pool, heavy, /*fee=*/10'000'000);
        tracked.push_back({heavy.GetHash(), MakeTransactionRef(heavy), 10'000'000, true, false});
    }
    for (size_t i = 0; i < N_MWEB; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, MWEB_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), MWEB_FEE, false, true});
    }
    size_t S_tail = 0;
    uint64_t W_tail = 0;
    for (size_t i = 0; i < N_TAIL; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[N_MWEB + i]}, 1, 1);
        if (S_tail == 0) {
            S_tail = EstimateSerDelta(CTransaction(mtx));
            W_tail = TxMWEBWeight(CTransaction(mtx));
        }
        Submit(pool, mtx, TAIL_FEE);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), TAIL_FEE, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_REQUIRE_LE(BlockMWEBInputCount(tmpl->block), mw::MAX_NUM_INPUTS);

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    const size_t n_mweb = CountIncludedTracked(tmpl->block, tracked, true);
    LogFillMetrics("L1-full", tmpl->block, rem, n_mweb, S_tail);
    BOOST_REQUIRE_GT(n_mweb, 0u);
    // L1 is binding at this fixture's granularity: another heavy filler cannot
    // fit. The old alternative n_mweb > 0 was already required above.
    BOOST_REQUIRE_MESSAGE(rem.rem_l1 < GetTransactionWeight(*tracked.front().tx),
                          "l1_full: another heavy L1 filler would still fit");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "L1-full");
    // If MWEB weight still has room for a typical dense filler and ser allows, NEAR_CAP weight.
    if (static_cast<uint64_t>(rem.rem_mweb) <= W_F || static_cast<uint64_t>(rem.rem_ser) < S_tail) {
        // At least one budget is binding relative to leftover grains — OK.
    } else {
        // Remaining eligible MWEB must be individually unfittable (L1 full or ser).
        AssertAllEligibleRemainingUnfittable(tmpl->block, pool, tracked, TAIL_FEE,
                                             static_cast<CAmount>(std::max<uint64_t>(W_tail, 1)), "L1-full");
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(m1_residual_budget_monster_skipped_tails_fill)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // Dense fill first (weight), then a residual-unfittable mid-monster with higher fee already in mempool.
    constexpr int KERNELS = 4000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N + 20, COIN);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    // Mid monster: fits empty (~7.8MB) but not after dense weight fill (~9.5MB already used).
    CMutableTransaction mid = MakeSyntheticMonster(40'000, 1'000'000, 700);
    Submit(pool, mid, 1'000'000);
    tracked.push_back({mid.GetHash(), MakeTransactionRef(mid), 1'000'000, true, false});

    for (size_t i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, KERNELS);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), KERNELS, false, true});
    }
    for (size_t i = N; i < N + 20; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, 1, 100);
        Submit(pool, mtx, 100);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 100, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_CHECK_EQUAL(CountIncludedMonsters(tmpl->block, tracked), 0u);
    BOOST_REQUIRE_GT(CountIncludedTracked(tmpl->block, tracked, true), 0u);
    AssertNearCapWeight(LeftoverBudgetsOf(tmpl->block), W_F, "M1");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "M1");

    // Mid-monster must still be in the mempool for a later block.
    {
        LOCK(pool.cs);
        BOOST_REQUIRE_MESSAGE(pool.exists(mid.GetHash()), "M1: residual monster missing from mempool");
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(c2_500_heavy_l1_candidates_preserve_mweb_fill)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // MWEB weight packing with 500 competing heavy L1 candidates.
    // The primary consecutive-failure boundary is covered separately below.
    constexpr int KERNELS = 4000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N + 5, COIN);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    for (size_t i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, KERNELS);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), KERNELS, false, true});
    }
    constexpr int N_SKIP = 500;
    constexpr size_t HEAVY_OUTS = 2'500; // ~10k weight each — won't fit once L1 is near-full from stubs/coinbase growth
    for (int i = 0; i < N_SKIP; ++i) {
        CMutableTransaction heavy = MakeHeavyL1(static_cast<uint64_t>(i + 3000), HEAVY_OUTS, /*fee=*/1'000);
        Submit(pool, heavy, /*fee=*/1'000'000);
        tracked.push_back({heavy.GetHash(), MakeTransactionRef(heavy), 1'000'000, true, false});
    }
    for (int i = 0; i < 30; ++i) {
        CMutableTransaction tiny = MakeL1Filler(static_cast<uint64_t>(i + 4000), /*fee=*/500);
        Submit(pool, tiny, /*fee=*/50'000);
        tracked.push_back({tiny.GetHash(), MakeTransactionRef(tiny), 50'000, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    LogFillMetrics("C2", tmpl->block, rem);
    BOOST_REQUIRE_GT(CountIncludedTracked(tmpl->block, tracked, true), 0u);
    AssertNearCapWeight(rem, W_F, "C2");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "C2");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(c1_1100_heavy_l1_candidates_preserve_mweb_fill)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // 1,100 competing heavy L1 candidates must not starve MWEB fillers.
    // This fixture does not put primary L1 weight within its 4,000-WU early-exit margin.
    constexpr int KERNELS = 4000;
    constexpr uint64_t W_F = 2 * KERNELS + mw::STANDARD_OUTPUT_WEIGHT;
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N + 5, COIN);
    DrainMempool(m_node);

    std::vector<TrackedTx> tracked;
    constexpr int N_SKIP = 1'100;
    constexpr size_t HEAVY_OUTS = 3'000;
    for (int i = 0; i < N_SKIP; ++i) {
        CMutableTransaction heavy = MakeHeavyL1(static_cast<uint64_t>(i + 5000), HEAVY_OUTS, /*fee=*/1'000);
        Submit(pool, heavy, /*fee=*/5'000'000);
        tracked.push_back({heavy.GetHash(), MakeTransactionRef(heavy), 5'000'000, true, false});
    }
    for (size_t i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, KERNELS, 1);
        Submit(pool, mtx, KERNELS);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), KERNELS, false, true});
    }
    for (int i = 0; i < 40; ++i) {
        CMutableTransaction tiny = MakeL1Filler(static_cast<uint64_t>(i + 7000), /*fee=*/500);
        Submit(pool, tiny, /*fee=*/100'000);
        tracked.push_back({tiny.GetHash(), MakeTransactionRef(tiny), 100'000, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, true);
    LogFillMetrics("C1", tmpl->block, rem, n_fill);
    if (n_fill == 0) {
        TriggerStop({
            .reason = "C1: >1000 consecutive failures starved fillers (early-exit hole)",
            .rem_l1 = rem.rem_l1,
            .rem_mweb = rem.rem_mweb,
            .rem_ser = rem.rem_ser,
            .consecutive_failure_suspicion = true,
            .prefer_fewer_inputs_gap = true,
        });
    }
    BOOST_REQUIRE_GT(n_fill, 0u);
    AssertNearCapWeight(rem, W_F, "C1");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "C1");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(consecutive_failure_boundary_and_residual_recovery)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    for (int skips : {1000, 1001}) {
        DrainMempool(m_node);
        // The highest-rate transaction leaves exactly 2,000 WU of assembler
        // L1 budget: primary's 4,000-WU near-full predicate is now reachable.
        auto prefill = MakeHeavyL1(900'000, 2'250, 1'000);
        constexpr CAmount PREFILL_FEE = 1'000'000'000;
        Submit(pool, prefill, PREFILL_FEE);
        const int64_t prefill_weight = GetTransactionWeight(CTransaction(prefill));
        for (int i = 0; i < skips; ++i) {
            auto heavy = MakeHeavyL1(1'000'000 + i, 1'000, 1'000);
            BOOST_REQUIRE_GT(GetTransactionWeight(CTransaction(heavy)), 2'000);
            Submit(pool, heavy, 5'000'000);
        }
        std::vector<TrackedTx> tails;
        for (int i = 0; i < 10; ++i) {
            auto tail = MakePeginTx(COIN, 0, 2'000'000 + i);
            Submit(pool, tail, 10'000);
            tails.push_back({tail.GetHash(), MakeTransactionRef(tail), 10'000, false, true});
        }
        BlockCreateOptions options;
        options.test_block_validity = false; // selection fixture, as in BuildTemplate
        options.coinbase_output_script = CScript() << OP_TRUE;
        options.block_min_fee_rate = CFeeRate{0};
        options.block_reserved_weight = 8'000;
        options.block_max_weight = 8'000 + prefill_weight + 2'000;
        const auto tmpl = BlockAssembler{chainstate, &pool, options}.CreateNewBlock();
        BOOST_REQUIRE(tmpl);
        BOOST_REQUIRE(IncludedHashes(tmpl->block).contains(prefill.GetHash()));
        BOOST_REQUIRE_GT(CountIncludedTracked(tmpl->block, tails, true), 0u);
        if (skips == 1000) {
            BOOST_CHECK_GT(tmpl->m_package_feerates.size(), 1u); // primary reaches tails
        } else {
            // Residual adds tails after primary gives up; it does not append
            // primary package-feerate records. Disabling residual must fail here.
            BOOST_CHECK_EQUAL(tmpl->m_package_feerates.size(), 1u);
        }
        AssertNeverExceed(tmpl->block);
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(g2_fee_floor_does_not_false_fail_no_gap)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    std::vector<TrackedTx> tracked;
    for (int i = 0; i < 40; ++i) {
        CMutableTransaction mtx = MakePeginTx(COIN + i, 0, static_cast<uint64_t>(i + 70'000));
        Submit(pool, mtx, /*fee=*/50'000);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 50'000, false, true});
    }
    // Low-feerate junk that may fit leftover but must not trip NO_GAP at the high floor.
    for (int i = 0; i < 20; ++i) {
        CMutableTransaction mtx = MakePeginTx(COIN + 1000 + i, 0, static_cast<uint64_t>(i + 80'000));
        Submit(pool, mtx, /*fee=*/100);
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 100, false, true});
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "G2");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(a1_mweb_aggregation_and_estimate_conservative)
{
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    constexpr int N = 25;
    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N, COIN);
    DrainMempool(m_node);
    std::vector<CTransactionRef> submitted;
    size_t body_est = 0;
    for (int i = 0; i < N; ++i) {
        CMutableTransaction mtx = MakeConsolidation({utxos[i]}, 10, 1);
        body_est += MWEB::Miner::EstimateTxMWEBBodyBytes(CTransaction(mtx));
        BOOST_CHECK_EQUAL(MWEB::Miner::EstimateTxL1StubBytes(CTransaction(mtx)), 0u);
        Submit(pool, mtx, 10);
        submitted.push_back(MakeTransactionRef(mtx));
    }
    // Hybrid pegins too.
    for (int i = 0; i < 5; ++i) {
        CMutableTransaction mtx = MakePeginTx(COIN + i, 0, static_cast<uint64_t>(i + 90'000));
        body_est += MWEB::Miner::EstimateTxMWEBBodyBytes(CTransaction(mtx));
        Submit(pool, mtx, 5'000);
        submitted.push_back(MakeTransactionRef(mtx));
    }

    auto tmpl = BuildTemplate(chainstate, pool);
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_REQUIRE(!tmpl->block.mweb_block.IsNull());
    BOOST_REQUIRE(tmpl->block.vtx.size() >= 2);
    BOOST_CHECK(tmpl->block.vtx.back()->IsHogEx());

    const size_t merged = tmpl->block.mweb_block.m_block->GetTxBody().Serialized().size();
    BOOST_CHECK_GE(body_est, merged);

    // MWEB-only txs must not appear as L1 stubs with embedded mweb_tx.
    for (const auto& tx : tmpl->block.vtx) {
        if (!tx || tx->IsCoinBase() || tx->IsHogEx()) continue;
        BOOST_CHECK(tx->mweb_tx.IsNull());
    }
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(t3b_randomized_near_pressure_boundary)
{
    MineToMwebChain(*this, m_node);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    CTxMemPool& pool = *Assert(m_node.mempool);

    constexpr uint32_t SEED = 0xBEEF42;
    constexpr int ITERS = 8;
    std::mt19937 rng(SEED);
    std::vector<test::TxOutput> bank = MinePegins(*this, m_node, 64, COIN);
    DrainMempool(m_node);
    size_t bank_cursor = 0;

    for (int iter = 0; iter < ITERS; ++iter) {
        DrainMempool(m_node);
        if (bank_cursor + 16 > bank.size()) {
            bank = MinePegins(*this, m_node, 64, COIN);
            bank_cursor = 0;
            DrainMempool(m_node);
        }
        std::vector<TrackedTx> tracked;
        // Mix dense kernels (size toward pressure) with pegins and a mid-monster.
        const int n_dense = 3 + static_cast<int>(rng() % 4);
        for (int i = 0; i < n_dense && bank_cursor < bank.size(); ++i) {
            const int kernels = 2000 + static_cast<int>(rng() % 2500);
            CMutableTransaction mtx = MakeConsolidation({bank[bank_cursor++]}, kernels, 1);
            Submit(pool, mtx, kernels);
            tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), kernels, false, true});
        }
        const int n_pegin = 20 + static_cast<int>(rng() % 30);
        for (int i = 0; i < n_pegin; ++i) {
            auto mtx = MakePeginTx(COIN + iter * 100 + i, 0, static_cast<uint64_t>(iter * 1000 + i + 120'000));
            Submit(pool, mtx, 10'000);
            tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), 10'000, false, true});
        }
        {
            const size_t mid_ins = 20'000 + (rng() % 20'000);
            auto mon = MakeSyntheticMonster(mid_ins, 80'000, static_cast<uint64_t>(iter + 1100));
            Submit(pool, mon, 80'000);
            tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), 80'000, true, false});
        }

        std::unique_ptr<CBlockTemplate> tmpl;
        try {
            tmpl = BuildTemplate(chainstate, pool);
        } catch (const std::exception& e) {
            BOOST_REQUIRE_MESSAGE(false, "T3b seed=0x" << std::hex << SEED << " iter=" << std::dec << iter
                                                      << " threw: " << e.what());
        }
        BOOST_REQUIRE(tmpl);
        AssertNeverExceed(tmpl->block);
        AssertPackageFeeratesNonIncreasing(*tmpl, "T3b iter=" + util::ToString(iter));
        AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T3b seed=0xBEEF42 iter=" + util::ToString(iter));
    }
}

/**
 * Consensus-max fan-out of standard-format outputs: N = 11,111 → weight 200,000.
 * Relay policy must reject this nonstandard transaction. After test-only mempool
 * insertion, CreateNewBlock/TestBlockValidity must accept exact MAX (assembler `>`
 * must match Weight::ExceedsMaximum / BlockBuilder). Wire size is below BIP324.
 */
BOOST_AUTO_TEST_CASE(bp_max_standard_fanout_atmp_and_block)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    constexpr size_t N =
        (mw::MAX_BLOCK_WEIGHT - mw::BASE_KERNEL_WEIGHT) / mw::STANDARD_OUTPUT_WEIGHT;
    BOOST_REQUIRE_EQUAL(N, 11111);
    const uint64_t expected_weight =
        static_cast<uint64_t>(N) * mw::STANDARD_OUTPUT_WEIGHT + mw::BASE_KERNEL_WEIGHT;
    BOOST_REQUIRE_EQUAL(expected_weight, 200'000);
    BOOST_REQUIRE_LE(expected_weight, mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE_GT(expected_weight + mw::STANDARD_OUTPUT_WEIGHT, mw::MAX_BLOCK_WEIGHT);

    std::vector<test::TxOutput> seeds = MinePegins(*this, m_node, /*count=*/1, /*amount=*/50 * COIN);
    BOOST_REQUIRE_EQUAL(seeds.size(), 1u);
    DrainMempool(m_node);

    const CAmount fee = CFeeRate::GetMWEBFee(expected_weight);
    BOOST_REQUIRE_EQUAL(fee, static_cast<CAmount>(expected_weight) * 100);
    BOOST_REQUIRE_GT(seeds[0].GetAmount(), fee + static_cast<CAmount>(N));

    std::vector<test::TxOutput> children;
    CMutableTransaction mtx = MakeFanOut(seeds[0], N, fee, children);
    BOOST_REQUIRE_EQUAL(children.size(), N);

    const MWEB::Tx finalized{mtx.mweb_tx};
    BOOST_REQUIRE(!finalized.IsNull());
    const auto& body = finalized.m_transaction->GetBody();
    BOOST_REQUIRE_EQUAL(body.GetInputs().size(), 1u);
    BOOST_REQUIRE_EQUAL(body.GetOutputs().size(), N);
    BOOST_REQUIRE_EQUAL(body.GetKernels().size(), 1u);
    BOOST_REQUIRE_EQUAL(Weight::Calculate(body), expected_weight);
    BOOST_REQUIRE(!Weight::ExceedsMaximum(body));
    BOOST_REQUIRE_EQUAL(finalized.GetMWEBWeight(), expected_weight);

    {
        LOCK2(::cs_main, pool.cs);
        const MempoolAcceptResult result = Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_REQUIRE_EQUAL(result.m_state.GetRejectReason(), "mweb-txn-oversize");
        BOOST_REQUIRE_EQUAL(pool.size(), 0u);
        // This case targets the consensus block boundary, not standard relay.
        Submit(pool, mtx, fee);
    }

    BlockCreateOptions options;
    options.test_block_validity = true;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<CBlockTemplate> tmpl;
    try {
        tmpl = BlockAssembler{chainstate, &pool, options}.CreateNewBlock();
    } catch (const std::exception& e) {
        BOOST_REQUIRE_MESSAGE(false, strprintf("max fan-out CreateNewBlock/TestBlockValidity threw: %s", e.what()));
    }
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_REQUIRE(!tmpl->block.mweb_block.IsNull());
    BOOST_REQUIRE(tmpl->block.mweb_block.m_block);
    const auto& tip_body = tmpl->block.mweb_block.m_block->GetTxBody();
    BOOST_REQUIRE_EQUAL(tip_body.GetInputs().size(), 1u);
    BOOST_REQUIRE_EQUAL(tip_body.GetOutputs().size(), N);
    BOOST_REQUIRE_EQUAL(tip_body.GetKernels().size(), 1u);
    BOOST_REQUIRE_EQUAL(Weight::Calculate(tip_body), expected_weight);
    BOOST_REQUIRE_LE(ExactBlockSize(tmpl->block), MAX_BLOCK_SERIALIZED_SIZE_BIP324);
    // Output-heavy weight-max body is ~10 MiB — well inside the BIP324 envelope.
    BOOST_REQUIRE_LT(ExactBlockSize(tmpl->block), MAX_BLOCK_SERIALIZED_SIZE_BIP324 / 2 + 2'000'000);

    DrainMempool(m_node);
}

/**
 * Many medium fan-outs whose non-cut-through outputs sum above the old ~6.3k
 * 32 MiB BatchVerify cliff and approach weight max. Proves block-level
 * aggregated BatchVerify + exact body counts.
 */
BOOST_AUTO_TEST_CASE(bp_aggregated_fanouts_above_scratch_cliff)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    constexpr size_t BATCH = 200;
    constexpr size_t BATCH_WEIGHT = BATCH * mw::STANDARD_OUTPUT_WEIGHT + mw::BASE_KERNEL_WEIGHT;
    constexpr size_t N_TX = mw::MAX_BLOCK_WEIGHT / BATCH_WEIGHT; // 55
    BOOST_REQUIRE_EQUAL(BATCH_WEIGHT, 3602u);
    BOOST_REQUIRE_EQUAL(N_TX, 55u);
    constexpr size_t EXPECTED_OUTS = N_TX * BATCH; // 11000 > ~6260 cliff
    BOOST_REQUIRE_GT(EXPECTED_OUTS, 6'260u);
    const uint64_t expected_weight = static_cast<uint64_t>(N_TX) * BATCH_WEIGHT;
    BOOST_REQUIRE_LE(expected_weight, mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE_GT(expected_weight + BATCH_WEIGHT, mw::MAX_BLOCK_WEIGHT);

    std::vector<test::TxOutput> seeds = MinePegins(*this, m_node, N_TX, /*amount=*/COIN);
    BOOST_REQUIRE_EQUAL(seeds.size(), N_TX);
    DrainMempool(m_node);

    const CAmount fee = CFeeRate::GetMWEBFee(BATCH_WEIGHT);
    size_t staged = 0;
    for (size_t i = 0; i < N_TX; ++i) {
        BOOST_REQUIRE_GT(seeds[i].GetAmount(), fee + static_cast<CAmount>(BATCH));
        std::vector<test::TxOutput> children;
        CMutableTransaction mtx = MakeFanOut(seeds[i], BATCH, fee, children);
        BOOST_REQUIRE_EQUAL(children.size(), BATCH);
        LOCK2(::cs_main, pool.cs);
        const MempoolAcceptResult result = Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              strprintf("aggregated fan-out[%u] ATMP failed: %s", i, result.m_state.ToString()));
        ++staged;
    }
    BOOST_REQUIRE_EQUAL(staged, N_TX);
    BOOST_REQUIRE_EQUAL(pool.size(), N_TX);

    BlockCreateOptions options;
    options.test_block_validity = true;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<CBlockTemplate> tmpl;
    try {
        tmpl = BlockAssembler{chainstate, &pool, options}.CreateNewBlock();
    } catch (const std::exception& e) {
        BOOST_REQUIRE_MESSAGE(false, strprintf("aggregated fan-out CreateNewBlock threw: %s", e.what()));
    }
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);
    BOOST_REQUIRE(!tmpl->block.mweb_block.IsNull());
    BOOST_REQUIRE(tmpl->block.mweb_block.m_block);
    const auto& tip_body = tmpl->block.mweb_block.m_block->GetTxBody();
    // Independent spends: no cut-through between txs.
    BOOST_REQUIRE_EQUAL(tip_body.GetInputs().size(), N_TX);
    BOOST_REQUIRE_EQUAL(tip_body.GetOutputs().size(), EXPECTED_OUTS);
    BOOST_REQUIRE_EQUAL(tip_body.GetKernels().size(), N_TX);
    BOOST_REQUIRE_EQUAL(Weight::Calculate(tip_body), expected_weight);

    DrainMempool(m_node);
}

/**
 * T1b sibling: weight-binding fillers burn budget as many standard outputs
 * (few kernels), so NEAR_CAP(MWEB) also runs a large BatchVerify — unlike the
 * kernel-dense T1b which deliberately avoids bulletproof cost.
 */
BOOST_AUTO_TEST_CASE(t1b_output_weight_binding_batchverify)
{
    SKIP_IF_NOT_EXTENDED();
    MineToMwebChain(*this, m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    constexpr size_t OUTS_PER = 200;
    constexpr uint64_t W_F = OUTS_PER * mw::STANDARD_OUTPUT_WEIGHT + mw::BASE_KERNEL_WEIGHT;
    const size_t N = mw::MAX_BLOCK_WEIGHT / W_F; // 55
    BOOST_REQUIRE_EQUAL(W_F, 3602u);
    BOOST_REQUIRE_GT(N, 0u);
    BOOST_REQUIRE((N + 1) * W_F > mw::MAX_BLOCK_WEIGHT);
    const size_t expected_outs = N * OUTS_PER;
    BOOST_REQUIRE_GT(expected_outs, 6'260u);

    std::vector<test::TxOutput> utxos = MinePegins(*this, m_node, N + 1 + 2, COIN);
    BOOST_REQUIRE_EQUAL(utxos.size(), N + 1 + 2);
    DrainMempool(m_node);

    const CAmount fee = CFeeRate::GetMWEBFee(W_F);
    std::vector<TrackedTx> tracked;
    tracked.reserve(N + 1 + 2);

    for (size_t i = 0; i < N + 1; ++i) {
        BOOST_REQUIRE_GT(utxos[i].GetAmount(), fee + static_cast<CAmount>(OUTS_PER));
        std::vector<test::TxOutput> children;
        CMutableTransaction mtx = MakeFanOut(utxos[i], OUTS_PER, fee, children);
        BOOST_REQUIRE_EQUAL(TxMWEBWeight(CTransaction(mtx)), W_F);
        {
            LOCK2(::cs_main, pool.cs);
            const MempoolAcceptResult result = Assert(m_node.chainman)->ProcessTransaction(MakeTransactionRef(mtx));
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                                  strprintf("T1b-out fan-out[%u] ATMP failed: %s", i, result.m_state.ToString()));
        }
        tracked.push_back({mtx.GetHash(), MakeTransactionRef(mtx), fee, false, true});
    }

    for (int k = 0; k < 2; ++k) {
        CMutableTransaction mon = MakeSyntheticMonster(/*n_inputs=*/90'000, /*entry_fee_hint=*/1'000'000, static_cast<uint64_t>(k + 900));
        const CAmount mon_fee = 1'000'000;
        Submit(pool, mon, mon_fee);
        tracked.push_back({mon.GetHash(), MakeTransactionRef(mon), mon_fee, true, false});
    }

    BlockCreateOptions options;
    options.test_block_validity = true;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<CBlockTemplate> tmpl;
    try {
        tmpl = BlockAssembler{chainstate, &pool, options}.CreateNewBlock();
    } catch (const std::exception& e) {
        BOOST_REQUIRE_MESSAGE(false, strprintf("T1b-out CreateNewBlock threw: %s", e.what()));
    }
    BOOST_REQUIRE(tmpl);
    AssertNeverExceed(tmpl->block);

    const size_t n_fill = CountIncludedTracked(tmpl->block, tracked, /*fillers_only=*/true);
    const size_t n_mon = CountIncludedMonsters(tmpl->block, tracked);
    BOOST_CHECK_EQUAL(n_mon, 0u);
    BOOST_CHECK_EQUAL(n_fill, N);

    BOOST_REQUIRE(!tmpl->block.mweb_block.IsNull());
    BOOST_REQUIRE(tmpl->block.mweb_block.m_block);
    const auto& tip_body = tmpl->block.mweb_block.m_block->GetTxBody();
    BOOST_REQUIRE_EQUAL(tip_body.GetOutputs().size(), expected_outs);
    BOOST_REQUIRE_EQUAL(tip_body.GetKernels().size(), N);
    BOOST_REQUIRE_EQUAL(tip_body.GetInputs().size(), N);

    const LeftoverBudgets rem = LeftoverBudgetsOf(tmpl->block);
    LogFillMetrics("T1b-out", tmpl->block, rem, n_fill, /*S_f=*/0);
    AssertNearCapWeight(rem, W_F, "T1b-out");
    AssertNoGap(tmpl->block, pool, tracked, IncludedHashes(tmpl->block), "T1b-out");
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(chunk_failing_mid_way_is_unwound)
{
    MineToMwebChain(*this, m_node);
    DrainMempool(m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const CScript op_true = CScript() << OP_TRUE;

    // An unrelated peg-in in an earlier, higher-feerate chunk, still staged
    // when the failing chunk is unwound.
    const test::Tx earlier_pegin = test::Tx::CreatePegIn(COIN);
    const CTransactionRef& earlier_coinbase = m_coinbase_txns.at(2);
    const CAmount earlier_fee{20'000'000};
    CMutableTransaction earlier_hybrid = CreateValidTransaction(
                                           {earlier_coinbase},
                                           {COutPoint{earlier_coinbase->GetHash(), 0}},
                                           1,
                                           {coinbaseKey},
                                           {CTxOut{COIN, GetScriptForPegin(earlier_pegin.GetPegInCoin().GetKernelID())},
                                            CTxOut{earlier_coinbase->vout[0].nValue - COIN - earlier_fee, op_true}},
                                           std::nullopt,
                                           std::nullopt)
                                           .first;
    earlier_hybrid.mweb_tx = mw::MutableTx::From(*earlier_pegin.GetTransaction());

    // Parent: a valid hybrid peg-in, low feerate on its own.
    const test::Tx parent_pegin = test::Tx::CreatePegIn(COIN);
    const CTransactionRef& coinbase = m_coinbase_txns.at(1);
    const CAmount parent_fee{100'000};
    const CAmount parent_change = coinbase->vout[0].nValue - COIN - parent_fee;
    CMutableTransaction parent = CreateValidTransaction(
                                     {coinbase},
                                     {COutPoint{coinbase->GetHash(), 0}},
                                     1,
                                     {coinbaseKey},
                                     {CTxOut{COIN, GetScriptForPegin(parent_pegin.GetPegInCoin().GetKernelID())},
                                      CTxOut{parent_change, op_true}},
                                     std::nullopt,
                                     std::nullopt)
                                     .first;
    parent.mweb_tx = mw::MutableTx::From(*parent_pegin.GetTransaction());

    // Child: pays enough to pull the parent into its chunk, but its peg-in
    // output does not match its kernel, so it fails to stage after the parent.
    const test::Tx child_pegin = test::Tx::CreatePegIn(COIN);
    const CAmount child_fee{5'000'000};
    const CAmount child_change = parent_change - COIN / 2 - child_fee;
    CMutableTransaction child;
    child.vin.emplace_back(COutPoint{parent.GetHash(), 1});
    child.vout.emplace_back(COIN / 2, GetScriptForPegin(child_pegin.GetPegInCoin().GetKernelID()));
    child.vout.emplace_back(child_change, op_true);
    child.mweb_tx = mw::MutableTx::From(*child_pegin.GetTransaction());

    // Grandchild: its own, lower-feerate chunk, spending the child.
    const CAmount grandchild_fee{1'000};
    CMutableTransaction grandchild;
    grandchild.vin.emplace_back(COutPoint{child.GetHash(), 1});
    grandchild.vout.emplace_back(child_change - grandchild_fee, op_true);

    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(earlier_fee).Time(NodeSeconds{}).FromTx(earlier_hybrid));
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(parent_fee).Time(NodeSeconds{}).FromTx(parent));
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(child_fee).Time(NodeSeconds{}).FromTx(child));
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(grandchild_fee).Time(NodeSeconds{}).FromTx(grandchild));

    BlockCreateOptions options;
    options.test_block_validity = true;
    options.coinbase_output_script = op_true;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<CBlockTemplate> tmpl;
    BOOST_REQUIRE_NO_THROW(tmpl = BlockAssembler(chainstate, &pool, options).CreateNewBlock());
    BOOST_REQUIRE(tmpl);

    // The unwound chunk leaves no trace and keeps the earlier chunk, so the
    // residual pass can add the parent alone, and its MWEB part exactly once.
    const std::set<Txid> included = IncludedHashes(tmpl->block);
    BOOST_CHECK(included.contains(earlier_hybrid.GetHash()));
    BOOST_CHECK(included.contains(parent.GetHash()));
    BOOST_CHECK(!included.contains(child.GetHash()));
    BOOST_CHECK(!included.contains(grandchild.GetHash()));
    BOOST_CHECK(TemplateContainsMWEBTx(tmpl->block, CTransaction(earlier_hybrid)));
    BOOST_CHECK(TemplateContainsMWEBTx(tmpl->block, CTransaction(parent)));
    BOOST_CHECK(!TemplateContainsMWEBTx(tmpl->block, CTransaction(child)));
    BOOST_CHECK_EQUAL(tmpl->block.mweb_block.m_block->GetKernels().size(),
                      earlier_pegin.GetKernels().size() + parent_pegin.GetKernels().size());
    BOOST_CHECK_EQUAL(tmpl->m_package_feerates.size(), 1U);
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(hybrid_failing_fee_split_stages_nothing)
{
    MineToMwebChain(*this, m_node);
    DrainMempool(m_node);
    CTxMemPool& pool = *Assert(m_node.mempool);
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();

    // The kernel claims more fee than the entry pays, so the assembler rejects it.
    const CAmount kernel_fee{20'000};
    const test::Tx pegin = test::TxBuilder().AddPeginKernel(COIN).AddPlainKernel(kernel_fee).AddOutput(COIN - kernel_fee).Build();
    const CTransactionRef& coinbase = m_coinbase_txns.at(1);
    CMutableTransaction hybrid = CreateValidTransaction(
                                     {coinbase},
                                     {COutPoint{coinbase->GetHash(), 0}},
                                     1,
                                     {coinbaseKey},
                                     {CTxOut{COIN, GetScriptForPegin(pegin.GetPegInCoin().GetKernelID())},
                                      CTxOut{coinbase->vout[0].nValue - COIN - kernel_fee, CScript() << OP_TRUE}},
                                     std::nullopt,
                                     std::nullopt)
                                     .first;
    hybrid.mweb_tx = mw::MutableTx::From(*pegin.GetTransaction());
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(kernel_fee - 1).Time(NodeSeconds{}).FromTx(hybrid));

    BlockCreateOptions options;
    options.test_block_validity = true;
    options.coinbase_output_script = CScript() << OP_TRUE;
    options.block_min_fee_rate = CFeeRate{0};
    std::unique_ptr<CBlockTemplate> tmpl;
    BOOST_REQUIRE_NO_THROW(tmpl = BlockAssembler(chainstate, &pool, options).CreateNewBlock());
    BOOST_REQUIRE(tmpl);

    BOOST_CHECK(!IncludedHashes(tmpl->block).contains(hybrid.GetHash()));
    BOOST_CHECK(!TemplateContainsMWEBTx(tmpl->block, CTransaction(hybrid)));
    BOOST_CHECK(tmpl->block.mweb_block.m_block->GetKernels().empty());
    DrainMempool(m_node);
}

BOOST_AUTO_TEST_CASE(residual_fill_prefers_more_mweb_inputs_at_equal_size)
{
    const auto delta = [](const CTxMemPoolEntry& entry) {
        return MWEB::Miner::EstimateChunkSerializedDelta({std::cref(entry)});
    };
    const CTxMemPoolEntry two_inputs{TestMemPoolEntryHelper{}.FromTx(MakeSyntheticMonster(2, 0, 1, 1'000))};
    const CTxMemPoolEntry one_input_small{TestMemPoolEntryHelper{}.FromTx(MakeSyntheticMonster(1, 0, 2, 1'000))};
    BOOST_REQUIRE_GT(delta(two_inputs), delta(one_input_small));
    // Padding the one-input transaction's kernel to the two-input size leaves only the input count to differ.
    const CTxMemPoolEntry one_input{TestMemPoolEntryHelper{}.FromTx(
        MakeSyntheticMonster(1, 0, 2, 1'000 + delta(two_inputs) - delta(one_input_small)))};
    BOOST_REQUIRE_EQUAL(delta(one_input), delta(two_inputs));

    BOOST_CHECK(MWEB::Miner::ResidualFillBefore(two_inputs, one_input));
    BOOST_CHECK(!MWEB::Miner::ResidualFillBefore(one_input, two_inputs));
    // Size still decides first.
    BOOST_CHECK(MWEB::Miner::ResidualFillBefore(one_input_small, two_inputs));
    BOOST_CHECK(!MWEB::Miner::ResidualFillBefore(two_inputs, one_input_small));
}

BOOST_AUTO_TEST_SUITE_END()
