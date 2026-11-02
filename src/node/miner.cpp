// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/btc_launch_lock.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <interfaces/types.h>
#include <mw/consensus/params.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/node/coins_view.h>
#include <mweb/mweb_miner.h>
#include <mweb/mweb_models.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/mining_args.h>
#include <node/mining_types.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <sync.h>
#include <tinyformat.h>
#include <txgraph.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/log.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#include <algorithm>
#include <compare>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <numeric>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>

namespace node {

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    // Account for the BIP54 Murch-Zawy rule on all networks: the last block of
    // a difficulty adjustment period may not be earlier than its first block.
    if (height % difficulty_adjustment_interval == difficulty_adjustment_interval - 1) {
        const int first_height{height - static_cast<int>(difficulty_adjustment_interval) + 1};
        const CBlockIndex* first_block{Assert(pindexPrev->GetAncestor(first_height))};
        min_time = std::max<int64_t>(min_time, first_block->GetBlockTime());
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // ASERT (and testnet min-diff) depend on the candidate header time.
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockAssembler::BlockAssembler(Chainstate& chainstate,
                               const CTxMemPool* mempool,
                               BlockCreateOptions options)
    : mweb_miner(std::make_unique<MWEB::Miner>()),
      chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{[&] {
          if (auto result{CheckMiningOptions(options, /*use_argnames=*/false)}; !result) {
              throw std::runtime_error(util::ErrorString(result).original);
          }
          return FlattenMiningOptions(std::move(options));
      }()}
{
}

BlockAssembler::~BlockAssembler() = default;

void BlockAssembler::resetBlock()
{
    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = *Assert(m_options.block_reserved_weight);
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;
    nBlockMWEBWeight = 0;
    fIncludeMWEB = false;

    // Serialized-size baseline: header + max CompactSize(vtx) + coinbase pad.
    // MWEB HogEx / extension reserve is added once fIncludeMWEB is known.
    const size_t BLOCK_HEADER_BYTES = ::GetSerializeSize(CBlockHeader{});
    constexpr size_t MAX_COMPACTSIZE_BYTES = 9;
    nBlockSerializedSize = BLOCK_HEADER_BYTES + MAX_COMPACTSIZE_BYTES + MWEB::BLOCK_SERIALIZED_COINBASE_RESERVE;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction. It is skipped by the
    // getblocktemplate RPC and mining interface consumers must not use it.
    pblock->vtx.emplace_back();

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    // MWEB: Every block after activation needs the extension block and HogEx,
    // including templates built without a mempool.
    fIncludeMWEB = DeploymentActiveAfter(pindexPrev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_MWEB, m_chainstate.m_chainman.m_versionbitscache);
    if (fIncludeMWEB) {
        const mw::ICoinsView::Ptr mweb_view{m_chainstate.CoinsTip().GetMWEBView()};
        if (!mweb_view) {
            throw std::runtime_error("MWEB view not initialized");
        }
        const bool has_prev_hogex = pindexPrev->mweb_header != nullptr;
        mweb_miner->NewBlock(nHeight, mweb_view, has_prev_hogex);
        // Reserve HogEx + empty extension; grows as MWEB txs are added.
        nBlockSerializedSize += mweb_miner->EstimateSerializedExtensionBytes();
    }

    if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->StartBlockBuilding();
        addChunks();
        m_mempool->StopBlockBuilding();
    }

    if (fIncludeMWEB) {
        mweb_miner->AddHogExTransaction(pindexPrev, pblock, pblocktemplate->vTxFees, pblocktemplate->vTxSigOpsCost, nFees);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;
    m_last_block_mweb_weight = nBlockMWEBWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;

    // Construct coinbase transaction struct in parallel
    CoinbaseTx& coinbase_tx{pblocktemplate->m_coinbase_tx};
    coinbase_tx.version = coinbaseTx.version;

    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
    coinbase_tx.sequence = coinbaseTx.vin[0].nSequence;

    // Add an output that spends the full coinbase reward.
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    // Block subsidy + fees
    const CAmount block_reward{nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
    coinbaseTx.vout[0].nValue = block_reward;
    coinbase_tx.block_reward_remaining = block_reward;

    if (nHeight == 1 && chainparams.GetConsensus().btc_launch_lock.enabled) {
        const std::string header_hex{gArgs.GetArg("-btclaunchheader", "")};
        if (!header_hex.empty()) {
            const auto header = TryParseHex<unsigned char>(header_hex);
            if (!header || header->size() != BTC_LAUNCH_HEADER_SIZE) {
                throw std::runtime_error(
                    "Invalid -btclaunchheader: must be 160 hex characters (80-byte Bitcoin block header)");
            }
            CTxOut lock_out;
            lock_out.nValue = 0;
            lock_out.scriptPubKey = BuildBtcLaunchLockScript(*header);
            coinbaseTx.vout.push_back(lock_out);
        }
    }

    // Start the coinbase scriptSig with the block height as required by BIP34.
    // Mining clients are expected to append extra data to this prefix, so
    // increasing its length would reduce the space they can use and may break
    // existing clients.
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight;
    // Set script_sig_prefix here, so IPC mining clients are not affected by
    // the optional scriptSig padding below. They provide their own extraNonce,
    // and in a typical setup a pool name or realistic extraNonce already makes
    // the scriptSig long enough.
    coinbase_tx.script_sig_prefix = coinbaseTx.vin[0].scriptSig;
    if (nHeight <= 16) {
        // For blocks at heights <= 16, the BIP34-encoded height alone is only
        // one byte. Consensus requires coinbase scriptSigs to be at least two
        // bytes long (bad-cb-length), so an OP_0 is always appended at those
        // heights.
        coinbaseTx.vin[0].scriptSig << OP_0;
    }
    Assert(nHeight > 0);
    coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
    coinbase_tx.lock_time = coinbaseTx.nLockTime;

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    // Exact wire size after HogEx + coinbase commitment. Estimates are
    // pessimistic, so this should never exceed the consensus cap.
    {
        const size_t exact_size = ::GetSerializeSize(TX_WITH_WITNESS(*pblock));
        if (exact_size > MAX_BLOCK_SERIALIZED_SIZE_MINE) {
            throw std::runtime_error(strprintf(
                "CreateNewBlock: serialized size %u exceeds mine cap %u (estimate was %u)",
                exact_size, MAX_BLOCK_SERIALIZED_SIZE_MINE, nBlockSerializedSize));
        }
    }

    const CTransactionRef& final_coinbase{pblock->vtx[0]};
    if (final_coinbase->HasWitness()) {
        const auto& witness_stack{final_coinbase->vin[0].scriptWitness.stack};
        // Consensus requires the coinbase witness stack to have exactly one
        // element of 32 bytes.
        Assert(witness_stack.size() == 1 && witness_stack[0].size() == 32);
        coinbase_tx.witness = uint256(witness_stack[0]);
    }
    if (const int witness_index = GetWitnessCommitmentIndex(*pblock); witness_index != NO_WITNESS_COMMITMENT) {
        Assert(witness_index >= 0 && static_cast<size_t>(witness_index) < final_coinbase->vout.size());
        coinbase_tx.required_outputs.push_back(final_coinbase->vout[witness_index]);
    }
    if (const auto lock_index = GetBtcLaunchLockOutputIndex(*final_coinbase)) {
        coinbase_tx.required_outputs.push_back(final_coinbase->vout[*lock_index]);
    }

    LogDebug(BCLog::MINING, "CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d MWEB weight: %u serialized: %u\n",
             GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost, nBlockMWEBWeight,
             ::GetSerializeSize(TX_WITH_WITNESS(*pblock)));

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;

    // MINE_TEST_MWEB_SIZE builds near-max templates that intentionally violate
    // production MWEB input/weight caps for reject functionals; skip validity.
#if !defined(MINE_TEST_MWEB_SIZE)
    if (m_options.test_block_validity) {
        if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
            throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }
#endif
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() chunks: %.2fms, validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

BlockAssembler::ChunkLimitReject BlockAssembler::EvaluateChunkBlockLimits(
    const std::vector<CTxMemPoolEntryRef>& txs,
    int64_t chunk_weight,
    int64_t chunk_sigops_cost,
    uint64_t chunk_mweb_weight) const
{
    // block_max_weight has been flattened before block assembly limit checks.
    Assert(m_options.block_max_weight);
    if (nBlockWeight + chunk_weight >= *m_options.block_max_weight) {
        return ChunkLimitReject::Other;
    }
    if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) {
        return ChunkLimitReject::Other;
    }

    // MWEB: CreateNewBlock selection — weight/inputs/size fit on MWEB::Miner.
    // When not including MWEB, still enforce weight + serialized size (inputs gate skipped).
    if (fIncludeMWEB) {
        const auto mweb_reject = mweb_miner->CheckChunkFit(
            nBlockMWEBWeight, chunk_mweb_weight, nBlockSerializedSize, txs);
        if (mweb_reject == MWEB::ChunkFitReject::Size) {
            return ChunkLimitReject::Size;
        }
        if (mweb_reject != MWEB::ChunkFitReject::None) {
            return ChunkLimitReject::Other;
        }
    } else {
        if (nBlockMWEBWeight + chunk_mweb_weight > mw::MAX_BLOCK_WEIGHT) {
            return ChunkLimitReject::Other;
        }
        const uint64_t chunk_ser_delta = MWEB::Miner::EstimateChunkSerializedDelta(txs);
        if (nBlockSerializedSize + chunk_ser_delta > MAX_BLOCK_SERIALIZED_SIZE_MINE) {
            return ChunkLimitReject::Size;
        }
        const uint64_t remaining = MAX_BLOCK_SERIALIZED_SIZE_MINE - nBlockSerializedSize;
        if (remaining < MWEB::BLOCK_SERIALIZED_SIZE_PRESSURE) {
            if (MWEB::Miner::CountChunkMWEBInputs(txs) * mw::INPUT_BYTES > remaining) {
                return ChunkLimitReject::Size;
            }
        }
    }

    return ChunkLimitReject::None;
}

bool BlockAssembler::TestChunkBlockLimits(const std::vector<CTxMemPoolEntryRef>& txs,
                                          int64_t chunk_weight,
                                          int64_t chunk_sigops_cost,
                                          uint64_t chunk_mweb_weight) const
{
    return EvaluateChunkBlockLimits(txs, chunk_weight, chunk_sigops_cost, chunk_mweb_weight) ==
           ChunkLimitReject::None;
}

// True when BIP68 relative locks can actually constrain this tx. SEQUENCE_FINAL
// (and any nSequence with the disable bit) does not need BIP68 evaluation.
static bool HasEnabledSequenceLocks(const CTransaction& tx)
{
    if (tx.version < 2) return false;
    for (const auto& txin : tx.vin) {
        if ((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
            return true;
        }
    }
    return false;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - BIP68 relative locks when enabled
// - input presence when templates are self-validated (skips orphans / extra coinbases)
bool BlockAssembler::TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const
{
    AssertLockHeld(::cs_main);
    CBlockIndex* tip{m_chainstate.m_chain.Tip()};
    std::optional<CCoinsViewMemPool> view_mempool;
    if (m_mempool) {
        view_mempool.emplace(&m_chainstate.CoinsTip(), *m_mempool);
    }
    for (const auto tx : txs) {
        const CTransaction& tx_raw = tx.get().GetTx();
        if (!IsFinalTx(tx_raw, nHeight, m_lock_time_cutoff)) {
            return false;
        }
        // CSV is buried at height 0. Resolve coins when BIP68 can apply, or when
        // CreateNewBlock will TestBlockValidity (so orphans cannot poison the
        // template). Packing fixtures set test_block_validity=false and use
        // synthetic SEQUENCE_FINAL prevouts that must still be selectable.
        if (view_mempool && !tx_raw.IsMWEBOnly() &&
            (m_options.test_block_validity || HasEnabledSequenceLocks(tx_raw))) {
            const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(tip, *view_mempool, tx_raw)};
            if (!lock_points.has_value()) {
                return false;
            }
            if (HasEnabledSequenceLocks(tx_raw) && !CheckSequenceLocksAtTip(tip, *lock_points)) {
                return false;
            }
        }
        if (!fIncludeMWEB && tx_raw.HasMWEBTx()) {
            return false;
        }
    }
    return true;
}

bool BlockAssembler::AddToBlock(const CTxMemPoolEntry& entry)
{
    const CTransaction& raw_tx = entry.GetTx();
    const uint64_t ser_before_ext = fIncludeMWEB ? mweb_miner->EstimateSerializedExtensionBytes() : 0;
    const size_t l1_stub_bytes = MWEB::Miner::EstimateTxL1StubBytes(raw_tx);

    // MWEB: Check the hybrid's fee and sigop split before staging its MWEB
    // part, so a rejected transaction leaves nothing staged.
    CAmount hogex_fee = 0;
    int64_t hogex_sigops = 0;
    if (raw_tx.HasMWEBTx() && !raw_tx.IsMWEBOnly()) {
        const auto tx_fee = raw_tx.mweb_tx.GetFee();
        if (!tx_fee || *tx_fee > entry.GetFee()) {
            LogInfo("Invalid MWEB fee amount\n");
            return false;
        }

        hogex_fee = *tx_fee;
        hogex_sigops = MWEB::Miner::GetHogExSigOpCost(raw_tx);
        if (hogex_sigops > entry.GetSigOpCost()) {
            LogInfo("Invalid MWEB sigop cost\n");
            return false;
        }
    }

    if (raw_tx.HasMWEBTx() && !mweb_miner->AddMWEBTransaction(entry)) {
        return false;
    }

    CTransactionRef pTx = entry.GetSharedTx();
    if (!pTx->IsMWEBOnly()) {
        if (pTx->HasMWEBTx() || pTx->HadAttachedMWEB()) {
            CMutableTransaction mutable_tx(*pTx);
            mutable_tx.ClearAttachedMWEB();
            pTx = MakeTransactionRef(std::move(mutable_tx));
        }

        pblocktemplate->block.vtx.emplace_back(pTx);
        pblocktemplate->vTxFees.push_back(entry.GetFee() - hogex_fee);
        pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost() - hogex_sigops);
        ++nBlockTx;
    }

    // Update serialized-size estimate: L1 stub + extension delta.
    constexpr size_t MAX_COMPACTSIZE_BYTES = 9;
    if (l1_stub_bytes > 0) {
        nBlockSerializedSize += l1_stub_bytes + MAX_COMPACTSIZE_BYTES;
    }
    if (fIncludeMWEB && raw_tx.HasMWEBTx()) {
        const uint64_t ser_after_ext = mweb_miner->EstimateSerializedExtensionBytes();
        if (ser_after_ext > ser_before_ext) {
            nBlockSerializedSize += ser_after_ext - ser_before_ext;
        }
    }

    nBlockWeight += entry.GetTxWeight();
    nBlockSigOpsCost += entry.GetSigOpCost();
    nBlockMWEBWeight += entry.GetMWEBWeight();
    nFees += entry.GetFee();

    if (*m_options.print_modified_fee) {
        LogInfo("fee rate %s txid %s\n",
                  CFeeRate(entry.GetModifiedFee(), entry.GetTxSize()).ToString(),
                  entry.GetTx().GetHash().ToString());
    }

    return true;
}

void BlockAssembler::AddResidualFill(std::set<Txid>& included)
{
    // After the feerate-first walk, fill any leftover budget from remaining
    // mempool txs, smallest serialized delta first, until none fit.
    bool added_any;
    do {
        added_any = false;

        std::vector<CTxMemPoolEntryRef> candidates;
        candidates.reserve(m_mempool->size());
        for (const auto& entry : m_mempool->entryAll()) {
            const Txid& hash = entry.get().GetTx().GetHash();
            if (included.contains(hash)) continue;

            // Require all in-mempool parents already in the template (no tearing).
            bool parents_ok = true;
            for (const auto& parent : m_mempool->GetParents(entry.get())) {
                if (!included.contains(parent.get().GetTx().GetHash())) {
                    parents_ok = false;
                    break;
                }
            }
            if (!parents_ok) continue;
            candidates.push_back(entry);
        }

        std::stable_sort(candidates.begin(), candidates.end(), MWEB::Miner::ResidualFillBefore);

        for (const auto& entry : candidates) {
            const std::vector<CTxMemPoolEntryRef> chunk{entry};
            const int64_t chunk_sig_ops = entry.get().GetSigOpCost();
            const int64_t chunk_weight = entry.get().GetTxWeight();
            const uint64_t chunk_mweb_weight = entry.get().GetMWEBWeight();
            const CAmount chunk_fees = entry.get().GetModifiedFee();
            const int32_t chunk_vsize = entry.get().GetTxSize();

            if (m_options.block_min_fee_rate->GetTotalFee(chunk_vsize, chunk_mweb_weight) > chunk_fees) {
                continue;
            }
            if (!TestChunkBlockLimits(chunk, chunk_weight, chunk_sig_ops, chunk_mweb_weight) ||
                !TestChunkTransactions(chunk)) {
                continue;
            }
            if (!AddToBlock(entry.get())) {
                continue;
            }
            included.insert(entry.get().GetTx().GetHash());
            added_any = true;
            // Keep scanning this sorted pass; another pass re-sorts leftovers.
        }
    } while (added_any);
}

void BlockAssembler::addChunks()
{
    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    std::set<Txid> included;

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> selected_transactions;
    selected_transactions.reserve(MAX_CLUSTER_COUNT_LIMIT);
    FeePerWeight chunk_feerate;

    // This fills selected_transactions
    chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
    FeePerVSize chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);

    while (selected_transactions.size() > 0) {
        int64_t chunk_sig_ops = 0;
        int64_t chunk_weight = 0;
        uint64_t chunk_mweb_weight = 0;
        for (const auto& tx : selected_transactions) {
            chunk_sig_ops += tx.get().GetSigOpCost();
            chunk_mweb_weight += tx.get().GetMWEBWeight();
            chunk_weight += tx.get().GetTxWeight();
        }

        const CAmount chunk_fees = std::accumulate(selected_transactions.begin(), selected_transactions.end(), CAmount{0},
            [](CAmount sum, const auto& tx) { return sum + tx.get().GetModifiedFee(); });
        const int32_t chunk_vsize = std::accumulate(selected_transactions.begin(), selected_transactions.end(), int32_t{0},
            [](int32_t sum, const auto& tx) { return sum + tx.get().GetTxSize(); });

        // Check to see if min fee rate is still respected.
        if (m_options.block_min_fee_rate->GetTotalFee(chunk_vsize, chunk_mweb_weight) > chunk_fees) {
            // Everything else we might consider has a lower feerate — residual next.
            break;
        }

        const ChunkLimitReject limit_reject =
            EvaluateChunkBlockLimits(selected_transactions, chunk_weight, chunk_sig_ops, chunk_mweb_weight);
        const bool tx_ok = TestChunkTransactions(selected_transactions);

        if (limit_reject != ChunkLimitReject::None || !tx_ok) {
            // Pure size skips do not charge consecutive failures (avoids early-exit
            // starvation when large high-feerate chunks precede small fillers).
            if (limit_reject != ChunkLimitReject::Size || !tx_ok) {
                ++nConsecutiveFailed;
            }
            m_mempool->SkipBuilderChunk();

            const uint64_t remaining_ser = nBlockSerializedSize < MAX_BLOCK_SERIALIZED_SIZE_MINE
                                               ? MAX_BLOCK_SERIALIZED_SIZE_MINE - nBlockSerializedSize
                                               : 0;
            // block_max_weight has been flattened before block assembly limit checks.
            Assert(m_options.block_max_weight);
            const bool weight_near_full =
                nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > *m_options.block_max_weight;
            const bool size_near_full = remaining_ser < MWEB::BLOCK_SERIALIZED_SIZE_PRESSURE;
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && (weight_near_full || size_near_full)) {
                // Give up primary walk; residual may still fill leftovers.
                break;
            }
        } else {
            // MWEB: Add the chunk whole or not at all. A transaction that fails to
            // stage unwinds the chunk, so the block never holds part of a chunk
            // while the graph treats the rest, and its descendants, as included.
            const size_t num_txs{pblocktemplate->block.vtx.size()};
            const size_t num_fees{pblocktemplate->vTxFees.size()};
            const size_t num_sigops{pblocktemplate->vTxSigOpsCost.size()};
            const auto block_totals{std::tuple{nBlockWeight, nBlockTx, nBlockSigOpsCost, nBlockMWEBWeight, nBlockSerializedSize, nFees}};
            const auto mweb_checkpoint{fIncludeMWEB ? std::make_optional(mweb_miner->GetCheckpoint()) : std::nullopt};
            const bool added{std::all_of(selected_transactions.begin(), selected_transactions.end(),
                                         [this](const auto& tx) { return AddToBlock(tx); })};
            if (!added) {
                pblocktemplate->block.vtx.resize(num_txs);
                pblocktemplate->vTxFees.resize(num_fees);
                pblocktemplate->vTxSigOpsCost.resize(num_sigops);
                std::tie(nBlockWeight, nBlockTx, nBlockSigOpsCost, nBlockMWEBWeight, nBlockSerializedSize, nFees) = block_totals;
                if (mweb_checkpoint) mweb_miner->Restore(*mweb_checkpoint);
                ++nConsecutiveFailed;
                m_mempool->SkipBuilderChunk();
            } else {
                m_mempool->IncludeBuilderChunk();

                // This chunk fit and was added to the block.
                nConsecutiveFailed = 0;
                for (const auto& tx : selected_transactions) {
                    included.insert(tx.get().GetTx().GetHash());
                }
                pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize);
            }
        }

        selected_transactions.clear();
        chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
        chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);
    }

    AddResidualFill(included);
}

void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint64_t timestamp, uint64_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Reset cached checks
    block.m_checked_witness_commitment = false;
    block.m_checked_merkle_root = false;
    block.fChecked = false;
}

namespace {
class SubmitBlockStateCatcher final : public CValidationInterface
{
public:
    uint256 m_hash;
    bool m_found{false};
    BlockValidationState m_state;

    explicit SubmitBlockStateCatcher(const uint256& hash) : m_hash{hash} {}

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        if (block->GetHash() != m_hash) return;
        // ProcessNewBlock emits BlockChecked synchronously while holding cs_main,
        // so SubmitBlock can read these fields after ProcessNewBlock returns
        // without extra synchronization.
        m_found = true;
        m_state = state;
    }
};
} // namespace

bool SubmitBlock(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& block, std::string& reason, std::string& debug)
{
    reason.clear();
    debug.clear();

    // This follows the submitblock RPC's validation-state capture pattern, but
    // is intentionally kept separate from the RPC implementation. The RPC entry
    // point decodes hex, formats BIP22/JSONRPC results, and calls
    // UpdateUncommittedBlockStructures() for legacy witness handling. IPC
    // callers submit already-formed blocks and need bool + reason/debug
    // results.
    auto sc = std::make_shared<SubmitBlockStateCatcher>(block->GetHash());
    CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
    bool new_block;
    bool accepted = chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    // No queue drain is needed. The BlockChecked notification used above is
    // emitted synchronously by ProcessNewBlock, unlike most validation signals.
    CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);

    if (!new_block && accepted) {
        reason = "duplicate";
    } else if (!accepted && (!sc->m_found || sc->m_state.IsValid())) {
        // ProcessNewBlock can fail without a validation result, for example
        // from an activation or system error. It can also fail after a valid
        // BlockChecked result. In these cases the validation result is
        // inconclusive.
        reason = "inconclusive";
    } else if (!sc->m_found) {
        // The block was accepted but not connected, for example if it does not
        // have more work than the current tip.
        reason = "inconclusive";
    } else if (!sc->m_state.IsValid()) {
        reason = sc->m_state.GetRejectReason();
        debug = sc->m_state.GetDebugMessage();
    }
    const bool result{accepted && new_block && reason.empty()};
    CHECK_NONFATAL(result == reason.empty());
    return result;
}

void InterruptWait(KernelNotifications& kernel_notifications, bool& interrupt_wait)
{
    LOCK(kernel_notifications.m_tip_block_mutex);
    interrupt_wait = true;
    kernel_notifications.m_tip_block_cv.notify_all();
}

std::unique_ptr<CBlockTemplate> WaitAndCreateNewBlock(ChainstateManager& chainman,
                                                      KernelNotifications& kernel_notifications,
                                                      CTxMemPool* mempool,
                                                      const std::unique_ptr<CBlockTemplate>& block_template,
                                                      const BlockWaitOptions& wait_options,
                                                      const BlockCreateOptions& create_options,
                                                      bool& interrupt_wait)
{
    // Delay calculating the current template fees, just in case a new block
    // comes in before the next tick.
    CAmount current_fees = -1;

    // Alternate waiting for a new tip and checking if fees have risen.
    // The latter check is expensive so we only run it once per second.
    // Use SteadyClock for the wait deadline: NodeClock may be mocked to a
    // future launch genesis, and wait_until(NodeClock) would sleep until that
    // wall-calendar time on the real system clock.
    auto now_steady{SteadyClock::now()};
    const auto deadline = now_steady + wait_options.timeout;
    const MillisecondsDouble tick{1000};
    const bool allow_min_difficulty{chainman.GetParams().GetConsensus().fPowAllowMinDifficultyBlocks};

    do {
        bool tip_changed{false};
        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            // Note that wait_until() checks the predicate before waiting
            kernel_notifications.m_tip_block_cv.wait_until(lock, std::min(now_steady + tick, deadline), [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                AssertLockHeld(kernel_notifications.m_tip_block_mutex);
                const auto tip_block{kernel_notifications.TipBlock()};
                // We assume tip_block is set, because this is an instance
                // method on BlockTemplate and no template could have been
                // generated before a tip exists.
                tip_changed = Assume(tip_block) && tip_block != block_template->block.hashPrevBlock;
                return tip_changed || chainman.m_interrupt || interrupt_wait;
            });
            if (interrupt_wait) {
                interrupt_wait = false;
                return nullptr;
            }
        }

        if (chainman.m_interrupt) return nullptr;
        // At this point the tip changed, a full tick went by or we reached
        // the deadline.

        // Must release m_tip_block_mutex before locking cs_main, to avoid deadlocks.
        LOCK(::cs_main);

        // On test networks return a minimum difficulty block after 20 minutes
        if (!tip_changed && allow_min_difficulty) {
            const NodeClock::time_point tip_time{std::chrono::milliseconds{chainman.ActiveChain().Tip()->GetBlockTime()}};
            if (NodeClock::now() > tip_time + 20min) {
                tip_changed = true;
            }
        }

        /**
         * We determine if fees increased compared to the previous template by generating
         * a fresh template. There may be more efficient ways to determine how much
         * (approximate) fees for the next block increased, perhaps more so after
         * Cluster Mempool.
         *
         * We'll also create a new template if the tip changed during this iteration.
         */
        if (wait_options.fee_threshold < MAX_MONEY || tip_changed) {
            auto new_tmpl{BlockAssembler{
                chainman.ActiveChainstate(),
                mempool,
                create_options
                }.CreateNewBlock()};

            // If the tip changed, return the new template regardless of its fees.
            if (tip_changed) return new_tmpl;

            // Calculate the original template total fees if we haven't already
            if (current_fees == -1) {
                current_fees = std::accumulate(block_template->vTxFees.begin(), block_template->vTxFees.end(), CAmount{0});
            }

            // Check if fees increased enough to return the new template
            const CAmount new_fees = std::accumulate(new_tmpl->vTxFees.begin(), new_tmpl->vTxFees.end(), CAmount{0});
            Assume(wait_options.fee_threshold != MAX_MONEY);
            if (new_fees >= current_fees + wait_options.fee_threshold) return new_tmpl;
        }

        now_steady = SteadyClock::now();
    } while (now_steady < deadline);

    return nullptr;
}

std::optional<BlockRef> GetTip(ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!tip) return {};
    return BlockRef{tip->GetBlockHash(), tip->nHeight};
}

bool CooldownIfHeadersAhead(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const BlockRef& last_tip, bool& interrupt_mining)
{
    uint256 last_tip_hash{last_tip.hash};

    while (const std::optional<int> remaining = chainman.BlocksAheadOfTip()) {
        const int cooldown_seconds = std::clamp(*remaining, 3, 20);
        const auto cooldown_deadline{MockableSteadyClock::now() + std::chrono::seconds{cooldown_seconds}};

        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            kernel_notifications.m_tip_block_cv.wait_until(lock, cooldown_deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                const auto tip_block = kernel_notifications.TipBlock();
                return chainman.m_interrupt || interrupt_mining || (tip_block && *tip_block != last_tip_hash);
            });
            if (chainman.m_interrupt || interrupt_mining) {
                interrupt_mining = false;
                return false;
            }

            // If the tip changed during the wait, extend the deadline
            const auto tip_block = kernel_notifications.TipBlock();
            if (tip_block && *tip_block != last_tip_hash) {
                last_tip_hash = *tip_block;
                continue;
            }
        }

        // No tip change and the cooldown window has expired.
        if (MockableSteadyClock::now() >= cooldown_deadline) break;
    }

    return true;
}

std::optional<BlockRef> WaitTipChanged(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const uint256& current_tip, MillisecondsDouble& timeout, bool& interrupt)
{
    Assume(timeout >= 0ms); // No internal callers should use a negative timeout
    if (timeout < 0ms) timeout = 0ms;
    if (timeout > std::chrono::years{100}) timeout = std::chrono::years{100}; // Upper bound to avoid UB in std::chrono
    auto deadline{std::chrono::steady_clock::now() + timeout};
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        // For callers convenience, wait longer than the provided timeout
        // during startup for the tip to be non-null. That way this function
        // always returns valid tip information when possible and only
        // returns null when shutting down, not when timing out.
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || chainman.m_interrupt || interrupt;
        });
        if (chainman.m_interrupt || interrupt) {
            interrupt = false;
            return {};
        }
        // At this point TipBlock is set, so continue to wait until it is
        // different then `current_tip` provided by caller.
        kernel_notifications.m_tip_block_cv.wait_until(lock, deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return Assume(kernel_notifications.TipBlock()) != current_tip || chainman.m_interrupt || interrupt;
        });
        if (chainman.m_interrupt || interrupt) {
            interrupt = false;
            return {};
        }
    }

    // Must release m_tip_block_mutex before getTip() locks cs_main, to
    // avoid deadlocks.
    return GetTip(chainman);
}

} // namespace node
