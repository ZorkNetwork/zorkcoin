
#ifndef BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_BUILDER_H
#define BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_BUILDER_H
#include <mw/common/macros.h>
#include <mw/consensus/kernel_sum_validator.h>
#include <mw/consensus/params.h>
#include <mw/consensus/stealth_sum_validator.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/tx/peg_in_coin.h>
#include <mw/node/coins_view.h>
#include <memory>
#include <set>

MW_NAMESPACE

class BlockBuilder
{
public:
    using Ptr = std::shared_ptr<BlockBuilder>;

    /// <summary>
    /// Constructs a new BlockBuilder for assembling an MW ext block incrementally (tx by tx).
    /// </summary>
    /// <param name="height">The height of the block being built.</param>
    /// <param name="view">The CoinsView representing the latest state of the active chain. Must not be null.</param>
    /// <param name="max_weight">Assembler weight budget (defaults to consensus mw::MAX_BLOCK_WEIGHT).
    /// Mine-test binaries may raise this slightly to build +ε overweight reject templates.</param>
    /// <returns>A non-null BlockBuilder</returns>
    BlockBuilder(const uint64_t height, const mw::ICoinsView::Ptr& pCoinsView,
                 const uint64_t max_weight = mw::MAX_BLOCK_WEIGHT)
        : m_height(height), m_max_weight(max_weight),
          m_pCoinsView(std::make_shared<mw::CoinsViewCache>(pCoinsView)) { }

    bool AddTransaction(const Transaction::CPtr& pTransaction, const std::vector<PegInCoin>& pegins);

    /// <summary>
    /// The staged state at one point, so transactions added after it can be unstaged.
    /// </summary>
    struct Checkpoint {
        size_t num_txs;
        uint64_t weight;
        KernelSumValidator::SumState kernel_sums;
        StealthSumValidator::SumState stealth_sums;
    };
    Checkpoint GetCheckpoint() const;

    /// <summary>
    /// Unstages every transaction added after the checkpoint was taken.
    /// </summary>
    void Rollback(const Checkpoint& checkpoint);

    mw::Block::Ptr BuildBlock() const;

private:
    uint64_t m_height;
    uint64_t m_weight{0};
    uint64_t m_max_weight;
    mw::CoinsViewCache::Ptr m_pCoinsView;

    std::vector<Transaction::CPtr> m_stagedTxs;
    std::set<Hash> m_stagedInputs;
    std::set<Hash> m_stagedOutputs;
    std::set<Hash> m_stagedKernels;
    KernelSumValidator::SumState m_kernelSums;
    StealthSumValidator::SumState m_stealthSums;
};

END_NAMESPACE // mw
#endif // BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_BUILDER_H
