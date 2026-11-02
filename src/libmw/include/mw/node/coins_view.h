
#ifndef BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_H
#define BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_H
#include <mw/common/macros.h>
#include <mw/models/block/header.h>
#include <mw/models/block/block.h>
#include <mw/models/block/block_undo.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/tx/utxo.h>
#include <mw/mmr/mmr.h>
#include <mw/mmr/leaf_set.h>
#include <mw/interfaces/db_interface.h>
#include <memory>
#include <unordered_map>

// Forward Declarations
class CoinDB;
class CoinsViewUpdates;

MW_NAMESPACE

//
// An interface for the various views of the extension block's UTXO set.
// This is similar to CCoinsView in the main codebase, and in fact, each CCoinsView
// should also hold an instance of a mw::ICoinsView for use with MWEB-related logic.
//
class ICoinsView : public std::enable_shared_from_this<ICoinsView>
{
public:
    using Ptr = std::shared_ptr<ICoinsView>;
    using CPtr = std::shared_ptr<const ICoinsView>;

    ICoinsView(const mw::Header::CPtr& pHeader, const std::shared_ptr<mw::DBWrapper>& pDBWrapper)
        : m_pHeader(pHeader), m_pDatabase(pDBWrapper) { }
    virtual ~ICoinsView() = default;

    void SetBestHeader(const mw::Header::CPtr& pHeader) noexcept { m_pHeader = pHeader; }
    mw::Header::CPtr GetBestHeader() const noexcept { return m_pHeader; }

    const std::shared_ptr<mw::DBWrapper>& GetDatabase() const noexcept { return m_pDatabase; }
    void SetDatabase(const std::shared_ptr<mw::DBWrapper>& pDBWrapper) noexcept { m_pDatabase = pDBWrapper; }

    virtual bool IsCache() const noexcept = 0;

    // Virtual functions
    virtual UTXO::CPtr GetUTXO(const mw::Hash& output_id) const = 0;
    virtual void WriteBatch(
        const mw::DBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) = 0;

    virtual ILeafSet::Ptr GetLeafSet() const noexcept = 0;
    virtual IMMR::Ptr GetOutputPMMR() const noexcept = 0;

    /// <summary>
    /// Checks if there's a unspent coin in the view with a matching commitment.
    /// </summary>
    /// <param name="output_id">The output ID of the UTXO to look for.</param>
    /// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
    bool HasCoin(const mw::Hash& output_id) const noexcept { return GetUTXO(output_id) != nullptr; }

    /// <summary>
    /// Checks if there's a unspent coin with a matching commitment in the view that has not been flushed to the parent.
    /// This is useful for checking if a coin is in the mempool but not yet on chain.
    /// </summary>
    /// <param name="output_id">The output ID of the coin to look for.</param>
    /// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
    virtual bool HasCoinInCache(const mw::Hash& output_id) const noexcept = 0;

    /// <summary>
    /// Cleanup any old MMR files that no longer reflect the latest flushed state.
    /// </summary>
    virtual void Compact() const = 0;

private:
    mw::Header::CPtr m_pHeader;
    std::shared_ptr<mw::DBWrapper> m_pDatabase;
};

class CoinsViewCache : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewCache>;
    using CPtr = std::shared_ptr<const CoinsViewCache>;

    explicit CoinsViewCache(const ICoinsView::Ptr& pBase);

    bool IsCache() const noexcept final { return true; }

    UTXO::CPtr GetUTXO(const mw::Hash& output_id) const noexcept final;

    /// <summary>
    /// Validates and connects the block to the end of the chain.
    /// Consumer is required to call ValidateBlock first.
    /// </summary>
    /// <pre>Block must be validated via CheckBlock before connecting it to the chain.</pre>
    /// <param name="pBlock">The block to connect. Must not be null.</param>
    /// <throws>ValidationException if consensus rules are not met.</throws>
    mw::BlockUndo::CPtr ApplyBlock(const mw::Block::CPtr& pBlock, bool allow_historical_metadata_mismatch = false);

    void AddTx(const mw::Transaction::CPtr& pTx);

    /// <summary>
    /// Removes a block from the end of the chain.
    /// </summary>
    /// <param name="pUndo">The MWEB undo data to apply. Must not be null.</param>
    void UndoBlock(const mw::BlockUndo::CPtr& pUndo);

    void WriteBatch(
        const mw::DBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Compact() const final {
        if (GetBestHeader() != nullptr) {
            m_pBase->Compact();
        }
    }

    /// <summary>
    /// Commits the changes from the cached CoinsView to the base CoinsView.
    /// Adds the cached updates to the database if the base CoinsView is a DB view.
    /// </summary>
    /// <param name="pBatch">The optional DB batch. This must be non-null when the base CoinsView is a DB view.</param>
    void Flush(const mw::DBBatch::UPtr& pBatch = nullptr);

    mw::Block::Ptr BuildNextBlock(uint64_t height, const std::vector<mw::Transaction::CPtr>& transactions);

    bool HasCoinInCache(const mw::Hash& output_id) const noexcept final;
    bool HasSpendInCache(const mw::Hash& output_id) const noexcept;

    ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

private:
    mw::BlockUndo::CPtr ApplyBlockChanges(const mw::Block::CPtr& pBlock, bool allow_historical_metadata_mismatch);
    void AddUTXO(uint64_t header_height, const Output& output);
    UTXO SpendUTXO(const mw::Hash& output_id);

    ICoinsView::Ptr m_pBase;

    LeafSetCache::Ptr m_pLeafSet;
    PMMRCache::Ptr m_pOutputPMMR;

    std::shared_ptr<CoinsViewUpdates> m_pUpdates;
};

class CoinsViewDB : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewDB>;

    static CoinsViewDB::Ptr Open(
        const FilePath& datadir,
        const mw::Header::CPtr& pBestHeader,
        const mw::DBWrapper::Ptr& pDBWrapper
    );

    bool IsCache() const noexcept final { return false; }

    UTXO::CPtr GetUTXO(const mw::Hash& output_id) const final;
    void WriteBatch(
        const mw::DBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Compact() const final;

    ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

    bool HasCoinInCache(const mw::Hash& output_id) const noexcept final { return false; }

private:
    CoinsViewDB(
        const mw::Header::CPtr& pBestHeader,
        const mw::DBWrapper::Ptr& pDBWrapper,
        const LeafSet::Ptr& pLeafSet,
        const PMMR::Ptr& pOutputPMMR
    ) : ICoinsView(pBestHeader, pDBWrapper),
        m_pLeafSet(pLeafSet),
        m_pOutputPMMR(pOutputPMMR) { }

    void AddUTXO(CoinDB& coinDB, const Output& output);
    void AddUTXO(CoinDB& coinDB, const UTXO::CPtr& pUTXO);
    void SpendUTXO(CoinDB& coinDB, const mw::Hash& output_id);
    UTXO::CPtr GetUTXO(const CoinDB& coinDB, const mw::Hash& output_id) const;

    LeafSet::Ptr m_pLeafSet;
    PMMR::Ptr m_pOutputPMMR;
};

//! Fully-owned, parent-free MWEB view for historical light-client snapshots.
class CoinsViewMemory : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewMemory>;

    //! Deep-copy leafset, output PMMR, and unspent UTXOs from source (O(UTXO set)).
    static Ptr Materialize(const ICoinsView& source);

    //! AssumeUTXO snapshot warm: copy PMMR hashes + unspent leaf payloads only.
    static Ptr MaterializeAssumeUTXOSnapshot(const ICoinsView& source);

    //! Assemble a frozen view from pre-built components (AssumeUTXO stepped warm).
    static Ptr Create(
        const mw::Header::CPtr& pHeader,
        ILeafSet::Ptr pLeafSet,
        IMMR::Ptr pOutputPMMR,
        std::unordered_map<mw::Hash, UTXO::CPtr> utxos);

    bool IsCache() const noexcept final { return false; }

    UTXO::CPtr GetUTXO(const mw::Hash& output_id) const final;
    void WriteBatch(
        const mw::DBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Compact() const final {}
    bool HasCoinInCache(const mw::Hash& output_id) const noexcept final { return false; }

    ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

private:
    CoinsViewMemory(
        const mw::Header::CPtr& pHeader,
        ILeafSet::Ptr pLeafSet,
        IMMR::Ptr pOutputPMMR,
        std::unordered_map<mw::Hash, UTXO::CPtr> utxos)
        : ICoinsView(pHeader, nullptr),
          m_pLeafSet(std::move(pLeafSet)),
          m_pOutputPMMR(std::move(pOutputPMMR)),
          m_utxos(std::move(utxos)) {}

    ILeafSet::Ptr m_pLeafSet;
    IMMR::Ptr m_pOutputPMMR;
    std::unordered_map<mw::Hash, UTXO::CPtr> m_utxos;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_NODE_COINS_VIEW_H
