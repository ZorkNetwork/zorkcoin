
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_BLOCK_BLOCK_UNDO_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_BLOCK_BLOCK_UNDO_H
#include <mw/common/macros.h>
#include <mw/common/traits.h>
#include <mw/common/optional_serialization.h>
#include <mw/models/block/header.h>
#include <mw/models/tx/utxo.h>
#include <serialize.h>

MW_NAMESPACE

class BlockUndo : public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const BlockUndo>;

    //
    // Constructors
    //
    BlockUndo(const mw::Header::CPtr& pPrevHeader, std::vector<UTXO>&& coinsSpent, std::vector<mw::Hash>&& coinsAdded)
        : m_pPrevHeader(pPrevHeader), m_coinsSpent(std::move(coinsSpent)), m_coinsAdded(std::move(coinsAdded)) { }
    BlockUndo(const BlockUndo& other) = default;
    BlockUndo(BlockUndo&& other) noexcept = default;
    BlockUndo() = default;

    //
    // Operators
    //
    BlockUndo& operator=(const BlockUndo& other) = default;
    BlockUndo& operator=(BlockUndo&& other) noexcept = default;

    //
    // Getters
    //
    const mw::Header::CPtr& GetPreviousHeader() const noexcept { return m_pPrevHeader; }
    const std::vector<UTXO>& GetCoinsSpent() const noexcept { return m_coinsSpent; }
    const std::vector<mw::Hash>& GetCoinsAdded() const noexcept { return m_coinsAdded; }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(BlockUndo, obj)
    {
        READWRITE(WrapOptionalPtr(obj.m_pPrevHeader), obj.m_coinsSpent, obj.m_coinsAdded);
    }

    template <typename Stream>
    BlockUndo(deserialize_type, Stream& s)
    {
        Unserialize(s);
    }

private:
    Header::CPtr m_pPrevHeader;
    std::vector<UTXO> m_coinsSpent;
    std::vector<mw::Hash> m_coinsAdded;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_BLOCK_BLOCK_UNDO_H
