
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_PEG_IN_COIN_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_PEG_IN_COIN_H
#include <mw/common/traits.h>
#include <mw/models/crypto/hash.h>
#include <mw/util/string_util.h>
#include <consensus/amount.h>

//
// Represents coins being pegged in, i.e. moved from canonical chain to the extension block.
//
class PegInCoin : public Traits::ISerializable, public Traits::IPrintable
{
public:
    PegInCoin() = default;
    PegInCoin(const CAmount amount, mw::Hash kernel_id)
        : m_amount(amount), m_kernelID(std::move(kernel_id)) {}

    bool operator==(const PegInCoin& rhs) const noexcept
    {
        return m_amount == rhs.m_amount && m_kernelID == rhs.m_kernelID;
    }

    CAmount GetAmount() const noexcept { return m_amount; }
    const mw::Hash& GetKernelID() const noexcept { return m_kernelID; }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(PegInCoin, obj)
    {
        READWRITE(VARINT_MODE(obj.m_amount, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(obj.m_kernelID);
    }

    std::string Format() const noexcept final
    {
        return StringUtil::Format("PegInCoin(kernel_id: {}, amount: {})", m_kernelID, m_amount);
    }

private:
    CAmount m_amount;
    mw::Hash m_kernelID;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_PEG_IN_COIN_H
