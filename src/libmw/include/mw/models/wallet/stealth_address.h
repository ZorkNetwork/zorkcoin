
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_STEALTH_ADDRESS_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_STEALTH_ADDRESS_H
#include <mw/common/traits.h>
#include <mw/crypto/keys.h>
#include <mw/models/crypto/public_key.h>

class StealthAddress : public Traits::ISerializable
{
public:
    StealthAddress() = default;
    StealthAddress(PublicKey&& scan, PublicKey&& spend)
        : m_scan(std::move(scan)), m_spend(std::move(spend)) { }
    StealthAddress(const PublicKey& scan, const PublicKey& spend)
        : m_scan(scan), m_spend(spend) { }

    bool operator==(const StealthAddress& rhs) const noexcept
    {
        return m_scan == rhs.m_scan && m_spend == rhs.m_spend;
    }

    bool operator<(const StealthAddress& rhs) const noexcept
    {
        if (m_scan < rhs.m_scan) return true;
        if (m_scan != rhs.m_scan) return false;
        return m_spend < rhs.m_spend;
    }

    static StealthAddress Random()
    {
        return StealthAddress(Keys::Random().PubKey(), Keys::Random().PubKey());
    }

    const PublicKey& A() const noexcept { return m_scan; }
    const PublicKey& B() const noexcept { return m_spend; }

    const PublicKey& GetScanPubKey() const noexcept { return m_scan; }
    const PublicKey& GetSpendPubKey() const noexcept { return m_spend; }

    IMPL_SERIALIZABLE(StealthAddress, obj)
    {
        READWRITE(obj.m_scan, obj.m_spend);
    }

private:
    PublicKey m_scan;
    PublicKey m_spend;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_STEALTH_ADDRESS_H
