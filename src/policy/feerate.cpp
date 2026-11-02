// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <tinyformat.h>

#include <cstdlib>
#include <limits>

namespace {
static constexpr CAmount BASE_MWEB_FEE = 100;

CAmount GetMWEBFeeForWeight(uint64_t mweb_weight)
{
    if (mweb_weight > uint64_t(std::numeric_limits<CAmount>::max() / BASE_MWEB_FEE)) {
        return std::numeric_limits<CAmount>::max();
    }

    return CAmount(mweb_weight) * BASE_MWEB_FEE;
}
} // namespace

CAmount CFeeRate::GetMWEBFee(uint64_t mweb_weight)
{
    return GetMWEBFeeForWeight(mweb_weight);
}

CAmount CFeeRate::GetTotalFee(int32_t virtual_bytes, uint64_t mweb_weight) const
{
    const CAmount byte_fee = GetFee(virtual_bytes);
    const CAmount mweb_fee = GetMWEBFee(mweb_weight);
    if (byte_fee > 0 && mweb_fee > std::numeric_limits<CAmount>::max() - byte_fee) {
        return std::numeric_limits<CAmount>::max();
    }

    return byte_fee + mweb_fee;
}

CFeeRate::CFeeRate(const CAmount& nFeePaid, int32_t virtual_bytes)
{
    if (virtual_bytes > 0) {
        m_feerate = FeePerVSize(nFeePaid, virtual_bytes);
    } else {
        m_feerate = FeePerVSize();
    }
}

CFeeRate::CFeeRate(const CAmount& nFeePaid, int32_t virtual_bytes, uint64_t mweb_weight)
{
    const CAmount mweb_fee{GetMWEBFee(mweb_weight)};
    if (mweb_fee > 0 && nFeePaid < mweb_fee) {
        m_feerate = FeePerVSize(0, 1000);
    } else {
        *this = CFeeRate(nFeePaid - mweb_fee, virtual_bytes);
    }
}

CAmount CFeeRate::GetFee(int32_t virtual_bytes) const
{
    Assume(virtual_bytes >= 0);
    if (m_feerate.IsEmpty()) { return CAmount(0);}
    CAmount nFee = CAmount(m_feerate.EvaluateFeeUp(virtual_bytes));
    if (nFee == 0 && virtual_bytes != 0 && m_feerate.fee < 0) return CAmount(-1);
    return nFee;
}

std::string CFeeRate::ToString(FeeRateFormat fee_rate_format) const
{
    const CAmount feerate_per_kvb{GetFeePerK()};
    const auto format_feerate = [](const CAmount fee_rate, const CAmount divisor, const int decimals, const std::string& currency_unit, const std::string& size_unit) {
        Assert(divisor > 0);
        const char* sign{fee_rate < 0 ? "-" : ""};
        const CAmount quotient{std::abs(fee_rate / divisor)};
        const CAmount remainder{std::abs(fee_rate % divisor)};
        return strprintf("%s%d.%0*d %s/%s", sign, quotient, decimals, remainder, currency_unit, size_unit);
    };
    switch (fee_rate_format) {
    case FeeRateFormat::BTC_KVB: return format_feerate(feerate_per_kvb, COIN, /*decimals=*/8, CURRENCY_UNIT, "kvB");
    case FeeRateFormat::SAT_VB: return format_feerate(feerate_per_kvb, 1000, /*decimals=*/3, CURRENCY_ATOM, "vB");
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
