
#ifndef BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_INSUFFICIENT_FUNDS_EXCEPTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_INSUFFICIENT_FUNDS_EXCEPTION_H
#include <mw/exceptions/ltc_exception.h>
#include <mw/util/string_util.h>

#define ThrowInsufficientFunds(msg) throw InsufficientFundsException(msg, __FUNCTION__)
#define ThrowInsufficientFunds_F(msg, ...) throw InsufficientFundsException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class InsufficientFundsException : public LTCException
{
public:
    InsufficientFundsException(const std::string& message, const std::string& function)
        : LTCException("InsufficientFundsException", message, function)
    {

    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_INSUFFICIENT_FUNDS_EXCEPTION_H
