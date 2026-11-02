
#ifndef BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_NOT_FOUND_EXCEPTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_NOT_FOUND_EXCEPTION_H
#include <mw/exceptions/ltc_exception.h>
#include <mw/util/string_util.h>

#define ThrowNotFound(msg) throw NotFoundException(msg, __FUNCTION__)
#define ThrowNotFound_F(msg, ...) throw NotFoundException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class NotFoundException : public LTCException
{
public:
    NotFoundException(const std::string& message, const std::string& function)
        : LTCException("NotFoundException", message, function)
    {

    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_NOT_FOUND_EXCEPTION_H
