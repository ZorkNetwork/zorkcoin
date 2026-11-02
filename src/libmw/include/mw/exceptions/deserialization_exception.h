
#ifndef BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DESERIALIZATION_EXCEPTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DESERIALIZATION_EXCEPTION_H
#include <mw/exceptions/ltc_exception.h>
#include <mw/util/string_util.h>

#define ThrowDeserialization(msg) throw DeserializationException(msg, __FUNCTION__)
#define ThrowDeserialization_F(msg, ...) throw DeserializationException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class DeserializationException : public LTCException
{
public:
    DeserializationException(const std::string& message, const std::string& function)
        : LTCException("DeserializationException", message, function)
    {

    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DESERIALIZATION_EXCEPTION_H
