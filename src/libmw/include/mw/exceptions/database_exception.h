
#ifndef BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DATABASE_EXCEPTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DATABASE_EXCEPTION_H
#include <mw/exceptions/ltc_exception.h>
#include <mw/util/string_util.h>

#define ThrowDatabase(msg) throw DatabaseException(msg, __FUNCTION__)
#define ThrowDatabase_F(msg, ...) throw DatabaseException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class DatabaseException : public LTCException
{
public:
    DatabaseException(const std::string& message, const std::string& function)
        : LTCException("DatabaseException", message, function)
    {

    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_DATABASE_EXCEPTION_H
