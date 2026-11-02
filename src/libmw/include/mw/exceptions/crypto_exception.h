
#ifndef BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_CRYPTO_EXCEPTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_CRYPTO_EXCEPTION_H
#include <mw/exceptions/ltc_exception.h>
#include <mw/util/string_util.h>

#define ThrowCrypto(msg) throw CryptoException(msg, __FUNCTION__)
#define ThrowCrypto_F(msg, ...) throw CryptoException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class CryptoException : public LTCException
{
public:
    CryptoException(const std::string& message, const std::string& function)
        : LTCException("CryptoException", message, function)
    {

    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_EXCEPTIONS_CRYPTO_EXCEPTION_H
