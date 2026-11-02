
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_UTIL_STRING_UTIL_H
#define BITCOIN_LIBMW_INCLUDE_MW_UTIL_STRING_UTIL_H
#include <mw/common/traits.h>

#include <memory>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstdarg>
#include <charconv>
#include <vector>
#include <algorithm>
#include <system_error>
#include <sstream>
#include <stdexcept>
#include <type_traits>

#include <util/strencodings.h>

#ifdef _MSC_VER
#pragma warning(disable : 4840)
#endif

class StringUtil
{
public:
    static std::string Format(const char* format)
    {
        return std::string(format);
    }

    template<typename T, typename... Args>
    static std::string Format(const char* format, const T& first, const Args&... rest)
    {
        std::string result;
        const char* p = format;
        while (*p) {
            if (p[0] == '{' && p[1] == '}') {
                result += ConvertArg(first);
                return result + Format(p + 2, rest...);
            }
            if (p[0] == '{' && p[1] == ':') {
                const char* end = std::strchr(p, '}');
                if (end == nullptr) {
                    throw std::runtime_error("Invalid format string");
                }
                std::string spec(p + 2, end - p - 2);
                if (spec.size() >= 3 && spec[0] == '0' && spec[1] == '>') {
                    const auto width = ToIntegral<int>(spec.substr(2));
                    const int width_val = width.value_or(0);
                    const std::string arg = ConvertArg(first);
                    if (static_cast<int>(arg.size()) < width_val) {
                        result.append(static_cast<size_t>(width_val - arg.size()), '0');
                    }
                    result += arg;
                } else {
                    result += ConvertArg(first);
                }
                return result + Format(end + 1, rest...);
            }
            result += *p++;
        }
        throw std::runtime_error("Too many format arguments");
    }

    static bool StartsWith(const std::string& value, const std::string& beginning)
    {
        if (beginning.size() > value.size()) {
            return false;
        }

        return std::equal(beginning.begin(), beginning.end(), value.begin());
    }

    static bool EndsWith(const std::string& value, const std::string& ending)
    {
        if (ending.size() > value.size()) {
            return false;
        }

        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    static std::vector<std::string> Split(const std::string& str, const std::string& delimiter)
    {
        std::string::size_type lastPos = str.find_first_not_of(delimiter, 0);
        std::string::size_type pos = str.find_first_of(delimiter, lastPos);

        std::vector<std::string> tokens;
        while (std::string::npos != pos || std::string::npos != lastPos) {
            tokens.push_back(str.substr(lastPos, pos - lastPos));
            lastPos = str.find_first_not_of(delimiter, pos);
            pos = str.find_first_of(delimiter, lastPos);
        }

        return tokens;
    }

    static std::string ToLower(const std::string& str)
    {
        return ::ToLower(str);
    }

    template <typename T>
    static std::string IntegralToString(T value)
    {
        static_assert(std::is_integral_v<T>);
        char buf[32];
        auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), value);
        if (ec != std::errc{}) {
            throw std::runtime_error("IntegralToString failed");
        }
        return std::string(buf, ptr);
    }

    static std::string Trim(const std::string& s)
    {
        std::string copy = s;

        copy.erase(copy.begin(), std::find_if(copy.begin(), copy.end(), [](char ch) {
            return !IsSpace(ch);
        }));

        copy.erase(std::find_if(copy.rbegin(), copy.rend(), [](char ch) {
            return !IsSpace(ch) && ch != '\r' && ch != '\n';
        }).base(), copy.end());

        return copy;
    }

private:
    static std::string ConvertArg(const std::string& x)
    {
        return x;
    }

    static std::string ConvertArg(const char* x)
    {
        return std::string(x);
    }

    static std::string ConvertArg(const Traits::IPrintable& x)
    {
        return x.Format();
    }

    template <class T>
    static std::string ConvertArg(const std::vector<T>& x)
    {
        std::string str;
        for (const T& value : x) {
            if (str.empty()) {
                str += ConvertArg(value);
            } else {
                str += "," + ConvertArg(value);
            }
        }

        return "[" + str + "]";
    }

    static std::string ConvertArg(const std::shared_ptr<const Traits::IPrintable>& x)
    {
        if (x == nullptr) {
            return "NULL";
        }

        return x->Format();
    }

    static std::string ConvertArg(const std::exception& e)
    {
        return std::string(e.what());
    }

    static std::string ConvertArg(const std::error_code& ec)
    {
        return IntegralToString(ec.value()) + " - " + ec.message();
    }

    template <class T, typename SFINAE = std::enable_if_t<std::is_fundamental<T>::value>>
    static std::string ConvertArg(const T& x)
    {
        return IntegralToString(x);
    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_UTIL_STRING_UTIL_H
