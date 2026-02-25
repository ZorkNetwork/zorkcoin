// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <util/time.h>

#include <util/check.h>

#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <ctime>
#include <sstream>
#include <string>
#include <thread>

#include <tinyformat.h>

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<int64_t> nMockTime(0); //!< For testing

int64_t GetTime()
{
    int64_t mocktime = nMockTime.load(std::memory_order_relaxed);
    if (mocktime) return mocktime;

    return GetTimeMillis();
}

template <typename T>
T GetTime()
{
    const int64_t mocktime_val = nMockTime.load(std::memory_order_relaxed);
    const std::chrono::milliseconds mocktime_ms{mocktime_val};

    std::chrono::microseconds base = mocktime_val
        ? std::chrono::duration_cast<std::chrono::microseconds>(mocktime_ms)
        : std::chrono::microseconds{GetTimeMicros()};
    return std::chrono::duration_cast<T>(base);
}
template std::chrono::seconds GetTime();
template std::chrono::milliseconds GetTime();
template std::chrono::microseconds GetTime();

void SetMockTime(int64_t nMockTimeIn)
{
    Assert(nMockTimeIn >= 0);
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

int64_t GetMockTime()
{
    return nMockTime.load(std::memory_order_relaxed);
}

int64_t GetTimeMillis()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
    assert(now > 0);
    return now;
}

int64_t GetTimeMicros()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
    assert(now > 0);
    return now;
}

int64_t GetSystemTimeInSeconds()
{
    return GetTimeMicros()/1000000;
}

std::string FormatISO8601DateTime(int64_t nTime) {
    // Use boost::posix_time to preserve millisecond precision
    boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    boost::posix_time::ptime ptime = epoch + boost::posix_time::milliseconds(nTime);

    // Format manually to ensure milliseconds are included when non-zero
    boost::gregorian::date date = ptime.date();
    boost::posix_time::time_duration time_of_day = ptime.time_of_day();
    
    int64_t total_seconds = time_of_day.total_seconds();
    int64_t hours = total_seconds / 3600;
    int64_t minutes = (total_seconds % 3600) / 60;
    int64_t seconds = total_seconds % 60;
    // Extract milliseconds from nTime directly (more reliable)
    int64_t ms = nTime % 1000;
    
    if (ms == 0) {
        // Backward compatibility: omit milliseconds when zero
        return strprintf("%04d-%02d-%02dT%02lld:%02lld:%02lldZ",
                         date.year(), date.month().as_number(), date.day(),
                         hours, minutes, seconds);
    } else {
        return strprintf("%04d-%02d-%02dT%02lld:%02lld:%02lld.%03lldZ",
                         date.year(), date.month().as_number(), date.day(),
                         hours, minutes, seconds, ms);
    }
}

std::string FormatISO8601Date(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime/1000;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &ts) == nullptr) {
#else
    if (gmtime_s(&ts, &time_val) != 0) {
#endif
        return {};
    }
    return strprintf("%04i-%02i-%02i", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
}

int64_t ParseISO8601DateTime(const std::string& str)
{
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    
    // Reject obviously malformed input before expensive parsing
    if (str.size() < 20 || str.size() > 24 || str.back() != 'Z') {
        return 0;
    }
    
    // Extract milliseconds manually if present
    int64_t milliseconds = 0;
    std::string str_to_parse = str;
    size_t dot_pos = str.find('.');
    size_t z_pos = str.size() - 1;  // We already validated 'Z' is at the end
    
    if (dot_pos != std::string::npos && dot_pos < z_pos) {
        // Extract milliseconds (up to 3 digits)
        std::string ms_str = str.substr(dot_pos + 1, z_pos - dot_pos - 1);
        if (ms_str.length() > 3) {
            ms_str = ms_str.substr(0, 3); // Truncate to 3 digits
        }
        // Pad to 3 digits if needed (for proper parsing)
        while (ms_str.length() < 3) {
            ms_str += "0";
        }
        // Safe conversion - returns 0 on any invalid input (no exceptions)
        char* end = nullptr;
        long val = std::strtol(ms_str.c_str(), &end, 10);
        milliseconds = (end == ms_str.c_str() + 3 && val >= 0) ? val : 0;
        // Remove milliseconds from string for parsing
        str_to_parse = str.substr(0, dot_pos) + "Z";
    }
    
    // Parse the datetime (without milliseconds)
    static const std::locale loc_sec(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    
    std::istringstream iss(str_to_parse);
    iss.imbue(loc_sec);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    
    if (ptime.is_not_a_date_time() || epoch > ptime)
        return 0;
    
    // Calculate total milliseconds: seconds * 1000 + milliseconds
    boost::posix_time::time_duration diff = ptime - epoch;
    int64_t total_ms = diff.total_seconds() * 1000 + milliseconds;
    return total_ms;
}
