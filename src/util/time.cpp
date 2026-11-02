// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h>

#include <util/time.h>

#include <tinyformat.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <array>
#include <atomic>
#include <chrono>
#include <compare>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

static constexpr std::array<std::string_view, 7> weekdays{"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"}; // 1970-01-01 was a Thursday.
static constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

/** Mock time in milliseconds since epoch; 0 means use the system clock. */
static std::atomic<int64_t> nMockTime{0};
std::atomic<bool> g_used_system_time{false};
static std::atomic<MockableSteadyClock::mock_time_point::duration> g_mock_steady_time{}; //!< For testing

static_assert(NodeClock::epoch.time_since_epoch().count() == 0);

NodeClock::time_point NodeClock::now() noexcept
{
    const int64_t mocktime{nMockTime.load(std::memory_order_relaxed)};
    if (!mocktime) {
        g_used_system_time = true;
    }
    const std::chrono::system_clock::duration ret{
        mocktime ? std::chrono::milliseconds{mocktime} : std::chrono::system_clock::now().time_since_epoch()};
    assert(ret.count() > 0);
    return time_point{ret};
}

void SetMockTime(int64_t nMockTimeIn)
{
    // nMockTimeIn is milliseconds since epoch (0 clears mock).
    Assert(nMockTimeIn >= 0);
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

void SetMockTime(std::chrono::seconds mock_time_in)
{
    SetMockTime(std::chrono::duration_cast<std::chrono::milliseconds>(mock_time_in).count());
}

void SetMockTime(std::chrono::time_point<NodeClock, std::chrono::seconds> mock)
{
    SetMockTime(mock.time_since_epoch());
}

void SetMockTime(NodeMilliseconds mock)
{
    SetMockTime(TicksSinceEpoch<std::chrono::milliseconds>(mock));
}

int64_t GetMockTime()
{
    return nMockTime.load(std::memory_order_relaxed);
}

MockableSteadyClock::time_point MockableSteadyClock::now() noexcept
{
    const auto mocktime{g_mock_steady_time.load(std::memory_order_relaxed)};
    if (!mocktime.count()) {
        g_used_system_time = true;
    }
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::steady_clock::now().time_since_epoch()};
    return time_point{ret};
}

void MockableSteadyClock::SetMockTime(mock_time_point::duration mock_time_in)
{
    Assert(mock_time_in >= 0ms);
    g_mock_steady_time.store(mock_time_in, std::memory_order_relaxed);
}

void MockableSteadyClock::ClearMockTime()
{
    g_mock_steady_time.store(0ms, std::memory_order_relaxed);
}

int64_t GetTime()
{
    return GetTime<std::chrono::milliseconds>().count();
}

template <typename T>
T GetTime()
{
    const int64_t mocktime_val = nMockTime.load(std::memory_order_relaxed);
    if (mocktime_val) {
        return std::chrono::duration_cast<T>(std::chrono::milliseconds{mocktime_val});
    }
    return std::chrono::duration_cast<T>(std::chrono::microseconds{GetTimeMicros()});
}
template std::chrono::seconds GetTime();
template std::chrono::milliseconds GetTime();
template std::chrono::microseconds GetTime();

int64_t GetTimeMillis()
{
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    assert(now > 0);
    return now;
}

int64_t GetTimeMicros()
{
    const int64_t now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    assert(now > 0);
    return now;
}

int64_t GetSystemTimeInSeconds()
{
    return GetTimeMicros() / 1000000;
}

static bool Gmtime(int64_t time_val, struct tm& ts)
{
    const time_t t = time_val;
#if defined(HAVE_GMTIME_R)
    return gmtime_r(&t, &ts) != nullptr;
#elif defined(HAVE_GMTIME_S)
    return gmtime_s(&ts, &t) == 0;
#else
    // Fallback for platforms without the reentrant variants.
    if (struct tm* tmp{gmtime(&t)}) {
        ts = *tmp;
        return true;
    }
    return false;
#endif
}

std::string FormatISO8601DateTime(int64_t nTime)
{
    // nTime is milliseconds since epoch (block/header and mockable GetTime units).
    if (nTime < 0) return {};
    const int64_t sec = nTime / 1000;
    const int64_t ms = nTime % 1000;
    struct tm ts{};
    if (!Gmtime(sec, ts)) {
        return {};
    }
    if (ms == 0) {
        return strprintf("%04i-%02i-%02iT%02i:%02i:%02iZ",
                         ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                         ts.tm_hour, ts.tm_min, ts.tm_sec);
    }
    return strprintf("%04i-%02i-%02iT%02i:%02i:%02i.%03iZ",
                     ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                     ts.tm_hour, ts.tm_min, ts.tm_sec, static_cast<int>(ms));
}

std::string FormatISO8601Date(int64_t nTime)
{
    if (nTime < 0) return {};
    struct tm ts{};
    if (!Gmtime(nTime / 1000, ts)) {
        return {};
    }
    return strprintf("%04i-%02i-%02i", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
}

std::optional<int64_t> ParseISO8601DateTime(std::string_view str)
{
    // Accept "YYYY-MM-DDTHH:MM:SSZ" or "YYYY-MM-DDTHH:MM:SS.mmmZ" (ms timestamps).
    constexpr auto FMT_SIZE_SEC{std::string_view{"2000-01-01T01:01:01Z"}.size()};
    constexpr auto FMT_SIZE_MS{std::string_view{"2000-01-01T01:01:01.000Z"}.size()};

    int millis{0};
    if (str.size() == FMT_SIZE_MS) {
        if (str[19] != '.' || str[23] != 'Z') return {};
        const auto ms{ToIntegral<uint16_t>(str.substr(20, 3))};
        if (!ms || *ms > 999) return {};
        millis = *ms;
    } else if (str.size() != FMT_SIZE_SEC || str[19] != 'Z') {
        return {};
    }

    if (str[4] != '-' || str[7] != '-' || str[10] != 'T' || str[13] != ':' || str[16] != ':') {
        return {};
    }

    const auto year{ToIntegral<uint16_t>(str.substr(0, 4))};
    const auto month{ToIntegral<uint8_t>(str.substr(5, 2))};
    const auto day{ToIntegral<uint8_t>(str.substr(8, 2))};
    const auto hour{ToIntegral<uint8_t>(str.substr(11, 2))};
    const auto min{ToIntegral<uint8_t>(str.substr(14, 2))};
    const auto sec{ToIntegral<uint8_t>(str.substr(17, 2))};
    if (!year || !month || !day || !hour || !min || !sec) {
        return {};
    }
    const std::chrono::year_month_day ymd{std::chrono::year{*year}, std::chrono::month{*month}, std::chrono::day{*day}};
    if (!ymd.ok()) {
        return {};
    }
    const auto time{std::chrono::hours{*hour} + std::chrono::minutes{*min} + std::chrono::seconds{*sec} + std::chrono::milliseconds{millis}};
    const auto tp{std::chrono::sys_days{ymd} + time};
    // Return milliseconds to match GetTime()/block nTime units.
    return int64_t{TicksSinceEpoch<std::chrono::milliseconds>(tp)};
}

std::string FormatRFC1123DateTime(int64_t time)
{
    // HTTP dates are second-resolution; accept ms timestamps.
    const int64_t sec = time > 1'000'000'000'000LL ? time / 1000 : time;
    if (sec < -62167219200 || 253402300799 < sec) {
        // 4-digit year, so only support years 0 to 9999
        return "";
    }
    const std::chrono::sys_seconds secs{std::chrono::seconds{sec}};
    const auto days{std::chrono::floor<std::chrono::days>(secs)};
    const auto w{days.time_since_epoch().count() % 7}; // will be in the range [-6, 6]
    std::string_view weekday{weekdays.at(w >= 0 ? w : w + 7)};
    const std::chrono::year_month_day ymd{days};
    std::string_view month{months.at(unsigned{ymd.month()} - 1)};
    const std::chrono::hh_mm_ss hms{secs - days};
    return strprintf("%03s, %02u %03s %04i %02i:%02i:%02i GMT", weekday, unsigned{ymd.day()}, month, signed{ymd.year()}, hms.hours().count(), hms.minutes().count(), hms.seconds().count());
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    return MillisToTimeval(std::chrono::milliseconds{nTimeout});
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return {
        .tv_sec = static_cast<decltype(timeval::tv_sec)>(ms / 1000ms),
        .tv_usec = static_cast<decltype(timeval::tv_usec)>((ms % 1000ms) / 1us)};
}
