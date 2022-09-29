#pragma once
DISABLE_ANALYSIS
#include <format>
#include <iosfwd>
#include <string>
#include <vector>

#include <boost/any.hpp>
#include <boost/nowide/convert.hpp>
#include <plog/Log.h>
REENABLE_ANALYSIS

class ScopeMarker
{
public:
    ScopeMarker(char const* name);
    ~ScopeMarker();
};

#define BOOST_LOG_FUNC()            \
    ScopeMarker const CuRrEnT_ScOpE \
    {                               \
        __FUNCTION__                \
    }

enum class severity_level
{
    trace = plog::verbose,
    debug = plog::debug,
    info = plog::info,
    warning = plog::warning,
    error = plog::error,
    fatal = plog::fatal,
};

std::basic_ostream<char>& operator<<(std::basic_ostream<char>& os, severity_level sev);

void validate(boost::any& v, std::vector<std::string> const& values, severity_level* target_type, int);

std::string to_string(severity_level);

template <class CharT>
class std::formatter<severity_level, CharT>: public std::formatter<std::basic_string<CharT>, CharT>
{
public:
    template <class FormatContext>
    auto format(severity_level level, FormatContext& ctx) const
    {
        return std::formatter<std::basic_string<CharT>, CharT>::format(boost::nowide::widen(to_string(level)), ctx);
    }
};

#define WDLOG(sev) LOG(static_cast<plog::Severity>((severity_level::sev)))

class LogFormatter
{
public:
    static plog::util::nstring header();
    static plog::util::nstring format(plog::Record const& record);
};
