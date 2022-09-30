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

namespace plog
{
    auto constexpr trace = verbose;

    std::basic_ostream<char>& operator<<(std::basic_ostream<char>& os, plog::Severity sev);

    void validate(boost::any& v, std::vector<std::string> const& values, plog::Severity* target_type, int);

    std::string to_string(plog::Severity);
}  // namespace plog

template <class CharT>
class std::formatter<plog::Severity, CharT>: public std::formatter<std::basic_string<CharT>, CharT>
{
public:
    template <class FormatContext>
    auto format(plog::Severity level, FormatContext& ctx) const
    {
        return std::formatter<std::basic_string<CharT>, CharT>::format(boost::nowide::widen(to_string(level)), ctx);
    }
};

#define WDLOG(sev) LOG((plog::sev))

class LogFormatter
{
public:
    static plog::util::nstring header();
    static plog::util::nstring format(plog::Record const& record);
};
