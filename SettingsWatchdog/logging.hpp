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

/// <summary>
/// A helper class for the LOG_FUNC macro to keep track of the currently active function in each thread.
/// </summary>
class ScopeMarker
{
public:
    ScopeMarker(char const* name);
    ~ScopeMarker();
};

/// <summary>
/// Set the currently active function. The most recent instance of this will be included in log messages. When the scope
/// ends, the previously active function will become active again.
/// </summary>
#define LOG_FUNC()                  \
    ScopeMarker const CuRrEnT_ScOpE \
    {                               \
        __FUNCTION__                \
    }

namespace plog
{
    /// <summary>
    /// An alias for plog::verbose
    /// </summary>
    auto constexpr trace = verbose;

    /// <summary>
    /// Stream insertion operator for plog::Severity
    /// </summary>
    /// <param name="os">The output stream to write to</param>
    /// <param name="sev">The severity level</param>
    /// <returns>The output stream</returns>
    std::basic_ostream<char>& operator<<(std::basic_ostream<char>& os, plog::Severity sev);

    /// <summary>
    /// Read and validate a plog::Severity command-line argument for Boost.Program_Options.
    /// </summary>
    void validate(boost::any& v, std::vector<std::string> const& values, plog::Severity* target_type, int);

    /// <summary>
    /// Convert a plog::Severity to a string.
    /// </summary>
    std::string to_string(plog::Severity);
}  // namespace plog

/// <summary>
/// A std::formatter specialization for using plog::Severity with std::format.
/// </summary>
/// <typeparam name="CharT"></typeparam>
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

/// <summary>
/// A class collecting functions for formatting messages in Plog.
/// </summary>
class LogFormatter
{
public:
    static plog::util::nstring header();
    static plog::util::nstring format(plog::Record const& record);
};
