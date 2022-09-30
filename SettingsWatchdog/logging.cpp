#include "logging.hpp"

DISABLE_ANALYSIS
#include <chrono>
#include <cmath>
#include <format>
#include <ratio>
#include <stack>

#include <boost/nowide/convert.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/program_options/errors.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <plog/Record.h>

#include <windows.h>
REENABLE_ANALYSIS

#include "config.hpp"
#include "string-maps.hpp"

static thread_local std::stack<char const*> g_scopes;

ScopeMarker::ScopeMarker(char const* name)
{
    g_scopes.push(name);
}

ScopeMarker::~ScopeMarker()
{
    g_scopes.pop();
}

plog::util::nstring LogFormatter::header()
{
    return plog::util::nstring();
}

plog::util::nstring LogFormatter::format(plog::Record const& record)
{
    auto fn { g_scopes.top() };
    // On Windows, std::chrono::system_clock uses a duration with a ratio of
    // 1/100000000, which indicates how many 100-nanoseconds. When printed, it
    // gives 7 digits after the decimal place. We only want 3 digits for
    // millisecond precision. Therefore, we'll format the string "natively" and
    // then truncate it to the desired length.
    auto const time { std::chrono::system_clock::from_time_t(record.getTime().time)
                      + std::chrono::milliseconds(record.getTime().millitm) };
    auto const time_str = std::format(L"{:%Y-%m-%d %H:%M:%S}", time);
    using precision_difference = std::ratio_divide<std::milli, std::chrono::system_clock::duration::period>;
    static_assert(precision_difference::num > 1);
    static_assert(precision_difference::den == 1);
    auto const digit_difference
        = boost::numeric_cast<decltype(time_str)::size_type>(std::log10(precision_difference::num));

    return std::format(L"{0:.{1}} [{2}:{3}] <{4}> {5}: {6}\n", time_str, time_str.length() - digit_difference,
                       GetCurrentProcessId(), record.getTid(), record.getSeverity(), boost::nowide::widen(fn),
                       record.getMessage());
}

std::string plog::to_string(plog::Severity level)
{
    return ::get(severity_names, level).value_or(std::to_string(static_cast<int>(level)));
}

std::ostream& plog::operator<<(std::ostream& os, plog::Severity sev)
{
    return os << to_string(sev);
}

void plog::validate(boost::any& v, std::vector<std::string> const& values, plog::Severity* target_type, int)
{
    namespace po = boost::program_options;

    po::validators::check_first_occurrence(v);
    std::string const& s = po::validators::get_single_string(values);

    auto const sev = get_key(severity_names, s);
    if (!sev) [[unlikely]]
        throw po::validation_error(po::validation_error::invalid_option_value);
    v = sev.value();
}
