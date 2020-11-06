#include "logging.hpp"

DISABLE_ANALYSIS
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/attributes/clock.hpp>
#include <boost/log/attributes/constant.hpp>
#include <boost/log/attributes/function.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/expressions/formatters/format.hpp>
#include <boost/log/expressions/formatters/max_size_decorator.hpp>
#include <boost/log/expressions/formatters/named_scope.hpp>
#include <boost/log/expressions/formatters/stream.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/nowide/iostream.hpp>
#include <boost/phoenix/bind/bind_function.hpp>
#include <boost/phoenix/operator/arithmetic.hpp>
#include <boost/program_options/errors.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/range/algorithm/find_if.hpp>
REENABLE_ANALYSIS

#include "config.hpp"
#include "string-maps.hpp"

namespace bl = boost::log;

BOOST_LOG_ATTRIBUTE_KEYWORD(process_id, "ProcessId", decltype(boost::winapi::GetCurrentProcessId()))
BOOST_LOG_ATTRIBUTE_KEYWORD(thread_id, "ThreadId", decltype(boost::winapi::GetCurrentThreadId()))
BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", severity_level)

#pragma warning(push)
#pragma warning(disable : 4065)  // switch has default without case
// clang-format off
static bl::formatter const g_formatter
    = bl::expressions::format("%1%.%7% [%2%:%3%] <%4%> %5%: %6%")
    % bl::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
    % process_id
    % thread_id
    % severity
    % bl::expressions::format_named_scope(
        "Scope",
        bl::keywords::format = "%n",
        bl::keywords::incomplete_marker = "",
        bl::keywords::depth = 1)
    % bl::expressions::message
    % bl::expressions::max_size_decor(3, "")[
        // %f gives six digits of precision. We want three.
        bl::expressions::stream << bl::expressions::format_date_time<boost::posix_time::ptime>(
            "TimeStamp", "%f")
    ];
// clang-format on
#pragma warning(pop)

static bool severity_filter(bl::value_ref<severity_level, tag::severity> const& level)
{
    return level >= config::verbosity.get();
}

BOOST_LOG_GLOBAL_LOGGER_INIT(wdlog, logger_type)
{
    logger_type lg;
    lg.add_attribute("TimeStamp", bl::attributes::local_clock());
    lg.add_attribute("ProcessId", bl::attributes::make_constant(boost::winapi::GetCurrentProcessId()));
    lg.add_attribute("ThreadId", bl::attributes::make_function(&boost::winapi::GetCurrentThreadId));
    lg.add_attribute("Scope", bl::attributes::named_scope());

    auto const verbosity_filter = boost::phoenix::bind(&severity_filter, severity.or_none());

    auto const console = bl::add_console_log(boost::nowide::clog, bl::keywords::filter = verbosity_filter,
                                             bl::keywords::format = g_formatter);
    auto const file = bl::add_file_log(bl::keywords::file_name = config::log_file.get().native(),
                                       bl::keywords::open_mode = std::ios_base::app | std::ios_base::out,
                                       bl::keywords::auto_flush = true, bl::keywords::filter = verbosity_filter,
                                       bl::keywords::format = g_formatter);
    return lg;
}

std::ostream& operator<<(std::ostream& os, severity_level sev)
{
    return os << get(severity_names, sev).value_or("unknown");
}

void validate(boost::any& v, std::vector<std::string> const& values, severity_level* target_type, int)
{
    namespace po = boost::program_options;

    po::validators::check_first_occurrence(v);
    std::string const& s = po::validators::get_single_string(values);

    if (auto const it = boost::find_if(severity_names, [&s](auto p) { return p.second == s; });
        it != severity_names.cend()) {
        v = it->first;
        return;
    }
    throw po::validation_error(po::validation_error::invalid_option_value);
}
