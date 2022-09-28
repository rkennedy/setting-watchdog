#include "logging.hpp"

DISABLE_ANALYSIS
#include <chrono>
#include <format>
#include <stack>

#include <boost/program_options/errors.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <glog/logging.h>

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

void CustomPrefix(std::ostream& s, google::LogMessageInfo const& l, void*)
{
    auto fn = g_scopes.top();
    s << std::format(
        "{0:%Y-%m-%d %H:%M}:{1:02}.{2:03} [{3}:{4}] <{5}> {6}:",
        std::chrono::system_clock::from_time_t(l.time.timestamp()), std::chrono::seconds(l.time.sec()).count(),
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::microseconds(l.time.usec())).count(),
        GetCurrentProcessId(), l.thread_id, l.severity, fn);
}

/*
BOOST_LOG_GLOBAL_LOGGER_INIT(wdlog, logger_type)
{
    auto const console = bl::add_console_log(boost::nowide::clog, bl::keywords::filter = verbosity_filter,
                                             bl::keywords::format = g_formatter);
    auto const file = bl::add_file_log(bl::keywords::file_name = config::log_file.get().native(),
                                       bl::keywords::open_mode = std::ios_base::app | std::ios_base::out,
                                       bl::keywords::auto_flush = true, bl::keywords::filter = verbosity_filter,
                                       bl::keywords::format = g_formatter);
}*/

std::ostream& operator<<(std::ostream& os, severity_level sev)
{
    return os << get(severity_names, sev).value_or("unknown");
}

void validate(boost::any& v, std::vector<std::string> const& values, severity_level* target_type, int)
{
    namespace po = boost::program_options;

    po::validators::check_first_occurrence(v);
    std::string const& s = po::validators::get_single_string(values);

    auto const sev = get_key(severity_names, s);
    if (!sev) [[unlikely]]
        throw po::validation_error(po::validation_error::invalid_option_value);
    v = sev.value();
}
