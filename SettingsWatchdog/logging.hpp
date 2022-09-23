#pragma once
DISABLE_ANALYSIS
#include <iosfwd>
#include <string>
#include <vector>

#include <boost/any.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/trivial.hpp>
REENABLE_ANALYSIS

enum class severity_level
{
    trace,
    debug,
    info,
    warning,
    error,
    fatal,
};

std::basic_ostream<char>& operator<<(std::basic_ostream<char>& os, severity_level sev);

void validate(boost::any& v, std::vector<std::string> const& values, severity_level* target_type, int);

using logger_type = boost::log::sources::severity_logger_mt<severity_level>;

BOOST_LOG_GLOBAL_LOGGER(wdlog, logger_type)

#define WDLOG(sev) BOOST_LOG_SEV(wdlog::get(), (severity_level::sev))
