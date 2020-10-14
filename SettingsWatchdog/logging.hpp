#pragma once

#include <iosfwd>
#include <vector>
#include <string>

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/any.hpp>
#include <boost/format.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/trivial.hpp>

#pragma warning(pop)

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

#define WDLOG(sev, msg) BOOST_LOG_SEV(wdlog::get(), (severity_level::sev)) << boost::format((msg))
