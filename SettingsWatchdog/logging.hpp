#pragma once

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/trivial.hpp>

#pragma warning(pop)

using boost::log::trivial::trace;
using boost::log::trivial::debug;
using boost::log::trivial::info;
using boost::log::trivial::warning;
using boost::log::trivial::error;
using boost::log::trivial::fatal;
#ifdef UNICODE
using logger_type = boost::log::sources::wseverity_logger_mt<boost::log::trivial::severity_level>;
#else
using logger_type = boost::log::sources::severity_logger_mt<boost::log::trivial::severity_level>;
#endif

BOOST_LOG_GLOBAL_LOGGER(wdlog, logger_type)
