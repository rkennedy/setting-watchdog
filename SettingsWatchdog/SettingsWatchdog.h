#pragma once

using boost::log::trivial::trace;
using boost::log::trivial::debug;
using boost::log::trivial::info;
using boost::log::trivial::warning;
using boost::log::trivial::error;
using boost::log::trivial::fatal;
using logger_type = boost::log::sources::wseverity_logger_mt<boost::log::trivial::severity_level>;

BOOST_LOG_GLOBAL_LOGGER(wdlog, logger_type)
