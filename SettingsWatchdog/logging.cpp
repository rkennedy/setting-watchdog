#include "logging.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/attributes/clock.hpp>
#include <boost/log/attributes/constant.hpp>
#include <boost/log/attributes/function.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/expressions/formatters/format.hpp>
#include <boost/log/expressions/formatters/named_scope.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/phoenix/operator/arithmetic.hpp>

#pragma warning(pop)

namespace bl = boost::log;

BOOST_LOG_ATTRIBUTE_KEYWORD(process_id, "ProcessId", decltype(boost::winapi::GetCurrentProcessId()))
BOOST_LOG_ATTRIBUTE_KEYWORD(thread_id, "ThreadId", decltype(boost::winapi::GetCurrentThreadId()))

BOOST_LOG_GLOBAL_LOGGER_INIT(wdlog, logger_type)
{
    logger_type lg;
    lg.add_attribute("TimeStamp", bl::attributes::local_clock());
    lg.add_attribute("ProcessId", bl::attributes::make_constant(boost::winapi::GetCurrentProcessId()));
    lg.add_attribute("ThreadId", bl::attributes::make_function(&boost::winapi::GetCurrentThreadId));
    lg.add_attribute("Scope", bl::attributes::named_scope());
    bl::formatter formatter = (
        bl::expressions::format("%1% [%2%:%3%] <%4%> %5%: %6%")
        % bl::expressions::format_date_time<boost::posix_time::ptime>(
            "TimeStamp", "%Y-%m-%d %H:%M:%S")
        % process_id
        % thread_id
        % bl::trivial::severity
        % bl::expressions::format_named_scope(
            "Scope",
            bl::keywords::format = "%n",
            bl::keywords::incomplete_marker = "",
            bl::keywords::depth = 1)
        % bl::expressions::message
    );
    bl::add_console_log()->set_formatter(formatter);
    bl::add_file_log(
        bl::keywords::file_name = R"(C:\SettingsWatchdog.log)",
        bl::keywords::open_mode = std::ios_base::app | std::ios_base::out,
        bl::keywords::auto_flush = true
    )->set_formatter(formatter);
    return lg;
}