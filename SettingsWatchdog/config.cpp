#include "config.hpp"
#include "logging.hpp"

std::filesystem::path Config::log_file() const
{
    return R"(C:\SettingsWatchdog.log)";
}

boost::log::trivial::severity_level Config::verbosity() const
{
    return trace;
}
