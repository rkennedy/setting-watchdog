#include "config.hpp"
#include "logging.hpp"

std::filesystem::path Config::log_file() const
{
    return R"(C:\SettingsWatchdog.log)";
}

severity_level Config::verbosity() const
{
    return severity_level::trace;
}
