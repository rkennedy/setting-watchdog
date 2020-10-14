#include "config.hpp"
#include "logging.hpp"

static std::filesystem::path g_log(R"(C:\SettingsWatchdog.log)");
static severity_level g_verbose = severity_level::trace;

std::filesystem::path Config::log_file() const
{
    return g_log;
}

Config& Config::log_file(std::filesystem::path const& path)
{
    g_log = path;
    return *this;
}

severity_level Config::verbosity() const
{
    return g_verbose;
}

Config& Config::verbosity(severity_level const& sev)
{
    g_verbose = sev;
    return *this;
}
