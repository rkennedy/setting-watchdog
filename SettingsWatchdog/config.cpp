#include "config.hpp"
#include "logging.hpp"
#include "registry.hpp"
#include "errors.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/nowide/convert.hpp>

#pragma warning(pop)

auto constexpr config_registry_key = R"(SOFTWARE\SettingsWatchdog)";
static std::filesystem::path const default_log_file(R"(C:\SettingsWatchdog.log)");
static severity_level const default_severity = severity_level::trace;

std::filesystem::path Config::log_file() const
{
    try {
        return registry::read_string(HKEY_LOCAL_MACHINE, config_registry_key, "log file");
    } catch (std::system_error const& ex) {
        std::error_code const ec(ERROR_FILE_NOT_FOUND, std::system_category());
        if (ex.code() == ec)
            return default_log_file;
        throw;
    }
}

Config& Config::log_file(std::filesystem::path const& path)
{
    registry::write_string(HKEY_LOCAL_MACHINE, config_registry_key, "log file", path.native());
    return *this;
}

severity_level Config::verbosity() const
{
    try {
        return registry::read_int<severity_level>(HKEY_LOCAL_MACHINE, config_registry_key, "severity level");
    }
    catch (std::system_error const& ex) {
        std::error_code const ec(ERROR_FILE_NOT_FOUND, std::system_category());
        if (ex.code() == ec)
            return default_severity;
        throw;
    }
}

Config& Config::verbosity(severity_level const& sev)
{
    registry::write_int(HKEY_LOCAL_MACHINE, config_registry_key, "severity level", sev);
    return *this;
}
