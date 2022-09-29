#include "config.hpp"

namespace config
{
    auto constexpr config_registry_key = R"(SOFTWARE\SettingsWatchdog)";
    static std::filesystem::path const default_log_file(R"(C:\SettingsWatchdog.log)");
    static severity_level const default_severity = severity_level::trace;

    registry::value<std::filesystem::path> log_file(HKEY_LOCAL_MACHINE, config_registry_key, "log file",
                                                    default_log_file);
    registry::value<severity_level> verbosity(HKEY_LOCAL_MACHINE, config_registry_key, "severity level",
                                              default_severity);
}  // namespace config
