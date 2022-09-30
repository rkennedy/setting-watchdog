#include "config.hpp"

namespace config
{
    auto constexpr config_registry_key = R"(SOFTWARE\SettingsWatchdog)";
    static std::filesystem::path const default_log_file(R"(C:\SettingsWatchdog.log)");
    static plog::Severity const default_severity = plog::trace;

    registry::value<std::filesystem::path> log_file(HKEY_LOCAL_MACHINE, config_registry_key, "log file",
                                                    default_log_file);
    registry::value<plog::Severity> verbosity(HKEY_LOCAL_MACHINE, config_registry_key, "severity level",
                                              default_severity);
}  // namespace config
