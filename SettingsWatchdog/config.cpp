#include "config.hpp"

DISABLE_ANALYSIS
#include <ostream>

#include <boost/nowide/args.hpp>
#include <boost/nowide/iostream.hpp>
#include <boost/program_options.hpp>
#include <plog/Appenders/RollingFileAppender.h>
REENABLE_ANALYSIS

namespace po = boost::program_options;

static auto constexpr config_registry_key = R"(SOFTWARE\SettingsWatchdog)";
static std::filesystem::path const default_log_file(R"(C:\SettingsWatchdog.log)");
static plog::Severity const default_severity = plog::trace;

registry::value<std::filesystem::path> config::log_file(HKEY_LOCAL_MACHINE, config_registry_key, "log file",
                                                        default_log_file);
registry::value<plog::Severity> config::verbosity(HKEY_LOCAL_MACHINE, config_registry_key, "severity level",
                                                  default_severity);

config::program_action config::process_args(int argc, char* argv[], plog::Logger<0>& logger)
{
    boost::nowide::args a(argc, argv);

    po::options_description desc("Allowed options");
    desc.add_options()
        // clang-format off
        ("help,h", "This help message")
        ("install,i", "Install the service")
        ("uninstall,u", "Uninstall the service")
        ("log-location,l", po::value<std::filesystem::path>(), "Set the location of the log file")
        ("verbose,v", po::value<plog::Severity>(), "Set the verbosity level")
        // clang-format on
        ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        boost::nowide::cout << desc << std::endl;
        return program_action::help;
    }

    if (vm.contains("log-location")) {
        try {
            config::log_file.set(vm.at("log-location").as<std::filesystem::path>());
        } catch (std::system_error const& ex) {
            if (ex.code() != errors::access_denied) {
                throw;
            }
            // We're unable to store the log location. No big deal.
        }
    }
    static plog::RollingFileAppender<LogFormatter> file_appender(config::log_file.get().c_str());
    logger.addAppender(&file_appender);

    if (vm.contains("verbose")) {
        try {
            config::verbosity.set(vm.at("verbose").as<plog::Severity>());
        } catch (std::system_error const& ex) {
            if (ex.code() != errors::access_denied) {
                throw;
            }
            // We're unable to store the verbosity. No big deal.
        }
    }
    plog::get()->setMaxSeverity(config::verbosity.get());

    if (vm.contains("install"))
        return program_action::install;
    if (vm.contains("uninstall"))
        return program_action::uninstall;
    return program_action::run;
}
