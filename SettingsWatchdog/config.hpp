#pragma once

#include <filesystem>
#include <string>

#include <plog/Log.h>
#include <plog/Severity.h>

#include "logging.hpp"
#include "registry.hpp"

namespace registry
{
    template <>
    struct registry_traits<std::filesystem::path>
    {
        /// <summary>
        /// Converts a std::filesystem::path into a value that's supported in the registry.
        /// </summary>
        /// <param name="p">The path to convert</param>
        /// <returns>A std::wstring equivalent of the path</returns>
        static std::wstring genericize(std::filesystem::path const& p)
        {
            return p.native();
        }

        static std::filesystem::path specialize(std::wstring const& w)
        {
            return boost::nowide::narrow(w);
        }
    };
}  // namespace registry

namespace config
{
    /// <summary>
    /// A registry entry for the path and file name of the program's log file.
    /// </summary>
    extern registry::value<std::filesystem::path> log_file;

    /// <summary>
    /// A registry entry for the minimum verbosity level to log. Messages with
    /// verbosity lower than this value will not be logged.
    /// </summary>
    extern registry::value<plog::Severity> verbosity;

    enum class program_action
    {
        help,
        install,
        uninstall,
        run,
    };

    program_action process_args(int argc, char* argv[], plog::Logger<0>& logger);
}  // namespace config
