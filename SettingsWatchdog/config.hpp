#pragma once

#include <filesystem>
#include <string>

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
        static std::wstring convert(std::filesystem::path const& p)
        {
            return p.native();
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
}  // namespace config
