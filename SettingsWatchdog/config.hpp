#pragma once

#include <filesystem>
#include <string>

#include "logging.hpp"
#include "registry.hpp"

namespace registry
{
    template <>
    struct registry_traits<std::filesystem::path>
    {
        static std::wstring convert(std::filesystem::path const& p)
        {
            return p.native();
        }
    };
}  // namespace registry
namespace config
{
    extern registry::value<std::filesystem::path> log_file;
    extern registry::value<severity_level> verbosity;
}  // namespace config
