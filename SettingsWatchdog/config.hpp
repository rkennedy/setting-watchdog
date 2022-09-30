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
        static std::wstring convert(std::filesystem::path const& p)
        {
            return p.native();
        }
    };
}  // namespace registry
namespace config
{
    extern registry::value<std::filesystem::path> log_file;
    extern registry::value<plog::Severity> verbosity;
}  // namespace config
