#pragma once

#include "registry.hpp"
#include "logging.hpp"

#include <filesystem>
#include <string>

namespace registry {
    template <>
    struct registry_traits<std::filesystem::path> {
        static std::wstring convert(std::filesystem::path const& p) {
            return p.native();
        }
    };
}
namespace config
{
    extern registry::value<std::filesystem::path> log_file;
    extern registry::value<severity_level> verbosity;
}
