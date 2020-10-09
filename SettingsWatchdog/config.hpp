#pragma once

#include "logging.hpp"

#include <filesystem>

class Config
{
public:
    std::filesystem::path log_file() const;
    Config& log_file(std::filesystem::path const&);

    severity_level verbosity() const;
    Config& verbosity(severity_level const&);
};
