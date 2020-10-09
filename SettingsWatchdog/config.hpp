#pragma once

#include <filesystem>

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/log/trivial.hpp>

#pragma warning(pop)

class Config
{
public:
    std::filesystem::path log_file() const;
    Config& log_file(std::filesystem::path const&);

    boost::log::trivial::severity_level verbosity() const;
    Config& verbosity(boost::log::trivial::severity_level const&);
};
