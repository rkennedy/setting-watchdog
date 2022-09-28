#pragma once
DISABLE_ANALYSIS
#include <iosfwd>
#include <string>
#include <vector>

#include <boost/any.hpp>
#include <glog/logging.h>
REENABLE_ANALYSIS

void CustomPrefix(std::ostream& s, google::LogMessageInfo const& l, void*);

class ScopeMarker
{
public:
    ScopeMarker(char const* name);
    ~ScopeMarker();
};

#define BOOST_LOG_FUNC()            \
    ScopeMarker const CuRrEnT_ScOpE \
    {                               \
        __FUNCTION__                \
    }

enum class severity_level
{
    info = google::INFO,
    warning = google::WARNING,
    error = google::ERROR,
    fatal = google::FATAL,
};

std::basic_ostream<char>& operator<<(std::basic_ostream<char>& os, severity_level sev);

void validate(boost::any& v, std::vector<std::string> const& values, severity_level* target_type, int);
