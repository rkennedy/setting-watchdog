#pragma once

#include "logging.hpp"

#include <map>
#include <optional>
#include <string>
#include <utility>

#include <windows.h>

extern std::map<DWORD, std::string> const control_names;

extern std::map<DWORD, std::string> const session_change_codes;

extern std::map<DWORD, std::string> const wait_results;

extern std::map<DWORD, std::string> const registry_types;

extern std::map<severity_level, std::string> const severity_names;

template <typename Map, typename T>
std::optional<typename Map::mapped_type> get(Map const& map, T&& key)
{
    if (auto it = map.find(std::forward<T>(key)); it != map.end())
        return it->second;
    return std::nullopt;
}
