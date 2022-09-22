#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>

#include <boost/range/algorithm/find_if.hpp>

#include <windows.h>

#include "logging.hpp"

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

template <typename Map, typename T>
std::optional<typename Map::key_type> get_key(Map const& map, T&& value)
{
    if (auto const it = boost::find_if(map, [&value](auto p) { return p.second == value; }); it != map.cend())
        [[likely]] {
        return it->first;
    }
    return std::nullopt;
}
