#pragma once

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <utility>

#include <plog/Severity.h>

#include <windows.h>

#include "logging.hpp"

extern std::map<DWORD, std::string> const control_names;

extern std::map<DWORD, std::string> const session_change_codes;

extern std::map<DWORD, std::string> const wait_results;

extern std::map<DWORD, std::string> const registry_types;

extern std::map<plog::Severity, std::string> const severity_names;

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
    if (auto const it = std::ranges::find(map, std::forward<T>(value), &Map::value_type::second); it != map.cend())
        [[likely]]
    {
        return it->first;
    }
    return std::nullopt;
}
