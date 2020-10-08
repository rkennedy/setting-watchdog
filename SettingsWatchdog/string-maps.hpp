#pragma once

#include <map>
#include <string>

#include <windows.h>

extern std::map<DWORD, std::string> const control_names;

extern std::map<DWORD, std::string> const session_change_codes;

extern std::map<DWORD, std::string> const wait_results;

template <typename Map, typename T>
typename Map::mapped_type get_with_default(Map const& map, typename Map::key_type const& key, T const& default_value)
{
    if (auto it = map.find(key); it != map.end())
        return it->second;
    return default_value;
}
