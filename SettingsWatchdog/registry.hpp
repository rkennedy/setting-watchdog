#pragma once

#include <windows.h>

HKEY OpenRegKey(HKEY hKey, char const* lpSubKey, DWORD ulOptions, REGSAM samDesired);

class RegKey
{
    HKEY m_key;
    RegKey() = delete;
    RegKey(RegKey const&) = delete;
    RegKey& operator=(RegKey const&) = delete;
public:
    RegKey(HKEY key, char const* name, DWORD permissions);
    RegKey(RegKey&& other) noexcept;
    ~RegKey();
    operator HKEY() const;
};

void DeleteRegistryValue(HKEY key, char const* name);
