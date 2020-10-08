#pragma once

#include <windows.h>

HKEY OpenRegKey(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired);

class RegKey
{
    HKEY m_key;
    RegKey() = delete;
    RegKey(RegKey const&) = delete;
    RegKey& operator=(RegKey const&) = delete;
public:
    RegKey(HKEY key, TCHAR const* name, DWORD permissions);
    RegKey(RegKey&& other) noexcept;
    ~RegKey();
    operator HKEY() const;
};

void DeleteRegistryValue(HKEY key, TCHAR const* name);
