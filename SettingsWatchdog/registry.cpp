#include "registry.hpp"
#include "errors.hpp"
#include "logging.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/log/sources/severity_feature.hpp>
#include <boost/nowide/convert.hpp>

#pragma warning(pop)

HKEY OpenRegKey(HKEY hKey, char const* lpSubKey, DWORD ulOptions, REGSAM samDesired)
{
    HKEY result;
    RegCheck(RegOpenKeyExW(hKey, boost::nowide::widen(lpSubKey).c_str(), ulOptions, samDesired, &result), "opening registry key");
    return result;
}

RegKey::RegKey(HKEY key, char const* name, DWORD permissions):
    m_key(OpenRegKey(key, name, 0, permissions))
{}

RegKey::RegKey(RegKey&& other) noexcept:
    m_key(other.m_key)
{
    other.m_key = NULL;
}

RegKey::~RegKey()
{
    if (m_key)
        RegCloseKey(m_key);
}

RegKey::operator HKEY() const
{
    return m_key;
}

void DeleteRegistryValue(HKEY key, char const* name)
{
    switch (LONG const result = RegDeleteValueW(key, boost::nowide::widen(name).c_str()); result) {
        case ERROR_SUCCESS:
            WDLOG(info, "Deleted %1% value") % name;
            break;
        case ERROR_FILE_NOT_FOUND:
            WDLOG(trace, "%1% value does not exist") % name;
            break;
        default:
            WDLOG(error, "Error deleting %1% value: %2%") % name % result;
            break;
    }
}
