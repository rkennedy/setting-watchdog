#include "registry.hpp"
#include "errors.hpp"
#include "logging.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/format.hpp>
#include <boost/log/sources/severity_feature.hpp>

#pragma warning(pop)

#if UNICODE
using format = boost::wformat;
#else
using format = boost::format;
#endif

HKEY OpenRegKey(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired)
{
    HKEY result;
    RegCheck(RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, &result), "opening registry key");
    return result;
}

RegKey::RegKey(HKEY key, TCHAR const* name, DWORD permissions):
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

void DeleteRegistryValue(HKEY key, TCHAR const* name)
{
    switch (LONG const result = RegDeleteValue(key, name); result) {
        case ERROR_SUCCESS:
            BOOST_LOG_SEV(wdlog::get(), info) << format(TEXT("Deleted %1% value")) % name;
            break;
        case ERROR_FILE_NOT_FOUND:
#pragma warning(push)
#pragma warning(disable: 26812)
            BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("%1% value does not exist")) % name;
#pragma warning(pop)
            break;
        default:
            BOOST_LOG_SEV(wdlog::get(), error) << format(TEXT("Error deleting %1% value: %2%")) % name % result;
            break;
    }
}
