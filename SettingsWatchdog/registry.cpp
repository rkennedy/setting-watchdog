#include "registry.hpp"

DISABLE_ANALYSIS
#include <boost/nowide/convert.hpp>
REENABLE_ANALYSIS

#include "errors.hpp"
#include "logging.hpp"

static HKEY OpenRegKey(HKEY hKey, char const* lpSubKey, DWORD ulOptions, REGSAM samDesired)
{
    HKEY result;
    RegCheck(RegOpenKeyExW(hKey, boost::nowide::widen(lpSubKey).c_str(), ulOptions, samDesired, &result),
             "opening registry key");
    return result;
}

RegKey::RegKey(HKEY key, char const* name, DWORD permissions): m_key(OpenRegKey(key, name, 0, permissions))
{ }

RegKey::RegKey(RegKey&& other) noexcept: m_key(other.m_key)
{
    other.m_key = NULL;
}

RegKey::~RegKey()
{
    if (m_key) [[likely]]
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
            LOG(INFO) << std::format("Deleted {} value", name);
            break;
        case ERROR_FILE_NOT_FOUND:
            DLOG(INFO) << std::format("{} value does not exist", name);
            break;
        default:
            LOG(ERROR) << std::format("Error deleting {} value: {}", name, result);
            break;
    }
}
