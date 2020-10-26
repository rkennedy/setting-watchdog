#include "registry.hpp"
#include "errors.hpp"
#include "logging.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/log/sources/severity_feature.hpp>
#include <boost/nowide/convert.hpp>

#pragma warning(pop)

static HKEY OpenRegKey(HKEY hKey, char const* lpSubKey, DWORD ulOptions, REGSAM samDesired)
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

namespace registry
{
    std::string read_string(HKEY key, std::string const& subkey, std::string const& value_name)
    {
        DWORD type;
        DWORD data_size = 0;
        RegCheck(RegGetValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ, &type, nullptr, &data_size), "checking value size");
        switch (type) {
        case REG_EXPAND_SZ:
        case REG_SZ: {
            std::vector<char> buffer(data_size);
            RegCheck(RegGetValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ, nullptr, buffer.data(), &data_size), "reading string value");
            return boost::nowide::narrow(reinterpret_cast<wchar_t const*>(buffer.data()), data_size - sizeof(wchar_t));
        }
        default:
            throw std::domain_error(boost::str(boost::format("unsupported registry type %1%") % ::get(registry_types, type).value_or(std::to_string(type))));
        }
    }

    void write_string(HKEY key, std::string const& subkey, std::string const& value_name, std::string const& value) {
        write_string(key, subkey, value_name, boost::nowide::widen(value));
    }

    void write_string(HKEY key, std::string const& subkey, std::string const& value_name, std::wstring const& value) {
        RegCheck(RegSetKeyValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), REG_SZ, reinterpret_cast<BYTE const*>(value.data()), boost::numeric_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))), "storing string value");
    }
}
