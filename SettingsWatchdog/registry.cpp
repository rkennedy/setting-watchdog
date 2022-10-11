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

registry::key::key(HKEY key, char const* name, DWORD permissions): m_key(OpenRegKey(key, name, 0, permissions))
{ }

registry::key::key(key&& other) noexcept: m_key(other.m_key)
{
    other.m_key = NULL;
}

registry::key::~key()
{
    if (m_key) [[likely]]
        RegCloseKey(m_key);
}

registry::key::operator HKEY() const
{
    return m_key;
}

void registry::delete_value(HKEY key, char const* name)
{
    switch (LONG const result = RegDeleteValueW(key, boost::nowide::widen(name).c_str()); result) {
        case ERROR_SUCCESS:
            WDLOG(info) << std::format("Deleted {} value", name);
            break;
        case ERROR_FILE_NOT_FOUND:
            WDLOG(trace) << std::format("{} value does not exist", name);
            break;
        default:
            WDLOG(error) << std::format("Error deleting {} value: {}", name, result);
            break;
    }
}

registry::value_base::value_base(HKEY key, std::string const& subkey, std::string const& value_name):
    m_key(key),
    m_subkey(boost::nowide::widen(subkey)),
    m_value_name(boost::nowide::widen(value_name))
{ }

void registry::value_base::store(int64_t const value)
{
    RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), REG_QWORD,
                             reinterpret_cast<BYTE const*>(&value), sizeof value),
             "storing int value");
}

void registry::value_base::store(DWORD const value)
{
    RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), REG_DWORD,
                             reinterpret_cast<BYTE const*>(&value), sizeof value),
             "storing int value");
}

void registry::value_base::store(std::wstring const& value)
{
    RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), REG_SZ,
                             reinterpret_cast<BYTE const*>(value.data()),
                             boost::numeric_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))),
             "storing string value");
}

int64_t registry::value_base::load_qword(DWORD data_size) const
{
    int64_t result;
    BOOST_ASSERT(data_size == sizeof result);
    RegCheck(
        RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_QWORD, nullptr, &result, &data_size),
        "reading qword value");
    return result;
}

DWORD registry::value_base::load_dword(DWORD data_size) const
{
    DWORD result;
    BOOST_ASSERT(data_size == sizeof result);
    RegCheck(
        RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_DWORD, nullptr, &result, &data_size),
        "reading dword value");
    return result;
}

std::wstring registry::value_base::load_string(DWORD data_size) const
{
    std::vector<unsigned char> buffer(data_size);
    RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ, nullptr,
                          buffer.data(), &data_size),
             "reading string value");
    return std::wstring(reinterpret_cast<wchar_t const*>(buffer.data()), data_size / sizeof(wchar_t) - 1);
}
