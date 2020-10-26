#pragma once
#include "errors.hpp"
#include "string-maps.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <windows.h>

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/assert.hpp>
#include <boost/nowide/convert.hpp>
#include <boost/numeric/conversion/cast.hpp>

#pragma warning(pop)

namespace registry
{
    std::string read_string(HKEY key, std::string const& subkey, std::string const& value_name);
    void write_string(HKEY key, std::string const& subkey, std::string const& value_name, std::string const& value);
    void write_string(HKEY key, std::string const& subkey, std::string const& value_name, std::wstring const& value);

    template <typename T>
    std::enable_if_t<std::disjunction_v<std::is_integral<T>, std::is_enum<T>>, T>
    read_int(HKEY key, std::string const& subkey, std::string const& value_name)
    {
        DWORD type;
        DWORD data_size = 0;
        RegCheck(RegGetValueW(key, boost::nowide::widen(subkey).c_str() , boost::nowide::widen(value_name).c_str(), RRF_RT_REG_DWORD | RRF_RT_REG_QWORD, &type, nullptr, &data_size), "checking value size");
        switch (type) {
        case REG_DWORD: {
            DWORD result;
            BOOST_ASSERT(data_size == sizeof result);
            data_size = sizeof result;
            RegCheck(RegGetValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), RRF_RT_REG_DWORD, nullptr, &result, &data_size), "reading dword value");
            return boost::numeric_cast<T>(result);
        }
        case REG_QWORD: {
            int64_t result;
            BOOST_ASSERT(data_size == sizeof result);
            data_size = sizeof result;
            RegCheck(RegGetValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), RRF_RT_REG_QWORD, nullptr, &result, &data_size), "reading qword value");
            return boost::numeric_cast<T>(result);
        }
        default:
            throw std::domain_error(boost::str(boost::format("unsupported registry type %1%") % ::get(registry_types, type).value_or(std::to_string(type))));
        }
    }

    template <typename T>
    std::enable_if_t<std::disjunction_v<std::is_integral<T>, std::is_enum<T>>>
    write_int(HKEY key, std::string const& subkey, std::string const& value_name, T value)
    {
        using store_type = std::conditional_t<sizeof value <= sizeof(DWORD), DWORD, int64_t>;
        static_assert(sizeof(store_type) >= sizeof value);
        store_type const store_value = static_cast<store_type>(value);
        DWORD const type = std::conditional_t<sizeof value <= sizeof(DWORD), std::integral_constant<DWORD, REG_DWORD>, std::integral_constant<DWORD, REG_QWORD>>::value;
        RegCheck(RegSetKeyValueW(key, boost::nowide::widen(subkey).c_str(), boost::nowide::widen(value_name).c_str(), type, reinterpret_cast<BYTE const*>(&store_value), sizeof store_value), "storing int value");
    }
}

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
