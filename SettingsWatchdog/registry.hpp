#pragma once
DISABLE_ANALYSIS
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/assert.hpp>
#include <boost/nowide/convert.hpp>
#include <boost/numeric/conversion/cast.hpp>

#include <windows.h>
REENABLE_ANALYSIS

#include "errors.hpp"
#include "string-maps.hpp"

namespace registry
{
    template <typename T>
    struct registry_traits
    {
        // static U convert(T const&);
    };

    template <typename T>
    class value
    {
        HKEY const m_key;
        std::wstring const m_subkey;
        std::wstring const m_value_name;
        T const m_default_value;

    public:
        value(HKEY key, std::string const& subkey, std::string const& value_name, T const& default_value):
            m_key(key),
            m_subkey(boost::nowide::widen(subkey)),
            m_value_name(boost::nowide::widen(value_name)),
            m_default_value(default_value)
        { }
        value(HKEY key, std::string const& subkey, std::string const& value_name, T&& default_value):
            m_key(key),
            m_subkey(boost::nowide::widen(subkey)),
            m_value_name(boost::nowide::widen(value_name)),
            m_default_value(std::forward<T>(default_value))
        { }

        template <typename U>
        void set(U const& new_value)
        {
            if constexpr (std::disjunction_v<std::is_integral<T>, std::is_enum<T>>) {
                using store_type = std::conditional_t<sizeof new_value <= sizeof(DWORD), DWORD, int64_t>;
                store_type const store_value = static_cast<store_type>(new_value);
                static_assert(sizeof store_value >= sizeof new_value);
                DWORD const type
                    = std::conditional_t<sizeof new_value <= sizeof(DWORD), std::integral_constant<DWORD, REG_DWORD>,
                                         std::integral_constant<DWORD, REG_QWORD>>::value;
                RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), type,
                                         reinterpret_cast<BYTE const*>(&store_value), sizeof store_value),
                         "storing int value");
            } else if constexpr (std::is_same_v<U, std::string>) {
                set(boost::nowide::widen(new_value));
            } else if constexpr (std::is_same_v<U, std::wstring>) {
                RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), REG_SZ,
                                         reinterpret_cast<BYTE const*>(new_value.data()),
                                         boost::numeric_cast<DWORD>((new_value.size() + 1) * sizeof(wchar_t))),
                         "storing string value");
            } else {
                set(registry_traits<U>::convert(new_value));
            }
        }

        std::enable_if_t<std::disjunction_v<std::is_integral<T>, std::is_enum<T>, std::is_constructible<T, std::string>,
                                            std::is_constructible<T, std::wstring>>,
                         T>
        get() const
        {
            DWORD constexpr acceptible_types
                = std::conditional_t<std::disjunction_v<std::is_integral<T>, std::is_enum<T>>,
                                     std::integral_constant<DWORD, RRF_RT_REG_DWORD | RRF_RT_REG_QWORD>,
                                     std::integral_constant<DWORD, RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ>>::value;
            DWORD type;
            DWORD data_size = 0;
            switch (LSTATUS const reg_result = RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(),
                                                            acceptible_types, &type, nullptr, &data_size);
                    reg_result)
            {
                default:
                    RegCheck(reg_result, "checking value size");
                    break;  // not reached.
                case ERROR_FILE_NOT_FOUND:
                    break;
                case ERROR_SUCCESS:
                    if constexpr (std::disjunction_v<std::is_integral<T>, std::is_enum<T>>) {
                        switch (type) {
                            case REG_DWORD: {
                                DWORD result;
                                BOOST_ASSERT(data_size == sizeof result);
                                data_size = sizeof result;
                                RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_DWORD,
                                                      nullptr, &result, &data_size),
                                         "reading dword value");
                                return boost::numeric_cast<T>(result);
                            }
                            case REG_QWORD: {
                                int64_t result;
                                BOOST_ASSERT(data_size == sizeof result);
                                data_size = sizeof result;
                                RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_QWORD,
                                                      nullptr, &result, &data_size),
                                         "reading qword value");
                                return boost::numeric_cast<T>(result);
                            }
                            default:
                                throw std::domain_error(
                                    boost::str(boost::format("unsupported registry type %1%")
                                               % ::get(registry_types, type).value_or(std::to_string(type))));
                        }
                    } else if constexpr (std::disjunction_v<std::is_constructible<T, std::string>,
                                                            std::is_constructible<T, std::wstring>>) {
                        DWORD type;
                        DWORD data_size = 0;
                        RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(),
                                              RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ, &type, nullptr, &data_size),
                                 "checking value size");
                        switch (type) {
                            case REG_EXPAND_SZ:
                            case REG_SZ: {
                                std::vector<unsigned char> buffer(data_size);
                                RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(),
                                                      RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ, nullptr, buffer.data(),
                                                      &data_size),
                                         "reading string value");
                                std::wstring const result(reinterpret_cast<wchar_t const*>(buffer.data()),
                                                          data_size / sizeof(wchar_t) - 1);
                                if constexpr (!std::is_constructible_v<T, std::wstring>) {
                                    return boost::nowide::narrow(result);
                                }
                                return std::wstring(reinterpret_cast<wchar_t const*>(buffer.data()),
                                                    data_size / sizeof(wchar_t) - 1);
                            }
                            default:
                                throw std::domain_error(
                                    boost::str(boost::format("unsupported registry type %1%")
                                               % ::get(registry_types, type).value_or(std::to_string(type))));
                        }
                    }
            }
            return m_default_value;
        }
    };
}  // namespace registry

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
