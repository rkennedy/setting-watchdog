#pragma once
DISABLE_ANALYSIS
#include <cstdint>
#include <format>
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
    /// <summary>
    /// A trait class to teach registry::value how to convert arbitrary types
    /// into types that are supported by the registry. Specializations shoud
    /// provide a convert function that returns a registry-supported type.
    /// </summary>
    /// <typeparam name="T">The non-registry-supported type</typeparam>
    template <typename T>
    struct registry_traits
    {
        // static U convert(T const&);
    };

    /// <summary>
    /// A class representing a single value in the registry.
    /// </summary>
    /// <typeparam name="T">The type of the value. This can be any type, not
    /// just those supported by the registry, so select a type that's
    /// appropriate for the application code.</typeparam>
    template <typename T>
    class value
    {
        HKEY const m_key;
        std::wstring const m_subkey;
        std::wstring const m_value_name;
        T const m_default_value;
        std::optional<T> mutable m_current_value;

    public:
        /// <summary>
        /// Construct a new registry value.
        /// </summary>
        /// <param name="key">The base registry key where the value is stored. For example, HKEY_LOCAL_MACHINE.</param>
        /// <param name="subkey">The path to the subkey where the registry value is stored.</param>
        /// <param name="value_name">The name of the registry value.</param>
        /// <param name="default_value">A value to use for this registry entry if the value is not present in the
        /// registry.</param>
        value(HKEY key, std::string const& subkey, std::string const& value_name, T const& default_value):
            m_key(key),
            m_subkey(boost::nowide::widen(subkey)),
            m_value_name(boost::nowide::widen(value_name)),
            m_default_value(default_value)
        { }

        /// <summary>
        /// Store a new value in the registry. Uses registry_traits::convert if type U is not supported by the registry.
        /// </summary>
        /// <typeparam name="U">Any input type. It ought to be compatible with T, but that's not enforced
        /// anywhere.</typeparam>
        /// <param name="new_value">The value to store in the registry.</param>
        template <typename U>
        void set(U const& new_value)
        {
            if constexpr (std::disjunction_v<std::is_integral<T>, std::is_enum<T>>) {
                m_current_value = new_value;
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
                m_current_value = new_value;
                RegCheck(RegSetKeyValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), REG_SZ,
                                         reinterpret_cast<BYTE const*>(new_value.data()),
                                         boost::numeric_cast<DWORD>((new_value.size() + 1) * sizeof(wchar_t))),
                         "storing string value");
            } else {
                set(registry_traits<U>::convert(new_value));
            }
        }

        /// <summary>
        /// Read the current value from the registry.
        /// </summary>
        /// <returns>The current registry value, if present, else m_default_value</returns>
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
                                T const final_result = boost::numeric_cast<T>(result);
                                m_current_value = final_result;
                                return final_result;
                            }
                            case REG_QWORD: {
                                int64_t result;
                                BOOST_ASSERT(data_size == sizeof result);
                                data_size = sizeof result;
                                RegCheck(RegGetValueW(m_key, m_subkey.c_str(), m_value_name.c_str(), RRF_RT_REG_QWORD,
                                                      nullptr, &result, &data_size),
                                         "reading qword value");
                                T const final_result = boost::numeric_cast<T>(result);
                                m_current_value = final_result;
                                return final_result;
                            }
                            default:
                                throw std::domain_error(
                                    std::format("unsupported registry type {}",
                                                ::get(registry_types, type).value_or(std::to_string(type))));
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
                                std::wstring const final_result(reinterpret_cast<wchar_t const*>(buffer.data()),
                                                                data_size / sizeof(wchar_t) - 1);
                                m_current_value = final_result;
                                return final_result;
                            }
                            default:
                                throw std::domain_error(
                                    std::format("unsupported registry type {}",
                                                ::get(registry_types, type).value_or(std::to_string(type))));
                        }
                    }
            }
            return m_current_value.value_or(m_default_value);
        }
    };
}  // namespace registry

/// <summary>
/// A wrapper for HKEY that automatically closes itself upon destruction. Can be moved, but not copied.
/// </summary>
class RegKey
{
    HKEY m_key;
    RegKey() = delete;
    RegKey(RegKey const&) = delete;
    RegKey& operator=(RegKey const&) = delete;

public:
    /// <summary>
    /// Open a registry key.
    /// </summary>
    /// <param name="key">The base registry key, such as HKEY_LOCAL_MACHINE</param>
    /// <param name="name">The path of the subkey to open</param>
    /// <param name="permissions">Permissions required for accessing the registry key</param>
    RegKey(HKEY key, char const* name, REGSAM permissions);
    RegKey(RegKey&& other) noexcept;
    ~RegKey();
    /// <summary>
    /// Use the RegKey as an ordinary HKEY value.
    /// </summary>
    operator HKEY() const;
};

/// <summary>
/// Delete a value from the registry.
/// </summary>
/// <param name="key">The key where the value is stored.</param>
/// <param name="name">The name of the value to delete.</param>
void DeleteRegistryValue(HKEY key, char const* name);
