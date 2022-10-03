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
    template <typename T, typename = void>
    struct registry_traits
    {
        /// genericize converts a value of type T into a registry-supported type.
        // static U genericize(T const&);
        // static T specialize(U const&);
    };

    /// <summary>
    /// The specialization of registry_traits to handle all built-in registry types.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    template <typename T>
    struct registry_traits<
        T,
        typename std::enable_if_t<
            std::disjunction_v<std::is_same<T, DWORD>, std::is_same<T, int64_t>, std::is_same<T, std::wstring>>, void>>
    {
        static T genericize(T&& v)
        {
            return std::move(v);
        }
        static T specialize(T&& v)
        {
            return std::move(v);
        }
    };

    template <typename E>
    struct registry_traits<E, typename std::enable_if_t<std::is_enum_v<E>, void>>
    {
        using generic_type = std::conditional_t<sizeof E <= sizeof DWORD, DWORD, int64_t>;
        static generic_type genericize(E const v)
        {
            return static_cast<generic_type>(v);
        }
        static E specialize(int64_t const v)
        {
            return static_cast<E>(v);
        }
    };

    template <typename T>
    concept registry_supported = std::is_invocable<decltype(registry_traits<T>::specialize), std::wstring>::value
                                 || std::is_invocable<decltype(registry_traits<T>::specialize), int64_t>::value;

    class value_base
    {
    protected:
        value_base(HKEY key, std::string const& subkey, std::string const& value_name);
        HKEY const m_key;
        std::wstring const m_subkey;
        std::wstring const m_value_name;

        void store(std::wstring const&);
        void store(DWORD const);
        void store(int64_t const);

        std::wstring load_string(DWORD data_size) const;
        DWORD load_dword(DWORD data_size) const;
        int64_t load_qword(DWORD data_size) const;
    };

    /// <summary>
    /// A class representing a single value in the registry.
    /// </summary>
    /// <typeparam name="T">The type of the value. This can be any type, not
    /// just those supported by the registry, so select a type that's
    /// appropriate for the application code.</typeparam>
    template <registry_supported T>
    class value: protected value_base
    {
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
            value_base(key, subkey, value_name),
            m_default_value(default_value)
        { }

        /// <summary>
        /// Store a new value in the registry. Uses registry_traits::convert if type U is not supported by the registry.
        /// </summary>
        /// <typeparam name="U">Any input type. It ought to be compatible with T, but that's not enforced
        /// anywhere.</typeparam>
        /// <param name="new_value">The value to store in the registry.</param>
        void set(T const& new_value)
        {
            m_current_value = new_value;
            store(registry_traits<T>::genericize(new_value));
        }

        /// <summary>
        /// Read the current value from the registry.
        /// </summary>
        /// <returns>The current registry value, if present, else m_default_value</returns>
        T get() const
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
                    if constexpr (std::is_invocable<decltype(registry_traits<T>::specialize), int64_t>::value) {
                        switch (type) {
                            case REG_DWORD:
                            case REG_QWORD: {
                                int64_t const generic_result
                                    = type == REG_DWORD ? load_dword(data_size) : load_qword(data_size);
                                m_current_value = registry_traits<T>::specialize(generic_result);
                                return m_current_value.value();
                            }
                            default:
                                throw std::domain_error(
                                    std::format("unsupported registry type {}",
                                                ::get(registry_types, type).value_or(std::to_string(type))));
                        }
                    } else {
                        switch (type) {
                            case REG_EXPAND_SZ:
                            case REG_SZ: {
                                std::wstring const generic_result = load_string(data_size);
                                m_current_value = registry_traits<T>::specialize(generic_result);
                                return m_current_value.value();
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
