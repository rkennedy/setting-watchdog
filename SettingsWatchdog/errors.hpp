#pragma once

#include <system_error>
#include <utility>

#include <windows.h>

/// <summary>
/// Check the result of a Windows API function.
/// </summary>
/// <typeparam name="T">The return type of the API function</typeparam>
/// <param name="arg">The return value of the API function. Non-zero values pass.</param>
/// <param name="message">An informational message to include in the exception, if the call fails</param>
/// <returns>arg, if arg passes. Otherwise, it throws a system_error exception.</returns>
template <typename T>
T&& WinCheck(T&& arg, char const* message)
{
    if (!arg) [[unlikely]] {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, message);
    }
    return std::move(arg);
}

/// <summary>
/// Check the result of a Windows registry API function. This is different from WinCheck because registry functions
/// directly return their error codes instead of using GetLastError.
/// </summary>
/// <param name="arg">The return value of the registry API function. ERROR_SUCCESS passes.</param>
/// <param name="message">An informational message to include in the exception, if the call fails</param>
void RegCheck(LSTATUS arg, char const* message);

namespace errors
{
    /// <summary>
    /// An error code representing the ERROR_ACCESS_DENIED Windows error code.
    /// </summary>
    std::error_code const access_denied { ERROR_ACCESS_DENIED, std::system_category() };

    /// <summary>
    /// An error code representing the ERROR_NO_TOKEN Windows error code.
    /// </summary>
    std::error_code const no_token { ERROR_NO_TOKEN, std::system_category() };
}  // namespace errors
