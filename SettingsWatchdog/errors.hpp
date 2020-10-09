#pragma once

#include <system_error>
#include <utility>

#include <windows.h>

template <typename T>
T&& WinCheck(T&& arg, char const* message)
{
    if (!arg) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, message);
    }
    return std::move(arg);
}

LONG RegCheck(LONG arg, char const* message);
