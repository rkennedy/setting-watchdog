#pragma once

#include <system_error>
#include <utility>

#include <boost/winapi/basic_types.hpp>
#include <boost/winapi/get_last_error.hpp>

template <typename T>
T&& WinCheck(T&& arg, char const* message)
{
    if (!arg) {
        std::error_code ec(boost::winapi::GetLastError(), std::system_category());
        throw std::system_error(ec, message);
    }
    return std::move(arg);
}

boost::winapi::LONG_ RegCheck(boost::winapi::LONG_ arg, char const* message);
