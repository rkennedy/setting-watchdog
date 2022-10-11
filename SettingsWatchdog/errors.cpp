#include "errors.hpp"

void RegCheck(LSTATUS arg, char const* message)
{
    if (arg != ERROR_SUCCESS) [[unlikely]] {
        std::error_code ec(arg, std::system_category());
        throw std::system_error(ec, message);
    }
}
