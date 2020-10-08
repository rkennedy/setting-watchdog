#include "errors.hpp"

LONG RegCheck(LONG arg, char const* message)
{
    if (arg != ERROR_SUCCESS) {
        std::error_code ec(arg, std::system_category());
        throw std::system_error(ec, message);
    }
    return arg;
}
