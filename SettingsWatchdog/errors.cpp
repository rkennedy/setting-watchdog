#include "errors.hpp"
#include <boost/winapi/error_codes.hpp>

boost::winapi::LONG_ RegCheck(boost::winapi::LONG_ arg, char const* message)
{
    if (arg != boost::winapi::ERROR_SUCCESS_) {
        std::error_code ec(arg, std::system_category());
        throw std::system_error(ec, message);
    }
    return arg;
}
