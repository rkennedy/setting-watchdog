#pragma once
#include <string>

#include <boost/core/noncopyable.hpp>
#include <boost/nowide/convert.hpp>

#include <windows.h>
#include <wtsapi32.h>

template <void (*FREE)(void*)>
class AutoFreeString: private boost::noncopyable
{
private:
    wchar_t* m_value = NULL;
    std::string mutable m_narrow_value;

public:
    ~AutoFreeString()
    {
        FREE(m_value);
    }
    wchar_t** operator&()
    {
        return &m_value;
    }
    operator char const*() const
    {
        m_narrow_value = boost::nowide::narrow(m_value);
        return m_narrow_value.c_str();
    }
};

using WTSString = AutoFreeString<[](void* arg) { WTSFreeMemory(arg); }>;
using LocalString = AutoFreeString<[](void* arg) { LocalFree(arg); }>;
