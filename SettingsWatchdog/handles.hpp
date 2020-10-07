#pragma once

#include <windows.h>

class BaseServiceHandle
{
private:
    SC_HANDLE const m_handle;
    BaseServiceHandle(BaseServiceHandle const&) = delete;
    BaseServiceHandle() = delete;
protected:
    BaseServiceHandle(SC_HANDLE const handle, char const* action);
    ~BaseServiceHandle();
public:
    operator SC_HANDLE() const;
};

class ServiceManagerHandle: public BaseServiceHandle
{
public:
    explicit ServiceManagerHandle(DWORD permissions);
};

class ServiceHandle: public BaseServiceHandle
{
public:
    ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                  TCHAR const* display_name, DWORD type, DWORD start,
                  TCHAR const* path);
    ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                  DWORD access);
};

class AutoCloseHandle
{
private:
    HANDLE m_handle;
    AutoCloseHandle(AutoCloseHandle const&) = delete;
    AutoCloseHandle& operator=(AutoCloseHandle const&) = delete;
public:
    explicit AutoCloseHandle(HANDLE handle = NULL);
    AutoCloseHandle(AutoCloseHandle&& other) noexcept;
    ~AutoCloseHandle();
    HANDLE* operator&();
    operator HANDLE() const;
};

class Event: public AutoCloseHandle
{
public:
    Event();
};
