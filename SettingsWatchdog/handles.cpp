#include "errors.hpp"
#include "handles.hpp"

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/log/attributes/named_scope.hpp>

#pragma warning(pop)

BaseServiceHandle::BaseServiceHandle(SC_HANDLE const handle, char const* action):
    m_handle(WinCheck(handle, action))
{}

BaseServiceHandle::~BaseServiceHandle()
{
    BOOST_LOG_FUNC();
    CloseServiceHandle(m_handle);
}

BaseServiceHandle::operator SC_HANDLE() const {
    BOOST_LOG_FUNC();
    return m_handle;
}

ServiceManagerHandle::ServiceManagerHandle(DWORD permissions):
    BaseServiceHandle(OpenSCManager(nullptr, nullptr, permissions),
                      "opening service control manager")
{}

ServiceHandle::ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                             TCHAR const* display_name, DWORD type, DWORD start,
                             TCHAR const* path) :
    BaseServiceHandle(CreateService(manager, name, display_name,
                                    SERVICE_ALL_ACCESS, type, start,
                                    SERVICE_ERROR_NORMAL, path, nullptr,
                                    nullptr, nullptr, nullptr, nullptr),
                      "creating service")
{}

ServiceHandle::ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                             DWORD access):
    BaseServiceHandle(OpenService(manager, name, access), "opening service")
{}

AutoCloseHandle::AutoCloseHandle(HANDLE handle) :
    m_handle(handle)
{}

AutoCloseHandle::AutoCloseHandle(AutoCloseHandle&& other) noexcept:
    m_handle(other.m_handle)
{
    BOOST_LOG_FUNC();
    other.m_handle = NULL;
}

AutoCloseHandle::~AutoCloseHandle()
{
    BOOST_LOG_FUNC();
    if (m_handle)
        CloseHandle(m_handle);
}

HANDLE* AutoCloseHandle::operator&()
{
    BOOST_LOG_FUNC();
    return &m_handle;
}

AutoCloseHandle::operator HANDLE() const
{
    BOOST_LOG_FUNC();
    return m_handle;
}

Event::Event():
    AutoCloseHandle(WinCheck(CreateEvent(nullptr,
                                         true, // bManualReset
                                         false, // bInitialState
                                         nullptr), "creating event"))
{}
