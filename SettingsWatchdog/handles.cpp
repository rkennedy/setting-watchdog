#include "handles.hpp"

DISABLE_ANALYSIS
#include <boost/nowide/convert.hpp>
REENABLE_ANALYSIS

#include "errors.hpp"
#include "logging.hpp"

BaseServiceHandle::BaseServiceHandle(SC_HANDLE const handle, char const* action): m_handle(WinCheck(handle, action))
{ }

BaseServiceHandle::~BaseServiceHandle()
{
    LOG_FUNC();
    CloseServiceHandle(m_handle);
}

BaseServiceHandle::operator SC_HANDLE() const
{
    LOG_FUNC();
    return m_handle;
}

ServiceManagerHandle::ServiceManagerHandle(DWORD permissions):
    BaseServiceHandle(OpenSCManager(nullptr, nullptr, permissions), "opening service control manager")
{ }

ServiceHandle::ServiceHandle(ServiceManagerHandle const& manager, char const* name, char const* display_name,
                             DWORD type, DWORD start, std::filesystem::path const& path):
    BaseServiceHandle(CreateServiceW(manager, boost::nowide::widen(name).c_str(),
                                     boost::nowide::widen(display_name).c_str(), SERVICE_ALL_ACCESS, type, start,
                                     SERVICE_ERROR_NORMAL, path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr),
                      "creating service")
{ }

ServiceHandle::ServiceHandle(ServiceManagerHandle const& manager, char const* name, DWORD access):
    BaseServiceHandle(OpenServiceW(manager, boost::nowide::widen(name).c_str(), access), "opening service")
{ }

AutoCloseHandle::AutoCloseHandle(HANDLE handle): m_handle(handle)
{ }

AutoCloseHandle::AutoCloseHandle(AutoCloseHandle&& other) noexcept: m_handle(other.m_handle)
{
    LOG_FUNC();
    other.m_handle = NULL;
}

AutoCloseHandle::~AutoCloseHandle()
{
    LOG_FUNC();
    if (m_handle) [[likely]]
        CloseHandle(m_handle);
}

HANDLE* AutoCloseHandle::operator&()
{
    LOG_FUNC();
    return &m_handle;
}

AutoCloseHandle::operator HANDLE() const
{
    LOG_FUNC();
    return m_handle;
}

Event::Event():
    AutoCloseHandle(WinCheck(CreateEvent(nullptr,
                                         true,  // bManualReset
                                         false,  // bInitialState
                                         nullptr),
                             "creating event"))
{ }
