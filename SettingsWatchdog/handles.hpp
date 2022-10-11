#pragma once

#include <filesystem>

#include <windows.h>

/// <summary>
/// Base class for Windows service and service-manager handles.
/// </summary>
class BaseServiceHandle
{
private:
    SC_HANDLE const m_handle;
    BaseServiceHandle(BaseServiceHandle const&) = delete;
    BaseServiceHandle() = delete;

protected:
    /// <summary>
    /// Take ownership of the given handle. Throws an exception if the handle is null.
    /// </summary>
    /// <param name="handle">The handle to take ownership of</param>
    /// <param name="action">A brief message that will be included in the exception if the handle is null</param>
    BaseServiceHandle(SC_HANDLE const handle, char const* action);

    /// <summary>
    /// Close the wrapped service handle.
    /// </summary>
    ~BaseServiceHandle();

public:
    /// <summary>
    /// Expose the wrapped service handle.
    /// </summary>
    operator SC_HANDLE() const;
};

/// <summary>
/// A wrapper for Windows service-manager handles.
/// </summary>
class ServiceManagerHandle: public BaseServiceHandle
{
public:
    /// <summary>
    /// Open the service manager with the given permissions.
    /// </summary>
    explicit ServiceManagerHandle(DWORD permissions);
};

/// <summary>
/// A wrapper for Windows service handles.
/// </summary>
class ServiceHandle: public BaseServiceHandle
{
public:
    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="manager">The service manager</param>
    /// <param name="name">The internal name for the new service</param>
    /// <param name="display_name">The display name for the new service</param>
    /// <param name="type">The service type</param>
    /// <param name="start">The service start type</param>
    /// <param name="path">Full path of the binary to run for the service</param>
    ServiceHandle(ServiceManagerHandle const& manager, char const* name, char const* display_name, DWORD type,
                  DWORD start, std::filesystem::path const& path);

    /// <summary>
    /// Open an existing service.
    /// </summary>
    /// <param name="manager">The service manager</param>
    /// <param name="name">The name of the service to open</param>
    /// <param name="access">Desired access permissions on the service</param>
    ServiceHandle(ServiceManagerHandle const& manager, char const* name, DWORD access);
};

/// <summary>
/// A class to hold a Windows handle and close it on destruction.
/// </summary>
class AutoCloseHandle
{
private:
    HANDLE m_handle;
    AutoCloseHandle(AutoCloseHandle const&) = delete;
    AutoCloseHandle& operator=(AutoCloseHandle const&) = delete;

public:
    /// <summary>
    /// Construct an AutoCloseHandle by taking ownership of a Windows handle.
    /// </summary>
    explicit AutoCloseHandle(HANDLE handle = NULL);
    AutoCloseHandle(AutoCloseHandle&& other) noexcept;
    ~AutoCloseHandle();
    /// <summary>
    /// Address-of operator to allow passing this object to API functions that expect HANDLE* arguments.
    /// </summary>
    /// <returns>The address of the wrapped HANDLE member variable</returns>
    HANDLE* operator&();
    operator HANDLE() const;
};

/// <summary>
/// A Windows event-handle class that automatically closes the handle on destruction.
/// </summary>
class Event: public AutoCloseHandle
{
public:
    /// <summary>
    /// Create a manual-reset event whose state is initially cleared.
    /// </summary>
    Event();
};
