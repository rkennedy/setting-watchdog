#include "logging.hpp"
#include "errors.hpp"
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <iomanip>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <codeanalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <boost/algorithm/string/trim.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/format.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/sources/severity_feature.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/program_options.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>

#pragma warning(pop)

#include "git-commit.hpp"

namespace po = boost::program_options;

#define VALUE_NAME(x) { x, #x }
#if UNICODE
using format = boost::wformat;
#else
using format = boost::format;
#endif

auto const SystemPolicyKey = TEXT(R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System)");
auto const DesktopPolicyKey = TEXT(R"(Control Panel\Desktop)");
DWORD const ServiceType = SERVICE_WIN32_OWN_PROCESS;

class BaseServiceHandle
{
private:
    SC_HANDLE const m_handle;
    BaseServiceHandle(BaseServiceHandle const&) = delete;
    BaseServiceHandle() = delete;
protected:
    BaseServiceHandle(SC_HANDLE const handle, std::string const& action):
        m_handle(WinCheck(handle, action.c_str()))
    { }
    ~BaseServiceHandle()
    {
        BOOST_LOG_FUNC();
        CloseServiceHandle(m_handle);
    }
public:
    operator SC_HANDLE() const {
        BOOST_LOG_FUNC();
        return m_handle;
    }
};

class ServiceManagerHandle: public BaseServiceHandle
{
public:
    explicit ServiceManagerHandle(DWORD permissions):
        BaseServiceHandle(OpenSCManager(nullptr, nullptr, permissions),
                          "opening service control manager")
    { }
};

class ServiceHandle: public BaseServiceHandle
{
public:
    ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                  TCHAR const* display_name, DWORD type, DWORD start,
                  TCHAR const* path):
        BaseServiceHandle(CreateService(manager, name, display_name,
                                        SERVICE_ALL_ACCESS, type, start,
                                        SERVICE_ERROR_NORMAL, path, nullptr,
                                        nullptr, nullptr, nullptr, nullptr),
                          "creating service")
    { }
    ServiceHandle(ServiceManagerHandle const& manager, TCHAR const* name,
                  DWORD access):
        BaseServiceHandle(OpenService(manager, name, access), "opening service")
    { }
};

class AutoCloseHandle: private boost::noncopyable
{
private:
    HANDLE m_handle;
public:
    explicit AutoCloseHandle(HANDLE handle = NULL):
        m_handle(handle)
    { }
    AutoCloseHandle(AutoCloseHandle&& other) noexcept:
        m_handle(other.m_handle)
    {
        BOOST_LOG_FUNC();
        other.m_handle = NULL;
    }
    ~AutoCloseHandle() {
        BOOST_LOG_FUNC();
        if (m_handle)
            CloseHandle(m_handle);
    }
    HANDLE* operator&() {
        BOOST_LOG_FUNC();
        return &m_handle;
    }
    operator HANDLE() const {
        BOOST_LOG_FUNC();
        return m_handle;
    }
};

class AutoFreeWTSString: private boost::noncopyable
{
private:
    LPTSTR m_value = NULL;
public:
    ~AutoFreeWTSString() {
        BOOST_LOG_FUNC();
        WTSFreeMemory(m_value);
    }
    LPTSTR* operator&() {
        BOOST_LOG_FUNC();
        return &m_value;
    }
    operator LPTSTR() const {
        BOOST_LOG_FUNC();
        return m_value;
    }
};

void InstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CREATE_SERVICE);
    auto const self_path = boost::dll::program_location();
#pragma warning(push)
#pragma warning(disable: 26812) // Enum is unscoped. Prefer enum class.
    BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("Current file name is %1%")) % self_path.native();
#pragma warning(pop)

    ServiceHandle const service(handle, TEXT("SettingsWatchdog"),
                                TEXT("Settings Watchdog"), ServiceType,
                                SERVICE_AUTO_START, self_path.c_str());
    BOOST_LOG_SEV(wdlog::get(), info) << "Service created";

    SERVICE_DESCRIPTION description = { const_cast<LPTSTR>(TEXT("Watch registry settings and set "
        "them back to desired values")) };
    WinCheck(ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description), "configuring service");
    BOOST_LOG_SEV(wdlog::get(), trace) << "Service configured";
}

void UninstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CONNECT);
    ServiceHandle const service(handle, TEXT("SettingsWatchdog"), DELETE);
    BOOST_LOG_SEV(wdlog::get(), trace) << "Service opened";
    WinCheck(DeleteService(service), "deleting service");
    BOOST_LOG_SEV(wdlog::get(), info) << "Service deleted";
}

class Event: public AutoCloseHandle
{
public:
    Event():
        AutoCloseHandle(WinCheck(CreateEvent(nullptr,
                                             true, // bManualReset
                                             false, // bInitialState
                                             nullptr), "creating event"))
    { }
};

HKEY OpenRegKey(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired)
{
    HKEY result;
    RegCheck(RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, &result), "opening registry key");
    return result;
}

class RegKey: private boost::noncopyable
{
    HKEY m_key;
public:
    RegKey(HKEY key, TCHAR const* name, DWORD permissions):
        m_key(OpenRegKey(key, name, 0, permissions))
    {}
    RegKey(RegKey&& other) noexcept:
        m_key(other.m_key)
    {
        other.m_key = NULL;
    }
    ~RegKey()
    {
        if (m_key)
            RegCloseKey(m_key);
    }
    operator HKEY() const
    {
        return m_key;
    }
};

struct SessionData: private boost::noncopyable
{
    bool new_;
    bool running;
    Event notification;
    RegKey const key;
    std::basic_string<TCHAR> const username;
    SessionData(RegKey&& key, std::basic_string<TCHAR> const& username):
        new_(true),
        running(true),
        notification(),
        key(std::move(key)),
        username(username)
    {}
};

template <typename T>
class ServiceContext: public T
{
public:
    ServiceContext(LPCTSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc):
        T(),
        StatusHandle(WinCheck(RegisterServiceCtrlHandlerEx(lpServiceName, lpHandlerProc, this),
                              "registering service handler"))
    {}

    void SetServiceStatus(SERVICE_STATUS& lpServiceStatus) const {
        WinCheck(::SetServiceStatus(StatusHandle, &lpServiceStatus),
                 "setting service status");
    }
private:
    // MSDN: "The service status handle does not have to be closed."
    SERVICE_STATUS_HANDLE StatusHandle;
};

struct SettingsWatchdogContext
{
    Event StopEvent;
    Event SessionChange;
    DWORD stopping_checkpoint = 0;
    std::mutex session_mutex;
    std::map<DWORD, SessionData> sessions;
};

std::map<DWORD, std::string> const control_names
{
    VALUE_NAME(SERVICE_CONTROL_CONTINUE),
    VALUE_NAME(SERVICE_CONTROL_INTERROGATE),
    VALUE_NAME(SERVICE_CONTROL_NETBINDADD),
    VALUE_NAME(SERVICE_CONTROL_NETBINDDISABLE),
    VALUE_NAME(SERVICE_CONTROL_NETBINDENABLE),
    VALUE_NAME(SERVICE_CONTROL_NETBINDREMOVE),
    VALUE_NAME(SERVICE_CONTROL_PARAMCHANGE),
    VALUE_NAME(SERVICE_CONTROL_PAUSE),
    VALUE_NAME(SERVICE_CONTROL_PRESHUTDOWN),
    VALUE_NAME(SERVICE_CONTROL_SHUTDOWN),
    VALUE_NAME(SERVICE_CONTROL_STOP),
    VALUE_NAME(SERVICE_CONTROL_DEVICEEVENT),
    VALUE_NAME(SERVICE_CONTROL_HARDWAREPROFILECHANGE),
    VALUE_NAME(SERVICE_CONTROL_POWEREVENT),
    VALUE_NAME(SERVICE_CONTROL_SESSIONCHANGE),
    VALUE_NAME(SERVICE_CONTROL_TIMECHANGE),
    VALUE_NAME(SERVICE_CONTROL_TRIGGEREVENT),
    //VALUE_NAME(SERVICE_CONTROL_USERMODEREBOOT),
};

std::map<DWORD, std::string> const session_change_codes
{
    VALUE_NAME(WTS_CONSOLE_CONNECT),
    VALUE_NAME(WTS_CONSOLE_DISCONNECT),
    VALUE_NAME(WTS_REMOTE_CONNECT),
    VALUE_NAME(WTS_REMOTE_DISCONNECT),
    VALUE_NAME(WTS_SESSION_LOGON),
    VALUE_NAME(WTS_SESSION_LOGOFF),
    VALUE_NAME(WTS_SESSION_LOCK),
    VALUE_NAME(WTS_SESSION_LOCK),
    VALUE_NAME(WTS_SESSION_REMOTE_CONTROL),
    VALUE_NAME(WTS_SESSION_REMOTE_CONTROL),
    VALUE_NAME(WTS_SESSION_TERMINATE),
};

std::map<DWORD, std::string> const wait_results
{
    VALUE_NAME(WAIT_OBJECT_0),
    VALUE_NAME(WAIT_OBJECT_0 + 1),
    VALUE_NAME(WAIT_OBJECT_0 + 2),
    VALUE_NAME(WAIT_TIMEOUT),
    VALUE_NAME(WAIT_FAILED),
};

template <typename Map, typename T>
typename Map::mapped_type get_with_default(Map const& map, typename Map::key_type const& key, T const& default_value)
{
    if (auto it = map.find(key); it != map.end())
        return it->second;
    return default_value;
}

BOOL Convert(PSID sid, char*& str)
{
    return ConvertSidToStringSidA(sid, &str);
}

BOOL Convert(PSID sid, wchar_t*& str)
{
    return ConvertSidToStringSidW(sid, &str);
}

class SidFormatter
{
    PSID m_sid;
public:
    SidFormatter(PSID sid):
        m_sid(sid)
    { }
    template <typename T> friend std::basic_ostream<T>& operator<<(std::basic_ostream<T>& os, SidFormatter const& sf) {
        BOOST_LOG_FUNC();
        T* value;
        WinCheck(Convert(sf.m_sid, value), "converting string sid");
        os << value;
        LocalFree(value);
        return os;
    }
};

struct logging_lock_guard
{
    std::string label;
    std::lock_guard<std::mutex> guard;
    logging_lock_guard(std::mutex& m, std::string const& label):
        label(([](std::string const& l) { BOOST_LOG_SEV(wdlog::get(), debug) << format(TEXT("locking %1%")) % l.c_str(); return l; })(label)),
        guard(m)
    { }
    ~logging_lock_guard() {
        BOOST_LOG_SEV(wdlog::get(), debug) << format(TEXT("unlocked %1%")) % label.c_str();
    }
};

void add_session(DWORD dwSessionId, ServiceContext<SettingsWatchdogContext>* context)
{
    BOOST_LOG_FUNC();
    BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("adding session ID %1%")) % dwSessionId;
    {
        logging_lock_guard session_guard(context->session_mutex, "assertion");
        assert(context->sessions.find(dwSessionId) == context->sessions.end());
    }
    // Get session user name
    AutoFreeWTSString name_buffer;
    DWORD name_buffer_bytes;
    WinCheck(WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTSUserName, &name_buffer, &name_buffer_bytes), "getting session user name");
    BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("user for session is %1%")) % static_cast<LPTSTR>(name_buffer);

    AutoCloseHandle session_token;
    try {
        // Get SID of session
        WinCheck(WTSQueryUserToken(dwSessionId, &session_token), "getting session token");
    } catch (std::system_error const& ex) {
        std::error_code const error_no_token(ERROR_NO_TOKEN, std::system_category());
        if (ex.code() == error_no_token) {
            BOOST_LOG_SEV(wdlog::get(), info) << "no token for session";
            return;
        }
        throw;
    }

    DWORD returned_length;
    GetTokenInformation(session_token, TokenUser, nullptr, 0, &returned_length);

    std::vector<unsigned char> group_buffer(returned_length);
    WinCheck(GetTokenInformation(session_token, TokenUser, group_buffer.data(), boost::numeric_cast<DWORD>(group_buffer.size()), &returned_length), "getting token information");
    auto const token_user = reinterpret_cast<TOKEN_USER*>(group_buffer.data());

    SidFormatter const sid(token_user->User.Sid);
    try {
        boost::basic_format<TCHAR> subkey(TEXT("%1%\\%2%"));
        BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("session sid %1% (%2%)")) % sid % static_cast<LPTSTR>(name_buffer);
        RegKey key(HKEY_USERS, (subkey % sid % DesktopPolicyKey).str().c_str(), KEY_NOTIFY | KEY_SET_VALUE);

        logging_lock_guard session_guard(context->session_mutex, "emplacement");
        context->sessions.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(dwSessionId),
            std::forward_as_tuple(std::move(key), static_cast<LPTSTR>(name_buffer))
            );
        SetEvent(context->SessionChange);
    } catch (std::system_error const&) {
        BOOST_LOG_SEV(wdlog::get(), warning) << format(TEXT("no registry key for sid %1%")) % sid;
    }
}

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType,
                            LPVOID lpEventData, LPVOID lpContext)
{
    BOOST_LOG_FUNC();
    auto const context = static_cast<ServiceContext<SettingsWatchdogContext>*>(lpContext);

    BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("Service control %1% (%2%)")) % dwControl % get_with_default(control_names, dwControl, "unknown").c_str();
    switch (dwControl) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        case SERVICE_CONTROL_STOP:
        {
            SERVICE_STATUS stop_pending = { ServiceType, SERVICE_STOP_PENDING,
                0, NO_ERROR, 0, context->stopping_checkpoint++, 10 };
            context->SetServiceStatus(stop_pending);

            SetEvent(context->StopEvent);

            stop_pending.dwCheckPoint = context->stopping_checkpoint++;
            context->SetServiceStatus(stop_pending);
            return NO_ERROR;
        }
        case SERVICE_CONTROL_SESSIONCHANGE:
        {
            BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("session-change code %1%")) % get_with_default(session_change_codes, dwEventType, std::to_string(dwEventType)).c_str();
            auto const notification = static_cast<WTSSESSION_NOTIFICATION const*>(lpEventData);
            if (notification->cbSize != sizeof(WTSSESSION_NOTIFICATION)) {
                // The OS is sending the wrong structure size, so let's pretend
                // we don't know how to handle it.
                BOOST_LOG_SEV(wdlog::get(), error) << format(TEXT("Expected struct size %1% but got %2% instead"))
                    % sizeof(WTSSESSION_NOTIFICATION)
                    % notification->cbSize;
                return ERROR_CALL_NOT_IMPLEMENTED;
            }
            BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("Session %1% changed")) % notification->dwSessionId;
            switch (dwEventType) {
                case WTS_SESSION_LOGON:
                {
                    add_session(notification->dwSessionId, context);
                    break;
                }
                case WTS_SESSION_LOGOFF:
                {
                    logging_lock_guard session_guard(context->session_mutex, "logoff");
                    if (auto const it = context->sessions.find(notification->dwSessionId); it == context->sessions.end()) {
                        BOOST_LOG_SEV(wdlog::get(), info) << "unknown session; ignored.";
                    } else {
                        it->second.running = false;
                        SetEvent(context->SessionChange);
                    }
                    break;
                }
                default:
                    break;
            }
            return NO_ERROR;
        }
    }
}

void DeleteRegistryKey(HKEY key, TCHAR const* name)
{
    switch (LONG const Result = RegDeleteValue(key, name); Result) {
        case ERROR_SUCCESS:
            BOOST_LOG_SEV(wdlog::get(), info) << format(TEXT("Deleted %1% key")) % name;
            break;
        case ERROR_FILE_NOT_FOUND:
            BOOST_LOG_SEV(wdlog::get(), trace) << format(TEXT("%1% key does not exist")) % name;
            break;
        default:
            BOOST_LOG_SEV(wdlog::get(), error) << format(TEXT("Error deleting %1% key: %2%")) % name % Result;
            break;
    }
}

void RemoveLoginMessage(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryKey(key, TEXT("LegalNoticeText"));
    DeleteRegistryKey(key, TEXT("LegalNoticeCaption"));
}

void RemoveAutosignonRestriction(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryKey(key, TEXT("DisableAutomaticRestartSignOn"));
    DeleteRegistryKey(key, TEXT("DontDisplayLastUserName"));
}

void RemoveScreenSaverPolicy(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryKey(key, TEXT("ScreenSaveActive"));
    DeleteRegistryKey(key, TEXT("ScreenSaverIsSecure"));
    DeleteRegistryKey(key, TEXT("ScreenSaverTimeOut"));
    DeleteRegistryKey(key, TEXT("ScrnSave.exe"));
}

void EstablishNotification(HKEY key, Event const& NotifyEvent)
{
    BOOST_LOG_FUNC();
    BOOST_LOG_SEV(wdlog::get(), debug) << "Establishing notification";
    WinCheck(ResetEvent(NotifyEvent), "resetting event");
    RegCheck(RegNotifyChangeKeyValue(
        key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        NotifyEvent, true), "establishing notification");
    BOOST_LOG_SEV(wdlog::get(), debug) << "Established notification";
}

bool PrepareNextIteration()
{
    BOOST_LOG_FUNC();
    BOOST_LOG_SEV(wdlog::get(), debug) << "Looping again";
    return true;
}

template <typename T>
bool check_range(T const& min, T const& max, T const& value)
{
    return min <= value && value < max;
}

template <typename T>
bool ensure_range(T const& min, T const& max, T const& value, std::string const& label)
{
    if (check_range(min, max, value))
        return true;
    BOOST_LOG_SEV(wdlog::get(), warning) << format(TEXT("%1% %2% not in range [%3%,%4%)")) % label.c_str() % value % min % max;
    return false;
}

template <typename M, typename F>
void map_erase_if(M& m, F predicate)
{
    for (auto it = m.begin(); it != m.end(); )
        if (predicate(*it))
            m.erase(it++);
        else
            ++it;
}

void WINAPI SettingsWatchdogMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    BOOST_LOG_FUNC();
    try {
        BOOST_LOG_SEV(wdlog::get(), debug) << "Establishing service context";
        ServiceContext<SettingsWatchdogContext> context(TEXT("SettingsWatchdog"), ServiceHandler);
        try {
            DWORD starting_checkpoint = 0;
            SERVICE_STATUS start_pending = { ServiceType, SERVICE_START_PENDING, 0,
                NO_ERROR, 0, starting_checkpoint++, 10 };
            context.SetServiceStatus(start_pending);

            // Event handle must be created first because it must outlive its
            // associated registry key. When we close the registry key, the
            // registry-change notification will signal the event, so the event
            // needs to still exist when we close the registry key.
            BOOST_LOG_SEV(wdlog::get(), debug) << "Creating notification event";
            Event system_notify_event;
            BOOST_LOG_SEV(wdlog::get(), debug) << "Created notification event";

            BOOST_LOG_SEV(wdlog::get(), debug) << "Opening target registry key";
            RegKey const system_key(HKEY_LOCAL_MACHINE, SystemPolicyKey, KEY_NOTIFY | KEY_SET_VALUE);
            BOOST_LOG_SEV(wdlog::get(), debug) << "Opened target registry key";

            start_pending.dwCheckPoint = starting_checkpoint++;
            context.SetServiceStatus(start_pending);

            WTS_SESSION_INFO_1* raw_session_info;
            DWORD session_count;
            BOOST_LOG_SEV(wdlog::get(), debug) << "enumerating sessions";
            DWORD level = 1;
#pragma warning(push)
#pragma warning(disable: 6387) // Param 1 could be zero
            WinCheck(WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &raw_session_info, &session_count), "getting session list");
#pragma warning(pop)
            std::shared_ptr<WTS_SESSION_INFO_1> session_info(
                raw_session_info,
                [&session_count](void* info) {
                    WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, info, session_count);
                });
            std::for_each(
                session_info.get(), session_info.get() + session_count,
                [&context](WTS_SESSION_INFO_1 const& info) {
                    BOOST_LOG_SEV(wdlog::get(), trace) << "session " << info.pSessionName;
                    if (!info.pUserName) {
                        BOOST_LOG_SEV(wdlog::get(), debug) << "null user name; skipped";
                        return;
                    }
                    add_session(info.SessionId, &context);
                });

            start_pending.dwCheckPoint = starting_checkpoint++;
            context.SetServiceStatus(start_pending);

            EstablishNotification(system_key, system_notify_event);

            SERVICE_STATUS started = { ServiceType, SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE, NO_ERROR, 0, 0,
                0 };
            context.SetServiceStatus(started);

            RemoveLoginMessage(system_key);
            RemoveAutosignonRestriction(system_key);
            for_each(context.sessions.begin(), context.sessions.end(), [](std::map<DWORD, SessionData>::value_type const& item) {
                RemoveScreenSaverPolicy(item.second.key);
            });

            BOOST_LOG_SEV(wdlog::get(), debug) << "Beginning service loop";
            bool stop_requested = false;
            do {
                std::vector<HANDLE> wait_handles{ system_notify_event, context.StopEvent, context.SessionChange };
                auto const FixedWaitObjectCount = wait_handles.size();
                {
                    logging_lock_guard session_guard(context.session_mutex, "pre-wait");
                    boost::push_back(
                        wait_handles,
                        context.sessions
                        | boost::adaptors::map_values
                        | boost::adaptors::transformed(std::mem_fn(&SessionData::notification)));
                }
                if (!ensure_range<size_t>(1, MAXIMUM_WAIT_OBJECTS + 1, wait_handles.size(), "wait-handle count")) {
                    wait_handles.resize(MAXIMUM_WAIT_OBJECTS);
                }

                BOOST_LOG_SEV(wdlog::get(), info) << "Waiting for " << wait_handles.size() << " event(s)";
                DWORD const WaitResult = WaitForMultipleObjects(
                    boost::numeric_cast<DWORD>(wait_handles.size()),
                    wait_handles.data(), false, INFINITE);
                std::error_code ec(GetLastError(), std::system_category());
                BOOST_LOG_SEV(wdlog::get(), trace) << "Wait returned " << get_with_default(wait_results, WaitResult, std::to_string(WaitResult)).c_str();
                switch (WaitResult) {
                    case WAIT_OBJECT_0:
                    {
                        BOOST_LOG_SEV(wdlog::get(), trace) << "System registry changed";
                        RemoveLoginMessage(system_key);
                        RemoveAutosignonRestriction(system_key);
                        EstablishNotification(system_key, system_notify_event);
                        break;
                    }
                    case WAIT_OBJECT_0 + 1:
                    {
                        BOOST_LOG_SEV(wdlog::get(), trace) << "Stop requested";
                        SERVICE_STATUS stop_pending = { ServiceType,
                            SERVICE_STOP_PENDING, 0, NO_ERROR, 0,
                            context.stopping_checkpoint++, 10 };
                        context.SetServiceStatus(stop_pending);
                        stop_requested = true;
                        break;
                    }
                    case WAIT_OBJECT_0 + 2:
                    {
                        BOOST_LOG_SEV(wdlog::get(), trace) << "Session list changed";
                        WinCheck(ResetEvent(context.SessionChange), "resetting session event");
                        logging_lock_guard session_guard(context.session_mutex, "session-list change");
                        map_erase_if(context.sessions, [](std::map<DWORD, SessionData>::value_type const& item) {
                            return !item.second.running;
                        });
                        boost::for_each(
                            context.sessions
                            | boost::adaptors::map_values
                            | boost::adaptors::filtered(
                                [](SessionData const& session) {
                                    return session.new_;
                                }),
                            [](SessionData& session) {
                                // TODO Initialize new sessions
                                session.new_ = false;
                                EstablishNotification(session.key, session.notification);
                            });
                        break;
                    }
                    default:
                    {
                        if (check_range<size_t>(WAIT_OBJECT_0, WAIT_OBJECT_0 + wait_handles.size(), WaitResult)) {
                            auto const session_index = WaitResult - WAIT_OBJECT_0 - FixedWaitObjectCount;
                            logging_lock_guard session_guard(context.session_mutex, "session key change");
                            if (!ensure_range<size_t>(0, context.sessions.size(), session_index, "session index")) {
                                break;
                            }
                            auto const session_it = std::next(context.sessions.begin(), session_index);
                            auto const& session = session_it->second;
                            BOOST_LOG_SEV(wdlog::get(), trace) << "Session registry changed for " << session.username;
                            RemoveScreenSaverPolicy(session.key);
                            EstablishNotification(session.key, session.notification);
                        } else {
                            BOOST_LOG_SEV(wdlog::get(), warning) << "Unexpected wait result";
                        }
                        break;
                    }
                    case WAIT_TIMEOUT:
                    {
                        BOOST_LOG_SEV(wdlog::get(), warning) << "Infinity elapsed";
                        break;
                    }
                    case WAIT_FAILED:
                    {
                        BOOST_LOG_SEV(wdlog::get(), error) << "Waiting for notification failed";
                        throw std::system_error(ec, "Error waiting for events");
                    }
                }
            } while (!stop_requested && PrepareNextIteration());
            SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0, NO_ERROR,
                0, 0, 0 };
            context.SetServiceStatus(stopped);
        } catch (std::system_error const& ex) {
            if (ex.code().category() == std::system_category()) {
                SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0,
                    boost::numeric_cast<DWORD>(ex.code().value()), 0, 0, 0 };
                context.SetServiceStatus(stopped);
            } else {
                SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0,
                    ERROR_SERVICE_SPECIFIC_ERROR, boost::numeric_cast<DWORD>(ex.code().value()), 0, 0 };
                context.SetServiceStatus(stopped);
            }
            throw;
        }
    } catch (std::system_error const& ex) {
        BOOST_LOG_SEV(wdlog::get(), error) << format(TEXT("Error (%1%) %2%")) % ex.code() % boost::algorithm::trim_copy(std::string(ex.what())).c_str();
        return;
    }
}

int main(int argc, char* argv[])
{
    BOOST_LOG_FUNC();
    try {
        BOOST_LOG_SEV(wdlog::get(), info) << "Running " << boost::dll::program_location().native();
        BOOST_LOG_SEV(wdlog::get(), trace) << "Commit " << git_commit;

        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "This help message")
            ("install,i", "Install the service")
            ("uninstall,u", "Uninstall the service")
            ;
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }
        if (vm.count("install")) {
            InstallService();
            return EXIT_SUCCESS;
        }
        if (vm.count("uninstall")) {
            UninstallService();
            return EXIT_SUCCESS;
        }

        SERVICE_TABLE_ENTRY ServiceTable[] = {
            { const_cast<LPTSTR>(TEXT("SettingsWatchdog")), SettingsWatchdogMain },
            { nullptr, nullptr }
        };

        BOOST_LOG_SEV(wdlog::get(), debug) << "Starting service dispatcher";
        WinCheck(StartServiceCtrlDispatcher(ServiceTable),
                 "starting service dispatcher");
        BOOST_LOG_SEV(wdlog::get(), debug) << "Exiting";
        return EXIT_SUCCESS;
    } catch (std::system_error const& ex) {
        BOOST_LOG_SEV(wdlog::get(), error) << "Error (" << ex.code() << ") " << ex.what();
        return EXIT_FAILURE;
    }
}

// vim: set et sw=4 ts=4:
