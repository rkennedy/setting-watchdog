#include "stdafx.h"
#include "SettingsWatchdog.h"

namespace po = boost::program_options;
namespace bl = boost::log;

#define VALUE_NAME(x) { x, #x }

auto const SystemPolicyKey = TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
auto const DesktopPolicyKey = TEXT("Control Panel\\Desktop");
DWORD const ServiceType = SERVICE_WIN32_OWN_PROCESS;

template <typename T>
T&& WinCheck(T&& arg, char const* message)
{
    if (!arg) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, message);
    }
    return std::move(arg);
}

LONG RegCheck(LONG arg, char const* message)
{
    if (arg != ERROR_SUCCESS) {
        std::error_code ec(arg, std::system_category());
        throw std::system_error(ec, message);
    }
    return arg;
}

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
    AutoCloseHandle(AutoCloseHandle&& other):
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
    TCHAR self_path[MAX_PATH];
    WinCheck(GetModuleFileName(NULL, self_path, MAX_PATH), "fetching current file name");
    BOOST_LOG_TRIVIAL(trace) << "Current file name is " << self_path;
    ServiceHandle const service(handle, TEXT("SettingsWatchdog"),
                                TEXT("Settings Watchdog"), ServiceType,
                                SERVICE_AUTO_START, self_path);
    BOOST_LOG_TRIVIAL(info) << "Service created";

    SERVICE_DESCRIPTION description = { TEXT("Watch registry settings and set "
        "them back to desired values") };
    WinCheck(ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description), "configuring service");
    BOOST_LOG_TRIVIAL(trace) << "Service configured";
}

void UninstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CONNECT);
    ServiceHandle const service(handle, TEXT("SettingsWatchdog"), DELETE);
    BOOST_LOG_TRIVIAL(trace) << "Service opened";
    WinCheck(DeleteService(service), "deleting service");
    BOOST_LOG_TRIVIAL(info) << "Service deleted";
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
    RegKey(RegKey&& other):
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

struct SettingsWatchdogContext
{
    SERVICE_STATUS_HANDLE StatusHandle;
    Event StopEvent;
    Event SessionChange;
    DWORD stopping_checkpoint;
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
    auto it = map.find(key);
    if (it != map.end())
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

void add_session(DWORD dwSessionId, SettingsWatchdogContext* context)
{
    BOOST_LOG_FUNC();
    BOOST_LOG_TRIVIAL(trace) << "adding session ID " << dwSessionId;
    {
        std::lock_guard<std::mutex> session_guard(context->session_mutex);
        assert(context->sessions.find(dwSessionId) == context->sessions.end());
    }
    // Get session user name
    AutoFreeWTSString name_buffer;
    DWORD name_buffer_bytes;
    WinCheck(WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTSUserName, &name_buffer, &name_buffer_bytes), "getting session user name");
    BOOST_LOG_TRIVIAL(trace) << "user for session is " << static_cast<LPTSTR>(name_buffer);

    AutoCloseHandle session_token;
    try {
        // Get SID of session
        WinCheck(WTSQueryUserToken(dwSessionId, &session_token), "getting session token");
    } catch (std::system_error const& ex) {
        std::error_code const error_no_token(ERROR_NO_TOKEN, std::system_category());
        if (ex.code() == error_no_token) {
            BOOST_LOG_TRIVIAL(info) << "no token for session";
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
        BOOST_LOG_TRIVIAL(trace) << "session sid " << sid << " (" << static_cast<LPTSTR>(name_buffer) << ")";
        RegKey key(HKEY_USERS, (subkey % sid % DesktopPolicyKey).str().c_str(), KEY_NOTIFY | KEY_SET_VALUE);

        std::lock_guard<std::mutex> session_guard(context->session_mutex);
        context->sessions.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(dwSessionId),
            std::forward_as_tuple(std::move(key), static_cast<LPTSTR>(name_buffer))
            );
        SetEvent(context->SessionChange);
    } catch (std::system_error const&) {
        BOOST_LOG_TRIVIAL(warning) << "no registry key for sid " << sid;
    }
}

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType,
                            LPVOID lpEventData, LPVOID lpContext)
{
    BOOST_LOG_FUNC();
    auto const context = static_cast<SettingsWatchdogContext*>(lpContext);

    BOOST_LOG_TRIVIAL(trace) << "Service control " << dwControl << " ("
        << get_with_default(control_names, dwControl, "unknown")
        << ")";
    switch (dwControl) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        case SERVICE_CONTROL_STOP:
        {
            SERVICE_STATUS stop_pending = { ServiceType, SERVICE_STOP_PENDING,
                0, NO_ERROR, 0, context->stopping_checkpoint++, 500 };
            SetServiceStatus(context->StatusHandle, &stop_pending);

            SetEvent(context->StopEvent);

            stop_pending.dwCheckPoint = context->stopping_checkpoint++;
            SetServiceStatus(context->StatusHandle, &stop_pending);
            return NO_ERROR;
        }
        case SERVICE_CONTROL_SESSIONCHANGE:
        {
            BOOST_LOG_TRIVIAL(trace) << "session-change code " << get_with_default(session_change_codes, dwEventType, std::to_string(dwEventType));
            auto const notification = static_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
            if (notification->cbSize != sizeof WTSSESSION_NOTIFICATION) {
                // The OS is sending the wrong structure size, so let's pretend
                // we don't know how to handle it.
                BOOST_LOG_TRIVIAL(error) << "Expected struct size "
                    << sizeof WTSSESSION_NOTIFICATION << " but got "
                    << notification->cbSize << " instead";
                return ERROR_CALL_NOT_IMPLEMENTED;
            }
            BOOST_LOG_TRIVIAL(trace) << "Session " << notification->dwSessionId << " changed";
            switch (dwEventType) {
                case WTS_SESSION_LOGON:
                {
                    add_session(notification->dwSessionId, context);
                    break;
                }
                case WTS_SESSION_LOGOFF:
                {
                    std::lock_guard<std::mutex> session_guard(context->session_mutex);
                    auto const it = context->sessions.find(notification->dwSessionId);
                    if (it == context->sessions.end()) {
                        BOOST_LOG_TRIVIAL(info) << "Session is not known. Ignored.";
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
    LONG const Result = RegDeleteValue(key, name);
    switch (Result) {
        case ERROR_SUCCESS:
            BOOST_LOG_TRIVIAL(info) << "Deleted " << name << " key";
            break;
        case ERROR_FILE_NOT_FOUND:
            BOOST_LOG_TRIVIAL(trace) << name << " key does not exist";
            break;
        default:
            BOOST_LOG_TRIVIAL(error) << "Error deleting " << name << " key: "
                << Result;
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
    BOOST_LOG_TRIVIAL(trace) << "Establishing notification";
    WinCheck(ResetEvent(NotifyEvent), "resetting event");
    RegCheck(RegNotifyChangeKeyValue(
        key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        NotifyEvent, true), "establishing notification");
    BOOST_LOG_TRIVIAL(trace) << "Established notification";
}

bool PrepareNextIteration()
{
    BOOST_LOG_FUNC();
    BOOST_LOG_TRIVIAL(trace) << "Looping again";
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
    BOOST_LOG_TRIVIAL(warning) << boost::format("%1% %2% not in range [%3%,%4%)") % label % value % min % max;
    return false;
}

void WINAPI SettingsWatchdogMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    BOOST_LOG_FUNC();
    try {
        BOOST_LOG_TRIVIAL(trace) << "Establishing service context";
        SettingsWatchdogContext context = {
            WinCheck(RegisterServiceCtrlHandlerEx(TEXT("SettingsWatchdog"),
                                                  ServiceHandler, &context),
                     "registering service handler"),
            Event(),
            Event(),
            0
            // TODO initialize context.sessions with current session list
        };
        try {
            DWORD starting_checkpoint = 0;
            SERVICE_STATUS start_pending = { ServiceType, SERVICE_START_PENDING, 0,
                NO_ERROR, 0, starting_checkpoint++, 500 };
            SetServiceStatus(context.StatusHandle, &start_pending);

            // Event handle must be created first because it must outlive its
            // associated registry key. When we close the registry key, the
            // registry-change notification will signal the event, so the event
            // needs to still exist when we close the registry key.
            BOOST_LOG_TRIVIAL(trace) << "Creating notification event";
            Event system_notify_event;
            BOOST_LOG_TRIVIAL(trace) << "Created notification event";

            BOOST_LOG_TRIVIAL(trace) << "Opening target registry key";
            RegKey const system_key(HKEY_LOCAL_MACHINE, SystemPolicyKey, KEY_NOTIFY | KEY_SET_VALUE);
            BOOST_LOG_TRIVIAL(trace) << "Opened target registry key";

            start_pending.dwCheckPoint = starting_checkpoint++;
            SetServiceStatus(context.StatusHandle, &start_pending);

            WTS_SESSION_INFO_1* raw_session_info;
            DWORD session_count;
            BOOST_LOG_TRIVIAL(trace) << "enumerating sessions";
            DWORD level = 1;
            WinCheck(WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &raw_session_info, &session_count), "getting session list");
            std::shared_ptr<WTS_SESSION_INFO_1> session_info(
                raw_session_info,
                [&session_count](void* info) {
                    WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, info, session_count);
                });
            std::for_each(
                session_info.get(), session_info.get() + session_count,
                [&context](WTS_SESSION_INFO_1 const& info) {
                    BOOST_LOG_TRIVIAL(trace) << "session " << info.pSessionName;
                    if (!info.pUserName) {
                        BOOST_LOG_TRIVIAL(trace) << "null user name; skipped";
                        return;
                    }
                    add_session(info.SessionId, &context);
                });

            start_pending.dwCheckPoint = starting_checkpoint++;
            SetServiceStatus(context.StatusHandle, &start_pending);

            EstablishNotification(system_key, system_notify_event);

            SERVICE_STATUS started = { ServiceType, SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE, NO_ERROR, 0, 0,
                0 };
            SetServiceStatus(context.StatusHandle, &started);

            RemoveLoginMessage(system_key);
            RemoveAutosignonRestriction(system_key);
            for_each(context.sessions.begin(), context.sessions.end(), [](std::map<DWORD, SessionData>::value_type const& item) {
                RemoveScreenSaverPolicy(item.second.key);
            });

            BOOST_LOG_TRIVIAL(trace) << "Beginning service loop";
            bool stop_requested = false;
            do {
                std::vector<HANDLE> wait_handles{ system_notify_event, context.StopEvent, context.SessionChange };
                auto const FixedWaitObjectCount = wait_handles.size();
                {
                    std::lock_guard<std::mutex> session_guard(context.session_mutex);
                    for (auto it = context.sessions.begin(); it != context.sessions.end(); ++it) {
                        wait_handles.push_back(it->second.notification);
                    }
                }
                if (!ensure_range<size_t>(1, MAXIMUM_WAIT_OBJECTS + 1, wait_handles.size(), "wait-handle count")) {
                    wait_handles.resize(MAXIMUM_WAIT_OBJECTS);
                }

                BOOST_LOG_TRIVIAL(info) << "Waiting for " << wait_handles.size() << " event(s)";
                DWORD const WaitResult = WaitForMultipleObjects(
                    boost::numeric_cast<DWORD>(wait_handles.size()),
                    wait_handles.data(), false, INFINITE);
                std::error_code ec(GetLastError(), std::system_category());
                BOOST_LOG_TRIVIAL(trace) << "Wait returned " << get_with_default(wait_results, WaitResult, std::to_string(WaitResult));
                switch (WaitResult) {
                    case WAIT_OBJECT_0:
                    {
                        BOOST_LOG_TRIVIAL(trace) << "System registry changed";
                        RemoveLoginMessage(system_key);
                        RemoveAutosignonRestriction(system_key);
                        EstablishNotification(system_key, system_notify_event);
                        break;
                    }
                    case WAIT_OBJECT_0 + 1:
                    {
                        BOOST_LOG_TRIVIAL(trace) << "Stop requested";
                        SERVICE_STATUS stop_pending = { ServiceType,
                            SERVICE_STOP_PENDING, 0, NO_ERROR, 0,
                            context.stopping_checkpoint++, 500 };
                        SetServiceStatus(context.StatusHandle, &stop_pending);
                        stop_requested = true;
                        break;
                    }
                    case WAIT_OBJECT_0 + 2:
                    {
                        BOOST_LOG_TRIVIAL(trace) << "Session list changed";
                        WinCheck(ResetEvent(context.SessionChange), "resetting session event");
                        std::lock_guard<std::mutex> session_guard(context.session_mutex);
                        for (auto it = context.sessions.begin(); it != context.sessions.end(); ) {
                            auto& session = it->second;
                            if (!session.running) {
                                // Remove no-longer-running session
                                it = context.sessions.erase(it);
                                continue;
                            }
                            if (session.new_) {
                                // TODO Initialize new sessions
                                session.new_ = false;
                                EstablishNotification(session.key, session.notification);
                            }
                        }
                        break;
                    }
                    default:
                    {
                        if (check_range<size_t>(WAIT_OBJECT_0, WAIT_OBJECT_0 + wait_handles.size(), WaitResult)) {
                            auto const session_index = WaitResult - WAIT_OBJECT_0 - FixedWaitObjectCount;
                            std::lock_guard<std::mutex> session_guard(context.session_mutex);
                            if (!ensure_range<size_t>(0, context.sessions.size(), session_index, "session index")) {
                                break;
                            }
                            auto const session_it = std::next(context.sessions.begin(), session_index);
                            auto const& session = session_it->second;
                            BOOST_LOG_TRIVIAL(trace) << "Session registry changed for " << session.username;
                            RemoveScreenSaverPolicy(session.key);
                            EstablishNotification(session.key, session.notification);
                        } else {
                            BOOST_LOG_TRIVIAL(trace) << "Unexpected wait result";
                        }
                        break;
                    }
                    case WAIT_TIMEOUT:
                    {
                        BOOST_LOG_TRIVIAL(warning) << "Infinity elapsed";
                        break;
                    }
                    case WAIT_FAILED:
                    {
                        BOOST_LOG_TRIVIAL(error) << "Waiting for notification failed";
                        throw std::system_error(ec, "Error waiting for events");
                    }
                }
            } while (!stop_requested && PrepareNextIteration());
            SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0, NO_ERROR,
                0, 0, 0 };
            SetServiceStatus(context.StatusHandle, &stopped);
        } catch (std::system_error const& ex) {
            if (ex.code().category() == std::system_category()) {
                SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0,
                    boost::numeric_cast<DWORD>(ex.code().value()), 0, 0, 0 };
                SetServiceStatus(context.StatusHandle, &stopped);
            } else {
                SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0,
                    ERROR_SERVICE_SPECIFIC_ERROR, boost::numeric_cast<DWORD>(ex.code().value()), 0, 0 };
                SetServiceStatus(context.StatusHandle, &stopped);
            }
            throw;
        }
    } catch (std::system_error const& ex) {
        BOOST_LOG_TRIVIAL(error) << "Error (" << ex.code() << ") " << boost::algorithm::trim_copy(std::string(ex.what()));
        return;
    }
}

BOOST_LOG_ATTRIBUTE_KEYWORD(process_id, "ProcessId", DWORD)
BOOST_LOG_ATTRIBUTE_KEYWORD(thread_id, "ThreadId", DWORD)

void SetUpLogging()
{
    BOOST_LOG_FUNC();
    bl::core::get()->add_global_attribute("TimeStamp", bl::attributes::local_clock());
    bl::core::get()->add_global_attribute("ProcessId", bl::attributes::make_constant(GetCurrentProcessId()));
    bl::core::get()->add_global_attribute("ThreadId", bl::attributes::make_function(&GetCurrentThreadId));
    bl::core::get()->add_global_attribute("Scope", bl::attributes::named_scope());
    bl::formatter formatter = (
        bl::expressions::format("%1% [%2%:%3%] <%4%> %5%: %6%")
        % bl::expressions::format_date_time<boost::posix_time::ptime>(
            "TimeStamp", "%Y-%m-%d %H:%M:%S")
        % process_id
        % thread_id
        % bl::trivial::severity
        % bl::expressions::format_named_scope(
            "Scope",
            bl::keywords::format = "%n",
            bl::keywords::incomplete_marker = "",
            bl::keywords::depth = 1)
        % bl::expressions::smessage
    );
    bl::add_console_log()->set_formatter(formatter);
    bl::add_file_log(
        bl::keywords::file_name = "C:\\SettingsWatchdog.log",
        bl::keywords::open_mode = std::ios_base::app | std::ios_base::out,
        bl::keywords::auto_flush = true
    )->set_formatter(formatter);
}

int main(int argc, char* argv[])
{
    BOOST_LOG_FUNC();
    try {
        SetUpLogging();

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
            { TEXT("SettingsWatchdog"), SettingsWatchdogMain },
            { nullptr, nullptr }
        };

        BOOST_LOG_TRIVIAL(trace) << "Starting service dispatcher";
        WinCheck(StartServiceCtrlDispatcher(ServiceTable),
                 "starting service dispatcher");
        BOOST_LOG_TRIVIAL(trace) << "Exiting";
        return EXIT_SUCCESS;
    } catch (std::system_error const& ex) {
        BOOST_LOG_TRIVIAL(error) << "Error (" << ex.code() << ") " << ex.what();
        return EXIT_FAILURE;
    }
}

// vim: set et sw=4 ts=4:
