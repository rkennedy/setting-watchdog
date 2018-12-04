#include "stdafx.h"
#include "SettingsWatchdog.h"

namespace po = boost::program_options;
namespace bl = boost::log;

#define VALUE_NAME(x) { x, #x }

auto const SystemPolicyKey = TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
auto const DesktopPolicyKey = TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop");
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

class Event: private boost::noncopyable
{
private:
    HANDLE m_handle;
public:
    Event():
        m_handle(WinCheck(CreateEvent(nullptr, true, false, nullptr), "creating event"))
    { }
    Event(Event&& other):
        m_handle(other.m_handle)
    {
        BOOST_LOG_FUNC();
        other.m_handle = NULL;
    }
    ~Event() {
        BOOST_LOG_FUNC();
        CloseHandle(m_handle);
    }
    operator HANDLE() const {
        return m_handle;
    }
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
    SessionData(RegKey&& key):
        new_(true),
        running(true),
        notification(),
        key(std::move(key))
    {}
};

struct SettingsWatchdogContext
{
    SERVICE_STATUS_HANDLE StatusHandle;
    Event StopEvent;
    Event SessionChange;
    DWORD stopping_checkpoint;
    std::map<DWORD, SessionData> sessions;
};

std::map<DWORD, std::string> const control_names{
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

std::map<DWORD, std::string> const session_change_codes{
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

class SidFormatter: private boost::noncopyable
{
    PSID m_sid;
    mutable LPSTR m_value;
public:
    SidFormatter(PSID sid): m_sid(sid), m_value(nullptr)
    { }
    ~SidFormatter()
    {
        LocalFree(m_value);
    }
    friend std::ostream& operator<<(std::ostream& os, SidFormatter const& sf) {
        if (!sf.m_value)
            WinCheck(ConvertSidToStringSidA(sf.m_sid, &sf.m_value));
        return os << sf.m_value;
    }
};

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType,
                            LPVOID lpEventData, LPVOID lpContext)
{
    BOOST_LOG_FUNC();
    auto const context = static_cast<SettingsWatchdogContext*>(lpContext);

    BOOST_LOG_TRIVIAL(trace) << "Service control " << dwControl << " ("
        << (control_names.find(dwControl) == control_names.end()
            ? "unknown"
            : control_names.at(dwControl))
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
            BOOST_LOG_TRIVIAL(trace) << "session-change code " << dwEventType;
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
                    assert(context->sessions.find(notification->dwSessionId) == context->sessions.end());
                    // Get SID of session
                    HANDLE session_token;
                    WinCheck(WTSQueryUserToken(notification->dwSessionId, &session_token), "getting session token"); // TODO close session_token

                    DWORD returned_length;
                    GetTokenInformation(session_token, TokenLogonSid, nullptr, 0, &returned_length);

                    std::vector<unsigned char> group_buffer(returned_length);
                    WinCheck(GetTokenInformation(session_token, TokenLogonSid, group_buffer.data(), group_buffer.size(), &returned_length), "getting token information");
                    auto const token_groups = reinterpret_cast<TOKEN_GROUPS*>(group_buffer.data());

                    // Select the first SID for which the registry key exists.
                    if (std::none_of(token_groups->Groups, token_groups->Groups + token_groups->GroupCount,
                        [&context, &notification](SID_AND_ATTRIBUTES const* saa) {
                            SidFormatter const sid(saa->Sid);
                            try {
                                boost::basic_format<TCHAR> subkey(TEXT("%1%\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"));
                                BOOST_LOG_TRIVIAL(trace) << "session sid " << sid;
                                context->sessions.emplace(notification->dwSessionId, std::move(RegKey(HKEY_USERS, (subkey % sid).str().c_str(), KEY_NOTIFY | KEY_SET_VALUE)));
                            } catch (std::system_error const& ex) {
                                BOOST_LOG_TRIVIAL(warning) << "no registry key for sid " << sid;
                                return false;
                            }
                            SetEvent(context->SessionChange);
                            return true;
                        }))
                    {
                        BOOST_LOG_TRIVIAL(warning) << "no user sid found for session " << notification->dwSessionId;
                    }
                    break;
                }
                case WTS_SESSION_LOGOFF:
                {
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
        };

        DWORD starting_checkpoint = 0;
        SERVICE_STATUS start_pending = { ServiceType, SERVICE_START_PENDING, 0,
            NO_ERROR, 0, starting_checkpoint++, 500 };
        SetServiceStatus(context.StatusHandle, &start_pending);

        // Event handle must be created first because it must outlive its
        // associated registry key. When we close the registry key, the
        // registry-change notification will signal the event, so the event
        // needs to still exist when we close the registry key.
        BOOST_LOG_TRIVIAL(trace) << "Creating notification event";
        Event NotifyEvent;
        BOOST_LOG_TRIVIAL(trace) << "Created notification event";

        BOOST_LOG_TRIVIAL(trace) << "Opening target registry key";
        RegKey const system_key(HKEY_LOCAL_MACHINE, SystemPolicyKey, KEY_NOTIFY | KEY_SET_VALUE);
        BOOST_LOG_TRIVIAL(trace) << "Opened target registry key";

        start_pending.dwCheckPoint = starting_checkpoint++;
        SetServiceStatus(context.StatusHandle, &start_pending);

        start_pending.dwCheckPoint = starting_checkpoint++;
        SetServiceStatus(context.StatusHandle, &start_pending);

        EstablishNotification(system_key, NotifyEvent);

        SERVICE_STATUS started = { ServiceType, SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE, NO_ERROR, 0, 0,
            0 };
        SetServiceStatus(context.StatusHandle, &started);

        RemoveLoginMessage(system_key);
        RemoveAutosignonRestriction(system_key);

        BOOST_LOG_TRIVIAL(trace) << "Beginning service loop";
        bool stop_requested = false;
        do {
            std::vector<HANDLE> const wait_handles{ NotifyEvent, context.StopEvent, context.SessionChange };
            BOOST_LOG_TRIVIAL(trace) << "Waiting for next event";
            DWORD const WaitResult = WaitForMultipleObjects(
                boost::numeric_cast<DWORD>(wait_handles.size()),
                wait_handles.data(), false, INFINITE);
            std::error_code ec(GetLastError(), std::system_category());
            BOOST_LOG_TRIVIAL(trace) << "Wait returned " << WaitResult;
            switch (WaitResult) {
                case WAIT_OBJECT_0:
                {
                    BOOST_LOG_TRIVIAL(trace) << "Registry changed";
                    RemoveLoginMessage(system_key);
                    RemoveAutosignonRestriction(system_key);
                    EstablishNotification(system_key, NotifyEvent);
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
                    for (auto it = context.sessions.begin(); it != context.sessions.end(); ) {
                        if (!it->second.running) {
                            // Remove no-longer-running session
                            it = context.sessions.erase(it);
                            continue;
                        }
                        if (it->second.new_) {
                            // TODO Initialize new sessions
                            it->second.new_ = false;
                            EstablishNotification(it->second.key, it->second.notification);
                        }
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
                default:
                {
                    BOOST_LOG_TRIVIAL(trace) << "Unexpected wait result";
                    break;
                }
            }
        } while (!stop_requested && PrepareNextIteration());

        SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0, NO_ERROR,
            0, 0, 0 };
        SetServiceStatus(context.StatusHandle, &stopped);
    } catch (std::system_error const& ex) {
        BOOST_LOG_TRIVIAL(error) << "Error (" << ex.code() << ") " << ex.what();
        return;
    }
}

void SetUpLogging()
{
    BOOST_LOG_FUNC();
    bl::add_common_attributes();
    bl::core::get()->add_global_attribute(
        "Scope", bl::attributes::named_scope());
    bl::formatter formatter =
        (bl::expressions::format("%1% [%2%:%3%] <%4%> %5%: %6%")
         % bl::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
         % bl::expressions::attr<bl::attributes::current_process_id::value_type>("ProcessID")
         % bl::expressions::attr<bl::attributes::current_thread_id::value_type>("ThreadID")
         % bl::trivial::severity
         % bl::expressions::format_named_scope(
             "Scope",
             bl::keywords::format = "%n",
             bl::keywords::incomplete_marker = "",
             bl::keywords::depth = 1)
         % bl::expressions::smessage);
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
