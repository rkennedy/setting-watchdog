DISABLE_ANALYSIS
#include <algorithm>
#include <exception>
#include <functional>
#include <map>
#include <mutex>
#include <ranges>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <boost/algorithm/string/trim.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/nowide/convert.hpp>
#include <boost/nowide/iostream.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <plog/Initializers/ConsoleInitializer.h>
#include <plog/Log.h>

#include <windows.h>
#include <sddl.h>
#include <wtsapi32.h>
REENABLE_ANALYSIS

#include "config.hpp"
#include "errors.hpp"
#include "git-commit.hpp"
#include "handles.hpp"
#include "logging.hpp"
#include "registry.hpp"
#include "string-maps.hpp"

static auto const SystemPolicyKey = R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System)";
static auto const DesktopPolicyKey = R"(Control Panel\Desktop)";
static DWORD const ServiceType = SERVICE_WIN32_OWN_PROCESS;

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

static void InstallService()
{
    LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CREATE_SERVICE);
    auto const self_path = boost::dll::program_location();
    WDLOG(trace) << std::format("Current file name is {}", boost::nowide::narrow(self_path.native()));

    ServiceHandle const service(handle, "SettingsWatchdog", "Settings Watchdog", ServiceType, SERVICE_AUTO_START,
                                self_path);
    WDLOG(info) << "Service created";

    std::wstring const description_string
        = boost::nowide::widen("Watch registry settings and set them back to desired values");
    SERVICE_DESCRIPTIONW description = { .lpDescription = const_cast<wchar_t*>(description_string.c_str()) };
    WinCheck(ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description), "configuring service");
    WDLOG(trace) << "Service configured";
}

static void UninstallService()
{
    LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CONNECT);
    ServiceHandle const service(handle, "SettingsWatchdog", DELETE);
    WDLOG(trace) << "Service opened";
    WinCheck(DeleteService(service), "deleting service");
    WDLOG(info) << "Service deleted";
}

struct SessionData: private boost::noncopyable
{
    bool new_;
    bool running;
    Event notification;
    RegKey const key;
    std::string const username;

    SessionData(RegKey&& key, std::string const& username):
        new_(true),
        running(true),
        notification(),
        key(std::move(key)),
        username(username)
    { }
};

template <typename T>
class ServiceContext: public T
{
public:
    ServiceContext(char const* lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc):
        T(),
        StatusHandle(
            WinCheck(RegisterServiceCtrlHandlerExW(boost::nowide::widen(lpServiceName).c_str(), lpHandlerProc, this),
                     "registering service handler"))
    { }

    void SetServiceStatus(SERVICE_STATUS& lpServiceStatus) const
    {
        WinCheck(::SetServiceStatus(StatusHandle, &lpServiceStatus), "setting service status");
    }

private:
    // MSDN: "The service status handle does not have to be closed."
    SERVICE_STATUS_HANDLE StatusHandle;
};

// Context information about the program that's chared between multiple threads, particularly the main service thread
// running in SettingsWatchdogMain and the notification thread where ServiceHandler gets called.
struct SettingsWatchdogContext
{
    // A Windows event that gets triggered when it's time for the program to terminate.
    Event StopEvent;
    // A Windows event that the program will use to notify itself that the list of sessions has changed. The service
    // handler receives notifications when a session logs on or off, and the program needs to update its internal
    // session data accordingly.
    Event SessionChange;
    DWORD stopping_checkpoint = 0;
    // A mutex to protect updates to `sessions`.
    std::mutex session_mutex;
    // The user sessions being watched by the program. Key is the session ID, and value is the data associated with the
    // session in the program.
    std::map<DWORD, SessionData> sessions;
};

template <class CharT>
struct std::formatter<PSID, CharT>: std::formatter<char const*, CharT>
{
    template <class FormatContext>
    auto format(PSID sid, FormatContext& ctx) const
    {
        LOG_FUNC();
        LocalString value;
        WinCheck(ConvertSidToStringSidW(sid, &value), "converting string sid");
        return std::formatter<char const*, CharT>::format(static_cast<char const*>(value), ctx);
    }
};

template <class CharT>
struct std::formatter<std::error_code, CharT>: std::formatter<std::string, CharT>
{
    template <class FormatContext>
    auto format(std::error_code code, FormatContext& ctx) const
    {
        LOG_FUNC();
        std::ostringstream os;
        os << code;
        return std::formatter<std::string, CharT>::format(os.str(), ctx);
    }
};

// A lock that logs its label prior to acquiring or releasing its lock
struct logging_lock_guard
{
private:
    std::string m_label;
    std::lock_guard<std::mutex> m_guard;

public:
    logging_lock_guard(std::mutex& m, std::string const& label):
        m_label(([](std::string const& l) {
            // The lock gets acquired by creating `guard`, so we use this function to log the message during the
            // construction of `label` instead of after `guard` is already locked.
            WDLOG(debug) << std::format("locking {}", l);
            return l;
        })(label)),
        m_guard(m)
    { }
    ~logging_lock_guard()
    {
        WDLOG(debug) << std::format("unlocked {}", m_label);
    }
};

static std::string get_session_user_name(DWORD dwSessionId)
{
    WTSString name_buffer;
    DWORD name_buffer_bytes;
    WinCheck(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTSUserName, &name_buffer,
                                         &name_buffer_bytes),
             "getting session user name");
    return std::string { name_buffer };
}

static void add_session(DWORD dwSessionId, ServiceContext<SettingsWatchdogContext>* context)
{
    LOG_FUNC();
    WDLOG(trace) << std::format("adding session ID {}", dwSessionId);
#ifndef BOOST_ASSERT_IS_VOID
    {
        logging_lock_guard session_guard(context->session_mutex, "assertion");
        BOOST_ASSERT(context->sessions.contains(dwSessionId));
    }
#endif

    // Get session user name
    std::string const user_name { get_session_user_name(dwSessionId) };
    WDLOG(trace) << std::format("user for session is {}", user_name);

    AutoCloseHandle session_token;
    try {
        // Get SID of session
        WinCheck(WTSQueryUserToken(dwSessionId, &session_token), "getting session token");
    } catch (std::system_error const& ex) {
        if (ex.code() == errors::no_token) {
            WDLOG(info) << "no token for session";
            return;
        }
        throw;
    }

    DWORD returned_length;
    GetTokenInformation(session_token, TokenUser, nullptr, 0, &returned_length);

    std::vector<unsigned char> group_buffer(returned_length);
    WinCheck(GetTokenInformation(session_token, TokenUser, group_buffer.data(),
                                 boost::numeric_cast<DWORD>(group_buffer.size()), &returned_length),
             "getting token information");
    auto const token_user = reinterpret_cast<TOKEN_USER*>(group_buffer.data());

    try {
        WDLOG(trace) << std::format("session sid {} ({})", token_user->User.Sid, user_name);
        RegKey key(HKEY_USERS, std::format(R"({}\{})", token_user->User.Sid, DesktopPolicyKey).c_str(),
                   KEY_NOTIFY | KEY_SET_VALUE);

        logging_lock_guard session_guard(context->session_mutex, "emplacement");
        context->sessions.emplace(std::piecewise_construct, std::forward_as_tuple(dwSessionId),
                                  std::forward_as_tuple(std::move(key), user_name));
        SetEvent(context->SessionChange);
    } catch (std::system_error const&) {
        WDLOG(warning) << std::format("no registry key for sid {}", token_user->User.Sid);
    }
}

// Callback for handling events on a Windows service.
static DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    LOG_FUNC();
    auto const context = static_cast<ServiceContext<SettingsWatchdogContext>*>(lpContext);

    WDLOG(trace) << std::format("Service control {} ({})", dwControl,
                                get(control_names, dwControl).value_or("unknown"));
    // The OS notifies us of various events related to services.
    switch (dwControl) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        case SERVICE_CONTROL_STOP: {  // The OS has requested our service to stop.
            SERVICE_STATUS stop_pending = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_STOP_PENDING,
                .dwWin32ExitCode = NO_ERROR,
                .dwCheckPoint = context->stopping_checkpoint++,
                .dwWaitHint = 10,
            };
            context->SetServiceStatus(stop_pending);

            // Notify the service listener that we should stop.
            SetEvent(context->StopEvent);

            stop_pending.dwCheckPoint = context->stopping_checkpoint++;
            context->SetServiceStatus(stop_pending);
            return NO_ERROR;
        }
        case SERVICE_CONTROL_SESSIONCHANGE: {
            WDLOG(trace) << std::format("session-change code {}",
                                        get(session_change_codes, dwEventType).value_or(std::to_string(dwEventType)));
            auto const notification = static_cast<WTSSESSION_NOTIFICATION const*>(lpEventData);
            if (notification->cbSize != sizeof(WTSSESSION_NOTIFICATION)) [[unlikely]] {
                // The OS is sending the wrong structure size, so let's pretend
                // we don't know how to handle it.
                WDLOG(error) << std::format("Expected struct size {} but got {} instead",
                                            sizeof(WTSSESSION_NOTIFICATION), notification->cbSize);
                return ERROR_CALL_NOT_IMPLEMENTED;
            }
            WDLOG(trace) << std::format("Session {} changed", notification->dwSessionId);
            switch (dwEventType) {
                case WTS_SESSION_LOGON: {
                    add_session(notification->dwSessionId, context);
                    break;
                }
                case WTS_SESSION_LOGOFF: {
                    logging_lock_guard session_guard(context->session_mutex, "logoff");
                    if (auto const it = context->sessions.find(notification->dwSessionId);
                        it == context->sessions.end()) {
                        WDLOG(info) << "unknown session; ignored.";
                    } else {
                        // Mark the session for removal from the session list.
                        it->second.running = false;
                        // Wake up the main service thread so it stops watching for changes to the registry keys for
                        // this session.
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

static void RemoveLoginMessage(HKEY key)
{
    LOG_FUNC();
    DeleteRegistryValue(key, "LegalNoticeText");
    DeleteRegistryValue(key, "LegalNoticeCaption");
}

static void RemoveAutosignonRestriction(HKEY key)
{
    LOG_FUNC();
    DeleteRegistryValue(key, "DisableAutomaticRestartSignOn");
    DeleteRegistryValue(key, "DontDisplayLastUserName");
}

static void RemoveScreenSaverPolicy(HKEY key)
{
    LOG_FUNC();
    DeleteRegistryValue(key, "ScreenSaveActive");
    DeleteRegistryValue(key, "ScreenSaverIsSecure");
    DeleteRegistryValue(key, "ScreenSaverTimeOut");
    DeleteRegistryValue(key, "ScrnSave.exe");
}

// Tell the OS to set the event when there are changes to the given registry key.
static void EstablishNotification(HKEY key, Event const& NotifyEvent)
{
    LOG_FUNC();
    WDLOG(debug) << "Establishing notification";
    WinCheck(ResetEvent(NotifyEvent), "resetting event");
    RegCheck(RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, NotifyEvent, true),
             "establishing notification");
    WDLOG(debug) << "Established notification";
}

// A function to include in a `while` test to log the progress on each loop iteration.
static bool PrepareNextIteration()
{
    LOG_FUNC();
    WDLOG(debug) << "Looping again";
    return true;
}

template <typename T>
static bool check_range(T const& min, T const& max, T const& value)
{
    return min <= value && value < max;
}

template <typename T>
static bool ensure_range(T const& min, T const& max, T const& value, std::string const& label)
{
    if (check_range(min, max, value)) [[likely]]
        return true;
    WDLOG(warning) << std::format("{} {} not in range [{},{})", label, value, min, max);
    return false;
}

// The main entrypoint of the service. When this function returns, the service has terminated.
static void WINAPI SettingsWatchdogMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    LOG_FUNC();
    try {
        WDLOG(debug) << "Establishing service context";
        ServiceContext<SettingsWatchdogContext> context("SettingsWatchdog", ServiceHandler);
        try {
            DWORD starting_checkpoint = 0;
            SERVICE_STATUS start_pending = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_START_PENDING,
                .dwWin32ExitCode = NO_ERROR,
                .dwCheckPoint = starting_checkpoint++,
                .dwWaitHint = 10,
            };
            context.SetServiceStatus(start_pending);

            // Event handle must be created first because it must outlive its
            // associated registry key. When we close the registry key, the
            // registry-change notification will signal the event, so the event
            // needs to still exist when we close the registry key.
            WDLOG(debug) << "Creating notification event";
            Event system_notify_event;
            WDLOG(debug) << "Created notification event";

            WDLOG(debug) << "Opening target registry key";
            RegKey const system_key(HKEY_LOCAL_MACHINE, SystemPolicyKey, KEY_NOTIFY | KEY_SET_VALUE);
            WDLOG(debug) << "Opened target registry key";

            start_pending.dwCheckPoint = starting_checkpoint++;
            context.SetServiceStatus(start_pending);

            WTS_SESSION_INFO_1* raw_session_info;
            DWORD session_count;
            WDLOG(debug) << "enumerating sessions";
            DWORD level = 1;
#pragma warning(push)
            // The first parameter of WTSEnumerateSessionsEx is annotated with _In_, which indicates that its value
            // isn't supposed to be null. But WTS_CURRENT_SERVER_HANDLE is null, and that triggers a warning, which we
            // want to suppress.
#pragma warning(disable : 6387)  // Param 1 could be zero
            WinCheck(WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &raw_session_info, &session_count),
                     "getting session list");
#pragma warning(pop)
            std::shared_ptr<WTS_SESSION_INFO_1[]> session_info(raw_session_info, [&session_count](void* info) {
                WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, info, session_count);
            });
            std::for_each_n(session_info.get(), session_count, [&context](WTS_SESSION_INFO_1 const& info) {
                WDLOG(trace) << std::format("session {}", boost::nowide::narrow(info.pSessionName));
                if (!info.pUserName) {
                    WDLOG(debug) << "null user name; skipped";
                    return;
                }
                add_session(info.SessionId, &context);
            });

            start_pending.dwCheckPoint = starting_checkpoint++;
            context.SetServiceStatus(start_pending);

            EstablishNotification(system_key, system_notify_event);

            SERVICE_STATUS started = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_RUNNING,
                .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE,
                .dwWin32ExitCode = NO_ERROR,
            };
            context.SetServiceStatus(started);

            // Perform each of the cleanup tasks once at the start of the program. THen we'll watch the registry for any
            // updates.
            RemoveLoginMessage(system_key);
            RemoveAutosignonRestriction(system_key);
            std::ranges::for_each(context.sessions | std::views::values, RemoveScreenSaverPolicy, &SessionData::key);

            WDLOG(debug) << "Beginning service loop";
            bool stop_requested = false;
            do {
                std::vector<HANDLE> wait_handles { system_notify_event, context.StopEvent, context.SessionChange };
                auto const FixedWaitObjectCount = wait_handles.size();
                {
                    logging_lock_guard session_guard(context.session_mutex, "pre-wait");
                    std::ranges::copy(
                        context.sessions | std::views::values | std::views::transform(&SessionData::notification),
                        std::back_inserter(wait_handles));
                }
                if (!ensure_range<size_t>(1, MAXIMUM_WAIT_OBJECTS + 1, wait_handles.size(), "wait-handle count")) {
                    wait_handles.resize(MAXIMUM_WAIT_OBJECTS);
                }

                WDLOG(info) << std::format("Waiting for {} event(s)", wait_handles.size());
                DWORD const WaitResult = WaitForMultipleObjects(boost::numeric_cast<DWORD>(wait_handles.size()),
                                                                wait_handles.data(), false, INFINITE);
                std::error_code ec(GetLastError(), std::system_category());
                WDLOG(trace) << std::format("Wait returned {}",
                                            get(wait_results, WaitResult).value_or(std::to_string(WaitResult)));
                switch (WaitResult) {
                    case WAIT_OBJECT_0: {
                        WDLOG(trace) << "System registry changed";
                        // Do system-wide updates.
                        RemoveLoginMessage(system_key);
                        RemoveAutosignonRestriction(system_key);

                        // Reset so we're notified of more updates to the registry key.
                        EstablishNotification(system_key, system_notify_event);
                        break;
                    }
                    case WAIT_OBJECT_0 + 1: {
                        WDLOG(trace) << "Stop requested";
                        SERVICE_STATUS stop_pending = {
                            .dwServiceType = ServiceType,
                            .dwCurrentState = SERVICE_STOP_PENDING,
                            .dwWin32ExitCode = NO_ERROR,
                            .dwCheckPoint = context.stopping_checkpoint++,
                            .dwWaitHint = 10,
                        };
                        context.SetServiceStatus(stop_pending);
                        stop_requested = true;
                        break;
                    }
                    case WAIT_OBJECT_0 + 2: {
                        WDLOG(trace) << "Session list changed";
                        WinCheck(ResetEvent(context.SessionChange), "resetting session event");

                        logging_lock_guard session_guard(context.session_mutex, "session-list change");

                        // Remove any sessions that we've received log-off events for.
                        std::erase_if(context.sessions, [](auto const& item) { return !item.second.running; });

                        // Begin watching for changes to any sessions we've received log-on event for.
                        std::ranges::for_each(
                            context.sessions | std::views::values | std::views::filter(&SessionData::new_),
                            [](SessionData& session) {
                                session.new_ = false;
                                EstablishNotification(session.key, session.notification);
                            });
                        break;
                    }
                    default: {
                        if (check_range<size_t>(WAIT_OBJECT_0, WAIT_OBJECT_0 + wait_handles.size(), WaitResult)) {
                            auto const session_index = WaitResult - WAIT_OBJECT_0 - FixedWaitObjectCount;
                            logging_lock_guard session_guard(context.session_mutex, "session key change");
                            if (!ensure_range<size_t>(0, context.sessions.size(), session_index, "session index")) {
                                break;
                            }
                            auto const session_it = std::next(context.sessions.begin(), session_index);
                            auto const& session = session_it->second;
                            WDLOG(trace) << std::format("Session registry changed for {}", session.username);

                            // Do session-related updates.
                            RemoveScreenSaverPolicy(session.key);

                            // Reset so we're notified of more updates to the registry key.
                            EstablishNotification(session.key, session.notification);
                        } else {
                            WDLOG(warning) << "Unexpected wait result";
                        }
                        break;
                    }
                    case WAIT_TIMEOUT: {
                        WDLOG(warning) << "Infinity elapsed";
                        break;
                    }
                    case WAIT_FAILED: {
                        WDLOG(error) << "Waiting for notification failed";
                        throw std::system_error(ec, "Error waiting for events");
                    }
                }
            } while (!stop_requested && PrepareNextIteration());
            SERVICE_STATUS stopped = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_STOPPED,
                .dwWin32ExitCode = NO_ERROR,
            };
            context.SetServiceStatus(stopped);
        } catch (std::system_error const& ex) {
            SERVICE_STATUS stopped = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_STOPPED,
            };
            if (ex.code().category() == std::system_category()) {
                stopped.dwWin32ExitCode = boost::numeric_cast<DWORD>(ex.code().value());
            } else {
                stopped.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
                stopped.dwServiceSpecificExitCode = boost::numeric_cast<DWORD>(ex.code().value());
            }
            context.SetServiceStatus(stopped);
            throw;
        }
    } catch (std::system_error const& ex) {
        WDLOG(error) << std::format("Error ({}) {}", ex.code(), boost::algorithm::trim_copy(std::string(ex.what())));
        return;
    }
}

int main(int argc, char* argv[])
{
    LOG_FUNC();
    auto& logger { plog::init<LogFormatter>(plog::none, plog::streamStdErr) };
    try {
        auto const desired_action = config::process_args(argc, argv, logger);
        WDLOG(info) << std::format("Running {}", boost::nowide::narrow(boost::dll::program_location().native()));
        WDLOG(trace) << std::format("Commit {}", git_commit);

        switch (desired_action) {
            using enum config::program_action;
            case help:
                // Help has already been printed by process_args because it has the argument descriptions.
                return EXIT_SUCCESS;
            case install:
                InstallService();
                return EXIT_SUCCESS;
            case uninstall:
                UninstallService();
                return EXIT_SUCCESS;
            default:;
        }

        std::wstring const service_name = boost::nowide::widen("SettingsWatchdog");
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { const_cast<wchar_t*>(service_name.c_str()), SettingsWatchdogMain },
            { nullptr, nullptr },
        };

        WDLOG(debug) << "Starting service dispatcher";
        WinCheck(StartServiceCtrlDispatcherW(ServiceTable), "starting service dispatcher");
        WDLOG(debug) << "Exiting";
        return EXIT_SUCCESS;
    } catch (std::system_error const& ex) {
        WDLOG(error) << std::format("Error ({}) {}", ex.code(), boost::algorithm::trim_copy(std::string(ex.what())));
        return EXIT_FAILURE;
    } catch (std::exception const& ex) {
        auto const msg = std::format("Error: {}", boost::algorithm::trim_copy(std::string(ex.what())));
        try {
            WDLOG(error) << msg;
        } catch (std::exception const&) {
            boost::nowide::clog << std::format("Logging failed: {}\n{}", ex.what(), msg) << std::endl;
        }
        return EXIT_FAILURE;
    }
}

// vim: set et sw=4 ts=4:
