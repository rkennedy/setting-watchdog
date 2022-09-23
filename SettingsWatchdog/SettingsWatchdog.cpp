DISABLE_ANALYSIS
#include <algorithm>
#include <exception>
#include <experimental/map>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <boost/algorithm/string/trim.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/nowide/args.hpp>
#include <boost/nowide/convert.hpp>
#include <boost/nowide/iostream.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/program_options.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>

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

namespace po = boost::program_options;

auto const SystemPolicyKey = R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System)";
auto const DesktopPolicyKey = R"(Control Panel\Desktop)";
DWORD const ServiceType = SERVICE_WIN32_OWN_PROCESS;

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

void InstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CREATE_SERVICE);
    auto const self_path = boost::dll::program_location();
    WDLOG(trace) << std::format("Current file name is {}", boost::nowide::narrow(self_path.native()));

    ServiceHandle const service(handle, "SettingsWatchdog", "Settings Watchdog", ServiceType, SERVICE_AUTO_START,
                                self_path.c_str());
    WDLOG(info) << "Service created";

    std::wstring const description_string
        = boost::nowide::widen("Watch registry settings and set them back to desired values");
    SERVICE_DESCRIPTIONW description = { .lpDescription = const_cast<wchar_t*>(description_string.c_str()) };
    WinCheck(ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description), "configuring service");
    WDLOG(trace) << "Service configured";
}

void UninstallService()
{
    BOOST_LOG_FUNC();
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

struct SettingsWatchdogContext
{
    Event StopEvent;
    Event SessionChange;
    DWORD stopping_checkpoint = 0;
    std::mutex session_mutex;
    std::map<DWORD, SessionData> sessions;
};

template <class CharT>
struct std::formatter<PSID, CharT>: std::formatter<char const*, CharT>
{
    template <class FormatContext>
    auto format(PSID sid, FormatContext& ctx) const
    {
        BOOST_LOG_FUNC();
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
        BOOST_LOG_FUNC();
        std::ostringstream os;
        os << code;
        return std::formatter<std::string, CharT>::format(os.str(), ctx);
    }
};

struct logging_lock_guard
{
    std::string label;
    std::lock_guard<std::mutex> guard;
    logging_lock_guard(std::mutex& m, std::string const& label):
        label(([](std::string const& l) {
            WDLOG(debug) << std::format("locking {}", l);
            return l;
        })(label)),
        guard(m)
    { }
    ~logging_lock_guard()
    {
        WDLOG(debug) << std::format("unlocked {}", label);
    }
};

void add_session(DWORD dwSessionId, ServiceContext<SettingsWatchdogContext>* context)
{
    BOOST_LOG_FUNC();
    WDLOG(trace) << std::format("adding session ID {}", dwSessionId);
#ifndef BOOST_ASSERT_IS_VOID
    {
        logging_lock_guard session_guard(context->session_mutex, "assertion");
        BOOST_ASSERT(context->sessions.contains(dwSessionId));
    }
#endif

    // Get session user name
    WTSString name_buffer;
    DWORD name_buffer_bytes;
    WinCheck(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTSUserName, &name_buffer,
                                         &name_buffer_bytes),
             "getting session user name");
    WDLOG(trace) << std::format("user for session is {}", name_buffer);

    AutoCloseHandle session_token;
    try {
        // Get SID of session
        WinCheck(WTSQueryUserToken(dwSessionId, &session_token), "getting session token");
    } catch (std::system_error const& ex) {
        std::error_code const error_no_token(ERROR_NO_TOKEN, std::system_category());
        if (ex.code() == error_no_token) {
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
        WDLOG(trace) << std::format("session sid {} ({})", token_user->User.Sid, name_buffer);
        RegKey key(HKEY_USERS, std::format(R"({}\{})", token_user->User.Sid, DesktopPolicyKey).c_str(),
                   KEY_NOTIFY | KEY_SET_VALUE);

        logging_lock_guard session_guard(context->session_mutex, "emplacement");
        context->sessions.emplace(std::piecewise_construct, std::forward_as_tuple(dwSessionId),
                                  std::forward_as_tuple(std::move(key), std::string(name_buffer)));
        SetEvent(context->SessionChange);
    } catch (std::system_error const&) {
        WDLOG(warning) << std::format("no registry key for sid {}", token_user->User.Sid);
    }
}

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    BOOST_LOG_FUNC();
    auto const context = static_cast<ServiceContext<SettingsWatchdogContext>*>(lpContext);

    WDLOG(trace) << std::format("Service control {} ({})", dwControl,
                                get(control_names, dwControl).value_or("unknown"));
    switch (dwControl) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        case SERVICE_CONTROL_STOP: {
            SERVICE_STATUS stop_pending = {
                .dwServiceType = ServiceType,
                .dwCurrentState = SERVICE_STOP_PENDING,
                .dwWin32ExitCode = NO_ERROR,
                .dwCheckPoint = context->stopping_checkpoint++,
                .dwWaitHint = 10,
            };
            context->SetServiceStatus(stop_pending);

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

void RemoveLoginMessage(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryValue(key, "LegalNoticeText");
    DeleteRegistryValue(key, "LegalNoticeCaption");
}

void RemoveAutosignonRestriction(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryValue(key, "DisableAutomaticRestartSignOn");
    DeleteRegistryValue(key, "DontDisplayLastUserName");
}

void RemoveScreenSaverPolicy(HKEY key)
{
    BOOST_LOG_FUNC();
    DeleteRegistryValue(key, "ScreenSaveActive");
    DeleteRegistryValue(key, "ScreenSaverIsSecure");
    DeleteRegistryValue(key, "ScreenSaverTimeOut");
    DeleteRegistryValue(key, "ScrnSave.exe");
}

void EstablishNotification(HKEY key, Event const& NotifyEvent)
{
    BOOST_LOG_FUNC();
    WDLOG(debug) << "Establishing notification";
    WinCheck(ResetEvent(NotifyEvent), "resetting event");
    RegCheck(RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, NotifyEvent, true),
             "establishing notification");
    WDLOG(debug) << "Established notification";
}

bool PrepareNextIteration()
{
    BOOST_LOG_FUNC();
    WDLOG(debug) << "Looping again";
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
    if (check_range(min, max, value)) [[likely]]
        return true;
    WDLOG(warning) << std::format("{} {} not in range [{},{})", label, value, min, max);
    return false;
}

void WINAPI SettingsWatchdogMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    BOOST_LOG_FUNC();
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
#pragma warning(disable : 6387)  // Param 1 could be zero
            WinCheck(WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &raw_session_info, &session_count),
                     "getting session list");
#pragma warning(pop)
            std::shared_ptr<WTS_SESSION_INFO_1> session_info(raw_session_info, [&session_count](void* info) {
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

            RemoveLoginMessage(system_key);
            RemoveAutosignonRestriction(system_key);
            boost::for_each(context.sessions, [](std::map<DWORD, SessionData>::value_type const& item) {
                RemoveScreenSaverPolicy(item.second.key);
            });

            WDLOG(debug) << "Beginning service loop";
            bool stop_requested = false;
            do {
                std::vector<HANDLE> wait_handles { system_notify_event, context.StopEvent, context.SessionChange };
                auto const FixedWaitObjectCount = wait_handles.size();
                {
                    logging_lock_guard session_guard(context.session_mutex, "pre-wait");
                    boost::push_back(wait_handles,
                                     context.sessions | boost::adaptors::map_values
                                         | boost::adaptors::transformed(std::mem_fn(&SessionData::notification)));
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
                        RemoveLoginMessage(system_key);
                        RemoveAutosignonRestriction(system_key);
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
                        std::erase_if(context.sessions, [](auto const& item) { return !item.second.running; });
                        boost::for_each(context.sessions | boost::adaptors::map_values
                                            | boost::adaptors::filtered(std::mem_fn(&SessionData::new_)),
                                        [](SessionData& session) {
                                            // TODO Initialize new sessions
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
                            RemoveScreenSaverPolicy(session.key);
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
            if (ex.code().category() == std::system_category()) {
                SERVICE_STATUS stopped = {
                    .dwServiceType = ServiceType,
                    .dwCurrentState = SERVICE_STOPPED,
                    .dwWin32ExitCode = boost::numeric_cast<DWORD>(ex.code().value()),
                };
                context.SetServiceStatus(stopped);
            } else {
                SERVICE_STATUS stopped = {
                    .dwServiceType = ServiceType,
                    .dwCurrentState = SERVICE_STOPPED,
                    .dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR,
                    .dwServiceSpecificExitCode = boost::numeric_cast<DWORD>(ex.code().value()),
                };
                context.SetServiceStatus(stopped);
            }
            throw;
        }
    } catch (std::system_error const& ex) {
        WDLOG(error) << std::format("Error ({}) {}", ex.code(), boost::algorithm::trim_copy(std::string(ex.what())));
        return;
    }
}

int main(int argc, char* argv[])
{
    BOOST_LOG_FUNC();
    try {
        boost::nowide::args a(argc, argv);

        po::options_description desc("Allowed options");
        desc.add_options()
            // clang-format off
            ("help,h", "This help message")
            ("install,i", "Install the service")
            ("uninstall,u", "Uninstall the service")
            ("log-location,l", po::value<std::filesystem::path>(), "Set the location of the log file")
            ("verbose,v", po::value<severity_level>(), "Set the verbosity level")
            // clang-format on
            ;
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.contains("help")) {
            boost::nowide::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }
        if (vm.contains("log-location")) {
            config::log_file.set(vm.at("log-location").as<std::filesystem::path>());
        }
        if (vm.contains("verbose")) {
            config::verbosity.set(vm.at("verbose").as<severity_level>());
        }
        WDLOG(info) << std::format("Running {}", boost::nowide::narrow(boost::dll::program_location().native()));
        WDLOG(trace) << std::format("Commit {}", git_commit);

        if (vm.contains("install")) {
            InstallService();
            return EXIT_SUCCESS;
        }
        if (vm.contains("uninstall")) {
            UninstallService();
            return EXIT_SUCCESS;
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
        WDLOG(error) << std::format("Error: {}", boost::algorithm::trim_copy(std::string(ex.what())));
        return EXIT_FAILURE;
    }
}

// vim: set et sw=4 ts=4:
