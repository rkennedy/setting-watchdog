#include "stdafx.h"
#include "SettingsWatchdog.h"

namespace po = boost::program_options;
namespace bl = boost::log;

class ServiceManagerHandle
{
public:
    explicit ServiceManagerHandle(DWORD permissions):
        m_handle(OpenSCManager(nullptr, nullptr, permissions))
    {
        BOOST_LOG_FUNC();
        if (!m_handle) {
            std::error_code ec(GetLastError(), std::system_category());
            throw std::system_error(ec, "Error opening service control manager");
        }
    }
    ~ServiceManagerHandle() {
        BOOST_LOG_FUNC();
        CloseServiceHandle(m_handle);
    }

    operator SC_HANDLE() const {
        BOOST_LOG_FUNC();
        return m_handle;
    }
private:
    SC_HANDLE m_handle;
};

DWORD const ServiceType = SERVICE_WIN32_OWN_PROCESS;

void InstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CREATE_SERVICE);
    TCHAR self_path[MAX_PATH];
    if (!GetModuleFileName(NULL, self_path, MAX_PATH)) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, "Error fetch current file name");
    }
    BOOST_LOG_TRIVIAL(trace) << "Current file name is " << self_path;
    SC_HANDLE const service = CreateService(
        handle, TEXT("SettingsWatchdog"), TEXT("Settings watchdog"),
        SERVICE_ALL_ACCESS, ServiceType, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, self_path, nullptr, nullptr, nullptr, nullptr,
        nullptr);
    if (!service) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, "Error creating service");
    }
    BOOST_LOG_TRIVIAL(trace) << "Service created";
    BOOST_SCOPE_EXIT(&service) {
        CloseServiceHandle(service);
    } BOOST_SCOPE_EXIT_END;
}

void UninstallService()
{
    BOOST_LOG_FUNC();
    ServiceManagerHandle const handle(SC_MANAGER_CONNECT);
    SC_HANDLE const service = OpenService(
        handle, TEXT("SettingsWatchdog"), DELETE);
    if (!service) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, "Error opening service");
    }
    BOOST_SCOPE_EXIT(&service) {
        CloseServiceHandle(service);
    } BOOST_SCOPE_EXIT_END;
    BOOST_LOG_TRIVIAL(trace) << "Service opened";
    if (!DeleteService(service)) {
        std::error_code ec(GetLastError(), std::system_category());
        throw std::system_error(ec, "Error deleting service");
    }
    BOOST_LOG_TRIVIAL(trace) << "Service deleted";
}

struct SettingsWatchdogContext
{
    SERVICE_STATUS_HANDLE StatusHandle;
    HANDLE StopEvent;
    DWORD stopping_checkpoint;
};

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData,
                            LPVOID lpContext)
{
    BOOST_LOG_FUNC();
    SettingsWatchdogContext* const context = static_cast<SettingsWatchdogContext*>(lpContext);

    BOOST_LOG_TRIVIAL(trace) << "Service control " << dwControl;
    switch (dwControl) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        case SERVICE_CONTROL_STOP:
        {
            SERVICE_STATUS stop_pending = { ServiceType, SERVICE_STOP_PENDING, 0, NO_ERROR, 0, context->stopping_checkpoint++, 500 };
            SetServiceStatus(context->StatusHandle, &stop_pending);

            SetEvent(context->StopEvent);

            stop_pending.dwCheckPoint = context->stopping_checkpoint++;
            SetServiceStatus(context->StatusHandle, &stop_pending);
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
            BOOST_LOG_TRIVIAL(error) << "Error deleting " << name << " key: " << Result;
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

void EstablishNotification(HKEY key, HANDLE NotifyEvent)
{
    BOOST_LOG_FUNC();
    BOOST_LOG_TRIVIAL(trace) << "Establishing notification";
    LONG NotifyResult = RegNotifyChangeKeyValue(
        key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        NotifyEvent, true);
    if (NotifyResult != ERROR_SUCCESS) {
        std::error_code ec(NotifyResult, std::system_category());
        throw std::system_error(ec, "Error establishing notification");
    }
    BOOST_LOG_TRIVIAL(trace) << "Established notification";
}

bool PrepareNextIteration(HKEY key, HANDLE NotifyEvent)
{
    BOOST_LOG_FUNC();
    EstablishNotification(key, NotifyEvent);
    BOOST_LOG_TRIVIAL(trace) << "Looping again";
    return true;
}

void WINAPI SettingsWatchdogMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    BOOST_LOG_FUNC();
    try {
        SettingsWatchdogContext context = {};

        BOOST_LOG_TRIVIAL(trace) << "Registering service handler";
        context.StatusHandle = RegisterServiceCtrlHandlerEx(
            TEXT("SettingsWatchdog"), ServiceHandler, &context);
        if (!context.StatusHandle) {
            std::error_code ec(GetLastError(), std::system_category());
            throw std::system_error(ec, "Error registing service handler");
        }

        DWORD starting_checkpoint = 0;
        SERVICE_STATUS start_pending = { ServiceType, SERVICE_START_PENDING, 0, NO_ERROR, 0, starting_checkpoint++, 500 };
        SetServiceStatus(context.StatusHandle, &start_pending);

        BOOST_LOG_TRIVIAL(trace) << "Creating termination event";
        context.StopEvent = CreateEvent(nullptr, true, false, nullptr);
        if (!context.StopEvent) {
            std::error_code ec(GetLastError(), std::system_category());
            throw std::system_error(ec, "Error creating termination event");
        }
        BOOST_SCOPE_EXIT(&context) {
            CloseHandle(context.StopEvent);
        } BOOST_SCOPE_EXIT_END;
        BOOST_LOG_TRIVIAL(trace) << "Created termination event";

        start_pending.dwCheckPoint = starting_checkpoint++;
        SetServiceStatus(context.StatusHandle, &start_pending);

        BOOST_LOG_TRIVIAL(trace) << "Opening target registry key";
        HKEY key;
        LONG RegResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 0, KEY_NOTIFY | KEY_SET_VALUE, &key);
        if (RegResult != ERROR_SUCCESS) {
            std::error_code ec(RegResult, std::system_category());
            throw std::system_error(ec, "Error opening target registry key");
        }
        BOOST_SCOPE_EXIT(&key) {
            RegCloseKey(key);
        } BOOST_SCOPE_EXIT_END;
        BOOST_LOG_TRIVIAL(trace) << "Opened target registry key";

        start_pending.dwCheckPoint = starting_checkpoint++;
        SetServiceStatus(context.StatusHandle, &start_pending);

        BOOST_LOG_TRIVIAL(trace) << "Creating notification event";
        HANDLE NotifyEvent = CreateEvent(nullptr, true, false, nullptr);
        if (!NotifyEvent) {
            std::error_code ec(GetLastError(), std::system_category());
            throw std::system_error(ec, "Error creating notification event");
        }
        BOOST_SCOPE_EXIT(&NotifyEvent) {
            CloseHandle(NotifyEvent);
        } BOOST_SCOPE_EXIT_END;
        BOOST_LOG_TRIVIAL(trace) << "Created notification event";

        start_pending.dwCheckPoint = starting_checkpoint++;
        SetServiceStatus(context.StatusHandle, &start_pending);

        EstablishNotification(key, NotifyEvent);

        SERVICE_STATUS started = { ServiceType, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, NO_ERROR, 0, 0, 0 };
        SetServiceStatus(context.StatusHandle, &started);

        RemoveLoginMessage(key);
        RemoveAutosignonRestriction(key);

        BOOST_LOG_TRIVIAL(trace) << "Beginning service loop";
        bool stop_requested = false;
        do {
            std::vector<HANDLE> const wait_handles{ NotifyEvent, context.StopEvent };
            BOOST_LOG_TRIVIAL(trace) << "Waiting for next event";
            DWORD const WaitResult = WaitForMultipleObjects(
                boost::numeric_cast<DWORD>(wait_handles.size()),
                wait_handles.data(), false, INFINITE);
            BOOST_LOG_TRIVIAL(trace) << "Wait returned " << WaitResult;
            switch (WaitResult) {
                case WAIT_OBJECT_0:
                {
                    BOOST_LOG_TRIVIAL(trace) << "Registry changed";
                    RemoveLoginMessage(key);
                    RemoveAutosignonRestriction(key);
                    break;
                }
                case WAIT_OBJECT_0 + 1:
                {
                    BOOST_LOG_TRIVIAL(trace) << "Stop requested";
                    SERVICE_STATUS stop_pending = { ServiceType, SERVICE_STOP_PENDING, 0, NO_ERROR, 0, context.stopping_checkpoint++, 500 };
                    SetServiceStatus(context.StatusHandle, &stop_pending);
                    stop_requested = true;
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
                    std::error_code ec(GetLastError(), std::system_category());
                    throw std::system_error(ec, "Error waiting for events");
                }
                default:
                {
                    BOOST_LOG_TRIVIAL(trace) << "Unexpected wait result";
                    break;
                }
            }
        } while (!stop_requested && PrepareNextIteration(key, NotifyEvent));

        SERVICE_STATUS stopped = { ServiceType, SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0 };
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
        if (!StartServiceCtrlDispatcher(ServiceTable)) {
            std::error_code ec(GetLastError(), std::system_category());
            throw std::system_error(ec, "Error starting service dispatcher");
        }
        BOOST_LOG_TRIVIAL(trace) << "Exiting";
        return EXIT_SUCCESS;
    } catch (std::system_error const& ex) {
        BOOST_LOG_TRIVIAL(error) << "Error (" << ex.code() << ") " << ex.what();
        return EXIT_FAILURE;
    }
}