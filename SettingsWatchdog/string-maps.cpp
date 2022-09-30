#include "string-maps.hpp"

#define VALUE_NAME(x) \
    {                 \
        x, #x         \
    }

std::map<DWORD, std::string> const control_names {
    // clang-format off
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
    // VALUE_NAME(SERVICE_CONTROL_USERMODEREBOOT),
    // clang-format on
};

std::map<DWORD, std::string> const session_change_codes {
    // clang-format off
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
    // clang-format on
};

std::map<DWORD, std::string> const wait_results {
    // clang-format off
    VALUE_NAME(WAIT_OBJECT_0),
    VALUE_NAME(WAIT_OBJECT_0 + 1),
    VALUE_NAME(WAIT_OBJECT_0 + 2),
    VALUE_NAME(WAIT_TIMEOUT),
    VALUE_NAME(WAIT_FAILED),
    // clang-format on
};

std::map<DWORD, std::string> const registry_types {
    // clang-format off
    VALUE_NAME(REG_BINARY),
    VALUE_NAME(REG_DWORD),
    VALUE_NAME(REG_DWORD_LITTLE_ENDIAN),
    VALUE_NAME(REG_DWORD_BIG_ENDIAN),
    VALUE_NAME(REG_EXPAND_SZ),
    VALUE_NAME(REG_LINK),
    VALUE_NAME(REG_MULTI_SZ),
    VALUE_NAME(REG_NONE),
    VALUE_NAME(REG_QWORD),
    VALUE_NAME(REG_QWORD_LITTLE_ENDIAN),
    VALUE_NAME(REG_SZ),
    // clang-format on
};

std::map<plog::Severity, std::string> const severity_names {
    // clang-format off
    { plog::trace, "trace" },
    { plog::debug, "debug" },
    { plog::info, "info" },
    { plog::warning, "warning" },
    { plog::error, "error" },
    { plog::fatal, "fatal" },
    // clang-format on
};
