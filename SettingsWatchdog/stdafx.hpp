// stdafx.hpp: include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.hpp"

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
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/format.hpp>
#include <boost/log/attributes/constant.hpp>
#include <boost/log/attributes/function.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/phoenix.hpp>
#include <boost/program_options.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>
#pragma warning(pop)
