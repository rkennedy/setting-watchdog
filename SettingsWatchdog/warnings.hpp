#pragma once

/*
 * Microsoft Code Analysis flags lots of things in external library headers,
 * especially Boost headers. Although we can use /external:anglebrackets and
 * related compiler switches to disable warnings in external headers, it
 * doesn't work for Code Analysis warnings because they're not tied into the
 * warning-level system, so there's no "level" of warnings we can disable that
 * makes them go away for external headers.
 *
 * Therefore, we use pragmas to disable the analysis warnings when we include
 * the external headers. However, if we use pragmas directly in the code that
 * includes the headers, then Clang-format's header-sorting mechanism gets
 * stuck. It assumes the first pragma is the end of the includes, and so it
 * doesn't sort anything afterward. We use a lot of external headers in this
 * project.
 *
 * A workaround is to use /FI to get _this_ header included automatically at
 * the start of every translation unit, and then use the macro below to disable
 * and re-enable code analysis. Clang-format seems better able to cope with the
 * macros appearing among the includes.
 */
#include <codeanalysis/warnings.h>

#define DISABLE_ANALYSIS _Pragma("warning(push)") _Pragma("warning(disable: ALL_CODE_ANALYSIS_WARNINGS)")
#define REENABLE_ANALYSIS _Pragma("warning(pop)")
