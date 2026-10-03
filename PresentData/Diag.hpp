// Copyright (C) 2026 CapFrameX
// SPDX-License-Identifier: MIT
//
// Optional diagnostic log for analyzing memory and CPU growth.  Disabled unless the environment
// variable PRESENTMON_DIAG_LOG is set: "1" writes to %TEMP%\PresentMonDiag_<pid>.log, any other
// value is used as the log file path.  Every 10 seconds the consumer and output threads append a
// summary of their event rates, CPU time and the size of every internal tracking structure.
#pragma once

#include <windows.h>
#include <psapi.h>
#include <share.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <atomic>
#include <mutex>

namespace pmdiag {

inline std::atomic<int64_t> gLivePresentEvents{ 0 };
inline std::atomic<int64_t> gTotalPresentEvents{ 0 };

// Stop writing once the log reaches this size, in case diagnostics are left enabled.
constexpr long MAX_LOG_BYTES = 64l * 1024l * 1024l;

inline std::mutex& LogMutex()
{
    static std::mutex m;
    return m;
}

inline FILE* LogFile()
{
    static FILE* fp = []() -> FILE* {
        wchar_t value[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableW(L"PRESENTMON_DIAG_LOG", value, MAX_PATH);
        if (n == 0 || n >= MAX_PATH || value[0] == L'0') {
            return nullptr;
        }

        wchar_t path[MAX_PATH] = {};
        if (wcscmp(value, L"1") == 0) {
            wchar_t temp[MAX_PATH] = {};
            DWORD t = GetTempPathW(MAX_PATH, temp);
            if (t == 0 || t >= MAX_PATH) {
                return nullptr;
            }
            swprintf_s(path, L"%sPresentMonDiag_%lu.log", temp, GetCurrentProcessId());
        } else {
            wcscpy_s(path, value);
        }

        // Shared so the log can be read while PresentMon is running.
        return _wfsopen(path, L"a", _SH_DENYNO);
    }();
    return fp;
}

inline bool Enabled()
{
    static bool const enabled = LogFile() != nullptr;
    return enabled;
}

inline void Printf(char const* fmt, ...)
{
    FILE* fp = LogFile();
    if (fp == nullptr || ftell(fp) > MAX_LOG_BYTES) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
}

inline void Flush()
{
    FILE* fp = LogFile();
    if (fp != nullptr) {
        fflush(fp);
    }
}

inline uint64_t Qpc()
{
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    return (uint64_t) q.QuadPart;
}

inline double QpcToMs(uint64_t delta)
{
    static double const msPerTick = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return 1000.0 / (double) f.QuadPart;
    }();
    return msPerTick * (double) delta;
}

inline size_t ProcessPrivateBytes()
{
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    pmc.cb = sizeof(pmc);
    using Fn = BOOL (WINAPI*)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
    static Fn fn = []() -> Fn {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        return k32 ? reinterpret_cast<Fn>(GetProcAddress(k32, "K32GetProcessMemoryInfo")) : nullptr;
    }();
    if (fn == nullptr || !fn(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc), sizeof(pmc))) {
        return 0;
    }
    return pmc.PrivateUsage;
}

}
