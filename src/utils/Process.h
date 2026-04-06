#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <string>

class Process {
public:
    static DWORD findProcessByName(const std::string& processName);
    static std::wstring getCurrentProcessLastFolder();
    static std::wstring getCurrentProcessName();
    static void adjustPrivileges();
};
