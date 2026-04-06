#include "Process.h"
#include <filesystem>

DWORD Process::findProcessByName(const std::string& processName) {
    DWORD processes[1024], cbNeeded, processCount;
    EnumProcesses(processes, sizeof(processes), &cbNeeded);
    processCount = cbNeeded / sizeof(DWORD);

    for (unsigned int i = 0; i < processCount; ++i) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            char processPath[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath))) {
                std::string name = processPath;
                size_t pos = name.find_last_of("\\/");
                if (pos != std::string::npos) name = name.substr(pos + 1);
                if (name == processName) { CloseHandle(hProcess); return processes[i]; }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}

std::wstring Process::getCurrentProcessLastFolder() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(NULL, buffer, MAX_PATH)) {
        std::string full(buffer);
        size_t pos = full.find_last_of("\\/");
        std::string dir = full.substr(0, pos);
        pos = dir.find_last_of("\\/");
        return std::filesystem::path(dir.substr(pos + 1)).wstring();
    }
    return L"null";
}

std::wstring Process::getCurrentProcessName() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(NULL, buffer, MAX_PATH)) {
        std::string full(buffer);
        size_t pos = full.find_last_of("\\/");
        std::string name = full.substr(pos + 1);
        size_t dot = name.find_last_of(".");
        return std::filesystem::path(name.substr(0, dot)).wstring();
    }
    return L"null";
}

void Process::adjustPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
}
