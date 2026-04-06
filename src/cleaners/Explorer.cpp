#include "Explorer.h"
#include <algorithm>
#include <filesystem>

static const std::wstring prefetchPath = L"C:\\Windows\\Prefetch";

bool Explorer::deleteFileFromPrefetch(const std::wstring& fileName) {
    if (!std::filesystem::exists(prefetchPath)) return false;
    for (const auto& entry : std::filesystem::directory_iterator(prefetchPath)) {
        if (!entry.is_regular_file() || entry.path().extension() != L".pf") continue;
        std::wstring cur = entry.path().filename().wstring();
        std::wstring upper = fileName;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        if (cur.find(upper) != std::wstring::npos) {
            std::filesystem::remove(entry.path());
            Logger::log(Logger::Type::Info, "Removed %ls from Prefetch\n", cur.c_str());
            return true;
        }
    }
    return false;
}

bool Explorer::deleteFileFromRecent(const std::wstring& fileName) {
    PWSTR path = NULL;
    std::wstring recentPath;
    if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &path) == S_OK) {
        recentPath = path;
        CoTaskMemFree(path);
    }
    recentPath += L"\\Microsoft\\Windows\\Recent";
    if (!std::filesystem::exists(recentPath)) return false;
    for (const auto& entry : std::filesystem::directory_iterator(recentPath)) {
        if (!entry.is_regular_file()) continue;
        std::wstring cur = entry.path().filename().wstring();
        std::wstring curUp = cur, fileUp = fileName;
        std::transform(curUp.begin(), curUp.end(), curUp.begin(), ::toupper);
        std::transform(fileUp.begin(), fileUp.end(), fileUp.begin(), ::toupper);
        if (curUp.find(fileUp) != std::wstring::npos) {
            std::filesystem::remove(entry.path());
            Logger::log(Logger::Type::Info, "Removed %ls from Recent\n", cur.c_str());
            return true;
        }
    }
    return false;
}
