#include "Registry.h"
#include <vector>
#include <aclapi.h>
#include <functional>
#include <unordered_set>
#include <shlwapi.h>
#include <shlobj.h>
#include "../sdk/Logger.h"

static const std::wstring recentDocsPath  = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.dll";
static const std::wstring shallBagsPath   = L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
static const std::wstring shallBagsPath2  = L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
static const std::wstring userAssistPath  = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
static const std::wstring bamPath         = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

static std::wstring decodeUTF16LE(const uint8_t* data, DWORD dataSize) {
    std::wstring result;
    for (DWORD i = 0; i + 1 < dataSize; i += 2) {
        wchar_t ch = static_cast<wchar_t>(data[i] | (data[i + 1] << 8));
        if (ch == L'\0') break;
        result += ch;
    }
    return result;
}

static std::wstring binaryToWString(const BYTE* data, DWORD dataSize) {
    std::wstring result;
    for (DWORD i = 0; i < dataSize; ++i) {
        BYTE b = data[i];
        if (b >= 32 && b <= 126) result += static_cast<wchar_t>(b);
    }
    return result;
}

static std::wstring decodeROT13(const wchar_t* data, DWORD dataSize) {
    std::wstring result;
    for (DWORD i = 0; i < dataSize; i++) {
        wchar_t ch = data[i];
        if (iswalpha(ch)) {
            wchar_t base = iswupper(ch) ? L'A' : L'a';
            ch = (ch - base + 13) % 26 + base;
            result += ch;
        } else if (iswprint(ch)) result += ch;
        else result += L'?';
    }
    return result;
}

static std::vector<std::wstring> getSubKeysOfKey(HKEY key, std::wstring keyPath) {
    std::vector<std::wstring> subKeys{ L"" };
    HKEY hKey;
    if (RegOpenKeyEx(key, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR keyName[255];
        DWORD keyNameSize;
        while (true) {
            keyNameSize = 255;
            LONG res = RegEnumKeyEx(hKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL);
            if (res == ERROR_NO_MORE_ITEMS) break;
            if (res == ERROR_SUCCESS && !keyPath.empty())
                subKeys.push_back(keyPath + L"\\" + keyName);
            index++;
        }
        RegCloseKey(hKey);
    }
    return subKeys;
}

static std::wstring getCurrentUserName() {
    DWORD sz = 256; wchar_t u[256];
    return GetUserNameW(u, &sz) ? std::wstring(u) : L"";
}

static int grantAccessToKey(HKEY key) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    LONG lRes = GetSecurityInfo(key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
    if (lRes != ERROR_SUCCESS) { RegCloseKey(key); return lRes; }
    std::wstring userName = getCurrentUserName();
    memset(&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = const_cast<wchar_t*>(userName.c_str());
    lRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (lRes != ERROR_SUCCESS) { if (pSD) LocalFree((HLOCAL)pSD); RegCloseKey(key); return lRes; }
    lRes = SetSecurityInfo(key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
    if (pSD) LocalFree((HLOCAL)pSD);
    if (pNewDACL) LocalFree((HLOCAL)pNewDACL);
    RegCloseKey(key);
    return lRes;
}

bool Registry::deleteValueFromRecentDocs(const std::wstring& processName) {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, recentDocsPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;
    DWORD index = 0; WCHAR valName[255]; DWORD valNameSize; DWORD valType; BYTE data[1024]; DWORD dataSize;
    while (true) {
        valNameSize = 255; dataSize = sizeof(data);
        LONG res = RegEnumValue(hKey, index, valName, &valNameSize, NULL, &valType, data, &dataSize);
        if (res == ERROR_NO_MORE_ITEMS) break;
        if (res == ERROR_SUCCESS && valType == REG_BINARY && dataSize % 2 == 0) {
            std::wstring decoded = decodeUTF16LE(reinterpret_cast<uint8_t*>(data), dataSize);
            if (decoded.find(processName) != std::wstring::npos) {
                if (RegDeleteValue(hKey, valName) == ERROR_SUCCESS) {
                    Logger::log(Logger::Type::Info, "Removed %ls from RecentDocs\n", processName.c_str());
                    RegCloseKey(hKey); return true;
                }
            }
        }
        index++;
    }
    RegCloseKey(hKey); return false;
}

bool Registry::deleteValueFromUserAssist(const std::wstring& processName) {
    bool found = false;
    for (auto& key : getSubKeysOfKey(HKEY_CURRENT_USER, userAssistPath)) {
        std::wstring countKey = key + L"\\Count";
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, countKey.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) continue;
        DWORD idx = 0; WCHAR valName[255]; DWORD valNameSize; DWORD valType; BYTE data[1024]; DWORD dataSize;
        while (true) {
            valNameSize = 255; dataSize = sizeof(data);
            LONG res = RegEnumValue(hKey, idx, valName, &valNameSize, NULL, &valType, data, &dataSize);
            if (res == ERROR_NO_MORE_ITEMS) break;
            if (res == ERROR_SUCCESS && valType == REG_BINARY) {
                std::wstring decoded = decodeROT13(valName, valNameSize);
                if (decoded.find(processName) != std::wstring::npos) {
                    if (RegDeleteValue(hKey, valName) == ERROR_SUCCESS)
                        Logger::log(Logger::Type::Info, "Removed %ls from UserAssist\n", processName.c_str());
                    found = true;
                }
            }
            idx++;
        }
        RegCloseKey(hKey);
    }
    return found;
}

bool Registry::deleteValueFromBAM(const std::wstring& processName) {
    bool found = false;
    for (auto& key : getSubKeysOfKey(HKEY_LOCAL_MACHINE, bamPath)) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            grantAccessToKey(hKey);
            RegOpenKeyEx(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hKey);
            DWORD idx = 0; WCHAR valName[255]; DWORD valNameSize; DWORD valType; BYTE data[1024]; DWORD dataSize;
            while (true) {
                valNameSize = 255; dataSize = sizeof(data);
                LONG res = RegEnumValue(hKey, idx, valName, &valNameSize, NULL, &valType, data, &dataSize);
                if (res == ERROR_NO_MORE_ITEMS) break;
                if (res == ERROR_SUCCESS && valType == REG_BINARY) {
                    std::wstring wstr(valName);
                    if (wstr.find(processName) != std::wstring::npos) {
                        if (RegDeleteValue(hKey, valName) == ERROR_SUCCESS)
                            Logger::log(Logger::Type::Info, "Removed %ls from BAM\n", wstr.c_str());
                        found = true;
                    }
                }
                idx++;
            }
            RegCloseKey(hKey);
        }
    }
    return found;
}

bool Registry::deleteValueFromShallBags(const std::wstring& processName) {
    bool found = false;
    std::unordered_set<std::wstring> processed;
    std::function<void(HKEY, const std::wstring&)> processKey = [&](HKEY rootKey, const std::wstring& keyPath) {
        if (processed.count(keyPath)) return;
        processed.insert(keyPath);
        auto subKeys = getSubKeysOfKey(rootKey, keyPath);
        subKeys.push_back(keyPath);
        for (const auto& k : subKeys) {
            HKEY hKey;
            if (RegOpenKeyEx(rootKey, k.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                DWORD idx = 0; WCHAR valName[255]; DWORD valNameSize; DWORD valType; BYTE data[1024]; DWORD dataSize;
                while (true) {
                    valNameSize = 255; dataSize = sizeof(data);
                    LONG res = RegEnumValue(hKey, idx, valName, &valNameSize, NULL, &valType, data, &dataSize);
                    if (res == ERROR_NO_MORE_ITEMS) break;
                    if (res == ERROR_SUCCESS && valType == REG_BINARY) {
                        std::wstring str = binaryToWString(data, dataSize);
                        if (str.find(processName) != std::wstring::npos) {
                            if (RegDeleteValue(hKey, valName) == ERROR_SUCCESS)
                                Logger::log(Logger::Type::Info, "Removed %ls from ShellBags\n", str.c_str());
                            found = true;
                        }
                    }
                    idx++;
                }
                RegCloseKey(hKey);
            }
            processKey(rootKey, k);
        }
    };
    processKey(HKEY_CURRENT_USER, shallBagsPath);
    processKey(HKEY_CLASSES_ROOT, shallBagsPath2);
    return found;
}
