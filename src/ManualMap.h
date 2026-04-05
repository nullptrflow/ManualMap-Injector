#pragma once
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>

typedef HMODULE(WINAPI* f_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(HINSTANCE, DWORD, LPVOID);

// Internal structures for passing context to the remote shellcode
struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	BYTE* pBase;
	HINSTANCE hMod;
};

class ManualMap {
public:
	// Static entry point for the loader
	static bool MapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize);

private:
	// Internal mapping logic
	static void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
	
	// Helper functions to find addresses in the target process (Stealth)
	static ULONG_PTR GetModuleBaseExternal(HANDLE hProcess, const wchar_t* modName);
	static ULONG_PTR GetProcAddressExternal(HANDLE hProcess, ULONG_PTR hModule, const char* procName);
};
