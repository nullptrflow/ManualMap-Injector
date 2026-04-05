#include "ManualMap.h"
#include <iostream>

#define RF32(i) ((i >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RF64(i) ((i >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RF RF64
#else
#define RF RF32
#endif

#pragma optimize("", off)
void __stdcall ManualMap::Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) return;

	BYTE* b = pData->pBase;
	auto* opt = &reinterpret_cast<IMAGE_NT_HEADERS*>(b + reinterpret_cast<IMAGE_DOS_HEADER*>(b)->e_lfanew)->OptionalHeader;

	if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(b + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (imp->Name) {
			char* name = reinterpret_cast<char*>(b + imp->Name);
			HINSTANCE dll = pData->pLoadLibraryA(name);

			ULONG_PTR* ref = reinterpret_cast<ULONG_PTR*>(b + imp->OriginalFirstThunk);
			ULONG_PTR* func = reinterpret_cast<ULONG_PTR*>(b + imp->FirstThunk);

			if (!ref) ref = func;

			for (; *ref; ++ref, ++func) {
				if (IMAGE_SNAP_BY_ORDINAL(*ref)) {
					*func = reinterpret_cast<ULONG_PTR>(pData->pGetProcAddress(dll, reinterpret_cast<char*>(*ref & 0xFFFF)));
				} else {
					auto* i = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(b + (*ref));
					*func = reinterpret_cast<ULONG_PTR>(pData->pGetProcAddress(dll, i->Name));
				}
			}
			++imp;
		}
	}

	if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(b + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* cb = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
		if (cb) {
			for (; *cb; ++cb) {
				(*cb)(b, DLL_PROCESS_ATTACH, nullptr);
			}
		}
	}

	if (opt->AddressOfEntryPoint) {
		auto entry = reinterpret_cast<f_DLL_ENTRY_POINT>(b + opt->AddressOfEntryPoint);
		entry(reinterpret_cast<HINSTANCE>(b), DLL_PROCESS_ATTACH, nullptr);
	}
}
DWORD ShellcodeEndMarker() { return 0xDEADBEEF; }
#pragma optimize("", on)

bool ManualMap::MapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize) {
	if (!hProc || !pSrcData || !FileSize) return false;

	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	BYTE* target = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!target) return false;

	BYTE* local = new BYTE[nt->OptionalHeader.SizeOfImage];
	memset(local, 0, nt->OptionalHeader.SizeOfImage);
	memcpy(local, pSrcData, nt->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		if (sec[i].SizeOfRawData) {
			memcpy(local + sec[i].VirtualAddress, pSrcData + sec[i].PointerToRawData, sec[i].SizeOfRawData);
		}
	}

	IMAGE_NT_HEADERS* lnt = reinterpret_cast<IMAGE_NT_HEADERS*>(local + dos->e_lfanew);
	DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(target) - lnt->OptionalHeader.ImageBase;

	if (delta != 0) {
		if (lnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* r = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local + lnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (r->VirtualAddress) {
				UINT count = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* info = reinterpret_cast<WORD*>(r + 1);
				for (UINT i = 0; i != count; ++i, ++info) {
					if (RF(*info)) {
						ULONG_PTR* p = reinterpret_cast<ULONG_PTR*>(local + r->VirtualAddress + ((*info) & 0xFFF));
						*p += delta;
					}
				}
				r = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(r) + r->SizeOfBlock);
			}
		}
	}

	lnt->OptionalHeader.ImageBase = reinterpret_cast<ULONG_PTR>(target);
	WriteProcessMemory(hProc, target, local, nt->OptionalHeader.SizeOfImage, nullptr);
	delete[] local;

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
	data.pBase = target;

	SIZE_T scSize = reinterpret_cast<SIZE_T>(ShellcodeEndMarker) - reinterpret_cast<SIZE_T>(ManualMap::Shellcode);
	if (scSize <= 0 || scSize > 0x1000) scSize = 0x1000;

	BYTE* scArea = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(data) + scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	WriteProcessMemory(hProc, scArea, &data, sizeof(data), nullptr);
	WriteProcessMemory(hProc, scArea + sizeof(data), ManualMap::Shellcode, scSize, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(scArea + sizeof(data)), scArea, 0, nullptr);
	if (!hThread) return false;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProc, scArea, 0, MEM_RELEASE);

	return true;
}