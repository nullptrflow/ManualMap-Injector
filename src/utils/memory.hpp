#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

#include "../sdk/ntdefines.h"
#include "../sdk/ntstruct.h"

namespace MEMORY
{
	inline BOOL read(HANDLE proc_handle, const std::uintptr_t& address, void* buffer, size_t size)
	{
		return ReadProcessMemory(proc_handle, reinterpret_cast<const void*>(address), buffer, size, NULL);
	}

	inline BOOL write(HANDLE proc_handle, const std::uintptr_t& address, const void* value, size_t size)
	{
		return WriteProcessMemory(proc_handle, reinterpret_cast<void*>(address), value, size, NULL);
	}

	inline uintptr_t get_mod_base_ex(HANDLE proc_handle, const wchar_t* mod_name) {
		NtQueryInformationProcess_t NtQueryInformationProcess =
			reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

		PROCESS_BASIC_INFORMATION pbi{};
		ULONG retLen = 0;
		NTSTATUS st = NtQueryInformationProcess(proc_handle, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
		if (st != 0) return 0;

		PEB peb{};
		if (!read(proc_handle, reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress), &peb, sizeof(peb))) return 0;

		PEB_LDR_DATA ldr{};
		if (!read(proc_handle, reinterpret_cast<std::uintptr_t>(peb.Ldr), &ldr, sizeof(ldr))) return 0;

		LIST_ENTRY list = ldr.InLoadOrderModuleList;
		uintptr_t head = reinterpret_cast<uintptr_t>(peb.Ldr) + offsetof(PEB_LDR_DATA, InLoadOrderModuleList);
		uintptr_t curr = reinterpret_cast<uintptr_t>(list.Flink);

		while (curr && curr != head) {
			LDR_DATA_TABLE_ENTRY entry{};
			if (!read(proc_handle, curr, &entry, sizeof(entry))) break;

			wchar_t name_buf[MAX_PATH]{};
			if (entry.BaseDllName.Length && entry.BaseDllName.Buffer) {
				size_t len = entry.BaseDllName.Length / sizeof(wchar_t);
				if (len >= MAX_PATH) len = MAX_PATH - 1;
				read(proc_handle, reinterpret_cast<std::uintptr_t>(entry.BaseDllName.Buffer), name_buf, len * sizeof(wchar_t));
				name_buf[len] = 0;
			}

			if (_wcsicmp(name_buf, mod_name) == 0)
				return reinterpret_cast<uintptr_t>(entry.DllBase);

			curr = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
		}
		return 0;
	}

	inline uintptr_t get_proc_addr_ex(HANDLE proc_handle, const wchar_t* mod_name, const char* proc_name) {
		uintptr_t base = get_mod_base_ex(proc_handle, mod_name);
		if (!base) return 0;

		IMAGE_DOS_HEADER dos{};
		if (!read(proc_handle, base, &dos, sizeof(dos))) return 0;
		if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

		IMAGE_NT_HEADERS64 nt{};
		if (!read(proc_handle, base + dos.e_lfanew, &nt, sizeof(nt))) return 0;
		if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

		auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!dir.VirtualAddress) return 0;

		IMAGE_EXPORT_DIRECTORY exp{};
		if (!read(proc_handle, base + dir.VirtualAddress, &exp, sizeof(exp))) return 0;

		std::vector<DWORD> names(exp.NumberOfNames);
		std::vector<WORD> ords(exp.NumberOfNames);
		std::vector<DWORD> funcs(exp.NumberOfFunctions);

		if (!read(proc_handle, base + exp.AddressOfNames, names.data(), names.size() * sizeof(DWORD))) return 0;
		if (!read(proc_handle, base + exp.AddressOfNameOrdinals, ords.data(), ords.size() * sizeof(WORD))) return 0;
		if (!read(proc_handle, base + exp.AddressOfFunctions, funcs.data(), funcs.size() * sizeof(DWORD))) return 0;

		for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
			char name[256]{};
			if (!read(proc_handle, base + names[i], name, sizeof(name) - 1)) continue;
			if (strcmp(name, proc_name) != 0) continue;
			return base + funcs[ords[i]];
		}
		return 0;
	}

	inline unsigned char* pattern_scan(HINSTANCE mod, std::vector<std::uint8_t> pattern, uint64_t bitmask, std::int32_t offset)
	{
		if (!mod) return nullptr;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
		auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
		auto module_size = nt->OptionalHeader.SizeOfImage;
		auto base = reinterpret_cast<uint8_t*>(mod);
		size_t pattern_len = pattern.size();

		for (size_t i = 0; i <= module_size - pattern_len; ++i) {
			bool found = true;
			for (size_t j = 0; j < pattern_len; ++j) {
				if (!(bitmask & (1ULL << j))) continue;
				if (base[i + j] != pattern[j]) { found = false; break; }
			}
			if (found) return base + i + offset;
		}
		return nullptr;
	}
}
