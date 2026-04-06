#include <iostream>
#include <fstream>
#include "ManualMap.h"
#include "sdk/Logger.h"
#include "utils/Process.h"
#include "cleaners/Registry.h"
#include "cleaners/Explorer.h"

int main(int argc, char* argv[]) {
	Process::adjustPrivileges();

	DWORD pid = 0;
	const char* dllPath = nullptr;

	if (argc >= 3) {
		pid = std::stoul(argv[1]);
		dllPath = argv[2];
	} else if (argc == 2) {
		dllPath = argv[1];
		
		std::string processName;
		Logger::log(Logger::Type::Input, "Enter target process name (e.g., game.exe): ");
		std::cin >> processName;
		
		pid = Process::findProcessByName(processName);
		if (pid == 0) {
			Logger::log(Logger::Type::Error, "Process '%s' not found!\n", processName.c_str());
			return 1;
		}
		Logger::log(Logger::Type::Info, "Found process '%s' with PID: %lu\n", processName.c_str(), pid);
	} else {
		Logger::log(Logger::Type::Warning, "Usage:\n");
		Logger::log(Logger::Type::Info, "  Loader.exe <pid> <dll>\n");
		Logger::log(Logger::Type::Info, "  Loader.exe <dll>  (will prompt for process name)\n");
		return 1;
	}

	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		Logger::log(Logger::Type::Error, "Failed to open DLL: %s\n", dllPath);
		return 1;
	}

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<BYTE> buf(size);
	if (!file.read(reinterpret_cast<char*>(buf.data()), size)) {
		Logger::log(Logger::Type::Error, "Failed to read DLL file\n");
		return 1;
	}

	Logger::log(Logger::Type::Info, "DLL size: %lld bytes\n", size);

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) {
		Logger::log(Logger::Type::Error, "Failed to open process (PID: %lu). Error: %lu\n", pid, GetLastError());
		return 1;
	}

	Logger::log(Logger::Type::Info, "Injecting into PID: %lu...\n", pid);

	if (ManualMap::MapDll(h, buf.data(), size)) {
		Logger::log(Logger::Type::Info, "Injection successful!\n");
		
		std::wstring processName = Process::getCurrentProcessName();
		Logger::log(Logger::Type::Info, "Cleaning execution traces...\n");
		
		Explorer::deleteFileFromPrefetch(processName);
		Explorer::deleteFileFromRecent(processName);
		Registry::deleteValueFromRecentDocs(processName);
		Registry::deleteValueFromUserAssist(processName);
		Registry::deleteValueFromBAM(processName);
		Registry::deleteValueFromShallBags(processName);
		
		Logger::log(Logger::Type::Info, "Trace cleanup complete\n");
	} else {
		Logger::log(Logger::Type::Error, "Injection failed!\n");
	}

	CloseHandle(h);
	return 0;
}
