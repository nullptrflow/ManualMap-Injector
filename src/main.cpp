#include <iostream>
#include <fstream>
#include "ManualMap.h"

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cout << "Loader.exe <pid> <dll>" << std::endl;
		return 1;
	}

	DWORD pid = std::stoul(argv[1]);
	const char* path = argv[2];

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open()) return 1;

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<BYTE> buf(size);
	if (!file.read(reinterpret_cast<char*>(buf.data()), size)) return 1;

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) return 1;

	if (ManualMap::MapDll(h, buf.data(), size)) {
		std::cout << "done" << std::endl;
	} else {
		std::cout << "failed" << std::endl;
	}

	CloseHandle(h);
	return 0;
}