#pragma once
#include <Windows.h>
#include <shlobj.h>
#include <string>
#include "../sdk/Logger.h"

class Explorer {
public:
	static bool deleteFileFromPrefetch(const std::wstring& fileName);
	static bool deleteFileFromRecent(const std::wstring& fileName);
};
