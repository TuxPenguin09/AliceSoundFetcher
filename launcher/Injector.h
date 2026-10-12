#pragma once

#include <filesystem>

namespace fs = std::filesystem;

class Injector {
public:
	static bool LaunchAndInject(const fs::path& exePath, const fs::path& dllPath);
};