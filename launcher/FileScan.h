#pragma once

#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

class FileScan {

public:
	// Finds all .afa files in directory (recursive)
	static std::vector<fs::path> findAFAFiles(const fs::path& directory);

	// Helper: Print results
	static void printFiles(const std::vector<fs::path>& files);
};