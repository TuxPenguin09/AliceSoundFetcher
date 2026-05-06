#include <iostream>
#include <string>
#include <filesystem>

#include "FileScan.h"
#include "../parser/AFARead.h"

namespace fs = std::filesystem;

void printBanner() {
	std::cout << "Alice Sound Fetcher" << std::endl;
}

bool isEXEFile(const fs::path& filePath) {
	return filePath.has_extension() && filePath.extension() == ".exe";
}

int main(int argc, char* argv[]) {
	printBanner();

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <path_to_exe> " << "or drag an AliceSoft System game onto this program." << std::endl;
		std::cerr << "Error: No executable file provided." << std::endl;
		return 1;
	}

	fs::path gamePath = argv[1];

	if (!fs::exists(gamePath)) {
		std::cerr << "Error: The specified file does not exist." << std::endl;
		return 1;
	}

	if (!isEXEFile(gamePath)) {
		std::cerr << "Error: The specified file is not an executable (.exe)." << std::endl;
		return 1;
	}

	std::cout << "Game selected: " << gamePath.string() << std::endl;
	fs::path gameDir = gamePath.parent_path();

	std::cout << "Game directory: " << gameDir.string() << std::endl;

	std::cout << "afa: Scanning for .afa..." << std::endl;
	auto afaFiles = FileScan::findAFAFiles(gameDir);
	FileScan::printFiles(afaFiles);
	std::cout << "afa: Found " << afaFiles.size() << "\n" << std::endl;

	std::cout << "afa: Indexing AFA archives..." << std::endl;
	for (const auto& afaFile : afaFiles) {
		AFAArchive archive = AFARead::parse(afaFile);

		std::cout << "afa: Indexed " << archive.entries.size() << " entries from " << afaFile.filename().string() << "\n" << std::endl;
	}

	return 0;
}