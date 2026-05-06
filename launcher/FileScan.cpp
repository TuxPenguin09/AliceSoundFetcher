#include "FileScan.h"
#include <iostream>

std::vector<fs::path> FileScan::findAFAFiles(const fs::path& dir) {
	std::vector<fs::path> res;

	if (!fs::exists(dir)) {
		return res;
	}

	try {
		for (const auto& entry : fs::recursive_directory_iterator(dir)) {
			if (!entry.is_regular_file()) {
				continue;
			}

			const fs::path& path = entry.path();

			// Case-insensitive check for .afa
			if (path.has_extension()) {
				std::string ext = path.extension().string();

				for (auto& c : ext) {
					c = std::tolower(c);
				}
				if (ext == ".afa") {
					res.push_back(path);
				}
			}
		}
	}
	catch (const std::exception ex) {
		std::cerr << "FileScan Error: " << ex.what() << std::endl;
	}

	return res;
}

void FileScan::printFiles(const std::vector<fs::path>& files) {
	std::cout << "\nFound .afa files:" << std::endl;

	if (files.empty()) {
		std::cout << "[none]" << std::endl;
		return;
	}

	for (const auto& file : files) {
		std::cout << "- " << file.string() << std::endl;
	}

	std::cout << std::endl;
}