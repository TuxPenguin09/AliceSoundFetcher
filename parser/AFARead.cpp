#include "AFARead.h"
#include <fstream>
#include <iostream>

AFAArchive AFARead::parse(const fs::path& afaPath) {
	AFAArchive archive;
	archive.archPath = afaPath.string();

	std::ifstream file(afaPath, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "AFA Read Error: Open failed " << afaPath.string() << std::endl;
		return archive;
	}

	// Reading the first 16 bytes for sign inspection
	char header[16] = {};
	file.read(header, sizeof(header));

	std::cout << "AFA Read: Parsing " << afaPath.filename().string() << std::endl;
	std::cout << "AFA Read: Header bytes: ";
	for (int i = 0; i < 16; i++) {
		printf("%02X ", static_cast<unsigned char>(header[i]));
	}
	std::cout << std::endl;

	// Fetch file size
	file.seekg(0, std::ios::end);
	uint64_t fileSize = file.tellg();
	std::cout << "AFA Read: File size: " << fileSize << " bytes" << std::endl;

	// [DEV] Will become the real manifest extraction.
	AFAEntry fake;
	fake.name = afaPath.filename().string();
	fake.fileName = "__INDEX_PENDING__";
	fake.offset = 0;
	fake.size = fileSize;
	archive.entries.push_back(fake);

	return archive;
}
