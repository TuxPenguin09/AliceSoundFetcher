#include "AFARead.h"
#include <fstream>
#include <iostream>

AFAFormat AFARead::detectFormat(const char* header) {
	// AFAH
	if (header[0] == 'A' && header[1] == 'F' && header[2] == 'A' && header[3] == 'H') {
		return AFAFormat::AFAH_STANDARD;
	}

	// AliceArch
	if (std::memcmp(header + 8, "AlicArch", 8) == 0) {
		return AFAFormat::ALICEARCH_EXTENDED;
	}

	return AFAFormat::UNKNOWN;
}

AFAArchive AFARead::parse(const fs::path& afaPath) {
	AFAArchive archive;
	archive.archPath = afaPath.string();

	std::ifstream file(afaPath, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "AFA Read Error: Open failed " << afaPath.string() << std::endl;
		return archive;
	}

	// Reading the first 16 bytes for sign inspection
	char header[32] = {};
	file.read(header, sizeof(header));

	std::cout << "AFA Read: Parsing " << afaPath.filename().string() << std::endl;
	std::cout << "AFA Read: Header bytes: ";
	for (int i = 0; i < 16; i++) {
		printf("%02X ", static_cast<unsigned char>(header[i]));
	}
	std::cout << std::endl;

	switch (archive.format) {
		case AFAFormat::AFAH_STANDARD:
			std::cout << "AFA Read: AFAH Standard" << std::endl;
			break;
		case AFAFormat::ALICEARCH_EXTENDED:
			std::cout << "AFA Read: AlicArch Extended" << std::endl;
			break;
		case AFAFormat::UNKNOWN:
			std::cout << "AFA Read: Unknown format" << std::endl;
			break;
	}

	// Fetch file size
	/*
	file.seekg(0, std::ios::end);
	uint64_t fileSize = file.tellg();
	std::cout << "AFA Read: File size: " << fileSize << " bytes" << std::endl;
	*/

	// [DEV] Will become the real manifest extraction.
	AFAEntry tmp;
	//fake.name = afaPath.filename().string();
	tmp.fileName = "__INDEX_PENDING__";
	tmp.offset = 0;
	tmp.size = 0;
	archive.entries.push_back(tmp);

	return archive;
}
