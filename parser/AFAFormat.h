#pragma once

#include <string>
#include <vector>
#include <cstdint>

enum class AFAFormat {
	AFAH_STANDARD,
	ALICEARCH_EXTENDED,
	UNKNOWN
};

struct AFAEntry {
	std::string fileName;	// ashdevilinanutshell.ogg
	uint64_t offset;		// internal offset in archive
	uint64_t size;			// size of the file, in bytes?
};

struct AFAArchive {
	std::string archPath;
	AFAFormat format;
	std::vector<AFAEntry> entries;
};