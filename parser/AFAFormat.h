#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct AFAEntry {
	std::string name;		// audio.afa
	std::string fileName;	// ashdevilinanutshell.ogg
	uint64_t offset;		// internal offset in archive
	uint64_t size;			// size of the file, in bytes?
};

struct AFAArchive {
	std::string archPath;
	std::vector<AFAEntry> entries;
};