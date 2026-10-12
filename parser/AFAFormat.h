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
	std::string fileName;	// member name, e.g. "10001.ogg" (SJIS for some archives)
	uint64_t offset;		// ABSOLUTE byte offset of the payload in the .afa file
	uint64_t size;			// payload size in bytes

	// End of payload, convenience for range checks.
	uint64_t end() const { return offset + size; }
};

struct AFAArchive {
	std::string archPath;
	AFAFormat format = AFAFormat::UNKNOWN;
	std::vector<AFAEntry> entries;

	// Parsed header fields (AFA v1/v2; see docs/afa-format notes).
	uint32_t version = 0;			// 1 or 2
	uint32_t unknown1 = 0;			// header +0x04
	uint32_t unknown2 = 0;			// header +0x14
	uint64_t dataStart = 0;		// header +0x18, base for every file_offset
	uint32_t compressedSize = 0;	// header +0x20, already corrected (-16)
	uint32_t uncompressedSize = 0;	// header +0x24, size of the decoded file index

	// Parse outcome.
	bool valid = false;
	std::string error;			// empty when valid
};