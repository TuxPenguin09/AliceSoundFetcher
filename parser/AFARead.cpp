#include "AFARead.h"

// windows.h defines min()/max() macros that collide with <algorithm>'s std::max.
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>

#include "Inflate.h"
#include "AFAv3.h"

namespace {

	// ---- AFA v1/v2 on-disk layout (little-endian) ----
	//
	//  0x00  4  magic_1      "AFAH"
	//  0x04  4  unknown_1    (0x1C on the archives observed so far)
	//  0x08  8  magic_2      "AlicArch"
	//  0x10  4  afa_version  1 or 2
	//  0x14  4  unknown_2
	//  0x18  4  data_start   absolute base for every file_offset
	//  0x1C  4  magic_3      "INFO"
	//  0x20  4  compressed_size    (subtract 16 to get the real payload size)
	//  0x24  4  uncompressed_size  size of the decoded file index
	//  0x28  4  file_count
	//  0x2C  .. zlib-compressed file index
	//
	// File descriptors inside the decoded index:
	//  4  name_size      actual byte count of file_name
	//  4  padded_size    bytes to consume for file_name (may exceed name_size)
	//  n  file_name
	//  4  unknown_1      likely Windows timestamp
	//  4  unknown_2      likely Windows timestamp
	//  4  unknown_3      AFA v1 only
	//  4  file_offset    relative to data_start
	//  4  file_size
	//  ...

	constexpr size_t HEADER_SIZE = 0x2c;
	constexpr size_t INFO_OFFSET = 0x1c;
	constexpr size_t COMPRESSED_SIZE_ADJUST = 16;

	uint32_t readU32(const unsigned char* p) {
		return static_cast<uint32_t>(p[0])
			| (static_cast<uint32_t>(p[1]) << 8)
			| (static_cast<uint32_t>(p[2]) << 16)
			| (static_cast<uint32_t>(p[3]) << 24);
	}

	} // namespace

AFAFormat AFARead::detectFormat(const char* header) {
	if (header == nullptr) {
		return AFAFormat::UNKNOWN;
	}

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
		archive.error = "open failed";
		return archive;
	}

	// The header is 0x2C bytes: 0x00..0x2B.
	unsigned char header[HEADER_SIZE] = {};
	file.read(reinterpret_cast<char*>(header), sizeof(header));

	if (file.gcount() != static_cast<std::streamsize>(sizeof(header))) {
		std::cerr << "AFA Read Error: File too small to contain an AFA header "
			<< afaPath.string() << std::endl;
		archive.error = "file too small for an AFA header";
		return archive;
	}

	archive.format = detectFormat(reinterpret_cast<const char*>(header));

	if (archive.format == AFAFormat::UNKNOWN) {
		std::cerr << "AFA Read Error: Unrecognised AFA signature " << afaPath.string() << std::endl;
		archive.error = "unrecognised AFA signature";
		return archive;
	}

	archive.unknown1 = readU32(header + 0x04);

	// AFA v3 detection: "AFAH" followed by a u32 version of 3 at +0x08, with no
	// "AlicArch" identifier and no "INFO" marker. The v3 index is encrypted and
	// bit-unaligned, so it is handled by a separate reader.
	if (std::memcmp(header + 8, "AlicArch", 8) != 0 && readU32(header + 0x08) == 3) {
		// v3: the encrypted index lives in the header region, so only that prefix is
		// needed. Voice archives run past 1 GB, so reading the whole file is not an
		// option.
		file.close();

		const uint32_t indexSize = readU32(header + 0x04);
		const uint64_t prefixLen =
			std::min<uint64_t>(indexSize + 16, fs::file_size(afaPath));

		std::ifstream raw(afaPath, std::ios::binary);
		std::vector<unsigned char> all(static_cast<size_t>(prefixLen));
		raw.read(reinterpret_cast<char*>(all.data()),
			static_cast<std::streamsize>(all.size()));
		raw.close();

		// File size is needed separately for the payload-bounds check.
		const uint64_t fileSizeTotal = fs::file_size(afaPath);

		std::cout << "AFA Read: Parsing " << afaPath.filename().string()
			<< " (v3, encrypted index)" << std::endl;

		AliceAFA::v3::Result v3 = AliceAFA::v3::parse(
			all, 0, 0, fileSizeTotal,
			[](const std::vector<unsigned char>& in, size_t expected, std::string& err)
				-> std::vector<unsigned char> {
				std::vector<unsigned char> out;
				if (!AliceInflate::zlibInflate(in, out, expected, err)) {
					return {};
				}
				return out;
			});

		if (!v3.ok) {
			std::cerr << "AFA Read Error: " << v3.error << " " << afaPath.string() << std::endl;
			archive.format = AFAFormat::AFAH_STANDARD;
			archive.version = 3;
			archive.error = v3.error;
			return archive;
		}

		archive.format = AFAFormat::AFAH_STANDARD;
		archive.version = 3;
		archive.dataStart = v3.dataStart;
		archive.compressedSize = v3.packedSize;
		archive.uncompressedSize = v3.unpackedSize;

		archive.entries.reserve(v3.entries.size());
		uint64_t lastEnd = 0;
		for (const AliceAFA::v3::Entry& e : v3.entries) {
			AFAEntry entry;
			entry.fileName = e.name;
			entry.offset = archive.dataStart + static_cast<uint64_t>(e.off);
			entry.size = e.size;
			if (entry.end() > lastEnd) {
				lastEnd = entry.end();
			}
			archive.entries.push_back(std::move(entry));
		}

		if (lastEnd > fileSizeTotal) {
			std::cerr << "AFA Read Error: Entry data extends past end of file ("
				<< lastEnd << " > " << fileSizeTotal << ") " << afaPath.string() << std::endl;
			archive.entries.clear();
			archive.error = "entry data past end of file";
			return archive;
		}

		archive.valid = true;
		std::cout << "AFA Read:   ok, " << archive.entries.size()
			<< " entries, payload ends at " << lastEnd << " / " << fileSizeTotal << std::endl;
		return archive;
	}

	archive.version = readU32(header + 0x10);
	archive.unknown2 = readU32(header + 0x14);
	archive.dataStart = readU32(header + 0x18);
	archive.uncompressedSize = readU32(header + 0x24);
	const uint32_t fileCount = readU32(header + 0x28);

	const uint32_t storedCompressedSize = readU32(header + 0x20);

	if (std::memcmp(header + INFO_OFFSET, "INFO", 4) != 0) {
		std::cerr << "AFA Read Error: Missing INFO section marker " << afaPath.string() << std::endl;
		archive.error = "missing INFO section marker";
		return archive;
	}

	if (archive.version != 1 && archive.version != 2) {
		std::cerr << "AFA Read Warning: Unexpected AFA version " << archive.version
			<< " " << afaPath.string() << std::endl;
	}

	if (storedCompressedSize < COMPRESSED_SIZE_ADJUST) {
		std::cerr << "AFA Read Error: Implausible compressed size " << storedCompressedSize
			<< " " << afaPath.string() << std::endl;
		archive.error = "implausible compressed index size";
		return archive;
	}

	archive.compressedSize = storedCompressedSize - COMPRESSED_SIZE_ADJUST;

	std::cout << "AFA Read: Parsing " << afaPath.filename().string() << std::endl;
	std::cout << "AFA Read:   format=v" << archive.version
		<< " dataStart=" << archive.dataStart
		<< " files=" << fileCount
		<< " index=" << archive.uncompressedSize << "B" << std::endl;

	// Read the compressed index that follows the header.
	std::vector<unsigned char> compressed(archive.compressedSize);
	file.read(reinterpret_cast<char*>(compressed.data()),
		static_cast<std::streamsize>(compressed.size()));

	if (file.gcount() != static_cast<std::streamsize>(compressed.size())) {
		std::cerr << "AFA Read Error: Truncated file index " << afaPath.string() << std::endl;
		archive.error = "truncated file index";
		return archive;
	}

	std::vector<unsigned char> index;
	{
		std::string error;
		if (!AliceInflate::zlibInflate(compressed, index, archive.uncompressedSize, error)) {
			std::cerr << "AFA Read Error: " << error << " " << afaPath.string() << std::endl;
			archive.error = error;
			return archive;
		}
	}

	// Walk the descriptors.
	const bool hasExtraField = (archive.version == 1);
	size_t pos = 0;
	archive.entries.reserve(fileCount);

	for (uint32_t i = 0; i < fileCount; ++i) {
		if (pos + 8 > index.size()) {
			std::cerr << "AFA Read Error: File index truncated at entry " << i
				<< " of " << fileCount << " " << afaPath.string() << std::endl;
			archive.entries.clear();
			archive.error = "file index truncated";
			return archive;
		}

		const uint32_t nameSize = readU32(index.data() + pos);
		const uint32_t paddedSize = readU32(index.data() + pos + 4);
		pos += 8;

		if (paddedSize > index.size() - pos || nameSize > paddedSize) {
			std::cerr << "AFA Read Error: Bad name length at entry " << i
				<< " (name=" << nameSize << " padded=" << paddedSize << ") "
				<< afaPath.string() << std::endl;
			archive.entries.clear();
			archive.error = "bad name length in file index";
			return archive;
		}

		AFAEntry entry;
		// Kept byte-exact: some members carry Shift-JIS names (e.g. Dohna Dohna).
		entry.fileName.assign(reinterpret_cast<const char*>(index.data() + pos), nameSize);
		pos += paddedSize;

		if (pos + 8 + (hasExtraField ? 4u : 0u) > index.size()) {
			std::cerr << "AFA Read Error: File index truncated at entry " << i
				<< " " << afaPath.string() << std::endl;
			archive.entries.clear();
			archive.error = "file index truncated";
			return archive;
		}

		pos += 8; // unknown_1, unknown_2 (timestamps)
		if (hasExtraField) {
			pos += 4; // unknown_3, AFA v1 only
		}

		const uint32_t fileOffset = readU32(index.data() + pos);
		const uint32_t fileSize = readU32(index.data() + pos + 4);
		pos += 8;

		entry.offset = archive.dataStart + static_cast<uint64_t>(fileOffset);
		entry.size = fileSize;
		archive.entries.push_back(std::move(entry));
	}

	// Strong sanity check: a correct descriptor layout consumes the index exactly.
	if (pos != index.size()) {
		std::cerr << "AFA Read Warning: File index not fully consumed ("
			<< pos << " of " << index.size() << " bytes) "
			<< afaPath.string() << " - descriptor layout may be wrong" << std::endl;
	}

	// Confirm the payloads actually exist inside the file.
	uint64_t lastEnd = 0;
	for (const AFAEntry& entry : archive.entries) {
		lastEnd = std::max(lastEnd, entry.end());
	}

	file.seekg(0, std::ios::end);
	const uint64_t fileSizeTotal = static_cast<uint64_t>(file.tellg());

	if (lastEnd > fileSizeTotal) {
		std::cerr << "AFA Read Error: Entry data extends past end of file ("
			<< lastEnd << " > " << fileSizeTotal << ") " << afaPath.string() << std::endl;
		archive.entries.clear();
		archive.error = "entry data past end of file";
		return archive;
	}

	archive.valid = true;
	std::cout << "AFA Read:   ok, " << archive.entries.size() << " entries, payload ends at "
		<< lastEnd << " / " << fileSizeTotal << std::endl;

	return archive;
}