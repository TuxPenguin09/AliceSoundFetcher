#pragma once

// AliceSoft AFA v3 support.
//
// v3 differs structurally from v1/v2:
//   - 12-byte header: "AFAH", index_size (u32), 3 (u32)
//   - data_start = index_size + 8
//   - the dictionary and the compressed file index live in a BIT-UNALIGNED
//     stream: a single padding bit is inserted after the header, so no field
//     is byte-aligned
//   - file names are doubly encrypted: once by a PRNG seeded with the string
//     length, then again through an encrypted dictionary
//
// Ported from libsys4 (nunuhara), which is itself adapted from GARbro.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace AliceAFA {

	namespace v3 {

		// ---- PRNG (MT19937-family, "munge" variant) ----
		struct Rnd {
			uint32_t state[521] = {};
			int current = -1;

			void shuffle() {
				for (int i = 0; i < 32; i += 4) {
					state[i + 0] ^= state[i + 489];
					state[i + 1] ^= state[i + 490];
					state[i + 2] ^= state[i + 491];
					state[i + 3] ^= state[i + 492];
				}
				for (int i = 32; i < 521; i += 3) {
					state[i + 0] ^= state[i - 32];
					state[i + 1] ^= state[i - 31];
					state[i + 2] ^= state[i - 30];
				}
			}

			void init(uint32_t seed) {
				uint32_t val = 0;
				for (int i = 0; i < 17; i++) {
					for (int j = 0; j < 32; j++) {
						seed = 1566083941u * seed + 1u;
						val = (seed & 0x80000000u) | (val >> 1);
					}
					state[i] = val;
				}
				state[16] = state[15] ^ (state[0] >> 9) ^ (state[16] << 23);
				for (int i = 17; i < 521; i++) {
					state[i] = state[i - 1] ^ (state[i - 16] >> 9) ^ (state[i - 17] << 23);
				}
				shuffle();
				shuffle();
				shuffle();
				shuffle();
				current = -1;
			}

			uint32_t next() {
				current++;
				if (current >= 521) {
					shuffle();
					current = 0;
				}
				return state[current];
			}
		};

		// ---- MSB-first bit reader over a byte buffer ----
		// This is NOT the LSB-first DEFLATE bit order; the two must not be mixed.
		struct BitStream {
			const uint8_t* data = nullptr;
			size_t size = 0;
			size_t pos = 0;
			int cached = 0;
			uint32_t cache = 0;
			bool failed = false;

			// Returns -1 once the stream is exhausted.
			int readBits(int count) {
				while (cached < count) {
					if (pos >= size) {
						failed = true;
						return -1;
					}
					cache = (cache << 8) | static_cast<uint32_t>(data[pos++]);
					cached += 8;
				}
				const uint32_t mask = (count == 0) ? 0u : ((1u << count) - 1u);
				cached -= count;
				return static_cast<int>((cache >> cached) & mask);
			}

			// Returns false when the stream is exhausted. Note the byte values are 0..255,
			// so the failure test must check each read individually rather than
			// OR-ing them together.
			bool readInt32(uint32_t& out) {
				int b[4];
				for (int i = 0; i < 4; i++) {
					b[i] = readBits(8);
					if (b[i] < 0) {
						return false;
					}
				}
				out = static_cast<uint32_t>(b[0]) |
					(static_cast<uint32_t>(b[1]) << 8) |
					(static_cast<uint32_t>(b[2]) << 16) |
					(static_cast<uint32_t>(b[3]) << 24);
				return true;
			}
		};

		struct Entry {
			std::string name;   // decoded, byte-exact (may be Shift-JIS)
			uint32_t off = 0;   // relative to data_start
			uint32_t size = 0;
		};

		struct Result {
			bool ok = false;
			std::string error;
			uint32_t indexSize = 0;
			uint32_t dataStart = 0;
			uint32_t packedSize = 0;
			uint32_t unpackedSize = 0;
			std::vector<Entry> entries;
		};

		// Decompresses a zlib stream. Supplied by the caller so this header stays
		// independent of the inflate implementation.
		using InflateFn = std::vector<uint8_t> (*)(const std::vector<uint8_t>&,
			size_t,
			std::string&);

		// Parses the v3 metadata starting at `fileOffset` within `file`.
		// `file` must contain at least the header and the encrypted index region;
		// the caller may pass a prefix of a much larger archive. `realFileSize` is
		// the archive's true size, used only to reject implausible data_start.
		inline Result parse(const std::vector<uint8_t>& file,
			size_t fileOffset,
			size_t maxEntries,
			uint64_t realFileSize,
			InflateFn inflateZlib) {

			Result r;

			if (fileOffset + 12 > file.size()) {
				r.error = "file too small for a v3 header";
				return r;
			}

			auto le32 = [&](size_t off) -> uint32_t {
				return static_cast<uint32_t>(file[off]) |
					(static_cast<uint32_t>(file[off + 1]) << 8) |
					(static_cast<uint32_t>(file[off + 2]) << 16) |
					(static_cast<uint32_t>(file[off + 3]) << 24);
			};

			r.indexSize = le32(4);
			r.dataStart = r.indexSize + 8u;

			if (realFileSize != 0 && r.dataStart + 8 >= realFileSize) {
				r.error = "v3 data_start is outside the file";
				return r;
			}

			// --- dictionary, read from the bit-unaligned stream ---
			BitStream bs;
			bs.data = file.data() + fileOffset;
			bs.size = file.size() - fileOffset;
			bs.pos = 12;

			bs.readBits(1); // single padding bit after the header

			uint32_t dictSizeRaw = 0;
			if (!bs.readInt32(dictSizeRaw)) {
				r.error = "truncated v3 dictionary size";
				return r;
			}
			if (dictSizeRaw > (1u << 20)) {
				r.error = "implausible v3 dictionary size";
				return r;
			}
			const size_t dictSize = static_cast<size_t>(dictSizeRaw);

			std::vector<uint8_t> dict(dictSize);

			Rnd rnd;
			rnd.init(static_cast<uint32_t>(dictSize));
			for (size_t i = 0; i < dictSize; i++) {
				const int count = static_cast<int>(rnd.next()) & 3;
				if (bs.readBits(count + 1) < 0) {
					r.error = "truncated v3 dictionary";
					return r;
				}
				rnd.next();
				const int v = bs.readBits(8);
				if (v < 0) {
					r.error = "truncated v3 dictionary";
					return r;
				}
				dict[i] = static_cast<uint8_t>(v);
			}

			// --- compressed index ---
			uint32_t packedSizeRaw = 0, unpackedSizeRaw = 0;
			if (!bs.readInt32(packedSizeRaw) || !bs.readInt32(unpackedSizeRaw)) {
				r.error = "invalid v3 index sizes";
				return r;
			}
			if (packedSizeRaw > (1u << 30) || unpackedSizeRaw > (1u << 30)) {
				r.error = "implausible v3 index sizes";
				return r;
			}
			const size_t packedSize = packedSizeRaw;
			const size_t unpackedSize = unpackedSizeRaw;

			r.packedSize = packedSizeRaw;
			r.unpackedSize = unpackedSizeRaw;

			std::vector<uint8_t> packed(packedSize);
			for (size_t i = 0; i < packedSize; i++) {
				const int v = bs.readBits(8);
				if (v < 0) {
					r.error = "truncated v3 compressed index";
					return r;
				}
				packed[i] = static_cast<uint8_t>(v);
			}

			std::string zerr;
			std::vector<uint8_t> unpacked = inflateZlib(packed, unpackedSize, zerr);
			if (unpacked.empty() && unpackedSize != 0) {
				r.error = "v3 index inflate failed: " + zerr;
				return r;
			}

			// --- file table, also bit-unaligned with a leading padding bit ---
			BitStream tbl;
			tbl.data = unpacked.data();
			tbl.size = unpacked.size();

			tbl.readBits(1); // single padding bit

			uint32_t nrFilesRaw = 0;
			if (!tbl.readInt32(nrFilesRaw)) {
				r.error = "invalid v3 file count";
				return r;
			}
			const uint32_t nrFiles = nrFilesRaw;

			size_t want = static_cast<size_t>(nrFiles);
			if (maxEntries > 0 && want > maxEntries) {
				want = maxEntries;
			}
			r.entries.reserve(want);

			for (size_t i = 0; i < want; i++) {
				if (tbl.readBits(2) < 0) { // 2 bits of padding per descriptor
					r.error = "truncated v3 file table";
					return r;
				}

				// Encrypted characters: PRNG layer seeded by the string length.
				uint32_t bufSizeRaw = 0;
				if (!tbl.readInt32(bufSizeRaw)) {
					r.error = "truncated v3 file name length";
					return r;
				}
				if (bufSizeRaw > (1u << 20)) {
					r.error = "implausible v3 file name length";
					return r;
				}
				const size_t bufSize = bufSizeRaw;

				rnd.init(static_cast<uint32_t>(bufSize));

				std::vector<uint16_t> chars(bufSize);
				for (size_t k = 0; k < bufSize; k++) {
					const int count = static_cast<int>(rnd.next()) & 3;
					if (tbl.readBits(count + 1) < 0) {
						r.error = "truncated v3 file name";
						return r;
					}
					rnd.next();
					const int lo = tbl.readBits(8);
					const int hi = tbl.readBits(8);
					if (lo < 0 || hi < 0) {
						r.error = "truncated v3 file name";
						return r;
					}
					chars[k] = static_cast<uint16_t>(lo | (hi << 8));
				}

				// Dictionary layer.
				// The decrypted name is NUL-terminated; the reference implementation
				// converts it with strlen(), so that trailing NUL is not part of the
				// stored name and must be trimmed here too.
				std::vector<char> decoded(bufSize);
				for (size_t k = 0; k < bufSize; k++) {
					const uint16_t idx = chars[k];
					if (static_cast<size_t>(idx) >= dict.size()) {
						r.error = "v3 dictionary index out of range";
						return r;
					}
					decoded[k] = static_cast<char>(dict[idx] ^ 0xa4);
				}
				const size_t nameLen = ::strnlen(decoded.data(), decoded.size());

				Entry e;
				e.name.assign(decoded.data(), nameLen);

				uint32_t u0 = 0, u1 = 0, off = 0, size = 0;
				if (!tbl.readInt32(u0) || !tbl.readInt32(u1) ||
					!tbl.readInt32(off) || !tbl.readInt32(size)) {
					r.error = "truncated v3 file descriptor";
					return r;
				}

				e.off = off;
				e.size = size;
				r.entries.push_back(std::move(e));
			}

			r.ok = true;
			return r;
		}

	} // namespace v3

} // namespace AliceAFA