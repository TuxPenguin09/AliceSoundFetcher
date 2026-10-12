#pragma once

// Minimal, dependency-free DEFLATE/zlib decompressor (RFC 1950 / RFC 1951).
//
// AliceSoundFetcher only ever needs to READ archives, so this implements
// decompression only. It is self-contained so the parser needs no zlib
// dependency and no extra link library.
//
// RtlDecompressBuffer was evaluated first and rejected: with
// COMPRESSION_FORMAT_ZLIB it faults on these inputs, and
// COMPRESSION_FORMAT_DEFAULT is LZNT1 rather than DEFLATE.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace AliceInflate {

	namespace Detail {

		constexpr int MAXBITS = 15;

		struct BitStream {
			const uint8_t* in = nullptr;
			size_t inLen = 0;
			size_t inPos = 0;
			uint32_t bitBuf = 0;
			int bitCnt = 0;
			bool overrun = false;

			// Returns -1 when the stream is exhausted.
			// need == 0 is a normal case: DEFLATE extra-bit counts are 0 for the
			// shortest codes, so this must consume nothing and preserve the buffer.
			int bits(int need) {
				if (need == 0) {
					return 0;
				}
				uint32_t val = bitBuf;
				while (bitCnt < need) {
					if (inPos >= inLen) {
						overrun = true;
						return -1;
					}
					val |= static_cast<uint32_t>(in[inPos++]) << bitCnt;
					bitCnt += 8;
				}
				bitBuf = val >> need;
				bitCnt -= need;
				return static_cast<int>(val & ((1u << need) - 1u));
			}
		};

		struct Huffman {
			std::vector<int16_t> count;   // number of codes per bit length
			std::vector<int16_t> symbol;  // symbols ordered by code
		};

		// Builds a canonical Huffman decoding table. Returns false when the code
		// lengths are over-subscribed (corrupt input).
		int decode(BitStream& s, const Huffman& h) {
			int code = 0;
			int first = 0;
			int index = 0;

			for (int len = 1; len <= MAXBITS; ++len) {
				int b = s.bits(1);
				if (b < 0) {
					return -1;
				}
				code |= b;

				int count = h.count[len];
				if (code - count < first) {
					return h.symbol[index + (code - first)];
				}

				index += count;
				first += count;
				first <<= 1;
				code <<= 1;
			}
			return -2;
		}

		// Canonical Huffman codes may be up to MAXBITS wide.
		// Derived from Mark Adler's reference "puff" decoder (RFC 1951).
		bool construct(Huffman& h, const int16_t* length, int n) {
			h.count.assign(MAXBITS + 1, 0);
			for (int symbol = 0; symbol < n; ++symbol) {
				if (length[symbol] < 0 || length[symbol] > MAXBITS) {
					return false; // invalid code length
				}
				++h.count[length[symbol]];
			}

			// A code is over-subscribed when more symbols exist than bit patterns.
			int left = 1;
			for (int len = 1; len <= MAXBITS; ++len) {
				left <<= 1;
				left -= h.count[len];
				if (left < 0) {
					return false;
				}
			}

			std::vector<int> offs(MAXBITS + 2, 0);
			for (int len = 1; len <= MAXBITS; ++len) {
				offs[len + 1] = offs[len] + h.count[len];
			}

			h.symbol.assign(n, 0);
			for (int symbol = 0; symbol < n; ++symbol) {
				if (length[symbol] != 0) {
					h.symbol[offs[length[symbol]]++] = static_cast<int16_t>(symbol);
				}
			}
			return true;
		}

		// Decompresses a raw DEFLATE stream (no zlib wrapper) into out.
		bool rawInflate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, std::string& error) {
			static const int16_t LENS[29] = {
				3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51,
				59, 67, 83, 99, 115, 131, 163, 195, 227, 258
			};
			static const int16_t LEXT[29] = {
				0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
				4, 4, 4, 4, 5, 5, 5, 5, 0
			};
			static const int16_t DISTS[30] = {
				1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
				769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
			};
			static const int16_t DEXT[30] = {
				0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
				9, 9, 10, 10, 11, 11, 12, 12, 13, 13
			};
			static const int16_t CLORDER[19] = {
				16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
			};

			BitStream s;
			s.in = data;
			s.inLen = len;

			// A stored block always starts at the next whole byte boundary. bits()
			// may have pre-fetched up to 7 whole bytes into bitBuf; give those back
			// so inPos points at the LEN field.
			auto alignToByte = [&]() {
				const int wholeBytes = s.bitCnt / 8;
				s.inPos -= static_cast<size_t>(wholeBytes);
				const int spare = s.bitCnt - (wholeBytes * 8);
				s.bitBuf = spare > 0 ? (s.bitBuf >> spare) : 0;
				s.bitCnt = 0;
			};

			int last = 0;
			do {
				last = s.bits(1);
				if (last < 0) {
					error = "truncated deflate stream (block header)";
					return false;
				}
				int type = s.bits(2);
				if (type < 0) {
					error = "truncated deflate stream (block type)";
					return false;
				}

				if (type == 0) {
					// Stored: align to a byte boundary, then LEN / NLEN.
					alignToByte();

					if (s.inPos + 4 > s.inLen) {
						error = "truncated stored block header";
						return false;
					}
					uint32_t blen = static_cast<uint32_t>(data[s.inPos]) |
						(static_cast<uint32_t>(data[s.inPos + 1]) << 8);
					uint32_t nlen = static_cast<uint32_t>(data[s.inPos + 2]) |
						(static_cast<uint32_t>(data[s.inPos + 3]) << 8);
					s.inPos += 4;

					if ((blen ^ 0xFFFFu) != nlen) {
						error = "stored block length check failed";
						return false;
					}
					if (s.inPos + blen > s.inLen) {
						error = "truncated stored block payload";
						return false;
					}
					out.insert(out.end(), data + s.inPos, data + s.inPos + blen);
					s.inPos += blen;

				}
				else if (type == 1 || type == 2) {
					Huffman lencode;
					Huffman distcode;

					if (type == 1) {
						// Fixed Huffman.
						int16_t lengths[288];
						int symbol = 0;
						for (; symbol < 144; ++symbol) lengths[symbol] = 8;
						for (; symbol < 256; ++symbol) lengths[symbol] = 9;
						for (; symbol < 280; ++symbol) lengths[symbol] = 7;
						for (; symbol < 288; ++symbol) lengths[symbol] = 8;
						if (!construct(lencode, lengths, 288)) {
							error = "bad fixed literal/length table";
							return false;
						}
						int16_t distLengths[30];
						for (int i = 0; i < 30; ++i) distLengths[i] = 5;
						if (!construct(distcode, distLengths, 30)) {
							error = "bad fixed distance table";
							return false;
						}
					}
					else {
						// Dynamic Huffman.
						int nlen = s.bits(5);
						int ndist = s.bits(5);
						int ncode = s.bits(4);
						if (nlen < 0 || ndist < 0 || ncode < 0) {
							error = "truncated deflate stream (dynamic header)";
							return false;
						}
						nlen += 257;
						ndist += 1;
						ncode += 4;
						if (nlen > 286 || ndist > 30) {
							error = "too many length or distance codes";
							return false;
						}

						std::vector<int16_t> all(320, 0);

						int index = 0;
						for (; index < ncode; ++index) {
							int v = s.bits(3);
							if (v < 0) {
								error = "truncated deflate stream (code lengths)";
								return false;
							}
							all[CLORDER[index]] = static_cast<int16_t>(v);
						}
						for (; index < 19; ++index) {
							all[CLORDER[index]] = 0;
						}

						Huffman lenlen;
						if (!construct(lenlen, all.data(), 19)) {
							error = "bad code-length table";
							return false;
						}

						index = 0;
						while (index < nlen + ndist) {
							int symbol = decode(s, lenlen);
							if (symbol < 0) {
								error = "corrupt code-length sequence";
								return false;
							}
							if (symbol < 16) {
								all[index++] = static_cast<int16_t>(symbol);
							}
							else {
								int16_t len = 0;
								int repeat = 0;
								if (symbol == 16) {
									if (index == 0) {
										error = "repeat with no previous length";
										return false;
									}
									len = all[index - 1];
									repeat = s.bits(2);
									if (repeat < 0) {
										error = "truncated deflate stream (repeat)";
										return false;
									}
									repeat += 3;
								}
								else if (symbol == 17) {
									repeat = s.bits(3);
									if (repeat < 0) {
										error = "truncated deflate stream (repeat)";
										return false;
									}
									repeat += 3;
								}
								else {
									repeat = s.bits(7);
									if (repeat < 0) {
										error = "truncated deflate stream (repeat)";
										return false;
									}
									repeat += 11;
								}
								if (index + repeat > nlen + ndist) {
									error = "code-length repeat overruns table";
									return false;
								}
								while (repeat-- > 0) {
									all[index++] = len;
								}
							}
						}

						if (all[256] == 0) {
							error = "missing end-of-block code";
							return false;
						}

						if (!construct(lencode, all.data(), nlen)) {
							error = "bad literal/length table";
							return false;
						}
						if (!construct(distcode, all.data() + nlen, ndist)) {
							error = "bad distance table";
							return false;
						}
						// Distances never exceed the window size; anything larger is corrupt.
						for (int i = 0; i < ndist; ++i) {
							if (all[nlen + i] > 0 && DISTS[i] > 32768) {
								error = "distance code exceeds the 32K window";
								return false;
							}
						}
					}

					// Decode symbols until end-of-block.
					for (;;) {
						int symbol = decode(s, lencode);
						if (symbol < 0) {
							error = "corrupt literal/length code";
							return false;
						}
						if (symbol < 256) {
							out.push_back(static_cast<uint8_t>(symbol));
							continue;
						}
						if (symbol == 256) {
							break;
						}

						symbol -= 257;
						if (symbol >= 29) {
							error = "invalid length symbol";
							return false;
						}
						int extra = s.bits(LEXT[symbol]);
						if (extra < 0) {
							error = "truncated deflate stream (length extra bits)";
							return false;
						}
						int length = LENS[symbol] + extra;

						int dist = decode(s, distcode);
						if (dist < 0) {
							error = "corrupt distance code";
							return false;
						}
						if (dist >= 30) {
							error = "invalid distance symbol";
							return false;
						}
						extra = s.bits(DEXT[dist]);
						if (extra < 0) {
							error = "truncated deflate stream (distance extra bits)";
							return false;
						}
						dist = DISTS[dist] + extra;

						if (static_cast<size_t>(dist) > out.size()) {
							error = "distance points before start of output";
							return false;
						}

						size_t from = out.size() - static_cast<size_t>(dist);
						for (int i = 0; i < length; ++i) {
							out.push_back(out[from + static_cast<size_t>(i)]);
						}
					}
				}
				else {
					error = "invalid deflate block type";
					return false;
				}
			} while (last == 0);

			return true;
		}

		uint32_t adler32(const uint8_t* data, size_t len) {
			constexpr uint32_t BASE = 65521u;
			uint32_t a = 1, b = 0;
			size_t i = 0;
			while (i < len) {
				size_t chunk = (len - i < 5552) ? (len - i) : 5552;
				for (size_t k = 0; k < chunk; ++k) {
					a += data[i + k];
					b += a;
				}
				a %= BASE;
				b %= BASE;
				i += chunk;
			}
			return (b << 16) | a;
		}

	} // namespace Detail

	// Decompresses a zlib stream (RFC 1950): 2-byte header, deflate data,
	// 4-byte big-endian Adler-32.
	inline bool zlibInflate(const std::vector<uint8_t>& in,
		std::vector<uint8_t>& out,
		size_t expectedSize,
		std::string& error) {

		if (in.size() < 6) {
			error = "zlib stream too short";
			return false;
		}

		const uint8_t cmf = in[0];
		const uint8_t flg = in[1];

		if ((cmf & 0x0F) != 8) {
			error = "unsupported zlib compression method " + std::to_string(cmf & 0x0F);
			return false;
		}
		if (((static_cast<uint16_t>(cmf) << 8) | flg) % 31u != 0) {
			error = "bad zlib header check";
			return false;
		}
		if (flg & 0x20) {
			error = "zlib preset dictionaries are not supported";
			return false;
		}

		out.clear();
		if (expectedSize > 0) {
			out.reserve(expectedSize);
		}

		if (!Detail::rawInflate(in.data() + 2, in.size() - 2, out, error)) {
			return false;
		}

		// Verify the trailing Adler-32.
		if (in.size() >= 4) {
			const size_t tail = in.size() - 4;
			const uint32_t want = (static_cast<uint32_t>(in[tail]) << 24) |
				(static_cast<uint32_t>(in[tail + 1]) << 16) |
				(static_cast<uint32_t>(in[tail + 2]) << 8) |
				static_cast<uint32_t>(in[tail + 3]);
			const uint32_t got = Detail::adler32(out.data(), out.size());
			if (want != got) {
				error = "adler32 mismatch (corrupt zlib stream)";
				return false;
			}
		}

		return true;
	}

} // namespace AliceInflate