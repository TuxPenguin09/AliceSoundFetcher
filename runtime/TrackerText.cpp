// Reading Shift-JIS text out of the game's memory, and deciding whether a run of
// bytes is an archive entry name.
//
// Archive entry names in these games are raw CP932, so an ASCII-only scanner
// reports nothing at all. Everything here exists because of that, and because the
// addresses involved come from the game's own data and are not guaranteed to be
// mapped.

#include "TrackerShared.h"

#include <cstdio>
#include <cstring>

namespace tracker {

int shiftJisRunLength(const uint8_t* p, int max) {
	int i = 0;
	int repeat = 1;
	while (i < max && p[i] != 0x00) {
		const uint8_t c = p[i];

		// Four identical bytes in a row is not text. 0xDD in particular is both a
		// legitimate half-width katakana byte and the value Windows fills freshly
		// committed heap with, so uninitialised memory reads as a long run of
		// "characters" and was being reported as a 44-character string.
		if (i > 0 && p[i - 1] == c) {
			++repeat;
			if (repeat > 3) {
				break;
			}
		} else {
			repeat = 1;
		}

		// ASCII, plus the half-width katakana block, which is single byte.
		if ((c >= 0x20 && c <= 0x7E) || (c >= 0xA1 && c <= 0xDF)) {
			++i;
			continue;
		}

		const bool isLead = (c >= 0x81 && c <= 0x9F) || (c >= 0xE0 && c <= 0xFC);
		if (!isLead || i + 1 >= max) {
			break;
		}
		const uint8_t trail = p[i + 1];
		if (!((trail >= 0x40 && trail <= 0x7E) || (trail >= 0x80 && trail <= 0xFC))) {
			break;
		}
		i += 2;
	}
	return i;
}

bool safeReadMemory(void* dst, uintptr_t src, size_t length) {
	__try {
		memcpy(dst, (const void*)src, length);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

// Same, but reading through a pointer that may not be mapped.
//
// This lives in its own function because a function containing __try cannot also
// hold objects that need unwinding, and the call site deals in std::string. Returns
// -1 when the read faulted.
//
// The unguarded version of this walked off into unmapped memory and took the game
// down with it. Any read of a value taken out of an object field has to be
// protected, because such a field is arbitrary data as far as this code is
// concerned.
int safeShiftJisRunLength(uintptr_t address, char* out, int max) {
	__try {
		const int len = shiftJisRunLength((const uint8_t*)address, max);
		if (len > 0) {
			memcpy(out, (const void*)address, (size_t)len);
			out[len] = '\0';
		}
		return len;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
}

int nameScore(const uint8_t* p, int len) {
	int score = 0;
	bool hasSeparator = false;
	bool hasExtension = false;

	for (int i = 0; i < len; ++i) {
		const uint8_t c = p[i];
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z')) {
			score += 2;
		} else if (c == '/') {
			score += 2;
			hasSeparator = true;
		} else if (c == '.') {
			// a dot immediately followed by letters is an extension
			if (i + 1 < len) {
				const uint8_t n = p[i + 1];
				if ((n >= 'A' && n <= 'Z') || (n >= 'a' && n <= 'z')) {
					hasExtension = true;
					score += 3;
				}
			}
			score += 1;
		} else if (c == '_' || c == '-') {
			score += 1;
		} else if (c >= 0x81) {
			score += 1; // a legitimate two-byte character, worth something
		} else {
			score -= 1;
		}
	}

	if (hasSeparator) {
		score += 25;
	}
	if (hasExtension) {
		score += 45;
	}
	if (len < 4) {
		score -= 50;
	}
	return score;
}

void escapeToLog(char* out, size_t outCap, const uint8_t* p, int len) {
	size_t used = 0;
	for (int i = 0; i < len && used + 5 < outCap; ++i) {
		const uint8_t c = p[i];
		if (c >= 0x20 && c < 0x7F) {
			out[used++] = (char)c;
		} else {
			const int n = snprintf(out + used, outCap - used, "\\x%02X", c);
			if (n <= 0) {
				break;
			}
			used += (size_t)n;
		}
	}
	if (outCap > 0) {
		out[used < outCap ? used : outCap - 1] = '\0';
	}
}

} // namespace tracker