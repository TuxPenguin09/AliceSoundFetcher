// The archive entry-name index, and confirmation against it.
//
// The launcher parses every .afa archive and writes the result here. That list is
// what lets the tracker tell a real entry name from a run of bytes that merely looks
// like one -- and that distinction is the whole reason this tool is trustworthy.
// Scoring alone accepted "kimg_logo.png", which looks entirely real and exists
// nowhere in the game.
//
// Two indexes are built from the same records: one keyed on the full entry name,
// one on the name with its extension removed. The second exists because the engine
// holds the stem and the extension in separate strings and joins them only on the
// playback path, so an audio entry's full name never exists as one string at any
// point a hook can observe. Without it, audio produced nothing at all while
// graphics matched perfectly.

#include "TrackerShared.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <unordered_set>

namespace tracker {

bool g_indexLoaded = false;

namespace {

constexpr wchar_t kIndexEnvVar[] = L"ALICE_SOUNDFETCHER_INDEX";

struct IndexRecord {
	uint64_t hash;
	uint32_t archiveOffset; // into g_indexText
	uint32_t nameOffset;    // into g_indexText
	uint32_t nameLength;
};

struct StemRecord {
	uint64_t hash;
	uint32_t archiveOffset; // into g_indexText
	uint32_t stemOffset;    // into g_indexText
	uint32_t stemLength;
	// Length of the whole entry name from the same offset, i.e. stem plus the
	// extension. Needed because the archive filter tests the extension, and the
	// stem on its own has none: filtering on stemLength alone rejects every entry
	// and silently logs nothing at all.
	uint32_t fullLength;
};

constexpr uint32_t kStemAmbiguous = 0xFFFFFFFFu;

std::vector<char> g_indexText;
std::vector<IndexRecord> g_index;  // sorted by hash
std::vector<StemRecord> g_stemIndex; // sorted by hash

// Which archives are reported.
//
// Empty means "audio extensions only". Otherwise it is an explicit allow-list of
// archive names, matched case-insensitively. Set through ALICE_SOUNDFETCHER_ARCHIVES.
std::unordered_set<std::string> g_archiveAllow;

// How the filter was configured, for the start-up log line.
bool g_archiveFilterIsExplicit = false;

// The archive name for a record, i.e. everything before the tab.
std::string archiveName(uint32_t archiveOffset, uint32_t nameOffset) {
	const char* start = &g_indexText[archiveOffset];
	size_t archiveLen = nameOffset - archiveOffset;
	if (archiveLen > 0 && start[archiveLen - 1] == '\t') {
		--archiveLen;
	}
	return std::string(start, archiveLen);
}

std::string toLowerAscii(const std::string& s) {
	std::string out = s;
	for (char& c : out) {
		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
	}
	return out;
}

// Whether a confirmed entry should be reported.
bool archiveIsReported(const std::string& archive, const uint8_t* name,
	uint32_t nameLength);

// Read the archive allow-list.
//
// An explicit list lets a caller say exactly which archives it wants, which is what
// makes it possible to report EvenicleSound and EvenicleVoice while saying nothing
// about EvenicleCG, EvenicleCG2 and EvenicleFlat. Leaving it unset falls back to
// audio extensions, which keeps the default useful on a title whose archive names
// are not known in advance.
void loadArchiveFilter() {
	wchar_t buffer[2048] = {};
	const DWORD copied = GetEnvironmentVariableW(
		L"ALICE_SOUNDFETCHER_ARCHIVES", buffer, 2048);

	if (copied == 0 || copied >= 2048) {
		g_archiveFilterIsExplicit = false;
		g_archiveAllow.clear();
		return;
	}

	g_archiveFilterIsExplicit = true;
	g_archiveAllow.clear();

	// Narrow explicitly. Building a std::string straight from the wchar_t buffer
	// would pick the wchar_t iterator constructor and silently truncate every
	// character on the way in. Archive names are ASCII, so the loop is exact, but
	// anything else would be quietly mangled into a name that matches nothing.
	std::string all;
	all.reserve(copied);
	for (DWORD i = 0; i < copied && buffer[i] < 0x80; ++i) {
		all.push_back((char)buffer[i]);
	}

	size_t start = 0;
	while (start <= all.size()) {
		const size_t comma = all.find(',', start);
		const size_t end = (comma == std::string::npos) ? all.size() : comma;

		std::string name = all.substr(start, end - start);
		while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) {
			name.erase(name.begin());
		}
		while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) {
			name.pop_back();
		}
		if (!name.empty()) {
			g_archiveAllow.insert(toLowerAscii(name));
		}

		if (comma == std::string::npos) {
			break;
		}
		start = comma + 1;
	}
}

// Resolve a candidate that is an entry name minus its extension.
//
// Only reports a match when the stem is unambiguous, and says so in the log, so a
// stem-only hit is never mistaken for a full entry name.
bool lookupEntryStem(const uint8_t* bytes, int length, std::string& archiveOut,
	NameMatch* matchOut);

} // namespace

const char* nameMatchKind(NameMatch match) {
	switch (match) {
	case NameMatch::Exact:    return "exact";
	case NameMatch::StemOnly: return "stem";
	default:                  return "none";
	}
}

uint64_t fnv1a(const void* data, size_t length) {
	const uint8_t* p = (const uint8_t*)data;
	uint64_t h = 1469598103934665603ULL;
	for (size_t i = 0; i < length; ++i) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

namespace {

// Extensions treated as audio when no explicit archive list is configured.
//
// The point of the tool is to report audio, and an Evenicle session otherwise
// produces far more graphic than sound: 3541 CG .webp names and 221 .flat names
// against 440 .ogg and 18945 .opus. Filtering by extension rather than by
// hard-coded archive name keeps this working for other System-4 titles, whose
// archives are also named per-resource.
bool isAudioExtension(const uint8_t* name, uint32_t length) {
	static const char* const kAudioExtensions[] = {
		".ogg", ".opus", ".wav", ".mp3", ".flac", ".m4a", ".aac"
	};

	// Find the last dot, ignoring any path separator before it.
	uint32_t dot = length;
	for (uint32_t i = length; i > 0; --i) {
		const uint8_t c = name[i - 1];
		if (c == '/') {
			break;
		}
		if (c == '.') {
			dot = i - 1;
			break;
		}
	}
	if (dot >= length) {
		return false; // no extension
	}

	for (const char* ext : kAudioExtensions) {
		const size_t extLen = strlen(ext);
		if (length - dot != extLen) {
			continue;
		}
		bool same = true;
		for (size_t i = 0; i < extLen; ++i) {
			const uint8_t c = name[dot + i];
			if (c >= 'A' && c <= 'Z') {
				// Compare case-insensitively without modifying the source bytes.
				if (c - 'A' + 'a' != (uint8_t)ext[i]) {
					same = false;
					break;
				}
			} else if (c != (uint8_t)ext[i]) {
				same = false;
				break;
			}
		}
		if (same) {
			return true;
		}
	}
	return false;
}

bool archiveIsReported(const std::string& archive, const uint8_t* name,
	uint32_t nameLength) {
	if (!g_archiveFilterIsExplicit) {
		return isAudioExtension(name, nameLength);
	}
	return g_archiveAllow.count(toLowerAscii(archive)) != 0;
}

bool lookupEntryStem(const uint8_t* bytes, int length, std::string& archiveOut,
	NameMatch* matchOut) {
	if (g_stemIndex.empty() || length <= 0) {
		return false;
	}

	// Cheap reject before any work. Every string handed to this function is a
	// candidate from live game memory, so the overwhelming majority are not names at
	// all, and returning immediately on those is what keeps the hook cheap.
	const uint8_t last = bytes[length - 1];
	if (last != 0x20 && last != '~') {
		// A stem ends in an alphanumeric, which in a Shift-JIS name is ASCII or a
		// half-width katakana byte.
		if (!((last >= '0' && last <= '9') || (last >= 'A' && last <= 'z') ||
			(last >= 0xA1 && last <= 0xDF))) {
			return false;
		}
	}

	const uint64_t h = fnv1a(bytes, (size_t)length);

	size_t lo = 0, hi = g_stemIndex.size();
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		if (g_stemIndex[mid].hash < h) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (lo >= g_stemIndex.size() || g_stemIndex[lo].hash != h) {
		return false;
	}

	for (size_t i = lo; i < g_stemIndex.size() && g_stemIndex[i].hash == h; ++i) {
		const StemRecord& r = g_stemIndex[i];
		if (r.archiveOffset == kStemAmbiguous) {
			continue; // same stem in more than one entry: refuse to guess
		}
		if (r.stemLength != (uint32_t)length) {
			continue;
		}
		if (memcmp(&g_indexText[r.stemOffset], bytes, (size_t)length) == 0) {
			std::string archive = archiveName(r.archiveOffset, r.stemOffset);
			// The filter needs the extension too, so it is tested against the full
			// entry name rather than the stem.
			if (!archiveIsReported(archive,
				(const uint8_t*)&g_indexText[r.stemOffset], r.fullLength)) {
				return false;
			}
			archiveOut = std::move(archive);
			*matchOut = NameMatch::StemOnly;
			return true;
		}
	}
	return false;
}

} // namespace

bool lookupEntryName(const uint8_t* bytes, int length, std::string& archiveOut,
	NameMatch* matchOut) {
	if (!g_indexLoaded || length <= 0) {
		return false;
	}

	const uint64_t h = fnv1a(bytes, (size_t)length);

	size_t lo = 0, hi = g_index.size();
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		if (g_index[mid].hash < h) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}

	if (lo < g_index.size() && g_index[lo].hash == h) {
		// The hash matched; confirm the bytes, because a hash collision must never
		// be reported as a confirmed match.
		for (size_t i = lo; i < g_index.size() && g_index[i].hash == h; ++i) {
			const IndexRecord& r = g_index[i];
			if (r.nameLength != (uint32_t)length) {
				continue;
			}
			if (memcmp(&g_indexText[r.nameOffset], bytes, (size_t)length) == 0) {
				std::string archive = archiveName(r.archiveOffset, r.nameOffset);
				if (!archiveIsReported(archive,
					(const uint8_t*)&g_indexText[r.nameOffset], r.nameLength)) {
					return false;
				}
				archiveOut = std::move(archive);
				*matchOut = NameMatch::Exact;
				return true;
			}
		}
	}

	// Not a whole entry name. Try the stem index, which is what identifies audio:
	// the engine keeps the stem and the extension apart.
	return lookupEntryStem(bytes, length, archiveOut, matchOut);
}

void loadEntryIndex() {
	wchar_t pathBuf[MAX_PATH] = {};
	const DWORD copied = GetEnvironmentVariableW(
		kIndexEnvVar, pathBuf, MAX_PATH);
	if (copied == 0 || copied >= MAX_PATH) {
		logInfo("AudioTracker: no entry index supplied; name validation disabled.");
		return;
	}

	std::ifstream file(pathBuf, std::ios::binary);
	if (!file) {
		logInfo("AudioTracker: entry index could not be opened.");
		return;
	}

	file.seekg(0, std::ios::end);
	const std::streamoff size = file.tellg();
	file.seekg(0, std::ios::beg);
	if (size <= 0) {
		return;
	}

	g_indexText.resize((size_t)size);
	file.read(g_indexText.data(), size);
	if (!file) {
		g_indexText.clear();
		return;
	}

	g_index.reserve(g_indexText.size() / 24 + 16);

	size_t lineStart = 0;
	while (lineStart < g_indexText.size()) {
		size_t lineEnd = lineStart;
		while (lineEnd < g_indexText.size() && g_indexText[lineEnd] != '\n') {
			++lineEnd;
		}
		if (lineEnd > lineStart && g_indexText[lineEnd - 1] != '\r') {
			size_t sep = lineStart;
			while (sep < lineEnd && g_indexText[sep] != '\t') {
				++sep;
			}
			if (sep < lineEnd && sep > lineStart) {
				IndexRecord record{};
				record.archiveOffset = (uint32_t)lineStart;
				record.nameOffset = (uint32_t)(sep + 1);
				record.nameLength = (uint32_t)(lineEnd - (sep + 1));
				record.hash = fnv1a(&g_indexText[record.nameOffset],
					record.nameLength);
				g_index.push_back(record);
			}
		}
		lineStart = lineEnd + 1;
	}

	std::sort(g_index.begin(), g_index.end(),
		[](const IndexRecord& a, const IndexRecord& b) { return a.hash < b.hash; });

	// Build the stem index from the same records, so it cannot drift out of step
	// with the full-name index.
	for (const IndexRecord& record : g_index) {
		// The extension is the last '.' after the last path separator. Entries are
		// plain names with no directory part in this game, but allowing for one costs
		// nothing and avoids cutting at a dot inside a path.
		size_t dot = (size_t)record.nameLength;
		for (size_t i = record.nameLength; i > 0; --i) {
			const char c = g_indexText[record.nameOffset + i - 1];
			if (c == '/') {
				break;
			}
			if (c == '.') {
				dot = i - 1;
				break;
			}
		}
		if (dot == 0 || dot >= record.nameLength) {
			continue; // no extension, or a dotfile: nothing useful to key on
		}

		StemRecord stem{};
		stem.archiveOffset = record.archiveOffset;
		stem.stemOffset = record.nameOffset;
		stem.stemLength = (uint32_t)dot;
		stem.fullLength = record.nameLength;
		stem.hash = fnv1a(&g_indexText[stem.stemOffset], stem.stemLength);
		g_stemIndex.push_back(stem);
	}

	std::sort(g_stemIndex.begin(), g_stemIndex.end(),
		[](const StemRecord& a, const StemRecord& b) { return a.hash < b.hash; });

	// Mark any stem that occurs more than once, so a lookup can refuse it rather
	// than pick one of the candidates.
	size_t ambiguous = 0;
	for (size_t i = 0; i < g_stemIndex.size();) {
		size_t j = i;
		while (j < g_stemIndex.size() && g_stemIndex[j].hash == g_stemIndex[i].hash) {
			++j;
		}
		if (j - i > 1) {
			bool identical = true;
			for (size_t k = i + 1; k < j && identical; ++k) {
				if (g_stemIndex[k].stemLength != g_stemIndex[i].stemLength ||
					memcmp(&g_indexText[g_stemIndex[k].stemOffset],
						&g_indexText[g_stemIndex[i].stemOffset],
						g_stemIndex[i].stemLength) != 0) {
					identical = false;
				}
			}
			if (!identical) {
				for (size_t k = i; k < j; ++k) {
					g_stemIndex[k].archiveOffset = kStemAmbiguous;
				}
				++ambiguous;
			}
		}
		i = j;
	}

	g_indexLoaded = true;
	logInfo("AudioTracker: entry index loaded: %zu names, %zu bytes, "
		"%zu stems (%zu ambiguous).",
		g_index.size(), g_indexText.size(), g_stemIndex.size(), ambiguous);

	if (g_archiveFilterIsExplicit) {
		// Name the archives so it is obvious when a setting has a typo and the
		// filter is silently excluding everything.
		logInfo("AudioTracker: reporting only %zu named archives:",
			g_archiveAllow.size());
		for (const std::string& name : g_archiveAllow) {
			logInfo("AudioTracker:   %s", name.c_str());
		}
	} else {
		logInfo("AudioTracker: reporting audio extensions only "
			"(.ogg .opus .wav .mp3 .flac .m4a .aac).");
	}
}

} // namespace tracker