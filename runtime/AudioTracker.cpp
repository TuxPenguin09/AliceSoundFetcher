#include "AudioTracker.h"

#include <windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Stage 1 audio tracking.
//
// This code runs inside the injected DLL, i.e. inside the game's own process.
//
// Why the hook looks here: AliceSoft resolves DirectSound dynamically and never
// opens per-sound files, because every asset lives inside the .afa archive and
// is played from memory. Hooking CreateFileW for ".ogg" therefore cannot fire.
// The sound engine's own classes do get called per sound, and they are reachable
// through RTTI, which the shipped binaries retain.
//
// Every audio class in the engine is hooked, not just one guess, because the class
// that actually carries per-sound playback is not known ahead of time and picking
// one by name is a guess. Logging every call identifies it from observation.
//
// Stage 1 deliberately makes no assumption about object layout. Each event logs
// the class, the slot, `this`, and the two raw stack words above the return
// address, which is enough to identify the right function and its calling
// convention without guessing at field offsets.
// ---------------------------------------------------------------------------

namespace {

	// -----------------------------------------------------------------------
	// Log
	//
	// The game process has no usable console, so events are appended to a file
	// that the launcher tails. FILE_SHARE_READ|FILE_SHARE_WRITE lets both
	// processes hold the file open at once.
	// -----------------------------------------------------------------------

	constexpr wchar_t kLogEnvVar[] = L"ALICE_SOUNDFETCHER_LOG";

	HANDLE g_logFile = INVALID_HANDLE_VALUE;
	SRWLOCK g_logLock = SRWLOCK_INIT;

	std::atomic<int> g_slotCount{ 0 };
	std::atomic<bool> g_initialized{ false };

	uintptr_t g_moduleBase = 0;
	size_t g_moduleSize = 0;

	// Executable address ranges of the main module.
	//
	// These matter far more than they look. The .rdata section is laid out as a
	// long run of [CompleteObjectLocator][vftable] pairs for many unrelated
	// classes, so the dwords *after* a class's last virtual function look exactly
	// like more virtual functions -- they are simply pointers that happen to fall
	// inside the image. Counting "pointers inside the module" therefore walks off
	// the end of the vtable and into neighbouring classes, and patching those
	// slots corrupts every class that follows. Confining the walk to executable
	// memory stops it at the next class's COL.
	std::vector<std::pair<uintptr_t, uintptr_t>> g_execRanges;

	bool ensureLogFile() {
		if (g_logFile != INVALID_HANDLE_VALUE) {
			return true;
		}

		wchar_t path[MAX_PATH] = {};
		DWORD copied = GetEnvironmentVariableW(kLogEnvVar, path, MAX_PATH);
		if (copied == 0 || copied >= MAX_PATH) {
			// Fall back beside the game so events are never silently dropped.
			wchar_t modulePath[MAX_PATH] = {};
			if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) {
				wchar_t* lastSlash = wcsrchr(modulePath, L'\\');
				if (lastSlash) {
					*(lastSlash + 1) = L'\0';
					wcscat_s(modulePath, L"AliceSoundFetcher.log");
				}
				wcscpy_s(path, modulePath);
			}
		}

		if (path[0] == L'\0') {
			return false;
		}

		g_logFile = CreateFileW(
			path,
			FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		return g_logFile != INVALID_HANDLE_VALUE;
	}

	void writeLogLine(const char* line) {
		if (!ensureLogFile()) {
			return;
		}

		// Serialise writers so two game threads cannot interleave partial lines.
		AcquireSRWLockExclusive(&g_logLock);

		std::string buffer;
		buffer.reserve(strlen(line) + 2);
		for (const char* p = line; *p; ++p) {
			if (*p == '\n') {
				buffer += '\r';
			}
			buffer += *p;
		}
		buffer += '\r';
		buffer += '\n';

		DWORD written = 0;
		WriteFile(g_logFile, buffer.data(), (DWORD)buffer.size(), &written, nullptr);
		FlushFileBuffers(g_logFile);
		OutputDebugStringA(line);

		ReleaseSRWLockExclusive(&g_logLock);
	}

	void logTimestamp(char* out, size_t cap) {
		SYSTEMTIME st{};
		GetLocalTime(&st);
		snprintf(out, cap, "[%02u:%02u:%02u.%03u]",
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	}

	void logInfo(const char* fmt, ...) {
		char stamp[32];
		logTimestamp(stamp, sizeof(stamp));

		char body[400];
		va_list args;
		va_start(args, fmt);
		vsnprintf(body, sizeof(body), fmt, args);
		va_end(args);

		char line[512];
		snprintf(line, sizeof(line), "%s %s\r\n", stamp, body);
		writeLogLine(line);
	}

	// -----------------------------------------------------------------------
	// Module / RTTI discovery
	// -----------------------------------------------------------------------

	bool isExecutable(uintptr_t va) {
		for (const auto& range : g_execRanges) {
			if (va >= range.first && va < range.second) {
				return true;
			}
		}
		return false;
	}

	void describeModule() {
		HMODULE main = GetModuleHandleW(nullptr);
		if (!main) {
			return;
		}
		g_moduleBase = (uintptr_t)main;

		// Size straight from the PE headers, avoiding a psapi dependency.
		const auto* dos = (const IMAGE_DOS_HEADER*)main;
		const auto* nt = (const IMAGE_NT_HEADERS32*)((const uint8_t*)main + dos->e_lfanew);
		g_moduleSize = nt->OptionalHeader.SizeOfImage;

		g_execRanges.clear();
		const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
		for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
			if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
				continue;
			}
			// Use the larger of the two sizes: MSVC can leave real code sitting
			// past VirtualSize, and Evenicle's .text is exactly that case
			// (VirtualSize 0x295E53 vs SizeOfRawData 0x296000).
			uint32_t span = sec->Misc.VirtualSize;
			if (sec->SizeOfRawData > span) {
				span = sec->SizeOfRawData;
			}
			const uintptr_t lo = (uintptr_t)main + sec->VirtualAddress;
			g_execRanges.emplace_back(lo, lo + span);
		}
	}

	const uint8_t* findInModule(const char* needle) {
		if (!g_moduleBase || !g_moduleSize) {
			return nullptr;
		}
		const size_t needleLen = strlen(needle);
		if (!needleLen || g_moduleSize < needleLen) {
			return nullptr;
		}

		const uint8_t* start = (const uint8_t*)g_moduleBase;
		const uint8_t* end = start + g_moduleSize;
		for (const uint8_t* p = start; p + needleLen <= end; ++p) {
			if (memcmp(p, needle, needleLen) == 0) {
				return p;
			}
		}
		return nullptr;
	}

	// Resolve the TypeDescriptor RVA for a class by its unqualified name.
	//
	// The full RTTI name is matched, i.e. the character after the class name must
	// be '@'. Without that check, searching for "CDirectSound" would happily match
	// ".?AVCDirectSoundBuffer@kiwi@@" whenever that string happened to come first
	// in the image, and the wrong class would get hooked.
	uint32_t findTypeDescriptorRva(const char* className) {
		std::string needle = ".?AV";
		needle += className;

		const uint8_t* match = findInModule(needle.c_str());
		if (!match) {
			return 0;
		}
		if (match[needle.size()] != '@') {
			return 0;
		}

		// A TypeDescriptor is { vftable; spare; char name[] }, so the name sits
		// 8 bytes into it.
		return static_cast<uint32_t>(match - (const uint8_t*)g_moduleBase) - 8;
	}

	// MSVC CompleteObjectLocator:
	//   signature, offset, cdOffset, pTypeDescriptor, pClassHierarchy, pSelf
	//
	// Verified against the shipped AliceSoft builds: pTypeDescriptor is stored as
	// an absolute VA rather than an RVA, and pSelf is zero. Anchoring on pSelf
	// (as one would for a rebased image) therefore fails here, so both encodings
	// are tried and the signature word validates the candidate instead.
	bool findCompleteObjectLocator(uint32_t typeDescriptorRva, uint32_t& outColRva) {
		const uint8_t* start = (const uint8_t*)g_moduleBase;
		const uint8_t* end = start + g_moduleSize;

		const uint32_t keys[2] = {
			static_cast<uint32_t>(g_moduleBase + typeDescriptorRva), // VA encoding
			typeDescriptorRva,                                       // RVA encoding
		};

		for (int keyIndex = 0; keyIndex < 2; ++keyIndex) {
			const uint32_t key = keys[keyIndex];

			for (const uint8_t* p = start; p + sizeof(uint32_t) <= end; ++p) {
				uint32_t value = 0;
				memcpy(&value, p, sizeof(value));
				if (value != key) {
					continue;
				}

				// pTypeDescriptor sits at offset +12.
				const uint8_t* candidate = p - 12;
				if (candidate < start || candidate + 20 > end) {
					continue;
				}

				uint32_t signature = 0;
				memcpy(&signature, candidate, sizeof(signature));
				if (signature > 1) {
					continue;
				}

				outColRva = static_cast<uint32_t>(candidate - start);
				return true;
			}
		}
		return false;
	}

	// The vtable pointer sits immediately after the COL pointer, so the COL is
	// referenced as a dword in the data section and the entry after it is the
	// vtable. Same VA/RVA ambiguity, so both are tried. The candidate is only
	// accepted when a following slot already points into executable memory.
	bool findVtable(uint32_t colRva, uintptr_t& outVtable) {
		const uint8_t* start = (const uint8_t*)g_moduleBase;
		const uint8_t* end = start + g_moduleSize;

		const uint32_t keys[2] = {
			static_cast<uint32_t>(g_moduleBase + colRva),
			colRva,
		};

		for (int keyIndex = 0; keyIndex < 2; ++keyIndex) {
			const uint32_t key = keys[keyIndex];

			for (const uint8_t* p = start; p + sizeof(uint32_t) <= end; ++p) {
				uint32_t value = 0;
				memcpy(&value, p, sizeof(value));
				if (value != key) {
					continue;
				}

				const uint8_t* table = p + 4;
				if (table + 4 > end) {
					continue;
				}
				uintptr_t first = 0;
				memcpy(&first, table, sizeof(first));
				if (!isExecutable(first)) {
					continue;
				}

				outVtable = reinterpret_cast<uintptr_t>(table);
				return true;
			}
		}
		return false;
	}

	// -----------------------------------------------------------------------
	// Hook bookkeeping
	// -----------------------------------------------------------------------

	// The audio classes to hook. Every one is attempted; a missing class is
	// reported and skipped rather than treated as an error, because the exact set
	// differs per game.
	const char* const kAudioClasses[] = {
		// The playback path proper.
		"CSoundPlayer",
		"CDirectSoundBuffer",

		// The archive side. CSoundFileAFA resolves a member of an .afa archive to
		// audio data, so it is where an entry name is actually present -- the
		// decoded sound object does not retain it, which is why dumping
		// CSoundDataOgg never turned up a name.
		"CSoundFileAFA",
		"CSoundFileList",

		// Decoded data.
		"CSoundDataOgg",
		"CSoundDataWav",

		// Routing and grouping; these tend to hold the key that started playback.
		"CGroupTree",
		"CSoundChannel",
		"CSoundChannelList",
		"CLowLevelChannelList",
		"CHighLevelChannelList",
		"CKiwiSoundEngine",
	};
	constexpr int kAudioClassCount = (int)(sizeof(kAudioClasses) / sizeof(kAudioClasses[0]));

	struct HookTarget {
		std::string className;
		int slot;       // index within that class's vtable
		void* original; // untouched entry address
	};

	std::vector<HookTarget> g_targets;
	uint8_t* g_stubBase = nullptr;
	int g_stubCount = 0;

	// Per-stub call counters, bumped without locking.
	LONG g_callCounts[512] = {};

	// Quiet mode: count only, never format or write. See AudioTrackerLogHook.
	bool g_quiet = false;

	// Passthrough mode: each stub is nothing but a jump to the original entry, so
	// the vtable is patched exactly as before but nothing of ours ever executes.
	//
	// This isolates the two possible causes of a fault after patching. If the game
	// still dies, the fault comes from the vtable contents themselves rather than
	// from running our code on the game's audio path.
	bool g_passthrough = false;

	bool envFlag(const wchar_t* name) {
		wchar_t value[8] = {};
		return GetEnvironmentVariableW(name, value, 8) > 0 && value[0] == L'1';
	}

	// Emit the raw bytes of the first stub.
	//
	// The stubs are hand-assembled, and a single wrong byte produces failures that
	// look like engine bugs rather than encoding bugs. Printing the bytes makes
	// the encoding reviewable by eye instead of by inference.
	void logFirstStubBytes(const uint8_t* stub, size_t size) {
		char line[256];
		int n = snprintf(line, sizeof(line), "  stub[0] bytes:");
		for (size_t i = 0; i < size && n > 0 && n < (int)sizeof(line) - 4; ++i) {
			n += snprintf(line + n, sizeof(line) - (size_t)n, " %02X", stub[i]);
		}
		if (n > 0) {
			logInfo("%s", line);
		}
	}

	// -----------------------------------------------------------------------
	// Stage 2: identifying sound objects among the call arguments.
	//
	// Stage 1 established which engine functions are called. Stage 2 needs to
	// answer a different question: of everything flowing through those calls,
	// which value is the sound being played?
	//
	// The vtable pointer at offset 0 makes this answerable without guessing an
	// object layout. Anything whose first dword equals one of the vtables we
	// patched is an instance of that class, so an argument can be classified by
	// comparing one dword. That is a far safer assumption than a fixed field
	// offset: if the layout is wrong, the classifier simply returns "not a known
	// class" rather than reporting confident nonsense.
	// -----------------------------------------------------------------------

	// vtable address -> class name, for every hooked class.
	std::vector<std::pair<uintptr_t, std::string>> g_classVtables;

	// Set while deliberately probing possibly-invalid pointers, so the vectored
	// exception handler does not report the resulting access violations as if
	// they were faults in the game or in our stubs.
	LONG g_probing = 0;

	// Object pointers already dumped, so each instance is reported once rather
	// than on every call that mentions it. Claimed with an interlocked compare
	// exchange so two game threads cannot both decide to dump the same object.
	// Sized generously: a collision evicts an entry and causes a re-dump, which
	// is merely noise, but it is worth avoiding.
	constexpr size_t kSeenObjectCount = 4096;
	volatile LONG g_seenObjects[kSeenObjectCount] = {};

	// Comparison hooks to install on the import table.
	constexpr int kMaxCompareHooks = 4;

	// These helpers use __try/__except and therefore must not construct any
	// object with a destructor.
	bool safeRead32(uintptr_t address, uint32_t* out) {
		__try {
			*out = *(volatile uint32_t*)address;
			return true;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	// Reads a NUL-terminated ASCII string, returning its length or -1.
	// Rejects anything that is not plainly printable, so a random heap pointer
	// is not mistaken for a string.
	int safeReadAscii(uintptr_t address, char* out, int max) {
		__try {
			int i = 0;
			for (; i < max; ++i) {
				const char c = ((volatile char*)address)[i];
				if (c == '\0') {
					break;
				}
				if (c < 0x20 || c > 0x7E) {
					return -1;
				}
				out[i] = c;
			}
			out[i] = '\0';
			return (i > 0 && i < max) ? i : -1;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return -1;
		}
	}

	// Classify a candidate pointer by its vtable, or nullptr if it is not an
	// instance of a class we hooked.
	const std::string* identifyObject(uintptr_t candidate) {
		if (candidate < 0x10000 || candidate > 0x7FFEFFFF) {
			return nullptr;
		}

		uint32_t vptr = 0;
		InterlockedExchange(&g_probing, 1);
		const bool ok = safeRead32(candidate, &vptr);
		InterlockedExchange(&g_probing, 0);
		if (!ok) {
			return nullptr;
		}

		for (const auto& entry : g_classVtables) {
			if (entry.first == vptr) {
				return &entry.second;
			}
		}
		return nullptr;
	}

	// -----------------------------------------------------------------------
// Stage 2: the archive entry-name index, shared by the launcher.
//
// The launcher has already parsed every .afa, so it writes the entry names out
// for us. A string found inside a sound object is only reported once it matches
// a real entry, because "looks like a filename" is a weak signal: pointer data
// and Japanese display labels score just as well, and an unverified match is
// worse than no output at all.
// -----------------------------------------------------------------------

struct IndexRecord {
	uint64_t hash;
	uint32_t archiveOffset; // into g_indexText
	uint32_t nameOffset;    // into g_indexText
	uint32_t nameLength;
};

std::vector<char> g_indexText;
std::vector<IndexRecord> g_index; // sorted by hash
bool g_indexLoaded = false;

uint64_t fnv1a(const void* data, size_t length) {
	const uint8_t* p = (const uint8_t*)data;
	uint64_t h = 1469598103934665603ULL;
	for (size_t i = 0; i < length; ++i) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

// List every module loaded into the game process.
//
// The engine registers "AFALoader" and "KiwiSoundEngine" as plugins by name, and
// everything found so far in the main executable concerns only opening an archive
// file. If the code that resolves an archive member lives in a plugin, it is not
// in Evenicle.exe at all, and hooking it means addressing it by module rather
// than through RTTI. This settles that question directly instead of by
// inference from strings.
void logLoadedModules() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	MODULEENTRY32 entry{};
	entry.dwSize = sizeof(entry);
	if (!Module32First(snapshot, &entry)) {
		CloseHandle(snapshot);
		return;
	}

	int count = 0;
	do {
		char name[MAX_PATH] = {};
		WideCharToMultiByte(CP_ACP, 0, entry.szModule, -1, name, MAX_PATH - 1, nullptr, nullptr);

		// Only non-system modules are interesting; the base set is always there.
		const bool isSystem = entry.szExePath[1] == L':' &&
			(entry.szExePath[2] == L'W' || entry.szExePath[2] == L'w') &&
			(entry.szExePath[3] == L'i' || entry.szExePath[3] == L'I');
		if (!isSystem) {
			logInfo("  module %-34s base=%p size=0x%X",
				name, (void*)entry.modBaseAddr, entry.modBaseSize);
			++count;
		}
	} while (Module32Next(snapshot, &entry));

	logInfo("AudioTracker: %d non-system modules loaded.", count);
	CloseHandle(snapshot);
}

// Enumerate modules once the game has finished starting.
//
// Called from a background thread rather than from init(): init() runs inside
// DllMain, i.e. before the game's own start-up code has executed, so at that
// point nothing but the core system libraries are loaded and the list says
// nothing useful about where the engine's plugin code actually lives.
void moduleSnapshotThread() {
	Sleep(8000);

	logInfo("AudioTracker: module list 8s after start-up:");
	logLoadedModules();
}

void loadEntryIndex() {
	wchar_t pathBuf[MAX_PATH] = {};
	const DWORD copied = GetEnvironmentVariableW(
		L"ALICE_SOUNDFETCHER_INDEX", pathBuf, MAX_PATH);
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
				record.hash = fnv1a(&g_indexText[record.nameOffset], record.nameLength);
				g_index.push_back(record);
			}
		}
		lineStart = lineEnd + 1;
	}

	std::sort(g_index.begin(), g_index.end(),
		[](const IndexRecord& a, const IndexRecord& b) { return a.hash < b.hash; });

	g_indexLoaded = true;
	logInfo("AudioTracker: entry index loaded: %zu names, %zu bytes.",
		g_index.size(), g_indexText.size());
}

// Look a raw byte string up. Returns true and fills the archive name when the
// string is a real entry.
bool lookupEntryName(const uint8_t* bytes, int length, std::string& archiveOut) {
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
	if (lo >= g_index.size() || g_index[lo].hash != h) {
		return false;
	}

	// The hash matched; confirm the bytes, because a hash collision must never be
	// reported as a confirmed match.
	for (size_t i = lo; i < g_index.size() && g_index[i].hash == h; ++i) {
		const IndexRecord& r = g_index[i];
		if (r.nameLength != (uint32_t)length) {
			continue;
		}
		if (memcmp(&g_indexText[r.nameOffset], bytes, (size_t)length) == 0) {
			const char* start = &g_indexText[r.archiveOffset];
			size_t archiveLen = r.nameOffset - r.archiveOffset;
			if (archiveLen > 0 && start[archiveLen - 1] == '\t') {
				--archiveLen;
			}
			archiveOut.assign(start, archiveLen);
			return true;
		}
	}
	return false;
}

// -----------------------------------------------------------------------
// Hooking the engine's string comparisons.
//
// The archive index is searched by name and that search ends in a string
// comparison. Hooking the comparison sidesteps everything that made the vtable
// approach miss: there is no object layout to guess and no need to know which
// function performs the lookup. Any comparison whose argument is a real archive
// entry name *is* the lookup.
//
// The hook goes on the import address table, not on the function prologue. An
// IAT entry is a data pointer, so overwriting it touches no code, needs no
// relocation of displaced instructions, and is trivially reversible.
// -----------------------------------------------------------------------

// Defined further down with the rest of the Shift-JIS helpers; declared here so
// the comparison hooks can use them without the file having to be reordered
// around this block.
int shiftJisRunLength(const uint8_t* p, int max);
int safeShiftJisRunLength(uintptr_t address, char* out, int max);
void escapeToLog(char* out, size_t outCap, const uint8_t* p, int len);

using CompareFn = int(__cdecl*)(const char*, const char*);

CompareFn g_compareOriginals[kMaxCompareHooks] = {};
int g_compareHookCount = 0;

// Report a comparison argument if it names a real archive entry.
//
// Only ever called with a pointer that came out of the game's own data, so the
// read is guarded and the probing flag is raised while it happens.
void reportCompareArgument(const char* value, const char* where, int slot) {
	if (!value || !g_indexLoaded) {
		return;
	}
	const uintptr_t candidate = (uintptr_t)value;
	if (candidate < 0x10000 || candidate > 0x7FFEFFFF) {
		return;
	}

	char raw[512];
	InterlockedExchange(&g_probing, 1);
	const int len = safeShiftJisRunLength(candidate, raw, (int)sizeof(raw) - 1);
	InterlockedExchange(&g_probing, 0);

	if (len < 3) {
		return;
	}

	std::string archive;
	if (!lookupEntryName((const uint8_t*)raw, len, archive)) {
		return;
	}

	char text[1024];
	escapeToLog(text, sizeof(text), (const uint8_t*)raw, len);
	logInfo("MATCH %s slot=%d name=\"%s\" [%s]", where, slot, text, archive.c_str());
}

int __cdecl hookedCompare0(const char* a, const char* b) {
	reportCompareArgument(a, "cmp0", 0);
	reportCompareArgument(b, "cmp0", 1);
	return g_compareOriginals[0](a, b);
}
int __cdecl hookedCompare1(const char* a, const char* b) {
	reportCompareArgument(a, "cmp1", 0);
	reportCompareArgument(b, "cmp1", 1);
	return g_compareOriginals[1](a, b);
}
int __cdecl hookedCompare2(const char* a, const char* b) {
	reportCompareArgument(a, "cmp2", 0);
	reportCompareArgument(b, "cmp2", 1);
	return g_compareOriginals[2](a, b);
}
int __cdecl hookedCompare3(const char* a, const char* b) {
	reportCompareArgument(a, "cmp3", 0);
	reportCompareArgument(b, "cmp3", 1);
	return g_compareOriginals[3](a, b);
}

CompareFn g_compareWrappers[kMaxCompareHooks] = {
	hookedCompare0, hookedCompare1, hookedCompare2, hookedCompare3
};

// Import names whose signature is (const char*, const char*).
const char* const kCompareImports[] = {
	"strcmp", "_stricmp", "strcmpi", "lstrcmpA", "lstrcmpiA"
};

void installCompareHooks() {
	const auto* base = (const uint8_t*)g_moduleBase;
	const auto* dos = (const IMAGE_DOS_HEADER*)base;
	const auto* nt = (const IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
	const IMAGE_DATA_DIRECTORY* dir =
		&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!dir->VirtualAddress || !dir->Size) {
		return;
	}

	const auto* descriptor = (const IMAGE_IMPORT_DESCRIPTOR*)(base + dir->VirtualAddress);

	for (; descriptor->Name; ++descriptor) {
		// Both thunks are required. A descriptor with OriginalFirstThunk == 0 is a
		// bound import, and walking the name table would then start at the MZ
		// header and run off into unmapped memory -- which is exactly how this
		// loop first crashed.
		if (!descriptor->FirstThunk || !descriptor->OriginalFirstThunk) {
			continue;
		}

		// FirstThunk is the import address table: the writable copy of the bindings,
		// which is exactly what has to be patched. OriginalFirstThunk is the
		// read-only name table and is walked alongside it only to recover names.
		IMAGE_THUNK_DATA* thunk =
			(IMAGE_THUNK_DATA*)(void*)(base + descriptor->FirstThunk);
		const auto* names =
			(const IMAGE_THUNK_DATA*)(base + descriptor->OriginalFirstThunk);

		for (int guard = 0; guard < 4096; ++guard) {
			if (!thunk->u1.Function || !names->u1.AddressOfData) {
				break;
			}
			if (thunk->u1.Function == names->u1.Function) {
				++thunk;
				++names;
				continue; // ordinal import; no name to match on
			}

			const auto* hint =
				(const IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData);
			const char* importName = (const char*)hint->Name;

			for (size_t want = 0; want < sizeof(kCompareImports) / sizeof(kCompareImports[0]); ++want) {
				if (strcmp(importName, kCompareImports[want]) != 0) {
					continue;
				}
				if (g_compareHookCount >= kMaxCompareHooks) {
					return;
				}

				const int slot = g_compareHookCount++;
				g_compareOriginals[slot] =
					reinterpret_cast<CompareFn>(thunk->u1.Function);

				// Make the page writable, swap the slot, restore protection.
				DWORD oldProtect = 0;
				if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
						PAGE_READWRITE, &oldProtect)) {
					--g_compareHookCount;
					return;
				}
				thunk->u1.Function =
					reinterpret_cast<ULONG_PTR>(g_compareWrappers[slot]);
				FlushInstructionCache(GetCurrentProcess(), &thunk->u1.Function,
					sizeof(thunk->u1.Function));
				VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
					oldProtect, &oldProtect);

				logInfo("AudioTracker: hooked import %s -> wrapper %d", importName, slot);
				return; // one hook per imported name is enough
			}
		}
	}
}

// -----------------------------------------------------------------------
// Hooking the engine's own string assignment.
//
// The executable imports no CRT string comparison at all -- no strcmp, _stricmp,
// strcmpi, lstrcmpA, strncmp, memcmp or wcscmp appears anywhere in the import
// table -- so there is nothing of that kind to hook. What it does have is
// 0x00460509, its own std::string::assign(const char*):
//
//   00460509  mov eax, 005821C9        ; allocator
//   00460518  mov edi, ecx             ; this
//   0046051d  mov ebx, [ebp+8]         ; source
//   00460528  mov [edi+14h], 0Fh      ; _Myres = 15, so small-string
//   00460534  <strlen loop>
//   00460549  cmp eax, 10h             ; capacity < 16 -> keep it inline
//   00460558  call 00526480            ; memcpy
//   00460560  mov byte [esi+ebx], 0
//
// Every name the engine holds -- including an archive entry name -- has to pass
// through this function, so validating the source argument against the index
// needs no knowledge of any object layout at all. Its first instruction is
// exactly five bytes, so it relocates cleanly: overwrite it with a jump, and
// replay the displaced bytes inside the stub.
// -----------------------------------------------------------------------

// Default target: the std::string::assign identified above, as an RVA so it
// survives a different load address. Override with ALICE_SOUNDFETCHER_ASSIGNHOOK
// (decimal RVA) to retarget without a rebuild.
constexpr uintptr_t kStringAssignRva = 0x00060509;

using AssignHookFn = void(__cdecl*)(const char* source);
AssignHookFn g_stringAssignOriginal = nullptr;

void __cdecl onAssignString(const char* source) {
	if (g_indexLoaded && source) {
		const uintptr_t candidate = (uintptr_t)source;
		if (candidate >= 0x10000 && candidate <= 0x7FFEFFFF) {
			char raw[512];
			InterlockedExchange(&g_probing, 1);
			const int len = safeShiftJisRunLength(candidate, raw, (int)sizeof(raw) - 1);
			InterlockedExchange(&g_probing, 0);

			if (len >= 3) {
				std::string archive;
				if (lookupEntryName((const uint8_t*)raw, len, archive)) {
					char text[1024];
					escapeToLog(text, sizeof(text), (const uint8_t*)raw, len);
					logInfo("MATCH assign name=\"%s\" [%s]", text, archive.c_str());
				}
			}
		}
	}
}

// Byte offsets are spelled out and each entry carries its own length comment
// because every one of these was wrong at least once: `FF 74 24 14` is four
// bytes, not three, and getting that wrong silently shifts the call and the
// jump that follow it, which sends execution into the middle of the stub.
constexpr size_t kAssignStubSize = 32;
constexpr size_t kAssignStubSaveBegin = 0;   // 9C 50 51 52                     4 bytes
constexpr size_t kAssignStubPushArg = 4;     // FF 74 24 14                     4 bytes
constexpr size_t kAssignStubCall = 8;        // E8 <rel32>                      5 bytes
constexpr size_t kAssignStubClean = 13;      // 83 C4 04                        3 bytes
constexpr size_t kAssignStubRestore = 16;    // 5A 59 58 9D                     4 bytes
constexpr size_t kAssignStubDisplaced = 20;  // B8 <imm32>                      5 bytes
constexpr size_t kAssignStubJmp = 25;        // E9 <rel32>                      5 bytes
static_assert(kAssignStubJmp + 5 <= kAssignStubSize, "assign stub overruns");

void installAssignStringHook() {
	if (!g_moduleBase) {
		return;
	}

	uintptr_t rva = kStringAssignRva;
	wchar_t override[16] = {};
	if (GetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_ASSIGNHOOK",
			override, (DWORD)(sizeof(override) / sizeof(override[0]))) > 0) {
		rva = (uintptr_t)_wtoi(override);
	}

	uint8_t* target = (uint8_t*)(g_moduleBase + rva);
	if (!isExecutable((uintptr_t)target)) {
		logInfo("AudioTracker: string-assign hook target RVA 0x%X is not executable.", rva);
		return;
	}

	// Refuse anything whose opening instruction is not exactly the five bytes we
	// know how to replay. A different function at the same RVA, or one that
	// starts with a relative branch, must not be patched on a guess.
	uint8_t original[5] = {};
	memcpy(original, target, sizeof(original));
	if (original[0] != 0xB8) { // mov eax, imm32
		logInfo("AudioTracker: string-assign hook skipped: opening byte 0x%02X "
			"is not the expected `mov eax, imm32`.", original[0]);
		return;
	}
	const uint32_t displacedImmediate = (uint32_t)original[1] |
		((uint32_t)original[2] << 8) |
		((uint32_t)original[3] << 16) |
		((uint32_t)original[4] << 24);

	uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, kAssignStubSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!stub) {
		return;
	}
	memset(stub, 0xCC, kAssignStubSize);

	stub[kAssignStubSaveBegin] = 0x9C;     // pushfd
	stub[kAssignStubSaveBegin + 1] = 0x50; // push eax
	stub[kAssignStubSaveBegin + 2] = 0x51; // push ecx
	stub[kAssignStubSaveBegin + 3] = 0x52; // push edx

	// [esp+20h] after the four saves is the caller's first stack argument, which
	// for std::string::assign is the source char*.
	stub[kAssignStubPushArg] = 0xFF;
	stub[kAssignStubPushArg + 1] = 0x74;
	stub[kAssignStubPushArg + 2] = 0x24;
	stub[kAssignStubPushArg + 3] = 0x14;

	const uintptr_t onAssign = (uintptr_t)&onAssignString;
	stub[kAssignStubCall] = 0xE8;
	const int32_t callRel = (int32_t)(onAssign - (uintptr_t)(stub + kAssignStubCall + 5));
	memcpy(stub + kAssignStubCall + 1, &callRel, sizeof(callRel));

	stub[kAssignStubClean] = 0x83;                 // add esp, 4
	stub[kAssignStubClean + 1] = 0xC4;
	stub[kAssignStubClean + 2] = 0x04;

	stub[kAssignStubRestore] = 0x5A;     // pop edx
	stub[kAssignStubRestore + 1] = 0x59; // pop ecx
	stub[kAssignStubRestore + 2] = 0x58; // pop eax
	stub[kAssignStubRestore + 3] = 0x9D; // popfd

	// Replay the instruction we displaced, then resume at the next one.
	stub[kAssignStubDisplaced] = 0xB8;
	memcpy(stub + kAssignStubDisplaced + 1, &displacedImmediate, 4);

	stub[kAssignStubJmp] = 0xE9;
	const int32_t resumeRel = (int32_t)((uintptr_t)(target + 5) -
		(uintptr_t)(stub + kAssignStubJmp + 5));
	memcpy(stub + kAssignStubJmp + 1, &resumeRel, sizeof(resumeRel));

	FlushInstructionCache(GetCurrentProcess(), stub, kAssignStubSize);

	// Publish the entry point so the jmp written below lands in the stub.
	DWORD oldProtect = 0;
	if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		VirtualFree(stub, 0, MEM_RELEASE);
		logInfo("AudioTracker: VirtualProtect on the assign hook failed (%lu).",
			GetLastError());
		return;
	}

	// E9 rel32 measured from the end of the instruction, i.e. target + 5.
	target[0] = 0xE9;
	const int32_t entryRel = (int32_t)((uintptr_t)stub - (uintptr_t)(target + 5));
	memcpy(target + 1, &entryRel, sizeof(entryRel));
	FlushInstructionCache(GetCurrentProcess(), target, 5);
	VirtualProtect(target, 5, oldProtect, &oldProtect);

	g_stringAssignOriginal = (AssignHookFn)target; // unusable after patching; kept for clarity

	logInfo("AudioTracker: hooked std::string::assign at %p -> stub %p",
		target, stub);

	// Print the emitted bytes so the encoding can be checked by eye rather than
	// inferred from a crash.
	{
		char line[256];
		int n = snprintf(line, sizeof(line), "  assign-stub bytes:");
		for (size_t i = 0; i < kAssignStubSize && n > 0 && n < (int)sizeof(line) - 4; ++i) {
			n += snprintf(line + n, sizeof(line) - (size_t)n, " %02X", stub[i]);
		}
		if (n > 0) {
			logInfo("%s", line);
		}
	}
}

// Length of the printable Shift-JIS run starting at p, capped at max.
	//
	// Archive entry names in these games are raw Shift-JIS (CP932), so an
	// ASCII-only scanner reports nothing at all. CP932 two-byte characters have
	// lead bytes 0x81-0x9F *or* 0xE0-0xFC, and the trail byte is 0x40-0x7E or
	// 0x80-0xFC. Accepting only a handful of lead bytes truncates names at the
	// first hiragana/katakana character, which is what happened to
	// "Attack/Defense.ogg" -- it was being reported as "ttack/Defense o".
	int shiftJisRunLength(const uint8_t* p, int max) {
		int i = 0;
		int repeat = 1;
		while (i < max && p[i] != 0x00) {
			const uint8_t c = p[i];

			// Four identical bytes in a row is not text. 0xDD in particular is both
			// a legitimate half-width katakana byte and the value Windows fills
			// freshly committed heap with, so uninitialised memory reads as a long
			// run of "characters" and was being reported as a 44-character string.
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

	// Copy from a possibly-unmapped address.
	//
	// This lives in its own function because a function containing __try cannot
	// also hold objects that need unwinding, and the call site deals in
	// std::string. Returns false when the read faulted.
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
	// The unguarded version of this walked off into unmapped memory and took the
	// game down with it. Any read of a value taken out of an object field has to
	// be protected, because such a field is arbitrary data as far as this code is
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

	// How much a candidate run looks like an archive entry name.
	//
	// Widening the Shift-JIS ranges made the scanner accept so much that plain
	// pointer data read as "text" and the longest run was no longer the right
	// pick. An archive entry name is recognisable by shape: directory separators,
	// an extension, and plenty of ASCII. Scoring on that beats picking by length.
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

	// Copy a run out with every non-ASCII byte escaped.
	//
	// The names are Shift-JIS and the log is read back as plain bytes, so writing
	// them raw produces mojibake in any console whose code page is not 932. The
	// escaped form is unambiguous and can be matched byte-for-byte against the
	// names reported by `alice ar list`.
	void escapeToLog(char* out, size_t outCap, const uint8_t* p, int len) {
		size_t used = 0;
		for (int i = 0; i < len && used + 5 < outCap; ++i) {
			const uint8_t c = p[i];
			if (c >= 0x20 && c < 0x7F) {
				out[used++] = (char)c;
			} else {
				used += (size_t)snprintf(out + used, outCap - used, "\\x%02X", c);
			}
		}
		out[used] = '\0';
	}

	bool isSoundDataClass(const std::string& name) {
		return name.rfind("CSoundData", 0) == 0;
	}

	// Classes whose instances get a one-off memory dump.
	//
	// The decoded sound object is the obvious candidate, but the decoded data
	// itself carries no name field, so the player and channel objects are dumped
	// as well: whichever of them was handed an archive entry name is where the
	// name actually is.
	bool isDumpClass(const std::string& name) {
		return isSoundDataClass(name) ||
			name == "CSoundPlayer" ||
			name == "CSoundChannel" ||
			name == "CKiwiSoundEngine";
	}

	// Claim an (object, slot) pair for dumping. Returns true only the first time.
	//
	// Keyed on the slot as well as the object on purpose. Claiming once per object
	// caught it during construction, when the memory still belonged to a previous
	// occupant of the pool: a vtable pointer already saying CSoundDataOgg while
	// the rest of the block still held an unrelated texture name and script text.
	// Claiming per slot instead samples the object at each stage of its lifecycle,
	// which is where the entry name actually gets written.
	//
	// The compare-and-swap must be seeded with the value that was actually read.
	// Seeding it with the key instead looks tidier but is wrong: the exchange only
	// stores when *slot already equals the comparand, so on a fresh zeroed slot the
	// store is skipped and nothing is ever marked as seen.
	bool claimObjectDump(uintptr_t obj, int slot) {
		if (obj == 0) {
			return false;
		}
		const uint32_t key = (uint32_t)obj ^ (uint32_t)((slot + 1) * 0x9E3779B1u);
		const size_t index = ((key >> 3) ^ (key >> 17)) & (kSeenObjectCount - 1);
		const LONG current = g_seenObjects[index];
		if (current == (LONG)key) {
			return false; // already dumped
		}
		const LONG previous =
			InterlockedCompareExchange(&g_seenObjects[index], (LONG)key, current);
		return previous == current; // we won the race
	}

	// Resolve which classes to hook.
	//
	// Defaults to every audio class, but the set is overridable through
	// ALICE_SOUNDFETCHER_CLASSES (comma separated). Being able to hook exactly one
	// class per run is what makes it practical to find out which single class is
	// responsible for a crash, without a rebuild for every experiment.
	std::vector<std::string> resolveClassList() {
		std::vector<std::string> result;

		wchar_t buffer[1024] = {};
		const DWORD copied = GetEnvironmentVariableW(
			L"ALICE_SOUNDFETCHER_CLASSES", buffer, (DWORD)(sizeof(buffer) / sizeof(buffer[0])));

		if (copied == 0 || copied >= sizeof(buffer) / sizeof(buffer[0])) {
			for (int i = 0; i < kAudioClassCount; ++i) {
				result.emplace_back(kAudioClasses[i]);
			}
			return result;
		}

		std::string all(buffer, buffer + copied);
		size_t start = 0;
		while (start <= all.size()) {
			const size_t comma = all.find(',', start);
			const size_t end = (comma == std::string::npos) ? all.size() : comma;
			std::string name = all.substr(start, end - start);
			while (!name.empty() && name.front() == ' ') { name.erase(name.begin()); }
			while (!name.empty() && name.back() == ' ') { name.pop_back(); }
			if (!name.empty()) {
				result.push_back(name);
			}
			if (comma == std::string::npos) {
				break;
			}
			start = comma + 1;
		}
		return result;
	}

} // namespace

// ---------------------------------------------------------------------------
// C-ABI surface shared with the assembly stubs.
//
// Defined at global scope with C linkage on purpose: anything inside an
// anonymous namespace gets internal linkage and the assembler cannot bind it.
// ---------------------------------------------------------------------------

namespace AudioTrackerInternals {
	void timestamp(char* out, size_t cap) { logTimestamp(out, cap); }
	void write(const char* line) { writeLogLine(line); }
	const char* className(int id) { return g_targets[id].className.c_str(); }
	int slotOf(int id) { return g_targets[id].slot; }
}

// ---------------------------------------------------------------------------
// Forwarding stub, one per slot, emitted into RWX memory.
//
// Layout (36 bytes, padded to 48 so each stub keeps 16-byte alignment):
//
//   9C              pushfd
//   50 51 52        push eax / push ecx / push edx
//   8B C8           mov  eax, ecx           ; `this`, implicit for thiscall
//   8B 54 24 14     mov  edx, [esp+20h]     ; first stack word above retaddr
//   8B 4C 24 18     mov  ecx, [esp+24h]     ; second stack word
//   68 <id>         push id
//   51 52 50        push sp1 / push sp0 / push this
//   E8 <rel32>      call AudioTrackerLogHook   (callee pops the four arguments)
//   5A 59 58        pop edx / pop ecx / pop eax
//   9D              popfd
//   E9 <rel32>      jmp  original
//
// The pushes are right-to-left, matching __stdcall: the first declared parameter
// is pushed last and so ends up lowest in the callee frame. Getting this backwards
// silently shifts every argument by one slot, which looks like garbage object
// pointers rather than an obvious failure.
//
// Why this shape rather than the earlier `push slot / call trampoline / jmp`:
//
//   * The stub id is passed as an ordinary __stdcall argument, so it no longer has
//     to be smuggled through the stack. The previous version pushed the index and
//     read `this`/arg1 from fixed offsets that only lined up because of the exact
//     number of pushes, so every argument read depended on that count.
//   * Nothing is left on the stack when the original function runs. ESP is back to
//     its entry value before the tail jump, so a __stdcall callee still finds its
//     arguments exactly where it expects them.
//   * No global variables are involved. The previous version wrote `this`/arg1 into
//     plain globals and read them back from the logger, which two game threads
//     entering the audio path concurrently could interleave into a mismatched pair.
// ---------------------------------------------------------------------------

namespace {

	// Byte offsets inside a stub, shared by the emitter and the doc comment.
	constexpr size_t kStubSize = 48;

	constexpr size_t kOffSaveBegin = 0;   // 9C 50 51 52
	constexpr size_t kOffSelf = 4;        // 8B C8
	constexpr size_t kOffSp0 = 6;         // 8B 54 24 14
	constexpr size_t kOffSp1 = 10;        // 8B 4C 24 18
	constexpr size_t kOffPushId = 14;     // 68 <imm32>
	constexpr size_t kOffPushSp1 = 19;    // 51
	constexpr size_t kOffPushSp0 = 20;    // 52
	constexpr size_t kOffPushSelf = 21;   // 50
	constexpr size_t kOffCall = 22;       // E8 <rel32>
	constexpr size_t kOffRestore = 27;    // 5A 59 58 9D
	constexpr size_t kOffJmp = 31;        // E9 <rel32>

} // namespace

extern "C" void __stdcall AudioTrackerLogHook(void* self, void* sp0, void* sp1, int id);

// ---------------------------------------------------------------------------
// Exception diagnostics.
//
// An access violation inside the game is hard to attribute by hand: the faulting
// module is reported as "unknown" for any address inside our stub arena, because
// VirtualAlloc'd pages belong to no module. This handler records the faulting
// address and says explicitly whether it landed in one of our stubs, which turns
// "the game crashed after we hooked it" into a definitive answer.
// ---------------------------------------------------------------------------

namespace {

	PVOID g_vehHandle = nullptr;

	LONG CALLBACK trackerVeh(PEXCEPTION_POINTERS info) {
		if (!info || !info->ExceptionRecord) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		const DWORD code = info->ExceptionRecord->ExceptionCode;

		// Only the faults that a bad stub would produce are interesting; letting the
		// handler chatter about every handled exception the engine throws internally
		// would bury them.
		const bool interesting =
			code == EXCEPTION_ACCESS_VIOLATION ||
			code == EXCEPTION_ILLEGAL_INSTRUCTION ||
			code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
			code == EXCEPTION_PRIV_INSTRUCTION;

		if (!interesting) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// Access violations raised on purpose while probing candidate argument
		// pointers are expected and must not be reported as faults; otherwise
		// routine probing buries the real ones.
		if (g_probing) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		const uintptr_t fault = (uintptr_t)info->ExceptionRecord->ExceptionAddress;
		const bool inStubs =
			g_stubBase != nullptr &&
			fault >= (uintptr_t)g_stubBase &&
			fault < (uintptr_t)g_stubBase + (uintptr_t)g_stubCount * kStubSize;

		const int stubId = inStubs ? (int)((fault - (uintptr_t)g_stubBase) / kStubSize) : -1;

		char line[400];
		int n = snprintf(line, sizeof(line),
			"FAULT code=0x%08lX addr=%p inStub=%d stubId=%d target=%s/%d",
			(unsigned long)code, (void*)fault, inStubs ? 1 : 0, stubId,
			(stubId >= 0 && stubId < (int)g_targets.size()) ? g_targets[stubId].className.c_str() : "?",
			(stubId >= 0 && stubId < (int)g_targets.size()) ? g_targets[stubId].slot : -1);
		if (n > 0 && info->ContextRecord) {
			n += snprintf(line + n, sizeof(line) - (size_t)n,
				" eip=%p esp=%p ebp=%p eax=%p ecx=%p edx=%p",
				(void*)info->ContextRecord->Eip, (void*)info->ContextRecord->Esp,
				(void*)info->ContextRecord->Ebp, (void*)info->ContextRecord->Eax,
				(void*)info->ContextRecord->Ecx, (void*)info->ContextRecord->Edx);

			// When the fault address is the object pointer rather than an
			// instruction, the interesting question is who called it. The return
			// address on top of the frame identifies the call site, so the stack is
			// dumped and each word classified as game code, our stub, or other.
			const uintptr_t sp = info->ContextRecord->Esp;
			for (int i = 0; i < 6 && n > 0 && n < (int)sizeof(line) - 24; ++i) {
				uintptr_t word = 0;
				__try {
					word = *(const uintptr_t*)(sp + (uintptr_t)i * sizeof(uintptr_t));
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					break;
				}
				const char* kind = "other";
				if (inStubs && word >= (uintptr_t)g_stubBase &&
					word < (uintptr_t)g_stubBase + (uintptr_t)g_stubCount * kStubSize) {
					kind = "STUB";
				} else if (word >= g_moduleBase && word < g_moduleBase + g_moduleSize) {
					kind = isExecutable(word) ? "game-code" : "game-data";
				}
				n += snprintf(line + n, sizeof(line) - (size_t)n,
					" [%d]=%08lX/%s", i, (unsigned long)word, kind);
			}
		}
		if (n > 0) {
			logInfo("%s", line);
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

} // namespace

void AudioTracker::installExceptionDiagnostics() {
	if (g_vehHandle == 0) {
		g_vehHandle = AddVectoredExceptionHandler(1, trackerVeh);
	}
}

// ---------------------------------------------------------------------------
// AudioTracker
// ---------------------------------------------------------------------------

const wchar_t* AudioTracker::logPath() {
	static wchar_t cached[MAX_PATH] = {};
	if (cached[0] == L'\0') {
		GetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_LOG", cached, MAX_PATH);
	}
	return cached;
}

int AudioTracker::slotCount() {
	return g_slotCount.load();
}

// Called from a forwarding stub on one of the game's own threads, inside an audio
// call path. Everything it needs arrives as arguments, so nothing is read from
// shared state and two threads cannot mix up each other's values.
extern "C" void __stdcall AudioTrackerLogHook(void* self, void* sp0, void* sp1, int id) {
	if (id < 0 || id >= (int)g_targets.size()) {
		return;
	}
	const HookTarget& target = g_targets[id];

	// Quiet mode still counts, but does no formatting, no locking and no file
	// I/O. This separates two very different failure modes that otherwise look
	// identical from the outside: a forwarding stub that corrupts the engine, and
	// a hook that merely does too much work (CRT formatting, a global lock, file
	// I/O) on a game thread that may be running under the loader lock or during
	// early start-up.
	if (g_quiet) {
		InterlockedIncrement(&g_callCounts[id]);
		return;
	}

	char stamp[32];
	AudioTrackerInternals::timestamp(stamp, sizeof(stamp));

	// Classify the incoming arguments before formatting, so the event line shows
	// what the values actually are rather than leaving that to interpretation.
	const std::string* sp0Class = identifyObject((uintptr_t)sp0);
	const std::string* sp1Class = identifyObject((uintptr_t)sp1);

	char line[320];
	int written;
	if (sp0Class || sp1Class) {
		written = snprintf(line, sizeof(line),
			"%s CALL %s slot=%d this=%p sp0=%s(%p) sp1=%s(%p)\r\n",
			stamp, target.className.c_str(), target.slot, self,
			sp0Class ? sp0Class->c_str() : "?", sp0,
			sp1Class ? sp1Class->c_str() : "?", sp1);
	} else {
		written = snprintf(line, sizeof(line),
			"%s CALL %s slot=%d this=%p sp0=%p sp1=%p\r\n",
			stamp, target.className.c_str(), target.slot, self, sp0, sp1);
	}
	if (written <= 0) {
		return;
	}

	AudioTrackerInternals::write(line);

	// A sound data object is what we ultimately care about, so dump its memory
	// once per instance. The layout is deliberately *not* assumed here: reading
	// the raw bytes is how the layout gets established in the first place, and
	// guessing an offset now would risk printing a plausible-looking but wrong
	// filename, which is worse than printing nothing.
	//
	// Before any of that: the entry name may simply arrive as a call argument,
	// as a bare pointer to a Shift-JIS string. CSoundFileAFA is handed the member
	// name to resolve, so that is the most direct place a confirmed name can be
	// obtained -- and it needs no layout knowledge at all.
	{
		const void* argValues[2] = { sp0, sp1 };
		for (int a = 0; a < 2; ++a) {
			const uintptr_t candidate = (uintptr_t)argValues[a];
			if (candidate < 0x10000) {
				continue;
			}

			char raw[512];
			InterlockedExchange(&g_probing, 1);

			const int len = safeShiftJisRunLength(candidate, raw, (int)sizeof(raw) - 1);
			if (len >= 3) {
				std::string archive;
				char text[1024];

				// Exact match first: the engine may pass the bare member name.
				if (lookupEntryName((const uint8_t*)raw, len, archive)) {
					escapeToLog(text, sizeof(text), (const uint8_t*)raw, len);
					logInfo("PLAY %s slot=%d arg%d name=\"%s\" [%s]",
						target.className.c_str(), target.slot, a, text, archive.c_str());
				}
				else {
					// Otherwise the name may be the tail of a path such as
					// "EvenicleVoice/10001.opus"; retry on the last component.
					int lastSlash = -1;
					for (int i = 0; i < len; ++i) {
						if (raw[i] == '/') {
							lastSlash = i;
						}
					}
					if (lastSlash >= 0) {
						const uint8_t* tail = (const uint8_t*)raw + lastSlash + 1;
						const int tailLen = len - lastSlash - 1;
						if (tailLen >= 3 && lookupEntryName(tail, tailLen, archive)) {
							escapeToLog(text, sizeof(text), tail, tailLen);
							logInfo("PLAY %s slot=%d arg%d name=\"%s\" [%s]",
								target.className.c_str(), target.slot, a,
								text, archive.c_str());
						}
					}
				}
			}

			InterlockedExchange(&g_probing, 0);
		}
	}
	// The object of interest is usually `this` rather than an argument -- a call
	// like CSoundDataOgg::SomeMethod() *is* operating on the sound object. The
	// arguments are still checked, because a sound object can equally arrive as a
	// parameter to a player or channel method.
	const std::string* dumpClass[3] = { nullptr, sp0Class, sp1Class };
	const void* dumpValue[3] = { nullptr, sp0, sp1 };
	if (isDumpClass(target.className)) {
		dumpClass[0] = &target.className;
		dumpValue[0] = self;
	}

	for (int i = 0; i < 3; ++i) {
		if (!dumpClass[i] || !isDumpClass(*dumpClass[i])) {
			continue;
		}
		if (!claimObjectDump((uintptr_t)dumpValue[i], target.slot)) {
			continue;
		}

		const uintptr_t obj = (uintptr_t)dumpValue[i];

		// Every read below deliberately touches addresses taken from object
		// fields, which are not guaranteed to be mapped. The whole block is
		// therefore marked as probing: the failures are expected, they are caught
		// by the __except in each helper, and the vectored handler must not report
		// them as faults in the game. The flag has to stay set for the entire
		// block, including the field loop at the end -- clearing it early lets
		// routine probing bury the real faults.
		InterlockedExchange(&g_probing, 1);

		uint8_t bytes[256] = {};
		safeReadMemory(bytes, obj, sizeof(bytes));

		char hex[1024];
		int n = snprintf(hex, sizeof(hex), "OBJ %s %p bytes:",
			dumpClass[i]->c_str(), dumpValue[i]);
		for (int k = 0; k < 256 && n > 0 && n < (int)sizeof(hex) - 4; ++k) {
			n += snprintf(hex + n, sizeof(hex) - (size_t)n, " %02X", bytes[k]);
		}

		char ascii[33];
		for (int k = 0; k < 32; ++k) {
			ascii[k] = (bytes[k] >= 0x20 && bytes[k] < 0x7F) ? (char)bytes[k] : '.';
		}
		ascii[32] = '\0';

		// Hunt for the entry name inside the bytes already read, rather than by probing
		// further memory. Scanning a local buffer cannot fault at all, so the
		// search is both safer and faster than chasing pointer fields.
		//
		// Every plausible run is tested against the index, and only confirmed
		// matches are reported as names. Scoring alone accepted "kimg_logo.png",
		// which looks entirely real and exists nowhere in this game's archives.
		int bestOffset = -1, bestLength = 0, bestScore = 0;
		int matches = 0;

		for (int k = 0; k + 3 <= 256; ++k) {
			const int len = shiftJisRunLength(bytes + k, 256 - k);
			if (len < 3) {
				continue;
			}

			std::string archive;
			if (lookupEntryName(bytes + k, len, archive)) {
				char escaped[1024];
				escapeToLog(escaped, sizeof(escaped), bytes + k, len);
				logInfo("NAME %s %p +0x%02X len=%d = \"%s\"  [%s]",
					dumpClass[i]->c_str(), dumpValue[i], k, len,
					escaped, archive.c_str());
				++matches;
			}

			const int score = nameScore(bytes + k, len);
			if (len >= 4 && (score > bestScore ||
				(score == bestScore && len > bestLength))) {
				bestScore = score;
				bestLength = len;
				bestOffset = k;
			}
		}

		// Nothing in this object matched a real entry. Record the best near-miss
		// so the next round of hunting has something to go on, but say plainly
		// that it is not a match.
		if (matches == 0 && bestOffset >= 0 && bestLength >= 4 && bestScore > 0) {
			char escaped[1024];
			escapeToLog(escaped, sizeof(escaped), bytes + bestOffset, bestLength);
			logInfo("NAME? %s %p +0x%02X len=%d score=%d = \"%s\" (no index match)",
				dumpClass[i]->c_str(), dumpValue[i], bestOffset,
				bestLength, bestScore, escaped);
		}

		// Deliberately no pointer chasing here.
		//
		// An earlier version interpreted every field as a pointer and as an MSVC
		// std::string, which meant following values read out of an object into
		// memory of unknown validity. It never produced a single confirmed name --
		// entry names turned out to be stored inline -- while generating hundreds
		// of access violations and destabilising the game. Everything now happens
		// against the buffer already copied above, which cannot fault.

		InterlockedExchange(&g_probing, 0);

		if (n > 0) {
			logInfo("%s", hex);
		}
		logInfo("OBJ %s %p first32-ascii: %s",
			dumpClass[i]->c_str(), dumpValue[i], ascii);
	}
}

int AudioTracker::init() {
	if (g_initialized.exchange(true)) {
		return g_slotCount.load();
	}

	// Installed first so that even a fault during discovery or vtable patching
	// is recorded rather than lost.
	installExceptionDiagnostics();

	if (envFlag(L"ALICE_SOUNDFETCHER_QUIET")) {
		g_quiet = true;
		logInfo("AudioTracker: QUIET mode (counters only, no logging).");
	}

	if (envFlag(L"ALICE_SOUNDFETCHER_PASSTHROUGH")) {
		g_passthrough = true;
		logInfo("AudioTracker: PASSTHROUGH mode (bare jmp stubs, no logging).");
	}

	describeModule();

	// Load the entry-name index before any hooking, so name validation is ready
	// for the very first event rather than warming up later.
	loadEntryIndex();

	// Hook the string comparisons that the archive lookup ends in.
	installCompareHooks();
	installAssignStringHook();

	// A thread created here does not start until DllMain returns and the loader
	// lock is released, which is exactly when the delay becomes meaningful.
	CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
		moduleSnapshotThread();
		return 0;
	}, nullptr, 0, nullptr);

	logInfo("AudioTracker: module base=%p size=0x%X exec ranges=%d",
		(void*)g_moduleBase, (unsigned)g_moduleSize, (int)g_execRanges.size());

	// ---- pass 1: locate every class and measure its vtable ---------------
	struct Plan {
		std::string className;
		uintptr_t vtable;
		int slots;
		uintptr_t nextEntry;
	};

	std::vector<Plan> plans;
	int totalSlots = 0;

	const std::vector<std::string> classList = resolveClassList();
	logInfo("AudioTracker: hooking %zu classes", classList.size());

	for (const std::string& name : classList) {
		const char* nameC = name.c_str();

		const uint32_t tdRva = findTypeDescriptorRva(nameC);
		if (!tdRva) {
			logInfo("  %s: no RTTI", nameC);
			continue;
		}

		uint32_t colRva = 0;
		if (!findCompleteObjectLocator(tdRva, colRva)) {
			logInfo("  %s: no CompleteObjectLocator", nameC);
			continue;
		}

		uintptr_t vtable = 0;
		if (!findVtable(colRva, vtable)) {
			logInfo("  %s: no vtable", nameC);
			continue;
		}

		// Count consecutive pointers into EXECUTABLE memory. The entry past the
		// last virtual function is the COL of whichever class the linker emitted
		// next, and it points into .rdata, so this ends the walk at the right slot.
		int slots = 0;
		while (slots < 256) {
			uintptr_t fn = 0;
			memcpy(&fn, (const void*)(vtable + (uintptr_t)slots * 4), sizeof(fn));
			if (!isExecutable(fn)) {
				break;
			}
			++slots;
		}

		uintptr_t nextEntry = 0;
		memcpy(&nextEntry, (const void*)(vtable + (uintptr_t)slots * 4), sizeof(nextEntry));

		// A class with hundreds of virtual functions is not plausible and would
		// mean the executable-range test has misfired. Skip rather than patch.
		if (slots <= 0 || slots > 128) {
			logInfo("  %s: implausible slot count %d at vtable %p, skipped",
				nameC, slots, (void*)vtable);
			continue;
		}

		// Optional cap on how many slots are patched, used to bisect which
		// individual virtual function is responsible for a fault.
		wchar_t capBuf[16] = {};
		if (GetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_MAXSLOTS",
				capBuf, (DWORD)(sizeof(capBuf) / sizeof(capBuf[0]))) > 0) {
			const int maxSlots = _wtoi(capBuf);
			if (maxSlots > 0 && maxSlots < slots) {
				logInfo("  %s: capping slots %d -> %d (MAXSLOTS)",
					nameC, slots, maxSlots);
				slots = maxSlots;
			}
		}

		logInfo("  %s: COL=0x%X vtable=%p slots=%d next=%p",
			nameC, colRva, (void*)vtable, slots, (void*)nextEntry);

		plans.push_back({ name, vtable, slots, nextEntry });
		totalSlots += slots;
	}

	if (plans.empty() || totalSlots == 0) {
		logInfo("AudioTracker: no audio class vtable could be hooked");
		return 0;
	}

	// ---- pass 2: build one flat stub arena --------------------------------
	uint8_t* stubBase = (uint8_t*)VirtualAlloc(
		nullptr, (size_t)totalSlots * kStubSize, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!stubBase) {
		logInfo("AudioTracker: VirtualAlloc for stubs failed (error %lu)", GetLastError());
		return 0;
	}

	g_targets.reserve(totalSlots);

	const uintptr_t loggerAddr = (uintptr_t)&AudioTrackerLogHook;
	int stubIndex = 0;

	for (const Plan& plan : plans) {
		const int firstId = stubIndex;

		for (int s = 0; s < plan.slots; ++s) {
			uintptr_t realFn = 0;
			memcpy(&realFn, (const void*)(plan.vtable + (uintptr_t)s * 4), sizeof(realFn));

			g_targets.push_back({ plan.className, s, (void*)realFn });

			uint8_t* stub = stubBase + (size_t)stubIndex * kStubSize;
			memset(stub, 0xCC, kStubSize); // int3 fill, so a bug lands in a debugger

			// Pure forwarding: the stub is entered at offset 0, so the jump has to
			// go there. Writing it at kOffJmp instead would leave the entry point
			// filled with the 0xCC breakpoint bytes and crash on the first call.
			if (g_passthrough) {
				stub[0] = 0xE9;
				const int32_t jmpRel =
					(int32_t)(realFn - (uintptr_t)(stub + 5));
				memcpy(stub + 1, &jmpRel, sizeof(jmpRel));
				++stubIndex;
				continue;
			}

			stub[kOffSaveBegin] = 0x9C;                     // pushfd
			stub[kOffSaveBegin + 1] = 0x50;                 // push eax
			stub[kOffSaveBegin + 2] = 0x51;                 // push ecx
			stub[kOffSaveBegin + 3] = 0x52;                 // push edx

			stub[kOffSelf] = 0x8B;                         // mov eax, ecx
			stub[kOffSelf + 1] = 0xC1;

			if (g_quiet) {
				// Nothing downstream uses the stack words, so the reads are turned
				// into NOPs. This keeps the stub layout identical while isolating
				// whether touching memory above the return address is what upsets
				// the engine -- for a function with no stack arguments, those words
				// are whatever the caller happened to leave there.
				for (size_t k = 0; k < 4; ++k) {
					stub[kOffSp0 + k] = 0x90;
					stub[kOffSp1 + k] = 0x90;
				}
			} else {
				stub[kOffSp0] = 0x8B;                 // mov edx, [esp+20h]
				stub[kOffSp0 + 1] = 0x54;
				stub[kOffSp0 + 2] = 0x24;
				stub[kOffSp0 + 3] = 0x14;

				stub[kOffSp1] = 0x8B;                 // mov ecx, [esp+24h]
				stub[kOffSp1 + 1] = 0x4C;
				stub[kOffSp1 + 2] = 0x24;
				stub[kOffSp1 + 3] = 0x18;
			}

			// Arguments are pushed right-to-left, so the first parameter
			// (self) is pushed last and lands lowest in the frame.
			stub[kOffPushId] = 0x68;                       // push imm32 (id)
			const int id = stubIndex;
			memcpy(stub + kOffPushId + 1, &id, sizeof(id));

			stub[kOffPushSp1] = 0x51;                      // push ecx  (sp1)
			stub[kOffPushSp0] = 0x52;                      // push edx  (sp0)
			stub[kOffPushSelf] = 0x50;                     // push eax  (this)

			stub[kOffCall] = 0xE8;                          // call rel32
			// rel32 is measured from the END of the whole instruction, and
			// `E8 rel32` is 5 bytes (1 opcode + 4 displacement). Using
			// kOffCall + 4 here lands one byte short, so the call goes to
			// loggerAddr + 1 -- into the middle of the logger's first
			// instruction. The symptom is not an obvious failure: the engine
			// appears to jump to data addresses and the stack is left holding a
			// garbage return address.
			const int32_t callRel =
				(int32_t)(loggerAddr - (uintptr_t)(stub + kOffCall + 5));
			memcpy(stub + kOffCall + 1, &callRel, sizeof(callRel));

			stub[kOffRestore] = 0x5A;                       // pop edx
			stub[kOffRestore + 1] = 0x59;                   // pop ecx
			stub[kOffRestore + 2] = 0x58;                   // pop eax
			stub[kOffRestore + 3] = 0x9D;                   // popfd

			stub[kOffJmp] = 0xE9;                           // jmp rel32
			// Same 5-byte arithmetic as the call above: E9 rel32 spans offsets
			// kOffJmp .. kOffJmp+4, so the displacement is relative to
			// kOffJmp + 5. Adding only 4 lands the jump one byte into the real
			// function instead of on its first instruction.
			const int32_t jmpRel =
				(int32_t)(realFn - (uintptr_t)(stub + kOffJmp + 5));
			memcpy(stub + kOffJmp + 1, &jmpRel, sizeof(jmpRel));

			++stubIndex;
		}

		logInfo("  %s: hooking %d slots (stub ids %d..%d)",
			plan.className.c_str(), plan.slots, firstId, stubIndex - 1);
	}

	FlushInstructionCache(GetCurrentProcess(), stubBase, (size_t)stubIndex * kStubSize);

	logFirstStubBytes(stubBase, kStubSize);

	// ---- pass 3: redirect each vtable -------------------------------------
	int patched = 0;
	for (const Plan& plan : plans) {
		const SIZE_T bytes = (SIZE_T)plan.slots * 4;

		DWORD oldProtect = 0;
		if (!VirtualProtect((void*)plan.vtable, bytes, PAGE_READWRITE, &oldProtect)) {
			logInfo("  %s: VirtualProtect failed (error %lu)",
				plan.className.c_str(), GetLastError());
			continue;
		}

		uintptr_t* table = (uintptr_t*)plan.vtable;
		for (int s = 0; s < plan.slots; ++s) {
			const int id = patched + s;
			table[s] = (uintptr_t)(stubBase + (size_t)id * kStubSize);
		}
		FlushInstructionCache(GetCurrentProcess(), (void*)plan.vtable, bytes);
		VirtualProtect((void*)plan.vtable, bytes, oldProtect, &oldProtect);
		patched += plan.slots;
	}

	// Read the tables back and confirm every entry landed. A half-applied patch
	// corrupts the engine in a way that is very hard to attribute later, so it is
	// checked rather than assumed.
	int verified = 0;
	int cursor = 0;
	for (const Plan& plan : plans) {
		uintptr_t* table = (uintptr_t*)plan.vtable;
		for (int s = 0; s < plan.slots; ++s, ++cursor) {
			if (table[s] == (uintptr_t)(stubBase + (size_t)cursor * kStubSize)) {
				++verified;
			}
		}
	}

	if (verified != patched) {
		logInfo("AudioTracker: vtable write-back FAILED (%d/%d)", verified, patched);
		return 0;
	}

	g_stubBase = stubBase;
	g_stubCount = stubIndex;
	g_slotCount = stubIndex;

	// Publish the vtable map so the hook can recognise instances of these classes
	// among its call arguments. This is what lets Stage 2 identify a sound object
	// by its vtable instead of by an assumed field offset.
	for (const Plan& plan : plans) {
		g_classVtables.emplace_back(plan.vtable, plan.className);
	}

	logInfo("AudioTracker: hooked %d slots across %zu classes, all verified.",
		stubIndex, plans.size());

	return stubIndex;
}

void AudioTracker::cleanup() {
	// The original vtable is restored when the game exits; there is nothing to
	// undo here while it is running.
	g_initialized = false;
}