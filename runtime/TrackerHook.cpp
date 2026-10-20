// Settings, guarded reads, name deduplication, and fault diagnostics.
//
// AudioTrackerLogHook itself lives in AudioTracker.cpp. This file holds the state
// and helpers it uses that no other unit needs to see.

#include "AudioTracker.h"
#include "TrackerShared.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <unordered_map>

namespace tracker {

// Quiet mode: count only, never format or write.
//
// This separates two very different failure modes that otherwise look identical from
// the outside: a forwarding stub that corrupts the engine, and a hook that merely does
// too much work (CRT formatting, a global lock, file I/O) on a game thread that may be
// running under the loader lock or during early start-up.
bool g_quiet = false;

// Verbose: also log every hooked call. Off by default, because the call stream runs
// to thousands of lines a session and buried the one thing that matters -- a confirmed
// archive entry name.
bool g_verbose = false;

// Object memory dumps and near-miss strings. Diagnosis only.
bool g_dumpObjects = false;

bool g_hookComparisons = false;

// Report the name the player object is currently playing. This is the primary output:
// it is what "which sound is playing" means. On by default, because without it the
// tool reports what a game loaded rather than what it played.
bool g_liveNames = true;

// Passthrough mode: each stub is nothing but a jump to the original entry, so the
// vtable is patched exactly as before but nothing of ours ever executes.
//
// This isolates the two possible causes of a fault after patching. If the game still
// dies, the fault comes from the vtable contents themselves rather than from running
// our code on the game's audio path.
bool g_passthrough = false;

std::vector<std::pair<uintptr_t, std::string>> g_classVtables;

std::atomic<int> g_slotCount{ 0 };
std::atomic<bool> g_initialized{ false };

LONG g_probing = 0;

namespace {

// Confirmed entry names, reported once each.
//
// This is a hash map rather than a vector scanned linearly, and that is not a
// stylistic choice. Evenicle hands the runtime 19548 distinct names during start-up
// alone, and a linear scan of a growing vector is quadratic in that count: roughly 190
// million string comparisons, all on the game's own audio threads, all inside a hook.
// That is what made the game visibly slow down once the stem index was added and
// every voice name started matching.
//
// Repeats are counted but not logged again. A summary of the counts at shutdown would
// be the obvious next step, and is deliberately not here: the game process exits
// through DLL_PROCESS_DETACH, and doing file I/O from that callback is a good way to
// turn a clean exit into a hang.
std::unordered_map<std::string, int> g_reportedNames;

// Object pointers already dumped, so each instance is reported once rather than on
// every call that mentions it. Claimed with an interlocked compare exchange so two
// game threads cannot both decide to dump the same object.
//
// Sized generously: a collision evicts an entry and causes a re-dump, which is merely
// noise, but it is worth avoiding.
constexpr size_t kSeenObjectCount = 4096;
volatile LONG g_seenObjects[kSeenObjectCount] = {};

// Classes whose instances get a one-off memory dump.
//
// The decoded sound object is the obvious candidate, but the decoded data itself
// carries no name field, so the player and channel objects are dumped as well:
// whichever of them was handed an archive entry name is where the name actually is.
bool isDumpClassImpl(const std::string& name) {
	return name.rfind("CSoundData", 0) == 0 ||
		name == "CSoundPlayer" ||
		name == "CSoundChannel" ||
		"CKiwiSoundEngine" == name;
}

// Claim an (object, slot) pair for dumping. Returns true only the first time.
//
// Keyed on the slot as well as the object on purpose. Claiming once per object caught
// it during construction, when the memory still belonged to a previous occupant of
// the pool: a vtable pointer already saying CSoundDataOgg while the rest of the block
// still held an unrelated texture name and script text. Claiming per slot instead
// samples the object at each stage of its lifecycle.
//
// The compare-and-swap must be seeded with the value that was actually read. Seeding
// it with the key instead looks tidier but is wrong: the exchange only stores when the
// slot already equals the comparand, so on a fresh zeroed slot the store is skipped
// and nothing is ever marked as seen.
bool claimObjectDumpImpl(uintptr_t obj, int slot) {
	if (obj == 0) {
		return false;
	}
	const uint32_t key = (uint32_t)obj ^ (uint32_t)((slot + 1) * 0x9E3779B1u);
	const size_t index = ((key >> 3) ^ (key >> 17)) & (kSeenObjectCount - 1);
	const LONG current = g_seenObjects[index];
	if (current == (LONG)key) {
		return false; // already dumped
	}
	return InterlockedCompareExchange(&g_seenObjects[index], (LONG)key, current)
		== current;
}

// ---------------------------------------------------------------------------
// Exception diagnostics.
//
// An access violation inside the game is hard to attribute by hand: the faulting
// module is reported as "unknown" for any address inside our stub arena, because
// VirtualAlloc'd pages belong to no module. This handler records the faulting address
// and says explicitly whether it landed in one of our stubs, which turns "the game
// crashed after we hooked it" into a definitive answer.
// ---------------------------------------------------------------------------

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

	// Access violations raised on purpose while probing candidate argument pointers
	// are expected and must not be reported as faults; otherwise routine probing
	// buries the real ones.
	if (g_probing > 0) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	const uintptr_t fault = (uintptr_t)info->ExceptionRecord->ExceptionAddress;
	const bool inStubs =
		g_stubBase != nullptr &&
		fault >= (uintptr_t)g_stubBase &&
		fault < (uintptr_t)g_stubBase + (uintptr_t)g_stubCount * kStubSize;

	const int stubId = inStubs
		? (int)((fault - (uintptr_t)g_stubBase) / kStubSize) : -1;

	char line[400];
	int n = snprintf(line, sizeof(line),
		"FAULT code=0x%08lX addr=%p inStub=%d stubId=%d target=%s/%d",
		(unsigned long)code, (void*)fault, inStubs ? 1 : 0, stubId,
		(stubId >= 0 && stubId < (int)g_targets.size())
			? g_targets[stubId].className.c_str() : "?",
		(stubId >= 0 && stubId < (int)g_targets.size())
			? g_targets[stubId].slot : -1);
	if (n > 0 && info->ContextRecord) {
		n += snprintf(line + n, sizeof(line) - (size_t)n,
			" eip=%p esp=%p ebp=%p eax=%p ecx=%p edx=%p",
			(void*)info->ContextRecord->Eip, (void*)info->ContextRecord->Esp,
			(void*)info->ContextRecord->Ebp, (void*)info->ContextRecord->Eax,
			(void*)info->ContextRecord->Ecx, (void*)info->ContextRecord->Edx);

		// When the fault address is the object pointer rather than an instruction,
		// the interesting question is who called it. The return address on top of the
		// frame identifies the call site, so the stack is dumped and each word
		// classified as game code, our stub, or other.
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

PVOID g_vehHandle = nullptr;

} // namespace

void installExceptionHandler() {
	if (g_vehHandle == 0) {
		g_vehHandle = AddVectoredExceptionHandler(1, trackerVeh);
	}
}

bool envFlag(const wchar_t* name) {
	wchar_t value[8] = {};
	return GetEnvironmentVariableW(name, value, 8) > 0 && value[0] == L'1';
}

bool safeRead32(uintptr_t address, uint32_t* out) {
	__try {
		*out = *(volatile uint32_t*)address;
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

// Reads a NUL-terminated ASCII string, returning its length or -1.
// Rejects anything that is not plainly printable, so a random heap pointer is not
// mistaken for a string.
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

// Classify a candidate pointer by its vtable, or nullptr if it is not an instance of a
// class we hooked.
const std::string* identifyObject(uintptr_t candidate) {
	if (candidate < 0x10000 || candidate > 0x7FFEFFFF) {
		return nullptr;
	}

	uint32_t vptr = 0;
	InterlockedIncrement(&g_probing);
	const bool ok = safeRead32(candidate, &vptr);
	InterlockedDecrement(&g_probing);
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

void reportConfirmedName(const char* prefix, const uint8_t* bytes, int length,
	const std::string& archive, NameMatch match) {
	char text[1024];
	escapeToLog(text, sizeof(text), bytes, length);

	const std::string key = std::string(prefix) + "|" + archive + "|" + text;
	if (++g_reportedNames[key] > 1) {
		return;
	}

	// "exact" is the name exactly as the archive spells it. "stem" is the name without
	// its extension, which is how audio appears, because the engine keeps the stem and
	// the extension in separate strings and only joins them on the playback path.
	// Saying which is which keeps the two from being confused.
	logInfo("%s name=\"%s\" [%s] (%s)", prefix, text, archive.c_str(),
		nameMatchKind(match));
}

bool claimObjectDump(uintptr_t obj, int slot) {
	return claimObjectDumpImpl(obj, slot);
}

bool isDumpClass(const std::string& name) {
	return isDumpClassImpl(name);
}

} // namespace tracker

// ---------------------------------------------------------------------------
// AudioTracker's public surface
// ---------------------------------------------------------------------------

void AudioTracker::installExceptionDiagnostics() {
	tracker::installExceptionHandler();
}

const wchar_t* AudioTracker::logPath() {
	static wchar_t cached[MAX_PATH] = {};
	if (cached[0] == L'\0') {
		GetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_LOG", cached, MAX_PATH);
	}
	return cached;
}

int AudioTracker::slotCount() {
	return tracker::g_slotCount.load();
}
