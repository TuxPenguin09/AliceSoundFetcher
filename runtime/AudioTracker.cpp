#include "AudioTracker.h"

#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
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
		"CSoundPlayer",
		"CSoundChannel",
		"CDirectSoundBuffer",
		"CDirectSound",
		"CSoundDataOgg",
		"CSoundDataWav",
		"ISoundData",
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

	char line[256];
	int written = snprintf(line, sizeof(line),
		"%s CALL %s slot=%d this=%p sp0=%p sp1=%p\r\n",
		stamp, target.className.c_str(), target.slot, self, sp0, sp1);
	if (written <= 0) {
		return;
	}

	AudioTrackerInternals::write(line);
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

	logInfo("AudioTracker: hooked %d slots across %zu classes, all verified.",
		stubIndex, plans.size());

	return stubIndex;
}

void AudioTracker::cleanup() {
	// The original vtable is restored when the game exits; there is nothing to
	// undo here while it is running.
	g_initialized = false;
}