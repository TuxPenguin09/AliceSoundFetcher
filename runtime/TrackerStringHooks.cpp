// The two string hooks: the engine's own std::string::assign, and the CRT
// comparisons.
//
// Why assign and not the comparisons: Evenicle imports no CRT string comparison at
// all -- no strcmp, _stricmp, strcmpi, lstrcmpA, strncmp, memcmp or wcscmp appears
// anywhere in the import table -- so there is nothing of that kind to hook. That
// absence is what pointed at the engine's own routine.
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
// through this function, so validating the source argument against the index needs
// no knowledge of any object layout at all. Its first instruction is exactly five
// bytes, so it relocates cleanly: overwrite it with a jump, and replay the displaced
// bytes inside the stub.
//
// Note what this hook can and cannot tell you. It fires when the engine *assigns* a
// string, which for audio happens once during a start-up sweep of the archive. It
// is therefore evidence that a name exists, not that it played. For the name being
// played, see TrackerLiveName.cpp.

#include "TrackerShared.h"

#include <cstdio>
#include <cstring>

namespace tracker {

namespace {

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
			InterlockedIncrement(&g_probing);
			const int len = safeShiftJisRunLength(candidate, raw,
				(int)sizeof(raw) - 1);
			InterlockedDecrement(&g_probing);

			if (len >= 3) {
				std::string archive;
				NameMatch match = NameMatch::None;
				if (lookupEntryName((const uint8_t*)raw, len, archive, &match)) {
					reportConfirmedName("MATCH", (const uint8_t*)raw, len, archive,
						match);
				}
			}
		}
	}
}

// Byte offsets are spelled out and each entry carries its own length comment
// because every one of these was wrong at least once: `FF 74 24 14` is four bytes,
// not three, and getting that wrong silently shifts the call and the jump that
// follow it, which sends execution into the middle of the stub.
constexpr size_t kAssignStubSize = 32;
constexpr size_t kAssignStubSaveBegin = 0;   // 9C 50 51 52                     4 bytes
constexpr size_t kAssignStubPushArg = 4;     // FF 74 24 14                     4 bytes
constexpr size_t kAssignStubCall = 8;        // E8 <rel32>                      5 bytes
constexpr size_t kAssignStubClean = 13;      // 83 C4 04                        3 bytes
constexpr size_t kAssignStubRestore = 16;    // 5A 59 58 9D                     4 bytes
constexpr size_t kAssignStubDisplaced = 20;  // B8 <imm32>                      5 bytes
constexpr size_t kAssignStubJmp = 25;        // E9 <rel32>                      5 bytes
static_assert(kAssignStubJmp + 5 <= kAssignStubSize, "assign stub overruns");

// ---------------------------------------------------------------------------
// CRT comparison hooks.
//
// The archive index is searched by name and that search ends in a string
// comparison. Hooking the comparison sidesteps everything that made the vtable
// approach miss: there is no object layout to guess and no need to know which
// function performs the lookup.
//
// The hook goes on the import address table, not on the function prologue. An IAT
// entry is a data pointer, so overwriting it touches no code, needs no relocation of
// displaced instructions, and is trivially reversible.
// ---------------------------------------------------------------------------

constexpr int kMaxCompareHooks = 4;
using CompareFn = int(__cdecl*)(const char*, const char*);

CompareFn g_compareOriginals[kMaxCompareHooks] = {};
int g_compareHookCount = 0;

const char* const kCompareImports[] = { "strcmp", "_stricmp", "strcmpi", "lstrcmpA" };

// Report a comparison argument if it names a real archive entry.
//
// Only ever called with a pointer that came out of the game's own data, so the read
// is guarded and the probing flag is raised while it happens.
//
// Neither side of the comparison is attributed to a caller any more: the whole
// point of these hooks was to find the name, and a confirmed name is now logged once
// wherever it is first seen rather than with the site that happened to see it first.
void reportCompareArgument(const char* value) {
	if (!value || !g_indexLoaded) {
		return;
	}
	const uintptr_t candidate = (uintptr_t)value;
	if (candidate < 0x10000 || candidate > 0x7FFEFFFF) {
		return;
	}

	char raw[512];
	InterlockedIncrement(&g_probing);
	const int len = safeShiftJisRunLength(candidate, raw, (int)sizeof(raw) - 1);
	InterlockedDecrement(&g_probing);

	if (len < 3) {
		return;
	}

	std::string archive;
	NameMatch match = NameMatch::None;
	if (lookupEntryName((const uint8_t*)raw, len, archive, &match)) {
		reportConfirmedName("MATCH", (const uint8_t*)raw, len, archive, match);
	}
}

int __cdecl hookedCompare0(const char* a, const char* b) {
	reportCompareArgument(a);
	reportCompareArgument(b);
	return g_compareOriginals[0](a, b);
}
int __cdecl hookedCompare1(const char* a, const char* b) {
	reportCompareArgument(a);
	reportCompareArgument(b);
	return g_compareOriginals[1](a, b);
}
int __cdecl hookedCompare2(const char* a, const char* b) {
	reportCompareArgument(a);
	reportCompareArgument(b);
	return g_compareOriginals[2](a, b);
}
int __cdecl hookedCompare3(const char* a, const char* b) {
	reportCompareArgument(a);
	reportCompareArgument(b);
	return g_compareOriginals[3](a, b);
}

CompareFn g_compareWrappers[kMaxCompareHooks] = {
	hookedCompare0, hookedCompare1, hookedCompare2, hookedCompare3
};

} // namespace

void installCompareHooks() {
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	if (!kernel) {
		return;
	}

	for (int slot = 0; slot < kMaxCompareHooks; ++slot) {
		const char* importName = kCompareImports[slot];

		for (int attempt = 0; attempt < 3; ++attempt) {
			wchar_t moduleName[64] = {};
			if (attempt == 0) {
				wcscpy_s(moduleName, L"msvcrt.dll");
			} else if (attempt == 1) {
				wcscpy_s(moduleName, L"ucrtbase.dll");
			} else {
				wcscpy_s(moduleName, L"api-ms-win-crt-string-l1-1-0.dll");
			}

			HMODULE mod = GetModuleHandleW(moduleName);
			if (!mod) {
				continue;
			}

			FARPROC proc = GetProcAddress(mod, importName);
			if (!proc) {
				continue;
			}

			DWORD oldProtect = 0;
			if (!VirtualProtect((void*)proc, sizeof(void*),
				PAGE_READWRITE, &oldProtect)) {
				continue;
			}
			g_compareOriginals[g_compareHookCount] = (CompareFn)proc;
			memcpy((void*)proc, &g_compareWrappers[slot], sizeof(void*));
			VirtualProtect((void*)proc, sizeof(void*), oldProtect, &oldProtect);
			FlushInstructionCache(GetCurrentProcess(), (void*)proc,
				sizeof(void*));

			logInfo("AudioTracker: hooked import %s -> wrapper %d",
				importName, slot);
			++g_compareHookCount;
			return; // one hook per imported name is enough
		}
	}
}

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
		logInfo("AudioTracker: string-assign hook target RVA 0x%X is not executable.",
			rva);
		return;
	}

	// Refuse anything whose opening instruction is not exactly the five bytes we
	// know how to replay. A different function at the same RVA, or one that starts
	// with a relative branch, must not be patched on a guess.
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
	const int32_t callRel = (int32_t)(onAssign -
		(uintptr_t)(stub + kAssignStubCall + 5));
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
	const int32_t entryRel =
		(int32_t)((uintptr_t)stub - (uintptr_t)(target + 5));
	memcpy(target + 1, &entryRel, sizeof(entryRel));
	FlushInstructionCache(GetCurrentProcess(), target, 5);
	VirtualProtect(target, 5, oldProtect, &oldProtect);

	g_stringAssignOriginal = (AssignHookFn)target; // unusable after patching

	logInfo("AudioTracker: hooked std::string::assign at %p -> stub %p",
		target, stub);

	// Print the emitted bytes so the encoding can be checked by eye rather than
	// inferred from a crash.
	{
		char line[256];
		int n = snprintf(line, sizeof(line), "  assign-stub bytes:");
		for (size_t i = 0; i < kAssignStubSize && n > 0 &&
			n < (int)sizeof(line) - 4; ++i) {
			n += snprintf(line + n, sizeof(line) - (size_t)n, " %02X", stub[i]);
		}
		if (n > 0) {
			logInfo("%s", line);
		}
	}
}

} // namespace tracker