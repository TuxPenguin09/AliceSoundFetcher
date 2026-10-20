// Hooking the engine's own string functions, and the forwarding stubs that carry
// every call back into the C++ hook.
//
// Two kinds of hook live here:
//
//   * The hand-assembled forwarding stub, one per virtual function, emitted into
//     RWX memory and written over the engine's vtable.
//   * std::string::assign, patched directly, which is where a name exists as a
//     string at all.
//
// The stubs are byte offsets and hand-written displacements. That is not a stylistic
// choice -- it is the only way to reach these functions with the stack exactly as
// the callee expects it, but it does mean a single wrong byte produces failures that
// look like engine bugs rather than encoding bugs. Every offset therefore carries a
// length comment, and the emitted bytes are printed to the log so the encoding can
// be checked by eye instead of inferred from a crash.

#include "TrackerShared.h"

#include <cstdio>
#include <cstring>

namespace tracker {

// The audio classes to hook.
//
// The channel and group classes were once cut down to five to keep the log
// readable. That reason no longer applies -- the call stream is verbose-only, so an
// extra class adds nothing to a default run -- and the trimming was probably why
// playback inside a scene logged nothing: the voice was being carried by a channel
// object, and no channel class was hooked to read it from.
//
// None of these are expected to produce a name through the string path. The archive
// side is reached through std::string::assign, which needs no class hooks at all.
// What the classes are for is being read at the moment they are used.
const char* const kAudioClasses[] = {
	// Playback path.
	"CSoundPlayer",
	"CDirectSoundBuffer",

	// Routing. Scene dialogue runs through these, and the live name was found at a
	// different offset in each, so they are as likely to hold the name being played
	// as the player is.
	"CSoundChannel",
	"CSoundChannelList",
	"CLowLevelChannelList",
	"CHighLevelChannelList",
	"CGroupTree",

	// Decoded data.
	"CSoundDataOgg",
	"CSoundDataWav",

	// Only Evenicle 2 and Dohna Dohna have this one -- it does not exist in
	// Evenicle, which is the build the live name was proven on. It carries a full
	// thirteen-slot vtable in both, the same shape as the Ogg and Wav data classes,
	// so it is the most likely carrier for audio that went through a filter path
	// and never reached one of those.
	"CSoundDataFiltered",

	"CKiwiSoundEngine",

	// Archive side. CSoundFileAFA resolves a member of an .afa archive to audio
	// data, so it is handed the member name to resolve.
	"CSoundFileAFA",
	"CSoundFileList",
};

std::vector<HookTarget> g_targets;
uint8_t* g_stubBase = nullptr;
int g_stubCount = 0;

LONG g_callCounts[512] = {};

namespace {

// Emit the raw bytes of the first stub.
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

// Defaults to every audio class, but the set is overridable through
// ALICE_SOUNDFETCHER_CLASSES (comma separated). Being able to hook exactly one class
// per run is what makes it practical to find out which single class is responsible
// for a fault, without a rebuild for every experiment.
std::vector<std::string> resolveClassList() {
	std::vector<std::string> result;

	wchar_t buffer[1024] = {};
	const DWORD copied = GetEnvironmentVariableW(
		L"ALICE_SOUNDFETCHER_CLASSES", buffer, (DWORD)(sizeof(buffer) / sizeof(buffer[0])));

	if (copied == 0 || copied >= sizeof(buffer) / sizeof(buffer[0])) {
		for (const char* const name : kAudioClasses) {
			result.emplace_back(name);
		}
		return result;
	}

	// Narrow explicitly. Building a std::string straight from the wchar_t buffer
	// would pick the wchar_t iterator constructor and silently truncate every
	// character on the way in; class names are ASCII so the loop is exact, but
	// anything else would be quietly mangled into a name that hooks nothing.
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
// Forwarding stub layout.
//
//   9C              pushfd
//   50 51 52        push eax / push ecx / push edx
//   8B C8           mov  eax, ecx           ; `this`, implicit for thiscall
//   8B 54 24 14     mov  edx, [esp+20h]     ; first stack word above retaddr
//   8B 4C 24 18     mov  ecx, [esp+24h]     ; second stack word
//   68 <id>         push id
//   51 52 50        push sp1 / push sp0 / push this
//   E8 <rel32>      call AudioTrackerLogHook  (callee pops the four arguments)
//   5A 59 58        pop edx / pop ecx / pop eax
//   9D              popfd
//   E9 <rel32>      jmp  original
//
// The pushes are right-to-left, matching __stdcall: the first declared parameter is
// pushed last and so ends up lowest in the callee frame. Getting this backwards
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

int installVtableHooks() {
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
		memcpy(&nextEntry, (const void*)(vtable + (uintptr_t)slots * 4),
			sizeof(nextEntry));

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
		logInfo("AudioTracker: VirtualAlloc for stubs failed (error %lu)",
			GetLastError());
		return 0;
	}

	g_targets.reserve(totalSlots);

	const uintptr_t loggerAddr = (uintptr_t)&AudioTrackerLogHook;
	int stubIndex = 0;

	for (const Plan& plan : plans) {
		const int firstId = stubIndex;

		for (int s = 0; s < plan.slots; ++s) {
			uintptr_t realFn = 0;
			memcpy(&realFn, (const void*)(plan.vtable + (uintptr_t)s * 4),
				sizeof(realFn));

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
			// loggerAddr + 1 -- into the middle of the logger's first instruction.
			// The symptom is not an obvious failure: the engine appears to jump to
			// data addresses and the stack is left holding a garbage return address.
			const int32_t callRel =
				(int32_t)(loggerAddr - (uintptr_t)(stub + kOffCall + 5));
			memcpy(stub + kOffCall + 1, &callRel, sizeof(callRel));

			stub[kOffRestore] = 0x5A;                       // pop edx
			stub[kOffRestore + 1] = 0x59;                   // pop ecx
			stub[kOffRestore + 2] = 0x58;                   // pop eax
			stub[kOffRestore + 3] = 0x9D;                   // popfd

			stub[kOffJmp] = 0xE9;                           // jmp rel32
			// Same 5-byte arithmetic as the call above: E9 rel32 spans offsets
			// kOffJmp .. kOffJmp+4, so the displacement is relative to kOffJmp + 5.
			// Adding only 4 lands the jump one byte into the real function instead
			// of on its first instruction.
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
		if (!VirtualProtect((void*)plan.vtable, bytes, PAGE_READWRITE,
			&oldProtect)) {
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

	// Publish the vtable map so the hook can recognise instances of these classes
	// among its call arguments. This is what lets the hook identify a sound object
	// by its vtable instead of by an assumed field offset.
	for (const Plan& plan : plans) {
		g_classVtables.emplace_back(plan.vtable, plan.className);
	}

	logInfo("AudioTracker: hooked %d slots across %zu classes, all verified.",
		stubIndex, plans.size());

	return stubIndex;
}

} // namespace tracker