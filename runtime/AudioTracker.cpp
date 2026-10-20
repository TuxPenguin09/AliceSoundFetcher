// AudioTracker: start-up, the hook entry point, and teardown.
//
// This code runs inside the injected DLL, i.e. inside the game's own process.
//
// Why the hook looks where it does: AliceSoft resolves DirectSound dynamically and
// never opens per-sound files, because every asset lives inside the .afa archive and
// is played from memory. Hooking CreateFileW for ".ogg" therefore cannot fire. The
// sound engine's own classes do get called per sound, and they are reachable through
// RTTI, which the shipped binaries retain.
//
// Every audio class in the engine is hooked, not just one guess, because the class
// that actually carries per-sound playback is not known ahead of time and picking one
// by name is a guess. Logging every call identifies it from observation.

#include "AudioTracker.h"
#include "TrackerShared.h"

#include <cstdio>
#include <cstring>
#include <cwchar>

// Defined in TrackerLog.cpp. External linkage on purpose: the emitted stub binds to
// them by address.
namespace tracker::internals {
void timestamp(char* out, size_t cap);
void write(const char* line);
} // namespace tracker::internals

// ---------------------------------------------------------------------------
// AudioTrackerLogHook
//
// Called from a forwarding stub on one of the game's own threads, inside an audio call
// path. Everything it needs arrives as arguments, so nothing is read from shared state
// that two threads could mix up.
// ---------------------------------------------------------------------------

extern "C" void __stdcall AudioTrackerLogHook(void* self, void* sp0, void* sp1,
	int id) {
	using namespace tracker;

	if (id < 0 || id >= (int)g_targets.size()) {
		return;
	}
	const HookTarget& target = g_targets[id];

	// Counted in every mode. The per-class totals printed at exit are the only way
	// to tell a hook that never fired from one whose read found nothing, and quiet
	// mode is exactly when that distinction is being investigated.
	InterlockedIncrement(&g_callCounts[id]);

	// Quiet mode does no formatting, no locking and no file I/O.
	if (g_quiet) {
		return;
	}

	char stamp[32];
	internals::timestamp(stamp, sizeof(stamp));

	// Classify the incoming arguments before formatting, so the event line shows what
	// the values actually are rather than leaving that to interpretation. Only done
	// when the results are actually going to be used: in the default mode neither the
	// call stream nor the object dumps are written, and this runs thousands of times a
	// session.
	const bool needArgClasses = g_verbose || g_dumpObjects;
	const std::string* sp0Class = needArgClasses
		? identifyObject((uintptr_t)sp0) : nullptr;
	const std::string* sp1Class = needArgClasses
		? identifyObject((uintptr_t)sp1) : nullptr;

	// The call stream is diagnostics, not the result. It runs to thousands of lines a
	// session and buries the confirmed names, so it is verbose-only.
	if (g_verbose) {
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
		if (written > 0) {
			internals::write(line);
		}
	}

	// The entry name may simply arrive as a call argument, as a bare pointer to a
	// Shift-JIS string. CSoundFileAFA is handed the member name to resolve, so that is
	// the most direct place a confirmed name can be obtained, and it needs no layout
	// knowledge at all.
	{
		const void* argValues[2] = { sp0, sp1 };
		for (int a = 0; a < 2; ++a) {
			const uintptr_t candidate = (uintptr_t)argValues[a];
			if (candidate < 0x10000) {
				continue;
			}

			char raw[512];
			InterlockedIncrement(&g_probing);
			const int len = safeShiftJisRunLength(candidate, raw,
				(int)sizeof(raw) - 1);
			InterlockedDecrement(&g_probing);

			if (len < 3) {
				continue;
			}

			std::string archive;
			NameMatch match = NameMatch::None;
			if (lookupEntryName((const uint8_t*)raw, len, archive, &match)) {
				reportConfirmedName("PLAY", (const uint8_t*)raw, len, archive, match);
				continue;
			}

			// Otherwise the name may be the tail of a path such as
			// "EvenicleVoice/10001.opus"; retry on the last component.
			int lastSlash = -1;
			for (int i = 0; i < len; ++i) {
				if (raw[i] == '/') {
					lastSlash = i;
				}
			}
			if (lastSlash < 0) {
				continue;
			}

			const uint8_t* tail = (const uint8_t*)raw + lastSlash + 1;
			const int tailLen = len - lastSlash - 1;
			if (tailLen >= 3 && lookupEntryName(tail, tailLen, archive, &match)) {
				reportConfirmedName("PLAY", tail, tailLen, archive, match);
			}
		}
	}

	// The live playback name, read from the object that is playing it. This is the
	// primary output: it answers "which file is playing now".
	if (g_liveNames) {
		reportLiveName((uintptr_t)self, target.className, id);
	}

	// Object memory dumps are diagnosis only, and by far the largest thing the hook
	// used to produce. Used to establish the object layout; now off by default.
	if (!g_dumpObjects) {
		return;
	}

	// The object of interest is usually `this` rather than an argument -- a call like
	// CSoundDataOgg::SomeMethod() *is* operating on the sound object. The arguments
	// are still checked, because a sound object can equally arrive as a parameter to
	// a player or channel method.
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

		// Every read below deliberately touches addresses taken from object fields,
		// which are not guaranteed to be mapped. The whole block is therefore marked
		// as probing: the failures are expected, they are caught by the __except in
		// each helper, and the vectored handler must not report them as faults in the
		// game. The flag has to stay set for the entire block -- clearing it early lets
		// routine probing bury the real faults.
		InterlockedIncrement(&g_probing);

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
		// further memory. Scanning a local buffer cannot fault at all, so the search is
		// both safer and faster than chasing pointer fields.
		//
		// Every plausible run is tested against the index, and only confirmed matches
		// are reported as names. Scoring alone accepted "kimg_logo.png", which looks
		// entirely real and exists nowhere in this game's archives.
		int matches = 0;

		for (int k = 0; k + 3 <= 256; ++k) {
			const int len = shiftJisRunLength(bytes + k, 256 - k);
			if (len < 3) {
				continue;
			}

			std::string archive;
			NameMatch match = NameMatch::None;
			if (lookupEntryName(bytes + k, len, archive, &match)) {
				char escaped[1024];
				escapeToLog(escaped, sizeof(escaped), bytes + k, len);
				logInfo("NAME %s %p +0x%02X len=%d = \"%s\"  [%s] (%s)",
					dumpClass[i]->c_str(), dumpValue[i], k, len,
					escaped, archive.c_str(), nameMatchKind(match));
				++matches;
			}
		}

		// Deliberately no pointer chasing here.
		//
		// An earlier version interpreted every field as a pointer and as an MSVC
		// std::string, which meant following values read out of an object into memory
		// of unknown validity. It never produced a single confirmed name -- entry names
		// turned out to be stored inline -- while generating hundreds of access
		// violations and destabilising the game. Everything now happens against the
		// buffer already copied above, which cannot fault.

		InterlockedDecrement(&g_probing);

		(void)matches;
		if (n > 0) {
			logInfo("%s", hex);
		}
		logInfo("OBJ %s %p first32-ascii: %s",
			dumpClass[i]->c_str(), dumpValue[i], ascii);
	}
}

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

int AudioTracker::init() {
	using namespace tracker;

	if (g_initialized.exchange(true)) {
		return g_slotCount.load();
	}

	// Installed first so that even a fault during discovery or vtable patching is
	// recorded rather than lost.
	installExceptionDiagnostics();

	if (envFlag(L"ALICE_SOUNDFETCHER_QUIET")) {
		g_quiet = true;
		logInfo("AudioTracker: QUIET mode (counters only, no logging).");
	}

	g_verbose = envFlag(L"ALICE_SOUNDFETCHER_VERBOSE");
	g_dumpObjects = envFlag(L"ALICE_SOUNDFETCHER_DUMPOBJECTS");
	g_hookComparisons = envFlag(L"ALICE_SOUNDFETCHER_COMPARES");
	g_passthrough = envFlag(L"ALICE_SOUNDFETCHER_PASSTHROUGH");

	logInfo("AudioTracker: verbose=%d dumpObjects=%d hookComparisons=%d",
		g_verbose ? 1 : 0, g_dumpObjects ? 1 : 0, g_hookComparisons ? 1 : 0);

	describeModule();
	loadEntryIndex();

	if (g_hookComparisons) {
		installCompareHooks();
	}
	installAssignStringHook();

	// A thread created here does not start until DllMain returns and the loader lock
	// is released, which is exactly when the delay becomes meaningful.
	CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
		tracker::moduleSnapshotThread();
		return 0;
	}, nullptr, 0, nullptr);

	logInfo("AudioTracker: module base=%p size=0x%X exec ranges=%d",
		(void*)g_moduleBase, (unsigned)g_moduleSize, (int)g_execRanges.size());

	const int slots = installVtableHooks();
	g_slotCount = slots;
	return slots;
}

void AudioTracker::cleanup() {
	// The original vtable is restored when the game exits; there is nothing to undo
	// here while it is running. The counters are worth one last write, though: this
	// is the only moment they are complete, and they are what explains a playback
	// that produced no line.
	tracker::logLiveStats();
	tracker::g_initialized = false;
}