#pragma once

// Stage 1 audio tracking.
//
// Runs inside the injected DLL, i.e. inside the game's own process, so it can
// observe playback as it happens rather than inferring it from file access.
//
// What this stage deliberately does NOT do: decode any object layout. It logs
// the slot index, the incoming registers and a timestamp, which is enough to
// confirm we hooked the right function without guessing at field offsets. A
// wrong assumption would otherwise show up as plausible-looking garbage.

class AudioTracker {
public:
	// Discovers the sound-engine vtables and installs forwarding stubs.
	// Returns the number of hooked virtual slots, or 0 on failure.
	static int init();

	static void cleanup();

	// Installs a vectored exception handler that records the faulting address of
	// any access violation, so a crash caused by one of our stubs can be attributed
	// to our code rather than guessed at. Safe to call before init().
	static void installExceptionDiagnostics();

	// Number of slots discovered; 0 before init().
	static int slotCount();

	// Path the log is written to, resolved from the launcher.
	static const wchar_t* logPath();
};