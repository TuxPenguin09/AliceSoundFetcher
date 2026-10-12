#pragma once

#include <filesystem>

namespace fs = std::filesystem;

// Opens the live session-log window in its own console.
//
// The injected DLL appends events to a log file; this launcher watches that
// file and mirrors new lines into a separate console, so audio events stay
// visible while the game runs and remain on screen after it exits.
//
// The tailer runs on its own thread. It is stopped by LogTailer::stop(), which
// the launcher calls once the tracked process has exited.
class LogTailer {
public:
	// Begins tailing logPath. Returns false if the file cannot be opened.
	static bool start(const fs::path& logPath);

	// Signals the tail thread to finish. Safe to call more than once.
	static void stop();

	static bool running();
};