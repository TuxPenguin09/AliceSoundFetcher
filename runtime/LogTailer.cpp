#include "LogTailer.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace {

	std::atomic<bool> g_running{ false };
	std::thread g_thread;

	// Track the byte offset already printed so only new lines are emitted.
	std::streamoff g_offset = 0;

	// Every line is flushed as it is produced.
	//
	// This matters more than it looks: a console opened for a new window is line
	// buffered, but when stdout is a pipe or a redirected file it becomes fully
	// buffered. Anything not explicitly flushed can sit in the buffer while the
	// program is blocked waiting for a keypress, which makes a live log viewer
	// look permanently frozen even though it is receiving events correctly.
	void emit(const std::string& line) {
		std::cout << line << std::endl;
		std::cout.flush();
	}

	void tailLoop(fs::path logPath) {
		emit(std::string("[log] Watching ") + logPath.string());
		emit(std::string(72, '-'));

		// Read with an explicit handle rather than std::ifstream.
		//
		// The log is created by the injected DLL, which may not have run yet, and
		// std::ifstream caches a failed open for the lifetime of the stream. The
		// handle is re-opened until the file appears, sharing access with the DLL
		// (which opens with FILE_SHARE_READ | FILE_SHARE_WRITE).
		HANDLE file = INVALID_HANDLE_VALUE;
		int announced = 0;

		// Start at the beginning rather than the end: this thread may not be
		// scheduled until after the DLL has already written the discovery lines
		// and the first few playback events, and seeking to the end would skip
		// exactly the lines worth seeing.
		std::streamoff offset = 0;
		std::string pending;

		while (g_running.load()) {
			if (file == INVALID_HANDLE_VALUE) {
				file = CreateFileW(
					logPath.c_str(),
					GENERIC_READ,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					nullptr,
					OPEN_ALWAYS,
					FILE_ATTRIBUTE_NORMAL,
					nullptr);

				if (file == INVALID_HANDLE_VALUE) {
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					continue;
				}

				announced = 1;
				emit("[log] Connected. Audio events appear here as they play.");
			}

			LARGE_INTEGER size{};
			if (!GetFileSizeEx(file, &size)) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				continue;
			}

			if (size.QuadPart > offset) {
				// Seek to the offset we have already consumed, NOT to the end of
				// the file. Seeking to `size` puts the read pointer past the new
				// data and ReadFile then returns 0 bytes, so nothing is ever shown.
				LARGE_INTEGER from{};
				from.QuadPart = offset;
				if (!SetFilePointerEx(file, from, nullptr, FILE_BEGIN)) {
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					continue;
				}

				DWORD available = (DWORD)(size.QuadPart - offset);
				std::string chunk;
				chunk.resize(available);

				DWORD read = 0;
				if (ReadFile(file, chunk.data(), available, &read, nullptr) && read > 0) {
					offset += read;
					chunk.resize(read);
					pending += chunk;

					// Emit only complete lines; hold a trailing partial line until
					// its newline arrives.
					size_t start = 0;
					while (true) {
						size_t nl = pending.find('\n', start);
						if (nl == std::string::npos) {
							break;
						}
						std::string line = pending.substr(start, nl - start);
						if (!line.empty() && line.back() == '\r') {
							line.pop_back();
						}
						emit(line);
						start = nl + 1;
					}
					pending.erase(0, start);
				}
				continue;
			}

			(void)announced;
			std::this_thread::sleep_for(std::chrono::milliseconds(120));
		}

		if (!pending.empty()) {
			emit(pending);
		}

		if (file != INVALID_HANDLE_VALUE) {
			CloseHandle(file);
		}
	}
}

bool LogTailer::start(const fs::path& logPath) {
	if (g_running.load()) {
		return true;
	}

	// The file may not exist yet; the DLL creates it on first write. Create an
	// empty one so the tailer can open it immediately and pick it up.
	if (!fs::exists(logPath)) {
		std::ofstream create(logPath, std::ios::binary | std::ios::trunc);
	}

	g_running = true;
	g_thread = std::thread(tailLoop, logPath);
	return true;
}

void LogTailer::stop() {
	if (!g_running.load()) {
		return;
	}
	g_running = false;
	if (g_thread.joinable()) {
		g_thread.join();
	}
}

bool LogTailer::running() {
	return g_running.load();
}