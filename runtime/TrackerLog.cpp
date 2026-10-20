// The log file, and the settings that control how much of it there is.
//
// The game process has no usable console, so events are appended to a file that
// the launcher tails. FILE_SHARE_READ|FILE_SHARE_WRITE lets both processes hold
// the file open at once.

#include "TrackerShared.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>

namespace tracker {

namespace {

constexpr wchar_t kLogEnvVar[] = L"ALICE_SOUNDFETCHER_LOG";

HANDLE g_logFile = INVALID_HANDLE_VALUE;
SRWLOCK g_logLock = SRWLOCK_INIT;

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

	// Exactly one CRLF per line, whatever the caller supplied.
	//
	// This used to rewrite every '\n' as "\r\n" and then append another "\r\n"
	// unconditionally, while the callers had already put a "\r\n" on the end of
	// their own text. Every entry therefore reached the file as "\r\r\n\r\n" and
	// showed up as a blank line in the middle of the log -- around 390 of them in a
	// short session, which is a large share of why the output was hard to read.
	//
	// So: drop whatever terminator the caller used, discard CR entirely, turn each
	// remaining LF into CRLF, and finish with one CRLF.
	size_t length = strlen(line);
	while (length > 0 && (line[length - 1] == '\r' || line[length - 1] == '\n')) {
		--length;
	}

	std::string buffer;
	buffer.reserve(length + 2);
	for (size_t i = 0; i < length; ++i) {
		if (line[i] == '\r') {
			continue;
		}
		if (line[i] == '\n') {
			buffer += '\r';
			buffer += '\n';
		} else {
			buffer += line[i];
		}
	}
	buffer += '\r';
	buffer += '\n';

	DWORD written = 0;
	WriteFile(g_logFile, buffer.data(), (DWORD)buffer.size(), &written, nullptr);

	// No FlushFileBuffers here. WriteFile has already put the bytes where the
	// tailer process can read them -- that is the only other reader, and it shares
	// the file. Forcing them down to the physical disk on every single hooked call
	// costs far more than the log is worth, and the call volume is thousands of
	// lines a session.
	OutputDebugStringA(line);

	ReleaseSRWLockExclusive(&g_logLock);
}

} // namespace

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

} // namespace tracker

// The C-ABI surface the emitted stubs call into.
//
// These are the only two entry points into the tracker from generated machine
// code, and they exist so the stub does not have to know about timestamps or the
// log file at all. They must have external linkage: the stub binds to them by
// address, and the assembler cannot see anything with internal linkage.
namespace tracker::internals {

void timestamp(char* out, size_t cap) { logTimestamp(out, cap); }
void write(const char* line) { writeLogLine(line); }

} // namespace tracker::internals

