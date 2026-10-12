#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>

#include "FileScan.h"
#include "../parser/AFARead.h"
#include "../runtime/LogTailer.h"
#include "Injector.h"

namespace fs = std::filesystem;

void printBanner() {
	std::cout << "Alice Sound Fetcher" << std::endl;
}

bool isEXEFile(const fs::path& filePath) {
	return filePath.has_extension() && filePath.extension() == ".exe";
}

// Live-log viewer mode. The launcher re-launches this same executable with
// "--tail <logfile>" and CREATE_NEW_CONSOLE so audio events appear in their own
// window that outlives the game.
int runTailMode(const fs::path& logPath) {
	// Hide the cursor so live updates do not flicker.
	const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_CURSOR_INFO cursorInfo{};
	if (out != INVALID_HANDLE_VALUE && GetConsoleCursorInfo(out, &cursorInfo)) {
		cursorInfo.bVisible = FALSE;
		SetConsoleCursorInfo(out, &cursorInfo);
	}

	// Ensure the file exists before the tailer opens it, so the DLL appends to a
	// file we already have a handle on.
	if (!fs::exists(logPath)) {
		std::ofstream create(logPath, std::ios::binary | std::ios::trunc);
	}

	std::cout << "==================================================" << std::endl;
	std::cout << "  Alice Sound Fetcher - live audio log" << std::endl;
	std::cout << "==================================================" << std::endl;
	std::cout << "log file: " << logPath.string() << std::endl << std::endl;

	if (!LogTailer::start(logPath)) {
		std::cerr << "Failed to tail " << logPath.string() << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "Play the game. Audio events appear here as they play." << std::endl;
	std::cout << "This window stays open after the game exits." << std::endl;
	std::cout << std::endl;
	std::cout << "Press any key to close this window." << std::endl;

	// Let the tail thread print its header before the key prompt takes over the
	// console, otherwise the two interleave and the output looks scrambled.
	Sleep(300);
	system("pause");
	LogTailer::stop();

	if (out != INVALID_HANDLE_VALUE && GetConsoleCursorInfo(out, &cursorInfo)) {
		cursorInfo.bVisible = TRUE;
		SetConsoleCursorInfo(out, &cursorInfo);
	}
	return 0;
}

// ---------------------------------------------------------------------------
// Optional settings file
//
// A plain key=value file read from beside the executable, so the diagnostic
// knobs that matter day to day can be changed without a rebuild. Nothing here
// changes what the tool fundamentally does.
//
//   # comment
//   verbose = 1
//   classes = CSoundPlayer,CDirectSoundBuffer
//   dumpObjects = 0
//   hookComparisons = 0
//
// A missing file, or a missing key, means "use the default".
// ---------------------------------------------------------------------------

struct Settings {
	bool verbose = false;
	bool dumpObjects = false;
	bool hookComparisons = false;
	std::string classes; // empty means the built-in list
};

namespace {

fs::path settingsPath() {
	wchar_t selfPath[MAX_PATH] = {};
	if (!GetModuleFileNameW(nullptr, selfPath, MAX_PATH)) {
		return fs::path();
	}
	return fs::path(selfPath).parent_path() / "AliceSoundFetcher.ini";
}

std::string trimText(const std::string& s) {
	size_t begin = 0;
	size_t end = s.size();
	while (begin < end && (s[begin] == ' ' || s[begin] == '\t' || s[begin] == '\r')) {
		++begin;
	}
	while (end > begin && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r')) {
		--end;
	}
	return s.substr(begin, end - begin);
}

bool parseBool(const std::string& value, bool fallback) {
	const std::string v = trimText(value);
	if (v == "1" || v == "true" || v == "yes" || v == "on") {
		return true;
	}
	if (v == "0" || v == "false" || v == "no" || v == "off") {
		return false;
	}
	return fallback;
}

} // namespace

Settings loadSettings() {
	Settings settings;

	std::ifstream file(settingsPath());
	if (!file) {
		return settings; // no file is normal; defaults are what most users want
	}

	std::string line;
	while (std::getline(file, line)) {
		const size_t comment = line.find_first_of("#;");
		if (comment != std::string::npos) {
			line = line.substr(0, comment);
		}
		line = trimText(line);
		if (line.empty()) {
			continue;
		}

		const size_t equals = line.find('=');
		if (equals == std::string::npos) {
			continue;
		}

		std::string key = trimText(line.substr(0, equals));
		const std::string value = trimText(line.substr(equals + 1));

		// Tolerate a UTF-8 byte order mark.
		//
		// Notepad on Windows writes one by default, so an .ini saved from it is
		// the single most likely way for a user to produce a file. Without this the
		// first key is read as "\xEF\xBB\xBFverbose", matches nothing, and the
		// setting is ignored with no indication that anything went wrong.
		if (key.size() >= 3 &&
			(unsigned char)key[0] == 0xEF &&
			(unsigned char)key[1] == 0xBB &&
			(unsigned char)key[2] == 0xBF) {
			key.erase(0, 3);
		}

		if (key == "verbose") {
			settings.verbose = parseBool(value, settings.verbose);
		} else if (key == "dumpObjects") {
			settings.dumpObjects = parseBool(value, settings.dumpObjects);
		} else if (key == "hookComparisons") {
			settings.hookComparisons = parseBool(value, settings.hookComparisons);
		} else if (key == "classes") {
			settings.classes = value;
		} else {
			// An unrecognised key is more likely a typo than a deliberate extra
			// setting, and a typo that is ignored in silence is exactly the kind of
			// thing that sends someone looking for a bug that is not there.
			std::cout << "config: ignoring unknown setting \"" << key
				<< "\" in " << settingsPath().filename().string() << std::endl;
		}
	}

	if (settings.verbose) {
		std::cout << "config: verbose logging enabled" << std::endl;
	}

	return settings;
}

int main(int argc, char* argv[]) {
	// Tail mode takes no banner: the window is the log view itself.
	if (argc >= 3 && std::string(argv[1]) == "--tail") {
		return runTailMode(fs::path(argv[2]));
	}

	// Settings are read first so an explicit --verbose can override the file.
	Settings settings = loadSettings();

	std::string gameArgument;
	bool verboseFlag = false;
	for (int i = 1; i < argc; ++i) {
		const std::string arg = argv[i];
		if (arg == "--verbose" || arg == "-v") {
			verboseFlag = true;
		} else if (arg == "--help" || arg == "-h") {
			std::cout << "Usage: " << argv[0] << " <game.exe> [--verbose]" << std::endl
				<< "       " << argv[0] << " --tail <logfile>" << std::endl
				<< std::endl
				<< "Settings may be placed in AliceSoundFetcher.ini beside this program." << std::endl;
			return 0;
		} else if (gameArgument.empty()) {
			gameArgument = arg;
		}
	}
	if (verboseFlag) {
		settings.verbose = true;
	}

	printBanner();

	if (gameArgument.empty()) {
		std::cerr << "Usage: " << argv[0] << " <path_to_exe> " << "or drag an AliceSoft System game onto this program." << std::endl;
		std::cerr << "Error: No executable file provided." << std::endl;
		return 1;
	}

	fs::path gamePath = gameArgument;

	if (!fs::exists(gamePath)) {
		std::cerr << "Error: The specified file does not exist." << std::endl;
		return 1;
	}

	if (!isEXEFile(gamePath)) {
		std::cerr << "Error: The specified file is not an executable (.exe)." << std::endl;
		return 1;
	}

	std::cout << "Game selected: " << gamePath.string() << std::endl;
	fs::path gameDir = gamePath.parent_path();

	std::cout << "Game directory: " << gameDir.string() << std::endl;

	std::cout << "afa: Scanning for .afa..." << std::endl;
	auto afaFiles = FileScan::findAFAFiles(gameDir);
	FileScan::printFiles(afaFiles);
	std::cout << "afa: Found " << afaFiles.size() << "\n" << std::endl;

	// Keep every archive. The names are handed to the injected DLL so it can
	// check a string it finds inside a sound object against the real entry list
	// rather than trusting that a plausible-looking run of bytes is a filename.
	std::vector<AFAArchive> allArchives;

	std::cout << "afa: Indexing AFA archives..." << std::endl;
	for (const auto& afaFile : afaFiles) {
		AFAArchive archive = AFARead::parse(afaFile);

		if (archive.valid) {
			std::cout << "afa: Indexed " << archive.entries.size() << " entries from "
				<< afaFile.filename().string() << std::endl;
			allArchives.push_back(std::move(archive));
		}
		else {
			std::cout << "afa: Skipped " << afaFile.filename().string()
				<< " (" << archive.error << ")" << std::endl;
		}
	}
	std::cout << std::endl;

	// The DLL sits beside the launcher, so resolve it from our own module path
	// rather than the working directory. Drag-and-drop and shortcuts can start
	// us from anywhere.
	wchar_t selfPath[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
	fs::path dllPath = fs::path(selfPath).parent_path() / "AliceSoundFetcherDLL.dll";

	if (!fs::exists(dllPath)) {
		std::cerr << "Error: The specified DLL does not exist. " << dllPath << std::endl;
		system("pause");
		return 1;
	}

	// Session log. The injected DLL appends audio events here and the tailer
	// below mirrors them, so the env var is how the two processes agree on it.
	const fs::path logPath = fs::path(selfPath).parent_path() / "AliceSoundFetcher.log";
	SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_LOG", logPath.c_str());

	// Hand the resolved settings to the injected DLL. The launcher reads the file
	// rather than the DLL doing it: the DLL is already the busiest thing in the
	// process, and this keeps its start-up work to a few environment lookups.
	SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_VERBOSE",
		settings.verbose ? L"1" : L"0");
	SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_DUMPOBJECTS",
		settings.dumpObjects ? L"1" : L"0");
	SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_COMPARES",
		settings.hookComparisons ? L"1" : L"0");
	if (!settings.classes.empty()) {
		const std::wstring wide(settings.classes.begin(), settings.classes.end());
		SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_CLASSES", wide.c_str());
		std::cout << "config: hooking only the classes listed in the settings file"
			<< std::endl;
	}

	// Hand the entry names to the DLL.
	//
	// The runtime finds Shift-JIS strings inside sound objects, but "looks like a
	// filename" is a weak signal -- pointer data and Japanese display labels also
	// score well. Giving the DLL the real entry list lets it confirm a candidate
	// before reporting it, which is the difference between a measurement and a
	// guess. Format is one line per entry: archive name, TAB, raw entry name
	// bytes, LF. Written in binary because the names are Shift-JIS and must not
	// be transcoded on the way through.
	const fs::path indexPath = fs::path(selfPath).parent_path() / "AliceSoundFetcher.names";
	{
		std::ofstream index(indexPath, std::ios::binary | std::ios::trunc);
		size_t written = 0;
		if (index) {
			for (const AFAArchive& archive : allArchives) {
				const std::string archiveName = fs::path(archive.archPath).filename().string();
				for (const AFAEntry& entry : archive.entries) {
					index << archiveName << '\t' << entry.fileName << '\n';
					++written;
				}
			}
		}
		if (index && index.good()) {
			std::cout << "afa: Wrote " << written << " entry names to "
				<< indexPath.filename().string() << std::endl;
			SetEnvironmentVariableW(L"ALICE_SOUNDFETCHER_INDEX", indexPath.c_str());
		}
		else {
			std::cerr << "afa: Warning: could not write " << indexPath
				<< "; the runtime will not be able to validate names." << std::endl;
		}
	}

	// The live view gets its own console so this launcher's output stays
	// readable, and it keeps running after the game closes. It is this same
	// executable re-launched in --tail mode with a fresh console.
	std::wstring selfExe(selfPath);
	STARTUPINFOW tsi = { sizeof(tsi) };
	PROCESS_INFORMATION tpi = {};

	// CreateProcessW may modify the command line in place, so it needs a mutable
	// buffer. argv[0] is quoted because the path may contain spaces.
	// CreateProcessW may modify the command line in place, so it needs a mutable
	// buffer. argv[0] is quoted because the path may contain spaces.
	std::vector<wchar_t> tailCmd;
	const std::wstring tailCmdText = L"\"" + selfExe + L"\" --tail \"" + logPath.wstring() + L"\"";
	tailCmd.assign(tailCmdText.begin(), tailCmdText.end());
	tailCmd.push_back(L'\0');

	if (CreateProcessW(selfExe.c_str(), tailCmd.data(), nullptr, nullptr, FALSE,
		CREATE_NEW_CONSOLE, nullptr, nullptr, &tsi, &tpi)) {
		CloseHandle(tpi.hThread);
		CloseHandle(tpi.hProcess);
	}
	else {
		std::cout << "Note: could not start the log viewer (" << GetLastError() << ")" << std::endl;
		std::cout << "Audio events will still be written to " << logPath << std::endl;
	}

	std::cout << "Injecting DLL..." << std::endl;

	if (!Injector::LaunchAndInject(gamePath, dllPath)) {
		std::cerr << "Error: Failed to launch and inject." << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "Injection Successful!" << std::endl;
	std::cout << "Play the game; audio events appear in the log viewer window." << std::endl;
	std::cout << std::endl;
	std::cout << "Press any key to stop waiting (the game keeps running)." << std::endl;
	system("pause");
	return 0;
}