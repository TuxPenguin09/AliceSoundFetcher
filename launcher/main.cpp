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

int main(int argc, char* argv[]) {
	// Tail mode takes no banner: the window is the log view itself.
	if (argc >= 3 && std::string(argv[1]) == "--tail") {
		return runTailMode(fs::path(argv[2]));
	}

	printBanner();

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <path_to_exe> " << "or drag an AliceSoft System game onto this program." << std::endl;
		std::cerr << "Error: No executable file provided." << std::endl;
		return 1;
	}

	fs::path gamePath = argv[1];

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