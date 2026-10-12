#include "Injector.h"
#include <windows.h>
#include <TlHelp32.h>
#include <cwchar>

#include <iostream>
#include <fstream>

namespace {
	using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

	// RAII for kernel handles so every early return still releases them.
	class ScopedHandle {
	public:
		explicit ScopedHandle(HANDLE h = nullptr) : handle_(h) {}
		~ScopedHandle() { reset(); }

		ScopedHandle(const ScopedHandle&) = delete;
		ScopedHandle& operator=(const ScopedHandle&) = delete;

		HANDLE get() const { return handle_; }
		explicit operator bool() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

		void reset(HANDLE h = nullptr) {
			if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
				CloseHandle(handle_);
			}
			handle_ = h;
		}

	private:
		HANDLE handle_;
	};

	USHORT GetEffectiveMachine(HANDLE processHandle, USHORT& nativeMachine) {
		USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
		nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
		auto kernel32 = GetModuleHandleW(L"kernel32.dll");
		auto isWow64Process2 = reinterpret_cast<IsWow64Process2_t>(GetProcAddress(kernel32, "IsWow64Process2"));
		if (isWow64Process2 && isWow64Process2(processHandle, &processMachine, &nativeMachine)) {
			return processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine;
		}

		BOOL isWow64 = FALSE;
		if (IsWow64Process(processHandle, &isWow64)) {
			SYSTEM_INFO systemInfo;
			GetNativeSystemInfo(&systemInfo);
			USHORT native = (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
				? IMAGE_FILE_MACHINE_AMD64
				: IMAGE_FILE_MACHINE_I386;
			return isWow64 ? IMAGE_FILE_MACHINE_I386 : native;
		}

		return IMAGE_FILE_MACHINE_UNKNOWN;
	}

	USHORT GetPeMachineType(const fs::path& filePath) {
		std::ifstream file(filePath, std::ios::binary);
		if (!file) {
			return IMAGE_FILE_MACHINE_UNKNOWN;
		}

		IMAGE_DOS_HEADER dosHeader{};
		file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
		if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
			return IMAGE_FILE_MACHINE_UNKNOWN;
		}

		file.seekg(dosHeader.e_lfanew, std::ios::beg);
		DWORD ntSignature = 0;
		file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
		if (!file || ntSignature != IMAGE_NT_SIGNATURE) {
			return IMAGE_FILE_MACHINE_UNKNOWN;
		}

		IMAGE_FILE_HEADER fileHeader{};
		file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
		if (!file) {
			return IMAGE_FILE_MACHINE_UNKNOWN;
		}

		return fileHeader.Machine;
	}

	// WaitForInputIdle lives in user32.lib. Resolving it at run time keeps this file
	// free of extra link dependencies, matching the rest of the launcher.
	using WaitForInputIdle_t = BOOL(WINAPI*)(HANDLE, DWORD);

	WaitForInputIdle_t ResolveWaitForInputIdle() {
		static WaitForInputIdle_t fn = []() -> WaitForInputIdle_t {
			HMODULE user32 = GetModuleHandleW(L"user32.dll");
			if (!user32) {
				user32 = LoadLibraryW(L"user32.dll");
			}
			if (!user32) {
				return nullptr;
			}
			return reinterpret_cast<WaitForInputIdle_t>(
				GetProcAddress(user32, "WaitForInputIdle"));
		}();
		return fn;
	}

	// Resolve LoadLibraryW at its address INSIDE the target process.
	//
	// CreateRemoteThread takes a raw start address, and ASLR can place kernel32
	// at a different base in each process, so the ideal answer is the target's
	// own address. However, the target is still suspended at this point and a
	// suspended process has no populated module list, so
	// CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) fails against it. Use the
	// snapshot when it works, and otherwise fall back to our own address, which
	// is correct whenever the two processes share a kernel32 base. If the
	// fallback were ever wrong, LoadLibraryW faults in the target and the exit
	// code check below reports it rather than failing silently.
	LPTHREAD_START_ROUTINE ResolveRemoteLoadLibraryW(HANDLE process) {
		auto localKernel32 = GetModuleHandleW(L"kernel32.dll");
		if (!localKernel32) {
			std::cerr << "Injector Error: kernel32.dll is not loaded in this process." << std::endl;
			return nullptr;
		}

		auto localLoadLibraryW = reinterpret_cast<LPBYTE>(
			GetProcAddress(localKernel32, "LoadLibraryW"));
		if (!localLoadLibraryW) {
			std::cerr << "Injector Error: LoadLibraryW not found." << std::endl;
			return nullptr;
		}

		ScopedHandle snapshot(CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process)));

		MODULEENTRY32W module{};
		module.dwSize = sizeof(module);
		if (snapshot && Module32FirstW(snapshot.get(), &module)) {
			do {
				if (_wcsicmp(module.szModule, L"kernel32.dll") == 0) {
					const uintptr_t offset =
						reinterpret_cast<uintptr_t>(localLoadLibraryW) -
						reinterpret_cast<uintptr_t>(localKernel32);
					return reinterpret_cast<LPTHREAD_START_ROUTINE>(
						reinterpret_cast<uintptr_t>(module.modBaseAddr) + offset);
				}
			} while (Module32NextW(snapshot.get(), &module));
		}

		return reinterpret_cast<LPTHREAD_START_ROUTINE>(localLoadLibraryW);
	}
}

bool Injector::LaunchAndInject(const fs::path& exePath, const fs::path& dllPath) {
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};

	std::wstring exePathStr = exePath.wstring();
	std::wstring dllPathStr = dllPath.wstring();

	USHORT currentNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	USHORT currentMachine = GetEffectiveMachine(GetCurrentProcess(), currentNativeMachine);
	USHORT dllMachine = GetPeMachineType(dllPath);

	// Start suspended. Everything below happens while the game's main thread has
	// not executed a single instruction, so the archive has not been opened and
	// no audio has been played yet. The thread is resumed only after the DLL is
	// loaded and its hooks are installed.
	BOOL created = CreateProcessW(
		exePathStr.c_str(),
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		exePath.parent_path().wstring().c_str(),
		&si,
		&pi
	);

	if (!created) {
		std::cerr << "Error: Failed to create process. Error code: " << GetLastError() << std::endl;
		return false;
	}

	ScopedHandle process(pi.hProcess);
	ScopedHandle thread(pi.hThread);

	std::cout << "Process created (suspended). PID: " << pi.dwProcessId << std::endl;

	USHORT targetNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	USHORT targetMachine = GetEffectiveMachine(pi.hProcess, targetNativeMachine);

	if (currentMachine != IMAGE_FILE_MACHINE_UNKNOWN && targetMachine != IMAGE_FILE_MACHINE_UNKNOWN && currentMachine != targetMachine) {
		std::cerr << "Error: Injector and target process architectures do not match. Rebuild the injector/DLL for the target architecture." << std::endl;
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	if (dllMachine != IMAGE_FILE_MACHINE_UNKNOWN && targetMachine != IMAGE_FILE_MACHINE_UNKNOWN && dllMachine != targetMachine) {
		std::cerr << "Error: DLL architecture does not match the target process. Rebuild the DLL for the target architecture." << std::endl;
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	LPVOID remoteMem = VirtualAllocEx(
		pi.hProcess,
		NULL,
		(dllPathStr.size() + 1) * sizeof(wchar_t),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!remoteMem) {
		std::cerr << "Error: Failed to allocate memory in target process. Error code: " << GetLastError() << std::endl;
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	BOOL wroteMemory = WriteProcessMemory(
		pi.hProcess,
		remoteMem,
		dllPathStr.c_str(),
		(dllPathStr.size() + 1) * sizeof(wchar_t),
		NULL
	);

	if (!wroteMemory) {
		std::cerr << "Error: Failed to write DLL path into target process. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	LPTHREAD_START_ROUTINE remoteLoadLibraryW = ResolveRemoteLoadLibraryW(pi.hProcess);
	if (!remoteLoadLibraryW) {
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	// Loading the DLL runs DllMain, which starts the hook thread. That thread may
	// not have installed its hooks by the time LoadLibraryW returns, so wait
	// briefly on the game becoming responsive rather than assuming a race-free
	// window. HookManager does its work off the loader lock, so this is safe.
	ScopedHandle remoteThread(CreateRemoteThread(
		pi.hProcess,
		NULL,
		0,
		remoteLoadLibraryW,
		remoteMem,
		0,
		NULL
	));

	if (!remoteThread) {
		std::cerr << "Error: Failed to create remote thread. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WaitForSingleObject(remoteThread.get(), INFINITE);

	DWORD remoteExitCode = 0;
	GetExitCodeThread(remoteThread.get(), &remoteExitCode);

	if (remoteExitCode == 0) {
		std::cerr << "Error: LoadLibraryW failed inside target process." << std::endl;
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	std::wcout << L"DLL injected successfully. " << dllPathStr << std::endl;
	std::cout << "DLL loaded at remote module base: 0x" << std::hex << remoteExitCode << std::dec << std::endl;

	VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

	// Only now let the game run. Hooks are installed before any game code runs.
	DWORD resumeResult = ResumeThread(pi.hThread);
	if (resumeResult == static_cast<DWORD>(-1)) {
		std::cerr << "Error: Failed to resume process thread. Error code: " << GetLastError() << std::endl;
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	// Optional nicety: wait for the window to pump messages. Not required for the
	// injection itself, so a missing user32 must not fail the launch.
	WaitForInputIdle_t waitForInputIdle = ResolveWaitForInputIdle();
	if (waitForInputIdle) {
		waitForInputIdle(pi.hProcess, 5000);
	}

	std::cout << "Process resumed." << std::endl;

	return true;
}