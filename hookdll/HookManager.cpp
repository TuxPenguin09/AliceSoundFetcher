#include "HookManager.h"
#include <windows.h>
#include <iostream>
#include <MinHook.h>

typedef HANDLE(WINAPI* CreateFileW_t)(
	LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
);

CreateFileW_t originalCreateFileW = nullptr;

HANDLE WINAPI hookedCreateFileW(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
) {
	if (lpFileName) {
		std::wstring file(lpFileName);

		if (file.find(L".ogg") != std::wstring::npos) {
			// debug log
			OutputDebugStringW((L"AudioHook: " + file + L"\n").c_str());
		}
	}

	return originalCreateFileW(
		lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
	);
}

void HookManager::init() {
	MH_Initialize();

	MH_CreateHook(&CreateFileW, &hookedCreateFileW, reinterpret_cast<LPVOID*>(&originalCreateFileW));
	MH_EnableHook(&CreateFileW);

	OutputDebugStringA("HookManager: Hooks initialized.\n");
}

void HookManager::cleanup() {
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}