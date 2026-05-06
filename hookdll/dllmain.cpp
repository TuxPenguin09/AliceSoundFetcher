#include <windows.h>
#include "HookManager.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls(hModule);
			HookManager::init();
			break;
		case DLL_PROCESS_DETACH:
			HookManager::cleanup();
			break;
	}
	return TRUE;
}