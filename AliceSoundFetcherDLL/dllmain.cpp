#include "pch.h"
#include <windows.h>
#include "HookManager.h"
#include "../runtime/AudioTracker.h"

namespace {
    // Installs hooks once the DLL is mapped. Runs on its own thread so
    // DllMain never blocks on the loader lock.
    DWORD WINAPI InitHookThread(LPVOID) {
        HookManager::init();
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            HANDLE thread = CreateThread(nullptr, 0, InitHookThread, nullptr, 0, nullptr);
            if (thread) {
                CloseHandle(thread);
            }
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            HookManager::cleanup();
            break;
    }
    return TRUE;
}