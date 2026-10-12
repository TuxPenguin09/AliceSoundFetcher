#include "pch.h"
#include "HookManager.h"

#include <windows.h>
#include <MinHook.h>

#include <cstdio>

#include "../runtime/AudioTracker.h"

// The engine's audio path is reached through its own classes rather than a
// Windows API we can hook, because AliceSoft resolves DirectSound dynamically
// and never opens per-sound files: every asset lives inside the .afa archive and
// is played from memory.
//
// Hooking CreateFileW looking for ".ogg" cannot work for that reason, so the
// tracker discovers the engine's DirectSound buffer vtable via RTTI and hooks
// its methods instead. See runtime/AudioTracker.cpp.
void HookManager::init() {
	OutputDebugStringA("HookManager: installing audio hooks.\n");

	const int slots = AudioTracker::init();

	char message[128];
	snprintf(message, sizeof(message),
		"[%s] HookManager: %s audio hook (%d vtable slots).\n",
		GetModuleFileNameA(nullptr, nullptr, 0) ? "" : "",
		slots > 0 ? "installed" : "could not install",
		slots);
	OutputDebugStringA(message);
}

void HookManager::cleanup() {
	AudioTracker::cleanup();

	// MinHook is not used by the current tracker, but leave teardown correct if
	// a future hook requires it.
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}