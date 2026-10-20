// Walking the loaded game executable: what is in it, what is executable, and which
// class each name belongs to.
//
// Every hook target is found by searching this one image. RTTI is retained in the
// shipped binaries, which is what makes the approach possible without guessing at
// object layouts.

#include "TrackerShared.h"

#include <tlhelp32.h>

#include <cstring>
#include <cwchar>
#include <string>

namespace tracker {

uintptr_t g_moduleBase = 0;
size_t g_moduleSize = 0;

std::vector<std::pair<uintptr_t, uintptr_t>> g_execRanges;

namespace {

void logLoadedModules() {
	// Enumerate modules once the game has finished starting.
	//
	// Called from a background thread rather than from init(): init() runs inside
	// DllMain, i.e. before the game's own start-up code has executed, so at that
	// point nothing but the core system libraries are loaded and the list says
	// nothing useful about where the engine's plugin code actually lives.
	//
	// This answered one question -- whether the engine's plugins are separate DLLs
	// or built into the executable -- and the answer was "built in": all 95 modules
	// on a stock Windows machine are system, driver or overlay DLLs, and the
	// registry strings for AFALoader and KiwiSoundEngine resolve to code inside the
	// executable. It is kept for the next game this is pointed at, where the answer
	// may well differ, but it is verbose-only: on this game it costs 95 lines of
	// graphics-driver noise in every run and finds nothing.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	MODULEENTRY32W entry{};
	entry.dwSize = sizeof(entry);

	int count = 0;
	if (Module32FirstW(snapshot, &entry)) {
		do {
			// Only non-system modules are interesting; the base set is always there.
			const wchar_t* path = entry.szExePath;
			if (wcsstr(path, L"\\Windows\\") || wcsstr(path, L"\\System32\\")) {
				continue;
			}
			logInfo("  module %-32ls base=%08lX size=0x%lX",
				entry.szModule, (unsigned long)(uintptr_t)entry.modBaseAddr,
				(unsigned long)entry.modBaseSize);
			++count;
		} while (Module32NextW(snapshot, &entry));
	}

	logInfo("AudioTracker: %d non-system modules loaded.", count);
	CloseHandle(snapshot);
}

} // namespace

bool isExecutable(uintptr_t va) {
	for (const auto& range : g_execRanges) {
		if (va >= range.first && va < range.second) {
			return true;
		}
	}
	return false;
}

void describeModule() {
	HMODULE main = GetModuleHandleW(nullptr);
	if (!main) {
		return;
	}
	g_moduleBase = (uintptr_t)main;

	// Size straight from the PE headers, avoiding a psapi dependency.
	const auto* dos = (const IMAGE_DOS_HEADER*)main;
	const auto* nt = (const IMAGE_NT_HEADERS32*)((const uint8_t*)main + dos->e_lfanew);
	g_moduleSize = nt->OptionalHeader.SizeOfImage;

	g_execRanges.clear();
	const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
		if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
			continue;
		}
		// Use the larger of the two sizes: MSVC can leave real code sitting past
		// VirtualSize, and Evenicle's .text is exactly that case (VirtualSize
		// 0x295E53 vs SizeOfRawData 0x296000).
		uint32_t span = sec->Misc.VirtualSize;
		if (sec->SizeOfRawData > span) {
			span = sec->SizeOfRawData;
		}
		const uintptr_t lo = (uintptr_t)main + sec->VirtualAddress;
		g_execRanges.emplace_back(lo, lo + span);
	}
}

void moduleSnapshotThread() {
	Sleep(8000);

	if (!g_verbose) {
		return;
	}

	logInfo("AudioTracker: module list 8s after start-up:");
	logLoadedModules();
}

const uint8_t* findInModule(const char* needle) {
	if (!g_moduleBase || !g_moduleSize) {
		return nullptr;
	}
	const size_t needleLen = strlen(needle);
	if (!needleLen || g_moduleSize < needleLen) {
		return nullptr;
	}

	const uint8_t* start = (const uint8_t*)g_moduleBase;
	const uint8_t* end = start + g_moduleSize;
	for (const uint8_t* p = start; p + needleLen <= end; ++p) {
		if (memcmp(p, needle, needleLen) == 0) {
			return p;
		}
	}
	return nullptr;
}

// Resolve the TypeDescriptor RVA for a class by its unqualified name.
//
// The full RTTI name is matched, i.e. the character after the class name must be
// '@'. Without that check, searching for "CDirectSound" would happily match
// ".?AVCDirectSoundBuffer@kiwi@@" whenever that string happened to come first in
// the image, and the wrong class would get hooked.
//
// Every occurrence has to be considered, not only the first. One class name can be
// a prefix of another, and descriptors are not emitted in name order: in Evenicle
// the first "?AVCSoundChannel" in the image belongs to CSoundChannelList, so
// stopping at the first hit rejected it and logged "CSoundChannel: no RTTI" for a
// class whose descriptor was forty bytes further on. Any name that is a prefix of
// another was silently unhookable for the same reason.
uint32_t findTypeDescriptorRva(const char* className) {
	std::string needle = ".?AV";
	needle += className;

	if (!g_moduleBase || !g_moduleSize) {
		return 0;
	}

	const uint8_t* start = (const uint8_t*)g_moduleBase;
	const uint8_t* end = start + g_moduleSize;
	const size_t needleLen = needle.size();

	for (const uint8_t* p = start; p + needleLen + 1 <= end; ++p) {
		if (memcmp(p, needle.c_str(), needleLen) != 0) {
			continue;
		}
		if (p[needleLen] != '@') {
			continue; // a longer class name that starts with this one
		}
		// A TypeDescriptor is { vftable; spare; char name[] }, so the name sits 8
		// bytes into it.
		const size_t offset = (size_t)(p - start);
		if (offset < 8) {
			continue;
		}
		return static_cast<uint32_t>(offset - 8);
	}
	return 0;
}

bool findVtable(uint32_t colRva, uintptr_t& outVtable);

// MSVC CompleteObjectLocator:
//   signature, offset, cdOffset, pTypeDescriptor, pClassHierarchy, pSelf
//
// Verified against the shipped AliceSoft builds: pTypeDescriptor is stored as an
// absolute VA rather than an RVA, and pSelf is zero. Anchoring on pSelf (as one
// would for a rebased image) therefore fails here, so both encodings are tried and
// the signature word validates the candidate instead.
//
// A locator is accepted only once a vtable actually points at it. The signature
// check alone is not enough, because one TypeDescriptor can be named by more than
// one locator-shaped structure, and the first one in the image is not always the
// one a vtable uses. Dohna Dohna's CSoundChannel and CGroupTree, and Evenicle 2's
// CGroupTree, each have such a decoy ahead of the real locator; taking it made the
// class report "no vtable" while its vtable sat a few dozen bytes away, so the two
// routing classes that scene dialogue runs through were never hooked.
bool findCompleteObjectLocator(uint32_t typeDescriptorRva, uint32_t& outColRva) {
	const uint8_t* start = (const uint8_t*)g_moduleBase;
	const uint8_t* end = start + g_moduleSize;

	const uint32_t keys[2] = {
		static_cast<uint32_t>(g_moduleBase + typeDescriptorRva), // VA encoding
		typeDescriptorRva,                                       // RVA encoding
	};

	for (int keyIndex = 0; keyIndex < 2; ++keyIndex) {
		const uint32_t key = keys[keyIndex];

		for (const uint8_t* p = start; p + sizeof(uint32_t) <= end; ++p) {
			uint32_t value = 0;
			memcpy(&value, p, sizeof(value));
			if (value != key) {
				continue;
			}

			// pTypeDescriptor sits at offset +12.
			const uint8_t* candidate = p - 12;
			if (candidate < start || candidate + 20 > end) {
				continue;
			}

			uint32_t signature = 0;
			memcpy(&signature, candidate, sizeof(signature));
			if (signature > 1) {
				continue;
			}

			const uint32_t colRva = static_cast<uint32_t>(candidate - start);

			// Reject the decoy: a locator nothing points at is not this class's.
			uintptr_t ignored = 0;
			if (!findVtable(colRva, ignored)) {
				continue;
			}

			outColRva = colRva;
			return true;
		}
	}
	return false;
}

// The vtable pointer sits immediately after the COL pointer, so the COL is
// referenced as a dword in the data section and the entry after it is the vtable.
// Same VA/RVA ambiguity, so both are tried. The candidate is only accepted when a
// following slot already points into executable memory.
bool findVtable(uint32_t colRva, uintptr_t& outVtable) {
	const uint8_t* start = (const uint8_t*)g_moduleBase;
	const uint8_t* end = start + g_moduleSize;

	const uint32_t keys[2] = {
		static_cast<uint32_t>(g_moduleBase + colRva),
		colRva,
	};

	for (int keyIndex = 0; keyIndex < 2; ++keyIndex) {
		const uint32_t key = keys[keyIndex];

		for (const uint8_t* p = start; p + sizeof(uint32_t) <= end; ++p) {
			uint32_t value = 0;
			memcpy(&value, p, sizeof(value));
			if (value != key) {
				continue;
			}

			const uint8_t* table = p + 4;
			if (table + 4 > end) {
				continue;
			}
			uintptr_t first = 0;
			memcpy(&first, table, sizeof(first));
			if (!isExecutable(first)) {
				continue;
			}

			outVtable = reinterpret_cast<uintptr_t>(table);
			return true;
		}
	}
	return false;
}

} // namespace tracker