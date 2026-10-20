#pragma once

// Shared state and small utilities for the in-process audio tracker.
//
// Everything here is internal to the tracker: nothing in this header is part of
// the launcher's API. It is split out only so that the tracker's several
// translation units can agree on one copy of the state, rather than each holding
// its own.
//
// The one thing that must stay at global scope with C linkage is
// AudioTrackerLogHook, because the hand-assembled forwarding stubs call it by
// address and the assembler cannot bind to internal linkage. It is declared at the
// bottom of this file rather than tucked into one of the other headers, because it
// is the interface between the emitted machine code and everything else.

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tracker {

// ---------------------------------------------------------------------------
// Settings
//
// Read once at start-up from the environment the launcher sets from
// AliceSoundFetcher.ini. Each has a comment in TrackerSettings.cpp explaining what
// it turns on and why it is off or on by default.
// ---------------------------------------------------------------------------

extern bool g_verbose;
extern bool g_dumpObjects;
extern bool g_hookComparisons;
extern bool g_liveNames;
extern bool g_passthrough;

// Read an environment variable that is considered set when its value is "1".
bool envFlag(const wchar_t* name);

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

void logTimestamp(char* out, size_t cap);

// One log line: a timestamp, then the formatted text.
void logInfo(const char* fmt, ...);

// ---------------------------------------------------------------------------
// The loaded module
//
// The game executable, and the ranges of it that hold executable bytes. Everything
// else is discovered by walking this image: RTTI is searched inside it, and hook
// targets are chosen from it.
// ---------------------------------------------------------------------------

extern uintptr_t g_moduleBase;
extern size_t g_moduleSize;

// Executable address ranges of the main module.
//
// These matter far more than they look. The .rdata section is laid out as a long
// run of [CompleteObjectLocator][vftable] pairs for many unrelated classes, so the
// dwords *after* a class's last virtual function look exactly like more virtual
// functions -- they are simply pointers that happen to fall inside the image.
// Counting "pointers inside the module" therefore walks off the end of the vtable
// and into neighbouring classes, and patching those slots corrupts every class
// that follows. Confining the walk to executable memory stops it at the next
// class's COL.
extern std::vector<std::pair<uintptr_t, uintptr_t>> g_execRanges;

void describeModule();

bool isExecutable(uintptr_t va);

void moduleSnapshotThread();

// RTTI lookups, used to find each class's vtable inside the image. Each returns
// false rather than a guess when the structure cannot be located.
const uint8_t* findInModule(const char* needle);
uint32_t findTypeDescriptorRva(const char* className);
bool findCompleteObjectLocator(uint32_t typeDescriptorRva, uint32_t& outColRva);
bool findVtable(uint32_t colRva, uintptr_t& outVtable);

// ---------------------------------------------------------------------------
// Guarded reads
//
// The hooks read addresses taken from the game's own data, which are arbitrary as
// far as this code is concerned: most are unmapped. Every such read is guarded,
// and g_probing is raised while it happens so the vectored exception handler does
// not report the resulting access violation as a fault.
// ---------------------------------------------------------------------------

// Nesting depth of deliberate probing, not a boolean.
//
// The hooks run on whichever game thread happens to be in an audio call, and
// several of them probe at once. As a plain flag this was wrong under
// concurrency: thread A would finish and clear it while thread B was still reading
// an unguarded address, so B's caught access violation reached the vectored handler
// as if it were a real fault. Counting instead means the last probe out is the one
// that turns reporting back on.
// Defined in TrackerHook.cpp.
extern LONG g_probing;

// These use __try/__except and so must not construct anything with a destructor.
bool safeRead32(uintptr_t address, uint32_t* out);
int safeReadAscii(uintptr_t address, char* out, int max);
bool safeReadMemory(void* dst, uintptr_t src, size_t length);

// ---------------------------------------------------------------------------
// Shift-JIS text
//
// Archive entry names are raw CP932, so an ASCII-only scanner reports nothing at
// all. CP932 two-byte characters have lead bytes 0x81-0x9F or 0xE0-0xFC, and the
// trail byte is 0x40-0x7E or 0x80-0xFC.
// ---------------------------------------------------------------------------

int shiftJisRunLength(const uint8_t* p, int max);
int safeShiftJisRunLength(uintptr_t address, char* out, int max);
void escapeToLog(char* out, size_t outCap, const uint8_t* p, int len);

// How much a candidate run looks like an archive entry name. Diagnosis only: a
// name is never reported on its score, because scoring alone accepted
// "kimg_logo.png", which looks entirely real and exists nowhere in the game.
int nameScore(const uint8_t* p, int len);

// ---------------------------------------------------------------------------
// The archive entry-name index
//
// Loaded from the file the launcher wrote, and used to confirm that a string found
// in the game really is an archive entry. Confirmation is by exact byte comparison
// against the index, never by shape.
// ---------------------------------------------------------------------------

enum class NameMatch {
	None,
	Exact,      // the whole entry name, extension included
	StemOnly,   // the entry name without its extension
};

const char* nameMatchKind(NameMatch match);

extern bool g_indexLoaded;

// Look a raw byte string up. Fills archiveOut and matchOut when the string is a
// real entry name, or an entry name minus its extension.
//
// The distinction matters and is reported: an exact hit is the name as the archive
// spells it, whereas a stem hit means the engine holds the stem and appends the
// extension separately on the playback path. Audio only ever produces the second
// kind, which is why it went unrecognised for so long.
bool lookupEntryName(const uint8_t* bytes, int length, std::string& archiveOut,
	NameMatch* matchOut = nullptr);

uint64_t fnv1a(const void* data, size_t length);

void loadEntryIndex();

// ---------------------------------------------------------------------------
// Confirmed names
//
// Every name the tool prints goes through here, so deduplication happens in one
// place. A name is normally seen many times -- one looked up per frame would
// otherwise fill the log with thousands of identical lines.
// ---------------------------------------------------------------------------

void reportConfirmedName(const char* prefix, const uint8_t* bytes, int length,
	const std::string& archive, NameMatch match);

// ---------------------------------------------------------------------------
// Live playback name
//
// Reads the entry name off the object that is playing it and logs it when it
// changes. This is the primary output: without it the tool reports what a game
// loaded rather than what it played.
// ---------------------------------------------------------------------------

void reportLiveName(uintptr_t object, const std::string& className, int slot);

// Per-class counts of what the live-name read actually did, printed once when the
// game exits. A missing line for a voice that was heard is otherwise ambiguous:
// the hook may never have fired, the object read may have failed, or the read may
// have succeeded with no entry name inside the window. The counters separate them.
void logLiveStats();

// ---------------------------------------------------------------------------
// Hook bookkeeping
// ---------------------------------------------------------------------------

struct HookTarget {
	std::string className;
	int slot;       // index within that class's vtable
	void* original; // untouched entry address
};

extern std::vector<HookTarget> g_targets;
extern uint8_t* g_stubBase;
extern int g_stubCount;

// Per-stub call counters, bumped without locking.
extern LONG g_callCounts[512];

// The vtable of every hooked class, so an argument can be classified as an
// instance of one of them by comparing a single dword. That is a far safer
// assumption than a field offset: if the layout is wrong the classifier returns
// "not a known class" instead of confident nonsense.
extern std::vector<std::pair<uintptr_t, std::string>> g_classVtables;

const std::string* identifyObject(uintptr_t candidate);

extern std::atomic<int> g_slotCount;
extern std::atomic<bool> g_initialized;

// Quiet mode: count only, never format or write.
extern bool g_quiet;

// Install the vectored exception handler. Safe to call more than once.
void installExceptionHandler();

// Byte offsets inside a forwarding stub. Shared by the emitter and the comment
// describing its layout, because the two drifting apart is how the stub ends up
// half-written.
constexpr size_t kStubSize = 48;

constexpr size_t kOffSaveBegin = 0;   // 9C 50 51 52
constexpr size_t kOffSelf = 4;        // 8B C8
constexpr size_t kOffSp0 = 6;         // 8B 54 24 14
constexpr size_t kOffSp1 = 10;        // 8B 4C 24 18
constexpr size_t kOffPushId = 14;     // 68 <imm32>
constexpr size_t kOffPushSp1 = 19;    // 51
constexpr size_t kOffPushSp0 = 20;    // 52
constexpr size_t kOffPushSelf = 21;   // 50
constexpr size_t kOffCall = 22;       // E8 <rel32>
constexpr size_t kOffRestore = 27;    // 5A 59 58 9D
constexpr size_t kOffJmp = 31;        // E9 <rel32>

// ---------------------------------------------------------------------------
// Hook installation
// ---------------------------------------------------------------------------

// Discover each class's vtable through RTTI, emit one forwarding stub per virtual
// function, and redirect the vtable entries. Returns the number of slots hooked.
int installVtableHooks();

// The engine's own std::string::assign. Every name it holds passes through this,
// so validating the source argument against the index needs no knowledge of any
// object layout at all.
void installAssignStringHook();

// The CRT string comparisons. Off by default: Evenicle imports no strcmp family at
// all, so this matches nothing there. Kept because another game may import them,
// and because their absence is what identified the engine's own routine.
void installCompareHooks();

// ---------------------------------------------------------------------------
// Object dumps
//
// Diagnosis only. Used to establish the object layout; off by default because it
// produces a great deal of output and no names of its own now.
// ---------------------------------------------------------------------------

bool claimObjectDump(uintptr_t obj, int slot);
bool isDumpClass(const std::string& name);

} // namespace tracker

// Defined at global scope with C linkage on purpose: anything with internal
// linkage cannot be bound by the address the emitted stub calls.
extern "C" void __stdcall AudioTrackerLogHook(void* self, void* sp0, void* sp1,
	int id);