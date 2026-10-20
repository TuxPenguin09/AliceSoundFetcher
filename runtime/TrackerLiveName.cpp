// Reading the entry name off the object that is playing it.
//
// This is the primary output: it answers "which file is playing now", as opposed to
// "which files does this game contain" or "what has it loaded".
//
// Why it reads an object rather than a string: every audio name reaches the string
// hook during one four-second burst at start-up, in ascending archive order, and
// nothing at all afterwards. That burst is the engine enumerating its archive, not
// sounds playing -- logging it says a voice exists, not that it was heard. Graphics
// behave differently and do appear in real time, because each image is loaded when
// it is shown. So for audio the object is the only place the live name exists.
//
// Why it searches rather than reading a field: the name is not at a fixed offset.
// Observed offsets for confirmed live names span +0x38, +0x50, +0x60, +0x68, +0x7C,
// +0x88, +0xC0, +0xCC, +0xD0, +0xE0, +0xF0, +0xF8, +0x105, +0x118, +0x120, +0x130,
// +0x138, +0x13C, +0x13D, +0x168, +0x198, +0x1A0, +0x1AD, +0x1C0, +0x1D8, +0x1E5,
// +0x1FC, +0x240, +0x25C, +0x2A0, +0x31C, +0x37C, +0x3DC, +0x43C, +0x480, +0x48C,
// +0x4E0, +0x4EC, +0x510, +0x54C. A fixed offset read produced no name across 5811
// samples. A whole-object search for a run the entry index confirms finds all of
// them, and cannot report a plausible wrong name, because a run that is not a real
// entry simply is not one.

#include "TrackerShared.h"

#include <cstdio>
#include <cstring>
#include <map>

namespace tracker {

namespace {

// How much of the object to read.
//
// The two largest observed offsets sit within a few bytes of a 256-byte read. At
// +0xF8 a 256-byte window leaves 8 bytes, which happens to fit "24_4416" exactly
// and silently fails to match every longer name -- and a name cut short is not a
// name, so it produces no line rather than a wrong one.
//
// 1536 rather than 512 because CSoundChannel in Evenicle 2 is not one channel but a
// block of them: names were reported at +0x1C, +0x6C, +0x12C and +0x18C, evenly
// spaced, so the window was ending after roughly eight entries and any channel
// beyond that could never be read. A traced run then showed the real cost of that:
// voices 10048, 10053 and 10054 sit at +0x2A0, +0x25C, and later names at +0x54C,
// so a 512-byte read could not have reported them no matter which class fired. The
// statistics block reports read failures, so widening it cannot hide an overrun: an
// object near the end of a committed region shows up as readFail rather than as
// silence. Three times 512 was chosen over a much larger read because the widened
// window already reads into neighbouring heap on small objects, and every further
// byte makes that worse.
constexpr size_t kPlayerNameWindow = 1536;

// Last name reported per object, so a field that holds steady across thousands of
// calls produces one line rather than one per call.
//
// Two tables rather than one. An object can hold several names -- a player
// references both the sound it plays and the channel it is routed through -- and the
// second and later names were keyed by object-hash folded into the same table as the
// object pointer. Two objects whose keys collided evicted each other, so a name that
// had not changed was reported again: an observed run logged "79_4416" twice twenty
// seconds apart and "26092" twice eighteen milliseconds apart on one object.
// Separate tables make that impossible, because a name in one can never displace a
// name in the other.
//
// Fixed-size and lock-free: this runs on audio threads for every hooked call, so it
// must not allocate or take a lock. A stale entry can only cause a missed first
// report, never a wrong one.
constexpr size_t kLiveNameSlots = 512;

struct LiveNameSlot {
	uintptr_t object; // 0 = never used
	uint32_t length;  // 0 = nothing recorded yet
	uint32_t offset;  // where in the object it was found
	uint64_t hash;
};

LiveNameSlot g_liveNameSlots[kLiveNameSlots];
LiveNameSlot g_liveExtraSlots[kLiveNameSlots];

// Diagnostics: dump the whole object prefix on every sample, and count how many
// samples read successfully. Together these distinguish "the field is not there"
// from "the read is failing", which look identical from the outside.
bool g_liveProbe = false;

// Per-stub counts, indexed by stub id. Read back once at exit by logLiveStats.
//
// There are three ways a sound can play and produce no line, and from the log they
// are indistinguishable: the hook never fired, the window read failed because the
// object sits near the end of a committed region, or the read succeeded and no
// confirmed entry name lay inside the window. Knowing which one it is decides what
// to change -- another class, a safer read, or a bigger window -- so each is
// counted separately rather than inferred. A traced Evenicle 2 run settled it: zero
// read failures, and names at offsets no 512-byte window could reach.
LONG g_liveSamples[512];
LONG g_liveReadFail[512];
LONG g_liveNoText[512];
LONG g_liveNoName[512];
LONG g_liveNamed[512];

// Log one line per sample with the longest text run found in the window, whether or
// not it is a known entry name. Off by default; on with `trace = 1`.
//
// This is the only way to see the difference between "the object holds nothing" and
// "the object holds something that is not an entry name" -- for example a name with
// the extension still attached, or a path rather than a bare stem. Both currently
// look the same in the log: no PLAY line.
bool g_traceSamples = envFlag(L"ALICE_SOUNDFETCHER_TRACE");

LiveNameSlot* liveNameSlot(uintptr_t key) {
	// Fibonacci-style mixing, so objects that differ by a small stride -- which
	// pooled allocations very often do -- do not all land on one slot.
	const size_t index = (size_t)(((key >> 4) * 0x9E3779B1u) >> 22) %
		kLiveNameSlots;
	return &g_liveNameSlots[index];
}

LiveNameSlot* liveExtraSlot(uintptr_t key) {
	const size_t index = (size_t)(((key >> 4) * 0x85EBCA6Bu) >> 22) %
		kLiveNameSlots;
	return &g_liveExtraSlots[index];
}

void logLiveName(const std::string& className, uintptr_t object, uint32_t offset,
	const uint8_t* name, int length, const std::string& archive,
	NameMatch match) {
	char escaped[1024];
	escapeToLog(escaped, sizeof(escaped), name, length);
	// The class is part of the line because it is the only way to tell which part
	// of the engine a name came from: the same file can be read off a player, a
	// channel, or the decoded data object, and which one fired says whether the
	// routing classes are being exercised at all.
	logInfo("PLAY %s %p +0x%02X = \"%s\" [%s] (%s)", className.c_str(),
		(void*)object, (int)offset, escaped, archive.c_str(),
		nameMatchKind(match));
}

} // namespace

void reportLiveName(uintptr_t object, const std::string& className, int slotId) {
	if (object < 0x10000) {
		return;
	}

	const bool counted = slotId >= 0 && slotId < 512;
	if (counted) {
		InterlockedIncrement(&g_liveSamples[slotId]);
	}

	// Read the object prefix. Guarded, because `object` came from the game's own
	// call and is arbitrary as far as this code is concerned.
	uint8_t window[kPlayerNameWindow] = {};
	InterlockedIncrement(&g_probing);
	const bool read = safeReadMemory(window, object, sizeof(window));
	InterlockedDecrement(&g_probing);
	if (!read) {
		if (counted) {
			InterlockedIncrement(&g_liveReadFail[slotId]);
		}
		return;
	}

	if (g_liveProbe) {
		char probe[1024];
		int pn = snprintf(probe, sizeof(probe), "LIVE %p bytes:", (void*)object);
		for (size_t k = 0; k < kPlayerNameWindow && pn > 0 &&
			pn < (int)sizeof(probe) - 4; ++k) {
			pn += snprintf(probe + pn, sizeof(probe) - (size_t)pn, " %02X",
				window[k]);
		}
		logInfo("%s", probe);
	}

	// Scan the object for runs that are confirmed archive entries.
	//
	// This runs on every hooked audio call, so it has to be cheap. It is: an object
	// is mostly small integers and padding, and shiftJisRunLength rejects a
	// non-text byte on its first test, so nearly every offset costs one comparison.
	// Only runs of three or more bytes reach the index lookup.
	//
	// The whole buffer is scanned rather than stopping at the first hit, because an
	// object can hold more than one name: a player may reference both the sound it
	// plays and the channel it is routed through.
	int foundOffset = -1;
	int foundLength = 0;
	std::string archive;
	NameMatch match = NameMatch::None;
	bool haveName = false;

	// Longest text run seen anywhere in the window, matched or not. Only used for
	// the trace line and to tell "no text at all" from "text that is not an entry".
	int bestOffset = -1;
	int bestLength = 0;

	for (size_t k = 0; k + 3 <= kPlayerNameWindow; ++k) {
		const int len = shiftJisRunLength(window + k,
			(int)(kPlayerNameWindow - k));
		if (len < 3) {
			continue;
		}
		if (len > bestLength) {
			bestLength = len;
			bestOffset = (int)k;
		}

		std::string candidateArchive;
		NameMatch candidateMatch = NameMatch::None;
		if (!lookupEntryName(window + k, len, candidateArchive, &candidateMatch)) {
			continue;
		}

		if (haveName) {
			// A further name in the same object, tracked under its own slot so that
			// it too is reported once rather than on every call.
			const uint64_t extraHash = fnv1a(window + k, (size_t)len);
			const uintptr_t extraKey = object + (uintptr_t)k;
			LiveNameSlot* extra = liveExtraSlot(extraKey);
			if (extra->object == extraKey && extra->length == (uint32_t)len &&
				extra->offset == (uint32_t)k && extra->hash == extraHash) {
				continue; // already reported and unchanged
			}
			extra->object = extraKey;
			extra->length = (uint32_t)len;
			extra->offset = (uint32_t)k;
			extra->hash = extraHash;

			logLiveName(className, object, (uint32_t)k, window + k, len,
				candidateArchive, candidateMatch);
			if (counted) {
				InterlockedIncrement(&g_liveNamed[slotId]);
			}
			continue;
		}

		foundOffset = (int)k;
		foundLength = len;
		archive = std::move(candidateArchive);
		match = candidateMatch;
		haveName = true;
	}

	if (g_traceSamples) {
		char text[256] = "-";
		if (bestLength >= 3) {
			escapeToLog(text, sizeof(text), window + bestOffset, bestLength);
		}
		logInfo("SAMPLE %s slot=%d %p best=+0x%X len=%d \"%s\" %s",
			className.c_str(), slotId, (void*)object, bestOffset, bestLength, text,
			haveName ? "entry" : "none");
	}

	if (!haveName) {
		// Distinguishing these two makes the next run decisive: no text at all means
		// we are reading the wrong object or the wrong region of it, while text that
		// is not a known entry means we are reading the right place but the string
		// is not the shape the index expects.
		if (counted) {
			InterlockedIncrement(bestLength >= 3 ? &g_liveNoName[slotId]
				: &g_liveNoText[slotId]);
		}
		return;
	}

	// Compare against the last name reported for this object. The name itself is not
	// kept -- only its hash, length and offset -- so this stays a small fixed table
	// and the comparison is cheap. The offset is compared as well as the hash, so
	// the same name appearing at a different place in the object is still treated
	// as a change rather than being suppressed.
	const uint8_t* name = window + foundOffset;
	const uint64_t hash = fnv1a(name, (size_t)foundLength);

	LiveNameSlot* slot = liveNameSlot(object);
	if (slot->object == object && slot->length == (uint32_t)foundLength &&
		slot->offset == (uint32_t)foundOffset && slot->hash == hash) {
		return; // unchanged
	}

	logLiveName(className, object, (uint32_t)foundOffset, name, foundLength, archive,
		match);
	if (counted) {
		InterlockedIncrement(&g_liveNamed[slotId]);
	}

	slot->object = object;
	slot->length = (uint32_t)foundLength;
	slot->offset = (uint32_t)foundOffset;
	slot->hash = hash;
}

// Print what every hooked class actually saw. Called once, when the game exits.
//
// A class with calls but no samples means the live-name read never ran on it, so its
// slots are not the ones carrying playback. Samples but no names means the window
// held nothing the entry index knows -- either the window is too small for that
// object or the name lives somewhere else entirely. Read failures point at the read
// itself rather than the search. Rows are aggregated per class because the slots of
// one class behave the same way.
void logLiveStats() {
	struct Row {
		int slots = 0;
		long long calls = 0;
		long long samples = 0;
		long long readFail = 0;
		long long noText = 0;
		long long noName = 0;
		long long named = 0;
	};

	std::map<std::string, Row> rows;
	for (size_t i = 0; i < g_targets.size() && i < 512; ++i) {
		const HookTarget& target = g_targets[i];
		Row& row = rows[target.className];
		++row.slots;
		row.calls += g_callCounts[i];
		row.samples += g_liveSamples[i];
		row.readFail += g_liveReadFail[i];
		row.noText += g_liveNoText[i];
		row.noName += g_liveNoName[i];
		row.named += g_liveNamed[i];
	}

	if (rows.empty()) {
		return;
	}

	logInfo("AudioTracker: live-name statistics");
	for (const auto& entry : rows) {
		logInfo("  %-24s slots=%2d calls=%8lld samples=%8lld noText=%8lld "
			"noEntry=%8lld readFail=%6lld named=%6lld", entry.first.c_str(),
			entry.second.slots, entry.second.calls, entry.second.samples,
			entry.second.noText, entry.second.noName, entry.second.readFail,
			entry.second.named);
	}
}

} // namespace tracker