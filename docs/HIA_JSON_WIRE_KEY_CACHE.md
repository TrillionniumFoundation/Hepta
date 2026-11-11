# Optional HIA immutable-key cache

This candidate addresses repeated normalization of small object keys in the
ordinary selected JSON wire owner. It is development work. The preceding
source-bound cloud r7 run remains HOLD: its original native-timeout assertion
measured 7.024678764999408 seconds against an unchanged 5-second limit. The
earlier executor session 96283 remains unknown. This candidate does not qualify
either run or replace a complete source-bound cold/full gate.

## Ownership and supported capability

`NativeJsonWire.encode_ordinary` may request the HIAWIR03 capability for the
fresh `ForeignGraphObserver` it creates. The bridge verifies the exact class,
original constructor and observation methods/code objects, original instance
field layout and exact registry dictionaries, and the builtin integer-limit
observation. It does not traverse or serialize the graph. Explicit formatters,
custom and virtual observers, instance method replacement, and replaced class
methods remain on the uncached HIAWIR02 path. `encode_observed` and ordinary
low-level `WireSession` construction retain HIAWIR02 unless the private builtin
capability is explicitly requested and all its facts match.

The capability assumes these interpreter transport definitions remain stable
through one synchronous session; it does not promise equivalence under
asynchronous monkeypatching of the interpreter or bridge. No callback is
introduced to opt into the cache. Opaque values and string subclasses still
receive their original HIA type rejection. Exact strings are immutable, and
the observer retains strong references with nonreused handles.

HIA owns cache lookup, capacity, slot collisions, UTF-8 copying, and admission.
It saves only the bytes of a key whose original mode-1 preflight has already
completed successfully, including the original per-string byte budget and
surrogate checks. Later mode-1/mode-2 normalization of that same handle and
codepoint length can reuse the saved bytes. Graph node/depth/queued budgets,
collision detection, sorting, aggregate output budgets and all non-POINTS
observations remain in their original stages. Values are not cached.

There are 1024 slots of 160 bytes. A slot stores the nonzero handle, codepoint
length, UTF-8 byte length, admitted JSON width and up to 128 UTF-8 bytes. Only
keys of at most 32 codepoints are eligible. `handle & 1023` chooses a slot. An
occupied slot belonging to another handle is a miss and remains unchanged.
Full capacity, collisions and long keys resume uncached HIA normalization;
none adds a refusal or reduces the accepted byte/node/depth domain.

## Versioned native protocol

HIAWIR02 keeps its 104-byte initial frame, original workspace size, continuation
replies and state writes. HIAWIR03 uses a 112-byte initial frame with the same
first thirteen words and capability word 1 at byte 104. It requires renderer
fact 0. Replies must retain the session's version. Truncated/extra frames,
unknown capability values, a mixed reply version, and an inconsistent workspace
length are protocol refusals before a foreign observation.

The new protocol adds exactly 163840 workspace bytes before the existing
8192-byte HIA binary64 formatter workspace. Header word 648 points to the cache;
words 656, 664 and 672 count cache hits, misses and stores. The original protocol
leaves these formerly unused words zero. A private continuation workspace is
still trusted state; arbitrary forged scratch contents are not an accepted
input domain.

## Required evidence

The original compiler limits and 3/5-second caller assertions remain unchanged.
Acceptance requires the original three Core controls, original 19-case/228-step
legacy full-state comparison, independent cached/uncached byte and error
comparisons, capacity/collision controls, custom-observer request equality,
protocol/output/workspace canaries, and an actual original three-budget run.
Those are separate from complete ordinary-caller, installed-wheel and matching
source cold qualification. The retained encoder and unsupported foreign option
or renderer domains described by the ordinary entry profile remain explicit.
