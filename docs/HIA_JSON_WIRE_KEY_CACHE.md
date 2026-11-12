# Versioned HIA immutable-key cache

This candidate addresses repeated normalization of small object keys in the
ordinary selected JSON wire owner. It is development work. The preceding
source-bound cloud r7 run remains HOLD: its original native-timeout assertion
measured 7.024678764999408 seconds against an unchanged 5-second limit. The
earlier executor session 96283 remains unknown. This candidate does not qualify
either run or replace a complete source-bound cold/full gate.

The protocol-04 source revision passed its six source methods once in
`e257247c3e94146b15cf4c3e2e671ee30af94610`. The first source attempt and its SSA
verifier rejection remain in that commit's ancestry. This result includes no
native timing, original 89-method group, installed behavior or current cold
qualification. Those results remain required for the combined candidate.

## Ownership and supported capability

`NativeJsonWire.encode_ordinary` may request the HIAWIR04 capability for the
fresh `ForeignGraphObserver` it creates. The bridge verifies the exact class,
original constructor and observation methods/code objects, original instance
field layout and exact registry dictionaries, and the builtin integer-limit
observation. It does not traverse or serialize the graph. Explicit formatters,
custom and virtual observers, instance method replacement, and replaced class
methods remain on the uncached HIAWIR02 path. `encode_observed` and ordinary
low-level `WireSession` construction retain HIAWIR02 unless the private builtin
capability is explicitly requested and all its facts match.

The existing private `_builtin_keys=True` option still selects HIAWIR03 and
retains its original request sequence. HIAWIR04 uses the separate private
`_builtin_key_summaries=True` option. Only the fresh, admitted ordinary observer
selects it automatically. Every ordinary call starts a fresh workspace; no
cached facts are shared across calls.

The capability assumes these interpreter transport definitions remain stable
through one synchronous session; it does not promise equivalence under
asynchronous monkeypatching of the interpreter or bridge. No callback is
introduced to opt into the cache. Opaque values and string subclasses still
receive their original HIA type rejection. Exact strings are immutable, and
the observer retains strong references with nonreused handles.

The low-level private capability argument is used by protocol tests with
truthful observers. It does not establish a no-hook guarantee for manually
corrupted internal registry dictionaries, monkeypatched `struct`/builtins,
or other arbitrary hosted-runtime mutation. Those extensions remain outside
this fresh ordinary-observer capability.

HIA owns cache lookup, capacity, slot collisions, UTF-8 copying, and admission.
It saves only the bytes of a key whose original mode-1 preflight has already
completed successfully, including the original per-string byte budget and
surrogate checks. Later mode-1/mode-2 normalization of that same handle and
codepoint length can reuse the saved bytes. Graph node/depth/queued budgets,
collision detection, sorting, aggregate output budgets and all non-POINTS
observations remain in their original stages for HIAWIR02 and HIAWIR03.
HIAWIR04 can additionally reuse already admitted exact-string key facts during
later key-only SUMMARY phases. It keeps every value/container SUMMARY, CHILD
request and sorting observation. It does not advance an observation past its
original failure boundary. Values and containers are not cached.

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
length are protocol refusals before a foreign observation. The initial
workspace must be fresh and completely zeroed; resetting only its magic is
not a supported new-session operation. Initialization nevertheless clears
`CACHE_BASE` before selecting either version, so HIAWIR02 cannot accidentally
reuse a stale capability pointer.

The new protocol adds exactly 163840 workspace bytes before the existing
8192-byte HIA binary64 formatter workspace. Header word 648 points to the cache;
words 656, 664 and 672 count cache hits, misses and stores. The original protocol
leaves these formerly unused words zero. A private continuation workspace is
still trusted state; arbitrary forged scratch contents are not an accepted
input domain.

HIAWIR04 uses the same 112-byte initial frame and capability value as HIAWIR03,
with its own magic and version-matched replies. It keeps the same fixed cache
extent. Header words 680, 688, 696 and 704 record key-summary readiness, size,
hits and misses. Facts are published only after successful original key
preflight, with the handle written last; occupied slots are not replaced.
HIAWIR02 and HIAWIR03 retain their original byte-level protocol and request
sequences. No extra allocation or larger accepted key budget is introduced.

## Required evidence

The original compiler limits and 3/5-second caller assertions remain unchanged.
Acceptance requires the original three Core controls, original 19-case/228-step
legacy full-state comparison, independent cached/uncached byte and error
comparisons, capacity/collision controls, custom-observer request equality,
protocol/output/workspace canaries, and an actual original three-budget run.
Those are separate from complete ordinary-caller, installed-wheel and matching
source cold qualification. The retained encoder and unsupported foreign option
or renderer domains described by the ordinary entry profile remain explicit.

Protocol 04 adds six source methods and a separate six-method current-cold
native qualifier, `tools/qualify_hia_json_wire_key_summary.py`. The latter uses
the original 180-second process owner and 3-second cleanup, binds the actual
current wire and formatter builds and retains all compile originals. The
original 89-method group and original seven cache-native methods are still
required in their original scopes; the extra six cannot replace them. A
successful source result or synthetic protocol control cannot supply native
qualification.
