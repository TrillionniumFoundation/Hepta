# Optional HIA immutable-key cache

This candidate addresses repeated normalization of small object keys in the
ordinary selected JSON wire owner. It is development work. The preceding
source-bound cloud r7 run remains HOLD: its original native-timeout assertion
measured 7.024678764999408 seconds against an unchanged 5-second limit. The
earlier executor session 96283 remains unknown. This candidate does not qualify
either run or replace a complete source-bound cold/full gate.

## Ownership and supported capability

`NativeJsonWire.encode_ordinary` may request the HIAWIR05 capability for the
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

The low-level private capability argument is used by protocol tests with
truthful observers. It does not establish a no-hook guarantee for manually
corrupted internal registry dictionaries, monkeypatched `struct`/builtins,
or other arbitrary hosted-runtime mutation. Those extensions remain outside
this fresh ordinary-observer capability.

The HIAWIR03 key-byte behavior, also included in HIAWIR04, is as follows.
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

## Required evidence

The original compiler limits and 3/5-second caller assertions remain unchanged.
Acceptance requires the original three Core controls, original 19-case/228-step
legacy full-state comparison, independent cached/uncached byte and error
comparisons, capacity/collision controls, custom-observer request equality,
protocol/output/workspace canaries, and an actual original three-budget run.
Those are separate from complete ordinary-caller, installed-wheel and matching
source cold qualification. The retained encoder and unsupported foreign option
or renderer domains described by the ordinary entry profile remain explicit.

## Reusing immutable scalar observations

HIAWIR04 also reuses the four words of a previously received SUMMARY for an
exact builtin None, bool, int, float or str. This is a cache of observed facts,
not an admission result. The original HIA node, depth, queued-child, string,
number, collision and output-budget checks still run at their original stages.
LIMBS, POINTS, DIGIT_LIMIT and renderer observations retain their original
order. Lists, tuples and dictionaries are not cached: their summaries continue
to observe the live container and establish fresh iteration cursors.

The capability is the same fresh, exact, synchronous builtin observer used by
the admitted HIAWIR03 key cache. Strong registry references keep its nonzero
handles from being reused. Custom observers, patched observation methods and
explicit renderers stay on the original HIAWIR02 path. The capability does not
cover asynchronous transport-definition changes or corruption of private
observer registries and continuation memory.

HIA owns 256 scalar slots of 40 bytes beginning at workspace byte 16480. Each
slot contains a nonzero handle and the four received SUMMARY words.
The expression handle & 255 selects the slot. Only an empty slot is filled;
an occupied slot for another handle remains unchanged and takes the original
foreign-observation path. The last byte is 26719, below the unchanged stack at
32768. HIAWIR02 and HIAWIR03 do not write these slots. No output, input, node,
depth or native compiler bound changes.

A successfully admitted key-cache entry can independently supply the immutable
string kind and original codepoint length. It does not replace any string or
key admission decision. The key-byte cache continues to apply its original
length, collision, surrogate and capacity behavior.

HIAWIR04 uses the same 112-byte initial frame and capability word 1 as HIAWIR03.
Every reply must preserve the selected version. After opcode, sequence and
full length validation, the owner resets the private SUMMARY source. Header
word 680 is zero for the checked foreign reply, one for an admitted key's
codepoint length at 688, or an HIA-derived pointer to a populated scalar slot's
four facts. Header 712 counts eliminated SUMMARY requests; 720 and 728 count
scalar stores and scalar hits. These words are untouched on the two older
protocols. A hit changes the next HIA phase without leaving a pending foreign
request.

## Recovery and qualification status

The 2026-11-14 executor reset removed local candidate snapshots and raw test
artifacts. The original C4 HIA was regenerated from the exact
65179cc083c5b3d9e8530e98410aef4f943cf069 source baseline and the retained
authoring edits. The generated 360431 bytes exactly match the previously
observed source SHA-256
f8c6f109def6a1202351880292230489aab141757802f29facf2149a1e4de497.

The reconstructed bridge, new control tests and this document have new byte
identities. They require new test receipts. Regenerating identical HIA source
does not recover a lost raw receipt or establish a new qualification.

Historical failures remain failures: the original baseline locally exceeded
the unchanged 5-second caller assertion; C4's complete original 89-case gate
with the pinned Z3 dependency passed 88 cases and failed that assertion at
5.383011797006475 seconds. A previous C4 run with one missing-dependency skip
was incomplete. The expanded C5 exceeded the unchanged 8192-operation limit;
its bounded form was slower in the measured same-host comparison. C6's narrow
admission-word reuse also failed the unchanged 5-second case. No full cold
qualification, ordinary-caller qualification, runtime compiler-pin upgrade or
production activation is established by this development work.

## Adjacent child observations in HIAWIR05

HIAWIR05 includes the HIAWIR04 immutable-fact behavior and introduces request
opcode 7 for one dictionary entry during encoding. HIA supplies the container
handle and entry index. The transport calls the original child(handle,index,0)
and then child(handle,index,1), in that order, and returns their two nonzero
handles in the first two words of the ordinary 56-byte reply. The two
observations share one request/acknowledgement. No graph traversal, sorting,
normalization, admission or encoding decision moves into the transport.

This request is limited to encoding phases 115 and 145. The preflight key
read, key admission and value read remain separate and keep their original
order. A dictionary SUMMARY still starts a fresh traversal. The sorted path
retains the original key/value nonzero checks and store order; the unsorted
path retains its original behavior without adding a new refusal. The exact
builtin registry supplies nonzero, strongly retained handles; forged private
registries and replacement transport methods are outside this capability.

The new profile requires both prior private builtin capabilities and the
explicit paired-child option. Custom observers, replaced methods, explicit
renderers and older low-level profiles retain their previous requests.
Expanding opcode 7 into its two child observations must reproduce the complete
foreign-observation order, arguments, output bytes and error outcomes of
HIAWIR04. Foreign values are not speculatively observed before key preflight.

The bridge consumes a pending observation exactly once, including an exception
during either mechanical child call. If the key call raises, the value call
does not run. A malformed or repeated native acknowledgement is refused before
publishing any of its contents. Request/sequence/version admission remains HIA
owned. The same initial frame and workspace extent are retained, and none of
the existing output/node/depth/compiler limits changes.

The continuation also reads the private protocol word once per entry after
the original workspace-length guard and reuses it only through the initial
receive/admission branch. No writer can change that word in the reused range.
This does not cache a foreign observation or move a caller's budget origin.

HIAWIR05 is an unqualified development candidate until its own source-bound
JSON controls and original full ordinary-caller gate complete. The historical
failures described above remain retained. A mechanical bridge unit control is
reported separately from the tests that execute actual HIA native images.
