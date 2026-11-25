# Native mutable result values

## Qualified component and boundary

The final `hia_result_value` image is **960822 bytes**, SHA-256
`32b9ec44279379d9d99343fd3ec5ef7d26144e082e11a3babd13f1aff62bf3eb`.
All value, ownership, mutation, JSON import/export, numeric conversion and
allocation policies are HIA sources. The 577-byte mechanical bridge performs
fixed role calls, Linux syscalls, atomic compare/exchange and exchanges. It has
no libc import and accepts no caller-selected function pointer. The HIA packer
builds both flat executable text and an ET_REL object.

This is a qualified component of the ongoing background/native-runtime
integration. It does not claim complete BackgroundOptimizer, whole-runtime,
installation, cold acceptance, activation, or cleanup. The companion JSON
embeds the actual bounded reports, source identities and native rebuild
evidence. Earlier report fields that say `whole_value_closed: false` retain
their original per-run scope; the aggregate below is the component
qualification, not a global release declaration.

## Source and build authority

Six new source modules are `result_value_core.hepta`,
`result_value_owner.hepta`, `result_value_import.hepta`,
`result_value_export.hepta`, `result_value_binary64.hepta` and
`result_value_packer.hepta`, under `examples/hia_bootstrap`.
The reusable dependencies are the already qualified
`background_optimizer_json_capture.hepta` and
`agent_binary64_format.hepta`. The readable mechanical template is
`tools/hia_result_value_bridge.S`; its assembled text is 577 bytes with SHA-256
`76d5db80890a2213c3696cd6effa7e8dcc2fc89da069d8fbed5fadfcf5810895`.

The six modules were independently compiled with the actual HIA source builder
813129 bytes / `494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`.
The rebuild reproduced every source and flat module byte for byte. Each source
remains below the unchanged budgets: 128 functions, 1536 blocks, 8192
operations, and 16 parameters per block. Python authoring and oracle tools are
qualification conveniences; they are not runtime dispatch, input validation,
allocation, serialization, ownership or numeric authority.

The HIA packer is 48956 bytes /
`7322bd2793e8308d6bc5689e6b6ec616a00f3326596ddd7f11c18e6222ae6fd5`.
Its `HIABVP01` input is an 80-byte header followed by seven flat modules:
magic at 0, role count 7 at 8, seven lengths at 16..64, and mode at 72
(0 ET_REL, 1 flat). Role order is owner, core, import, export, capture, format,
number. Work space is at least 512 bytes. Existing per-role 4 MiB and
aggregate 16 MiB text bounds remain unchanged. It returns the exact output
length, `0xffffffff` for invalid input, or `0xfffffffe` for insufficient
output/work capacity. Error paths do not partially publish output.

## Native ABI

Entry has the six-word convention
`entry(input_ptr, input_n, output_ptr, output_n, context_ptr, context_n)`.
Output is at least 8192 bytes; context is at least 256 bytes. Views must be
non-null when nonempty, nonwrapping and pairwise disjoint. Invalid views return
`0xfffffffd` before writes. A malformed private request returns that code;
only the private output phase word may have been reset. A valid operation
returns 0 and a `HIABVR01` reply, including semantic errors.

The context is opaque, initially zeroed, stable at its address until all
references are released, and bound to its initializing process. The caller
must allocate a fresh context after destruction. An inherited context is
rejected in the fork child before waiting on an inherited mutex.

The `HIABVQ01` request is exactly 128 bytes plus its tail:

| Offset | Field |
| --- | --- |
| 0 | Magic |
| 8 | Operation |
| 16 | Flags, currently zero |
| 24, 32, 40 | Capability A: node offset and two nonce words |
| 48, 56, 64 | Capability B |
| 72, 80, 88 | Capability C |
| 96 | Tail byte count |
| 104, 112 | Argument 0 and argument 1 |
| 120 | Reserved zero |

Unused capabilities and arguments must be zero. Nonce-bearing capability
nodes are checked against the actual context-owned registry before use; input
capabilities are never treated as dereferenceable pointers.

The public `HIABVR01` reply occupies 128 bytes:

| Offset | Field |
| --- | --- |
| 0 | Magic |
| 8 | Status |
| 16 | Kind |
| 24, 32, 40 | Fresh owned result capability, when returned |
| 48 | Logical length or operation boolean |
| 56 | Chunk offset |
| 64 | Copied bytes or enumeration count |
| 72 | Scalar byte length or required output bytes |
| 80, 88, 96 | Reserved zero |
| 104, 112 | Stable identity pair while an object reference is held |

Bytes 128..8191 belong to the private continuation. Payloads and enumeration
entries start at 8192. Each valid new entry initializes this private state, so
the caller may reuse poisoned output storage without clearing it. Success of
operations 0, 6, 20 and 22 has no result body beyond magic/status. Errors return
no owned result capability.

Status codes are 0 success, 1 invalid or wrong-kind capability, 2 TypeError,
3 KeyError, 4 IndexError, 5 MemoryError, 6 lifecycle, 7 invalid scalar or
operation, 8 ValueError, 9 OverflowError, 10 Unicode error, 11 internal/system,
and 13 insufficient output. Status 13 reports the required size at 72.
Exception text formatting is the caller's HIA policy, not a hidden host path.

## Value operations

Kinds are 0 null, 1 bool, 2 arbitrary integer, 3 binary64, 4 WTF-8 string,
5 list, 6 dict and 7 bytes. Null, false and true are context singletons.
Scalars are immutable. Containers preserve shared identity and are mutable;
cycles are permitted. Every retain, get or enumeration result is a distinct
owned capability to the existing object.

| Op | Operation | Arguments and result |
| --- | --- | --- |
| 0 | Initialize | arg0 integer decimal digit limit: 0 or at least 640; normal caller default 4300 |
| 1 | Import JSON | Tail is original JSON; returns a fresh value capability |
| 2 | Create scalar | arg0 kind; tail or arg1 supplies scalar |
| 3 | Empty list | Returns owned list |
| 4 | Empty dict | Returns owned dict |
| 5 | Retain value | A; returns new capability to the same object |
| 6 | Drop value | A; consumes exactly that capability |
| 7 | Inspect type | A; kind, logical length, scalar bytes and identity |
| 8 | Identity equality | A/B; boolean at 48 |
| 9 | Dict get | A dict, B key; retained existing value |
| 10 | Dict set | A dict, B key, C value |
| 11 | Dict delete | A dict, B key |
| 12 | List get | A list, B integer/bool index |
| 13 | List set | A list, B index, C value |
| 14 | List insert | A list, B index, C value |
| 15 | List delete | A list, B index |
| 16 | List append | A list, B value |
| 17 | Length | A string/bytes/list/dict; scalar TypeError otherwise |
| 18 | Export snapshot | A; returns independent owned bytes |
| 19 | Copy scalar/bytes chunk | A; arg0 full-width offset, arg1 byte count |
| 20 | Destroy | Allowed only with no live value or context-token capabilities |
| 21 | Retain context | Returns a fresh independent context token |
| 22 | Drop context | A context token, or zero A to consume the initial anchor once |
| 23 | Enumerate children | A list/dict; arg0 start, arg1 requested count |

Scalar integer tails are canonical decimal ASCII, optionally negative, without
leading plus/zero or negative zero. Binary64 uses eight little-endian bytes.
Strings use WTF-8 and retain isolated surrogates; logical string length counts
Unicode code points. Bytes are raw. Bool uses arg1 0/1; null has no tail.
Type inspection reports zero logical length for null/bool/int/float while
keeping the scalar byte length separate.

Lists implement negative indexes, insertion clamping and original oversized
index errors. Dict primitive keys retain original null/bool/int/float/string/
bytes semantics. In particular `True == 1 == 1.0`, NaN identity keys,
first-inserted key identity on replacement, insertion order, and
delete/reinsert order are preserved. Lists/dicts as keys are unhashable.

JSON import invokes the qualified native lossless capture role itself; it
does not accept a caller-asserted parsed arena. Duplicate keys replace the
value at the first key's insertion position. Export traverses the actual
shared graph, repeats acyclic shared subtrees, detects active cycles, checks
finite numbers and the configured integer digit limit, and preserves strict
UTF-8 error precedence. It returns independent snapshot bytes. Exporting
bytes or unsupported keys raises TypeError.

Chunk offsets/counts are full-width unsigned words. Count zero measures total
scalar byte length at reply 72. A nonzero count requires output capacity
8192+count; insufficient capacity reports 13 without truncation.

Enumeration holds one value mutex for the snapshot. Start at or beyond length
returns zero entries; otherwise count is the minimum of the request and
remaining children. Required output is 8192+64*count. A short view allocates no
capabilities. Each 64-byte entry has index at 0, value kind at 8, key capability
at 16/24/32 (zero for lists), and value capability at 40/48/56. All nonzero
capabilities are independently owned. Allocation failure rolls back every
partially retained entry.

## Independent context ownership

Initialization creates one implicit initial anchor. Operation 21 creates a
registered nonce-bearing context token, returned at 24/32/40. Its kind/length/
identity fields are zero; it is not a null value and all ordinary value
operations reject it. Operation 22 with A consumes only that token. Stale,
wrong-nonce, cross-context and value capabilities are rejected without
consuming any other token.

Operation 22 with all-zero A consumes the initial anchor exactly once; a
second attempt is a lifecycle error even when independent tokens remain.
Operation 20 refuses to destroy a context with any outstanding value or
context token. It may consume a still-live initial anchor when otherwise
empty. After the initial anchor has been consumed, dropping the final value
or context token unmaps the arena and marks the context destroyed.

A Future/ResultBox can therefore own its own context token and its retained
value without depending on another object's initial anchor. Returned values
remain valid after their originating Future/owner has been released. There
is no untyped public increment/decrement counter that allows one holder to
consume another holder's ownership.

## Allocation and reclamation

The HIA owner manages a growable private mapping, with mmap/mremap performed
by the fixed bridge. A pure HIA buddy allocator, registry, container storage,
reference accounting and cycle collection use arena-relative offsets. Actual
mremap relocation preserves live capabilities and object identity.

A context futex mutex serializes mutation and reference changes. Acyclic
release is immediate. Unreachable cycles are collected periodically, after
the final capability, and on allocation pressure before retry. Enumeration
and import failures roll back unpublished references. Dict storage is
compacted/reused and list storage shrinks/frees as children are removed.
There is no introduced fixed aggregate value byte/node limit; real resource
exhaustion returns MemoryError.

## Actual qualification

Every case below executed the final image whose SHA-256 appears above.

| Qualification | Actual scope |
| --- | --- |
| Native packaging and views | 46 gates; HIA object/flat packing twice, invalid/short atomicity, preserved source bounds, aliases/overflow/null view rejection |
| Original JSON and mutation round trips | 46 cases, duplicates, escape spelling, integer/float edge cases, 600 levels, 10000 values, 9 MiB decimal/string, aliases/cycle recovery |
| Mutations and ownership | 9 groups, 42566 native calls, 1800 original list/dict operations, numeric dict equality, 10000 delete/reinsert cycles, thread sharing, actual mremap move, stale/cross-context/fork rejection |
| Large admitted values | All 1114112 Unicode code points; 100663309-byte balanced decimal; 67108865-byte owned bytes; 262144 owned children survive parent release |
| Private protocol | 46 guards, poisoned reused output, full-width chunk/enumeration offsets, scalar/error priority, no capability publication on short output |
| Actual kernel allocation faults | 7 groups, 12 actual Linux ENOMEM results, unchanged old mappings, rollback/retry, pressure collection, final zero owned mappings |
| Independent context tokens | 4 groups, 3710 native calls, 201 distinct tokens, exact single consumption, token typing, value survival, concurrent stale-drop/ABA protection |
| Independent HIA rebuild | All six new source and flat modules byte-identical |

Kernel fault qualification changed only child-process mmap/mremap size
arguments using ptrace under a temporary child-only RLIMIT_AS. Return values
came from the real Linux kernel. Product bytes and state machines were
unchanged; owned mappings were tracked until actual munmap. These results do
not substitute for final integrated Future/runtime/cold/installation gates.
