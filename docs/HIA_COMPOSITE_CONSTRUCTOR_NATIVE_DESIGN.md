# Complete HIA composite constructor candidate

Status: new isolated implementation design. No constructor, default-path,
cold, compiler, whole-language, or retained-owner removal claim is made here.
The candidate is based on `1e8d554cb87e2a88adb5085b1e975812c23829b6` plus the
frozen full-function overlay, recorded byte-for-byte in the development
directory's `baseline.json`. The complete function terms deliverable remains
frozen in its separate worktree.

## Indivisible ownership

HIA will own the whole original `_Elaborator.__init__` semantic sequence:

1. Exact nominal document keys, supported schema, legacy/profile condition,
   module identifier, and assignment of initial document/counter/profile state.
2. Native type initialization with HIA-selected recursive-chain and
   partial-record flags. This occurs before inspecting function inventory.
3. Function inventory and creation of ordered function/signature/origin maps.
4. For each function in source order: exact shape (v4 optional return_loans),
   name, duplicate check, complete parameter admission, return-list kind,
   resolution of **all** return references, then the stored-loan escape check.
5. Native v4 origins, committing that origin row before checking effects.
   Only after valid effects are the function and signature committed.
6. Every concrete task declaration, including unused ones, in definition
   order: resolve its name and admit its protocol against the complete registry.

No host routine will inspect source names, decide schema/profile, check effects,
walk return references, decide which declarations are tasks, resolve an origin
path, or reconstruct a semantic lowering plan. The host will materialize the
native-issued registry and type identities as representations of complete state.

## Typed services and state

The kernel requests only these separately owned native operations: initialize
types; admit parameters; resolve one type; admit origins; admit a task protocol.
Requests use monotonically increasing IDs, fixed kinds, exact resume phases,
and full generic object streams. Parameters and returned descriptors use
same-session issued IDs with bidirectional identity checks. Origins retain the
native type owner's original parameter name and scalar offset.

There is no raw-ID shortcut in the existing native type adapter. The new bridge
will mechanically materialize native IDs into that session's exact descriptors
and call its existing native APIs. This preserves the currently selected type
owner's diagnostic policy: category, ordering and state remain contractual;
some existing generalized English context differs from the older hosted types.
Such dependency differences must not be relabeled constructor regressions.

The HIA owner keeps the registry and origins in insertion order. Its final
generic state result includes the detached document, native profile enum,
initialization stage, registry rows, origin rows and semantic error status.
Stage publication distinguishes no assigned fields, document/profile assigned,
type owner assigned, and registry initialized. On semantic refusal the bridge
mirrors only fields committed at that stage, including an origin row committed
before a later effect error. Type-session cache/active/work state is retained.

The completed state supplies `document`, `native_types`/`types`, zero initial
serial/value slots, ordered `functions`, `signatures`, `return_origins`, and
empty helpers/cache. The profile enum mechanically selects the existing static
operation-set representation and returned-loan flag. The already implemented
full-function session can then bind that same detached document and type state.
The late function-owner installation hook remains after all constructor
semantics, as in the current candidate.

## Transport and implementation limits

Use an independent constructor kernel and independent generic renderer image,
with distinct state/request/frame identities. Reuse the existing generic
token/arena authoring algorithms without changing the frozen function bundle.
The input has one already structurally bounded document and a boolean legacy
flag. Every true public admission remains in place.

The semantic input region and workspace initially use the existing generic
owner's 64 MiB input region and 192 MiB total workspace. These internal buffers
must be justified from the original source-node/byte and 1024-function limits;
they do not add a new source/output quota. Constructor state contains compact
type IDs and source references, never expanded type layouts or Core bodies.
The workspace is released before allocating the full function workspace.

Compilation must preserve the existing bootstrap limits (128 functions, 1536
blocks, 8192 instructions, 256 blocks and 2048 SSA values per function, 16
parameters, and the original child execution limits). A two-image split is
expected to fit; only actual generated structure and compilation can establish
this. No limit will be enlarged to make an unfinished kernel compile.

Malformed/replayed responses, wrong request kinds/phases/counts, unissued IDs,
changed source bytes, and decoder errors must permanently poison the session.
The generic stream returns complete constructor state even after an ordered
semantic error; it never authorizes execution or substitutes for final Core
admission.

## Required acceptance

Compare against the complete retained constructor with independently selected
native type sessions on both sides. Include public v1--v4 and legacy inputs,
all shape/name/effect failures, duplicate-before-bad-type order, all-returns
resolution before loan refusal, origin commit before effect refusal, unused
task checks, exact partial maps and type state, and caller/source readback.
For successful cases, feed the result to the complete native function bundle
with retained constructor/function semantic helpers poisoned, and verify and
execute the completed Core. Installed-wheel and source/image refusal evidence
must use actual images under unchanged compiler limits.

Private arbitrary replacement dictionaries and custom Python legacy objects
outside the public bounded-document path are not silently treated as another
admission API. Their scope must remain explicit, as for the complete function
session; no broader private-call equivalence is inferred from public tests.
