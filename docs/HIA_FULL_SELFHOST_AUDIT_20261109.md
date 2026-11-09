# Whole-stack HIA selfhosting audit — 2026-11-09

## Decision and source authority

**Whole-stack rewrite is OPEN, not complete.** The successful native fixed point
is real, but does not establish that the rest of the project is implemented in
HIA. The current implementation contains a live `hepta/` package with 212 Python
files, 76,126 lines and 4,125,579 bytes. These are source inventory figures, not a
percentage-completion estimate. Archived copies and example source files are
not counted as production replacements.

The project is `TrillionniumFoundation/Hepta`; there is no separate organization
repository named `HIA`. `main` is the public metadata/entry branch, not the full
compiler source. The selected public v9 source lock is `2598f430`; the separately
named v16 source lock is `6ecd8023`. Neither automatically selects an unmerged
selfhost candidate. Development continues here from PR #834 source commit
`ffbf0b89ddb468a056561543bce3e1fcab6b8da3`, which contains the v16 baseline and
v17 internal scalar result work. Do not copy a full compiler into metadata-only
`main`, silently advance release locks, or promote unrelated candidate branches.

The open-PR inventory observed during this audit contains 465 entries. Many
are stacked historical/research branches; their titles or isolated success
receipts do not establish integration into the selected source. Current adjacent
work includes #829 information pricing, #830 copied-image proof/adoption, #831
paired cost reading, #832 public minimum-image entry, #833 artifact-chain replay
and #835 paid-observation/deadline retention. These have distinct source and
acceptance identities; they are not blanket qualifications of this branch.

## Current development and qualification

On exact PR #834 head `ffbf0b89`, the observed workflows include:

| Gate | Observed state |
| --- | --- |
| Selfhost source / cold / native / language (`42642459675`) | success |
| Unified candidate (`42642459577`) | success |
| Six-outcome source/application (`42642459646`) | success |
| Agent native tools, finite CRC, intelligent assembly | success |
| Verified optimization/NDU, direct x86 backend, round4 runtime | success |
| Actual-host ABI (`42642459832`) | failure; macOS job cancelled |
| Real upstream C++ (`42642459828`) | failure; macOS job cancelled |

A cancelled required platform is **not** an executed pass. Prior green runs
cannot replace fresh execution after source changes. Proof and optimization
experiments also retain their own boundaries: finite scalar/leaf proofs are not
whole compiler refinement, and no general NDU economic benefit is established.
Hardware-required GPU/MCU claims cannot be closed by host emulation or renaming.

## Implementation boundary, component by component

| Component | Implemented in HIA now | Still needed for whole-stack closure |
| --- | --- | --- |
| Scanner / assembly parser | Fixed canonical `hia-asm.v1` bytes | General identifiers, full grammar and diagnostics |
| Core validation / ownership | Fixed scalar and resource profile, CFG/call checks | Composites, returned-loan provenance, full signatures |
| Code generator / ELF writer | Linux x86-64 flat and bounded ELF | General linker, multiple exports, other targets |
| Execution / standard library | Explicit bounded compiled primitives | General runtime, tasks/I/O, production library |
| Modules / packages / build | No full HIA replacement | Module graph, package/build/install orchestration |
| Agent tools / persistence | Compiled leaf programs, not service rewrite | Worker/service/store/protocol implementations |
| Optimizer / proof tools | Selected compiled kernels only | Planner, optimizer, validators and proof construction |
| CLI / release | Public checked entry exists, host orchestrated | Standalone HIA toolchain entry and release path |

`tools/audit_hia_selfhost_closure.py --output <new.json>` inventories every live
Python package file with AST imports and SHA-256, maps implementation authorities,
and emits these open boundaries. It is static audit evidence, not runtime or
formal evidence; dynamic imports and semantic equivalence require separate checks.

## Implemented follow-through: v18 empty result tuples

The compiler now accepts internal `fn fN(...) -> ()`, `_ = call(...)`, and `ret()`.
The public borrowed-buffer `f0 -> u32` ABI and the 1 MiB source/output/workspace
limits remain unchanged. Scalar-result discarding, missing effects, leaked
owners and live child loans remain rejected. The exact structural node count no
longer underflows for an empty signature. Empty direct self-tail calls preserve
the same-frame jump and immediate-return requirement.

The source-only cold replay passed all 11 ownership/isolation checks and its
nested native qualification passed **1,917 / 1,917** checks. Both original and
modified-source compiler chains reached their respective machine-byte fixed
points. The `multi` family preserves 43 original scalar cases and 17 original
refusals, adding 20 observations across seven void programs and seven refusals.
The source/reference/discovery regression passed 43 tests; the complete language
regression additionally passed 1,196 / 1,196 checks. Machine-readable
receipts remain bound to their actual source file manifests, not to this prose.

Historical recovery bundles/manifests remain immutable. CI now validates those
bytes against the original/recovered commits, then independently regenerates and
qualifies the current source; intentionally improved source must not be required
to equal an old snapshot, nor should the old snapshot be rewritten to match it.

## Implemented follow-through: v19 compiler growth space

Exact packed-byte/length keyword selection replaces per-keyword control-flow
branches. The keyword body uses 15 CFG blocks; the full compiler uses 1,370
instead of 1,522, within the unchanged 1,536-block and 1 MiB buffer limits.
A fresh source-only cold replay passed 11 / 11 checks in approximately 124 seconds
under the unchanged 180-second owner deadline. Its native qualification passed
3,965 / 3,965 checks; source/reference/discovery passed 46 tests. A new dedicated
keyword family checks 510 VM observations, including every keyword, offsets,
unknown mutations, long input and embedded NUL, against both native generations
in both flat and ELF forms. Source identity is recorded in the retained summary;
no previous-version fixed point is substituted for this new compiler.

## Implemented follow-through: v20 all Core scalar types

All ten integer types plus `bool` and `unit` now have native HIA admission inside
the fixed numeric-name profile. Signed comparison, arithmetic, shifts, width/sign
normalization, checked/wrapping conversions, literals, selection and internal
result tuples execute as HIA-generated machine code. The source-only cold replay
passed 11/11 and nested native qualification passed **3,385/3,385**, approximately
139 seconds within the unchanged 180-second deadline. The 49 source/reference
checks pass. Every one of 557 signed, 686 signed-involving conversion and 552
keyword input observations remains represented; batching reduces repeated process
and verification overhead, not the witness set. Both original and modified
compiler generations reach their own byte fixed points.

The first whole-project local run on v19 failed: umask 002 caused temporary lock
files to violate the existing no-group-write check, `/tmp` was itself inside a
Git project, and a piped Linux crash collector delayed SIGILL classification.
The failures are not passes. A private non-project temp directory, umask 077 and
post-exec nondumpable disposable native children yielded a passing 20-test
focused replay without increasing timeouts or weakening file checks. Full v20 unified qualification on exact commit `24dc49a` subsequently passed
**571/571** with no skipped tests, errors or failures, and its language
qualification passed **1,196/1,196**. These receipts do not qualify later code.
GitHub v20 cold and unified gates still failed their unchanged 180-second cold
deadline; the local pass is not a substitute for those failures.

The first v20 cold attempt correctly rejected a fixture exceeding 2,048 SSA
values; another correctly rejected a VM fixture with 257 results against a
256-item list cap. Adaptive batching and a 31-input keyword bank retain every
original case within those existing bounds. The passing attempt has new source
identity; neither failed attempt is relabeled successful. The earlier v19 GitHub
cold timeout is also retained as a failure rather than replaced by the local run.

## Ordered remaining work and acceptance

1. Preserve the admitted source grammar and capacity accounting while making the
   compiler large enough to implement missing language features within explicit
   resource bounds; do not silently raise a ceiling to hide a layout conflict.
2. All Core scalar types are implemented in the fixed profile. Complete
   returned-loan provenance, composite elaboration and general signatures after
   the bounded owned-result stage. Retain independent VM,
   negative-control, native and modified-self bootstrap observations.
3. Implement arbitrary identifiers, module graphs and a general linker/export
   interface in HIA. Compile multi-module programs from source bytes without a
   Python parser or verifier after B0.
4. Replace the interpreter/runtime/library and CLI/build/package authorities,
   then the worker/persistence/optimization/proof-tool implementations according
   to explicit component conformance contracts. Calling the Python implementation
   through an FFI or copying its output is not a rewrite.
5. Rebuild the **entire toolchain** from a source-only clean environment through
   B0/B1/B2/B3 and an actual changed-source fixed point; build real projects,
   install on clean machines and execute all applicable platform/resource gates.

Until those gates execute successfully, `whole_stack_rewritten_in_hia` and
`whole_HIA_language_self_hosted` must remain false. This ledger is the continuation
of implementation, not a declaration that planning or a subset closes the goal.

## Implemented follow-through: v21 owned-result transfer

The private ABI now reserves 64 bytes, with three 16-byte result slots and a
576-byte frame overhead. The unchanged public entry still returns u32; the
source/output/workspace caps remain 1 MiB. Both buffer descriptor words cross
call/return boundaries, and chain descriptors retain their zero spare word.
Callees transfer rather than free returned owners; caller-side fresh roots and
callee-side descendant/liveness checks preserve linear cleanup. Exact ordered
self-tail calls preserve the original result pointer. Returned loans are still
refused, not silently turned into fresh external roots.

The first local v21 attempt failed because an old chain fixture required a now
supported owner tuple to be refused. Its exact source was preserved and moved
to positive VM, independent native backend and successor ELF execution; unsafe
resource controls remain negative. The second cold replay passed 11/11 and
3,467/3,467 nested checks, about 138 seconds. Subsequent fixture-performance
changes have new source identities and require new execution receipts.

To address the actual GitHub deadline without raising it or dropping inputs,
qualification-only wrappers coalesce equal initialization runs and use Core's
guaranteed zeroed allocation; constant-only SSA sharing preserves every load,
arithmetic operation, store and call. Duplicate assembly round trips already
performed by the strict renderer are not repeated. The standalone keyword
fixture lowers exactly the live compiler keyword body, checked against the
complete generated document. Native trap observations remain fresh processes;
only identical source compilations within one compiler generation can be reused.

The final v21 fixture replay (`v21-cold-03`) passed 11/11 and 3,467/3,467
checks in about **126 seconds**, preserving all 88 tuple observations and 31
refusals. The previous valid chain-owner result exclusion is additionally run
through independent VM, direct native and linked successor ELF observations.
Both source manifests and separate generation fixed points are retained in
`review-evidence/hia-whole-selfhost-20261109/v21-cold-summary.json`. This does not
turn the still-open CI or whole-stack gates into passes.

### Pre-B0 reference scheduling follow-through

Independent Core references now run in fresh isolated processes under the
existing two-worker budget. Each report binds the exact source manifest, family,
actual child PID and payload hash; source/payload/provenance substitution is
refused. All 13 references must complete before B0 starts. Seed construction,
B1/B2/B3 and the modified chain remain sequential. Every native observation
retains its fresh child process and existing resource/deadline controls.
The fresh source-only replay passed 11/11 and 3,467/3,467 native checks in
approximately **111 seconds**, with identical compiler image hashes. This local
result is not a GitHub deadline pass; the next exact-source CI must execute.

## Implemented follow-through: v22 explicit traps and full test inventory

All five Core trap terminators are now parsed, effect-checked, accounted and
lowered in HIA. Independent VM observations preserve each semantic code, actual
earlier output writes, branch choice and live owner/loan state on error paths.
Flat and ELF successors execute real UD2, including scalar/void callees. The ABI
does not return a trap-code word. Six malformed/effect controls remain rejected.
The fresh v22 cold replay passed 11/11 and **3,581/3,581** native checks in about
111 seconds; 71 source/reference/discovery checks passed. The compiler has
101 functions, 1,489 blocks and 7,357 operations, within unchanged capacities.

The exact v21 unified candidate run executed 575 tests and failed only an Agent
discovery assertion hard-coded to v20. It is retained as a failed run. Discovery
now compares the entire current source-bound contract, not a version label.
GitHub source/Agent failures on `25ca259` had the same exact cause; downstream
skipped jobs are not passes. Fresh v22 CI must run independently.

**Scope correction:** the 571/575-test unified candidate gate is a selected
source/native/installation inventory, not every repository test. The new
`tools/qualify_hia_all_tests.py` derives its inventory from every live
`tests/test_hia*.py` plus shared Core acceptance modules. At v22 it inventories
473 modules and 4,391 static methods. It binds every tracked checkout file,
retains module-load failures, actual executed IDs, all skips and expected failures,
and never promotes platform gaps or finite tests into whole-stack closure.
Non-HIA repository tests and real cross-target/hardware runs remain separately
required where applicable; this full HIA run has not yet been reported passed.
