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
| Scanner / assembly parser | Bounded `hia-asm.v1`, general ASCII function/SSA/formal names and exact lookup | General block identifiers, full module grammar and diagnostics |
| Core validation / ownership | Fixed scalar/resource profile, CFG/call checks and parameter-bound returned loans | Composites, general signatures and full language admission |
| Code generator / ELF writer | Linux x86-64 flat and bounded ELF | General linker, multiple exports, other targets |
| Execution / standard library | Explicit bounded compiled primitives | General runtime, tasks/I/O, production library |
| Modules / packages / build | No full HIA replacement | Module graph, package/build/install orchestration |
| Agent tools / persistence | Compiled leaf programs, not service rewrite | Worker/service/store/protocol implementations |
| Optimizer / proof tools | Selected compiled kernels only | Planner, optimizer, validators and proof construction |
| CLI / release | Bounded HIA Linux syscall-only compiler filter; production entry host orchestrated | Full production CLI, installation, package/build and release path |

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

## Actual full HIA test run and v23 follow-through

The exact b4d332b checkout derived 474 modules / 4,393 static methods and ran
4,388 unittest cases in 1,217.640 seconds. It **FAILED**: four failures, eighteen
errors and 299 skips. Source bytes stayed unchanged; expected case IDs were not
all started because class setup and platform gaps prevented some execution.
The source-bound public summary retains every failing/error ID and all skip
reasons (`v22-all-hia-tests-summary.json`). Static methods are not run counts.

One actual defect was resolving a rustup proxy to `rustup` before execution,
which changes argv[0] dispatch. Preflight now executes the requested absolute
path while separately pinning resolved bytes and rejecting rebinding/drift.
Actual Rust compilation plus a multicall-alias regression and existing tamper
controls pass. Missing pinned Rust 1.90, Clang20, QEMU and native-profile inputs
remain real qualification gaps until supplied and run; no skip is a pass.

The next compiler stage implements internal parameter-bound returned loans:
exact external formal identity through CFG renaming, forward/backward calls,
shared tuple slots, swapped formal order, caller-owned parent views and checked
self-tail returns. Returned values are all validated before consumption, and
the caller creates local child capabilities rather than inventing external
roots. The public ABI and existing capacity/deadline ceilings are unchanged.
This does not replace the still-Python runtime, modules/build, CLI, Agent worker
and optimizer/proof stack, or establish complete language/refinement closure.

The final v23 cold replay passed 11/11 and 3,797/3,797 checks, with 124 tuple
observations and 47 refusals (36/16 specifically for returned loans). Both
original and changed compilers reach distinct fixed points. Language coverage
passed 1,196/1,196 plus all ten retained report assertions. The earlier language
run failed only its duplicated stale profile label (1,195/1,196), remains retained,
and was corrected by importing the source-bound contract profile. This is not
a claim that the first full-repository test run passed.

The inventory runner now also has `--repository-wide`, deriving every live
`tests/**/test*.py` (730 modules at this stage), including non-HIA language,
module/package, C-migration, runtime and frontend tests. It retains their exact
IDs, source snapshot, load/setup failures and gaps independently of the narrower
HIA-only run. All three inventory/path controls pass; execution requires an
exact clean checkout and actual tool/native-profile inputs.

### Further authoring headroom, independently requalified

Typed constants are now shared only within their exact SSA block. A closed
acyclic AST check permits eager calls only for genuinely finite scalar helpers:
no loops, resource parameters, memory, checked shifts or recursive cycles. Calls
remain real calls; no target input operation or test observation is deleted.
Two VM/structural adversarial controls preserve arithmetic and block dominance.
The compiler drops from 7,788 to 6,956 operations and from 1,505 to 1,487 blocks,
without changing any capacity. The fresh pinned source passes 43 source/reference
tests, 3,797 native cold checks and 1,196 language checks plus ten report asserts.
The complete repository run remains independently active on the unchanged
f535528 checkout; this later source is not falsely attributed to that run.


## Implemented follow-through: v24 kernel-executable compiler filter

HIA now emits a static Linux x86-64 ET_EXEC compiler entry with stdin/stdout I/O.
It directly uses mmap/read/write/exit; no PT_INTERP, libc or dynamic loader is
needed by this executable. The canonical borrowed-buffer compiler ABI remains
inside it, and its original 1 MiB limits remain unchanged. It has no arbitrary
path opening, full production CLI or installer. The syscall entry's output is
not atomic filesystem publication, and inherited SIGPIPE remains explicit.

Fresh source-only cold `v24-cold-03` passed **11/11** and native **3,837/3,837** in
141.380 seconds under the unchanged 180-second deadline. Both original and
modified flat chains reach byte fixed points. Both executable compiler chains
also reproduce themselves directly through kernel exec; the original executable
additionally builds a genuinely changed M1/M2/M3 executable chain, with M1 != M2,
M2 == M3 and M3 != original. Independent Core VM byte-program observations and
Core-admitted source/output-capacity fixtures precede B0. The live compiler has
108 functions, 1,505 blocks and 7,217 operations, within the unchanged limits.

Fresh language `v24-language-02` passed **1,196/1,196**, with all 10 report
assertions passing and no skipped cases. The exact CI source-step Python body
passed **67 tests**, and the focused source/ownership group passed 41. Earlier
`v24-language-01` correctly failed a stale inventory; its failure is retained.
The inventory was regenerated from reviewed actual contract/source bytes before
the final cold and language runs, not overwritten with an old receipt.

The previous GitHub source gate at `2bf39a4` failed because two unittest names
were mistakenly joined into one import string. That is fixed by separate names
and validated with the actual workflow step body. Prior GitHub failures,
platform cancellations and skipped downstream jobs remain failures/gaps, not
current-source passes. Full-repository regression on exact `f535528` is still
running; it already exposed a missing Boost-header dependency and an independent
C++ macro-rejection failure. It is not counted as passing. A task-local,
package-hash-verified Boost 1.83 header tree is being used for isolated diagnosis,
without changing the running checkout or system include tree.

Whole-stack status stays OPEN: **212 Python files / 76,126 lines** remain. This
filter does not replace general names/modules, composites, the production
runtime/library, package/build/install pipeline, Agent worker/service/store,
optimizer or proof construction. See `v24-executable-summary.json` in the review
evidence directory for source identities, per-case statuses and receipt hashes.


### Full-audit C++ dependency and negative-control diagnosis

The isolated real constructor test passes against the unchanged `f535528` source
when a package-hash-verified, task-local Boost 1.83 include tree is supplied. The
system include tree and running full-suite environment were not modified.

The macro failure is a control-fixture assumption, not a demonstrated production
checker bypass: libstdc++ 15 already enables `_GLIBCXX_ASSERTIONS` in unoptimized
builds. Defining it again does not change the expanded standard-library contract.
The negative test now probes the actual toolchain and tests both `-O0` and `-O2`,
disabling the real default when enabled and retaining the original enabling
mutation when disabled. Both actual captures reject at the existing expanded
standard-library gate. No production checker was changed, no skip introduced,
and the original failed full run is not relabeled passing. The separate control
summary retains compiler-state and source/receipt identities.


### Guard sharing and locked QEMU replay

Exact conditional failure effects now share a small HIA helper without eager
workspace access or effectful argument evaluation. The helper is excluded from
its own rewrite. Independent VM comparisons retain false-guard empty-buffer
success, ordered true effects, original bounds traps and lazy memory arguments.
Compiler size is **109 functions / 1,362 blocks / 7,208 operations**, reclaiming
143 blocks with no capacity/deadline change. Fresh source controls passed 39,
cold passed 11/11 with native **3837/3837**
in 140.290 seconds, and fresh language passed **1,196/1,196**
plus all 10 native-report assertions. These receipts are separate from v24's
preceding source bytes and are retained in `v24-guard-headroom-summary.json`.

The first full-repository run additionally rejected the system QEMU identity in
two real AArch64 corpus tests. The project's existing bootstrap installer fetched
and verified the locked QEMU 8.2.2 archive and executable in a task-local tree
(SHA-256 `e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e`).
Both tests then passed against the unchanged original `f535528` checkout in
9.767 seconds. No hardcoded tool identity or native-vs-emulator claim was changed.
This isolated replay does not make the earlier full-suite invocation green.


### v25 general function identifiers — qualified, not whole frontend closure

Function declarations and quoted call targets now use source byte names rather
than forced contiguous `fN` spelling. First-defined entry ABI remains the three
borrowed buffers returning `u32` with ELF export `f0`. ASCII names up to 128 bytes
include keyword/contextual, underscore, leading-zero suffix and long numeric
suffix controls. Length plus every source byte is compared after a hash filter;
the real equal-hash `aaB`/`aba` pair remains semantically distinct. Duplicate,
undefined, runtime-reserved, oversized and malformed names still reject. Forward
calls, loan returns and direct self-tail calls retain the full semantic pass.

All compiler functions were also alpha-renamed to readable authoring names:
original and changed-source compiler images reproduced the matching canonical
bytes, including an actual syscall-only executable compiling its renamed source.
The independent Core VM references were established before B0, not replaced by
outputs from the successor compiler. Existing language fixture IDs were retained:
two previous profile refusals are now positive cases, not discarded tests.

Exact-source cold replay passed **11/11**, native **4,009/4,009** in 151.317 seconds;
full language **1,196/1,196**, with all 10 native-report assertions and 72 exact
workflow-body source tests passed. The original B1=B2=B3 hash is
`ca7b8951441ce93c5b92803eba4fce60ab4bcb6aeb69ad9ceb71641e2a7e3722`;
changed M1 differs from M2=M3. Source is 115 functions, 1,445 blocks, 7,481
operations and 489,766 bytes. Capacities and cold deadlines were not increased.
`v25-function-identifiers-summary.json` retains source and execution receipts.
General SSA/block names, modules/exports, full runtime/build/release and the other
open component authorities are not closed by this function-name extension.


### First completed all-repository audit and fresh failure repairs

The exact clean `f535528` full-repository run completed **7,642 tests from
730 modules in 4,363.959 seconds**, with **5 failures and 14 errors**, no skips.
Inventory completion is false because board class setup failed. Source bytes and
Git status remained unchanged. This is a failed run, not a green audit. The
separate complete summary lists all failure/error identities and receipt hashes.

Several failures were real missing/mismatched toolchains (Boost, locked QEMU,
LLVM profile runtime and the Rust thumb target). The raw-model errors were an
invocation error in this audit's runner: its environment passed a directory
instead of the required actual manifest file. All 21 affected module tests
passed on unchanged source when corrected. Such isolated replay does not rewrite
the original full-run result. A new clean full-repository invocation is running.

Two actual code repairs followed: (1) HSIR wire input now enforces an explicit
256-container lexical nesting limit before JSON decoding, independent of host
Python recursion behavior, while string escapes and shallow diagnostic distinctions
remain checked; (2) the IR-PGO resource observer no longer reconstructs
`-march=native` after capturing a masked CPU policy. Its C harness and LTO link
inherit the captured research flags and preserve target identities before/after.
The old code produced a real SIGILL under the masked execution control once
its runtime dependency was available. Fresh execution of all target-profile and
HSIR-wire modules passes 34 tests, including both actual profile training/use
and allocation-refusal observer cases. No test was skipped or softened.

The missing board emulator was built from the official QEMU 8.2.2 source in a
task-local directory, with a truthful local-build suffix (not a falsified version
of the host's QEMU 10.2). All five board module tests then passed on unchanged
source, including six actual emulator cold boots and negative controls. The
physical-board and DMA qualification flags remain false. The LLVM profile
runtime is the actual installed compiler-rt20 archive; an architecture-path alias
resolves the installed compiler driver's packaging mismatch. Rust1.90's thumb
core target is installed in the task-local toolchain, without changing defaults.


### v26 SSA/formal identifiers — qualified with retained prior failures

The HIA compiler now interns exact source-byte SSA/formal names into 2048
per-function identities. Function signatures, entry names, all uses/definitions
and quoted return-loan origins share this identity; numeric-looking suffixes
are no longer workspace offsets. Typed keyword and underscore names, real hash
collisions, shared prefixes,128byte identifiers and a full2048slot table have
independent VM and actual successor executions. The 2049th distinct name,
malformed/oversized/reserved names, duplicates, undefined uses and entry-name
mismatches remain transactional refusals. Core resource/type/dominance checks
are not replaced by interning.

All **53** historical name-only resource exclusions retain their original IDs
and source bytes as positive execution cases, including six initially missed
borrowed-view cases. The first language run's12 stale refusal assertions and
the first cold run's180second timeout remain failed evidence. A multiplicative
slot spread avoids clustering while retaining the same2048bounded probes and
mandatory full-byte equality. No deadline or capacity was raised.

Fresh final cold replay passed **11/11**, native **4,141/4,141** in163.393seconds.
The language run passed **1,196/1,196** (122positive/267negative programs per
compiler), plus10native-report assertions; focused source/reference tests pass61.
Both original and genuinely changed compiler chains reach their expected
fixed points. Alpha-renaming **all** compiler functions and SSA/formal names
also reproduces canonical images and direct-kernel executable compilation.
The compiler is117functions/1476blocks/7594operations/496797sourcebytes,
within unchanged limits. Exact source/receipt hashes and previous failures
are retained in `v26-ssa-identifiers-summary.json`.

General block/module syntax, multiple exports/linking, composite admission,
the live Python production runtime/service/build/release authorities and all
whole-stack installation/qualification gates remain OPEN.
