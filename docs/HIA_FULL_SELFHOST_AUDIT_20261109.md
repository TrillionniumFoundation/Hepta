# Whole-stack HIA selfhosting audit — 2026-11-09

## Decision and source authority

**Whole-stack rewrite is OPEN, not complete.** The successful native fixed point
is real, but does not establish that the rest of the project is implemented in
HIA. The qualified `d5ac87bc` snapshot contains a live `hepta/` package with 219 Python
files, 76,816 lines and 4,159,869 bytes. These are source inventory figures, not a
percentage-completion estimate. Archived copies and example source files are
not counted as production replacements.

The audit also inventories **425 Python files /134224lines** under `tools/`,
separately from the production package. These include host authoring, build,
qualification and delivery authorities: they have not been rewritten merely
because a generated compiler reproduces itself. Package plus tool roots total
644Python files. Tests, historical evidence, experiments, examples, benchmarks
and formal-support scripts are explicitly outside those two AST-inventory roots;
no claim that those excluded roots are HIA replacements is made. Current file
hashes/imports and these scope exclusions are reconstructable losslessly from
`implementation-boundary-v28.json` plus the versioned lossless inventory deltas.
The prior clean `1b45c4e` snapshot accounts for **all10,027 tracked paths**
by identity, role and language, distinguishing research/evidence from live code.
Its live non-Python support inventory includes46Rust,8C and9Lean source files;
none is silently counted as rewritten in HIA. Whole-tree file accounting is not
a semantic review, execution qualification or completion percentage.

**Current integrated checkpoint (2026-11-10):** exact clean d5ac87bc combines
the source lexer/integer/binary64 image, independent two-object C export audit,
exact-length compiler keyword dispatch and HIA-emitted fresh native byte-ABI
observation. Both parents' selected code bytes and full audit narratives are
retained. The source contract includes318files; the shared compiler-hash closure
remains the exact independently checked370paths /219root modules. No compiler
ceiling, witness, phase worker,180-second cold deadline or3-second cleanup limit
is weakened. The observer child is native, but supervision and literal ISA
authoring remain foreign; it is not whole-runtime retirement or a sandbox.

On this same source, actual clean workflow checks104PASS; fresh source-only
cold11/11+5,049/5,049PASS127.214seconds; language1,242+10PASS; combined native
libraries77PASS; selected/default consumers83each; incremental55; shared15;
real selected/default parser/module callers63each. The original same-source
CI clock is retained separately from the328.382-second orchestration clock.
The binary64 midpoint supplement's source AND emitted image identities remain
exactly equal to this integrated installed candidate. These observations do
not establish remote speed or all-input equivalence. Public frontend-observer
summary, source equivalence and lossless delta bind this integrated source.

The old df52f8f full regression also ended FAIL:7,736tests/739modules,2failures,
1error,complete inventory/unchanged source. The error explicitly reports
ENOSPC; the two original failure causes remain unestablished. A later isolated
two-test diagnostic passes on that same immutable source with free disk, but
does not requalify the original run. Current whole-stack ledger remains OPEN.

**Prior float checkpoint (2026-11-10):** the selected 30-function HIA source image
also converts decimal floating literals to binary64 using exact rational integer
arithmetic, quotient/remainder comparison and nearest ties-to-even rounding.
Normal, subnormal, zero-underflow and nonfinite-overflow handling execute in HIA.
Neither integer nor float literal parsing uses the host parser in this selected
path; Python constructs numeric objects from native bytes. AST parsing and the
default reference remain foreign/live. The v3 manifest declares command 2 and
the explicit6,272-byte float workspace; compiler caps/deadlines are unchanged.

Exact clean6933f8c8 passed104source tests,11/11cold+5,047/5,047native checks in
164.838seconds,1,242language checks,69native libraries,83selected+83default
consumers,55incremental,15shared closure and63selected+63default parser/module
tests. Independent pre-seed VM controls include six floating cases. An additional
780exact-rational midpoint/adjacent controls and three overflow thresholds use
no host decimal parser as oracle; their source and native image hashes exactly
match the final installed candidate. These are finite observations, not an
all-input proof. See source-float-summary.json and source equivalence/delta.

The parent integer delivery7e7dc36 also FAILED remote cold at180seconds after
22phases, with cleanup confirmed. Both parent remote failures remain retained.
The old6a89994 whole-repository run ended7,709tests with3failures/15errors and
incomplete inventory; all15error traces and one failure explicitly contain
ENOSPC, while other failure causes remain open. It is FAIL, not acceptance.
The separate immutable c57fb17e integer full run is still pending; a full run
for6933f8c8 has not been completed. No default/production/main/release change.

**Prior integer checkpoint (2026-11-10):** the selected source lexer parses
arbitrary-size integer magnitudes in HIA, not through a host literal parser.
The v2 manifest declares command 0 for tokens and command 1 for integer
magnitudes; Python only constructs integer objects from the native bytes.
The 20-function image retains all earlier lexical checks and adds independent
pre-seed integer VM controls, four-radix randomized/boundary tests, transactional
refusals, guards and eight-way private concurrent calls with the host literal
parser unavailable. Floating conversion and the full parser remain foreign.

Exact clean c57fb17e passed104source tests,11/11cold+5,047/5,047native checks
in163.463seconds under the unchanged180-second deadline,1,242language checks,
66combined native-library tests,83selected and83default consumers,55incremental,
15shared-closure and63selected+63default parser/module tests. The complete
repository regression is running on a separate immutable c57fb17e checkout;
it is not qualified by these finite local gates. See source-integer-summary.json,
source-integer-source-equivalence.json and the lossless source-integer delta.

The earlier exact70ee7cd remote cold replay FAILED at180seconds, after22phases,
with cleanup confirmed. Its original artifact and failure summary are retained.
The newer local pass does not promote that historical remote failure.

**Prior lexical checkpoint (2026-11-10):** high-level Hepta source token recognition
now executes in a19-function HIA application under explicit operator selection.
The existing token API and real Python parser/module callers exercise that
path; Python numeric values/AST parsing/type checking and the default reference
remain. Exact069087b0 clean-source CI passed104tests; native cold replay passed
11/11outer and5,047/5,047native checks in160.561seconds under the unchanged180
second deadline. Language coverage passed1,242checks, combined native libraries
62tests, existing selected/default consumers83each, incremental55, and actual
selected/default parser/module tests63each. All are finite source-bound scopes.

The exact source-CI receipt was reused with its original clock after a retained
ENOSPC cold failure; that failure is not relabelled. A prior application/opcode
coverage declaration error was also retained and fixed without dropping gates.
The clean-snapshot inventory and full tracked-file identities reconstruct from
`implementation-boundary-source-lexer-delta.json`; source and native manifest
bindings are in `source-lexer-summary.json`. Metadata merging preserves all312
qualified exported paths byte-for-byte, recorded separately rather than called
a new cold run. No default/release lock/service/main activation has occurred.

The latest observed open-PR inventory has470entries (459drafts), at2026-11-10
05:14:45UTC; titles are not integration proof. The oldv30full-repository attempt
remains incomplete. The later exact2484f5c full run completed7,697tests with
six known exact-source-closure errors, no skips, and unchanged source; it is
FAIL, not promoted by newer local gates. Other newer full-repository attempts
remain independently pending. Whole-stack status is still3partial/5open.

The project is `TrillionniumFoundation/Hepta`; there is no separate organization
repository named `HIA`. `main` is the public metadata/entry branch, not the full
compiler source. The selected public v9 source lock is `2598f430`; the separately
named v16 source lock is `6ecd8023`. Neither automatically selects an unmerged
selfhost candidate. Development continues here from PR #834 source commit
`ffbf0b89ddb468a056561543bce3e1fcab6b8da3`, which contains the v16 baseline and
v17 internal scalar result work. Do not copy a full compiler into metadata-only
`main`, silently advance release locks, or promote unrelated candidate branches.

The earlier open-PR inventory observed during this audit contained 465 entries. Many
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
| Scanner / assembly parser | Bounded `hia-asm.v1`, general ASCII function/SSA/formal/block names, exact lookup and arbitrary entry declaration order | Full module grammar and diagnostics |
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

The exact workflow source-test body was then executed on clean committed
`9663be13c15b4af300a14f602f4e146d754eab1c`: **73 tests pass in71.719seconds**,
with Git clean before and after. A separate unchanged checkout of that commit
is running the wider HIA/shared-Core inventory; that is not full-repository
coverage. The older all-repository41a317a run is still separately in progress.

### v27 block identifiers and retained compiler-generation operations

Block definitions, entry references and forward/backward edges now resolve exact
ASCII identifiers through a256-entry source-order discovery table, occupying
workspace[1004304,1010448). Discovery skips non-header line bodies only to collect
names; all original syntax, SSA, type, ownership and CFG checks still execute.
The entry must still be the first declared block. Its valid-Core later-entry
control remains an explicit profile refusal. Actual equal-hash labels, keyword
labels,128byte names,256/1536block graphs, capability joins and backedges remain
independent VM and original/modified native witnesses. Whole-compiler alpha
renaming now covers all function, SSA/formal AND block labels.

Two180second cold timeouts are retained as failures. Authoring-only CFG compaction
removes215empty forwarding blocks and unobserved scalar edge parameters, retaining
all7678operations, entry/resource parameters and all operation operands as
liveness roots. Parallel substitutions preserve parameter permutations; empty
cycles retain divergence, and unused checked results still trap. Both documents
pass the ordinary Core verifier. This does not optimize accepted user programs
or assert identical VM step cost. Four focused VM controls include ordered writes,
loops, resources, returned origins and checked division. Source/reference tests
pass66; no deadline/capacity or witness inventory was reduced.

Final source-bound cold replay passes **11/11**, native **4257/4257** in
**166.476seconds**; original B1/B2/B3 and modified M2/M3 fixed points are distinct
and byte-identical within their own chains. Language regression passes
**1196/1196** plus10native-report assertions. The compiler now has118functions,
1287blocks,7678operations and424706source bytes. Exact source manifests and
retained failures are in `v27-block-identifiers-summary.json`. These are local
finite observations, not whole-stack or all-input qualification.

GitHub checks on prior head`dbd98fd` still failed cold and the unified suite's
cold test (589tests,1failure) at the unchanged180second deadline. Local passes
do not replace remote failures. New source requires its own CI execution.

The clean9663be1 HIA/shared-Core inventory has now completed **4409tests from
477modules,0failures,2class-setup errors,0skips**. Source stayed unchanged and
Git clean, but inventory execution is incomplete. Both errors are STB capture
initializations. The unchanged exact-source captures pass in isolated execution
and after importing all477test modules with the same environment; the run-order
or process-state cause remains OPEN. `v26-full-hia-test-run-summary.json` retains
the failed result. Neither isolated capture nor the separate current compiler
checks relabel that full run successful. The older41a317a all-repository run
continues separately and does not contain later fixes.

The complete workflow source steps on clean`aaaed68` then found **1failure in
78tests**: the keyword fixture had not applied the new authoring compaction and
thus no longer equaled the live compiler body. The exact-equality assertion is
unchanged; the fixture now applies the same verified transformation. All four
keyword source/reference tests pass. Fresh final cold replay after this repair
passes11/11 and4257/4257 in**161.414seconds**, with identical compiler machine
bytes to the earlier pass; the new source manifest and language1196/1196 plus
10assertions are retained separately. A fresh clean-source78test replay is still
required before claiming that workflow step passes.

The41a317a all-repository run has now completed **7654tests/731modules,1failure,
1error,0skips**, complete inventory and unchanged source. Its two diagnostics
are exactly the earlier HSIR-depth and masked-CPU IR-PGO defects, already repaired
in later source, but the failed run is not relabeled. See
`full-repository-second-run-summary.json`. The exact9663be1 isolated replay of
both STB modules passes17tests in63.304seconds, including their real native setup;
that also does not replace the failed HIA/shared-Core inventory or establish its
process-order cause. Latest-source full inventories remain required.


The repaired clean implementation commit`b048608b1ba6eb7144bce2f2b1d079383590a43a`
now passes the ACTUAL workflow recovery/regeneration and source-test steps:
**78tests in76.477seconds**, Git clean before/after, no skips. The earlier78test
failure remains retained. Both wider inventories have started afresh on a
separate unchanged checkout of that exact implementation: all HIA/shared-Core,
and separately all repository test modules. They do not reuse prior results.
A passive read-only watcher retains any failed STB migration report before test
temporary-directory finalization; it does not wrap, retry, skip or change tests.

## v28 arbitrary entry order, exact-source qualification and full-run diagnosis

The native HIA parser now admits a declared entry at any block-source position.
Entry parameters, external borrow origins, forbidden incoming-entry edges, CFG
replay, initial prologue jumps and same-frame self-tail jumps all use the actual
entry index. The exact formerly excluded later-entry program is retained as a
positive witness. Entry-last/middle256/1536block graphs, reverse resource joins,
returned-loan tails and wrong-origin/join negative controls are retained. No
source/output/workspace, SSA, operation, block, relocation or time limit increased.
The relocation derivation includes128possible entry jumps:11395<12000; the Core
wire bound includes the complete arbitrary-identifier source payload.

Pinned implementation **`d701f9ab2324babe98eabb02f9c693b84f657247`** has:

- Source-only cold replay11/11, native4347/4347 in171.134462998seconds.
- Language1196/1196 plus10report assertions; source group60tests passes.
- Full native unittest class19tests in207.334seconds, including20whole-compiler
  last/middle entry-layout checks across original and modified successors,
  canonical-source reproduction, static ET_EXEC reproduction and owned/chain CFGs.
- Actual clean committed workflow recovery/regeneration and source steps pass
  **80tests**,84.274seconds for both steps, Git clean before and after.

The first source-group run retained one stale relocation-bound assertion failure.
The first cold run passed narrowly at179.978seconds; the second exceeded180seconds
and remains failed. Packed keyword matching now omits only comparisons against
provably unwritten zero tail words, retaining length and every occupied packed
word; all prior observations and extra boundary mutation controls remain. The
first clean committed CI attempt also caught a missing staged keyword helper;
that failed commit is retained, the omitted implementation was committed, and
clean CI02 passed. None of those attempts is relabeled as final-source success.

The fresh `b048608` HIA/shared-Core inventory finished **4414tests/477modules,
0failures/2setup errors,0skips**,1697.169seconds, unchanged source and incomplete
execution. The passive watcher retained the actual failed STB migration: input
`{"fixture":"full_capture_only"}` lacked `configurations`. A clean-interpreter
reconstruction on the old source shows the preceding Linux relative-directory
test leaves `c_migration_project.capture_project` bound to a temporary MagicMock:
its first lazy import occurred while the dependency was patched. The test now
resolves the consumer before patching that dependency; production migration and
native STB assertions are unchanged. A clean-process regression passes, and the
original ordered Linux-then-actual-STB modules pass22tests in63.678seconds.
**This does not promote either failed full HIA run.** A completely fresh full HIA
inventory is running on unchanged clean `d701f9a`; the previous all-repository
`b048608` run remains running separately. Current-head remote CI is still required.

Receipts: `v28-entry-order-summary.json`, `v27-full-hia-test-run-summary.json` and
`implementation-boundary-v28.json` under the existing review-evidence directory.
General module grammar/diagnostics, composites, module/export/link graphs,
production runtime/stdlib, build/install/release, Agent service/store/tools,
optimizer/proof construction and applicable real-platform gates remain OPEN.


## v29 ordinary module labels and exact committed qualification

Ordinary Core module labels now select the flat ABI without spelling-based
rejection. The original `unsupported-module-name` source and witness ID are
unchanged but are now positive. Sixteen labels (including keywords, `_`, maximum
length and nonreserved prefixes) execute; eight genuinely invalid labels remain
negative. Explicit `selfhost_elf` and `selfhost_exec` ABI selectors are unchanged.
Original and modified whole compilers with renamed module labels reproduce their
matching images twice. Module imports, exports and general linking remain OPEN.

Pinned implementation **`f787ae400a8677e28c37bcfbfc934b97ef9b6d9b`** passes:

- Cold11/11 and native4351/4351,176.667seconds at the unchanged180second deadline.
- Language1242/1242 plus10report assertions; source61tests passes.
- Actual clean committed workflow recovery/regeneration and source steps:
  **81tests**,84.921seconds for both steps, Git clean before and after.
- Compiler118functions,1300blocks,7258operations,412076source bytes.

The separate **exact `d701f9a` v28** HIA/shared-Core inventory has now completed:
**4428tests/478modules,0failures,0errors,0skips**,1799.184seconds. Inventory is
complete and source stayed unchanged. This is full-inventory evidence for the
STB lazy-import repair, not a pass for later v29 or the non-HIA repository modules.
The old `b048608` all-repository run remains separately in progress.

Actual retained GitHub artifacts at old uploaded head `644e179` establish unified
593tests/1failure and cold timeout180.143seconds with completed owner cleanup.
The connector supplied those artifacts after local gh access failed. No new local
pass replaces either old remote failure. See `v27-github-failure-artifacts-summary.json`.

**Upload pending:** local v28/v29 commits are not on GitHub because the existing
local gh credentials expired. Remote PR836 still has head `644e179`. No fabricated
commit recreation, credential disclosure or protection change is used. The user
has been asked to restore the local login; development continues independently.

Receipts: `v29-module-identifiers-summary.json`, the lossless static inventory
`implementation-boundary-v29-delta.json`, and `v28-full-hia-test-run-summary.json`.
The audit's full record lists are path-indexed and reconstruct the retained full
v29 report byte-for-byte; this avoids duplicating the unchanged10000path inventory.
Finite native observations are not all-input proofs. Full JSON/Core frontend,
module graphs, general runtime/library, Agent service/store, build/install/release
and applicable physical-platform gates still prevent whole-stack closure.


## Completed old inventories and v30 HIA JSON admission candidate

The original clean **`b048608` all-repository inventory is now PASS**:
7666tests/732modules,0failures/0errors/0skips, complete inventory, unchanged source,
Git clean before/after. Its wrapper elapsed4604.920seconds; unittest4599.849seconds.
See `full-repository-third-run-summary.json`. This is a pass only for that old
source, not a promotion of later module/entry/JSON changes. The separate exact
`d701f9a` HIA/shared-Core4428test pass remains separately source-bound.

`examples/hia_bootstrap/json_preflight.hiaasm` now implements iterative JSON
syntax, strict UTF-8/escaped Unicode, decoded duplicate keys, exact object scopes
and pre-allocation node/depth budgets in HIA. It is compiled by the qualified HIA
native compiler. An operator-selected source/image-bound manifest routes the
EXISTING `preflight_hia_json` API through the HIA candidate inside its profile;
the default Python reference and full JSON value decoder remain unchanged.
The application profile admits8MiBwire,1..1048576nodes,rootdepth0..128; its private
key/state buffers are distinct from unchanged compiler capacities. Production,
Mac service, package installation and default-backend activation are NOT claimed.

The final local candidate implementation commit **`1b45c4eef1057cb4708919b933ed66eecd8933e6`**
has these finite observations:

- HIA JSON and independent-reference group19testsPASS10.280seconds. A real VM
  owner/loan wrapper executes before freshB0→B1→B2; B2 compiles the JSON source.
  Controls cover2000random trees plus randomized budgets,2000mutations, all256
  single/quoted bytes, decoded Unicode aliases,16384unique keys, exact/over1Mnode,
  128depth/8MiBwire, concurrency, scratch and artifact identity failures. The old
  six regressions additionally execute under actual native API selection.
- With a locally built manifest selected,65existing production-consumer regressions
  pass22.719seconds across tools,queue,assembly and actual Rust byte DAG consumers.
- The current declared compiler source closure passes cold11/11/native4351/4351
  in169.083seconds at the unchanged180second deadline. Original and modified
  fixed-point byte identities are unchanged; the complete source manifest matches.
- Actual recovery/regeneration and source CI steps pass **90tests**,79.374seconds
  total, on clean committed`1b45c4e`, Git clean before and after.

The first clean35020f4 CI attempt retained **90tests/1failure**: five new declared
source files were absent from the release freeze inventory. They were added to
`BOOTSTRAP_FILES`; exact inventory equality was not weakened.24contract/release
regressions pass, then completely fresh cleanCI02 passes. The failed attempt is
retained in `v30-json-preflight-summary.json`, not relabeled. A fresh complete
all-repository inventory now runs on immutable`1b45c4e`; it is NOT yet a pass.

Receipts: `v30-json-preflight-summary.json`, losslessly reconstructed
`implementation-boundary-v30-delta.json`, and `docs/HIA_JSON_PREFLIGHT_NATIVE.md`.
The production package still has213Python files/76265lines; tools408/131262.
Adding an optional HIA backend does not remove those Python authorities or count
as full JSON decoding. All8component boundaries remain3partial/5open. No all-input
refinement or worst-case cost proof, complete frontend/runtime/build/Agent rewrite,
release-lock promotion, main import or remote CI qualification is asserted.
**These local commits still await the user's existing gh-login restoration before
original Git history can be pushed.** PR836remotehead remains644e179.


## v31 HIA JSON values and exact current-source qualification

The15function HIA JSON value-arena library now constructs typed values, ordered
parent/sibling relationships, decoded UTF-8 strings/keys and original integer
lexemes. An explicitly selected source/image/compiler-bound backend integrates
existing Core/Agent inputs, queue journals, state wire, full-cost, paired replay
and Rust byte-DAG. The default reference, foreign Python-object materialization,
canonical encoder, semantic Core checker and service/runtime remain Python.
This is not a whole JSON/runtime-stack rewrite or production activation.

Exact final implementation **`2484f5c4107203dbac1b3154f95f6a8c21df0b8e`** passes:

- Actual clean committed workflow recovery/regeneration and94source tests,
  84.120seconds total, Git clean before/after.
- Source-only cold11/11 plus native4351/4351,166.202seconds at the unchanged
  180second deadline; original and changed-source fixed points retained.
- Language1242/1242 and10report assertions.
- Fresh native JSON18tests,18.011seconds, including actual independent VM
  observations before freshB0/B1/B2 and compiled value decoding.
- Explicitly installed HIA value backend83existing consumer tests,26.098seconds;
  separately default-reference83tests,21.952seconds. No skipped case is a pass.

Earlier implementation51d56f6 also passed its actual94source tests, cold11/11
plus4351native checks in177.203seconds, language1242 and native JSON18tests.
The final follow-up restores the prior detached-object bridge for internally
produced, already structured canonical JSON, avoiding a redundant hostile-wire
preflight of that same graph. Submitted-wire checks/budgets are unchanged; final
source steps return to84.120seconds from the earlier130.600seconds. Both source
identities and outcomes are retained, not substituted for each other.

The215Python-package/410host-tool inventory, all10036tracked implementation paths
and the3partial/5open component ledger remain explicit. Static records reconstruct
losslessly from v28 plus `implementation-boundary-v31-delta.json`; actual finite
receipts are in `v31-json-value-arena-summary.json`. No compiler capacity/deadline,
release lock, main branch, host service or Mac task was changed.

The earlier v30 full run produced no final report or observed exit status, and
is retained as INCOMPLETE, not a pass. A completely fresh whole-repository
inventory is running on immutable2484f5c with the actual pinned prerequisites.
It remains separate from all finite passes above and from old7666/4428passes.
Remote qualification of the new source must execute separately. Whole-stack
closure and all-input refinement/worst-case-cost claims remain false.


## v32 native canonical wire continuation (source-bound local qualification)

The22function HIA canonical-wire library decodes an arena, performs iterative
object-child linked-list merge sort in Unicode-codepoint order, emits compact
UTF-8 JSON with exact control escaping and normalizes -0. The existing Core
serialized-input path can explicitly select it after the unchanged structural
checks. With the value decoder also selected, canonical snapshots/as_dict
use HIA payload decoding. A real primitive Core input and its immutable snapshot
execute with Python json.loads/json.dumps/JSONDecoder.decode disabled in the
application conformance test. Semantic verification, foreign objects, caller-owned
object serialization, composites, other encoders, runtime and services remain
Python; this is not full frontend/runtime replacement or default activation.

The shared trusted-image manifest loader now refuses duplicate fields and binds
current source bytes as part of its cache key. An actual warm-cache source-drift
regression covers all3native JSON protocols, while mapped code stays immutable.
The low-level canonicalizer can preserve very long integer lexemes without
host integer construction; foreign decoder digit policies still apply to Core
admission, and no unrestricted Python-decoder equivalence is claimed.

Development observations:7VM/source checksPASS5.269s,26fresh native JSON tests
PASS28.359s,77default/source/release/cache regressionsPASS1.966s and83existing
consumers with both native manifests selectedPASS25.335s. The initial VM fixture
read240observation bytes from a valid224byte output at depth1; it correctly
trapped. The fixture now observes min(240, actual output capacity), preserving
every original input and refusal. That failed log is retained; no production
capacity or bounds check was changed to make it pass. These development logs
are not substitutes for exact committed cold/language/source qualification.

The staged whole-tree inventory has10044tracked paths; its216Python package
files and412host tools remain non-HIA authorities where described. All8component
boundaries still3partial/5open. Existing frozen v31 full-repository run remains
independent and running; no newer global pass is asserted. See
`docs/HIA_JSON_CANONICAL_NATIVE.md` for the actual ABI, integration and boundaries.

Exact committed implementation `23d461a4e714b6ef9fe44af9c8b6d3fb161e3bac`
now passes the actual clean-source workflow: 97 tests, 91.244668275 seconds
including regeneration, with a clean worktree before and after. Its cold replay
passes all 11 gates and 4,351 native checks in 173.628063743 seconds; language
coverage passes 1,242/1,242 plus the separate assertion checks. The existing
180-second cold deadline and compiler capacities remain unchanged.

The same frozen source passes 26 native JSON tests, then builds both application
images with its completed B3 compiler and cold receipt. Existing consumers pass
83 tests with both manifests selected and 83 with the default reference. The
complete sequential qualification takes 407.422016382 seconds. The first
orchestration attempt failed before running tests because its external helper
file did not exist; that setup failure is retained separately from the successful
source-bound run. See `review-evidence/hia-whole-selfhost-20261109/v32-json-canonical-summary.json`
and its losslessly reconstructable static-audit delta. Remote CI and current
whole-repository qualification are not promoted to passes by these local results.

## v33 primitive JSON Core native frontend (exact qualification pending)

The 40-function HIA frontend now decodes serialized primitive v8 Core, checks
closed representation shapes, preserves identifiers/declaration order/returned
loan metadata and emits bounded assembly for the real native HIA semantic
compiler. Its runtime path does not call the Python JSON parser, Core verifier
or renderer. A separate host driver still handles pinned manifests, allocation,
filesystem, subprocesses and trusted receipt metadata. General exports/composites
and the production CLI/service/runtime/build pipeline remain open.

Independent VM observations and the original/genuinely modified compiler JSON
inputs precede B0. Fresh B0/B1/B2 builds the frontend; both full compiler inputs
render exact source bytes and produce three generations with the required fixed
points. Native byte programs execute, including 24 distinct returned-loan/general
name programs and the caller-owned-parent case through explicit ELF selection
and actual external linking. Default flat mode refuses ELF/executable label
selection; an operator must explicitly select ELF in addition to its module
label. This does not rewrite the external linker/libc allocation runtime.

The development class passes 9 tests in 22.647 seconds, including randomized
field ordering, Unicode fragments/subtree boundaries, source drift, concurrency,
exact/over output capacity, shape confusion, injection and real native semantic
refusal. The first class run correctly refused the caller-owned-parent ELF label
under default flat selection; explicit ELF profile support and actual linking
were added without dropping that witness. The source/default regression replay
passes 70 tests in 13.817 seconds. Its initial uncommitted run used a stale source
contract and group-writable temporary files, which the existing strict boundary
correctly refused. The contract was regenerated and private fixture permissions
restored; no check or production limit was weakened. Both failed logs remain.

These development observations are not substitutes for a clean committed cold,
source workflow, language or whole-repository result. The next source-bound
qualification binds the full 297-file compiler source closure. Component status
remains 3 partial / 5 open; whole-stack completion and all-input correctness
remain false. See `docs/HIA_CORE_JSON_FRONTEND_NATIVE.md`.


## v33/v34 completed source-bound local qualification

Native frontend implementation `3fb8601fb1c6384401998fe37536180d7b79f1a5`
passes the actual source workflow: 99 tests, clean source before/after. Its cold
report passes all 11 gates / 4,351 native compiler checks in 178.556889613 seconds
within the unchanged 180-second deadline. Language coverage is 1,242/1,242 plus
its separate assertion checks; 33 fresh native JSON/frontend tests pass, followed
by 83 existing consumers with both JSON manifests selected and 83 default.
The full sequential qualification is 440.407369086 seconds. Completed cold B3
builds all three candidate images. This supersedes pending qualification above,
not the stated whole-stack limitations or the historical failures.

The ongoing frozen `2484f5c` full-repository run exposed six source-closure errors,
independently reproduced as six errors in 15 tests: the fixed old compiler input
inventory omitted the new native JSON modules. Follow-up
`bfd3b4406805c6e7ea25089022183331034f838a` binds 23 explicit bridge/HIA source/
build/driver/conformance additions, all 217 actual compiler Python modules and
360 source paths. The exact prior 337-path commitment and all older projections
remain checked; unknown/missing modules still refuse. Protocol v11 transfers
3,066 bytes from raw logs into identity metadata, preserving the 1 MiB aggregate
and all source/module/container/process/time caps. The initial development
accounting assertion accidentally compared the new identity to an older
projection; the original 131-byte historical comparison is now retained against
its proper 337-path identity alongside the new exact 3,066-byte assertion.

That clean committed follow-up passes 251 shared/legacy adversarial tests in
480.615 seconds, then 99 actual workflow source tests and a clean static audit.
All 298 exported native compiler source-manifest paths remain byte-identical to
the native-qualified implementation; this equivalence is checked path by path.
Native qualification is reused only for that identical source closure, not
invented as a newly executed cold run on the follow-up commit. The older full
repository run remains running with observed errors, not a completed or current
pass; the repair does not relabel it. Remote CI remains separately unqualified.

Public receipts: `v33-core-json-frontend-summary.json`,
`v34-exact-source-closure-summary.json` and the losslessly reconstructable v33/v34
inventory deltas under `review-evidence/hia-whole-selfhost-20261109/`.
Component status remains 3 partial / 5 open. Whole-stack completion is false.

## Integrated multiple scalar exports / JSON-to-ELF continuation

Exact executable source subject: `df52f8faa69b3dd93cd3838ec30fc843ce610c7e`.
This isolated continuation incorporates the original Core JSON frontend commit
`6a89994` and the SHA-256 branch rather than discarding either implementation.
Its own implementation/merge commits are `07b3fdd`, `5f0fc60`, `dce2e3f` and
`df52f8f`. Later evidence-only metadata is not presented as a separately executed
compiler. The declared source closure must remain byte-identical to this subject.

Actual HIA now parses a nonempty exact-name export list, emits multiple SysV
scalar wrappers, ELF symbol/string tables and allocator relocations. All private
functions remain checked. The JSON Core frontend renders the same explicit
export list only with operator ELF selection; real native semantic compilation,
independent object inspection, host linking and native function calls then run.
This is not a Python payload translator. Manifest/loading/allocation/filesystem,
receipt driving and the linker still are host responsibilities. Public resources
or multiresults, general module graphs/linking and production activation remain
outside this reviewed profile. Runtime-reserved and loader hook names refuse.

The compiler word-access optimization keeps little-endian byte order and prior
partial stores on a bounds trap. Twenty-eight independent VM/native cases cover
those boundaries. The compiler is123functions,1418blocks,8002operations and
453793source bytes, within the UNCHANGED128/1536/8192 and1MiB limits. The derived
relative-call upper bound11522 remains below12000. The cold deadline remains180s.

Fixed clean-source execution completed all13 selected steps in467.747seconds:

- Actual source-recovery/generation workflow and103source assertions: PASS.
- Source-only cold ownership/isolation11/11 and native5047/5047: PASS in163.885s.
- Language1242/1242, with10report assertions and no skips: PASS.
- Combined native export/JSON frontend/JSON/SHA library50tests: PASS.
- Exact shared acceptance closure15tests: PASS. v12 binds365paths and218actual
  root compiler modules, independently preserving every old commitment; the631
  extra identity bytes are transferred from raw logs, not a larger total budget.
- Current-source decoder/canonicalizer/SHA/Core-frontend native builds: PASS.
- Explicit installed and default consumers83tests each, selected incremental
  policy55tests: PASS.
- Additional exported-public/private-chain composition returns44561/91 under
  independent VM and actual native execution, including iterative destruction.

The current exact-source full repository regression has started from a separate
immutable `df52f8f` checkout with real pinned prerequisites. It is **NOT completed
by this report**. Older runs and remote CI are independent observations, not a
substitute for this result. Initial malformed fixture and stale exact-closure
failures remain recorded as failures in the public summary.

The lossless audit delta accounts for10070tracked paths at this implementation
subject:218package Python files/76667lines and421tool Python files/133115lines.
Tool files include authoring/qualification and are not all production runtime.
Static counts are not semantic closure evidence. The component ledger remains
**3 partial /5 open**, with no live authority silently retired. Whole-stack HIA
rewrite remains **OPEN**, defaults and production unchanged.

Reviewable records:
`review-evidence/hia-whole-selfhost-20261109/multiple-scalar-exports-summary.json`
and `implementation-boundary-multiple-exports-delta.json` in that directory.


### Independent cross-object scalar export audit

Two independently compiled HIA ELF objects are linked into one actual C
executable with `-z defs`, immediate binding and a non-executable stack. Both
source modules deliberately contain `private_value` with different results;
only public identifiers are prefixed. The independent Core VM evaluates all
10 public observations before the first seed/successor is built. The real
C caller uses declared `int8_t`, `bool`, `uintptr_t` and sixteen mixed scalar
arguments (including stack arguments), and exercises allocator imports in both
objects. Exact per-object symbols exclude private helpers and include only
the selected exports plus the closed allocator imports.

This checks real multi-object linkage and typed C ABI calls. It is not a
Hepta source-module graph resolver, a native linker implementation or a
whole-language/runtime closure claim. Compiler HIA source bytes are unchanged.


### High-level Hepta source scanning in HIA (candidate, whole stack OPEN)

Added a19-function HIA source lexical recognizer, distinct from the assembly
compiler scanner. It performs UTF-8 scalar/code-point position tracking,
nested comments, keywords/identifiers, lifetime/operator/string/numeric token
grammar and lexical diagnostics in HIA. An explicit operator manifest routes
the existing tokenize API and actual parser callers through native recognition.
Default/reference behavior remains unchanged, including fallback for source
representations outside this bounded candidate profile. Python numeric
materialization and AST/parser/type/module/runtime paths remain live.

The token ABI validates/counts before publishing any output and keeps the
8MiB input,1M-token including EOF and128-byte workspace profile explicit.
Compiler caps/deadlines do not change. Exact source closure v14 adds five
reviewed source-lexer paths, retains the365-path SHA-256 and all older
projections independently, and binds all219actual root Python modules.
The661-byte identity increase is transferred from raw logs to metadata;
aggregate evidence/container/source/module/process limits remain unchanged.
See HIA_SOURCE_LEXER_NATIVE.md. Fresh source-bound execution receipts are
required; the existing compiler fixed points are not whole-frontend closure.


### Exact source-lexer delivery checkpoint

The qualified source069087b0 remains the execution authority. Public records
retain the native lexer manifest, cold/CI/language/library/caller clocks and
identities, historical failures and losslessly reconstructable source inventory.
The metadata-only merge incorporates the preceding scalar-export qualification
without changing any of the312qualified compiler export paths. Native source
lexing does not close numeric value construction, the full frontend/type/module
graph, general runtime, agent services or build/release retirement.

## Qualification transport continuation: exact native observer subject eebf5a7

The multiple-export subject's real remote workflow
[42756927029](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42756927029)
completed **FAIL** on bf3360f: source/native/language passed, but source-only cold
replay exceeded its unchanged 180-second deadline. Twenty-six of 38 phases had
completed, with no reported phase exception, and owned-process cleanup was
confirmed. Full logs and the cold artifact remain retained. The earlier local
5,047-check pass does not replace that failure.

The exact executable subject `eebf5a7b04c5408924882936548168bf6886a34a`
adds exact-length keyword buckets and a HIA-emitted native byte-ABI observer for
ordinary qualification phase calls. The observer is emitted by an actual HIA
packer compiled by B3, compared with independent pre-B0 VM observations of every
ELF byte, and execs afresh from sealed bytes. Its supplied image is mapped RW then
RX. It has no Python runtime/libc/interpreter/linker in that child. The fixed ISA
syscall bridge still has explicit literal-instruction authoring; this is **not**
a high-level runtime/whole-stack retirement claim. Original B/M generations,
shared-library calls, custom preimages and post-UD2 shared captures retain the
independent stdlib loader. Host supervision, oracles, B0, linking and release
remain foreign authorities. See [the protocol and exact boundary](HIA_NATIVE_BYTE_ABI_OBSERVER.md).

Clean-commit local acceptance (not a remote performance guarantee):

- Actual recovery/regeneration workflow: 103 source tests pass.
- Source-only cold: 11/11 isolation/ownership checks and 5,049/5,049 native checks
  pass in 127.155 seconds, keeping 180 seconds plus separate 3-second cleanup.
- Language: 1,242 checks and 10 assertions pass.
- Native observer/export/JSON/SHA regressions: 58 tests pass; shared closure: 15
  tests pass. No witness, compiler ceiling or host worker is removed/increased.
- Separate real-kernel observations agree with the legacy loader for all six
  hard/soft resource limits and non-dumpability, inclusive maximum image/source/
  output/workspace sizes, and maximum-frame-plus-one refusal. These are separate
  observations, not relabelled cold pre-B0 references.
- An earlier keyword-only language run failed with ENOSPC; an initial VM fixture
  exceeded the unchanged return-list bound. Both failures are retained, rather
  than reclassified as passes.

Public `native-byte-abi-observer-summary.json` and its lossless static-audit delta
bind the exact executable subject. Later evidence-only metadata must preserve
all 313 declared source files byte-for-byte. This branch's source inventory is
218 package Python files / 76,667 lines and 423 tool Python files / 133,444 lines;
tools are not all production runtime. The ledger remains **3 partial / 5 open**.
Production activation/default switching, whole-repository completion, full
language correctness and native-only retirement are **not** claimed. A fresh
remote run is required; the historical timeout remains FAIL.
