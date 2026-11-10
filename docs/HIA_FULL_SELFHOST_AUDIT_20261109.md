# Whole-stack HIA selfhosting audit — 2026-11-09

> **Current product scope (2026-11-10): HIA Core + Agent.** The owner now requires high-level Hepta removal from the active product.
> This historical component branch still contains it and is not the post-removal
> product. Historical results below remain scoped evidence, not current native-only
> delivery. All nine whole-product obligations remain OPEN.

## Decision and source authority

**Whole-stack rewrite is OPEN, not complete.** This continuation adds an
operator-selected source type parser in HIA. It recognizes the complete existing
type grammar with an explicit bounded stack: qualified paths, generic arguments
and lifetimes, arrays/slices, read/mut references and raw const/mut pointers.
It is not a declaration/expression parser or a semantic type checker. Default
backends and old implementations remain unchanged, pending whole-stack closure.
The new implementation completed its own fresh qualification atfc5540f as
recorded below; baseline results are not substituted for changed-source evidence.

### Latest qualified baseline (before source type parsing)

The latest combined executable
qualification subject is `4f95ee91fd3aac0513135e22512f310ed806267d`; current
assembly-aware inventory subject is `115d042`, with all328qualified cold payloads
preserved byte-for-byte through review head `d7d1a34` (draft PR #845).

The qualified baseline `hepta/` package has **220 Python files /76,872lines /
4,161,818bytes**. Separately, baseline `tools/` has **428 Python files /134,502lines /
7,704,073bytes**. The648combined files include foreign authoring, build,
qualification and delivery authorities; tools are not all production runtime.
These inventories are neither a completion percentage nor proof of semantic
replacement. Assembly `.S`/`.s` support files are now explicitly classified,
not silently counted as HIA. Tests, historical evidence, experiments, examples,
benchmarks and formal-support scripts are outside those two Python roots, but
remain accounted for by tracked-file identity and role in the lossless audits.

Current combined local evidence is108source tests, cold11/11+5,049native checks
in101.204seconds under180+3seconds,1,242language checks+10assertions,96native
component tests,15shared-identity controls,83selected+83default consumers,
55selected incremental tests and63selected+63default parser/module callers.
The audit ledger remains **3partial/5open**. A separately frozen full-repository
run at4f95ee9 is pending. Remote CI atd7d1a34 has passed all four source, cold, native and language
jobs (run42766783539). The cold native checks took174.082seconds under
the unchanged180second deadline. No
full-repository or whole-stack PASS is established. Earlier shared-observer remote b4b1e4c timed
out at180seconds (28/38phases, cleanup complete), and remains FAIL despite local
passes and an earlier a19b612 remote success.

Exact current inventories reconstruct from `implementation-boundary-v28.json`
plus `implementation-boundary-integrated-stack-delta.json` and the separately
labelled `implementation-boundary-integrated-current-inventory-delta.json`.
See `integrated-native-stack-summary.json` and
`integrated-current-inventory-summary.json` for distinct executable/inventory
subjects and source-equivalence evidence. Main/release locks, production and
default backends have not been switched.

### Historical qualified checkpoints (not current closure claims)

The streaming bd3e9c2 snapshot had219package+418tool Python files; standalone
CLI bc9aa4a had219+420; integrated CLI/exports5fb6357 had219+424; the separate
source-integer c57fb17 snapshot had219+423. Their exact hashes, import inventories
and receipts are retained in the corresponding public summaries/deltas. They
are not substitutions for current combined-source qualification. The older
clean1b45c4e inventory accounts for10,027tracked paths, including46Rust,8C and
9Lean live support sources; whole-tree file accounting was not semantic or
execution qualification. Historical full-suite failures retain their original
status. The chronology below describes those checkpoints, not the current head.

**Streaming qualification:** Native HIA Core JSON representation, one-shot SHA and
incremental SHA are integrated in the current candidate. Exact implementation
`bd3e9c2a9e61e7b6a540fee1c26d54d03003c313` passes 102 clean source tests,
cold 11/11 with 4,351 native checks in150.394seconds, language1,242/1,242,
47native component tests, selected/default83 consumers each,55 selected
incremental tests and15 source-identity/accounting/provenance controls. Defaults
are not switched; whole-stack retirement is not eligible. Fresh full-repository
regression on this immutable implementation is running with no final result.
Its receipts and exact static inventory are recorded in
`sha256-stream-native-library-summary.json` and the lossless streaming delta.
Historical local/remote failures below are retained, not promoted by these passes.

**Current standalone JSON CLI:** Exact implementation
`bc9aa4a4865c2e52e085a79597791d9fb6c45607` passes104source checks, fresh cold11/11/
4351native in153.139seconds,9CLI tests,15exact-source controls, actual completedB3
flat/ELFbuilds and installed/copied executable observations including EINTR and
real partial-write failure. Its syscall-only runtime has no host payload parser
or Python driver; the build driver and complete production CLI remain host-owned.
No current-source full-repository result, production activation or retirement is
claimed. See `core-json-cli-native-summary.json` and its lossless inventory delta.

**Current integrated JSON CLI / scalar exports:** Exact implementation
`5fb6357a331d49916ad51c659b2ea58adf39fe7a` passes107clean source checks,
cold11/11and5047/5047native in152.673seconds, language1242/1242plus10
inventory assertions,69component tests and15source-closure/accounting controls.
Actual completedB3flat/ELFCLI builds and15installed/copied observations pass,
including two JSON-to-export-object compilations and a real typed C caller.
All316qualified source files remain bound to that implementation; metadata-only
publication is not substituted for their qualification. The static audit retains
219package Python files and424host-tool Python files,3partial/5openboundaries.
Full-repository execution on this immutable implementation is running, not passed.
See `json-cli-exports-native-summary.json` and its lossless inventory delta.

The previous4c0fb93remote unified gate is FAIL:595executed tests, one cold-replay
failure, no skipped tests. Its original ZIP has SHA256
`7b97a1330efa9562e09745c7a0b0d8807daeecca30f50a73c7c7cbf938cd6f60`.
The generic unittest removed its temporary nested diagnosis; the observation
cannot establish the precise child failure. The roughly182-second log interval
is recorded, not recast as a pass or an established root cause. Separately,
the dedicated selfhost workflow had a stale PR-base filter and did not trigger
for later stacked `work/hia-*` PRs. Its filter now includes that series without
changing any compiler, witness, timeout, capacity or permissions. The new remote
run must report its own outcome.
**Current continuation (2026-11-10):** the selected source lexer now parses
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
| Code generator / ELF writer | Linux x86-64 flat and bounded ELF with explicit multiple scalar exports | General linker, module graph and other targets |
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


## Incremental SHA and combined-source continuation

The current candidate integrates the primitive Core JSON frontend and both HIA
SHA libraries without replacing or dropping either branch. The incremental
library implements an explicit HIA initialization/update/finalize state machine
with 1,184 private bytes, at-most-8-MiB chunks and the SHA byte-length bound of
2^61-1 total bytes. It removes the one-shot total-size restriction from explicitly
selected bytes-valued Core payload hashing, not from unrelated APIs or resource
budgets. Python still owns allocation, code loading and chunk scheduling.

Development observations: six streaming tests passed, including an independent
Core VM sequence before fresh native B0/B1/B2, FIPS vectors, padding/split points,
1,000 random partitions, copy/repeated digest/update, >8-MiB payloads, private
concurrency, invalid transitions, length overflow and canaries. The combined
pre-merge integration ran 40 tests including a real cold replay and passed.
Those observations are not current merged-source qualification. Fresh clean
combined-source source/cold/native/consumer checks are required and recorded in
separate exact-commit receipts when complete.

Remote PR837 unified regression on4593f2b is retained as FAIL:595tests,
1cold-replay failure and6 exact-source-closure errors. Source identities had not
included the newly added package modules. The combined candidate explicitly
binds369 reviewed paths, all219 top-level Python compiler modules, preserves
all historical projections and transfers exactly1,168 bytes from raw logs to
identity metadata within the same aggregate envelope. Development closure
replay initially exposed two stale count assertions; both were updated to the
actual reviewed additions, with all negative controls retained. The subsequent
15-test source-identity/accounting/provenance replay passed. Historical remote
failures are not relabeled successful by these new-source observations.

### Required final state: HIA only, then retire legacy

The requested final distribution must contain the full native HIA compiler,
runtime, standard library, modules/build/install/CLI, worker/persistence and
optimization/proof authorities, with the old production stack removed. Optional
native backends and more generated HIA files are not that final state.
Before removing a still-required authority, its complete HIA replacement must
pass conformance/negative controls, the default path must switch without a
legacy fallback, full source-only and changed-source bootstraps must pass, fresh
whole-repository and applicable platform/resource regressions must pass, and
clean-machine installation plus real-project builds must execute without the
legacy toolchain. Current gates are OPEN; no old authority is deleted here.
Git history and non-shipped evidence retain recovery and audit custody.


### Retained cold timeout and fixed-width native word I/O

The first combined-source4660b8b cold attempt timed out at180.193seconds under
the unchanged180-second owner deadline. Native child ownership cleanup completed;
only6/11outer observations passed, and that attempt remains FAIL. Completed
phase receipts showed names/whole-compiler recompile work remaining at cutoff.
The candidate now expresses its fixed eight-byte workspace word reads/writes
as eight ordered HIA byte operations, eliminating loop bookkeeping without
changing endianness, per-byte bounds traps, prior-write visibility or access
order. No unaligned host word dereference or foreign load/store primitive was
introduced. Independent VM controls,320real-nativeunaligned/single-bit reads and
realSIGILLshort writes0..7plus a short-read unchanged-output control passed.
The compiler now has118functions/1294blocks/7352operations/414969sourcebytes,
within all unchanged caps. Its new bytes require fresh qualification; the old
4351-check receipts are not reused as new-source passes.
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


## Combined streaming and compiler word-I/O exact qualification

Exact clean implementation `bd3e9c2a9e61e7b6a540fee1c26d54d03003c313`
passes the complete sequential continuation:102 source tests, cold11/11 and
4,351 native compiler checks in150.393793910seconds under180;language1,242/1,242
plus10assertions;47native word-I/O/SHA/JSON/frontend tests;83actual installed
consumer tests and83default tests;55selected incremental tests;15exact-source/
accounting/provenance controls. Fresh completed B3 builds JSON decode,
canonicalization and streaming SHA manifests. Every stage leaves source clean.
The earlier180.193-second4660timeout remains FAIL and is separately hashed.
The current complete source manifests are not substituted with old compiler
images or prior test results. The full-repository run is separate and unresolved.
No default activation, live deployment, release-lock promotion or legacy-source
retirement occurs here. Final state remains HIA only after actual full closure.
The unused raw outputs of the ended failed cold run were losslessly compressed
with individual byte-for-byte roundtrip checks and a hash/restore manifest;
source, native images, receipts and the failure result remain retained.

## Native standalone JSON Core CLI continuation

The HIA ELF packer now emits a syscall-only executable containing the HIA JSON
Core representation frontend and the actual HIA semantic compiler. The executable
consumes JSON stdin and produces flat code or explicitly built ELF-object output
without a runtime Python driver, payload parser, interpreter, libc or external
linker. Private mmap state accommodates existing JSON arena/key limits, and the
reused compiler workspace is cleared. The production command surface and trusted
build driver are still host-owned; no old authority is retired.

Development conformance passes9tests including actual syscall tracing, byte-exact
HIA packaging, real generated-program execution, original/modified compiler
fixed points and resource/refusal/descriptor controls. The first modified-source
fixed-point assertion failed because it compared the pre-convergence first
generation; the corrected test requires later generations to agree. That failed
attempt is retained. The first v13identity test also retained a four-byte JSON
accounting discrepancy and a stale projection assertion; exact controls were
corrected, not bypassed, and15source/provenance/budget tests now pass.

Four reviewed CLI inputs extend the exact identity to373paths, retaining all
219actual package modules and every historical projection. Exactly536identity
bytes transfer from raw logs within the same aggregate envelope. These finite
development checks do not substitute for fresh committed qualification. See
`docs/HIA_CORE_JSON_CLI_NATIVE.md`; whole-stack rewrite/retirement remain OPEN.

The exact committedbc9aa4a continuation subsequently completed local acceptance:
104source/4351cold/9CLI/15sourcecontrols, actual B3-built flat/ELF artifacts and
installed/copied execution all pass with clean source. Actual first-read/write
EINTRretry and a real nonblocking partial-output failure are retained. Those
finite receipts do not establish the whole production command surface or close
full-repository/platform/native-only retirement gates.
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

## Integrated standalone JSON CLI and multiple exports

The development continuation combines the independently implemented bounded
multiple-export compiler with the standalone HIA JSON CLI, rather than
substituting one branch's qualification for the other's. The11CLI tests include
two actual JSON-to-object compilations and a typed ten-observation C executable
linking both objects, with intentionally identical private helper spellings.
The combined development suites also pass33component checks and15exact-source
identity/accounting controls. Fresh committed source/cold/language acceptance
for this combination is still required; no such result is claimed here.

The exact identity is v15 with378explicit paths and all219package modules.
The five export implementation/qualifier/conformance paths extend the373-path
v13identity by655encoded bytes, transferred from raw logs to metadata within
the unchanged one-MiB evidence envelope. v14was independently used on another
source fork and is not relabelled here. The historical365-path SHA-only v12
projection below is from the export fork; the current SHA-stream v12projection
remains369paths. Neither historical receipt is promoted to this combined source.

The actual compiler stays within its existing1MiB source/image/workspace and
180-second cold limits. It does not implement general module graph resolution
or a linker, production tasks/I/O, the complete library/CLI/build/install/release
chain, Agent/store or optimizer/proof authorities. Existing production sources
are still needed and have not been deleted.


The5fb6357combined continuation subsequently completed clean local qualification:
107source checks,11cold checks with5047native observations,1242language checks
plus10inventory assertions,69component tests,15source controls and15actual
installed/copied CLI observations. Two native-produced ELF objects link and
execute in one typed C caller; the external C/linker authority remains explicit.
Ended raw cold/language evidence is losslessly archived and verified against
every original member; temporary originals are also retained. Full-repository
regression and fresh remote/platform gates are still separate and unresolved.
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


## Combined CLI / native observer development continuation

The candidate integrates the HIA-emitted byte-ABI observer into the already
qualified standalone JSON CLI / scalar-export source. Ordinary phase calls exec
a fresh content-bound HIA-produced static ELF; no Python child runtime remains
on that path. Seed/B1..B3/M1..M3 controls, shared object loading, custom preimages
and prior writes after traps retain the separate independent loader. Host
supervision, source authoring, OS boundaries and the general production runtime
remain explicit; this is not a security sandbox or whole-stack retirement.

Development checks pass36CLI/observer/keyword/export/word-I/O tests plus15exact
source identity/accounting tests. The real native JSON CLI still generates both
export objects for the typed C caller. These are development observations, not
clean-source acceptance of the combined candidate; fresh committed cold,
language, source and installed gates remain required.

The v16closed identity explicitly registers all five observer source/reference/
conformance files and its cold-exported protocol document:384paths with an822byte
transfer within the same aggregate evidence envelope. Every historical path
commitment and execution limit is retained. The compiler now occupies123functions,
1454blocks,7830operations and451924source bytes, still inside the same declared
128/1536/8192 and1MiB ceilings. No compiler witness or owner deadline was removed.

The generic cold unittest now includes the actual process-owner receipt, bounded
raw stdout/stderr tails and observed phase counts in its assertion failure,
before temporary cleanup. This does not make a late/nonzero/missing result pass.
Prior4c0andbf336remote failures remain failures. The older d6e94whole-repository
result includes one cold failure AND seven errors (six exact-source closure
errors and one native-class setup error); it was not a one-failure-only pass.


A subsequent12-test standalone CLI development suite also executes actual
CLI-produced flat code through the newly built HIA observer, forbids legacy
child fallback and observes the syscall-only runtime. It validates the complete
returned source/output/workspace frame. The first test expected an untouched
workspace fill, but the reviewed bytesum program explicitly stores into both
mutable buffers; the corrected independent expectation checks both bytes.
The failed attempt remains evidence, not a product bug silently relabelled.
## Shared-output observer continuation: exact subject 4d490d8

The previous observer subject, published as `a19b612`, has now completed real
remote workflow [42761679281](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42761679281)
with all four jobs (source, cold, native and language) successful. Its cold
artifact contains 11/11 isolation checks and 5,049/5,049 native checks, taking
153.292 seconds under the unchanged 180-second limit. The compiler generation
hashes match the locally observed generations. The older bf3360f timeout is
still a failure; this success does not qualify subsequent source changes.

Exact executable subject `4d490d821be7b12267ee43b1791932d40e660355` extends the
HIA-emitted ELF observer to actual size-sealed shared output mappings. Custom
preimages and post-trap output no longer require the legacy phase loader. True
kernel SIGILL retains previously written bytes, independently read from the
parent-owned memfd after child termination. Normal-return stdout must agree
with those actual bytes. Extent sealing and prelaunch ENOSPC descriptor cleanup
are exercised. Every flat invocation still execs fresh; original generation
controls and seed/shared ELF still use the independent stdlib loader.

Local exact-source evidence:

- Source-only cold export: 11/11 checks and 5,049/5,049 native checks PASS in
  113.306 seconds (113.846 seconds outer wall), retaining 180+3-second bounds.
  The origin Git tree was dirty when this source-only cold export was created.
  After freezing the implementation, all 314 export payloads were compared
  byte-for-byte with the committed source. This is explicitly **not** labelled
  Git-clean-before-cold and was not reexecuted just for Git metadata.
- The remaining fixed-commit pipeline started and ended Git-clean: actual source
  workflow 103 tests, language 1,242 checks plus 10 assertions, native component
  suite 61 tests and shared closure 15 tests all PASS. The cold binding was
  independently rechecked in that pipeline.
- No compiler semantics, physical capacity, qualification witness, timeout,
  worker count or OS resource limit was relaxed.

Public `native-shared-byte-abi-observer-summary.json` and
`implementation-boundary-native-shared-observer-delta.json` bind this exact
subject; evidence-only metadata preserves all declared source bytes. The new
subject requires its own remote run. The ISA adapter is still literally
instruction-authored. Parent supervision, independent oracles, B0, linking,
release, production/runtime and default retirement remain open. Static audit
still records 218 package Python files and 423 tool Python files, with **3 partial
/ 5 open** components. Neither full-repository acceptance nor whole-stack HIA
closure is claimed.

## Unified native component qualification: exact subject 4f95ee9

The standalone JSON Core CLI/export compiler, incremental SHA library, native
source lexer with arbitrary-size bounded integer magnitudes, exact keyword
buckets and shared-output native observer are now integrated in one source
subject: `4f95ee91fd3aac0513135e22512f310ed806267d`. The combined source is
qualified afresh; individual fork receipts are not treated as combined evidence.

Completed local pipeline, Git-clean before and after every step:

- Actual recovery/regeneration workflow:108tests PASS.
- Source-only cold replay:11/11 checks and5,049/5,049 native checks PASS in
  101.204seconds nested, retaining the180-second gate and separate3-second
  cleanup. All328 exported payloads match the committed source bytes.
- Language:1,242checks plus10assertions PASS; combined native components:96tests
  PASS; exact shared-source closure:15tests PASS.
- Actual B3 builds decoder/canonicalizer/SHA/Core frontend/source lexer and both
  flat/ELF standalone JSON CLI profiles. Selected/default existing consumers:
  83tests each PASS; selected incremental policy:55PASS. Selected/default real
  parser and module callers:63tests each PASS.
- Actual installed CLI outputs execute through fresh HIA-emitted native observer
  children without the legacy fallback, with syscall traces retained. Two
  independently compiled export objects still link to a real typed C caller,
  including16mixed scalar arguments and independent VM comparison. C/linking
  remain explicitly foreign.

The combined v17 source identity contains389explicit paths and all220actual
root compiler modules. Both the separate370-path lexer fork and384-path observer
fork, plus every older projection, remain exact. The new661metadata bytes are
offset by661fewer raw-log bytes; aggregate evidence stays1048576bytes and all
other physical capacities/deadlines/worker counts remain unchanged.

Initial combined subject4a44a37 passed source108 and cold5049, but review found
the CLI execution fixture still expected the old HIAOBR01 response marker. After
the in-flight cold owner completed and confirmed cleanup, remaining orchestration
was cancelled, not labelled an accepted pipeline. The fixture was corrected to
the actual HIAOBR02 wire protocol and this fresh complete pipeline reran. An
intermediate launcher incorrectly reused an existing source-CI output path and
failed before test execution; that harness failure is also retained. Neither
failure was hidden by reusing a receipt or deleting tests.

Separately, shared-observer remote run
[42764255774](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42764255774)
onb4b1e4c failed cold qualification at unchanged180seconds:28/38phases completed,
zero phase exceptions, owned cleanup complete. Its complete artifact and job
logs are retained. The prior a19b612 remote success and this combined local PASS
do not override that failure or qualify a new remote source. Combined-source
remote CI and full-repository regression require their own fresh outcomes.

Reviewable `integrated-native-stack-summary.json` and the lossless
`implementation-boundary-integrated-stack-delta.json` bind this exact subject.
Static inventory:220package Python files/76,872lines and428tool Python
files/134,501lines. Tool counts include build/authoring/qualification machinery,
not just production runtime. The ledger remains**3partial/5open**: literal ISA
authoring, parent supervision/oracles, B0, host object construction, AST and type
checking, module/runtime authorities and build/link/release still need work.
No production/default switch, main merge, full-language/all-input equivalence,
full-repository PASS or whole-stack HIA closure is claimed.
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


## Combined CLI / native observer clean acceptance: exact subject 38ea1b2

The committed executable subject is `38ea1b2f580a0c62ba5373c5e8729c14158109f3`.
Clean local acceptance completed in407.223seconds: actual source workflow107tests;
source-only cold11/11isolation/ownership checks and5049/5049native checks across
all38phases in119.043seconds; language1242checks plus10assertions; combined
components78tests; exact shared closure15tests. The actual B3 builds both flat
and ELF standalone JSON CLIs. Sixteen installed/copied execution observations
include the typed C export caller and actual CLI-produced code executed in the
fresh HIA observer, with legacy child fallback forbidden and syscall-only
execution independently traced. All declared ceilings and deadlines remain.

The public `json-cli-observer-native-summary.json` binds this exact subject,
all323cold-input hashes, runner hashes, installed observations and the verified
lossless raw-evidence archive. Its matching static-audit delta reconstructs the
entire inventory byte-for-byte. A later auditor-only continuation explicitly
classifies both `.S` and `.s` references as assembly; its independent inventory
fixture passes. That static commit is identified separately from the executable
qualification, and every323cold-input hash is unchanged. The observer assembly
reference remains an explicit foreign-authoring boundary, not a hidden HIA claim.

The prior PR842C8EB remote cold failure is preserved: run42762528831,
job129653296438, actual owner `QUALIFICATION_TIMEOUT` at the unchanged180second
qualification deadline, return-9,34/38completed phases and confirmed cleanup.
Zero reported exceptions in completed phases do not qualify unfinished phases.
The119second local pass does not reclassify that remote failure or guarantee
future remote timing. Fresh current-source full-repository and remote gates
remain required; historical/adjacent-source passes do not substitute.

Static scope still contains219production-package Python files /76738lines and
426host-tool Python files /133911lines, plus explicitly inventoried non-Python
support. Tools are not all production runtime. The component ledger remains
**3 partial /5 open**. Full language, module/linker/runtime/build/install/CLI,
platform and clean-machine real-project closure remain **OPEN**. Defaults,
production activation and old-stack removal are unchanged. No required legacy
source has been deleted; retirement follows complete qualified replacement.


## Explicit JSON executable compiler chain: exact subject 289b951

The executable subject `289b9518c7cf87366d3e0c1a6b3b77b26ec8e0a6` adds an
operator-selected exec profile to the standalone HIA JSON Core filter and native
representation driver. Only explicit `selfhost_exec` without exports is admitted
in that profile; flat remains the default. Native semantic/resource validation
still checks the entry ABI and every private body. Packer references for all
three profiles and exec representation/echo VM references precede B0.

The actual JSON filter emits original and genuinely changed standalone compiler
ELFs. Those then compile assembly through real kernel exec, not a Python image
loader: E1=E2=E3; changed M1 differs from M2, M2=M3, and the changed fixed point
is distinct from original. Raw successor outputs and original/changed strace
observations are retained. Only execve/mmap/read/write/exit occur in those child
executables. An unrelated echo program agrees with the independent Core VM.
This is not full JSON-to-JSON self-hosting, file/module/build orchestration,
native linker replacement, production CLI closure or a security sandbox.

Clean exact-source gates: actual source workflow108tests; cold11/11 plus
5049/5049native checks/all38phases in120.213seconds; language1242checks plus10
assertions; combined components81tests; all three completed-B3 filter builds;
26installed/copy/filter observations and4raw native self-compilation successor
observations; shared closure15tests. No compiler/source/module/process/deadline
or aggregate evidence budget is enlarged. Source identity remains v16/384paths.
The first external installed harness omitted a case.sample fixture field after
the product suite had passed. Its invocation remains FAIL with all raw evidence;
a separate corrected driver supplies the fixture and completes installed/closure/
audit gates on the IDENTICAL committed source. Prior passed source/cold/language/
component/build gates are explicitly reused, not called re-executions. The
completion-only clock is14.160seconds; individual original clocks are retained.

Public `json-exec-cli-native-summary.json` and its matching lossless inventory
delta bind that source,323cold-input hashes, all runner hashes and raw archive
SHA256 `073ad444757b4b9b6e0c429c36b2d6fd40bf8ec015d5b63ecb51ff0bd7d4e562`.
Every archive member was compared with retained originals.

Current parent bc6095f remote run42765698026 remains FAIL: actual cold owner
QUALIFICATION_TIMEOUT180s,return-9,26/38phases completed,0reported exceptions in
completed phases,cleanup confirmed. Artifact13740096090 is retained in full:
37556154bytes/SHA256c382863b6730491294a2eaeffae135e2c187fbf8415c80fa44460cb88f9bcbf5.
This supersedes no failure and does not qualify unfinished phases. Prior C8EB,
4c0,bf336 and whole-repository failures stay retained. The older fixed bd3e9c2
full repository run completed7734tests with1native-child signal-vs-timeout
failure,0errors and0skips, unchanged clean source; its0.2s observation does not
establish whether the timeout preceded filter installation. No timeout/filter/
assertion was changed to erase it. Current full/remote gates remain separate.

Static inventory:219production-package Python files/76738lines plus426host-tool
Python files/133920lines and separate non-Python support. Ledger remains
**3 partial /5 open**. General frontend/Core/composites/module/linker/runtime,
build/install/release,Agent/store,optimizer/proof,cross-platform and clean-machine
real-project closure remain OPEN. No production/default switch or legacy
retirement has occurred. Old required implementation cannot be removed yet.


## Source lexer/integer plus executable JSON CLI composition candidate

Development checkpoint, not completed clean-source acceptance: the bounded v2
source lexer and integer magnitude application from c57fb17 is composed with
841fce7 native JSON flat/ELF/executable CLI and native observer. An additional
real composition test checks standalone JSON CLI output executed by the fresh
HIA-native observer. Development16tests and shared-source15tests passed. Fresh
source/cold/language/native/build/installed/default/full gates remain required.
No prior acceptance is relabeled as combined proof.

The explicit shared-source identity advances to v17/389paths, adding exactly
five lexer application inputs and preserving the v16/384path projection and all
older commitments. The aggregate evidence ceiling stays1048576bytes; identity
maximal164719bytes,metadata244595/raw799885/display4096. All compiler/module/
process/time limits remain unchanged. A new API bridge makes220production
Python modules; general parser, float object conversion, AST/types/module/
linker/runtime/build/install/Agent/store/proof remain foreign/open. No default
switch, release lock, production activation or old-code retirement occurs.


### Exact combined implementation f063abb: local qualification complete

Clean `f063abb10a3799c67b141ccedc483977835ead18` passes all20fresh qualification
steps in490.780seconds: actual source workflow109tests; cold11/11 plus5049/5049
native checks/all38phases in117.376seconds under unchanged180+3; language1242
checks plus10assertions;97combined native component tests;15shared-source tests;
actualB3JSON/sha/lexer/frontend builds;83selected and83default existing callers;
55incremental tests;63selected and63default real parser/module tests; all three
flat/ELF/exec CLI builds;26installed observations and4actual raw executable
compiler generation observations. The new standaloneJSON->lexer->nativeobserver
composition is freshly executed in those97tests, not inferred from parents.
All328cold inputs are byte-identical between qualified implementation and this
metadata continuation. Host object bridging, float conversion, source authors,
build drivers and the remaining open authorities are not HIA replacements.

Public `source-lexer-cli-composition-native-summary.json` binds complete receipts
and the lossless static inventory delta. Ended raw evidence archive20630445bytes,
SHA256f7e7ddd28a36d9973b971ff068e5ca91a166548a2556d6660d51ea834471b4c8:
every archive member compared with retained originals.220package Python modules/
76872lines plus428host tools/134435lines remain; ledger3partial/5open. No default,
production activation, release lock or old implementation removal occurs.

Parent841fce7 remote run42768119487 cold job129671739792 failed180s with actual
ownerQUALIFICATION_TIMEOUT,return-9,26/38completed phases,0completed-phase
exceptions and confirmedcleanup. Full37728107byteZIPartifact13741053010 retained,
SHA2563942a9da5c0e7afab6f3705ab3c66d9a766f7909939c908369d83b565f4eec4b.
Unfinished phases are not passes; local acceptance never supersedes that remote
failure. Source job passed; remaining remote jobs/full-current-source regression
are separate. Older exact4c0fb93 whole-repository run finished7743tests/741modules
with0failures/errors/skips and unchanged source, but does not qualify newer
commits. Older bd3full failure and previous remote failures remain retained.
Whole-stack rewrite and old-production retirement remain OPEN.


## Source float plus executable compiler composition development

Next candidate imports accepted6933f8c native exact decimal-rational to binary64
conversion into the2d12212 standalone JSON/lexer/observer lineage. Source lexer
v3 adds command2 with6272private workspace bytes and8output bytes; integer/
token/compiler input and resource limits remain unchanged. Host numeric
literal conversion is removed from the selected bridge; Python still constructs
objects from native bytes. The actual standalone JSON CLI->lexer->fresh HIA
observer testcase is retained and includes floating literals. All older lexical/
integer controls remain. Parent acceptance does not qualify the combined source;
new development and exact clean-source gates are required. No default or old
production implementation is removed. The unbound static auditor now explicitly
accounts for the high-level source lexer/API and its remaining object/parser
boundaries instead of silently omitting that application.

Development result: all19source/native lexer tests (including actual standalone
JSON/nativeobserver composition with a floating literal) and the unbound
assembly-inventory boundary fixture passed20tests/17.664seconds. The earlier
34test development run also passed19lexer plus15unchanged shared-source tests.
These are development observations, not final exact-source/remote/full acceptance.


### Exact float composition5253985 local qualification complete

Clean5253985012daf508906244862d6579560751e4e2 passed all20fresh steps in
518.886seconds: actualsource109tests, cold11/11+5049/5049/all38phases123.186seconds
underunchanged180+3, language1242+10, combinednative100, sharedclosure15, actual
B3JSON/sha/frontend/lexerbuilds,83selected+83defaultconsumers,55incremental,
63selected+63defaultparser/modules, flat/ELF/execCLIbuilds,26installedobservations
plus4raworiginal/changedexecutablecompiler-generationobservations.
No parent execution acceptance substitutes for those fresh combined gates.

All328cold input hashes remain unchanged in the metadata continuation. The raw
20862924byte archive has SHA256daf85f157705d7b505dde1181f551654c14d0f18143071e6318cb42d42d4f946;
every member compared with retained originals. Publicsource-float composition
summary and lossless inventory delta retain subject/provenance/receipts/failures.
The current lexer source4b1a5f06eb3f7b10ec4a8d3e5b7115f7c94149f8cd5029e202f1d482642572ed
and image587b5b21bb86df56b66cefe99659194453443b71e1cb5fa09c790c6b87e8aacf
also exactly match the earlier independent midpoint observation. That historical
observation is explicitly NOT re-executed or counted as fresh tests here.

Staticinventory220packagePython/76887lines plus428hosttools/134701lines, ledger
3partial/5open. The unboundauditor now explicitly records high-level source
lexing/numeric conversion and their remaining Python object/parser boundaries.
Generalparser/Core/composites/module/linker/runtime/installation/services/proof,
full-current-source regression, remote and clean-machine gates remain OPEN.
Parent2d12212 remote42769896908sourcePASS/coldRUNNING atcapture; parent841timeout
and older failures remain retained. No default/release/production switch or old
requiredimplementation removal. This is not whole-stack closure.


## Native compiler scratch/header throughput development

The actual baseline B3 compiler was sampled while performing 32 native
self-compilations, without changing profiler kernel settings or qualification
limits. Of 17455 in-image 1ms samples, generic get/put accounted for25.25%/19.46%,
next_token10.78%, keyword7.01%. The external C diagnostic is not a HIA production
implementation or a correctness proof. A prior numeric-identifier fast rejection
experiment showed no speedup and was rejected, with its patch/results retained.

This candidate uses the existing HIA buffer.fill_range primitive for precisely
those scratch byte ranges previously zeroed by loops. The two per-SSA strided
8byte fields still clear only their original bytes, never the intervening holes.
Compiler-private header fields32,48,64,72,232 use byte accesses: quote0..1,
phase0..2, function count0..128, ordinal0..127, output profile0..2 respectively.
Their complete256byte header is cleared before every semantic pass, so all
higher bytes stay zero. Function count is checked before incrementing; the
128-function ceiling and every other physical limit are unchanged. Generic
get/put retain their exact word/partial-write/trap ABI. Input values, output
position, error code, counters and table extents are not narrowed.

Development-only native B1=B2 was observed. Four repetitions interleaved against
the accepted parent image on this same, non-isolated host show parent/candidate
wall ratios1.123(current compiler),1.143(parent compiler),1.111(source lexer).
Every produced image is byte-identical across old/new compilers. A separate
foreign diagnostic compared full1MiB output and full1MiB scratch, not just
selected header words, for48valid/invalid inputs with bothzero and0xA5 scratch
preimages:96comparisons all agree exactly, including return values. These are
finite development observations, not all-input proof, exact-source acceptance,
or evidence that remote180s cold qualification now passes. Fresh clean-source,
cold/language/components/build/installed/full and remote gates remain required.
No deadline/cap/evidence ceiling, default, live installation or release lock is
changed, and no required legacy implementation is removed.

Development tests19/19 passed35.407seconds: live scanner/keyword Core VM,
unaligned word reads/all64bits and native partial-store traps, complete scalar
exports, two actual linked HIA objects, refusal/no-output and poisoned scratch.
The source/contract inventories were regenerated. This remains a development
checkpoint until the following fresh exact-commit gates complete.

### Exact scratch/header implementation accc4bd accepted locally

Cleanaccc4bd6de0fe37c572780e1ed904a7f219c0e8c passed all20fresh qualification
steps in489.136seconds: actualsource110tests; cold11/11plus5049/5049native
checks/all38phases in110.888seconds underunchanged180+3; language1242checks
plus10assertions;100nativecomponent tests;15shared-source tests; actualB3JSON/
sha/frontend/lexer andall3CLIprofilebuilds;83selectedplus83defaultcallers;
55incremental;63selectedplus63defaultparser/module tests;26installed observations
plus4rawnative executable compiler-successor observations. B1=B2=B3 is662882bytes,
SHA256a45a2a8c29ff320f5307bba00a4368facd15feb0aa300bca63af3457d5b30c0e.
The changed-source chain is separately distinct and reaches its own fixed point.
The compiler source457451bytes remains within all unchanged physical ceilings.
This is fresh acceptance, not inherited float-composition test counts.

Final raw archive21734562bytes, SHA25649b3afa9b95ebcfad471f790289f83694671178c70671182ab41309378c0c1b2:
all56506members compared with retained originals. The first nonfinal archive
included its own still-open journal, so the final archive excludes live archive/
queued-full journals; both captures and the retention note remain. An external
publication helper initially looked for manifest.json instead of the actual
CLIbuild.json; it failed before publishing. The corrected receipt reader uses
the same unchanged accepted source/artifacts; no test rerun or outcome relabeling.
Public compiler-header-throughput summary and lossless inventory delta bind the
fresh receipts, full source hashes, raw development observations and failures.

Parent1afa unified remote42771662610/job129680646771 isFAIL595tests/1failure:
actualcold180s/-9/34of38phases/0completed-phaseexceptions/cleanupconfirmed.
Full185742byteZIP13742861147 retained with server-matchingSHA256
b01e078c2484584d116ff098d1f9d4d06da0127a4203b34de80a1ffbc610192c.
Older2d12212 P2 cold42769896908/job129679068592 also endedFAIL180s/-9/26of38,
cleanupconfirmed; same-run source/native/language jobs separatelyPASS. Full
39675844byteZIP13741394214 retained, SHA2566aeaaf213fe4f07369655627d6a87260979a58f8d98ba6917eb094a835347930.
Neither remote failure is superseded by this local pass or by development timing.
Older38eaobserver whole-repository run endedFAIL7766tests/1failure/1error/0skips,
unchanged clean source: one temporary-project-marker error and one0.2s whole-child
timeout versus expectedSIGSYS. Exact timeout stage remains unproved; no filter,
timeout, assertion or legacy identity projection was weakened. Older exports/
stream/full/remote failures remain retained. Current fullsuite is frozenaccc and
QUEUED after the525float suite, additionally requiring the8GiB free-space reserve;
no current full tests have started. Remote/current full/clean-machine gates OPEN.

Inventory still220package Python modules/76887lines plus428hosttools/134701lines,
ledger3partial/5open. No default/live/release/main switch, old-stack deletion,
fullfrontend/module/link/runtime/build/service/proof or native-only closure claim.


## Native static ELF linker/filter continuation (candidate; full closure OPEN)

The new checked-in HIA ELF linker performs real object table/name resolution,
RX/RW/BSS layout and admitted RELA fixups, then writes an ET_EXEC. A separate HIA
filter packer emits the syscall-only linker CLI. No Python or external linker is
needed when that CLI links objects. The Python build/custody driver remains;
this is not a default production linker or complete module/runtime replacement.
See HIA_NATIVE_ELF_LINKER.md for the explicit application profile and exclusions.

Development controls include independent Core and foreign ld before native B0,
actual separately emitted HIA objects and typed C calls, weak/strong and absolute
relocations, data/BSS, full output equality, unchanged-output refusals, real
syscall traces, injected EINTR and an actual short-write pipe. Authoring Mod and
17-block-parameter failures remain in external logs: app-specific lowering and
helper extraction fixed these without changing the compiler's original ceilings.
The initial GNU CET note refusal remains recorded; the candidate implements the
understood FEATURE_1_AND intersection, not silent dropping of needed properties.
Clean exact-source combined qualification is recorded separately when completed.

The explicit shared closure now has396 paths with commitment
4997ea6d666023fd9888ede790a63fb3c978d40e32b8d4ba827b9f27cb9a62c4;
the original389-path v17 projection and every older projection remain pinned.
Seven actual new inputs add929 maximum identity serialization bytes, transferred
from raw-log allocation within the SAME1MiB aggregate envelope. Compiler and
execution/test deadlines, capacities and witnesses are unchanged.

Older289 exec fullsuite ended PASS7770tests/743modules,0failures/errors/skips,
clean source unchanged and complete inventory. This is OLD-source evidence only.
Olderf063 lexer fullsuite ended FAIL7757tests,2failures/3errors,0skips with
incomplete inventory; all five report ENOSPC while retaining clean source.
Original reports/logs and condensed final observations remain external evidence.
No rerun or environment repair turns that failure into a pass. The frozen525
float fullsuite started after that terminal, and the frozenaccc throughput suite
remains queued. Current full/remote/platform/clean-machine gates remain OPEN.

The package still has220 Python modules. No old production implementation,
default/live/release/main route or general frontend/runtime/build/service/proof
closure was removed or promoted by this native-linker candidate.


First exact native-linker candidate46dcf93 failed the clean111-test source gate:
the existing release-freeze assertion detected all seven new inputs missing from
BOOTSTRAP_FILES. The original failure and clean source report are retained;
no cold or later joint steps were run by that failed driver. The correction adds
those exact inputs to the frozen release closure, preserving the assertion.
A fresh complete pipeline, not a relabeled partial rerun, is required afterward.


## Source type parser continuation — explicit native grammar, not whole closure

The standalone HIA application has a two-pass count/validate then emit arena ABI.
It uses8512bytes of private workspace,128frames of64bytes starting at320, and
80-byte nodes after a64-byte header. Its input is a type prefix and lookahead,
not a whole compilation unit. Input is bounded to8MiB, nodes to1Mi; the existing
parser's96nesting budget is preserved using its remaining depth, never raised.
Arrays use the bundled real HIA lexer magnitude decoder, not a Python literal
parser. Generic `>>` and `>=` split/cursor positions preserve existing callers.

Explicit selection uses `HEPTA_HIA_SOURCE_TYPES_MANIFEST=/.../manifest.json`.
`python -B -m tools.build_hia_source_types --compiler <completed-B3>
--cold-report <matching-cold-report> --output <new-private-directory>` builds
the image and its `source-lexer/manifest.json` child. Both are trusted local
artifacts pinned to source/image identities. Missing or drifting selection
fails closed; no automatic fallback to the old type grammar is admitted.

Development first exposed an unsupported non-tail recursive authoring prototype;
its native refusal and raw source remain in retained evidence. The implementation
was rewritten with explicit frames without changing compiler recursion support
or any qualification deadline. Two test-fixture syntax errors (missing effects,
then wrong effects delimiters) were corrected; both failed logs are retained.
The final development run passed27tests (11new application controls,
15historical closure controls and1whole-tree audit control). A prior corrected
25-test run is retained separately, before the explicit128frame boundary case. Independent VM byte witnesses precede a fresh native seed;
real existing source corpus, diagnostics, partial operators,4096digit arrays,
remaining caller depth, concurrent actual parser calls with old type grammar and
old lexer patched to fail, and poisoned-workspace transactional refusals are
covered. These are finite observations, not an all-input refinement proof.

The reviewed shared source identity advances explicitly tov18:394paths,
commitment`ba4fcb100a6f27c75e1eb195a32c5c61096b23e02d8de2c2a8c17888574a0379`,
including all221actual package modules. All389v17 paths and both older lexer
and observer fork projections remain independently pinned. Identity bytes grow
by661to165380, transferred exactly from raw logs: metadata245256+raw799224
+display4096=1048576, unchanged. No evidence gate is weakened.

The static boundary stays3partial/5open. Python still owns authoring, image
loading, object construction and arena/cursor validation, most frontend grammar
and type checking, modules/builds, execution/runtime, tools and release. No main
merge, production/default switch or legacy retirement is authorized by these
local component observations alone.

The first clean qualification at4f78442ran109source tests and failed one release
closure control: four new bootstrap files were missing from the explicit release
freeze inventory. No cold/native downstream gates ran in that failed pipeline.
The four files are now explicitly included, without relaxing the exact-inventory
assertion or modifying a release lock. The failed report and complete log remain
retained; a corrected commit requires a completely fresh qualification.

### Completed exact source-type candidate qualification

Clean executable subject `fc5540f425663a71e6577c5075dfb5bbceead669` passed the
entire fresh component pipeline in502.651seconds:109original source-recovery/
regeneration controls, cold11/11isolation and5049/5049native checks in114.176s
under180+3s,1242language checks+10assertions,107combined component tests and
15exact shared-identity controls. Real currentB3built the type parser and its
actual HIA lexer, plus all prior JSON/SHA/Core frontend and standalone CLI
artifacts. Selected/default existing consumers83each,incremental55,
lexer-selected/default parser/modules63each,and actual type-selected/default
frontend/parser/module/owned-generic callers98each passed. Real installed CLI
composition16observations and syscall traces also passed, not just in-memory
fixtures. No old fallback was used for the explicitly selected type grammar.

This exact snapshot has221package Python files/77091lines/4173435bytes and
430host-tool Python files/134944lines/7722090bytes (651combined Python files).
The explicit boundary stays3partial/5open, not a completion percentage. Exact
static records reconstruct losslessly from `implementation-boundary-v28.json`
plus `implementation-boundary-source-types-delta.json`; actual checks/builds
and retained failures are bound by `source-types-native-summary.json`.

Raw ended qualifier captures are archived in21071177bytes, SHA256
`0a7f78e7745c650890dfe177fa15e7ff4f5c673dd36aa537696d9e9940b470bd`.
All56049regular members (3374136311uncompressed bytes) were compared byte-for-
byte with the retained originals; external source-CI/unittest logs also remain
retained separately. The initial source-gate failure remains FAIL. New candidate
remote CI and current entire-repository qualification are still required; the
older PR845four-job success is not relabelled for this changed source.


### Retained first remote source-type run and scoped checkout correction

Remote run42772128006at295170dwas CANCELLED, not passed: GitHub's check annotation
explicitly reports the10minute source-job limit. Checkout consumed5m44s, then
recovery succeeded and assertions ran until cancellation. Cold/native/language
were skipped, not completed. Its complete source log, annotations and7392byte
ZIP (SHA256eaed84fe8c97e591e7a1db8aaf771b215b9d0ce50da430d3881be9b1a6a82ed0)
remain retained. There is no evidence of a failing source assertion in that
interrupted log, but incomplete tests are not a PASS.

Checkout is now scoped to the exact immutable candidate (depth1). The source
job explicitly restores only that candidate's complete ancestry with a single-
reference,no-tags unshallow fetch, asserts that it is no longer shallow and
that HEAD is unchanged, then runs every original bundle/tree/blob/ancestor
recovery assertion unchanged. Other native/cold/language jobs need the exact
HEAD tree rather than unrelated branch history; their source identity, cold
isolation and all tests remain unchanged. No10minute job limit,180second cold
limit, test inventory, compiler capability or process/evidence budget is raised.
Fresh scoped-checkout source verification and current remote execution are
required for this workflow-only correction; fc5540fcomponent evidence is not
relabelled as a new whole-toolchain run.

## Source expression grammar continuation (v32 candidate, NOT whole-stack closure)

The operator-selected `HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST` application now
implements the existing expression/prefix/argument grammar in executable HIA,
composing the actual type grammar and source scanner helpers. It covers all
binary precedences, unary operators, named calls, index/field postfixes, casts,
arrays, struct values, qualified paths and turbofish type lists. Explicit
128-byte frames preserve the existing caller's remaining combined 96-level
syntax budget; standalone admission is bounded at128 frames. This is not an
implementation of declaration/statement grammar, semantic checking or modules.

The128-byte arena supports parents allocated after left children; the foreign
bridge validates ownership/cycles/ranges then constructs objects iteratively.
A separate bitset records actual generic `>>`/`>=` splits without modifying
real binary operators, including error cursors and previously split initial
operator tokens. Workspace is25024fixed bytes plus ceil(input-bytes/8) trace
bytes, input8MiB and1Mnodes. Ordinary invalid/short-output calls leave output
untouched. A separately tagged diagnostic-only replay preserves completed
namespace observations on failure; it is rejected by the AST arena decoder.
HIA lexer token values supply integer/float objects; host grammar fallback is
not used. Host object construction, value bridging, manifests and authoring
remain explicit foreign dependencies.

Development controls execute four complete hand-specified arenas in the
independent Core VM before B0, then compare every byte with actual B1/B2-built
native code. Controls exercise all operator-pair precedences,300 composed
expressions, real complete source examples, exact errors/token cursors/spans,
qualified names after failures, nesting boundaries, long left chains,
concurrent actual parsers with reference lexer/expression/type helpers patched
to fail, poisoned output guards and malformed arenas. Latest development
application/shared-closure/static-inventory tests:28PASS. This is development
acceptance only: fresh clean-source cold/language/native/install, current-head
remote and full-repository gates remain required.

All failed development captures remain: initial namespace observations were
lost on errors (fixed with the explicitly separate HIA diagnostic replay),
string-error consumed bytes excluded the closing quote (fixed using the actual
scanner cursor), one corpus fixture used a nonrecursive glob, one invocation
named a nonexistent audit test module, and a new hand-written VM oracle omitted
two token columns. A later run also hit actual `/tmp` inode exhaustion; its
failures were retained and an independent private temporary root was selected,
without deleting existing evidence or changing compiler/execution budgets.

Shared identity v19 explicitly includes399paths/all222actual package modules,
commitment`1b2ca83b05da13e0e7f655ddbd41f3979ff6b95696a0037f7ad33f5f0ef5130f`.
It preserves exact v18/394, v17/389 and both prior fork projections. Additional
691metadata bytes transfer from raw capture:245947metadata +798533raw
+4096display =1048576unchanged. No previous phase/worker/deadline/compiler
limits are raised. Defaults/production/main/release locks remain unchanged;
whole-stack ledger stays3partial/5open, no legacy retirement authorized by this
component result.

### Retained first clean expression attempt and receipt robustness

Exact clean372446310c58b2d14b4858a8291980659c7fc92c passed the actual110
source assertions with no failures/skips. Its first cold attempt FAILED: the
owner receipt existed but was empty, and the parent raised JSONDecodeError;
there was no completed cold report or authoritative cleanup receipt. All
partial exports/logs remain retained and are not treated as accepted evidence.
A separate harmless transport probe observed EDQUOT while flushing a request
on the same `/dev/shm` usrquota filesystem despite globally free blocks.
Another harmless probe under a private `/run/user/1000` directory completed
normally with actual ECHILD cleanup. This does not retroactively prove cleanup
of the original failed owner.

The parent now handles empty/truncated/nonobject owner receipts as the explicit
`OWNER_RECEIPT_INVALID_HOLD`, retaining receipt byte count/hash and the observed
supervisor exit while leaving qualification returncode unset and cleanup
unconfirmed. No output or nested success is admitted. Eight real-process
lifecycle controls PASS, including five malformed transport byte variants from
real harmless replacement supervisors. The180-second qualification deadline,
separate3-second cleanup bound and every execution/physical cap remain fixed.
A completely fresh current-source qualification is required after this fix.

### Fresh corrected expression candidate qualification completed

Exact clean executable subject **cee375ef5fc0dca7c045444f8f20b7d72b15b158**
completed the entirely fresh pipeline in **499.161seconds**: source110PASS;
cold11/11 +5049/5049native checksPASS in104.000seconds (outer104.488),
unchanged180+separate3cleanup; language1242checks+10assertionsPASS;
combined native components119PASS; shared source controls15PASS. All actual
B3 application builds completed. Existing selected/default consumers83each,
selected incremental55, lexer-selected/default parser/modules63each, and
**type-only/expression-only/combined/default frontend callers98each** PASS.
Actual installed flat/ELF standalone CLI composition16observations PASS,
including typed C-linked exports, independent VM comparison and syscall traces.
A supplemental clean-subject owner lifecycle run8PASS2.258s; an earlier
supplementary invocation used the task parent instead of the project root and
failed import (log retained, not counted as accepted tests).

The actual HIA expression image is234927bytes, SHA256
`46cfe1e5a881ef07c092038b5d3e39856bbe341d0b631b17f4ca3dc91e55abc6`.
All56072regular raw archive members were compared byte-for-byte with retained
originals (3377930256uncompressed bytes). The lossless archive is21272108bytes,
SHA256`478594b61c24dccd6f4dd9e6ca7aaab776eeefffa0198014d59c06659d42cc8f`.
Raw originals remain retained; private runtime placement is recorded explicitly.
Public `source-expressions-native-summary.json` and its exact lossless static
inventory delta bind the executable source, counts, builds, failures and archive.
Snapshot remains222package Python/77483lines and432tool Python/135474lines,
654Python files; these are inventory counts, not completion percentages.

A fresh whole-repository run has started in a separate immutableCEE checkout
with real locked prerequisites; no result is yet available. Current-source
remote CI remains required. The evidence/CI-only follow-up adds the eight owner
lifecycle controls to the actual native job; it changes no cold-exported source
payload or implementation. Prior canceled, quota-failed and entire-repository
failed attempts remain failures; neither component passes nor old remote
receipts establish full-stack closure. Defaults/production/main/release locks
stay unchanged and the ledger is still3partial/5open.


## Native type/expression + v3 numeric lexer + static linker composition

Development composition joins the independently accepted native ELF linker and
source type/expression grammars. The selected source lexer remains v3: exact
decimal-rational binary64 rounding is not reverted to a host float parser. The
type/scanner authoring composition selects actual reachable scanner helpers;
unused decimal limb code is not accidentally exposed under the smaller type
workspace ABI. All lexical, numeric, type, expression and linker controls remain.
New joint expression controls include binary64 tie/subnormal/maximal values
with foreign decimal conversion and reference grammar explicitly disabled.

Shared identity v20 binds406paths, commitment
855761770d145406609a3b2daf764765305b101b0619c50315adee135846ae2a.
Both accepted branch projections remain exact: native linker396paths and
expression399paths, plus all prior type/lexer/observer/CLI identities.929bytes
of raw-log allowance transfer to identity metadata for linker paths, within the
unchanged1048576byte evidence envelope. No compiler input/output/workspace,
module, process, execution or time ceiling increases. Profile v33 binds the
combined source, not a claim that a larger language profile is implemented.

Fresh clean-source, original/modified cold fixed points, language/component,
selected/default callers, actual installed CLI/linker and full repository/remote
gates are required. Parent passes are not combined execution evidence. The
first development identity calculation omitted the canonical final newline;
existing strict identity tests rejected it and raw failures remain retained.
Its corrected literal uses the existing canonical commitment function, without
relaxing any projection or aggregate-budget assertion. No default/live/release
switch or deletion of still-required legacy production code occurs here.

Development verification on the combined worktree:52actual source/native tests
passed in51.892seconds (type, expression, v3numeric lexer and static ELF linker),
including no-foreign-grammar and no-host-decimal controls.15shared identity and
aggregate boundary tests passed separately. These are not clean-commit cold or
whole-repository results. The boundary inventory still counts222production
Python modules and435host Python tools, with3partial/5open components.


## HIA type grammar continuation (development source)

The operator-selected native type grammar now replaces real `Parser._type`
recognition inside its explicit token/byte profile: paths, generic type/lifetime
arguments, raw/ref/array/slice forms, exact depth/diagnostics/cursor and `>>`/`>=`
mutation. Independent VM observations precede B0; real B1/B2 fixed-point builds,
750 deterministic recursive/mutated type inputs, depth boundaries and 300 actual
source files pass development conformance. Both lexical modes are explicit;
selected tests disable the original Python type grammar, and dual-selected tests
also disable the original lexical recognizer. Clean final qualification remains
separate from these development results. See [profile](HIA_TYPE_PARSER_NATIVE.md).

Shared source closure v15 binds exactly 375 paths/220 top-level Python modules
and retains every earlier projection, including all 370 v14 paths. The extra
663 identity bytes transfer from logs to metadata inside the same aggregate
1 MiB evidence budget; compiler/runtime/process/call limits remain unchanged.
The entire source parser, semantics, modules, runtime and delivery are NOT closed.
Previous PR846 remote cold FAIL at 180 seconds/26 phases remains a failure;
local passes do not replace it. No main/default/release activation is performed.


## Whole-source grammar and native linker composition (development)

This integration retains the complete bounded token-driven source task machine
and its iterative type parser, alongside the existing v3 numeric lexer,
source-driven type/expression parsers, streaming SHA, standalone JSON compiler
and static ELF linker. All application selectors remain explicit. Selecting both
type profiles gives the token type parser precedence; out-of-token-profile input
can use the source type profile before the reference. The whole-program parser
has precedence for Program parsing within its explicit validated-token profile.

The whole-program profile is at most 4,096 tokens / 1 MiB packet and requires a
3,158,016-byte private workspace. Out-of-profile reference behavior remains and
Python token/AST materialization, semantic checking, modules/build, runtime,
Agent/persistence and proof authorities remain foreign. This is not default
activation, full-stack closure or authorization to delete required old code.
Both separately reviewed 406-path and 380-path parent projections and all older
projections remain exact inside the 416-path union. The additional 1,329 metadata
bytes are transferred from raw logs inside the same aggregate evidence envelope.
Fresh combined-source qualification is required; parent passes are not inherited.


## Native Agent scalar identity acceptance — Core/Agent scope

The explicit HIA scalar identity candidate is qualified on exact commit
`8ce57530583986db0fda64a926ccd3dff3261b8f`, with a fresh 18-stage run. The selected HIA app
checks canonical u64 decimal and lowercase SHA-256 grammar; it does not compute
a digest, authorize an operation or implement durable persistence. Reference
numeric/regex predicates are disabled in real selected store/worker controls.

The actual isolation gate found an eager foreign-comparison import via macro
advice. Its failed receipt remains FAIL. Ordinary discovery now avoids that
import; explicit native NDU still uses the original bounded process pump, with
unchanged cleanup/output/deadline semantics and import time charged to budget.
The same strict blocked-import/empty-PATH worker gate was rerun, not relaxed.

Exact source CI, original+modified cold bootstrap, language coverage, real B3
application build, selected/default Agent calls, process controls, installed
compatibility CLI and lossless evidence archival are recorded in
`../review-evidence/hia-whole-selfhost-20261109/agent-identity-native-summary.json`.

The wheel is still a Python-host development installation. In particular it
omits this native app's source resource; selected-native installed identity is
not qualified. JSON/schema/correlation/auth, edit orchestration, SQLite and
filesystem recovery, Core module/build/runtime and native-only release remain
OPEN. Scope change and this component pass do not close any whole obligation.
Default service/main/release locks and legacy implementations remain unchanged.


## Installed Agent scalar identity resource acceptance — historical component

Exact commit `e3e441dca3f1da5deaf655f4c63dbbc67c32cc84` passed a fresh 19-stage component
qualification. The twelve real Agent resources are now carried by actual source
distributions and wheels, bound into source/release/shared identities, and read
only from the explicit checkout or installed package root. No cwd/HOME/foreign
checkout fallback is used. Actual installed selected-native workers match source
identities; missing/tampered native assets, discovery-pin drift and complete data
root removal reject before persistent state creation. The real current B3 image
is copied into independent installed artifact custody.

See `../review-evidence/hia-whole-selfhost-20261109/agent-identity-installed-resources-summary.json`
for exact source/cold/native/default/selected/installed controls and retained
capacity-preflight failure. This branch still contains the historical high-level
language; the owner's superseding removal is being handled in a separate active
product tree. This is not that tree's qualification or a deliverable legacy
package. Useful installation fixes require integration and exact requalification
there. All nine Core/Agent whole obligations remain OPEN. Python build/worker,
JSON/schema/auth/correlation, editing, SQLite and recovery remain host owned.
No main/default service/release activation, native-only delivery or old production
retirement is authorized by this component receipt.
