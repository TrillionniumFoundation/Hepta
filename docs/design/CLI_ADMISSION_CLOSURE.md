# Composed loader to CLI: falsifiable integration closure plan

Baseline: draft #633, e9f65e2c0c53ccb38b6257ad7821314a200fa6c4, validated 658 controls on Python 3.11 and 3.12. This document proposes integration; it does not activate a production default or establish a hard sandbox. Earlier OWNED_LOADER_INTEGRATION.md describes a historical profile: the current composition enforces graph quotas and single-lex ownership, plus AST/append/copy/transform/map/shallow/Package admissions.

## First proposed slice

An explicitly selected experimental profile for `check --frontend-only` only. Keep every existing command/default unchanged. Refuse build/run/emit/header/patch/import-c and all other native/workspace/publication surfaces under this new profile until separately closed. A future explicit flag or command needs a reviewed versioned policy and response schema; no magic environment variable, monkeypatch, global context or production import from experiments.

Reject unsupported runtime/profile/command combinations before input I/O. Current Package runtime rejection occurs late at the fourth copy and is not itself an early CLI guard. Create the owner before any input-path resolution/read and pass raw argv source spelling to its load operation. Keep the owned handle alongside the ordinary Analysis.project graph through source decode, `pipeline.analyze(..., native=False, loaded_project=handle.project)`, and final `handle.unchanged()`. Never pass a wrapper as Analysis.project or call public graph.unchanged as the authority. The same owner/ledger covers final validation and any reload; terminal means no retry under a fresh owner within that request.

Even frontend-only analysis performs checking, code generation and hashing; only loader work is admitted by this profile. Do not call the complete CLI invocation bounded or preemptible. Report frontend_only, never native-qualified.

## Concrete current blockers and counterexamples

1. `pipeline.analyze_project` uses public load_project and public project.unchanged. A naive load substitution returns the graph but discards owner revalidation, silently bypassing the final-read ledger. Test: snapshot reader bytes/reads immediately after owner.load, run the existing pipeline wrapper, and show its final public revalidation leaves those counters unchanged; a handle revalidation consumes more.
2. `cli.main` resolves `args.source` before its analyze_project call. This loses the original lexical entry alias. Test: a symlink entry reaches the pipeline as its resolved target, unlike direct raw-entry Owner.load whose bindings include the lexical alias. Future path must retain alias and reject post-load retargeting.
3. Rejected is RuntimeError, intentionally outside metadata/unchanged catches. CLI catches HeptaError, OSError, ValueError, UnicodeError and SubprocessError, not Rejected. Test: injected refusal escapes main and produces no defined response. Fix by boundary-only conversion after cleanup, never by inheriting ValueError/HeptaError.
4. Admission refusal currently carries an arbitrary string and later calls report terminal, not a frozen first cause. Budget, unsupported runtime/cold Path/schema, replacement hook, wrong thread/reentrancy, cancellation and I/O need distinct categories. Introduce structured provenance at the originating rejection sites, not string parsing. Proposed budget fields: phase, dimension, limit, admitted, attempted, with observed OS bytes/reads separate. Validate exact positive ints and reject unknown policy keys. First failure persists on later operations.
5. CLI build/run compile again after analyze_project's final revalidation, with no owner checks around the second compilation/publication/execution. Test using controlled fake compilation and source mutation demonstrates that analysis success is not publication authorization. Native scope remains rejected in the first slice.
6. Owner.unchanged preserves package-snapshot semantics and does not re-read Hepta.lock. A lock-only change may leave it true. Tests must preserve this fact; initial --locked means initial disk verification, not fresh lock authentication, overlay authority or immutable snapshot.
7. The public graph/report/AST remain mutable; private source authority survives public-map edits, but AST mutation is not authenticated by unchanged. Trust ordinary internal consumers in the first slice; no adversarial same-process consumer contract.
8. Profile Path support is CPython 3.11/3.12 POSIX and exact canonical state. 3.12 cold/partial Path, subclass/foreign slot and finite-pin mutation refuse before the fourth copy, but may occur after earlier loader work. No fallback or normalization should conceal this refusal. Unexpected copier/MemoryError/RecursionError remains terminal and is not fabricated as quota exhaustion.

## Thread, hook and bootstrap policy

One request owner is created and used on one thread; cross-thread/reentrant use is terminal. A future worker executor creates its owner inside the worker, never on the dispatcher then transfers it. Cancellation checkpoints are cooperative. They do not interrupt synchronous reducers, checking, metadata calls, filesystem operations or native subprocess cleanup.

Current pins are a finite trusted-bootstrap contract. Pre-import replacement, arbitrary function-code/private globals, another thread mutating the runtime between checks, tracing/signals and finalizers are not fenced by an in-process sandbox. Durable tests should demonstrate documented finite-hook rejection and thread ownership; do not reinterpret those as hostile-thread isolation. Native process timeouts/output caps are separate controls.

## Source, locks and publication

Refuse all non-None source overrides, including empty mappings, before reads. Do not silently grant IDE/protocol/workspace overlay semantics. Preserve raw lexical entry binding, role-based source/manifest/lock/header/sidecar limits, source hashes, symlink retarget checks and final same-ledger revalidation. Test source change between analysis and final check, exhausted final read allowance, package inventory change, stale lock at admission, lock-only late change, alias retarget and public-authority mutation.

The first slice writes no output and runs no native compiler. Later build/run/native integration requires owner-preserving pre/post compile and pre-publication checks, existing artifact transaction gates, original-output preservation on failure, transitive-header/toolchain identity boundaries, and fresh compiler-bound qualification after any production source change. Revalidation is not atomic filesystem snapshotting and cannot alone close a publication race.

## Quota selection and measurement

Do not silently promote experimental defaults as safe production values. Freeze a named policy version containing every inherited limit and its exact unit; policy construction happens before I/O. Distinguish per-file role bytes, cumulative observed returned bytes (including overflow sentinel), read attempts, graph nodes/edges/depth/path checks, metadata invocation/JSON depth, tokens/parses/parser nesting, AST/append units, unfolded copy visits, transform entries, map visits, shallow entries and actual Package deepcopy-call projections.

Calibrate workload evidence over all 80 examples plus package diamonds/wide imports, long identifiers/string literals, near-depth syntax, C-import sidecars/headers and repeated revalidation. Record accepted workloads and per-dimension headroom; define false-refusal expectations before selecting named values. For every limit, execute exact/one-below or equivalent threshold tests and ensure the next over-budget operation does not start (earlier work in that stage may already have occurred). Existing 658 tests are inherited evidence, not proof that every integration limit or flag has been tested. Tighten a single dimension while holding the rest generous to identify the refusing boundary. No automatic retry with increased quotas.

## Parser and native boundary inventory

Hepta syntax uses the real Python lexer/parser with owned single-lex tokens and AST/append admission. The profile does not turn it into a native parser. The Rust HIA/Core shadow checker/executor is not an interchangeable Hepta source parser; any future native source parser requires its own exact-byte binding, AST/diagnostic differential, output limits, crash/timeout/truncation tests and no owner-reset fallback. JSON/TOML parsing remains synchronous with admitted input bytes and invocation/depth checks; it has no hard CPU/allocation limit. `hepta.c_import.import_header` separately reads headers directly, creates HeaderParser, and invokes compiler/probe processes; it does not accept this Owner and does not inherit its counters. The plain-char Prepared experiment has a separate context path and must not be represented as composed #633 integration. No measured loader parse quota implies native HeaderParser/probe work or Rust/GCC/Clang work is charged.

Before admitting those paths, separately specify header snapshot/materialization admission, native parser/probe limits, process startup/timeout/output/cleanup behavior, transitive dependency observations, and qualification; test that no legacy header reader or unowned graph reload is reachable. Until then reject those command routes under the proposed first profile.

## Required staged gates

A. Publish only this audit and current-behavior counterexample tests. Independent review before implementation.
B. Add structured failure and frozen versioned policy to isolated owner/context experiments; preserve all old behavior and old profiles. Independently reviewed negative/cancel/terminal tests and both Python jobs.
C. Add an isolated explicit owner-preserving frontend adapter over real pipeline.analyze. No CLI selection yet. Fail tests on any legacy load/revalidation fallback, early path normalization, reset ledger, discarded handle or native invocation. Compare full successful reports/diagnostics and source bytes with legacy within the admitted class.
D. Only after B/C pass, review an explicit CLI opt-in for check --frontend-only, versioned response schema/exit codes and flag validation. Subprocess tests must establish no traceback on defined refusal, no output artifact or native process, same legacy defaults, and exact identity/compiler-hash handling. No command-wide boundedness claim.
E. Native/publishing/overlay/other-platform expansions are separate designs with separate qualification. Do not merge/deploy or switch defaults as part of this audit.

## Reproducible example headroom probe

`python -m experiments.cli_admission_audit.calibrate_examples` loads every example with an independent owner and performs one additional same-owner revalidation. For successful loads only, it records current cumulative-counter peaks, the after-load count for each peak case, and a list of unmeasured per-file/depth dimensions. Diagnostic-ending case counters are explicitly unmeasured. The reference commit identifies the audited design baseline, not runtime checkout attestation. Values depend on interpreter and checkout path and do not select a production policy. The current corpus is not an adversarial maximum or a complete project workload; analysis, native work and publication are excluded. The regression requires 68 graphs and 12 original diagnostics, successful final revalidation, and explicit unmeasured dimensions.
