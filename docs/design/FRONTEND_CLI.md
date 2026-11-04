# Explicit experimental frontend CLI

Stage D follows independently reviewed Stage C #636 at commit
`3d441a4c7d39fd49839f754c5be7ae3775c1b7b4`, tree
`2dc9d3d4f7b5bc1f7b736d8ef2f8f21a9becc4b1`. All inherited files remain
frozen. This adds only experiments/frontend_cli, this document and its workflow.
The design was independently reviewed before implementation. There is no installed
entrypoint, production import from experiments, default switch or native activation.

## Invocation

`python -B -m experiments.frontend_cli check --frontend-only --policy loader-experimental-v1 SOURCE [--locked]`

The named policy and frontend opt-in are required exactly once. Only locked is an
optional flag. No policy values/files/environment settings, output, source overlays,
backend, compiler, target, build/run/emit/header/patch/import-c or other commands are
accepted. Abbreviations, duplicate flags, extra operands, unknown aliases and response
files refuse. `--` ends option parsing: `-- -` and `-- @name` denote literal filenames,
not stdin or response-file expansion. Empty source spelling refuses. No input path is
constructed, resolved or opened while parsing. One FrontendRequest is constructed
before the original source string is supplied to its check method. Runtime refusal at
construction preserves Rejected.failure even though no request was assigned.

`--help` or `check --help` returns JSON help with no owner or input access. Other help
combinations refuse. The policy_v1.json fixture freezes all 33 default limits and units;
it is test evidence, not a runtime configuration file. Policy defaults remain experimental,
not calibrated production recommendations. No retry raises limits or creates a fresh owner.

## Response and exit contract

Each process outcome attempts one ASCII-escaped strict JSON object plus newline on
stdout. Schema is `hepta.experimental.frontend-cli.v1`. Every envelope contains
policy_version, frontend_only, native_qualified, outcome, ok, report, diagnostics,
first_failure and error. Help additionally contains usage. Policy_version identifies
the selected fixed contract, not proof that owner construction or admission completed.
Frontend_only identifies requested scope; native_qualified is always false.

- help/success: exit 0. Help ok means help succeeded, not source validation.
- diagnostic: exit 1, ordinary loader/checker/race diagnostics.
- usage: exit 2, fixed E_ARGUMENTS without echoing argv.
- refused: exit 3, budget/runtime/schema/integrity/lifecycle/I/O failure.
- cancelled/interrupted: exit 130, explicit cooperative cancellation/KeyboardInterrupt.
- error: exit 70, unexpected/SystemExit/memory/recursion, invalid result or serialization.
- output transport failure: exit 74 regardless of execution outcome.

First originating Failure controls execution classification, not the last escaping
exception. An original diagnostic has category diagnostic; an I/O-origin HeptaError
keeps its original diagnostic and category io. A returned E_MODULE_RACE report with
sticky io keeps its complete report but is refused, not an ordinary diagnostic-only
outcome. Ordinary returned diagnostic reports can have first_failure=null. Success
requires report.ok to be exact True, status frontend_only and no first failure. A
contradictory successful report plus failure is an internal error with report suppressed.

Report is the complete original hepta.check.v1 report when analysis genuinely returns.
Thrown failures always have report=null, including after analysis began internally.
Escaping original HeptaError diagnostics appear in envelope diagnostics; returned
report diagnostics remain inside report. No compiler/source/generated-source hash is
fabricated on early failure. Existing compiler_sha256 hashes production hepta/*.py,
not the experimental CLI/adapter; it is not experiment-build attestation.

Failure serialization copies only fixed fields with validated primitive types. Reports
are copied as strict JSON primitives without repr, default=str, arbitrary encoders or
exception-message fallback. Intended original diagnostic/report paths and messages
remain visible; raw argv, unexpected exception contents and tracebacks are not echoed.
Public AST/report objects remain mutable and are not an adversarial security boundary.

Serialization finishes before the first stdout write. Explicit cancellation or
KeyboardInterrupt during argument handling or serialization emits a report-null
cancelled/interrupted response with exit 130 when output has not started. During
output, transport failure still wins with exit 74. Invalid report serialization
suppresses the whole report and exits 70; already materialized first cause is retained
when possible. A fixed full-schema emergency envelope is available if JSON encoding
itself fails. No second stdout response follows a write attempt. Short writes, write
errors or flush errors exit 74 with only a best-effort fixed stderr notice. A receiver
may have partial bytes or even a complete object whose delivery was not confirmed;
exit status is authoritative for transport. The module explicitly exits after main's
flush, without interpreter atexit output retries, to avoid shutdown BrokenPipe noise.
Import/interpreter failures, forced termination and unrecoverable memory exhaustion
are outside guaranteed clean-response handling. This is not a hard sandbox.

## Scope and inherited gaps

The adapter retains its exact owner/handle/ledger through the real frontend and final
revalidation. Compiler invocation and project/artifact publication are absent. Pure
source emission and compiler-source hashing still occur. Only loader admission is
metered; frontend work, encoding/output and cancellation latency are not bounded.
The canonical -B avoids Python bytecode writes. Without it Python import caches may
be written; no claim of absolutely no filesystem writes is made.

Initial --locked is initial lock verification, not a fresh final lock authentication.
A lock-only late change can still pass. Symlink retargeting and source/inventory changes
have inherited race semantics. Revalidation is not an atomic filesystem snapshot,
public AST is not authenticated, and cancellation is cooperative. No native qualification,
overlay authority or publication authorization follows from frontend success.

## Validation

The gate plans 811 unique controls with consumers (679 without): 767 inherited plus
19 CLI and 25 independent regressions. Controls include real subprocess responses,
full 80-example report/diagnostic parity, raw alias spelling, strict argument matrix,
frozen policy, real adapter budget/cancellation/source races, no native/project output,
constructor refusal, original first-cause precedence, report suppression, schema types,
serialization, short writes, broken pipes and flush/stderr failure. The inherited gate
covers lock/inventory/revalidation and complete adapter lifecycle semantics. Tests use
patching only in their harness; no production or CLI fault-injection option exists.

The workflow pins exact candidate and Stage C commit/tree, rejects inherited changes,
runs CPython 3.11 and 3.12, all controls, 99 direct lexer/parser comparisons, 80 direct
loader comparisons and 813 prior-profile outcomes. Rust 1.90.0/GCC are used only by
inherited controls, never by the new CLI. Counts and passing tests are scoped evidence,
not proof of complete adversarial coverage or approval to merge/deploy/expand scope.
