# Proposed bounded declaration-position diagnostic

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

Design only at repository head `14802588c6328fd534499c26c75c7bec15ec319f`.
Independent review and separate implementation authorization are required. No
Lean invocation, implementation, publication, or proof acceptance accompanies
this document.

The actual full-DAG attempt at `a907f2a`, run `41666803300`, job `126024183887`,
completed Baseline and SyntaxData, then timed out in LinearTransport after
60.264 seconds with no captured stdout/stderr. The remaining seven stages did
not start. This establishes neither the expensive declaration nor the timeout's
root cause. The following is an observation experiment, not another unchanged
full-DAG retry and not a smaller acceptance contract.

## Isolation and fixed limits

Use a separate diagnostic entry point/protocol, not a relaxed acceptance
validator. First build and independently validate the entire original prepared
DAG, including all five complete input bindings, their source manifests, the
66-name positive inventory and ten original rejection targets. Freeze this
original preparation before deriving an instrumented source.

The diagnostic launcher has a hard allowlist and hard cap of three processes,
in this exact order: Baseline, SyntaxData, LinearTransport. Successful Baseline
and SyntaxData outputs may supply the next diagnostic invocation only under the
existing fresh-root, pinned-checker, support-identity and same-run olean gates.
The other seven stages are always `diagnostic_not_scheduled`, including when
LinearTransport exits zero. Never retry a stage or fall back to the acceptance
runner from this mode. Do not import the diagnostic LinearTransport olean into
any subsequent module, export it as accepted evidence, or reuse it in another
run.

The report remains a nonaccepting terminal result, with
`kernel_core_syntax_connection_checked = false`, all existing wider proof flags
false, all twelve global obligations unproved, and DENY_ALL. Distinguish
`diagnostic_completed`, `diagnostic_timeout`, `diagnostic_failed` and interrupted
or missing terminal receipt within diagnostic metadata; none maps to `passed`.
A normal acceptance receipt still requires the unchanged complete ten-stage
validator. Diagnostic text must never be passed to the acceptance inventory
parser as a substitute for such a receipt.

Keep 60 seconds per process, no launch after 540 seconds, 600 seconds external
wall time, and the existing job limit. The narrower three-process cap does not
replace or enlarge the global eleven-launch ceiling. Keep 2 MiB per generated
source, 8 MiB aggregate generated sources, 32 MiB per olean and 128 MiB aggregate
oleans. Count the original source inventory plus the additional instrumented
source if both are retained; marker text is not exempt. No extra Lean probe,
`--deps`, retry, install, native target execution, plugin, import, or limit change
is proposed.

## Deterministic marker placement: at most 24 sites

Instrument only LinearTransport. Baseline and SyntaxData sources remain
byte-identical to their frozen originals. A marker is exactly one line:

    #check "HIA_DIAG_v1_LIN_000"

Use sequential three-digit IDs after sorting and deduplication, starting at 000.
This is a pure check of a fixed String literal, not a new declaration, evaluated
IO action, proof, or claim about a theorem. Permit only this exact template and
the IDs in the frozen diagnostic manifest. No arbitrary expression, generated
string computation, `#eval`, `run_cmd`, `run_elab`, new option, or user-selected
marker is allowed.

Read command boundaries from the already validated restricted generated-source
grammar, not from substring guesses inside theorem bodies. A declaration's
"after" boundary means the start offset of the next top-level command, after
all continuation lines of that declaration. Preserve the original newline bytes.
Reject unsupported command shapes or ambiguous/missing anchors before launch.
The original names and leaf/nonleaf classification come from the independently
validated structured manifest, checked against the actual source declarations.

Construct these 24 candidate sites:

1. Before the first segment definition, after the original import/namespace.
2. After the last segment definition.
3. After the last named-tail definition.
4. Before the first theorem declaration.
5. After the first emitted leaf serialization theorem.
6. After the first emitted leaf parsing theorem.
7. After the first emitted nonleaf serialization theorem.
8. After the first emitted nonleaf parsing theorem.
9. After theorem ordinal 128 in the original source order.
10. After theorem ordinal 256.
11. After theorem ordinal 384.
12. After theorem ordinal 512.
13. After theorem ordinal 640.
14. After theorem ordinal 768.
15. After the last non-root theorem declaration.
16. Before `linear_bounds`.
17. After `linear_bounds`.
18. After `linear_serialized`.
19. After `linear_parsed`.
20. After `linear_length`.
21. After `linear_byte_range`.
22. After `linear_transport`.
23. Before the original contiguous final axiom-print block.
24. After the last original axiom-print command, at end of source.

The current transport source has 843 theorems. Ordinals are one-based and count
only original `theorem` declarations, not definitions or inserted commands.
Require this reviewed theorem inventory rather than silently adapting to a
changed generator. Merge coincident offsets into one site, retaining all its
anchor labels. Sort by original UTF-8 byte offset and assign IDs in that order.
The final number is therefore at most 24, never expanded to improve a result.
A later attempt with a different placement requires a newly reviewed manifest;
there is no automatic narrowing or binary-search retry in this experiment.

Freeze each site's ID, original offset, instrumented offset, adjacent original
command names/kinds, all anchor labels, and exact marker bytes/hash. Also freeze
the original and diagnostic full source hashes, source sizes and marker count.
Construct the instrumented source by copying original byte intervals and
inserting these exact blocks. Then use a separate removal check: verify every
block at its recorded instrumented offset, remove exactly those intervals, and
require byte-for-byte equality to the independently validated original source.
Do not use a broad regex that could erase unrelated commands. Reject duplicate,
reordered, moved, substituted, or unexpected marker blocks. Reapply the original
full-input/source validator to the stripped result and confirm original
manifests are unchanged. Verify these identities before and after the process.

This preserves all raw data, byte literals, aliases, bounds, proof statements,
proof text, imports, original order, and final inventories. It does not promise
identical scheduling or cost: any instrumentation is an experiment variable.

## Why stdout PTY, not Lean-side IO flushing

The pinned v4.19 source provides the following chain:

- `Lean.Elab.Frontend.runFrontend` enables asynchronous elaboration by default
  and calls snapshot `runAndReport`.
- `Lean.Language.Basic` reports snapshots incrementally in tree preorder.
  Its report function calls `IO.print`/`IO.println` without explicit flushing.
- `runtime/io.cpp` wraps ordinary stdout as a `FILE*` stream; its `putStr`
  implementation uses `std::fwrite`. No stdout `setvbuf` override is present.
- glibc's file-buffer allocation selects line buffering for a TTY.

Accordingly, connecting stdout to a PTY is expected to release complete newline
messages once the CLI has reported them. It does not force a pending snapshot
to finish, alter tree traversal, or force messages out of unfinished tasks.
The current zero-output timeout does not prove that libc buffering was its cause.

Do not implement the tempting alternative `#eval` or `run_cmd` containing
`IO.getStdout`/`IO.getStderr`, `putStrLn` and `flush`. Both command forms pass
through `elabEvalCore`, which wraps execution in `IO.FS.withIsolatedStreams`.
The replacement in-memory stream's `flush` is a no-op, and its captured text is
later converted into log messages. This is not a reliable direct OS flush path.
There is no need to authorize direct file-descriptor access or arbitrary IO for
the proposed pure marker approach.

Read-only source references inspected for this design:

- https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/Frontend.lean
- https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Language/Basic.lean
- https://github.com/leanprover/lean4/blob/v4.19.0/src/runtime/io.cpp
- https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/BuiltinEvalCommand.lean
- https://github.com/leanprover/lean4/blob/v4.19.0/src/Init/System/IO.lean
- https://github.com/bminor/glibc/blob/glibc-2.39/libio/filedoalloc.c

The glibc source inspection establishes a platform precondition, not an assertion
that an uninspected CI host uses precisely that version. Before launching the
third process, require all of these exact runtime predicates, obtained without
an additional Lean process:

- `sys.platform == "linux"`;
- `platform.machine() == "x86_64"`;
- `/etc/os-release` has exactly one unambiguous `ID` equal to `ubuntu` and exactly
  one unambiguous `VERSION_ID` equal to `24.04`, after parsing the file's standard
  quoted-value syntax without shell evaluation;
- `os.confstr("CS_GNU_LIBC_VERSION") == "glibc 2.39"`.

Record the observed values. A missing, unreadable, duplicate/ambiguous, unknown,
or different value prevents the third process from launching. Do not infer a
match from a related distribution, compatible version, runner label, or binary
filename. An unsupported platform, unavailable PTY, or failed configuration is
a diagnostic infrastructure failure, not permission to silently revert to pipes
or add a buffering wrapper, preload library, command-line flag, or extra probe.
These predicates do not convert expected line-buffer behavior into a guaranteed
real-run observation.

## Bounded collection and interruption

Keep the exact pinned Lean executable, argv, cwd, search-path isolation and
support checks. Do not add `--json`, `--profile`, `-j`, altered trust, or
`set_option Elab.async false`. Capture mode alone changes for LinearTransport:
stdout goes to a freshly allocated PTY slave; stderr goes to a distinct pipe;
stdin stays noninteractive. Do not merge streams or acquire a controlling
terminal. Before launch, record the slave's termios settings, set its entire
output-flags field (`oflag`) to zero, then read the settings back with
`tcgetattr`. Require `oflag == 0` and `os.isatty(slave_fd) == True`; record both
before/after settings and the isatty result. This disables all output processing,
including OPOST and ONLCR, rather than clearing an incomplete selected bitmask.
A failed set/readback/predicate prevents the third process from launching, with
no fallback. Retain exact raw bytes and hashes. Any normalized display text is a separate explicitly labeled view, not
a replacement for raw evidence.

Use a continuously serviced nonblocking reader/select loop for both descriptors,
with bounded read chunks. Preserve stdout/stderr identity, arrival byte offsets,
and monotonic receive times. Parent-side receive times are not Lean computation
times. Persist a start receipt before launch and bounded observations while
running, rather than keeping all diagnostics only in a final in-memory object.
Use precreated safe-root, no-follow, single-link files and the exact allowed file
inventory; keep any append handles bound to verified file identities.

The existing 1 MiB per-process allowance includes durable raw streams, live
metadata, final RESULT, and their one byte-exact job-log presentation. Reserve
1,024 bytes for fixed presentation labels/newlines. Durable evidence is capped
at (1,048,576 - 1,024) / 2 = 523,776 bytes: at most 507,392 raw stdout/stderr
bytes and 16,384 metadata bytes. Capture may use only 12,288 metadata bytes,
leaving 4,096 for the final runner RESULT. These are stricter sub-budgets, not
an increase to any existing limit. Count every append or replacement write;
truncation or overwrite never restores quota. Terminal records use accurate
explicit before_terminal counters; total physical bytes are independently
recomputable from the bounded files.

The runner serializes the actual complete final RESULT compactly, including
only hash references to already frozen parent receipts, and checks its actual
encoded byte size together with the actual events file. An oversized result
becomes an explicitly failed bounded result; if even that cannot fit, no final
receipt is invented. The CLI does not also print the result. The single safe
presentation step uses stdout.buffer.write on exact file bytes and counts labels
and newlines, so invalid or partial UTF-8 cannot expand through replacement.
It rechecks durable bytes plus the exact forthcoming display bytes against 1 MiB
before displaying any live evidence. No stage may borrow a fresh allowance from
another file or persistence layer.

The existing large source/support identities remain in the separately frozen
original preparation manifests. Live metadata references those manifests by
verified path/hash; it does not repeatedly serialize their contents. Such a
reference does not exempt any newly written diagnostic metadata from its budget.
Stop with `diagnostic_output_limit` and terminate the process if the raw allowance
would be exceeded, retaining only the bounded prefix and a truncation indicator.
Enforce the raw combined-stream cap at the reader, not merely when retaining
logs: count every stdout/stderr byte received, limit each read to the remaining
raw allowance, and stop reading/kill/reap as soon as that allowance is exhausted.
Reaching this conservative cutoff is a diagnostic limit failure even if no
additional byte has yet been observed. Thus combined raw bytes read never exceed
1 MiB (the reserved-metadata scheme imposes a stricter raw limit). Report only
observed byte counts/hashes, never an invented total for discarded or unread
output. Do not buffer unbounded output before truncation. Output without newlines is
still drained in bounded chunks; do not wait for a newline before enforcing the
cap or timeout. An incomplete final marker is not an observed complete marker.

Run the child in an isolated process group/session for cleanup, without a
controlling terminal; this launch detail is part of the diagnostic manifest.
At the 60-second monotonic deadline, or a cancellation/output-limit failure,
immediately kill the diagnostic process group, then reap the leader and drain
only already available residual bytes within the remaining diagnostic cap and
a fixed short cleanup deadline. Do not grant a new computational grace period,
wait indefinitely for inherited descriptors, or restart anything. The global
600-second external bound covers startup, collection and cleanup as well.
Record signal/returncode when known and mark cleanup/reaping/drain incompleteness
explicitly. Treat Linux PTY EIO as terminal EOF only in the expected closed-slave
termination state; other read errors are infrastructure failures.

A durable marker checkpoint is useful but is not a guarantee against SIGKILL,
host loss, disk failure, or interruption between receipt and persistence. Missing
or unfinished terminal receipts remain interrupted/unknown and nonaccepting.
No process or olean advances after an interrupted stage.

## Interpretation and decision rule

Report `last_observed_marker`, its original source boundary, the next planned
boundary, available error messages, returncode/signal and elapsed process time.
Do not report a declaration as proved solely because its following marker was
seen. Async elaboration and ordered snapshot reporting can make the reporting
frontier differ from the currently expensive computation. No marker does not
mean no work occurred. The experiment may narrow a source-position interval;
it does not guarantee identification of a single lemma or establish a runtime
root cause.

Even complete diagnostic LinearTransport output cannot establish the original
unmodified module's acceptance, the other four inputs, all negatives, or the
full syntax connection. A successful diagnostic run merely informs a subsequent
reviewed change or an explicitly approved original full-DAG attempt. Do not
change scheduling to synchronous mode as a hidden fallback: that introduces a
separate experimental variable and cannot diagnose the original concurrent
run's timing by itself.

A prefix-only probe is not this experiment. Truncation would fail exact source
restoration, and current data/proof interleaving can omit later input definitions.
It may establish only a separately labeled partial probe, never complete-byte
transport. No prefix retry is authorized here.

## Required mocked adversarial tests before any real diagnostic

1. Valid three-stage diagnostic with unchanged Baseline/SyntaxData and a complete
   instrumented LinearTransport; all seven later stages remain unlaunched and
   every acceptance flag stays false even if all three processes exit zero.
2. Request a fourth stage, skip/reuse a failed parent, retry, switch protocol,
   import a diagnostic olean elsewhere, or enter the normal acceptance path:
   reject before the forbidden action.
3. Marker insertion inside a theorem continuation, wrong/duplicate/reordered IDs,
   shifted byte offsets, non-ASCII offset confusion, missing original byte,
   changed proof or import, extra IO command, and over-24 sites: fail validation.
   Rehashing the diagnostic manifest must not bypass original-source equality.
4. Wrong input aliases, changed canonical bytes, dropped final print inventory,
   altered root proposition or resource limit: original independent validation
   must reject before instrumentation or launch.
5. PTY allocation/isatty/termios/platform failures: explicit blocked diagnostic,
   no pipe fallback, buffering wrapper, extra invocation, or timeout increase.
6. Simulated partial marker, split UTF-8, CRLF, very long line, output with no
   newline, and malformed/spoofed marker text: raw bytes stay bounded; only exact
   complete expected records with matching location/order are observations.
7. Concurrent stdout/stderr bursts and either stream flooding: both are serviced,
   remain distinct, and share the single retained-byte allowance. Cap overflow
   kills the process and retains marked bounded evidence.
8. Timeout before any output, during a partial line, after several markers, and
   during final inventory; verify process-group cleanup, bounded draining/reaping,
   timeout metadata, no downstream launch, and no theorem acceptance from logs.
9. Closed-slave EIO versus genuine PTY error, descendants holding descriptors,
   incomplete cleanup, external interruption and a missing terminal receipt:
   no blocking indefinitely and no invented final success.
10. Launch/deadline, source/aggregate/module and diagnostic accounting boundaries,
    changed pinned binary/support/source during the process, forged parent
    outputs, unsafe log-file identities and oversized generated marker manifests.

Mocks establish collection and rejection behavior, not Lean progress, marker
availability on a real host, kernel success, or a performance claim. Independent
implementation review must precede one explicitly authorized diagnostic run.

## Isolated implementation boundary

The implementation uses `retired harness diagnose-core-syntax-declarations`, separate
from the unchanged acceptance runner. `core_syntax_declaration_diagnostic_sources`
validates and derives the marker source; `core_syntax_diagnostic_capture` owns
platform checks and bounded PTY collection. The original first two sources are
retained in their actual package paths, the other eight originals under
`original/`, and only the instrumented LinearTransport is an extra source.
Original and diagnostic manifests remain separately hash-bound. A diagnostic
olean is never entered into the checked-parent inventory.

On this research branch the existing Lean workflow is temporarily switched to
this diagnostic entry point, rather than adding a second concurrent Lean lane:
GitHub pull-request path filters consider the accumulated diff, so an additional
lane would otherwise repeat the full acceptance attempt. Its name and step label
explicitly identify the nonaccepting diagnostic. The CLI returns nonzero even
when all three diagnostic processes finish. Returning to complete acceptance
requires an explicit workflow change and fresh exact-head verification.

The original 207 Python controls remain unchanged. New source controls and
execution/fake-child controls run in separate matrix jobs with the existing
180-second step and five-minute job bounds. These tests do not execute Lean or
establish that markers will be visible on the real CI host.

If capture unexpectedly raises without a reliable launch receipt, the runner
records a three-invocation upper bound and `invocation_count_exact=false`; it
does not infer that a possibly launched process never ran. External interruption
can still leave only an unfinished receipt. Cleanup contains the unreaped
leader's process group, not a hostile descendant that escapes into a new session.
