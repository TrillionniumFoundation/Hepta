# Explicit HIA bounded-file reader

This component provides an explicitly selected HIA continuation for
`hepta.hia_program_tools.read_bounded`. Without
`HEPTA_HIA_BOUNDED_READ_MANIFEST`, the retained Python policy remains selected.
An explicit empty, missing, malformed or mismatched manifest refuses; it does
not authorize fallback to the retained policy.

## What HIA owns

The generated 59,728-byte source owns the observation sequence, regular-file
and size branches, the read count, normal and exceptional context close
continuations, dynamic rejection continuation, exception disposition, operand
moves, temporary unwind plans and named-local release plans. The entry is
`f0(readbuf, mutbuf, mutbuf) -> u32`, with a 64-byte packet, 24-byte result and
1,024-byte private workspace. Its source-owned ABI is
`hepta/hia_bounded_read_abi.json`; no executable image is checked into the
package or silently selected.

Path conversion, OS calls, CPython file buffering, context-manager machinery,
actual foreign callables and operators, dynamic global lookup, exception
objects and runtime reference counting remain hosted Python/CPython
operations. The 8 MiB default is the original definition-time default; the
caller-supplied limit remains a foreign operand. No new UID, hardlink, parent
directory or pathname restriction is imposed by the product policy.

The original `read_bounded`, `_reject` and `HIAEditRejected` AST remains in
the public module. A complete original source fixture is retained independently
for finite differential controls. The reference function supplied to native
reads supplies its actual globals/builtins/constants; its body is not called.

## Build and select

A strict build consumes the compiler and completed cold report for the exact
current full source closure:

```sh
python -B -m tools.build_hia_bounded_read \
  --compiler /absolute/current-B3.image.bin \
  --cold-report /absolute/current-cold-report.json \
  --output /absolute/new-bounded-read-build
```

The strict gate runs before creating the build output. It retains the original
20-second wall / 10-second CPU compile limit, checks the full child request,
stdout, receipt, input and 1 MiB output, and publishes the selectable manifest
only after source/compiler/ABI stability checks and the completed build record.

An explicit `--development` may replace `--cold-report`; the resulting record
is labeled `DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD`. It cannot serve as a
matching-source cold receipt. Changing the profile or source requires a new
matching cold report for strict admission.

An operator may set `HEPTA_HIA_BOUNDED_READ_MANIFEST` to the completed
`manifest.json`. Selection rereads the source binding on warm cache access.
An already mapped owner also compares the current source against the immutable
source digest admitted with that mapping.

## Fixed finite validation

`tools.qualify_hia_bounded_read` accepts the same compiler and mode arguments,
plus a new evidence directory. One original owned-process supervisor bounds the
whole validation at 180 seconds with three seconds for cleanup. Inside it,
build preparation retains 60 seconds, each of the four finite groups retains
30 seconds, and the complete original eight-test group retains 180 seconds;
the enclosing owner remains the overall bound. All seven original CLI child
commands retain their original 20-second timeouts.

The gate requires 12 rejection-continuation, 24 lifetime/global-binding,
10 private permission and 9 real filesystem cases: all 55 fixed IDs, with no
skips or other anomalous outcomes. It then requires all original eight methods
and all seven CLI children, with the retained policy code object forbidden.
Case details, raw tracebacks, source/image bindings, requests, process receipts
and stdout/stderr remain in the evidence directory on failure. FIFO and
symlink fixtures are real objects; consumers archiving that directory must use
typed no-follow collection.

This validator is not automatically added to the existing 30-gate complete
qualification, and its finite PASS is not a full project or cold PASS.

## Evidence and open boundaries

Actions run 43175489773 exercised the original r4b candidate on CPython 3.14.4.
Its 55 finite cases, original eight methods and seven CLI children passed under
the unchanged original budgets; its outer owner naturally completed in
34.200557801 seconds. The original compiler was freshly produced as B0/B1/B2
within that development run. The full originals and independent 260-record
audit are retained at commit
`a27026122c62c55994c5f836914cccf25fec3836`. The generated HIA SHA256 is
`ecb7d81b3cf79b0a12a6c9f193c6a431f461a00870268e5a239154c7f42237ea`.

This integration keeps those HIA bytes but adds a builder, source-owned ABI,
resource declarations and validation entry. The earlier development result
does not qualify the new v80 source closure, its wheel installation, or a new
runtime binary. Source checks and regeneration are separately reported.

Arbitrary foreign-object behavior, cyclic-GC scheduling, traceback/reflection
equivalence, every asynchronous interruption/finalizer window and fully native
OS/context operations remain open. The finite lifetime comparison disables
unrelated cyclic collection and preserves raw traceback locations without
equating them. Default activation, retirement of the reference route, installed
execution of this component and full-project native qualification are not
claimed.
