# Opt-in observed native dependency admission

This is a research-only successor to #619 at
`43ea9c8f316d38cf3aa14b883d540a7ad0c5f3c6` (tree
`e454a09e83c86263b4cc0a43563821e8fd266755`). All inherited files are unchanged.
Production `hepta`, its CLI, default experimental entry points, and typed C
adapter behavior are unchanged. This is **not** production C-import integration.

## Why this step

The earlier request context meters source/lock/header loading, but `Prepared`
reads compiler-generated dependency files and native dependencies outside that
ledger. Its publication recheck also reads dependencies directly. A real valid
locked `strlen` build with a 2,000,005-byte forced-include header succeeds with
an earlier 1,000,000-byte total/header allowance. The old ledger reports only
99,443 bytes and 120 reads, despite observing and publishing the dependency.
That was an explicitly excluded scope, not an advertised old-contract violation.

This new entry point refuses the oversized observation and preserves the
previous artifact. The permanent red/green test executes real GCC on both paths.
No compiler, parsing, file-read or type-check mocks are used in that test.

## Explicit API and lifetime

Use `experiments.native_observations.build_plan.execute` with the existing
immutable `experiments.c_char_boundary.build_plan.Request`. It accepts only the
existing narrow C/native-bin check/build/run request and creates a fresh native
observation `Context` before loading. There is no CLI switch, automatic fallback,
serialized-context import, old-receipt authorization or production default change.

The same Context, Reader and native deadline cover loader reads, bounded depfile
reads, dependency hash streams and final re-observations. Every outcome closes
the Context. Path/parser/encoding/I/O/callback/quota errors are terminal. The
existing private importer lifetime remains in place; replacing it with a reviewed
production injection API is still a separate prerequisite.

Check and build do not execute the user program. Run does. Compilation uses the
inherited original header, fresh boundary checks, TU-local typed adapters and
fixed flags. No C type is bypassed; unsupported declarations remain unsupported.

## Admission and accounting

Defaults add these explicit finite experimental policy values:

- depfile bytes: 262,144 per read
- native dependency bytes: 16,000,000 per observation
- native dependency entries: 8,192 cumulatively
- native path length: 4,096 Unicode code points

The inherited total-byte budget is 32,000,000 and read-invocation budget is 1,024.
The Reader maximum and native roles are fixed during Context initialization,
before its first read. A path previously admitted under a tighter role retains
that tighter cap. Nothing resets its allowances between loading, compiling,
checking dependencies or publishing.

A depfile read and every dependency stream consume the same Reader ledger.
Every listed dependency is charged before retention/deduplication, including
repetitions across translation units. Every revalidation observation charges a
new entry and read. Repeated resolved paths with different digests are refused;
each original raw spelling, resolved identity and digest is retained, rather than
letting the last TU overwrite previous evidence. The receipt's old-style mapping
is presentation only, never authority for revalidation.

The inherited Reader charges each admitted read invocation and actual bytes
returned by the OS. A growing input may require one overflow sentinel byte, also
charged, before terminal rejection. An oversized fstat may refuse before reading
its bytes; the attempted invocation is still charged. These are cumulative
observation limits, not promises that the counter never exceeds its byte limit
by that sentinel.

Local Linux x86_64 / GCC 14.2 measurements of real strlen check/build/run in all
three inherited char modes used 52 dependencies, at most 1,117,644 cumulative
bytes, 222 reads and 156 entries. These values explain finite fixture headroom,
not universal workload sizing. AArch64 qualification remains the hosted workflow's
job; no unexecuted platform result is claimed here.

## Deliberately narrow depfile grammar

Only a single GCC `-MD/-MF` rule is admitted. Plain tokens and `$$` for a literal
`$` are supported; whitespace-separated backslash-newline continuation tokens
are supported. All backslashes **inside** path/target tokens are rejected,
including GCC encodings for spaces, tabs, `#` and literal backslashes. Colons in
dependency paths, comments, variable expansion, multiple rules, invalid UTF-8 and
other unsupported/ambiguous forms are rejected. This is not a general Make parser
or a promise of all Linux filename support. Such refusal preserves old output.

Independent real-GCC review found that treating backslashes like shell escapes
can hash the wrong existing file. GCC emits consecutive literal backslashes
unchanged before ordinary characters; a filename ending in a backslash can mimic
a continuation. Both could silently select a decoy path. The final parser fails
closed for those cases, with two independently authored real-GCC regressions.
A failed profile never falls back to old parsing or unbounded observation.

## Identity and publication checks

Each raw path is resolved again around observation and at revalidation, and its
resolved identity must match its stored identity. An equal-content symlink
retarget is refused. Before replacement, dependencies are rehashed from retained
records; the original output spelling is resolved again and compared with the
initial destination. A final cooperative guard rechecks dependency bindings and
output collisions against original protected inputs and observed dependencies.
Failures leave the previous output intact and remove the staged candidate.

These checks are sequential. Concurrent changes after the last observation can
still occur. No atomic publication *decision*, compiler-consumed-byte snapshot,
current-at-return guarantee or system-wide exclusion protocol is provided.
`atomic_system_snapshot` and `foreign_binary_authenticated` remain false.

Package locks retain their existing content schema and diagnostics. They are not
extended to sysroot dependencies or treated as full native dependency closure.
The new controls retain valid/malformed/missing/stale lock behavior.

## What this does not bound or qualify

Post-compile admission happens after the compiler has already consumed its
inputs. It bounds Python observation work, not compiler include expansion,
compiler memory, header parsing, hidden wrapper inputs, linked libraries,
compiler-binary identity reads, generated-artifact reads, synchronous filesystem
latency or cleanup. No hard CPU/heap/time bound or authenticated closure follows.
Foreign pointer validity, aliasing, lifetime, bounds, termination and effects
remain obligations. Native qualification remains the inherited finite Linux GCC
x86_64/AArch64 profile, not a general ABI guarantee.

## Verification

`python -B -m experiments.native_observations.gate` requires exactly 202 unique
controls, including all 164 inherited controls plus 36 author and 2 independent
controls. It rejects skips, expected failures, unexpected successes and ordinary
failures. Hosted CI pins exact head and baseline tree, permits exactly 11 additive
files, binds real GCC/Rust 1.90 and runs all controls twice on Linux x86_64/AArch64.

`--local` explicitly omits the seven Rust consumers and requires 195 controls
with no skips. This is not a full hosted pass. The original pipeline's default
imported-char C conflict is not repaired by this isolated module.

Production integration still needs reviewed loader/importer APIs, diagnostics
and quotas, and actual subprocess CLI check/build/run validation across the whole
native lifetime. No merge, deployment, default activation or wider ABI claim.
