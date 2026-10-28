# P3 follow-up: consistent parameter contracts across declarations

Two concrete declaration-admission defects are fixed in implementation
`e8c5da272560cf1243b7113faa5b9868d24b136c`. The affected **104 test methods pass**
on that exact fetched commit. The four preserved original inputs have the
expected two acceptances and two rejections. A first, overly strict whole-file
comparison of generated Rust failed because the new output directory appears
in diagnostic comments; that failure remains intact, with a separate, narrowly
scoped byte comparison and independent review below.

**This closes the two reproduced contract-binding inconsistencies. Complete
P0–P7 product acceptance remains open.** See the
[preceding status](../p0_p7_partial_records_incremental/current-status.json)
for the broader remaining resource, compiler, migration, performance, Agent
and hardware requirements.

## Exact source and review stack

| Identity | Value |
| --- | --- |
| Previous published evidence | `1739484bbda1a49a39b05714e2017d35b5c2c7e9`, [draft PR #338](https://github.com/TrillionniumFoundation/Hepta/pull/338) |
| Executed fix | `e8c5da272560cf1243b7113faa5b9868d24b136c` |
| Git tree | `20c6ba1e845e3d59c0027cd0d4ee305ddd602936` |
| Preserved local implementation | `695223952a5795af9ffd72339697d2626dd90e50`, identical tree |
| Official source snapshot | `07a64c2999a128570d0e0da6aa186d562fc63d3a8c4592b765d0c440b40852ed` |
| Source snapshot files | 1,067 |
| Implementation changes | Two production files, one focused test module and one contract document |

All four published blobs and the complete remote tree matched the reviewed
local implementation. The actual remote commit was fetched and checked out
cleanly before either formal command. Both commands retain their exact source
identities. This later evidence publication changes no executable code, tests,
examples, tools or source-snapshot documents.

The earlier full 2,548 Python / 54 Rust results remain attributed to `d942f18b`.
They have not been relabelled as full-suite execution of this later fix.

## Reproduced problem and resulting behavior

The previous declaration identity compared C parameter types and access modes
but omitted where a named slice extent resolved. The record-view override also
compared an initializer's source spelling rather than its resolved position.

| Caller contract | Captured declaration / definition | Previous admission |
| --- | --- | --- |
| `length: "n"` | `probe(p, n, other)` / `probe(data, other, n)` | Accepted although `n` resolves to positions 1 and 2 |
| `initialize: {"data": "a"}` | `bind(ctx, a, b, n)` / `bind(state, b, a, n)` | Accepted although `a` resolves to positions 1 and 2 |

Positions are **zero-based original C parameter positions**. The two associated
same-position renaming controls were also accepted, as intended. All four
original C programs executed three defined calls against separately stated
expected values: **12 original native calls**, no target native calls. These
observations establish a contract-admission inconsistency; they do not establish
a target runtime memory failure or a defined-input target-equivalence failure.
[Original report](baseline/report.json) and [final seal](baseline/seal.json)
preserve the captured inputs, original results and compiler/process records.

The fix adds one shared signature-shape helper after the existing contract
checks. Slice extents use tagged `("fixed", 1)` or `("parameter", position)`
identities. Each initializer field maps to its source parameter position.
Both ordinary C and record-view collection use the helper. Types, pointer/value
classification, access modes and existing C qualifiers remain in the comparison.
Original names and contract syntax remain unchanged for emission and diagnostics.

Conflicting declaration sets now reject with the existing `E_C_FUNCTION` before
a migration directory is published. Same-position renaming continues to work.
The six new methods cover both declaration/definition collection orders, the
record-view override for ordinary slices, both legal-renaming controls and the
distinction between fixed extent 1 and parameter position 1.

## Completed affected regression

The following selection ran once on the actual fetched fix. The predeclared
test limit was 600 seconds, with a 630-second outer supervisor including evidence
collection. No budget was increased and no test was skipped.

| Module | Passed methods |
| --- | ---: |
| C project migration | 34 |
| C record views | 25 |
| Original C parameter types | 6 |
| C project build matrix | 6 |
| Captured source arguments | 5 |
| Captured semantic flags | 6 |
| C++ project HIA | 5 |
| C++ constexpr migration | 11 |
| New parameter-contract identity regressions | 6 |
| **Total** | **104** |

The terminal footer is `Ran 104 tests in 375.839s`, followed by `OK`.
The test command took 376.225400 seconds; the outer supervisor took 378.134756
seconds. All 104 canonical method IDs are unique. Failures, errors and skips are
zero. Source and selected Python/Clang/GCC/Rust/libclang identities match before
and after. Native tests within these modules ran as part of the selection; their
calls are not separately counted or represented as new native qualifications.

[Regression report](regression/report.json) ·
[Supervisor terminal result](regression/execution.json) ·
[Raw unittest stderr](regression/stderr.log) ·
[Canonical methods](regression/canonical-test-ids.txt)

## Exact original-input replay and retained comparison failure

The public migration entry point reprocessed the exact sealed pre-fix input
files into new output directories. It did not recompile or execute the original
reference programs and did not build or execute target native programs.
Clang capture and frontend checks were performed. The fixed 120-second outer
budget was retained; the completed command took 13.648422 seconds.

| Original case | New public admission |
| --- | --- |
| Slice, same position with legal renaming | Accepted |
| Slice, named length changes position | Rejected: `E_C_FUNCTION`, no output bundle |
| Record initializer, same source position | Accepted |
| Record initializer, source changes position | Rejected: `E_C_FUNCTION`, no output bundle |

Both accepted cases have byte-identical `source.hepta` and `bridge.rs`. However,
the first collector required the complete `generated.rs` files to be identical
as well. This expectation ignored the output-path diagnostic annotations. The
collector therefore exited **1**, and its report remains **`passed: false`**.
The first report, streams, plan, script, manifests and supervisor result are
preserved, including their original result fields:

- [First replay report](replay/first-report.json), SHA-256
  `79226f461935837b3a820f29a06d7a638643b79052c1a8b42d54a1e186781b54`.
- [First supervisor result](replay/first-execution.json).

A **separate offline review**, with no migration, compiler or native rerun,
checks the retained bytes under an explicit, narrow relocation rule. Only a
parsed `// hepta-source:` begin annotation's `span.path` may change, and it must
change from that exact case's old `source.hepta` path to its exact new path.
Duplicate JSON keys, other fields, offsets, formatting and all non-annotation
bytes must remain unchanged. Replacing that one unique JSON string must restore
the entire original line exactly.

There are 9 such changed lines in the 50-line slice output and 17 in the
99-line initializer output. All executable Rust and all other bytes match.
Eight in-memory negative controls—changed return value, span start, unknown path
and annotation kind for each positive case—are rejected. These are comparison
controls, not additional unit methods or native executions. An independent
reviewer separately checks the raw diffs and reaches the same limited result.

[Strict relocation review and controls](replay/emission-path-review.json) ·
[Independent raw-diff review](replay/independent-path-review.json)

The offline result does not rewrite or convert the first failed gate into a
pass. Full raw `generated.rs` equality remains false; the qualified observation
is exact equality except for the verified diagnostic destination paths.

## Separate P6 session-history audit

A bounded audit on the **previous** published commit `1739484b` examined 12
predeclared transitions: retargeted calls and direct-interface changes,
deletion/readdition and rejected-edit rollback, loan permissions after retargeting,
and canonical no-op followed by a real edit and a stale patch. There were 8
acceptances, 4 expected rejections and zero full/incremental byte, diagnostic or
dependency differences. Nine base/candidate pairs were outside the earlier
957-candidate corpus. The other three transitions exercised patch history.

This audit found no new blocker. It did not execute full regression, native
applications, models or performance tests, and is not reattributed to the new
C-contract fix. [History summary](p6/history-summary.json).

## Evidence boundaries and remaining acceptance

Six round-trip-checked archives retain 158 exact text/source/JSON/stream members.
Four original native binaries are explicitly omitted from this text projection
and identified by size and SHA-256 in the archive inventory. Original absolute
paths and failure fields are not rewritten. The static review also retains the
initial validation-harness findings and their corrections; its approval does
not predict a command's later runtime result.

The source-level fix changes admission consistency for the declared migration
profiles. It does not establish foreign pointer provenance, actual allocation
size, initialization, aliasing, general C/C++ equivalence or whole-language
soundness. The prior P1/P2/P4/P5/P6/P7 limits remain open, including general memory
and concurrency, compiler refinement, broad migration, stable representative CPU
results, equal-budget model benefit, actual GPU execution and physical-board
resource/recovery qualification. No full release-gate rerun, remote CI completion
or merge is claimed.

See [machine-readable delta](current-status.json),
[parameter-contract semantics](../../../docs/C_PARAMETER_CONTRACT_IDENTITY.md)
and [archive inventory](archive-summary.json).
