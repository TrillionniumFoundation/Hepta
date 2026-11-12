# Recoverable HIA owners: independent source integration

This branch is an isolated source-generation harness. It checks out product commit
`4b19af89a766593f7d5f1cc2db256e81aba7afcb`, tree
`1bc7c90996e1910ad66ba771b0bfee1d5bfa655c`, with all 3153 tracked files.
It does not change a product or audit ref.

The finite overlay combines the successful original Core/Emission/CLI source
integration with Core R4, Emitter R4, Byte ABI whole-emission wiring, Verification
R6, NativeBuild, and CallArena. The separately authored finish R5 repair is applied
only through its three exact before/after replacements. Proof is excluded.
Individual component results are not transferred to this source union.

## Frozen inputs and semantic changes

`inputs/INPUTS.json` binds every immutable owner packet by byte count, SHA-256,
and Git blob. `inputs/MERGE-PLAN.json` identifies the exact source chosen for each
of 112 overlay paths. Mechanical union files are stored in
`inputs/derived-sources.json`; their metadata is equally pinned.
The expected pre-generation index tree is
`e0da2630916be12071d2d37173cc033d371ead11`, with 3239 files.

The original 46-file pure Core closure remains intact. Seventeen backend and
execution-mechanism files are separately named; all 63 combined identity inputs
remain freshly read in sorted order. The original Core-only test is unchanged.
One NativeBuild source assertion now checks its actual mechanism classification,
with a matching negative assertion for pure Core. No hash input is removed.
Three previously retained extra terminal newlines are removed only after complete
Python AST equality, including source positions, has been established.

The external finish regression fixture is retained as
`inputs/probe_native_finish.py`. This source stage does not execute it or place it
in automatic product test discovery. Its actual native regressions have separate
owner-specific development runs.

## Actual generation and controls

The workflow uses ubuntu-latest, exact CPython 3.14.4, the original pinned source
dependencies, and the unchanged 1800-second source-command supervisor. It runs all
88 actual generators, generates the language/support/native inventories using the
real checkout HEAD and index, and reruns the source-owned generator shell with its
original Git-diff check. Only the explicitly named generated outputs may change.

The 157 selectors and 764 ordered tests from the previous successful joint source
run are preserved. Eleven additional selectors contribute 62 source controls,
for 168 selectors and 826 expected tests. Actual unittest discovery must exactly
match the frozen ordered IDs. Failures, errors, skips, expected failures, unexpected
successes, duplicate IDs, loader failures, and changed source bytes all reject.

Reports retain the complete before/after source maps, original command outputs,
actual Git metadata, changed source text, and every completed failed phase.
The workflow always attempts an evidence export and uploads the original files.
Lossless numbered compressed JSON log chunks support recovery of generated reports.

This stage does not run current-source cold replay or the full retained suite.
It does not enable native defaults, migrate live state, remove legacy code, or
claim the union has inherited any prior machine qualification.
