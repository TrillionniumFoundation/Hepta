# Existing numeric casts with concrete Copy ADTs

This is a **numeric-only source transplant and joint qualification**, not a new
numeric conversion implementation and not a wholesale merge of older research
branches. P11/P01 remain PARTIAL.

## Exact source composition

- Destination parent: #705 `9ecea4e1320039afdd720742e49e41b79ad02004`, whose
  branch contains the #700–#705 fieldless/payload/generic enum, generic record,
  builtin Result and internal Unit lowering sequence.
- Numeric origin: #579 `855733829c5ed9311770a338b5c347017363c191`, directly
  based on #572 `9417612c5f0ec00299a68e2be3685a9413e66ab2`.
- The numeric helper module `hepta/c_float_conversions.py`, both original
  numeric test modules, their explicit test-package identity, and
  [C_FLOAT_CASTS.md](C_FLOAT_CASTS.md) are copied **byte for byte** from #579.
  That document's earlier execution results are historical origin evidence,
  not results for this new composition.
- The numerical state declarations, complete cast-expression dispatch and
  numerical helper-emission block in `hepta/c_backend.py` are exact source
  fragments from #579. The only surrounding integration edit adds `float.h`.
  The rest of the destination production code stays unchanged.

`tools/numeric_adt_source_origins.json` records exact commit/blob/SHA256
identities. `tools/verify_numeric_adt_sources.py` verifies all five copied files
and all three numerical fragments. It is run before the strict test gate.
It proves source identity of those bounded parts, not their semantic correctness
or that the complete #579 branch was merged. In particular, unrelated #564
resource/runtime/borrow changes are not silently composed.

The earlier exploratory float-to-integer reimplementation is **not published**.
Its local tests motivated composition, but none of its helper code is used here.

## Joint contract

The already-qualified numeric semantics are unchanged: 20 float-to-integer
pairs truncate/saturate with NaN-to-zero, and 22 integer-to-float/float-width pairs
use exact dyadic encoding with nearest/ties-even rounding. The latter preserve
zero signs and map narrowing overflow to signed infinity; NaN payloads and
floating exception flags are not promised. The original format, word-order,
subnormal and no-fast-math requirements stay intact. Float-to-integer helpers
retain their original default non-trapping floating-environment boundary.

These casts now operate in the same checked source as concrete Copy records,
enums, Result and Unit: ordered constructors, copied arrays and records, match
payload snapshots, mutable replacements, borrowed aggregate slices, and source
module identities. The new composition does not add more cast pairs, source
syntax, literal admission, generic functions, resource payloads, foreign
aggregate ABI, recursive layouts or runtime allocation semantics.

## Reproduction and exact inventories

```sh
python tools/verify_numeric_adt_sources.py
python tools/validate_c_numeric_adt_composition.py
python tools/validate_c_unit_values.py
python tools/qualify_c_float_int_oracle.py
python tools/qualify_c_numeric_adt_oracle.py
```

The **native-C-only** gate freezes 321 unique methods: 23 newly authored scalar
and joint methods, all 289 inherited Unit-gate identities in their original
order, and the nine original non-Rust numeric methods. The gate explicitly
lists the two unexecuted Rust-reference methods. It does not label them passed
or hide them as skipped. One historical unsupported-cast fixture now uses
unsupported i128 instead of the newly composed float-to-i32 conversion; its
method identity, diagnostic and unrelated resource case are preserved.

Set `HEPTA_ENUM_REQUIRE_RUST=1` with pinned Rust 1.90.0 both on PATH and selected
by `RUSTC` to require the **323-method C-and-Rust inventory**. That mode adds both
original Rust-reference methods, and all new/native inherited consumers and
both oracles require their actual Rust comparisons. Missing tools, mismatched
versions, missing/duplicate inventory entries, skips/xfails/xpasses and input
hash drift fail closed. Separate frozen files name every method in both modes.

The eight joint methods cover all 42 pairs inside
`Result<Event<Cell<T>>,Unit>`, mutation after copying, match snapshots after
replacing the source enum, numeric/Unit constructor effect order, borrowed
slices, source-module composition, loop dispatch and unused function bodies.
Every joint method executes native C at O0 and O3 with nonrecovering undefined
behavior and float-cast-overflow sanitizers. Nine additional scalar methods and
the public CLI example execute the numeric subset separately. Original numeric
corpora and their rounding/FTZ/DAZ/profile-refusal checks remain intact.

The two independent Python-derived oracles exercise actual separately compiled
exported functions and exact-bit native clients. One checks the 20 scalar
float-to-integer pairs; the other checks all 42 pairs inside nested generic
records/Results/enums/Unit snapshots and borrowed aggregate slices. Both record
source, compiler, commands, corpus, expected output, objects, binaries and
process outcomes at O0/O3, and reject real deliberately wrong-output clients.
They share the production frontend, so they are not independent language
interpreters. Raw observations, native process executions and unit methods are
separate counts, never added together as tests.

## Retained negative evidence and limits

On unchanged #705, the eight final joint methods produce seven error methods
and one failure: casts remain unsupported. On a clean tree-identical local
export of #579, three error methods and one failure remain because the older
branch does not implement the full Copy-ADT/Unit composition; four methods pass.
Those parent failures are not presented as new-source passes. Earlier
exploratory tests and fixture-correction failures are retained separately.

The read-only exact-head workflow requests Linux x86-64/ARM64 × Python 3.11/3.13,
pinned Rust, the complete 323-method mode and both native oracles. It checks
exact source identity and cleanliness before/after and retains full logs.
Local C-only runs, origin-branch hosted successes and queued new workflows do
not establish native Rust/ARM or final integration qualification for this tree.
No complete language parity, source/refinement proof, performance superiority,
production qualification, merge, release or deployment is claimed.


## 2026-11-05 retained hosted fixture failure and correction

The original exact head `a36ca868057967fe556c4ca9f7a72b8ef50ce5d5` failed all
four numeric jobs in [run 42014604491](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42014604491).
Each ran the original 321-method C-and-Rust inventory and recorded 21 EACCES
entries: nine scalar and eight joint consumers shared a Rust compile call that
omitted `crate_type="bin"`; four more error entries were inherited Unit trap
subcases. The default Rust compilation kind is correctly `rlib`, so a successful
library build was followed by an invalid attempt to execute the library.
Both numeric oracles were after the failed gate and were not reached there.

All four inherited Unit jobs in
[run 42014604334](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42014604334)
separately ran the original 288 methods and recorded those four Unit EACCES
entries. These failures remain original negative results, not successful Rust
comparison or evidence of a compiler numerical error.

The numeric success helper now explicitly requests a Rust binary. The exact
three-file Unit test correction is carried from #705 commit
`4e8ec1710c3f3b2ea7168ed93893942680eb7c63`, requesting a binary at both Rust
emission and compilation. No production compiler, permission, executable-mode,
security setting, expected output, trap assertion or original method is changed.
No chmod or fallback execution is used. A read-only audit of all 23
`compile_rust` callsites identified these two incorrect runnable callers;
remaining compile-only, object, static-library and explicit-bin uses retain
their intended artifact types.

The two additional regression methods check the Rust call contract with mocked
Rust compilation/execution while still compiling and running real C. They are
explicitly not native Rust evidence. The new numeric contract regression fails
against the original omission and passes with explicit `bin`. They expand the
inventories to 321 C-only / 323 C-and-Rust, preserving every original method in
relative order. The inherited Unit inventory is now 289. Real Rust and ARM
correction results require the new exact-head hosted jobs; local C-only passes
and mock contracts do not replace those executions.
