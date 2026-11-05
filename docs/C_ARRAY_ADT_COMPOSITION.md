# Temporary-array reads with concrete Copy ADTs

This bounded P11/P01 integration starts from PR #706 exact
`a36ca868057967fe556c4ca9f7a72b8ef50ce5d5` and selectively adapts the already
implemented temporary-array reads in PR #583 exact
`a7e88847ede16c60951c4f044b54dfcf8bb1dfb6`. It is not a new invention of the
array-read capability and does not merge the broad resource/runtime branch.

## Joint behavior

Immediate indexing and `len` can materialize nonempty fixed-array rvalues once,
including literals, returned arrays and nested record/array projections. This
now composes with concrete Copy generic records/enums, builtin Result, internal
Unit and #706's existing numerical casts. The native consumers cover:

- Unit arrays with exact-once side effects, base-before-index order, `len` and
  both short-circuit directions.
- Returned arrays of `Result<Event<Cell<f32>>,Unit>`, complete payload dispatch,
  generic record fields and internal Unit values.
- Nested returned generic records/arrays, copy snapshots, integer/float casts,
  read/mut named arrays and source-module aliases.
- Dynamic bounds traps for Unit arrays, including `usize` maximum, with no
  undefined access; unsupported effectful indices still reject before emission.

The implementation transplants the original value-index and length fragments
byte for byte. The sequence adapter keeps only this destination's Copy-array
profile. Complete C layout validation precedes materialization. Place-based
assignment, borrowing and pointer extraction remain unchanged; `allow_temporary`
is enabled only for value indexing and length reads. The frontend and generic
function refusal are unchanged. No resource IR gate is removed or bypassed:
this destination never admitted those broader programs.

`tools/verify_array_adt_sources.py` verifies the original test blob, original
read-fragment identities and the bounded adapter. Reversing only these edits
must recover #706's C backend byte for byte. The numeric-origin checks from
#706 continue to pass unchanged.

## Exact qualification contract

```
python tools/validate_c_array_adt_composition.py
python tools/qualify_c_array_adt_oracle.py
python tools/validate_c_numeric_adt_composition.py
```

The strict native-C inventory contains **333 unique methods**: all 319 inherited
#706 identities in order, ten new joint controls and four unchanged applicable
#583 controls. No skipped tests, expected failures, duplicate/missing methods,
source changes or provenance mismatches qualify. The original six-method
#583 test file is retained byte for byte as `tests/c_array_values_origin.py`,
with original method bodies and names. This non-discoverable fixture filename
prevents ordinary unittest discovery from running its inapplicable diagnostic;
the strict runner explicitly loads the applicable methods.
Its generic/resource-gate diagnostic check is explicitly inapplicable to this
narrower source: the new generic-function control requires earlier blanket
refusal. It is not silently counted as passed. The original Rust-reference
method and the two numeric Rust-only methods are explicitly unexecuted in C-only
mode. Required Rust mode freezes **336 methods** and executes those methods plus
all native-reference branches in the inherited and new joint helpers.

All source/test/example/qualification inputs in the bounded materialized compiler
export are hashed before and after the combined gate. This is not the complete
repository release gate.

An independent Python-derived oracle checks 64 seeded Result/enum/Unit records,
nested numeric generic records and repeated side effects. Three successful
fixtures produce **333 expected observations per execution**. Each is executed
at C O0/O3 with nonrecovering UBSan; three separately compiled wrong-output
programs must fail the same exact-output expectation. Two Unit bounds fixtures
run at both optimization levels and must abort, with no C sanitizer diagnostics.
The oracle records source, compiler and executable hashes plus original outputs.
It shares the parser/checker and is not an independent language interpreter.

The read-only exact-head workflow requires pinned Rust 1.90.0 on Linux
x86-64/AArch64 with Python 3.11/3.13, all 336 methods, the joint array oracle and
both inherited numeric oracles. Missing required Rust fails closed. Earlier
origin-branch successes are not results for this new source.

## Baselines and retained limits

The unchanged #706 source rejects the joint temporary-array reads. The unchanged
#583 source has temporary arrays but rejects internal Unit storage/fields and
lacks the later numeric composition. Independent review verifies the original
staged tree against published #583 before using it as a baseline. Neither old
qualification establishes the new joint behavior.

Generic functions, resource arrays/payloads, temporary borrows/assignment,
returned slices, zero-length arrays and public aggregate C ABI remain outside
this increment. Numerical and raw-pointer limits are unchanged. No recursive
execution, literal admission, signature audit, import/publication or output-path
change is included. Finite native tests are not whole-language soundness,
performance superiority or production qualification. P11/P01 remain PARTIAL.

The first published test layout used the original discoverable filename, which
would make ordinary discovery run the inapplicable diagnostic. The source bytes
are unchanged but were moved to the explicit origin fixture before final
qualification. That superseded head is not relabeled as the final candidate.

Local evidence: the 333-method combined gate and 319-method inherited gate are
run on Python 3.12/3.13 with GCC 14.2.0. Native Rust and ARM are not available
locally and are not claimed. Initial example missing-effect and oracle
missing-effect/duplicate-binding attempts are retained as failures, not passes.
No merge, release, deployment or activation is authorized by this draft.
