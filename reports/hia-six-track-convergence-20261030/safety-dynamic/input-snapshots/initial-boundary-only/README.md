# Adaptive argument snapshot repair

## Scope and source

The starting file is `hepta/hia_adaptive.py` at
`953fa62dee5aa563551d57b1374ab95b6d548b45` (the same file bytes also appear at
`192d2cbba7e49bde3b03af73685ecf96f6fb1b05`). The retained original is exactly
Git blob `1b30383c47fbc2f1d3e100aa012126c6436f6f41`; its raw SHA-256 is
`1db194dde0e4ea3a2b0b629c950312c488b506fe1f0b683a1a062f3f4d349384`.
The runner checks this Git blob identity before its original negative control.

The original `_arguments` validated producer-owned lists and only then copied
them. A real second thread, scheduled between the check and the copy, changed
`[7]` to `[18446744073709551616]`; the invalid u64 reached the dispatcher.
Other retained cases substitute a negative integer or Boolean, append an extra
argument, and extend a batch after the initial length limit check. Both
`call_many` and `measure` use this path.

## Change

Take an outer snapshot bounded by `_MAX_BATCH + 1`, reject an oversized captured
batch, and take each exact list/tuple row snapshot bounded by `arity + 1`.
Validate the captured immutable values and dispatch those same values. The
extra element detects an overlength list without making an unbounded copy of
a producer list grown concurrently. Integer domain, arity and the existing
batch limit remain unchanged.

Rows are captured sequentially. This is not an atomic snapshot of all nested
producer lists and does not promise such an interface. The invariant is that
each dispatched vector is the exact immutable vector that was validated.

## Retained execution

`tests/test_hia_adaptive_arguments.py` has eight test methods. Real threads
mutate only caller-owned containers; a line trace selects the interleaving.
The tests use actual argument/dispatch methods and Python call spies. They
do not qualify a compiler, loader, native backend, or whole-language safety.

At this staging point, repository dependencies had not yet been restored.
`run_boundary_regression.py` therefore loads the actual AST method nodes with
their original filename/line identity, rather than claiming a complete package
import. The full package test remains to be run in the integrated checkout.

| Source | Methods | Failure records | Errors | Skips |
| --- | ---: | ---: | ---: | ---: |
| Exact original | 8 | 7 | 0 | 0 |
| Repair | 8 | 0 | 0 | 0 |

The seven original failure records cover five methods, including three
subtests in the scalar-mutation method. The retained logs and JSON contain
the actual observations, complete tracebacks, source and test digests. They
are not native qualification records.

## Independent read-only review

The separate `language_theory` agent reviewed the production change and tests
without editing them. It found no blocking issue: exact built-in bounded
snapshots prevent validation/use drift, exact type checking rejects Boolean
and subclass values, the internal admitted ABI supplies arity, and sequential
row capture is accurately disclosed. The reviewer considered the existing
specific-risk tests sufficient and did not request additional broad testing.

## Files for integration

- `hepta/hia_adaptive.py`: production file; only `_arguments` changes.
- `tests/test_hia_adaptive_arguments.py`: normal full-package test module.
- `original/hia_adaptive.py`: exact original source for negative control.
- `run_boundary_regression.py`: explicitly scoped staging runner.
- `original-boundary.log` and `original-boundary-result.json`: retained failures.
- `fixed-boundary.log` and `fixed-boundary-result.json`: retained repair result.

The integrated source and final artifact identities must be recorded separately.
No staged observation is relabeled as an execution of a later merge commit.
