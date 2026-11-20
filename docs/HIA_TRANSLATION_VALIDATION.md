# HIA scalar translation validation

`hepta.hia_translation_validation` separates **legal resource flow** from
**preserved function behavior**. Every input first passes the existing
`verify_program` authority. Passing that checker alone cannot authorize an
optimization: a well-typed, memory-safe function can still compute the wrong
answer.

## Supported proof domain

The versioned profile `hia.scalar-acyclic-bitvector-traps.v1` compares one public
scalar function in two independently verified programs. It supports:

- All existing signed and unsigned 8/16/32/64-bit integer types, 64-bit
  `usize`/`isize`, booleans, unit, and multiple return values.
- Acyclic closed SSA control-flow graphs with branches, jumps, and block
  parameters. Phi-like values are merged under exact predecessor guards.
- Wrapping and checked add/subtract/multiply; checked division, remainder,
  shifts, negation, and casts; wrapping casts; bitwise/boolean operations,
  comparisons, constants, and scalar selection.
- Exact return values and the **first specified trap code**. An unused checked
  operation may still trap and cannot be discarded without proving that trap
  impossible. Signed division truncates toward zero; signed remainder follows
  the dividend; signed MIN/-1 traps for both operations. Checked shifts check
  the count, not the bits discarded by a left shift.

The encoder creates symbolic inputs covering every value of each declared type
and asks whether a behavior difference exists. With a source-bound
`HEPTA_HIA_CNF_MANIFEST`, HIA projects the bounded boolean and fixed-width
integer graph into its own Boolean solver, including the checked operations'
ordered traps. If the native profile or its circuit budget cannot decide the
obligation, the existing Z3 path can try it. `unsat` yields `proved`; `sat`
yields `disproved` only after the model's arguments are replayed in the
canonical HIA interpreter and reproduce different observations. This replay
validates counterexamples; it is **not** the basis of the all-input proof.

The cold-built Linux x86-64 `hia-proof-cnf` executable accepts the existing
bounded HIA proof frames on stdin and writes their binary replies on stdout.
It uses the same HIA circuit projector and Boolean solver without Python or Z3
at runtime. Build it with `python -m tools.build_hia_proof_cnf --compiler B3.image.bin
--cold-report cold.json --output new-proof-dir`. This is a proof component: it
does not turn arbitrary source or ELF inputs into independently verified
programs, and an unknown or refused frame supplies no proof.

Loops, calls, resources, foreign code, concurrency, and floating point are
outside this profile. A function is limited to 128 blocks, 2048 operations,
32 parameters, and 16 returns. Unsupported inputs, solver absence, solver
timeout/unknown, and invalid canonical programs return `unknown`; none are
implicitly approved, including an identical unsupported before/after pair.

`validate_scalar_calls` is a separate bounded profile for acyclic direct
calls. With the installed HIA checker selected, actual callee graphs produce
typed summaries that are rebound to each call site's arguments. The checker
does not use the inlining producer, and observes traps at the original call
position. If Boolean search is inconclusive, the HIA word evaluator can
exhaustively check domains with at most 16 input bits and sufficient work
budget. Larger or unsupported obligations may use the existing pinned Z3
path; they are not certified by an incomplete search.

`validate_bounded_translation` is the separate single-feedback-edge
profile. The selected HIA image discovers the feedback edge and enumerates
the reachable (block, traversal count) pairs in deterministic order, with
the same block and operation limits as the retained path. The canonical
unfolding marks a would-be traversal past its limit
with a distinct Boolean return. The selected HIA circuit checker tests
whether that marker or an incomplete outcome is reachable; normal traps in
the original graph do not count as truncation. Only a successful bound check
admits the independent all-input comparison against the candidate. Bounds
and results are freshly checked, not assumptions supplied by the unroller.

## API and consumers

```python
from hepta.hia_translation_validation import (
    validate_translation,
    verify_translation_receipt,
)

receipt = validate_translation(before, after, function="calculate", timeout_ms=2000)
if receipt["status"] != "proved":
    # Keep the previously verified baseline.
    ...

# When loading persisted evidence, bind it to the current exact documents and
# recompute the proof before admitting the candidate.
fresh = verify_translation_receipt(before, after, receipt, function="calculate")
```

`before_sha256` and `after_sha256` bind canonical primitive Core bytes.
`before_input_sha256` and `after_input_sha256` additionally bind the structured
input when composite elaboration is involved. `function`, `profile`, `scope`,
and `validator_sha256` prevent reuse under a different target, profile, or
checker implementation. A consumer may instead call `validate_translation`
fresh and check those identities directly. A serialized `"status": "proved"`
is never an authorization token. Even a forged receipt with correct program
hashes is rejected if the recomputed semantic query is not proved.

The proof covers only the selected function. A module-level consumer must
preserve the public ABI and check every relevant export; one receipt cannot
authorize arbitrary edits to other functions.

## Trust and claims

The selected solver and its encoder are in the trusted implementation. The
encoders follow the canonical executable HIA semantics; their correspondence is
tested and inspected, not proved by Lean/Coq. Canonical ownership checks remain
executable checks, not a whole-language soundness theorem. This module does not
prove LLVM/native refinement, resource bounds, latency, energy, or global
optimality. Backend execution requires its existing qualification independently.

If the installed HIA solver cannot decide a case and the optional `z3-solver`
dependency is absent, the result is `unknown` with `reason = "solver_unavailable"`.

Run the focused adversarial tests and retain a real qualification receipt:

```sh
python -m unittest tests.test_hia_translation_validation -v
python tools/qualify_hia_translation_validation.py --output translation-evidence.json
```

Qualification includes a wrapping cancellation proved for all u32 inputs, a
safe-but-wrong replacement, removal of an observable checked trap, an unsupported
loop, and a forged proof receipt. A missing solver fails qualification instead
of being counted as a successful proof.
