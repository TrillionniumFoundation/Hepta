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
and asks Z3 whether a behavior difference exists. `unsat` yields `proved`;
`sat` yields `disproved` only after the model's arguments are replayed in the
canonical HIA interpreter and reproduce different observations. This replay
validates counterexamples; it is **not** the basis of the all-input proof.

Loops, calls, resources, foreign code, concurrency, and floating point are
outside this profile. A function is limited to 128 blocks, 2048 operations,
32 parameters, and 16 returns. Unsupported inputs, solver absence, solver
timeout/unknown, and invalid canonical programs return `unknown`; none are
implicitly approved, including an identical unsupported before/after pair.

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

Z3 and the Python symbolic encoder are in the trusted implementation. The
encoder follows the canonical executable HIA semantics; its correspondence is
tested and inspected, not proved by Lean/Coq. Canonical ownership checks remain
executable checks, not a whole-language soundness theorem. This module does not
prove LLVM/native refinement, resource bounds, latency, energy, or global
optimality. Backend execution requires its existing qualification independently.

The optional `z3-solver` dependency is needed to obtain `proved` or `disproved`.
Absence is reported as `unknown` with `reason = "solver_unavailable"`.

Run the focused adversarial tests and retain a real qualification receipt:

```sh
python -m unittest tests.test_hia_translation_validation -v
python tools/qualify_hia_translation_validation.py --output translation-evidence.json
```

Qualification includes a wrapping cancellation proved for all u32 inputs, a
safe-but-wrong replacement, removal of an observable checked trap, an unsupported
loop, and a forged proof receipt. A missing solver fails qualification instead
of being counted as a successful proof.
