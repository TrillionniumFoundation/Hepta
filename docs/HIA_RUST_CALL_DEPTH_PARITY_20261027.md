# HIA P2: Rust scalar VM root-zero call-depth parity

**Base:** PR #274 `fbf6abdc7156187c962544c3261a577ab81b3c30`.
This is a narrow independent execution-oracle fix. It does not change the
canonical Python `verify_program`, executable HIA schema, Rust ownership
checker, LLVM backend, native ABI, compiler admission, or resource contracts.

## Reproducible mismatch and correction

The canonical Python VM enters the root invocation at `depth=0` and
rejects when `depth >= max_call_depth` **before entering the next frame**.
This root-inclusive contract was already explicitly fixed in
`docs/HIA_VM_CALL_DEPTH_BUDGET_20261026.md` and covered by
`tests/test_hia_vm_call_depth.py`.
A later Rust shadow change incorrectly changed its limit to
`depth > MAX_CALL_DEPTH`. Both implementations use limit 32 in the
Python↔Rust scalar VM differential suite.

For a function that calls itself once per frame and never returns:

| Interpreter | First rejected depth | Entered frames | VM ticks |
| --- | ---: | ---: | ---: |
| Canonical Python (`>= 32`) | 32 | 32 | 64 |
| Divergent Rust (`> 32`) | 33 | 33 | 66 |
| Corrected Rust (`>= 32`) | 32 | 32 | 64 |

There are two ticks per entered frame before the next recursion: call
entry and the recursive-call operation. No extra tick is charged for a
rejected invocation. The configured number 32 means **32 total active
frames including the root**, not 32 descendants beyond it. A 33rd frame
would contradict the canonical Python runtime and the independent static
`max_call_depth` convention.

## Committed checks

- Rust scalar VM recursion regression now requires **64** ticks.
- Python↔Rust differential verifies finite recursion succeeds through
  depth 31 and refuses at depth 32, plus an exact infinite-recursion
  status, budget-code and 64-tick check.
- The original canonical Python-only root-inclusive regression remains in
  `tests/test_hia_vm_call_depth.py`.
- Existing signed division/remainder overflow, CFG/PHI, arithmetic, limited
  scalar grammar and ownership rejection behavior remain unchanged.

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml recursion_is_bounded_independently_of_step_budget
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
```

The 32-frame/64-tick boundary was reproduced by an independent CPython
count-only control and matched the existing canonical Python source contract,
**not an exact-head actual Rust/Cargo execution**.
The local environment does not expose Cargo/rustc or a GitHub checkout.
No green CI, native parity or end-to-end safety is inferred from the new
tests being committed.

**OPEN:** generic ownership/Memory SSA, true source→Core→LLVM/Rust
refinement, cross-target ABI, arbitrary C/C++, held-out AI-agent benefit,
physical devices and sustained performance.
`whole_project_blockers_closed=false`.

## Follow-up P2: explicit scalar export-list parity

The canonical standalone Core accepts optional `exports` and checks every
listed function, including an empty list meaning no public entrypoints.
The Rust scalar verifier originally rejected the entire optional field,
preventing independent differential verification of valid exported HIA
modules. This candidate extends the **existing** Rust scalar-only verifier,
without introducing a new schema or capability type.

- The optional top-level key is admitted only with exact strict structure.
- Each export is a unique, existing valid identifier; no duplicate, unknown,
  bool or malformed export is accepted. All signatures in this Rust shadow
  remain scalar-only by its existing whole-module checker.
- `execute_scalar` must refuse an unexported entry even when the same
  internal helper is available via an admitted exported call.
- Absence of `exports` retains the original scalar public-entry behavior.

Direct Rust adversarial tests and the real Python↔Rust optional-export
differential are now committed; neither has executed on this exact SHA
because Cargo and complete GitHub checkout are unavailable locally. This
only broadens finite Rust scalar shadow correspondence, **not** full
program/Owner/Core/LLVM refinement or production external authorization.

`whole_project_blockers_closed=false`.
