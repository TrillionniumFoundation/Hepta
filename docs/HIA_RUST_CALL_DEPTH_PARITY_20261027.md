# HIA P2: Rust scalar VM root-zero call-depth parity

**Base:** PR #274 `fbf6abdc7156187c962544c3261a577ab81b3c30`.
This is a narrow independent execution-oracle fix. It does not change the
canonical Python `verify_program`, executable HIA schema, Rust ownership
checker, LLVM backend, native ABI, compiler admission, or resource contracts.

## Reproducible mismatch and correction

The canonical Python VM enters the root invocation at `depth=0` and
rejects only when `depth > max_call_depth`. The Rust scalar shadow also
starts the root at `depth=0`, but formerly used
`depth >= MAX_CALL_DEPTH`. Both are configured with numeric limit 32
by the existing Python↔Rust differential test.

For a function that calls itself once per frame and never returns:

| Interpreter | First rejected depth | Entered frames | VM ticks |
| --- | ---: | ---: | ---: |
| Canonical Python (`> 32`) | 33 | 33 | 66 |
| Previous Rust (`>= 32`) | 32 | 32 | 64 |
| Patched Rust (`> 32`) | 33 | 33 | 66 |

There are two ticks per entered frame before the next recursion: call
entry and the recursive-call operation. No extra tick is charged for a
rejected invocation. The configured number 32 means *maximum nested
depth beyond the root*, not 32 simultaneous frames. The corrected Rust
oracle permits 33 total active frames for this configuration, as Python
already does.

## Committed checks

- Real Rust scalar VM recursive budget regression now requires **66** ticks.
- Python↔Rust actual-model differential includes a finite recursion that
  succeeds at depth 32 and refuses at depth 33, plus a separately asserted
  infinite-recursion boundary (status, budget code and exact steps).
- Existing signed division/remainder overflow, CFG/PHI, arithmetic, limited
  scalar grammar and ownership rejection behavior remain unchanged.

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml recursion_is_bounded_independently_of_step_budget
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
```

The arithmetic of 32/33 frame boundaries was reproduced in an independent
CPython count-only control, **not an exact-head actual Rust/Cargo execution**.
The local environment does not expose Cargo/rustc or a GitHub checkout.
No green CI, native parity or end-to-end safety is inferred from the new
tests being committed.

**OPEN:** generic ownership/Memory SSA, true source→Core→LLVM/Rust
refinement, cross-target ABI, arbitrary C/C++, held-out AI-agent benefit,
physical devices and sustained performance.
`whole_project_blockers_closed=false`.
