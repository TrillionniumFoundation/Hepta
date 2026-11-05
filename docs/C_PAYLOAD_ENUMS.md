# Copy-payload source enums in the independent C backend

This finite P11 increment is stacked on fieldless-enum PR #700, exact commit
`63e676b12275c6b636aa7e83d149e9e4fcd751bd`. It adds ordinary non-generic source
enum payloads, not imported C enums or a public enum ABI. No other research
branch is composed. P11 and P01 remain PARTIAL.

A later bounded extension specializes concrete Copy-generic source enums; see
[C_GENERIC_ENUMS.md](C_GENERIC_ENUMS.md). The original scope and qualification
results recorded below describe this earlier increment, not a new full gate.

## Contract

- Enums may mix fieldless variants and tuple variants with one or more payloads.
- Payloads use existing supported C-backend Copy types: scalar values, positive
  fixed arrays, supported records, nested non-generic enums, and existing raw pointer
  types. Existing unsupported nested types still reject, even in unused enums.
- Constructor arguments execute exactly once, left to right. Every argument is
  materialized before the next argument, including arguments later ignored by
  a pattern. C initializer evaluation order cannot reorder their effects.
- A match evaluates and copies its scrutinee exactly once before dispatch. Named
  payload bindings copy from that snapshot into immutable, arm-local values.
  Replacing the original enum in the arm cannot change a previously bound value.
  `_` ignores a field without introducing a binding.
- Value parameters, returns, assignments, arrays/records containing enums,
  borrowed enum parameters/slices, nested matches, early returns and continuing
  arms retain the existing frontend and C-backend rules.

Each compiler-private enum struct contains a declaration-index tag and, when
needed, a union of per-variant structs. Generated member names use numerical
positions, not user spellings. Constructors initialize only the selected payload
member; match cases read only the matching member. Whole-value copies retain
that member's value. No equality, binary serialization, layout, padding-byte,
size, tag or ABI stability is promised. Raw pointer payloads do not provide new
lifetime or provenance guarantees; dereferencing still requires explicit unsafe.

## Boundaries retained

The unchanged frontend rejects linear resources and capabilities in payloads,
invalid payload types/arity, nonexhaustive or duplicate arms, binding shadowing,
mutation of bindings, escaping bindings, effect violations, and enum exposure
through C exports, extern signatures or repr(C) records.

Generic enums/functions/records, builtin Result, Unit payloads, zero-length and
Unit-element arrays, unsized owned slices, recursively defined C layouts, unions
and existing unsupported runtime types remain outside this bounded C backend.
No resource-payload ADT, new runtime allocation, scheduler, recursive execution,
foreign-layout support or general borrow/lifetime model is added. This change
alters only `hepta/c_backend.py` production logic.

Two inherited refusal fixtures now use a Unit payload rather than a newly
supported integer payload. The fieldless fixture's method name and frozen ID are
updated accordingly. All other inherited tests/assertions are preserved.

## Reproduction and qualification

From the repository root with Python 3.11 or newer and native GCC:

```
python -m hepta run examples/payload_enums.hepta --backend c
python tools/validate_c_payload_enums.py
python tools/qualify_c_payload_enum_oracle.py
```

The strict runner freezes 215 unique methods: 17 new payload methods plus all
198 inherited fieldless, C backend, parser/checker, ADT and cross-feature methods.
It requires exact planned/started/finished/passed identity equality, no skips,
expected failures or unexpected successes, and unchanged compiler/test/example/
runner/inventory input hashes. This is not the full project gate.

Twelve new native consumer methods compile/execute C at both O0 and O3 with
nonrecovering UBSan. A thirteenth executes the actual public CLI example. Tests
cover 73 independently generated variants with zero to four fields, mixed scalar
payloads, nested arrays/records/enums, copies across variant changes, ignored
fields, constructor and scrutinee effects, module aliases, borrowed slices,
source replacement, arm scopes and loop continuation. Four new refusal methods
retain unsupported-type, frontend, C ABI and conservative borrowing boundaries.
The twelve direct consumers also invoke the Rust frontend emitter; emission
alone is not native Rust qualification. The public CLI example uses C only.

The independent supplemental oracle uses Python-generated expected values,
including seeded payload/variant/copy cases, and native O0/O3 executions. Its
results and source/tool identities are emitted as JSON, not used to authorize
unsupported programs or foreign representation assumptions.

Set `HEPTA_ENUM_REQUIRE_RUST=1` and `RUSTC` to an actual pinned Rust 1.90.0 binary
to require native Rust comparisons at both optimization levels. The read-only
exact-head workflow requires this mode on Linux x86-64 and ARM64 with Python
3.11/3.13. Missing setup or a queued job is not a pass. Hosted results must be
checked for the exact payload PR head rather than inherited from #700.

## Evidence limits

Local GCC 14.2.0 validation uses the qualified x86-64 data model. Native Rust and
ARM are not available locally and have not been executed. Finite native execution
and UBSan do not prove full backend equivalence, whole-language type/memory
soundness, arbitrary unsafe input correctness, performance superiority, public
ABI qualification or release readiness. No merge, release or deployment follows
from this draft.

Local strict gates pass 215/215 methods with zero skips on Python 3.12.14 and
3.13.5. The independent oracle passes all six C executions on each Python
version: 120 seeded cases plus two ordered-evaluation/copy adversaries at each
optimization level. Its missing-required-Rust negative control exits nonzero.

The final 17-method suite against unchanged #700 production reports 11 lowering
errors, three failing methods and three passes. The module/CLI failures reflect
parent payload refusal; the borrow failure reflects that same earlier refusal
instead of the now-reachable conservative borrow diagnostic. Initial new test
fixtures had three mistakes (an expected diagnostic spelling, a default i64
loop value supplied to i32, and a missing explicit unsafe block); those tests
were corrected before the final gates. Earlier failures are not final passes.

Independent review also caught the renamed inherited test ID left in its old
alphabetical inventory position. The 198-ID parent inventory is regenerated in
actual discovery order, and both the inherited 198-method gate and new 215-method
gate are rerun. The new runner also hashes the inherited runner/inventory and
independent oracle source to preserve these qualification inputs.
