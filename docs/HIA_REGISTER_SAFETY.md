# Selected register Core: generic safety and an actual rewrite

`formal/HiaRegisterSafety.lean` extends the exact executable model in
`formal/HiaSelectedCore.lean`. The qualification tool concatenates both files
into one pinned Lean kernel input, then adds the actual original and candidate
programs exported from verified Core. This preserves a small, inspectable
proof domain: positional registers, `u32` literals and wrapping addition and
subtraction, in a straight-line program with one result register.

## Proved statements

The generic model defines `ValidOperation`, `ValidCode` and `WellFormed`.
Operands must name registers already available. Each operation appends exactly
one register; a well-formed result lies within the resulting register vector.

| Theorem | Quantification and guarantee |
| --- | --- |
| `read_defined` | Every in-range register read returns a value. |
| `evaluate_total` | Every valid literal/add/sub operation returns a word. |
| `executeOne_total` | A valid operation executes and increases the logical register vector length by exactly one. |
| `run_total` | Any well-formed finite instruction list executes; its final register count is the input count plus instruction count. |
| `execute_total` | Any well-formed selected program returns a word for every argument vector of the declared arity. |
| `read_append_existing` | Appending registers does not change an existing valid read. |
| `dead_literal_preserves` | Appending or removing one final unused literal preserves the returned value of every well-formed selected program. |

These are generic inductive proofs. They do not enumerate the input space.
The existing `run_append` theorem is checked in the same kernel input.

The selected actual source is
`formal/selected_u32_dead_literal.hia.json`. Its five operations add two `u32`
arguments, add and subtract a bias, and create an unused literal. The candidate
removes only that final instruction. The exporter emits both actual instruction
lists and result-register indices, then Lean checks their well-formedness,
their exact dead-literal relationship, total execution, and equivalence for
all **2^64** argument pairs. The resulting positive input has **14 theorem
dependency reports**.

The 272 frozen boundary/seeded pairs from the existing selected-Core protocol
also run through the production Python interpreter for both actual Core
programs. Values and resource ledgers match; the candidate consumes exactly
one fewer VM tick. That observed tick difference prevents interpreting the
value theorem as a proof of quota-stop equivalence.

## Negative controls

The same pinned Lean executable must reject all three controls:

| Mutation | Intended failed theorem |
| --- | --- |
| Change register guards from `< available` to `≤ available` | `evaluate_total` |
| Change the appended program's result register by one | `dead_literal_preserves` |
| Change the actual candidate's first wrapping addition to subtraction while retaining the source | `source_is_dead_extension` |

The last mutation is a different, still well-typed actual Core candidate. It
is independently verified and exported; the proof fails because the emitted
source/candidate relation no longer holds. The input tests also reject an
actual forward reference and a final literal that is returned rather than
unused. Retained-report tests reject a missing control, changed Core identity,
inflated claims, boolean/integer substitutions and a reduced execution case
denominator.

No unpinned executable, missing Lean installation, skipped mutation or failed
kernel invocation produces a passing qualification. The unit-test module can
be used without Lean for input-boundary development, but that mode has no
theorem evidence. Formal acceptance uses the required `--lean` command below
or runs the full suite with `LEAN` set to the pinned executable.

```sh
python3 -B tools/bootstrap_verification.py --lean-only --directory /tmp/hepta-tools
python3 -B tools/qualify_hia_register_safety.py \
  --lean /tmp/hepta-tools/lean-4.19.0/bin/lean \
  --output-directory artifacts/hia-core-contracts-20261030/register-safety
LEAN=/tmp/hepta-tools/lean-4.19.0/bin/lean \
  python3 -B -m unittest tests.test_hia_register_safety -v
```

## Guarantee boundary and trusted components

| Stage | What this increment establishes | Remaining guarantee gap |
| --- | --- | --- |
| Hepta/C/C++ source | No new source-level theorem | Source-to-Core correctness, migration semantics and foreign behavior remain separate. |
| Actual primitive Core | Canonical verifier reruns on both programs; instruction/result mappings and exact bytes are retained | Python verifier soundness and exporter refinement are not proved. |
| Selected mathematical Core | Generic register safety, total execution, exact logical growth and dead-literal value preservation; selected actual mapping checked for every argument pair | Owners, views, memory effects, loops, traps, FFI and concurrent programs are outside the model. |
| LLVM/backend | No new backend theorem | Lowering and optimization refinement need separate validation. |
| Machine artifact | No machine-code theorem or native execution claim | ABI, native resource use, hardware behavior and faults need target-specific evidence. |

The kernel executable must match the repository's pinned Lean 4.19.0 binary
hash. The source manifest includes the Core checker, shared opcode catalog,
schema, parser preflight, runtime, both formal files and exporter/qualification
code. The retained support manifest covers the imported Lean modules and
shared runtime. All are checked for drift during qualification. The allowed
proof dependency inventory excludes placeholders in positive proofs.

The selected mathematical machine terminates because its instruction list is
finite and its well-formed arithmetic operations are total. This statement
does not imply termination of general Hepta programs. Logical register length
also does not measure interpreter objects, allocator overhead, native stack
bytes or process RSS. Evidence replay checks retained observations and fresh
Core mappings; it is not a cryptographic attestation of a hostile producer or
host.

The independent `tools/qualify_hia_catalog_compatibility.py` additionally
compares finite primitive-Core acceptance against the pinned #399 checker.
That regression comparison helps detect semantic loss during catalog
integration and retains a separate `verifier_semantic_equivalence_proved: false`
claim.
