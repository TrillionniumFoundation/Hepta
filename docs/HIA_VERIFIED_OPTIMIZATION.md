# Verified optimization over the standalone HIA core

This increment supplies an executable transformation validator, a native
publication boundary, and an explicit route inventory. It does not establish
whole-language soundness, arbitrary C/C++ equivalence, LLVM refinement, a globally
optimal compiler, or a performance advantage over Rust.

## One executable admission path

`hepta hia routes` prints `hepta.hia.routes.v1`. The inventory distinguishes:

| Input or consumer | Actual path and boundary |
| --- | --- |
| Primitive HIA v1–v7, composite v1–v2 | Existing canonical `verify_program`; composite normalization is rechecked |
| Finite Hepta source | Checked AST to explicit standalone value/resource CFG |
| Historical executable core v1 | Authenticate original source, decode actual operations, lower and reverify |
| Historical scalar core v0 | Authenticate original source/path/project, translate actual SSA and PHIs, reverify |
| Historical nominal v2 spelling | Explicit legacy adapter only; no ambiguous automatic schema inference |
| C / C++ migrators | Each declared migration profile produces Hepta or HIA; the actual result must pass standalone admission |
| Rust / TypeScript / Python / Go / assembly source | No implemented source frontend; reject as executable HIA input |
| HSIR / CFG / SSA exports | Only supported through the authenticated historical scalar envelope |
| Resource IR / Concurrent IR / HMIR exports | Side-condition or structural descriptions; not independently executable value semantics |
| Standalone interpreter / direct LLVM | Consume the same reverified HIA bytes |
| Source Rust / source C / old owned LLVM | Explicit existing source backends; never implicit standalone fallback |

`admit_route` executes these finite adapters and ends in the same core checker.
Route metadata never authorizes execution. The CLI's source and historical
import paths now share this dispatcher. Unsupported features still fail in
their actual adapters; inventory inclusion does not widen their profiles.

## Transformation contract

Install the explicit optional dependency with
`python -m pip install -e '.[optimization]'`. The qualified profile uses
`z3-solver==4.15.4.0` (Z3 reports `4.15.4`). A missing or different solver cannot
produce a verified optimization.

The public entry point is:

```python
verify_optimization(base, candidate, policy=None) -> dict
```

Both inputs are independently admitted. The supported transformation preserves
the complete module interface, function signatures, CFG edges, block parameters,
terminators, and ordered resource/call operations. Scalar instructions between
these barriers may change. The candidate cannot simply assert input assumptions;
nonempty caller-supplied preconditions are rejected by this profile.

For each scalar segment, an independent bit-vector encoding asks whether any
finite-width input can change either the first trap or the scalar arguments
observed by the next effect, call, branch or return. Only UNSAT discharges that
obligation. On successful identical barriers, scalar outputs are shared fresh
symbolic values. Input and effect-output symbol namespaces are disjoint even
for adversarial source identifiers. Every proof request also owns a separate Z3
Context, including constants, empty disjunctions and the Solver. Concurrent
agent requests do not manipulate Z3's unsafe shared default Context.

This compositional check admits unchanged loops and resource programs without
unrolling a whole execution or pretending to prove arbitrary loop rewrites.
It is conservative: unreachable scalar states and untaken branch arguments
may create obligations that a more sophisticated verifier would not need.

The encoder models every admitted scalar instruction, including checked and
wrapping arithmetic, signed truncation-toward-zero division and remainder,
signed-minimum divided by minus one, shift-count traps, casts, Boolean logic,
comparisons and selection. Equal numeric results alone are insufficient:
swapping an overflow with a divide-by-zero trap is rejected.

The versioned receipt contains actual base and candidate hashes, structural
preconditions, target constraints, each SMT query and its digest, counterexamples
or solver-unknown reasons, operation/obligation/deadline budgets, resource
inventories, checker identity and the actual loaded SMT library identity.
Successful equivalence checks preserve allocation/refusal order and modeled
peak live bytes. VM instruction ticks, compiler cost and native runtime cost
are explicitly separate. The default policy is:

```json
{
  "schema": "hepta.hia.optimization-policy.v1",
  "target": "x86_64-unknown-linux-gnu",
  "timeout_ms": 5000,
  "max_scalar_operations": 4096,
  "max_obligations": 1024,
  "preconditions": []
}
```

The deadline is an admission deadline: a result arriving after it cannot be
verified. It is not an operating-system kill guarantee for all Python parsing or
symbolic-expression construction. The existing bounded core parser and explicit
operation/query limits also apply.

## Four outcomes, one deployable proof status

| Outcome | Meaning | Native candidate publication |
| --- | --- | --- |
| `verified` | Every supported obligation returned UNSAT before the deadline | May proceed through independent build and byte binding |
| `rejected` | Invalid core or a concrete semantic counterexample | Refused |
| `unknown` | Unsupported structure, absent/wrong solver, exhausted proof budget, or inconclusive solver | Refused |
| `timeout` | Admission deadline or solver timeout | Refused |

`fold_constants` is an untrusted proposer. It evaluates constant operations
through the existing interpreter and never uses the SMT encoder as its own
oracle. Its output still needs independent equivalence validation. The first
candidate set deliberately does not claim novel machine-code optimization:
LLVM can already fold many of these expressions.

```sh
hepta hia verify-optimization baseline.json --candidate proposed.json
hepta hia fold-constants baseline.json --output folded.json
hepta hia build-optimized baseline.json --candidate folded.json \
  --clang clang-20 --output candidate.so
```

`build_optimized_native` freezes caller-owned documents before proving them,
rechecks the actual candidate, builds through the existing LLVM authority, and
binds the final artifact to the base/candidate/proof/compiler/target identities.
It stages output until all checks succeed, uses no-replace publication, rereads
the exact bytes and withdraws only its own link on a failed final check. A JSON
receipt or a caller-provided hash is never accepted in place of this work.

The returned native receipt remains compilation evidence. Native execution,
ABI/platform qualification, performance, and runtime selection are separate
gates. Arbitrary external native libraries cannot acquire safety by wrapping
them in this receipt format.

## Allocator contract exposed to LLVM

The existing native runtime already requires `malloc`/`calloc` to return null or
fresh storage disjoint from other live allocations. Their LLVM return values now
carry `noalias`, matching LLVM's documented allocator-like return contract:
<https://llvm.org/docs/LangRef.html#parameter-attributes>.

Call-site `nobuiltin` and declaration `"no-builtins"` remain, as do all nullable
and allocation-failure paths. This change does not add `nonnull`, memory-effect,
allocation-family or allocation-size attributes that could remove observable
allocation attempts. Native failure injection and allocation/free observers are
regression gates. In the two registered benchmark kernels this annotation alone
produced identical final native bytes; no speedup is attributed to it.

## Validation and remaining trusted components

`tests/test_hia_optimization.py` checks all integer widths, counterexamples,
first-trap ordering, resource arguments, changed resource paths, loops, actual
allocation refusal, exhaustive 8-bit cast inputs, independent interpreter/SMT
boundary comparisons, adversarial symbolic names, deadline/unknown handling,
real native execution, producer mutation after proof, publication refusal
after checker drift, and an isolated four-thread actual solver regression.
`tests/test_hia_routes.py` executes source and historical
imports through the shared value/resource authority and exercises CLI refusal.

The Python verifier/encoder, pinned solver, native compiler/linker/loader,
runtime allocation contract and hardware remain trusted. SMT UNSAT over this
model is not a machine-checked proof of that model or of the LLVM backend.
Different CFGs, memory-layout rewrites, loop interchange, vectorization proofs,
foreign pointer provenance and general state migration remain unsupported.
