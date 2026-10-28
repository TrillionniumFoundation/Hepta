# Explicit normal-return admission for native scalar generations

`ScalarMultiversionRuntime(..., prove_total=True)` selects the new
`hepta.hia.scalar-multiversion-proved-total.linux-x86_64.v1` profile. The default
remains the original syntactically total profile: passing no option continues
to reject trapping-effect declarations and checked division/remainder, even
when a producer says a branch guards their exceptional inputs.

The new opt-in has a narrow purpose. Unsigned `u8` and `u16`
`int.div.checked`/`int.rem.checked` can participate in a total function that
handles every exceptional input before reaching the operation. Other checked
arithmetic, signed or wider division, loops, calls, resources and foreign effects
remain outside this runtime profile. All existing ABI and structural budgets
remain: every function is an exported scalar function, at most 16 functions,
16 scalar parameters and one result, with at most 64 blocks and 2,048 operations
per function. The runtime still executes only on Linux x86-64 with real kernel
memfd sealing.

## Totality and equivalence are separate proofs

The canonical verifier first checks the complete actual program. A new
`hia_scalar_totality.validate_scalar_totality` invocation then uses a fresh Z3
context and the existing finite scalar encoder for each function. Its query is
`outcome_tag != 0`: positive tags are specified traps, negative tags represent
missing symbolic execution paths, and only zero denotes a normal return.
Only UNSAT authorizes normal-return admission. SAT becomes `disproved` only
when the canonical VM independently reproduces the same first trap; a missing
path, disagreement, unavailable solver, timeout or solver unknown stays unknown.

Both the baseline and every candidate pass this fresh check before native
build or probing. Each proof binds the canonical program and original input
digests, function, profile, totality-validator digest and scalar-encoder digest.
The consumer checks exact proof fields and the UNSAT result; imported receipts
are not an admission API. Every exported function is checked, including an
otherwise unused function.

A total candidate still needs the independent all-input equivalence check
against the immutable baseline. A program equivalent to itself may trap, so a
self-equivalence proof cannot establish totality. Conversely, a changed
arithmetic result may be total and must still fail equivalence.

Generation metadata records the admission profile and totality-proof count.
Actual proof receipts are frozen as bytes in the generation and decoded into
detached snapshots. Caller edits to a snapshot cannot alter the admitted
generation or its retained proof record. Conditional publication measures the
fresh totality work inside its existing preparation budget; it retains
cancellation, generation/epoch checks, independent equivalence and sealed
artifact admission.

## Declared example and native checks

The research function accepts unsigned `x` and `d`. It returns `x` when `d` is
zero, otherwise the wrapping sum of `x / d` and `x % d`. A guard may specialize
`d == 16` while preserving the complete generic fallback. The normal-return
proof covers every typed argument, including the state argument when this
runtime is used by `ScalarStateSession`.

`tests/test_hia_multiversion_totality.py` builds and runs real LLVM-native
generations. It exhaustively compares both the baseline and a proved guarded
candidate against an independent integer specification for all 65,536 `u8`
input pairs, and checks `u16` boundaries and fallback values. It also exercises
conditional publication, detached evidence, explicit state across publish and
rollback, malformed/stale/unknown proofs, wrong guards, unused trapping exports,
and rejection before any build for a total-but-behavior-changing candidate.

```sh
python -m unittest tests.test_hia_scalar_totality \
  tests.test_hia_multiversion_totality -v
```

The encoder, solver, native compiler/loader, Python host and operating system
remain trusted. A total Core does not prove LLVM/native refinement, physical
execution time, whole-language soundness or profitable optimization. The
benchmark protocol and its actual source-bound timing evidence must establish
performance separately; enabling this profile does not assert a speedup.
