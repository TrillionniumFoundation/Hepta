# Sequential scalar Core proof chain

`tools/qualify_hia_sequential_core.py` binds the existing normal-return and
actual LLVM translation validators to one exact primitive Core. It recomputes
both obligations for **every public scalar export**; there is no caller-supplied
receipt and no option to omit a failing export. The emitted LLVM is retained and
its actual instructions, branches, guards and reachable callees are parsed by
the existing independent lowering checker.

## Quantifiers and limits

| Property | Quantifier and evidence | Remaining trust or exclusion |
| --- | --- | --- |
| Register reads and total execution of the abstract straight-line register model | Generic Lean theorems in `formal/HiaRegisterSafety.lean` quantify over every well-formed program in that mathematical model | This is not a proof of the production verifier, exporter, LLVM, or ownership |
| Normal return of the selected Core | Fresh Z3 query for every typed input of every selected public scalar export; reachable direct callees use their original bodies under actual caller path conditions | Acyclic scalar CFG/call profile, with existing function/block/operation/expansion limits; verifier and symbolic encoder remain trusted |
| Value and abort preservation for actual emitted LLVM | A separate fresh Z3 query parses the emitted internal functions and compares them with the selected Core, including poison conditions | Actual LLVM internal-body profile only; encoder/parser and Z3 remain trusted; native machine code and ABI are outside the proof |
| Composed normal return without LLVM abort or poison | Both obligations must pass for the same Core, same function and exact emitted LLVM digest, for every public scalar export | Per-artifact translation validation; not a generic soundness theorem for every legal Core program |
| Owners, loans, external resources and concurrency | No composed claim | Existing resource verification and separate abstract ownership theorems do not become implementation refinement proofs through this tool |

The distinction is between a bounded **program shape** and an unbounded choice
of values within each declared machine type. The input check is not a finite
random sample. For example, each two-`u32` export in
`formal/selected_sequential_u32.hia.json` has `2^64` possible argument tuples.
The query covers those tuples, but does not establish a theorem for all
programs with that signature.

The selected module contains a private, potentially trapping unsigned division
helper and a public caller that checks a zero denominator. The caller can be
total without claiming the private helper is total on every possible argument.
Exporting that helper creates another independent obligation and fails with a
replayed division-by-zero counterexample. The second public export performs
wrapping arithmetic. Its proof cannot be used to hide a trap in another export.

Normal return refers to the mathematical program semantics. It does not promise
that a host will never exhaust memory, kill a process or stop at a runtime quota.

## Proof identity and deadlines

Primitive scalar totality now identifies the pinned Z3 binding and actual loaded
library, hashes the checker, opcode catalog, schemas, symbolic semantics and VM
replay implementation, and checks their identities again before accepting SAT
or UNSAT. Both totality profiles and the composed source lock include the
extracted `hia_capability_flow.py` rules used by the canonical verifier. A byte
change in that dependency during a proof invalidates the result even when the
solver has returned UNSAT. The deadline covers source checking, encoding, solving, replay and
final identity checks. A late result is `unknown`, even if the solver returned
UNSAT. The deadline rejects late evidence; it is not a hard process timeout.

The compound checker also uses a single overall deadline across exports and
both proof stages. Source drift, unknown solver results, invalid profiles,
incomplete paths, failed replay, empty exports and incomplete evidence leave
all composed claims false. Partial successful rows remain visible for diagnosis.

The result always leaves `all_legal_programs_proved`,
`all_programs_in_profile_proved`, `verifier_or_encoder_refinement_proved`,
`ownership_or_resource_safety_proved`, `native_machine_code_or_c_abi_proved`
and `execution_authority` false.

## Reproduce

Use the repository's pinned Z3 4.15.4 environment:

```sh
python -m unittest tests.test_hia_scalar_totality tests.test_hia_sequential_core -v
python tools/qualify_hia_sequential_core.py \
  --core formal/selected_sequential_u32.hia.json \
  --output /tmp/hepta-sequential-proof \
  --timeout-ms 10000
```

The output directory must be new. It contains the canonical `core.hia.json`,
actual `program.ll`, `qualification.json`, retained lowering SMT-LIB queries
and a byte/hash manifest. Totality reports retain the query digest and complete
source/solver identity; rerunning the command recomputes totality from the
exact Core. Lowering queries can also be replayed independently with the
qualified Z3 installation. No saved JSON is accepted as execution authority.

The regression suite checks an added public trapping helper, overflow in a
second export, a changed actual LLVM arithmetic instruction, unrelated
same-shape totality evidence, missing solver proof, implementation drift,
unsupported loops/schemas and an exhausted whole-chain deadline. It also
replays the retained lowering queries with fresh solver instances.
