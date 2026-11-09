# Scoped proof/adoption and selfhost feature evidence

This development-source change makes the retained adoption identity explicit
and fills two previously unexecuted qualification paths. It does not change
either public release lock or activate the configured online runtime.

## Same-artifact adoption

`hia_adopt` retains an additive `artifact_identity` projection after its existing
build, proof, workload, ABI and generation checks. The projection binds the
canonical Core/input, canonical lowering or exact Agent plan, original object,
final ELF, target/backend, ABI signatures, proof subjects/profiles, installation
and adopted generation. It grants no authority independently of the retained
runtime state. Verification, evaluation and adoption still consume the original
bytes; they do not manufacture proof inputs by recompiling them.

The canonical and explicit-plan regression paths pass together with all existing
native machine-validation and native tool tests: **49 tests**. The selfhost
support contract changed only its digest for the modified service source.

## Three closed scalar instances

Run:

```sh
python -B tools/qualify_hia_scalar_proof_adoption.py --output /absolute/new-evidence
```

The program specification is `((x+y) mod 2^w) XOR (2^w-17)` when
`x < 2^(w-1)`, otherwise `((x-y) mod 2^w) AND (2^w-17)`, for the three
closed instances `w=8,32,64`. Each has two scalar inputs, a real conditional
branch, distinct block parameters and unsigned modular arithmetic.

All three completed the pinned worker protocol, Core admission, direct shared
ELF build, five independent-model SMT obligations, complete frozen-workload
evaluation, conditional local adoption and cold-process consumer operations.
Each instance made eight actual native calls from an acquired generation-1
lease after rollback; future acquisitions observed generation 0. Original
adoption replay was identical; released leases were rejected. There were 39
cold consumer operations and 24 finite consumer observations in total.

Each proof quantifies all typed inputs for its exact Core/object/final ELF in
the existing independent Core/x86/ELF model. The consumer observations are
finite host evidence. Python model and solver soundness, the caller/stack/loader
contract and complete hardware ISA refinement remain assumptions or open
obligations. This is not a kernel-checked whole-compiler theorem or a proof of
owned-resource lifetime preservation. No production adoption occurred.

The exporter reads and hashes server-issued artifacts recursively, including
the original Core, object, final image, proof records, assumptions, SMT queries,
evaluation and cost ledger. It retained 53 issued references per instance.
Private local authority databases are excluded from the published archive.
External model fees and full economic cost remain incomplete.

## Actual selfhost feature matrix

The new [matrix](HIA_SELFHOST_FEATURE_MATRIX.md) passed **9/9** registered
witness expectations after real B0→B1→B2→B3 compilation; B1/B2/B3 bytes match.
Unsigned CFG/call and owner-argument/scalar-return examples executed native
code. Signed helpers, scalar multiple results, returned owners/loans, general
helper names, a general module name and the combined naming/pair witness remain
valid Core rejected by the bootstrap compiler. This measures present support;
it does not implement those seven extensions.

The initial matrix attempt refused a stale contract while another edit was in
progress. Its failed record is retained separately. After normal contract
regeneration, the successful attempt verified unchanged source closure before
and after execution. The failed attempt is not relabelled.

## Acceptance boundary

| Priority | Executed result | Still open |
| --- | --- | --- |
| P1 | Explicit same-artifact adoption identity; canonical and exact-plan tests pass | Full compiler-buffer independent native refinement and production adoption |
| P2 | Exact-entry, actual bootstrap/native acceptance matrix 9/9 | Implementation and combination qualification of the rejected extensions |
| P3 | Three nontrivial closed instances with all-input model proof and actual adopted consumers | Mechanically checked model/ISA/loader/resource theorem chain |
| P4 | No new performance-win assertion | Real hotspot gain against strong baselines, tails and amortization |
| P5 | [Paid observation mechanism](HIA_PAID_OBSERVATION.md), complete 30-cell pilot | Trained/native NDU, independently blinded real tasks and incremental utility |

Original reports, archives and test logs are indexed in
[the evidence directory](../review-evidence/hia-proof-matrix-20261109-3977/README.md).
Local runs used Python 3.12, Z3 4.15.4 and jsonschema 4.26.0. The new hosted
workflow pins jsonschema 4.25.1 and Z3 4.15.4.0 and repeats all three
qualifications on its exact source commit; hosted success must be reported
separately from these local observations.
