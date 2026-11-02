# Trusted Core convergence and P0–P7 acceptance

This increment builds on PR #550, source
`d55ea70cf854428f30c2ba7e044741f5f379a419`. It repairs bounded admission and
selected lowering verification in the existing compiler. It does not establish
whole-language soundness, broad performance parity or production qualification.

## Existing execution authority

`python -m hepta hia routes` publishes the current compatibility inventory.
Its metadata does not grant admission. The implementation remains authoritative:

| Input | Explicit conversion | Executable admission |
| --- | --- | --- |
| Primitive HIA v1–v8 | Version-selected grammar | `hia_program.verify_program` |
| Composite v1 / v2 / v3 / v4 | Checked nominal elaboration to primitive v6 / v7 / v7 / v8 | Same verifier after elaboration |
| Hepta source | Fresh source checking, finite specialization and typed CFG lowering | Same verifier on resulting Core |
| Legacy executable / scalar Core | Source-bound checked adapter | Same verifier on resulting Core |
| Historical ambiguous nominal-v2 | Explicit `import_legacy_composite_v2`, checked before and after conversion | Same verifier on primitive output |
| HSIR / HMIR / Resource IR alone | No standalone executable admission | Reject as standalone HIA input |

`hia_schema.py` retains the existing v6 canonical compatibility target and v8
latest primitive feature profile. These are reviewed versions of the same
execution family. Relabeling all inputs `hia.core.v1` would erase compatibility
information. Existing old-version adapters retain their fixed targets and do
not acquire new instructions implicitly. The independent Rust byte-DAG profile
has explicit limited admission and cannot mint default Python or native authority.

## Repairs in this increment

1. **Cached ownership verdicts bind live class behavior.** A changed returned
   loan origin must recheck callers even if interface equality is replaced.
   Class methods, descriptors, inherited hooks and function defaults enter the
   local dependency snapshot. A mismatch falls back to the full checker; failed candidates do
   not replace the previous accepted base. This is cache invalidation under
   the declared dependency contract, not arbitrary process-code attestation.
2. **Source record scalarization uses the Core layout limits.** Nested and
   unused declarations cannot expand without the existing depth and flattened
   field bounds. Depth-aware memoization also bounds repeated zero-width
   layouts. Cycles and unsupported shapes retain explicit refusal.
3. **Selected scalar lowering proof work is charged before expansion.** Core
   and LLVM symbolic lanes each share a budget across paths and recursive
   calls. The whole-call deadline bounds symbolic work and the remaining SMT
   check; late solver results do not become verified receipts. This is a
   cooperative resource bound, not an OS hard-preemption guarantee.

Each defect has a retained failing-parent regression. The targeted tests use
small limits or controlled method changes; they do not require an exponentially
large input or an actual resource-exhaustion event.

## Current strict stage boundaries

| Stage | Foundation to reuse | Evidence still required for full closure |
| --- | --- | --- |
| P0 | Shared version/opcode registry, explicit adapters and checked routes | Complete historical producer/consumer census and source correspondence across the admitted scope |
| P1 | Typed ownership/effect verifier, returned-loan checks and limited formal models | Independent production type/ownership soundness and source-to-Core refinement, including memory and failure paths |
| P2 | Direct LLVM and scoped native/target execution | Physical x86-64/AArch64 qualification and each claimed platform's bidirectional C ABI |
| P3 | Existing C/C++ project capture, implementation migration and scoped foreign routes | Unseen third-party upgrades, behavior/lifecycle differential tests and recorded human effort |
| P4 | Finite candidate proposals and deterministic translation/lowering checks | Composed refinement evidence and independent application workloads against strong Rust/C++ baselines |
| P5 | Existing native NDU, fixed/DP baselines and cost ledger | Positive total lifecycle savings after decision, search, preparation, residency, reuse and failure costs |
| P6 | Existing task registration, hidden evaluation and Agent cost accounting | Actual unseen engineering completions, independent correctness and complete per-success costs |
| P7 | Existing artifact custody, generation fences and controlled recovery checks | Durable crash/restart and rollback qualification at the final authorization boundary |

All eight complete stage gates remain open. The prior #550 strong-Rust
observation on `d55ea70` passed 45/60 comparisons and failed its broad parity
gate. It is a source-specific historical observation, not a result for this
increment. No NDU or Agent benefit follows from these correctness repairs.

## Reproduce the scoped checks

Use a clean committed checkout, pinned Z3 4.15.4, Clang 20 and an explicitly
recorded Rust toolchain. Supply native tool paths through the existing
environment variables and keep build/evidence directories outside the checkout.

```sh
python -B tools/qualify_hia_three_lane.py --suite trusted-core \
  --output /absolute/outside-checkout/trusted-core.json
python -B tools/qualify_hia_three_lane.py --suite core-consistency \
  --output /absolute/outside-checkout/core-consistency.json
cargo test --locked --manifest-path rust/hia-core-shadow/Cargo.toml
```

The two Python receipts enumerate exact planned, started and completed test
identities, bind source commit/tree and reject skips or source drift. The
broader consistency suite is retained separately, including environment errors;
a focused passing suite cannot replace its result. The existing CI workflow
runs both suites on the same exact checkout and preserves their raw logs.
