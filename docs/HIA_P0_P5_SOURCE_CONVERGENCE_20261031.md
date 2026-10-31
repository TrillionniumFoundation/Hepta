# HIA P0/P5 precise two-parent source convergence (2026-10-31)

## Source authority and merge mechanics

Base: HIA #418 `3201298a9828927452d42bcac146e610e1348a7f`.
P0 parent: `29246ef7fae6277a29f1712c352eec8f6d1e6a4f` (#458 plus #459): immutable caller snapshot and bounded UTF-8 input.
P5 parent: `33d989298adbf5923bef164bd3aa17224b105428` (#455/#456/#457/#460): full-cost arithmetic, real Linux ELF observer, exact paired evidence and bounded evidence input.

This merge is based on GitHub exact tree objects rather than path-only cherry picking:
- P0 vs #418: seven paths, one modified `hepta/hia_program.py` plus six additions.
- P5 vs #418: **20 purely added** paths.
- Zero overlapping names, deleted paths or renamed names. Every P5 file inherits its exact source Git blob identity.
- Two actual Git parents retained. No reimplementation, reinterpretation or source replacement.

## Independent qualification

```sh
python -B -m unittest tests.test_hia_bounded_input_utf8 tests.test_hia_bounded_mutable_snapshot tests.test_hia_program tests.test_hia_json_preflight tests.test_hia_program_composite -v
python -B -m unittest tests.test_hia_opcode_catalog tests.test_hia_agent_assembly tests.test_hia_register_safety -v
python tools/generate_hia_catalog.py --check
python -B -m unittest tests.test_hia_bounded_research_wire tests.test_hia_full_cost_gate tests.test_hia_paired_holdout -v
python -B -m unittest tests.test_hia_native_process_observer tests.test_hia_native_paired_replay -v
```

Dedicated scoped GitHub workflow reruns every suite against the **merged source**. Earlier parent successes cannot be substituted for final merged-source receipts. The standalone Rust shadow, LLVM/native and real C/C++ release qualifications are independent release gates.

## No false promotion

All HIA P0-P7 production stages remain **OPEN** pending exact final source safety, refinement, Rust/LLVM/ABI and resource qualification. Existing native NDU full-cost disadvantages are preserved; no real positive NDU benefit, independent observation attestation, task-general Agent productivity gain, or production activation is claimed.

Authority: `DENY_ALL`. Safety certificate: `false`. Activation: `false`.

## First integrated run and scoped Lean corrective action

Exact merged commit `4929f9261e487702f2b6fd32b38d06e85ce1caa4` completed
[the scoped integration run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41182461635)
successfully: Core/intake 64 tests passed, catalog/assembly/register 36 completed
with **2 intentionally skipped Lean-only methods**, and cost/native 21+13 tests passed.
The two skips **are not** theorem qualification; do not silently relabel the job as
P1 proof passing.

The successor integration workflow explicitly runs `RegisterSafetyInputTests`
(no bypass/skip) and a *separate, nonoptional* pinned Lean 4.19.0 job. Its
`formal/toolchain-lock.json` archive and executable digests must match,
the original selected Core and optimized Core must pass the Lean kernel,
three independently mutated candidate obligations must fail as expected,
and 272 actual interpreter comparison cases must be retained. The exact
source and formal dependency hashes and positive/negative evidence
are uploaded as independent artifacts. A network/toolchain failure
remains a failed or incomplete gate; no synthetic/local-only fallback.
The formal theorem is limited to the selected straight-line wrapping u32
register machine. This **does not** prove general provenance, owners, FFI,
LLVM/native semantics, or whole-language safety.
