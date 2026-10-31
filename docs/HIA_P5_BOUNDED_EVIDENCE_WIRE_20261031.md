# HIA P5/P6 — bounded immutable evidence text intake

## Scope and source

Stacked directly on Hepta PR #457 at `5b895342d6d0c8c9a4e8d68147ac619ebef20dcb`, before any claim of
independent native NDU economic advantage. This is one narrow admission
hardening: three report/registration readers accepted immutable built-in text
and executed `raw.encode("utf-8")` BEFORE testing their registered byte limit.
An oversized string can therefore allocate a large full-wire temporary before
its rejection; this circumvents the intended pre-admission resource budget.

## Bounded fix

Introduce `hepta.hia_bounded_wire.checked_utf8_wire`: exact built-in string
type, exact integer budget, codepoint-count early refusal, ASCII path, and exact
UTF-8 counting in ≤4096-codepoint chunks (maximum 16 KiB temporary per chunk).
Only after successful size admission is the complete immutable wire encoded.
Malformed surrogate text remains a refusal in the original module's error
domain. Byte inputs, canonical digests, existing cost and sign-test math,
registration identities, reported observations, and `DENY_ALL` authority are
unchanged.

The three hardened entry points are:

- `hepta/hia_full_cost_gate.py::_wire` (262,144 bytes).
- `tools/hia_native_process_observer.py::_parse` (262,144 bytes).
- `hepta/hia_native_paired_replay.py::_read` (8 MiB).

This is a **wire-admission** fix; no claim is made about complete process RSS,
unverified external costs, independence of tasks, source/native refinement,
multi-process observation, or the sign test establishing future value.

## Actual qualification requirements

```sh
python -B -m unittest tests.test_hia_bounded_research_wire tests.test_hia_full_cost_gate tests.test_hia_paired_holdout -v
python -B -m unittest tests.test_hia_native_process_observer tests.test_hia_native_paired_replay -v
```

The new suite must reject oversize non-ASCII strings before full-wire
allocation (traced peak of the *rejecting size helper*, not whole program),
retain source/input digest equality between text and bytes, reject invalid
surrogates and untrusted text/object types, and preserve `DENY_ALL` even on
a synthetic positive input. Existing real C ELF controls must pass without
removing failures, missing costs, or measurement identities.

## P0–P7 acceptance boundary

This neither closes P5 nor any other production stage. HIA P5 still requires
prospective genuine HIA/Rust/Clang/NDU matched tasks, independently verified
cost receipts, non-overlapping heldout tasks, actual complete cost and rigorous
positive evidence over fixed/DP controls. Prior NDU full-cost comparisons were
negative. P0, P1, P2, P3, P4, P6 and P7 remain open under their own exact
semantic, proof, ABI, migration, runtime, Agent and physical-host gates.
