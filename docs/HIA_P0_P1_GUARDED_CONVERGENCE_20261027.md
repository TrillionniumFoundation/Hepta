# HIA P0→P1 guarded convergence: v1–v6 scoped-heap proofs atop v7

## Exact-source integration

- Recipient PR #276 HEAD: `ff484bbb3c381a46dd7ceefc0e1923720fbcfd8c`,
  itself based on v7 integration PR #210.
- Donor PR #278 HEAD: `64645ceb8f0158e97d06926d02296cf07494bdf8`.
- Direct donor Git blobs of `hepta/hia_heap_bound.py`, three scoped/zero
  heap test files, and the reviewed scoped integer SSA document are inserted
  **unchanged**. No full donor branch merge, new verifier, AST, LLVM emitter,
  language schema, or Rust runtime is introduced.
- The public `analyze_constant_live_heap` entrypoint body is byte-identical
  between the recipient pre-integration and the donor. New helper semantics
  include the strictly gated zero-heap/scoped-cyclic profile, reviewed bounded
  interval transfers and a separate requested-live-payload-only admission API.

## The nonnegotiable v7 boundary

The executable v7 registry (`hepta.hia_schema`) and independent canonical
`verify_program` remain the admission authorities for v7 execution. The
converged heap analyzer deliberately retains
`_ALLOWED_SCHEMAS = {hepta.hia.program.v1..v6}`.

A fully valid v7 program, even one whose operations are byte-equivalent to an
older admitted profile, is **refused** by this resource-budget analyzer with
`E_HIA_BUDGET_UNBOUNDED`. v7 chains, composite v2 and new resource semantics
need an explicit new accounting proof before budget admission. This is not an
execution ban or proof that the v7 language is invalid; it is a strict
version-limited resource claim.

## Runnable regressions

```sh
python -m unittest tests.test_hia_zero_heap_loops \
  tests.test_hia_scoped_alloc_loops \
  tests.test_hia_p0p1_v7_guard -v
python -m unittest tests.test_hia_heap_bound tests.test_hia_heap_intervals \
  tests.test_hia_static_budget -v
python -m unittest tests.test_hia_scoped_alloc_native -v
```

The native scoped-loop test requires the reviewed Clang/LLVM runtime and
must not silently skip an unavailable compiler when claiming native parity.

**Validation status:** exact donor and recipient Git blobs, program entry
symbol identity and v7 refusal guard were reviewed before this integration;
the complete recipient checkout could not be cloned in the current container
(GitHub DNS resolution unavailable). Thus these committed full-repository
tests and v7 native integration have NOT executed on the new exact HEAD.

## Remaining blockers

- P0: integrate remaining HSIR, HMIR and Resource IR producers/consumers.
- P1: general v7 chains, cross-block owner/loan and provenance/Memory SSA,
  complete error-path resource accounting and verified bounded-loop transfers.
- P2: standalone Rust/LLVM/VM parity on one shared Core, real exact-head
  execution, source→native refinement.
- P3–P7: independent ABI and C/C++ migration matrices, held-out Agent A/B,
  sustained/hardware performance and formal production qualification.

`whole_project_blockers_closed=false`.
