# Six-track convergence, 2026-10-30

This work joins the actual catalog branch at
`192d2cbba7e49bde3b03af73685ecf96f6fb1b05` and the P0-P7 branch at
`953fa62dee5aa563551d57b1374ab95b6d548b45`. Their common ancestor is
`2cc9fb3b92a7306d2f5aae316c99e8364be700f9`. Historical evidence keeps its
original source identity; it does not qualify the merged implementation.

## Merge decisions

- Preserve the catalog branch's central opcode contract, generated catalog,
  route checks, immutable VM invocation, native-child cleanup boundaries and
  all safety selectors.
- Preserve the P0-P7 branch's independent Rust structural/byte-DAG/finite-heap
  admission, scoped abort cleanup, finite oracle cache, map-repeat and timed
  XOR-fold profiles, source migration fixes and new experiment protocols.
- Review the Rust overlap against both pinned sources, retaining the newer
  implementation without losing the existing explicit-frame v3/v4 envelope.
  The detailed review and exact-lock gate are in
  `HIA_RUST_INTEGRATION_REVIEW_20261030.md`.
- Union the C project/do-while regression methods rather than choosing one
  parent's test file. Preserve first-body execution, distinct break/continue
  initialization paths, unsupported condition refusals and stopped ledgers.
- Merge safety capabilities by stable identifier. Both parents' full selector
  sets are retained. The revised contract is pinned in the qualification tool;
  neither an external receipt nor the JSON matrix grants program admission.

The initial union has 52 capabilities and 538 unique selectors. The bounded
native invocation fix adds one capability and 14 selectors: **53 capabilities,
552 selectors**. These are implementation obligations and finite regression
evidence, not a new whole-language soundness proof.

## New runtime repairs

`AdaptiveRuntime._arguments` previously validated caller-owned rows and copied
them afterwards. A producer thread could change a checked integer before the
copy, including supplying a value outside the native u64 domain. It now captures
a bounded outer sequence and bounded immutable row snapshots, validates those
snapshots, and dispatches exactly those values.

`OwnedAdaptiveRuntime` now also captures initial cells and the submitted queue
before validation. Concurrent growth after an initial size check cannot admit
more than 65,536 cells or 128 work items. This does not promise an atomic snapshot
of a caller's entire nested data structure. The native regression suite uses real
Clang-produced functions, sealed image admission, owner ledgers and queue
execution; the separate dispatcher-spy suite is labeled accordingly.

## Six acceptance tracks

| Track | Executable work | Limit that remains explicit |
| --- | --- | --- |
| Common semantics | Two-parent convergence; central catalog, full Python/Core admission, scoped independent Rust, interpreter, LLVM and routes | No universal source-to-Core or Core-to-machine refinement theorem |
| Safety and preservation | Existing loop/returned-loan/heap/scoped-abort checks plus new bounded native snapshot obligations | Finite profiles, explicit traps/budgets, foreign assumptions and actual artifact identities remain distinct |
| Real C++ maintenance | Locked Microsoft GSL final-action implementation and factory snapshots, real version change, separately built C++ and Hepta | A small RAII/callback component, not arbitrary C++ exceptions, containers, inheritance or the entire library |
| NDU value | Pay-once preparation, resident holding and memory quota; independent exhaustive/DP, fixed configuration and same-information greedy controls; actual semantic refusal and native NDU | Declared planning costs are not application timings; bounded candidate-path optimality is not whole-program global optimality |
| Dynamic execution | Actual scalar/owned adapters, active-call/borrow/retirement gates, immutable input capture and queue progress | Arbitrary OSR, external I/O replay, process-crash recovery and concurrent guest threads remain outside admission |
| Agent maintenance | A separately registered maintenance matrix with fresh tasks, two requested model tiers and the same hidden oracles | Correctness and complete development-cost advantage must be earned by fresh measurements; unknown human review cost is not zero |

## Evidence policy

Qualification must bind the committed source, selected tool identities, input
and artifact digests, raw execution output and actual failure paths. Failed
preflights and negative comparisons are retained. A successful safety gate does
not make an NDU speed or Agent productivity claim pass. Compiler/bridge setup,
search, proof checks, controller overhead, switching and failed work belong in
their cost ledgers; unknown costs cannot be used to claim a net advantage.

No existing protocol or historical result is relabeled as a new experiment.
Final run receipts and limitations are recorded alongside this document after
the committed baseline is exercised.
