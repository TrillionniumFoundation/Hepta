# HIA v6 finite static resource budget — P1/P2 incremental gate

**Status:** opt-in implementation on the current integrated standalone HIA Core.
This is a strict finite subset, **not** arbitrary-program resource analysis,
a worst-case CPU time bound, process RSS proof, or full source/LLVM refinement.

## Existing implementation reused

`hepta.hia_static_budget.analyze_static_budget` re-runs the one existing
`hepta.hia_program.verify_program` on canonical program bytes. It does **not**
parse Hepta source, generate LLVM or create another ownership checker. It
consumes only the exact typed/verified Core instruction and block vocabulary.
Its outputs are tied to the immutable Core SHA-256.

## Algorithm and deliberately narrow qualification

- Require every function's CFG and the complete interprocedural call graph to
  be acyclic. Use an iterative stable topological sort. Any CFG backedge,
  direct recursion or mutual recursion returns `E_HIA_BUDGET_UNBOUNDED`.
  Valid HIA loops and recursion remain supported **without** this opt-in gate.
- In reversed CFG DAG order, add all operation costs in a block and the
  maximum over its successor blocks. Every explicit `call` counts the
  full callee upper bound, even when a function is invoked more than once.
- `max_allocator_interactions` conservatively counts each `buffer.new`,
  `buffer.try_new` and `owner.drop`; count `drop` even when its owner is empty
  or an allocation attempt fails. It is an upper bound on allocator events,
  **not** the number of physical allocations or occupied heap bytes.
- `max_vm_ticks` counts exactly the virtual tick sites of the existing HIA
  Python evaluator: one per function invocation, opcode, and block terminator,
  including ticks of all nested calls. It does **not** bound native instructions,
  CPU time, host memory or Python interpreter allocations.
- `max_call_depth` is the upper bound on simultaneous invocation frames,
  counting the current function as depth 1.
- Limits are checked for every verified function. Unknown, negative, Boolean,
  floating or nonsensical limit types are rejected; no `False == 0` bypass.
  Conservative rejection is legitimate when an infeasible syntactic branch
  exceeds a limit.

The result is a deterministic `hepta.hia.static-budget.v1` JSON-compatible
receipt with the exact source Core digest, per-function bounds and explicit
FALSE claims for native time/RSS, language soundness and source refinement.
A receipt from arbitrary JSON is never accepted as authorization.

## Optional native gate

The **existing** `hepta.hia_source_bridge.build_checked_hepta_hia_native`
accepts `static_resource_limits={"max_allocator_interactions": 2,
"max_vm_ticks": 100, "max_call_depth": 2}`. If set, it re-verifies the derived
HIA Core and requires the finite bounds **before** emitting LLVM or publishing
an artifact. `build_checked_owned_hia_native` forwards the same optional policy.
Omitting this argument preserves existing loop/recursive-program behavior.
These declared finite policies are distinct from runtime VM `max_heap_bytes`.

## Evidence and limitations

Focused independently run Python 3.13.5 algorithm-smoke suite: 5/5 using a
stub of the existing HIA verifier; it checks DAG max paths, repeated calls,
cycle/recursion refusal, typed limits and reproducible receipts. The actual
in-repository `tests.test_hia_static_budget` additionally exercises the real
verified Core, interpreter observations and a source-to-native pre-LLVM
negative control, but it has **not** run on a complete exact-head checkout.

Recommended exact checkout commands:

    python -m unittest tests.test_hia_static_budget tests.test_hia_program \
      tests.test_hia_program_llvm tests.test_hia_owned_source_bridge -v
    python tools/release_check.py

This work does **not** close general bounded-memory/provenance SSA, backend
refinement, real hardware, C++ L2/L3, actual Agent A/B or whole-project gates.
`whole_project_blockers_closed=false`.
