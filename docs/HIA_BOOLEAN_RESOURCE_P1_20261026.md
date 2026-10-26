# P1: finite executable boolean control over verified Resource IR

Status: experimental finite profile, **not** full HIA v1 or a second semantic
authority. This increment adds only a constrained boolean-input edge interpreter;
all resource transitions still run through the existing independent Resource IR
verifier and `hia_resource_trace` replay implementation.

## Accepted subset

Only nongeneric Unit-returning functions with up to sixteen immutable by-value
boolean parameters, with all dynamic branch conditions referring to exactly
these unchanged parameters. Loops are allowed only within the finite fuel bound;
a constant true loop that never exits rejects as budget exhaustion. Computed
conditions, mutable params, scalar copies/assignments, returned owner values,
foreign effects, unsupported resource operations and non-boolean parameters
reject. Input values must be actual Python bools, not truthy integers.

The returned digest binds the graph receipt, typed input dictionary, selected
edges and the original resource path replay witness. This is a test instrument
for incremental value/resource convergence; it does **not** authenticate source,
prove its branch values agree with Hepta source semantics, implement memory
bytes/provenance, or establish native backend equivalence.

## Reproduce

```sh
python -m unittest tests.test_hia_boolean_trace tests.test_hia_resource_trace -v
```

A stripped isolated harness using the existing protocol stub passed 12/12
tests, including 7 new boolean tests. The exact source/checker/native Hepta
stack was **not executed** for this branch; this observation is not a production
gate. Real full-checkout validation, canonical source SSA alignment, Owned
LLVM exclusive use of executable operations, C/C++ L2/L3 migration, GPU,
physical DMA/IRQ, real Agent A/B, production latency and formal refinement
remain open. `whole_project_blockers_closed=false`.
