# HIA owns source effect and resource closure

The ordinary source checker now runs the complete final effect/resource pass in
`hepta/native/effect_closure.hiaasm`. `check(program)` reaches this pass without
an environment selector. The old Python fixed-point implementation and its
worker/resource conflict decisions have been removed from `finish_effects`.
Python still supplies the already collected local effects, declarations, call
edges and resource-clause presence; it reconstructs diagnostic strings and
shared result objects from the HIA decisions.

This is one real semantic replacement within the unfinished source checker.
Expression typing, ownership and lifetime checks, AST allocation, module and
package processing, compilation, the runtime and release orchestration still
have foreign implementations. This change does not qualify whole-language or
whole-stack self-hosting and does not permit retiring those implementations.

## Meaning and default execution

The HIA pass computes the least transitive effect solution for the complete
call graph, including recursive strongly connected components and declared
upper bounds on external or ordinary callees. A function's own declared upper
bound is included in its inferred effects only if a positive-length call path
returns to that function. The pass also decides all missing declarations,
worker-forbidden effects, and the three effect-based resource conflicts that
the previous pass decided. The checker preserves its diagnostic ordering.

The single checked-in HIA assembly source is the maintained algorithm. It has
no authoring-generator dependency. It is packaged inside `hepta`, with explicit
setuptools package data, rather than being available only in repository
examples. A built and installed wheel can run ordinary checks after its build
tree has been removed.

On Linux x86-64 LP64 with an executable `ld` resolved from `PATH` and an input
within the existing native borrowed-byte ABI, first use assembles and verifies
this HIA program with the existing Core bootstrap, emits its direct machine
code, and links it. The
captured result must match its build receipt before it is retained as one
sealed memfd and one loader owner for the process.
Every call has disjoint private input, output and workspace allocations. Code
is shared across concurrent calls. The bootstrap does not invoke the source
checker, preventing a bootstrap recursion.

Other platforms, hosts without the initial linker, and graphs larger than the
existing 1-MiB native ABI execute the **same HIA program** in the Core VM. The
VM does not contain a Python effect-propagation substitute. This preserves the
existing source language on those hosts without claiming native machine
execution there. Substrate selection happens before invocation. An assembly,
native build, native call, malformed result or HIA refusal is propagated; none
causes a silent retry. A process pins its imported package/source snapshot;
every call checks the HIA source against that snapshot, and warm-cache source
drift is rejected. Upgrading it requires restarting the process.

The remaining Python assembler, Core verifier, direct emitter, host VM, loader
and initial linker are explicit bootstrap dependencies. The independent
selfhost test additionally builds fresh B1, B2 and B3 compilers, checks the fixed
point, compiles this semantic pass with actual HIA machine code, and executes
the resulting flat image. That component test is separate from a completed
full-toolchain cold qualification.

## Wire contract

All words are unsigned, 64-bit, little endian. `f0(readbuf, mutbuf, mutbuf)`
returns `u32`: zero for success, `0xffffffff` for invalid input and
`0xfffffffe` for insufficient caller-provided capacity. The existing native
export wrapper retains its separate high-word ABI status.

| Input region | Fields |
| --- | --- |
| 32-byte header | magic `3550613244766531912`, version `1`, function count `n`, edge count `e` |
| `n` records, 24 bytes each | local effect mask, declared effect mask, resource-clause presence mask |
| `e` edges, 16 bytes each | caller index, callee index |

The exact input extent is `32 + 24*n + 16*e`. Effects occupy bits 0 through 7
in the order `alloc, block, ffi, io, panic, spawn, unsafe, write`. Resource
presence occupies bits 0 through 2 in the order `heap_allocations, may_block,
may_spawn`. Clause values and unsupported clauses retain the existing earlier
syntax checks. The pass considers presence just as the previous effect pass
did; it does not erase those earlier diagnostics.

The output has `n` 32-byte rows: inferred mask, missing-declaration mask,
worker-forbidden mask, and resource-conflict mask. The HIA pass, rather than
the transport bridge, computes all four fields. Source effect-vocabulary drift
and unknown internal local effects are rejected, so extending a host constant
cannot silently drop a new effect from the native bitset.

The workspace extent is `96 + 32*n + 8*e`: fixed metadata, inferred masks,
reverse adjacency heads, queue-membership flags, an `n`-slot circular queue and
one linked-list successor per edge. HIA checks every header, mask and edge
before publishing output. Length-based division and subtraction checks precede
extent multiplication. Invalid input or insufficient capacity leaves the
output untouched. Poisoned workspace is supported because every value read by
the algorithm is initialized on that invocation; reserved bytes are not read.

## Termination and compatibility

Every function is initially queued. Later enqueues require an actual increase
of its eight-bit inferred mask, and the membership flag prevents concurrent
duplicate queue entries. A function is popped at most nine times, and each
reverse edge is therefore traversed at most nine times. Cycles, self-calls,
duplicate edges and arbitrary edge order preserve these bounds. Queue storage
is proportional to function count, with no host recursion.

The VM uses a bound derived from this fixed instruction/call inventory:
`65536 + 8192 * input_bytes` ticks. The constant dominates admission, up to
nine traversals per edge, and eight byte operations per word in each helper.
The bridge does not introduce a function-count or call-count language limit.
Larger graphs select the same HIA interpreter before entering the existing
native byte boundary. Host allocation failures remain actual failures.

## Verification

`tests.test_hia_effects` covers an independent reachability-based oracle, all
512 directed three-node graphs, 160 deterministic random graphs and reversed
edge order, native/VM equality, a 1,000-node chain and cycle, a 64-node complete
graph, declared-only effects, ordinary defaults, exact worker/resource
diagnostic order, malformed/truncated graphs, capacity refusal, poisoned and
guarded buffers, concurrent calls, actual selfhost compilation, and wheel
installation outside the checkout. Every actual `.hepta` file in `tests` and
`examples` that the parser admits is checked against the independent oracle's
complete effect and diagnostic observations.

These tests are finite evidence for this pass. Platform, whole-repository and
whole-toolchain requirements remain separate gates.
