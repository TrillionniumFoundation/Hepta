# Primitive v1 entry payload bound

## Result and scope

`hepta.hia_heap_bound.analyze_entry_payload_bound(program, function)` adds a
read-only structural analysis to the existing heap-bound module. It reuses
`verify_program`, the existing call-DAG check and CFG edge interpretation.
It does not change any existing static-budget, heap-budget, runtime or native
admission. Its result is not an authority token: a consumer must re-run the
analysis on the actual Core, not trust a supplied report or digest.

For the retained real legacy Core
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`, the intended
entry is `legacy_checksum_chunk`. The executable Core contains 16 functions.
Its three `buffer.try_new` sites are in blocks `b128`, `b129`, and `b131`, with
same-block earlier `const usize` operands of 16, 8, and 8 bytes. The profile
checks all definitions and all call/CFG edges; it does not merely count those
three instructions in isolation. An accepted analysis gives the following
bound for each fresh invocation and every correctly typed scalar input:

| Quantity | Conservative upper bound |
| --- | ---: |
| Executed allocation opcodes | 3 |
| Nonzero HIA allocation requests | 3 |
| Cumulative requested byte-owner payload | 32 bytes |
| Simultaneously live byte-owner payload | 32 bytes |

The fixture is the exact existing migration artifact, not a rewritten model of
it. This analysis proves no additional C/C++ source or machine-code refinement.
Run evidence records the exact analyzer source, Core bytes, command, dependency
digests and outcome. The source/semantics argument below is a reviewed induction,
not a proof-assistant theorem establishing the whole language or the analyzer.

## Checked profile

1. The canonical Core verifier must accept the complete immutable input. A
   manually constructed `VerifiedProgram` is reverified. Source annotations,
   producer reports and claimed purity are not premises.
2. Only primitive `hepta.hia.program.v1` is admitted. A separately enumerated
   opcode/type/terminator inventory must also pass. Chains, foreign calls,
   unreviewed allocators, new schemas and composite programs are refused.
3. The selected public entry has only scalar inputs and outputs. Its fresh Core
   execution begins with no externally supplied owners. Private calls may take
   and return owners and take borrowed views; their summaries cover only new
   requests, not the unknown extent of a private caller's existing owners.
4. The complete direct call graph must be acyclic, including unused private
   definitions. Every syntactic call site is charged independently.
5. Each `buffer.new` / `buffer.try_new` argument must be an earlier **literal
   `const usize` in the same block**, in `0..2^63-1`. Arithmetic and block-parameter
   constant propagation are not attempted. Their refusal is conservative.
6. Exact CFG strongly connected components identify cyclic blocks. A cyclic
   block may contain no allocator opcode and no call whose transitive body
   contains an allocator opcode. Even zero-size allocation sites are refused in
   cycles. A call into a verified allocator-free closure may execute repeatedly.

The last rule permits actual legacy loops that load/store existing buffers,
borrow/end loans, move owners and call allocation-free functions. It does not
mistake an acyclic exit from a loop for a cyclic block. It also does not assume
that repeated owner/view operations consume no host metadata or native stack.

## Derivation linked to actual Core semantics

The accounting unit is the requested **byte-owner payload**, not a Python object,
allocator slab, buffer descriptor, C allocation header or resident memory page.
The reviewed rules are the v1 allocator, owner-transfer and call branches of
`hia_program_runtime._Machine.operation`, `.allocate`, `.new_owner`, `.drop`, and
`.invoke`; the canonical checker establishes typed SSA and linear resource flow.

For an allocation site of constant size `s > 0`, one visit performs at most one
allocation request and creates either `s` payload bytes or no payload. Failure
of `try_new` returns a logical empty owner; required-allocation failure aborts.
Zero-size allocation creates an empty owner without an allocator request.
A heap-budget stop can precede the request. None of these cases exceeds charging
one opcode, `1[s > 0]` requests and `s` cumulative requested bytes for the site.

The v1 closed opcode inventory has no other operation that creates or enlarges
payload. `owner.move`, block-edge transfers and owned call/return transfer the
existing owner; they do not clone its payload. Borrowed accesses do not allocate
a new payload, and dropping an owner cannot increase live payload. This does
not assert that the implementation performs no host allocation for views or
other metadata.

Induct over the acyclic call graph, callees first. For each function, remove
the allocation-free SCCs from its accounting (their contribution is zero).
Every remaining allocating block can be visited at most once per invocation:
two visits would imply a path back to the same block, putting it in a cycle.
At each noncyclic call site add the independently obtained callee summary.
Add all branch sites, even mutually exclusive or infeasible branches. This
overestimates the trace and requires no branch reachability oracle.

Thus the sum bounds requests and requested bytes for every finite prefix of
every invocation, including failed allocations, explicit/arithmetic traps and
execution-budget stops. A fresh scalar entry starts with zero external payload;
live payload is nonnegative and is at most the sum of all payload ever created,
which is at most cumulative requested bytes. For the actual entry this yields
`16 + 8 + 8 = 32`. Callee owner returns add no second charge to this sum.

## TCB, exclusions and falsification controls

The trusted implementation boundary includes the canonical Core checker and
schema/JSON preflight, the reviewed operational semantics, this finite graph
and accounting algorithm, and Python's execution/integer behavior. The source
tree and critical file digests are recorded for replay. No assertion is made
that hashing authenticates a producer or that this Python implementation has a
machine-checked soundness proof.

No bound is claimed for termination, VM tick count, total free calls, cleanup
after abort, repeated owner/view metadata, stack bytes, allocator overhead,
RSS, foreign resources, concurrent executions, recursive storage or native
code. The 32-byte bound is per fresh sequential Core invocation. It neither
authorizes an optimization nor expands a native installation gate.

The regression suite includes direct and transitive loop allocation (including
zero-size), unused recursion, dynamic and cross-block sizes, forged verified
Core, unknown opcodes and foreign allocator calls, future-verifier stubs,
resource-return entry rejection, owner-return transfer, allocation failure,
trap/budget-stop prefixes, branch overestimation and a loop's allocating exit.
The existing historical admission APIs must still refuse examples outside
their earlier domains. Finite VM observations are regression checks of the
accounting rules; the all-input bound comes from the structural argument.

## Reproduction

From a clean source checkout, with Python and no native toolchain/model needed:

```sh
python -m unittest tests.test_hia_entry_payload_bound -v
python tools/analyze_hia_entry_payload.py \
  tests/fixtures/hia_payload_bound/legacy_core.hia.json legacy_checksum_chunk \
  --require-clean-source --output /tmp/hepta-entry-payload-result.json
```

The output file must not already exist. The receipt includes graph components,
all allocation/call sites, callee-first summaries and a deterministic analysis
digest; independent re-execution can compare that digest. Run outputs should be
outside the source checkout until the source-bound run has completed.
