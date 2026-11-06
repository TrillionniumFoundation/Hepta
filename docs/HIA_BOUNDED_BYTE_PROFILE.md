# Bounded byte resources on the existing Core

`qualify_bounded_resources` composes the existing Core verifier, static event
analysis and requested-payload analysis into an optional admission used by the
production interpreter and native builder. A caller supplies a complete budget;
all quantities are recomputed from the current immutable Core. The report is
retained evidence and cannot be supplied as an execution certificate.

This closes a practical composition gap. Previously a v8 module could obtain
an event/call bound and a borrowed-entry payload bound through separate APIs,
while its ordinary native build did not require either. The optional profile
now checks both before execution or LLVM emission, covers every explicit public
export, and attaches their exact Core identities to the resulting observation
or build receipt.

## One semantic authority, explicit consumer scopes

| Responsibility | Existing authority used by the profile |
| --- | --- |
| Wire grammar and version | `hepta/hia_schema.py`, selected through `verify_program` |
| Primitive instruction signatures, effects and resource guards | `hepta/hia_opcodes.py` |
| Typed SSA, calls, owner consumption, loans, v8 return origins and error-as-value cleanup | `hepta/hia_program.py` and `hepta/hia_capability_flow.py` |
| Acyclic control/call graphs, potential allocator interactions, VM ticks and root-inclusive call frames | `analyze_static_budget` in `hepta/hia_static_budget.py` |
| Primitive v1–v6 live requested byte payload | `analyze_constant_live_heap` in `hepta/hia_heap_bound.py` |
| V8 borrowed-call additional local payload and complete public-entry peak | `qualify_entry_live_heap_budget` in `hepta/hia_heap_bound.py`, freshly applied to every export |
| Execution and runtime ledger | Existing `execute_program` interpreter |
| Actual LLVM, ABI checks, compiler capture and artifact publication | Existing `build_program_native` path |

The composition adds no opcode, schema alias, ownership interpretation, source
translator or alternate lowering. It never relabels v7 as v8. A valid Core can
remain outside this deliberately smaller optional profile.

## Declared configuration

The report profile is `explicit-scalar-exports-acyclic-byte-resources-v1`.
It accepts explicit primitive v1–v6 or reviewed byte-only v8 Core, with one to
128 explicitly declared scalar exports. Nominal inputs, implicit export
discovery, empty exports and v7 are outside this initial composed review.
V7's separate byte/event analyses and ordinary standalone execution remain
available; this profile does not infer the missing combined payload review.

The existing byte-resource analysis determines which integer and memory
operations are supported. Machine integers retain their exact existing width,
signedness, checked/wrapping and first-trap semantics. Calls are direct and
acyclic. Control-flow graphs are acyclic. V8 borrowed parameter loans and
returned loans use their canonical origin contract. Chains, owned resource
transfer through unreviewed calls, unknown allocation extents and unreviewed
operations are rejected. The audit includes private definitions.

All four limits are required as exact Python/JSON integers; Boolean values,
partial objects and unknown fields are rejected:

| Field | Accepted policy range | Meaning |
| --- | --- | --- |
| `max_allocator_interactions` | Nonnegative | Conservative potential allocation and free events per invocation |
| `max_vm_ticks` | 1–10,000,000 | Interpreter opcode, terminator and invocation events |
| `max_call_depth` | 1–256 | Synchronous frames, including the root |
| `max_live_heap_bytes` | 0–1,073,741,824 | Requested live HIA byte payload |

The shared policy ranges fit the existing interpreter's operational limits.
Allocator metadata, interpreter view objects, native stack and process RSS are
separate quantities. No number in this policy is a wall-clock limit.

All explicit public exports receive a payload bound. The v8 callee local-peak
summary excludes caller-owned external payload; the public scalar entry's peak
includes its own owners plus every callee's additional local peak. The existing
analysis rejects an allocation based on an unbounded borrowed extent instead
of treating that extent as zero or trusting a caller promise.

An evaluator's separately supplied limits must also cover the selected entry's
computed bounds. Smaller limits cause `E_HIA_BUDGET_POLICY` before invocation;
the effective runtime limits never exceed the requested composed policy. The
existing interpreter call-stack/host-memory restrictions still apply.

## Use through production APIs

```python
from hepta.core import execute_core, build_core
from hepta.hia_static_budget import qualify_bounded_resources

limits = {
    "max_allocator_interactions": 6,
    "max_vm_ticks": 32,
    "max_call_depth": 3,
    "max_live_heap_bytes": 8,
}

# core is an explicit verified/serializable primitive program, not a receipt.
analysis = qualify_bounded_resources(core, limits=limits)
observation = execute_core(core, "entry", [], bounded_resource_limits=limits)
native = build_core(core, "/tmp/new-entry.so", clang="clang-20",
                    bounded_resource_limits=limits)
```

The same optional keyword is available on `execute_program` and
`build_program_native`. The old broader standalone behavior is preserved when
it is omitted. Native emission still enforces its exact C wrapper profile;
resource qualification alone does not establish a native ABI or make an
unsupported public signature representable.

`bounded_resources` on an execution or build result binds the policy, every
export's bounds, original/canonical Core hashes and the reused sub-analyses.
Each new production call recomputes admission. Editing a retained result,
changing an input program, or passing a result where a policy belongs cannot
reuse an earlier success. A policy is copied once before analysis, so later
caller mutations do not widen the accepted budget.

## Errors, traps and proof boundaries

`buffer.try_new` keeps its existing empty-owner/false result on allocator
refusal. Empty allocations remain logical owners without allocator calls.
Ordinary error-as-value returns must end loans and consume owners just like
successful returns. Infallible allocation failure, bounds violations and
checked overflow retain their specified trap semantics. The profile does not
convert them into normal error values or promise destructor cleanup after an
aborting trap.

The existing Lean capability lifecycle/borrow models remain abstract models.
This composition does **not** establish that the production checker refines
those models, or prove a universal resource-safety theorem. The separate
[scalar sequential proof chain](HIA_SEQUENTIAL_CORE_PROOF_CHAIN.md) quantifies
all typed inputs only for its admitted acyclic scalar artifact and its actual
LLVM body; it does not widen to resources through this API.

The new report keeps checker/model refinement, source/Core refinement,
LLVM/machine-code refinement, process-RSS/native-stack bounds, exclusion of
program traps, guaranteed allocator success and whole-language soundness false.
Native build evidence continues to leave execution qualification false until
separate actual observations are collected. None of these statements changes
the unproved obligations recorded in the existing convergence/proof documents.

## Targeted regression evidence

```sh
python -m unittest tests.test_hia_bounded_profile -v
```

The suite includes an actual Clang 20+ object built through the production
bounded profile, linked to the existing independent allocator observer. The
v8 fixture has nested borrowed calls and three fallible allocations. Every
allocation refusal position and the no-refusal cases compare returned values,
attempts, successful allocations, frees, live bytes and peak bytes against the
real interpreter. All ordinary error returns balance owners and loans.

Other cases cover multiple public exports, checked overflow versus wrapping,
shared and mutable returned loans, empty allocations, every policy field,
policy capture, edited inputs, stale reports, whole-module chain rejection,
cycles, unknown extents, smaller evaluator quotas and native rejection before
emission/publication. These are finite implementation observations and
regressions, not replacements for the outstanding refinement proofs.
