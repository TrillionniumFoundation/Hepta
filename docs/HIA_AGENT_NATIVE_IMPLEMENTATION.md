# HIA Agent-native tools: implementation and qualification

This change implements the application contract in
[`HIA_AGENT_NATIVE_RUNTIME_CONTRACT.md`](HIA_AGENT_NATIVE_RUNTIME_CONTRACT.md).
The Agent selects changes and decides whether to request adoption. The tools
retain those explicit choices, check them, emit machine code, and return
observations. No optimizer runs implicitly in the direct path.

## Implemented boundary

The Hepta package contains a fixed-command worker and domain service. The
hepta-runtime integration exposes eleven tools through its existing MCP router:
`hia_describe`, `hia_artifact`, `hia_read`, `hia_context`, `hia_inspect`,
`hia_candidate`, `hia_verify`, `hia_emit`, `hia_evaluate`, `hia_adopt`, and
`hia_rollback`. The runtime also serves exact issued `hia://` artifact URIs.

The administrator installs an exact Hepta checkout, chooses the worker host and
private state directory, and pins the worker source inventory, direct backend,
and tool catalog. A tool argument cannot choose an executable, a different host,
or a storage authority. The installation manifest hashes actual installed
source bytes. It does not infer a Git commit from a dirty checkout.

The runtime uses its durable native process owner. Repeating a mutation with the
same tool and request key observes the original request; changing its arguments
is a conflict. An incomplete or mismatched terminal report cannot become a
completed HIA result. Disconnection and cancellation do not imply successful
completion or confirmed native termination.

## Supported profiles

| Surface | Implemented scope |
| --- | --- |
| Code generation | HIA-owned x86-64 encoding and ELF64 relocatable objects; Linux SysV AMD64 |
| Language | Existing primitive Core v1–v8 and the admitted composite elaboration path |
| Public native invocation | Integer and Boolean scalar inputs, at most one scalar or unit result; buffers and multiple results remain internal |
| Shared images | The already-emitted object is linked separately with GNU `ld`; no LLVM, C/Rust compiler, or external assembler generates its instructions |
| Optimization choices | Explicit Agent-authored Core imports/patches; v1 block layout and v2 checked scratch-register, immediate-form and function-layout plans |
| Finite plan checker | Exact permutations, a scratch-register bijection and exact alternate encodings; original Core, value slots, logical operation order, entry and CFG edges remain bound |
| Core admission | Existing whole-program verifier |
| Equivalence | Exact Core identity; exhaustive supported pure acyclic finite scalar domains; existing optional pinned-Z3 profile when available |
| Native observation | Disposable Linux processes, bounded wall time/CPU/address space, complete workload accounting, retained observations |
| Version publication | Conditional generation/epoch change, retained baseline, generation leases, compatible future-call rollback |
| Authority | Configured operator namespace; no claim of per-ChatGPT-user isolation |

Each verification check implements the self-contained
[proof result contract](HIA_AGENT_PROOF_RESULTS.md). A `proved` status only
establishes the listed property for the exact subject under its assumptions.
Receipt consumers reject unscoped legacy results, changed scope and conclusions
that disagree with retained checker evidence. This applies to emission,
evaluation and adoption.

The machine-choice checker establishes preservation relative to the canonical lowering
under its published assumptions. It is not a universal proof of Core-to-x86
refinement. Unsupported proof requests remain unsupported; they cannot satisfy a
required adoption claim. Native tests, Core admission, encoding identity and
behavioral equivalence remain separate evidence.

## Agent onboarding

Start with `hia_describe` and section `manifest`. Its readable manifest provides
the current profile identities, grammar, opcode/schema resources, workload and
objective formats, legal examples, diagnostics, and machine-plan schema. Read
only the relevant resources with `hia_read` or MCP `resources/read`.

The normal workflow is to retain inputs with `hia_artifact`, freeze the workload,
objective and budget with `hia_context`, import or patch a program, request
specific verification claims, retain each complete subject/property/profile/
assumptions/checker/unproved-obligations record, emit an object or shared image, verify the emitted
artifact, and evaluate the frozen baseline/candidate pair. Adoption consumes
the server's retained evidence and a current generation/epoch. A context or a
digest never grants execution authority.

The initial slot uses expected generation `"0"` and epoch `"0"`. Its evaluation
baseline remains available as generation `"0"`; the selected candidate becomes
generation `"1"`. Consumers acquire a generation lease, invoke that exact image,
and release the lease. Rollback changes future acquisitions and cannot reverse
past effects. This first profile is for pure scalar entry points; state migration
requires a separately specified application contract.

## Cost and result interpretation

Evaluation can compare native scalar-call latency or artifact bytes. Latency
includes the declared ctypes/FFI boundary. Byte reduction is a code-size result;
it is not a claim that an application is faster. Frozen expected outcomes and
reference semantics determine correctness separately from the optimization
metric.

The service retains failed and successful attempts and its measured operation
costs. External model/discovery costs are explicitly supplied or marked unknown.
Unknown costs are not zero, and an incomplete cost record cannot establish net
optimization benefit. A scripted integration test is not evidence that an
unseen Agent learned HIA. Fresh-context Agent qualification, when performed, has
its own complete transcript and does not establish what was absent from model
pretraining.

## Reproduction and evidence

The installed worker reports its immutable installation identities with:

```sh
python -B -m hepta.hia_agent_worker --installation-manifest
```

The runtime provider profile uses those identities and the exact same catalog
bytes embedded in its binary. The companion runtime configuration and deployment
contract document the fixed command and permitted paths.

Domain and native regression checks:

```sh
python -B -m unittest discover -s tests -p 'test_hia_agent_native*.py' -v
python -B tools/qualify_hia_direct_native.py --output /tmp/hia-direct-native.json
```

`tools/hia_agent_native_qualification.py` exercises the same tool contract either
through the domain service or an actual MCP stdio endpoint. The separate
`tools/hia_agent_native_client.py` is a thin recorded MCP client containing no
HIA grammar, compiler, optimizer, or task answers. It is suitable for a fresh
Agent context that must learn from discovery.

The schema generator's recorded checks validate wire definitions only. Actual domain,
native, transport, lifecycle, and Agent results are recorded in separate
qualification artifacts. This document does not turn schema checks into those
execution claims.

## Scope retained after integration

This implementation does not claim a self-hosted compiler, non-x86 machine
backends, universal compiler correctness, a universal equivalence prover,
arbitrary state migration, or net performance superiority. HIA's Python
bootstrap implementation and the Rust runtime remain explicit dependencies.
The Agent interface can support later self-hosting work; it does not itself
constitute a multi-generation bootstrap.
