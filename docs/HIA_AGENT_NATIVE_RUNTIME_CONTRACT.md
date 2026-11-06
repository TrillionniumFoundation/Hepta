# HIA Agent-driven native backend and runtime tool contract

Status: interface design, 2026-11-06. The accompanying
[`HIA_AGENT_NATIVE_TOOL_CATALOG.json`](HIA_AGENT_NATIVE_TOOL_CATALOG.json) is a
proposed MCP tool catalog. It is not a running server, a registered tool family,
a native execution qualification, or a self-hosting claim.

## 1. Product decision

HIA must have a direct machine-code backend. The primary product path is:

1. An Agent discovers the exact language and target contracts through tools.
2. The Agent acquires task, program, workload and machine context.
3. The Agent chooses and submits explicit program or machine implementation changes.
4. Deterministic validators check those changes in their declared support domains.
5. HIA's own backend lowers and encodes the admitted candidate directly.
6. hepta-runtime executes the candidate under its existing execution ownership,
   records results and costs, and conditionally adopts the Agent-selected result.

The direct backend must not silently fall back to LLVM, a C/Rust compiler or an
external assembler. A separately declared linker and OS/runtime dependency may
remain; object generation, linking, loading and execution are distinct facts.
Other backends may be independent comparison oracles. They are not the default
implementation of this direct path.

The Agent need not have encountered HIA in pretraining. General programming and
tool-use ability, supplied with version-accurate language contracts and feedback,
is the proposed onboarding route. Its effectiveness is an experimental claim
requiring a cold-start evaluation, not a consequence of exposing a JSON schema.

## 2. Responsibility boundary

| Owner | Responsibility |
| --- | --- |
| HIA Core | Exact types, integer modes, effects, CFG, calls, resources and trap semantics |
| Agent | Goals, context requests, optimization hypotheses, transformation selection and parameters, search budget, candidate choice and stopping |
| Direct backend | Published canonical lowering, mechanical realization of explicit plans, ISA/ABI legality, encoding, fixups, relocations and object construction |
| Validators | Core admission; supported equivalence/refinement checks; machine-plan legality; actual encoded artifact identity |
| hepta-runtime | MCP exposure, retained artifacts, execution ownership, target/context collection, bounded operations, measurement, conditional adoption and retirement |

The distinction is **semantic implementation versus profitability choice**, not
"deterministic versus AI": conventional optimizers can also be deterministic.
Canonical lowering must publish a fixed, valid baseline. It may use simple stack
slots and fixed scratch registers. It must not conceal automatic inlining,
vectorization, PGO or profitability-driven peepholes under the name "lowering".

An Agent can invoke a deterministic transformation implementation with explicit
parameters. For example, it can select an unroll factor or request a known
rewrite. The tool implements the chosen transformation; it does not independently
choose the search policy or silently replace the Agent's objective.

Required examples of the boundary:

| Necessary implementation | Optional optimization selected by the Agent |
| --- | --- |
| Realize checked-add overflow behavior | Prove a check redundant and remove it |
| Assign every value a valid physical location | Search for fewer spills or a better allocation |
| Emit a branch that reaches its destination | Choose a more compact layout or branch form |
| Implement the declared ABI | Specialize or inline an eligible call |

Every automatically executed lowering step and every Agent-selected plan must
have a stable identifier in the artifact receipt. No performance optimizer runs
implicitly on the direct path.

## 3. Source scope and current evidence

This design was checked against the Hepta Core/tool base
`542b8ae69ae4d7322638b2044c27f58943cc383c`, the subsequently published direct-native
PR #773 candidate `1cb9dafc5f670a7b991645f5b6fc06474f37451b`, and the hepta-runtime PR #84 candidate
`b3bac9e47fd09ee2c6bb0d62802bd55b7662f366`. The runtime default branch is
`hepta-runtime-base`, at `ba574f2a6a1b74e85191c58d7bec011720736bb9`; it is not a
substitute for the PR #84 candidate. No claim is made that these candidates are
deployed together or that either PR is merged.

The direct backend was initially observed as work in progress and was published
during this design review as [PR #773](https://github.com/TrillionniumFoundation/Hepta/pull/773).
Its `emit_program_machine`, `compile_program_machine`, `build_program_machine` and
`HIAProgramMachine` boundary informs this design. The candidate owns x86-64 bytes
and ELF64 object generation, with separate optional linkage. Its published
[usage and ABI](https://github.com/TrillionniumFoundation/Hepta/blob/1cb9dafc5f670a7b991645f5b6fc06474f37451b/docs/HIA_DIRECT_NATIVE.md)
and [local qualification record](https://github.com/TrillionniumFoundation/Hepta/blob/1cb9dafc5f670a7b991645f5b6fc06474f37451b/experiments/hia_direct_native_20261106/README.md)
are separate from the schema checks in this design. These schema checks do not
rerun native qualification or establish hosted CI, deployment or performance.

The PR keeps LLVM as the CLI default. A HIA MCP adapter must explicitly call the
direct machine API or select `hia build --backend native`. The existing CLI
`hia emit` still emits LLVM text; it must not be confused with the proposed
`hia_emit` MCP tool. This design does not modify the backend worktree or claim its
current API is already registered with hepta-runtime.

Existing reusable HIA entry points include:

| Purpose | Existing source/API |
| --- | --- |
| Language versions and instructions | `hia_schema.schema_registry`, `hia_opcodes.opcode_catalog` |
| Program inspection | `hia_program_tools.inspect_program` |
| Context slices and focused edits | `hia_edit_query.prepare_edit`, `render_edit_context`, `apply_edit` |
| Coordinated edits | `hia_edit_batch.prepare_batch`, `apply_batch` |
| Function/CFG-level edits | `hia_program_tools.apply_program_patch` |
| Core admission and reference execution | `hia_program.verify_program`, `hia_program_runtime.execute_program` |
| Restricted optimization validation | `hia_optimization.verify_optimization` |
| Conditional versions and leases | `hia_multiversion` mechanisms, subject to its existing narrow profiles |

The existing patch receipt explicitly does not prove behavioral equivalence.
At this base, the generic optimization verifier covers primitive v1-v7 under
restricted control/resource structure; it is not a general v8/CFG/algorithm
equivalence prover. Existing artifact sessions, differential executors and
multiversion preparation also have ABI/profile restrictions and LLVM coupling.
They require explicit extension rather than a claim that an MCP wrapper alone
completes the integration.

Runtime integration should use the existing `src/mcp/server.rs` router and typed
request conventions, plus the existing runtime provider, operation/job and
artifact mechanisms. Registering a new tool must also update any reviewed cloud
catalog and allowlist; the offline gateway catalog builder is not an HTTP server.
Existing durable request handlers must not be assumed to accept a new operation
kind without its implementation and lifecycle tests.

Pinned runtime references:

- [Tool-authoring contract](https://github.com/TrillionniumFoundation/hepta-runtime/blob/b3bac9e47fd09ee2c6bb0d62802bd55b7662f366/.agents/tool-authoring.md)
- [MCP router](https://github.com/TrillionniumFoundation/hepta-runtime/blob/b3bac9e47fd09ee2c6bb0d62802bd55b7662f366/src/mcp/server.rs)
- [Native provider example](https://github.com/TrillionniumFoundation/hepta-runtime/blob/b3bac9e47fd09ee2c6bb0d62802bd55b7662f366/src/mcp/rea_provider.rs)

## 4. Discoverable context

`hia_describe` returns a small manifest and immutable resource references. Further
reads supply only the requested definitions and examples. The contract must
include all of the following, without placing the entire repository in one prompt:

- Core schema, grammar and catalog digests; operand/result rules, attributes,
  effects, traps, resource transitions and explicit unsupported semantics.
- Legal and illegal examples, including checked/wrapping arithmetic, borrowing,
  cleanup and multi-block control flow. Examples describe the language, not hidden
  answers to the task being evaluated.
- A separate direct-backend capability manifest: ISA, ABI, features, accepted Core
  subset, runtime imports, code/frame limits and actual qualification scope.
- Available patch schemas, machine-plan schemas, validation profiles, execution
  profiles and their limitations.
- Structured diagnostics with phase, code, selector, expected/actual data and
  counterexamples where actually available.
- Context references for workload, baseline, objective, constraints, target
  measurement, evaluation split and budget. Context describes the requested
  optimization; it does not modify language meaning or supply execution authority.

Language legality and backend support are separate capabilities. A legal Core
program may be unsupported by a particular direct backend. Unsupported operations
must be reported as such, not routed through another compiler.

Descriptions, examples, schemas and error codes should be generated from or
checked against the same semantic tables used by validators. Resource content is
data, not authority to override the user's task or runtime policy. Model-facing
prose and machine-readable schema must be updated together.

## 5. Proposed tools

All names below are proposed HIA tools, not claims about the current registry.
MCP transport negotiation, protocol envelopes and authentication remain the
responsibility of the existing runtime. The JSON catalog specifies application
arguments and results, independently of the negotiated MCP protocol version.

| Tool | Operation |
| --- | --- |
| `hia_describe` | Discover language, direct backend, profiles, limits and resource references |
| `hia_artifact` | Retain bounded UTF-8 input or a permitted file as immutable data |
| `hia_read` | Read bounded artifact pages, including the discovered language contract |
| `hia_context` | Freeze a task/workload/target/budget context and return its identity |
| `hia_inspect` | Read a bounded program or lowered-machine view and relevant dependencies |
| `hia_candidate` | Import source or apply a snapshot-bound Core patch into an isolated candidate |
| `hia_verify` | Obtain separate Core, equivalence and lowering/refinement results in named profiles |
| `hia_emit` | Use only the direct backend, with canonical lowering or an explicit Agent machine plan |
| `hia_evaluate` | Compare an immutable baseline/candidate pair under the frozen workload and budget |
| `hia_adopt` | Conditionally install the Agent-selected candidate for future calls |
| `hia_rollback` | Conditionally restore a retained compatible generation for future calls |

Large sources, patches, plans and results use immutable artifact references with
digests, not arbitrary shell command strings or unbounded inline responses.
`hia_artifact` supplies the missing registration step: bounded UTF-8 input can be
retained directly; larger files are written through existing file tools and then
captured through a configured artifact profile and the runtime path resolver.
That capture must enforce permitted roots, size and stable regular-file identity.
It does not execute the input or admit it as a Core program.

Every artifact reference carries an exact server-issued `hia://artifacts/...`
URI. Implement the corresponding MCP resource read handler and `hia_read` for
tool-only clients. IDs are opaque; clients must not derive a path or URI from an
ID. Readers recheck authority and actual bytes, bind pagination to the digest, and
enforce the runtime's serialized response byte limit. A digest establishes
identity, not authority. Context/profile references resolve to retained server
records; their readable manifests are artifacts returned by discovery/context.

Long operations return an existing runtime operation/job reference. Polling,
results and cancellation reuse the runtime's lifecycle instead of introducing a
second scheduler. An adapter must register the HIA operation kinds first. For
typed result recovery, repeat the same HIA tool with its original `request_key`
and identical arguments. The adapter first resolves the original durable binding;
if it exists, it only observes that job. It verifies the terminal report's schema,
request/context/candidate/compiler/artifact identities and completeness before
returning the original tool's completed result. A first call reserves the durable
identity before launch. If a binding is unknown or its outcome cannot be proved,
the adapter must not relaunch it. A disconnect before receiving host/job IDs is
reconciled through the same request key.

`process_status` and `process_read` expose existing process observations; they do
not automatically produce verified HIA reports. Exit zero, raw stdout or a report
read by the model cannot substitute for adapter verification. Missing/mismatched
reports produce a structured rejection or unknown state as appropriate, never a
successful domain result. Existing `request_*`/`operation_*` tools do not acquire
these semantics simply because a HIA handler has been registered.

An accepted operation is not a completed evaluation, and timeout or disconnected
observation is not proof that a native child stopped. A complete terminal report
can still describe a cancelled or budget-limited evaluation; its
`planned_workload_complete` field remains separate. Unknown termination cannot be
reported as confirmed completion.

## 6. Binding and machine plans

Each operation after discovery binds the catalog digest and a retained context.
Mutation requests also bind their base program and, for adoption, the exact
current generation/epoch. Retained records bind at least:

- base/candidate Core bytes and digests;
- target ISA/ABI/features and backend implementation/profile;
- canonical lowering rule identity or Agent plan identity;
- actual text/object/image bytes and separate linker/runtime identities;
- validator identity, domain, assumptions and result;
- workload/evaluation split and target observations;
- objective, limits, full search cost and adopted version.

Core remains the semantic anchor. A target-specific machine representation may
expose explicit instruction forms, value locations, flags and clobbers, memory
dependencies, call ABI, stack slots, symbols and relocations. Its format is a
versioned capability returned by discovery; this document does not invent a
complete target IR or claim a checker for it exists.

An Agent can optimize Core first, then request the canonical direct lowering.
When a checked machine-plan profile is available, it can additionally submit
explicit selection, allocation or layout choices. The server checks both machine
legality and the declared relation to Core. Legal machine instructions alone do
not establish that they implement the Core program.

`hia_verify.subject` explicitly names Core alone, canonical lowering, a concrete
Agent machine plan, or an emitted native artifact. Lowering/refinement requests
must bind the canonical profile or exact plan/profile, backend and context target.
The returned receipt records that subject. `hia_emit` accepts a plan receipt only
for the same Core, target, backend and plan; a canonical-lowering receipt cannot
authorize another plan. Encoding checks refer to the actual emitted artifact and
build receipt in a subsequent verification call. Unsupported checker profiles
remain unsupported rather than manufacturing a receipt.

An unimplemented machine-plan profile returns `unsupported`. It must not accept
raw unchecked machine bytes as an optimization plan. Direct backend integration
can begin with canonical lowering while the machine-plan checker is developed.

## 7. Verification and diagnostics

Verification results are separate records for:

1. Core language/type/resource admission.
2. Base-to-candidate behavioral equivalence, if requested and supported.
3. Core-to-machine refinement, within an explicitly qualified domain.
4. Encoding/ABI/artifact checks and actual execution observations.

The proposed status vocabulary is `proved`, `refuted`, `unknown`, `unsupported`,
and `not_run`. A migration adapter must map existing results conservatively;
`verify_program` acceptance or passing test inputs must not be relabeled as a
whole-language soundness or universal refinement proof.

Each successful result must state its exact claim and domain. An allocation,
trap-order or interface change cannot be accepted as an equivalent optimization
merely because its output values match a few examples. Behavior-changing feature
work requires a different task specification; it must not silently weaken an
optimization's equivalence requirement.

Useful tool errors identify a stale base, unsupported profile, invalid type/loan,
failed assumption, counterexample or exhausted budget. They do not tell the Agent
to blindly repeat an unchanged request. An error response is distinct from an
operation accepted for asynchronous work.

## 8. Contextual optimization and cost

The Agent chooses transformations using actual goals and context: hot paths,
input distribution, call frequency, target features, memory pressure, latency
constraints and remaining search budget. Descriptive workload facts are not
universal invariants. A specialization based on observed inputs needs a checked
precondition or a correct fallback before deployment beyond those inputs.

Evaluation binds the same workload contract, target and measurement method for
baseline and candidate. It retains all attempted candidates, including invalid,
incorrect, timed-out and slower candidates. Holdout material must not be exposed
as optimization feedback when it is intended to test generalization.

Account separately for discovery/context, model calls, transformation execution,
verification, encoding/linking, benchmark runs, failed search, loading, switching
and ongoing execution. No NDU ranker, fixed optimizer or benchmark-selected winner
is an implicit decision owner. An Agent may explicitly request such an analysis
tool; its cost and role are recorded.

Net benefit depends on future use. Under a declared common cost unit, compare
expected repeated-execution savings with the full search, validation and adoption
cost. A latency constraint can still be decisive independently of that economic
comparison. Predicted benefit and observed benefit are different fields.

## 9. Adoption, recovery and rollback

The Agent selects a candidate; runtime checks the previously declared acceptance
conditions. The server consumes its own retained candidate/evidence records and
rechecks the current generation/epoch and current execution authorization. A
client-supplied `verified: true`, digest or receipt does not authorize adoption.
Every verification claim required by the frozen acceptance contract must have a
qualifying result for the exact subject/domain. `unknown`, `unsupported` and
`not_run` cannot satisfy a required proof. A top-level `completed` result means
the operation ended, not that all its claims were proved or the workload finished.

Each mutating operation has an idempotency key bound to its full request identity.
The same key with different arguments is rejected. Unknown completion is queried
under the original operation identity, not retried as a new execution.

Adoption is a conditional change for future calls. In-flight calls retain leases
on their code and data. Retirement releases a version only after its owned uses
finish. Rollback requires compatible retained code/state and a fresh check of the
current generation. It does not undo already completed I/O or state changes.
Initial integration may use a narrow pure-function ABI, explicitly advertised;
stateful applications require an additional state-layout and migration contract.

## 10. Implementation order and acceptance

1. **Backend boundary:** finish and qualify direct object generation for a fixed
   ISA/ABI/Core profile. Receipts distinguish own code generation from linking.
2. **Tool adapters:** expose generated catalogs, context, inspection, candidates,
   verification and direct emission through the existing runtime router/provider.
   Register execution kinds and the reviewed deployment catalog together.
3. **Complete cold-start loop:** a new Agent session discovers HIA through tools,
   writes a fresh program, submits and repairs an invalid candidate, emits and runs
   direct code, then evaluates an explicit optimization.
4. **Conditional use:** demonstrate adoption, stale-base rejection, in-flight
   version retention, cancellation/recovery and rollback for the declared ABI.
5. **Machine-level control:** add a validated target-plan profile, demonstrate an
   Agent-selected machine change and test rejection of illegal/clobbering plans.
6. **Measured value:** use held-out tasks and complete costs to separate learning
   the tool contract, producing correct code and achieving net optimization gain.

The cold-start study must record the full supplied context and every tool/model
attempt. No HIA-specific fine-tuning may be asserted merely from a fresh chat;
describe the actual model and what is known about its training exposure. A new or
held-out schema variant can test reliance on the discovered contract.

Separate capability from superiority. A passing loop proves a bounded integration
worked. Claims of better optimization require equal-information, budget-accounted
comparisons and real measurements. A finite search can prove an optimum only in
its declared finite candidate set.

## 11. Relationship to self-hosting

This architecture supplies a usable Agent access layer and does not wait for the
compiler to be self-hosted. Later, Agent tools can help implement and qualify HIA
components in HIA. Self-hosting still requires actual HIA compiler sources and a
repeatable multi-generation bootstrap. An Agent-driven optimization loop does not
itself establish self-hosting or autonomous recursive improvement.

## 12. Catalog validation scope

The accompanying catalog contains proposed, self-contained JSON Schemas for the
eleven tools. It can be validated without running a backend or native program.
Schema validation establishes only the consistency of these wire definitions.
It does not implement retained artifact lookup, hashing, authorization, semantic
validation, direct code generation, runtime registration or native execution.

Regenerate the catalog and its schema/fixture receipt with
`python tools/generate_hia_agent_native_contract.py`. The design-time generator
requires Python's `jsonschema` package; it adds no runtime dependency. To also
check the existing runtime catalog rules, pass
`--runtime-checkout /path/to/hepta-runtime`; the generator reads the pinned
`b3bac9e47fd09ee2c6bb0d62802bd55b7662f366:deploy/mcp_tool_contract.py` Git object.
This checks the proposed catalog's shape and drift rejection only, not registry
installation or runtime effects. All four operation annotations are explicit;
annotations remain descriptive hints, not authorization enforcement.

MCP references: [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
and [resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources).
Use the runtime's negotiated supported protocol rather than forcing a protocol
upgrade as a side effect of adding this application contract.
