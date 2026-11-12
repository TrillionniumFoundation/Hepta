# Remaining Python policy owners and native-only closure

## Result and evidence boundary

The next independent implementation is the **Agent verification coordinator**:
seven original methods in `hepta/hia_agent_service.py`, covering proof production,
receipt acceptance, replay, and the exact required-claim decision. It does not
overlap the root's Emitter or the peer's Byte ABI work. The existing primitive
Core admission, VM, static-budget and public heap owners must not be ported a
second time merely because their Python reference bodies still exist.

This report is a source audit, not a new qualification run. The base is commit
`4b19af89a766593f7d5f1cc2db256e81aba7afcb`, tree
`1bc7c90996e1910ad66ba771b0bfee1d5bfa655c`. Every one of its 3,153 exported files
was reread and checked against the original CI manifest for bytes, SHA-256, Git
blob and mode. The read-only directory contains another 343 Python bytecode
cache files; they are excluded from the base. There is no Git metadata in this
export, so it is not described as a clean Git checkout.

The complete structural inventory covers 197 `hepta` modules, 378 `tools`
modules and `setup.py`. `PYTHON-OWNER-INVENTORY.json` records every nested/class
callable's source and AST identity, source positions, imports, call names and
control nodes. AST hashes are observations under CPython 3.12.14; raw source
hashes are the cross-version authority. `REMAINING-OWNERS.json` and
`OWNER-PATHS.tsv` map every one of those 576 paths to a reviewed family. A family
assignment is not a proof of every function's runtime reachability or semantic
equivalence. Experimental tools remain explicitly separate from production
entry points.

The original inventory accidentally requested four obsolete resource-symbol
names. Its bytes are preserved. `REGISTRY-OBSERVATION-r2.json` extracts the
actual five literal tuples and asserts that every requested symbol exists.
An initial classification run also omitted `hia_cli_native`; its failing log
and script are preserved in `classification-original-r1/`. Neither diagnostic
is a product failure or a native test result.

## Source-bound coverage already present

| Surface | Actual coverage and boundary |
|---|---|
| Primitive Core admission | `verify_program` calls `selected_core_structure` after `_decode` and namespace handling. `hia_core_admission_native.py` owns the whole selected primitive declaration, 50-opcode, CFG and resource-flow policy. The host `_BlockCheck` route is the default/reference alternative, not evidence that selected whole admission delegates its body checks. |
| Nominal elaboration | Constructor/function/outer owners from two families, plus native types, records, enums, tasks, calls, terminators and helper cache. Their supported compositions, dual-selection refusal and actual pinned dependencies remain significant. Registration of one helper does not select the entire composition. |
| Execution and resources | Whole selected interpreter, structural static budget, public heap controller and retained heap dependencies already exist. Foreign buffer/object/memory transport and loader policy remain hosted. |
| Code, ELF and Plan | Selected machine state, instruction policy, encoder, ELF writer and Plan continuations exist. They have real Python object/exception/retirement bridges. |
| Agent stateful subowners | Namespace, request journal, slot/version/lease, execution budget and service context controllers already own their admitted transitions over the original store. Ordinary service orchestration around them remains a different owner. |
| JSON/data/hash helpers | Multiple raw-wire JSON, canonicalization, snapshots, binary64, source hashing and streaming SHA owners exist. Their different accepted domains must not be collapsed into a claim about the public arbitrary-object input boundary. |

Three separately frozen overlays were reread and byte-verified, without
modifying their directories or importing them into the product:

| Overlay | Exact input | Coverage relevant to this audit |
|---|---|---|
| Core/Plan, 27 paths | `cd2bbecffd0123da4d45d1c7cc2222df5676de51` | Complete `_Function` 22 methods, five lowering helpers and six lazy generators; shared Plan frame retirement and captured-owner identity. It excludes `_Emitter`, Byte ABI, public normalization and the primitive verifier. |
| Emission R6, 19 paths | `6d54602d2efe0c30174e90dd1c0a3edbbd8ef850` | `_hia_emit`, `_compile`, `_signatures`, seven private modes, lifetime/unknown-effect and held-proof binding. The verifier, proof engines, emitter, linker, storage and process ports remain dependencies. |
| CLI, three paths | `bfd6090978c82fa4701454a04f6d035175fdbee7` | Final named-local lifetime correction for the existing fifteen-action CLI controller. It does not migrate every callee or the hosted package entry point. |

Their exact path/SHA maps are in `FROZEN-OVERLAY-SOURCE-OBSERVATION.json`.
Author qualifications remain bound to those exact sources. This audit does
not transfer them to the future verification owner or a joint source tree.

## What the registries do and do not establish

The exact base has 30 worker `HELPERS`, 31 ordinary checker `NATIVE_OWNERS`, one
`HELD_NATIVE_OWNERS` entry, 46 checker `CORE_SOURCE_FILES`, 789 fixed selfhost
`SOURCE_FILES`, and 70 `NATIVE_SOURCE_FILES`. The five resource groups contain
11 discovery files, 70 native sources, three source-build files, one
compiler-build file and four publication-build files. These are different
inventories with different purposes. Their counts are not a percentage of
semantic closure.

`hia_native_helpers.py` still executes bundle schema, duplicate, path, size,
dependency, source/image and construction-order policy. It is more than a
pointer-passing adapter. `hia_checker_identity.py` still constructs and checks
source/selection/held-mapping identities. Native publisher and source-admission
kernels do not by themselves move these decisions into HIA. The source map
still needs a fresh complete ordered observation; neither a global cache nor
an mtime shortcut follows from this audit.

The frozen Core and Emission overlays add captured and held owner capabilities
to distinct checker routes. A future union must preserve all ordinary,
captured and held inventories and bind proofs to actual held executable bytes,
not a later environment selector or backing file.

## Remaining production policy families

### 1. Public input, assembly, route and edit semantics

The principal entry is `hia_program.py::verify_program`. Before whole native
admission it still runs `_decode`, `_bounded_detached_snapshot`, `_structure`,
UTF-8/string-size handling, namespace checks and nominal routing. The inspected
`hepta` and `tools` sources contain no production call of
`selected_program_normalization` outside the defining module. Its presence in
the resource tuple is not public activation.

The normalization candidate has a real unresolved boundary: exact physical
recursion/active C frames and foreign temporary lifetimes, in addition to its
version-bound CPython diagnostic mechanism. HIA-produced note/deliver bytes
still call CPython. They cannot be advertised as removal of the interpreter
dependency. Neither an 8 MiB raw-wire parser nor a fixed recursion counter is
an equivalent replacement for every existing Python object input.

Other hosted policy entry points are assembly parse/render in
`hia_agent_assembly.py`; `hia_routes.py::admit_route/execute_route`; schema and
legacy adapters in `hia_schema.py` and `hia_core_upgrade.py`; editing,
inspection and no-replace publication in `hia_program_tools.py`; simultaneous
edit/query/impact logic in `hia_edit_batch.py`, `hia_edit_query.py` and
`hia_patch_impact.py`; incremental-session metadata in `hia_incremental.py`.
Some patch paths already delegate to native kernels. Their outer input and
identity decisions still need explicit closure.

### 2. Agent wire and ordinary request coordination

`hia_agent_contract.py::catalog/check_vocabulary/validate/installation_manifest`
owns the closed wire vocabulary, schema decisions and installed identity.
`hia_agent_service.py` still owns substantial request policy around native
subowners: profiles/examples, errors, ordinary describe/artifact/read/inspect,
candidate coordination, verification, proof consumption, build-input custody,
cost-ledger construction, evaluation, adoption requirements and invocation.
Request-journal ownership is not whole request semantics; namespace ownership
is not the evaluation transaction or proof decision.

Frozen Emission covers three methods; existing Context covers its context and
deadline modes. The next seven-method verification owner closes a useful
contiguous producer/consumer boundary without duplicating either. Evaluation
and its cost ledger are a natural subsequent service owner, after the exact
verification capability is available. Original time limits, immutable context
creation time and fresh remaining-budget observations must remain intact.

`hia_agent_worker.py` and native-helper binding also retain startup, selection,
wire/error and dependency policy. Fifteen native CLI actions still enter a
Python package and call hosted components where those components are not
selected or not yet ported.

### 3. Proof contracts and independent proof engines

`hia_proof_contract.py::proof_subject/_method/_safe_core_method/proof_result`
constructs and admits the meaning of proof receipts. Its method/domain/source
binding is executable policy, even when the program being checked is native.
It should follow the coordinator as its own complete owner, with the same
actual held capabilities used by producer and consumer.

The service's `_behavior_equivalence` and `_independent_native_refinement`
remain separate Python proof-engine coordinators. Their finite-profile checks,
case enumeration, deadlines, evidence and counterexample/unknown/unsupported
decisions are outside the seven-method next owner. Calling them through a
declared foreign port does not migrate them.

The independent implementations are in `hia_translation_validation.py`,
`hia_optimization.py`, `hia_scalar_lowering_check.py`,
`hia_scalar_call_validation.py`, `hia_scalar_totality.py`,
`hia_scalar_proof_contract.py`, and `hia_safe_core.py`. Safe Core's independent
ELF binding and byte semantics are in `hia_safe_core_elf.py` and
`hia_safe_core_x64.py`. Z3 and external compiler/solver identities are real
dependencies. Their semantics must not be replaced by the implementation they
are supposed to check.

Proof-gated transformations and advisory proposals also remain hosted:
initialization/invariants, unrolling, call expansion, guarded reduction,
narrowing, reduction pipelines, empty-entry specialization, byte-sum/CRC,
finite actions, swap optimization and x86 search. The exact modules and all
entry AST identities are in the path map. Proposal generation and trusted
validation have different authority and should not be collapsed into one
opaque foreign business function.

### 4. Native build, external profiles and custody

The direct x64 path is well advanced but incomplete. Root owns the next
`_Emitter` six-method and outer-emission implementation; the peer owns Byte
ABI's `normalize_exports`, `emit_wrapper` and its nested `load`, with the
necessary helper closure. This audit creates no competing source changes.

`hia_program_native.py` also contains build/link/driver/publication policy.
Native Code or Core lowering does not make external `ld`, target loading or
whole artifact acceptance HIA-only. `object_structure.py`, `object_symbols.py`,
`elf_shared_abi.py`, `native_mapping_identity.py`, `native_tool_identity.py`,
`artifact_publication.py` and the admission side of
`artifact_publication_native.py` make actual object, symbol, source, tool,
mapping and publication decisions in Python. Those are policies, not generic
FFI copies.

The LLVM, AArch64 and Linux kernel-object routes in `hia_program_llvm.py`,
`hia_program_aarch64.py`, `hia_aarch64_elf.py`, `hia_linux_kernel.py` and
`hia_entry_layout.py` remain separately hosted implementations. Existing
supported routes cannot silently be removed because direct x64 works.

Compiler capture, process ownership and invocation/report policy remain in
`clang_capture.py`, `darwin_capture.py`, `windows_capture.py`,
`hia_agent_exec.py`, `hia_agent_runner.py`, `hia_native_byte_runner.py` and
`hia_native_differential.py`. A syscall itself is a mechanism. Deciding when to
launch, cancel, kill, reap, accept, preserve an unknown result or publish a
report is policy. The native linked observer covers its declared routes, not
every public process owner by association.

### 5. Adaptive state, queues and NDU

The adaptive/version lifecycle remains in `hia_adaptive.py`,
`hia_multiversion.py`, `hia_artifact_session.py`, `hia_background_optimizer.py`,
`hia_prepared.py`, `hia_scalar_state.py` and `hia_result_cache.py`. Owned-state,
finite-context, durable queue, continuation and settlement policy remains in
`hia_stateful.py`, `hia_finite_context.py`, `hia_durable_queue.py`,
`hia_continuation.py`, `hia_queue_commit.py` and `hia_host_region.py`. The
selected native retirement controller is a dependency, not migration of all
these surrounding state machines.

The `hia_ndu*` family, `hia_planning.py`, `hia_economic_search.py`,
`hia_invocation_bank.py`, `hia_full_cost_gate.py`, `hia_paired_holdout.py`,
`hia_native_paired_replay.py` and macro policy implement model, receipt,
session, cache, economic and advisory decisions around the original Rust NDU.
Rust execution is not HIA execution. The Rust byte-DAG and shadow-check
modules likewise retain explicit alternative/research scope. Their independent
evidence must remain available; removal requires actual replacement or an
explicit product-scope decision.

### 6. Source authoring, build and qualification tools

All 378 tool modules are mapped individually. Source authoring and an
independent test oracle are different from Python production policy. The
offline Plan/Core compiler emits ordinary HIA control flow; it does not run
host ASTs at runtime. That is a legitimate authoring boundary, while a
native-only regeneration/install story still has to account for Python
authoring and setuptools.

The build/cold/receipt/source-release controls, prerequisite bootstrap,
candidate preflight, source-contract validation and package-resource assembly
still execute Python policy. This includes `tools/build_hia_*.py`,
`tools/hia_selfhost_contract.py`, `tools/hia_candidate_preflight.py`,
`tools/hia_release.py`, `tools/bootstrap_toolchain.py`,
`tools/bootstrap_verification.py` and `setup.py`. Their native compiler output
does not by itself eliminate the hosted admission that authorizes it.

Qualification, replay, evidence archival, measurements, independent reference
tools and provider/Agent campaign tools should be retained outside the final
production execution closure. Their exact source must be kept for audit.
Python existence in those directories alone is not a reason to delete an
independent oracle, nor proof that a production native route falls back.

## Mechanisms that must not be counted as migrated business policy

`hia_exception_delivery.py`, generic object graph/token materialization,
private mmap/buffer transport, fixed exception tables and
`hia_retirement_effects.py` provide bounded mechanism or representation.
Those modules do not make proof, opcode or transaction decisions merely by
existing. Conversely, validation of a manifest, build receipt, object format,
proof scope or mapping identity is substantive custody policy even if its
file is named `_native.py`.

Current bridges also depend on the real Python object model and CPython
exception/frame ABI. Preserving that API is distinct from eliminating Python
as a runtime dependency. Both claims must remain explicit. No future bridge
may hide the seven original business bodies, interpret Python AST/source at
runtime, or classify a complete foreign proof engine as a mechanical primitive.

## Dependency order for the next concrete batches

1. **Verification coordinator — now selected.** Seven functions below; held
   native capability must flow through generation, consumption and replay.
   Implement and test a complete owner in its own directory.
2. **Proof-contract construction and acceptance.** Its callers already have a
   stable coordinator boundary. Then separate the two service proof-engine
   coordinators and their independent symbolic/byte/ELF models.
3. **Evaluation/cost-ledger/adoption coordinator.** Reuse context, budget,
   namespace, ledger, verification and runner capabilities; do not move their
   existing policies back into a host body or reset deadlines.
4. **Native artifact/build admission.** Object/symbol inventory, linker
   orchestration, source/tool/mapping identity, installed resource custody and
   publication acceptance, after the parallel Emitter and ByteABI owners.
5. **Public front end and service wire contract.** Full normalization remains
   an independent hard blocker and can proceed in parallel. Assembly/edit/
   routing and the closed Agent schema need complete, explicitly admitted
   owners rather than bytes-only aliases.
6. **Adaptive runtime, queue and NDU policy.** Migrate complete state machines
   after their execution/proof/build dependencies. Retain the actual external
   Rust/solver/compiler boundaries until each is replaced.
7. **Native package/default/retirement.** Switch actual public defaults only
   after the complete selected composition, fresh cold/full and installed
   closure have passed. Keep audit/reference materials separately.

## Immediate verification owner boundary

| Method | Decision owned by the new HIA image |
|---|---|
| `_subject` | Ordered profile/plan/build-receipt checks and subject result. |
| `_hia_verify` | Claim dispatch, evidence/binding construction, deadline decision, assumptions then evidence then receipt publication. |
| `_verification` | Receipt/implementation/Core binding, scope/schema and duplicate-property checks, evidence/assumption readback and exact proof comparison. |
| `_replay_verification` | Cached response validation, fresh installation check and exact original argument/conclusion comparison. |
| `_required_claims` | Complete receipt admission before required-claim loops, short-circuit claim qualification and exact candidate/baseline/plan decisions. |
| `_check_native_refinement_evidence` | Exact retained Core/object/image/query binding and query-inventory decisions. |
| `_native_refinement_binding` | Ordered binding construction with original object aliases and hash observations. |

`NEXT-OWNER-ORIGINAL-SEVEN.json` holds all seven exact original source bodies,
source/AST hashes and production/tool caller locations. The service file is
SHA-256 `3bc1a2e761378ecf58176cd454727f4c351b5c4c2cb30e06f7a883c781d8a0e3`.
The independent directory is `v78-agent-verification-development-r1`.

The shared service changes are limited to these wrappers/retained originals,
one constructor/close/held-owner capability, and the minimal helper/checker/
literal registry additions. Root performs the eventual union with frozen
Emission/Core/CLI. Native execution budgets and store transaction order stay
owned by their existing components.

Proof engines, `hia_proof_contract`, `_build_inputs`, storage, emitter and
solver/linker calls remain named dependencies. The selected coordinator must
poison its own seven references, preserve original callbacks and exceptions,
and never retry an unknown effect. Real original caller tests, VM/native full
frames, held-image drift/replay negatives, partial publication, actual SQLite
capabilities and installed packaging are separate required controls.

## Conditions before deleting the old whole implementation

Deletion is not presently authorized by technical closure. At minimum:

- Every supported public entry and composition must use native business
  decisions, with the complete original input domain, error order, aliases,
  temporary lifetimes, effect order, partial publication and unknown custody.
  Existing fixed profiles remain fixed; arbitrary-object APIs cannot silently
  inherit new wire/limb/depth limits.
- Proof production and consumption must bind the actual held/captured source,
  image and manifest capability. Current environment text cannot substitute
  for an already executing image. All transitive resources and bundle routes
  must be in the actual source/installed closure.
- The public default must actually select the completed HIA stack with no
  retained-policy fallback, host AST interpreter or embedded Python business
  source. Offline authoring/reference material and runtime mechanism must be
  explicitly distinguished.
- Exact current-source cold, component, public-caller and unfiltered full
  discovery gates must pass under their original limits: no skipped failures,
  filtered discovery, timeout inflation or result transfer from another tree.
  Python 3.12 observations are not Python 3.14 lifetime qualifications.
- Wheel/source-resource groups, byte readback, reproducible builds and actual
  process/compiler/solver/OS dependency receipts must match that same tree.
  The unresolved normalization physical-stack boundary and external backend/
  Rust/solver/runtime requirements must be closed or remain honestly outside
  a strictly named partial profile.
- Only then can production reachability prove which legacy modules/imports
  may be retired. Original failures, qualified references, tests, source
  hashes and historical HIA resources remain durable audit evidence.

This audit leaves `current_cold`, `whole_native`, `default_native` and
`legacy_deleted` false. It supplies the exact inventory and a concrete next
implementation boundary, not a completion percentage.
