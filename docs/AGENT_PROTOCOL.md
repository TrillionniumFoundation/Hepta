# Hepta 0.2 agent interfaces

Hepta provides structured inspection and two versioned body-replacement
protocols. The compiler release is 0.2; JSON schema versions remain independent:
inspection uses `hepta.inspect.v1`, checks use `hepta.check.v1`, and patches use
`hepta.patch.v1` or `hepta.patch.v2`.

These interfaces expose validation evidence and constrain edits. They do not
grant external permissions, prove functional equivalence, or make frontend
acceptance a substitute for native checking.

## 1. Inspect the exact project snapshot

```sh
python -m hepta inspect path/to/main.hepta
python -m hepta inspect path/to/package --locked
python -m hepta inspect path/to/main.hepta --backend c
```

The CLI accepts an entry source, a package directory, or a `hepta.toml` path.
It loads the explicit dependency graph and returns declarations, declared
contracts, inferred effect summaries, runtime resource contracts, diagnostics,
function/body spans, direct call names, and validation status. It does not
expose a complete typed local-expression IR or inspect every unrelated file in
a repository.

Important fields are:

| Field | Meaning |
| --- | --- |
| `source_sha256` | The entry source's UTF-8 content identity. It is not the hash of an arbitrary patch target. |
| `interface_sha256` | The assembled graph's declaration/contract identity. |
| `compiler_sha256` | The compiler package's Python source identity. |
| `project.sha256` | Resolved entry, source identities, resolved import edges, and package state. |
| `project.sources` | Absolute source/metadata paths mapped to their content hashes. |
| `project.modules` | Per-module source paths, resolved imports, and local-to-resolved symbol maps. |
| `project.path_bindings` | Lexical path bindings checked for retargeting during validation. |
| `symbols` | Function names, source paths, declaration/body positions, and direct call names. |
| `effects` | Fixed-point effect summaries for resolved function names. |
| `resource_contracts` | Explicit runtime TaskGroup budgets and their limited enforcement scope. |
| `assumptions` | Foreign contracts and raw-memory obligations accepted by the selected check. |
| `checks`, `backend`, `profile` | Which stages ran, actual compiler/target/flags, and validation results. |

The interface includes struct fields/visibility/representation/type parameters,
enum variants/payloads/type parameters/visibility, and function parameters,
ownership modes, return types, type parameters, effects, resources, and ABI
modifiers. An enum change or an otherwise unused generic parameter change is
therefore a contract change.

Spans use zero-based Unicode code-point offsets with exclusive ends, plus
one-based lines and columns. They are not UTF-8 byte or LSP UTF-16 positions.
Function spans cover the declaration; body spans include both braces. Native
diagnostics can additionally refer to generated Rust or C positions; those
must not be mistaken for original-source spans.

Imported functions may appear under resolved internal names in reports. To
edit one, use its source path and the original local name from
`project.modules[].symbols`. Do not put the generated `M<hash>_...` identifier
in source or use it as the local v2 patch symbol.

## 2. Preferred project transaction: hepta.patch.v2

Use v2 for an imported project or package. Save a request with exactly these
string-valued keys:

```json
{
  "schema": "hepta.patch.v2",
  "expected_project_sha256": "COPY_PROJECT_SHA256",
  "target": "src/math.hepta",
  "expected_source_sha256": "COPY_PROJECT_SOURCES_HASH_FOR_THIS_TARGET",
  "expected_interface_sha256": "COPY_INTERFACE_SHA256",
  "symbol": "sum",
  "replacement_body": "{ return 0; }"
}
```

`target` is relative to the package root, or to the standalone entry directory.
It must resolve to a `.hepta` source already in the loaded graph. Absolute
targets, unrelated files, C headers, and metadata sidecars are rejected. The
target's original local `symbol` must identify exactly one implemented
function; extern-only declarations cannot be patched. For a local path
dependency, the relative target may identify that dependency only when it is
actually present in the graph.

```sh
python -m hepta patch path/to/package --request request.json
python -m hepta patch path/to/package --request request.json --apply
```

The first command validates a candidate without writing. The second performs
validation again and writes only if its preconditions still hold. A preview
is not an approval token that bypasses validation on the later apply call.

The v2 sequence is:

1. Load the graph and require exact project, target-source, and interface
   identities.
2. Replace the selected body in memory, preserving all surrounding source.
   The replacement must be exactly one brace-delimited body, including no
   extra declarations or trailing outside text.
3. Parse and check the entire candidate graph, including unchanged files and
   every generic body, then run the actual Rust native validation gate.
4. Require the original interface, package state, and resolved module/import
   structure. Candidate source identities must equal the original set with
   only the target's content changed. Recheck the original graph even for a
   dry-run.
5. For apply, acquire shared per-source transaction locks, recheck the graph,
   stage and flush the new file, retain its permission mode, recheck again,
   and atomically replace that one file.

Invalid new types, effects, resource flow, borrowing, or source scope reject
the operation. Changing declarations, generic parameters, enum payloads,
visibility, ABI, declared effect bounds, or function resource clauses rejects
it even if the new program would otherwise compile. The protocol is one-body editing against a
complete loaded graph; it is not a general multi-file edit transaction.

Inferred effects may change within the frozen declared upper bound. Numeric
arguments to a body-local `task_group(...)` call are body contents, not frozen
function clauses; a valid replacement may change them. Review the candidate's
updated `resource_contracts` when those runtime budgets matter.

A successful response uses `status=validated` or `status=applied` and includes
target before/after source hashes, original/candidate project hashes, frozen
interface identity, and the candidate's validation report. It reports
`scope=one_body_complete_import_graph`. These hashes identify the validation
context; inspect the project again after an applied edit before constructing
another request.

For packages, an edit makes the content lock stale. The response marks
`package_lock_requires_refresh=true`; the transaction does not rewrite
`Hepta.lock`. Run `hepta lock PACKAGE`, then inspect the new snapshot. The
current patch CLI rejects `--locked` and non-Rust backends. It does not offer
frontend-only acceptance or a C-backend patch validation path. Generated C
bindings also retain their source/sidecar identity checks; changing those facts
belongs to a fresh import workflow, not a body-only patch.

## 3. Legacy single-source transaction: hepta.patch.v1

V1 remains available for a source with no imports:

```json
{
  "schema": "hepta.patch.v1",
  "expected_source_sha256": "COPY_THE_ACTUAL_SOURCE_HASH",
  "expected_interface_sha256": "COPY_THE_ACTUAL_INTERFACE_HASH",
  "symbol": "sum",
  "replacement_body": "{ return 0; }"
}
```

Use the same `hepta patch FILE --request ... [--apply]` commands. The schema
accepts exactly those keys. All bodies in the candidate unit receive checking
and Rust native validation; interface changes and outside-body injection are
rejected. The response reports `scope=single_compilation_unit_body_only`.

V1 rejects sources that declare imports. It does not validate the callers of a
leaf module, a package snapshot, or a containing project's dependency graph.
Use v2 when those contexts matter. A v1 source lock uses the same convention as
v2 so cooperative edits to a shared file cannot bypass one another's locks.

## 4. Locking, races, and failure behavior

Transaction locks are sidecars named `FILE.hepta-lock`; they are separate from
the package content file `Hepta.lock`. V1 locks its target. V2 locks every
Hepta source in the loaded read graph in canonical sorted order. Acquisition
is exclusive and nonblocking. A conflict returns `E_PATCH_BUSY` and releases
locks already acquired by that attempt. This coordinates overlapping v2
graphs with different entry files as well as v1 writers of a shared source.

Checks cover source bytes, package state, and lexical path bindings. Import
edges also participate in project identity: retargeting an alias to a file
already present in the graph still changes the semantic project snapshot.
Candidate validation cannot silently incorporate unrelated dependency edits.
After staging, the original graph is checked again immediately before rename.

The declared guarantee is `cooperative_writers_only`. The final recheck and
filesystem rename are not an atomic compare-and-swap against an editor that
ignores these locks. Atomic replacement applies to one target file, not to the
entire repository. Crashes can leave lock files requiring inspection; a busy
response does not delete another writer's lock. The protocol does not roll
back executed programs or arbitrary external effects.

Representative rejection codes include `E_STALE_SOURCE`, `E_STALE_PROJECT`,
`E_STALE_INTERFACE`, `E_PATCH_SCOPE`, `E_CONTRACT_CHANGE`, `E_PATCH_BUSY`, and
the underlying frontend/native diagnostics. Errors must be consumed from the
actual result; an agent should not infer success from a subprocess completing
or from an earlier preview.

## 5. Native evidence and validation states

Rust native checking records emitted-source identity, compiler identity,
target, flags, and a real nonempty metadata artifact. Wrong or explicitly
unavailable compiler paths and unexpected pinned versions fail closed. Builds
separately record final artifacts and supplied link arguments. These records
do not prove the behavior of arbitrary future link libraries or attest
malicious compiler installations.

The independent C path records generated-C, compiler, target, flags, and real
object/artifact identities. It leaves `rust_borrows_types=not_run`, records
`c_types_codegen=gcc_checked` on success, and reports `rustc_used=false`.
Its conservative borrow/subset checks are a separate implementation; the
report must not be described as having passed Rust validation. Unsupported
ADTs, generics, resource runtimes, and other C-subset exclusions are errors.

| Report state | Interpretation |
| --- | --- |
| `frontend_only` | Selected frontend/lowering accepted; native validation was explicitly skipped. |
| `checked` | The selected native validation gate succeeded for this snapshot/profile. |
| `checked_with_external_assumptions` | Native validation succeeded with explicitly recorded foreign/raw-memory assumptions. |
| `rejected` or a driver error | The requested acceptance condition was not established. |
| Backend `unknown` | A validation result was not established, for example a native timeout; it is not success. |

Check/inspect/patch do not run user programs. C header importing is a separate
operation that executes a generated native probe; `run`, runtime tests, and
evaluation tools have their own execution behavior. Native checking does not
prove hidden functional tests, final linking, termination, timing, or device
execution.

Every successful patch response carries `functional_equivalence_proved=false`
and `external_effects_rolled_back=false`. Identical signatures and effect
contracts allow different return values. The compiler likewise does not claim
whole-language soundness, universal superiority over Rust, bounded
cancellation latency, or deadlock freedom.

## 6. Formal work and agent evaluation

The repository has separate Lean-checked abstract models of resource
transitions, group budgets, and a small expression translation. Normal
compiler and patch commands do not invoke a general functional verifier, and
those proofs do not establish that the Python frontend or actual Rust/C
lowerings refine the models. See [formal/README.md](../formal/README.md).

An executable paired Hepta/Rust pilot is available at
[experiments/agent_eval](../experiments/agent_eval/README.md). Its JSONL adapter
schemas are distinct from the patch schemas described here. It provides frozen
paired tasks, bounded `check`/`public_test` tools, candidate reconstruction,
held-out native scoring, metering receipts, and replayable evidence.

Checked-in deterministic fixture qualification contains no measured AI/provider
runs and cannot be counted as productivity evidence. Production provider runs
require explicit adapters/model identities and the required sandbox; they fail
closed when that environment is unavailable. Token receipts remain adapter
attestations. The four-task functional pilot does not evaluate large-repository
maintenance, general ADT design, or concurrency workflows. Broader claims still
require comparable tooling, frozen tasks and budgets, multiple exact model
identities/replicates, contamination control, and honest reporting of failed or
incomplete attempts.
