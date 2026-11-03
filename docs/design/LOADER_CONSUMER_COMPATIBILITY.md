# Loader consumer compatibility and normal-source extraction design

Status: isolated design and executable audit, stacked on #621 at
`671ffdb1596d92efa1c33acb20a93720383a542a`. No production source changes,
new public loader API, switched entry point or bounded adapter.

## Decision

Do not promote #621's experiment class or runtime source rewriting into `hepta`.
Its value is differential evidence for moving operations, not object/API identity
compatibility. Preserve `hepta.modules.LoadedProject` in its existing module,
with the same eleven fields, constructor, match arguments, equality semantics,
report and legacy `unchanged` method. A future internal session must own a graph
in a separate handle, not append `_ops` to this exported dataclass.

`INTERFACES.md` explicitly says internal Python APIs/AST shapes are not stable
public compatibility promises. That is not permission to break current callers
silently. Installed Python packages remain importable, and downstream Python
users cannot be enumerated from this repository. Preserve the visible surface
unless a separately reviewed migration intentionally changes it.

## Reproducible inventory and limits

`python -m experiments.loader_consumer_audit.inventory` scans all 179 production
Python files and records SHA-256 for every file, including files with no match.
`inventory.json` retains 202 candidate references across 26 files, with line
numbers, import/call/surface classification and expressions. The test refuses any
source change or new production module until the inventory is regenerated and
reviewed. It follows direct import aliases and nested `.project` attributes.

This is a conservative syntax inventory, not a whole-program points-to analysis.
It cannot prove the absence of reflective imports, arbitrary variable renaming,
monkeypatching, installed plugins or external consumers. All 26 candidate files
were inspected. The inventory includes `analyze` fallback entry points and
explicit getattr identity reads, so not every row is a real LoadedProject use.
For example, `executable_core_qualify.py` uses `original` as Analysis, not
LoadedProject. `modules.py` and `packages.py` define the algorithms. The direct
and indirect surfaces and exclusions are classified below.
Tests and experiments are evidence, not counted as production consumers.

### Consumer map and preservation requirements

- `pipeline.py`: `analyze` consumes an explicitly supplied project's program,
  report and C-import metadata; its import fallback uses a source override.
  `analyze_project` loads, decodes entry bytes, analyzes and revalidates with
  override keys excluded. Loader errors occur before `analyze`'s diagnostic
  catch. HSIR/CFG/resource/concurrent exports also use getattr(project, identity,
  None), preserving the absent-project case. Preserve `Analysis.project` as the public graph, not a session wrapper.
  Compiler hash includes every `hepta/*.py` file, so any future production
  extraction changes compiler identity even if graph/report behavior matches.
- `cli.py`: lock command calls `write_lock`; ordinary check/inspect/build paths
  call `analyze_project`, then use entry and source paths to protect inputs from
  output overwrite. Keep CLI flags, exit status and named JSON schemas unchanged.
- `protocol.py` and `protocol_v3.py`: original source bytes/program/identity feed
  patch validation; candidate source hashes, modules and package state must
  match expectations; the original graph is revalidated before acceptance or
  publication. Do not replace disk lock authority with candidate overlay trust.
  Preserve v3 preview-only status and existing v2 writeback checks. The v1
  apply_patch path calls `analyze` on candidate text with original imports
  rejected and final scope checks afterward. An independent brace-escape/import
  probe failed with E_PARSE before loading; no loader reachability from that
  probe is claimed. Retain the path in the audit rather than generalize one probe.
- `workspace.py`: loads a staged tree, validates file closure, package inventory
  and C-import constraints, writes its lock, analyzes the graph, compares source
  inventory and checks original revalidation. Query paths inspect graph program
  and sources. Keep publication ordering and native validation gates unchanged.
- `agent_semantics.py`: loads the pinned workspace entry once, validates identity,
  checks the graph before and after semantic lowering, and separately verifies
  current-compiler Rust-qualified publication evidence. A loader pass must not
  downgrade or bypass that qualification.
- `llvm_owned_aarch64.py`, `llvm_owned_pipeline.py`, `llvm_ssa_pipeline.py`:
  consume analyzed project identity/sources and check `unchanged` around native
  work and publication. Preserve every check and original diagnostic boundary.
- `hia_native_differential.py` and `hia_source_bridge.py`: bind graph identity,
  source paths and compiler identity to differential/bridge products, rechecking
  before and after compilation and publication. A new graph owner must not be
  lost during nested calls or substituted for already-qualified evidence.
- `resource_source.py`: binds source/graph identity to resource analysis, checks
  revalidation and retains source receipts. `hmir.py` reads `Analysis.project`
  identity for lowering. Preserve null-project behavior for plain source input.
- `cpp_scoped.py`: calls `analyze_project` for generated consumer bindings and
  requires native qualification. No special loader call is needed or admitted.


### Other source-analysis entry points

`analyze` is a conditional graph entry point only when imports are present and no
project was supplied. All its production call sites are included in the syntax
inventory. Eight C++ generators call it for generated Hepta text:
`cpp_contracts.py`, `cpp_class_migrate.py`, `cpp_owned_migrate.py`,
`cpp_composed_migrate.py`, `cpp_composed_project.py`, `cpp_unique_project.py`,
`cpp_callback_project.py`, and `cpp_unique_reset.py`. These are potential fallback
surfaces, not evidence that current generated programs import modules.

`executable_core.py` calls analyze on user file text only after core lowering
rejects imports, so its present flow is not loader-reachable. Qualification calls
in `executable_core_qualify.py` use fixed fixture text; its Analysis attribute
matches are inventory false positives. `cli.py` imports analyze but does not call
it directly. No imported analyze aliases or pipeline module aliases were found
in this pinned source review; this is not a future or external-user guarantee.

No production consumer found here inspects LoadedProject dataclass fields or
pickles it. The explicit counterexamples cover those accessible Python surfaces
rather than claiming unobserved downstream use cannot exist.

## Observable compatibility contract

### Python and ownership

Keep signatures for `load_project(entry, *, locked=False, source_overrides=None)`,
`load_package(root, _stack=None, _cache=None)`, `package_snapshot(package)`,
`verify_lock(package)`, `write_lock(root)`, `unchanged(*, except_paths=())`, and
`report()`. Preserve Package identity too; callers may retain Package objects or
pass the internal positional recursion/cache arguments despite their names.
The legacy graph fields are program, entry, sources, source_bytes, identity,
modules, package, package_state, locked, bindings and c_imports.

The audit demonstrates #621's `_ops` addition changes `fields`, `asdict`,
constructor/match arguments and pickle module references. Candidate instances do
not satisfy `isinstance(x, hepta.modules.LoadedProject)` and do not compare equal
to original instances. Repr/equality exclusion of `_ops` does not fix those facts.
Legacy deepcopy, dataclass replacement and pickle round trips keep the original
class. These are current-process controls, not a cross-version pickle guarantee.

### Diagnostics, lock and override semantics

- Preserve eager read/decode/TOML/JSON order and existing catch scopes. `unchanged`
  returns false for OSError/HeptaError but propagates unrelated RuntimeError.
  New admission errors must never inherit HeptaError just to pass through stale
  catches; error design must be separately reviewed before bounded integration.
- Keep full diagnostic code, message, span path/start/end and phase, plus ordinary
  exception types/messages. Do not compare only a truthy/falsy final outcome.
- Keep two legacy lexing passes and original parser invocation. Admitted token
  provenance and avoiding duplicate lexing are separate changes.
- Legacy overrides resolve aliases and retain last-wins mapping order, eagerly
  encode all values, and may include unused entries. None/empty remain equivalent.
  Revalidation normally compares candidate bytes with disk; explicit except_paths
  excludes selected byte checks but does not remove package snapshot checks.
- A valid disk lock authenticates the disk inventory, not overridden text. A
  successful locked overlay analysis is possible; never call that native
  publication authorization or an authenticated overlaid program.
- Preserve lock serialization bytes, staging cleanup, final snapshot recheck,
  fsync/replace failures and old destination preservation. Do not add a session
  reset between initial load, graph analysis and final revalidation.
- Preserve lexical/resolved symlink binding checks, resolved import edges,
  canonical project identity and source/sidecar/header inclusion. The partial
  operations surface does not implement filesystem snapshot atomicity.

- `report()` deliberately aliases sources/modules/path_bindings/c_imports rather
  than deep-copying them. Preserve observable mutation/aliasing behavior during a
  mechanical extraction; API hardening is a separate change.
- `unchanged()` checks the stored package snapshot but does not re-read or verify
  Hepta.lock after initial load, even for a locked graph. Corrupting only the lock
  can leave unchanged true while a new verify_lock fails. Do not silently add
  extra lock I/O or reinterpret the method as a fresh lock verification.

## Proposed normal-source extraction, not an implementation in this PR

1. Keep public types and thin legacy entry points in their original modules.
   Move each algorithm body once to a private function in that same module,
   accepting required explicit operations as a keyword-only parameter. Existing
   public signatures delegate using a fresh LegacyLoaderOps. Retain the original
   public return annotations and positional `_stack`/`_cache` compatibility.
2. Recursive package/lock helpers call private helpers with the SAME operations
   instance. There must be no fallback to a public wrapper inside an internal
   operation, or it would silently create another owner. Do not rename/move
   Package or LoadedProject to an experimental module.
3. Extract the legacy revalidation body to a private `_unchanged(project, *, ops,
   except_paths=())` helper. Public `LoadedProject.unchanged` delegates with legacy
   operations. Private load uses `_unchanged(result, ops=ops, except_paths=...)`
   for its final check. No `_ops` field, dynamic per-instance method, global
   registry, weak-key map, context variable or monkeypatch is required.
4. A future separate internal `LoadedHandle(project, session)` would expose
   session-bound revalidation to explicit internal consumers. It must never be
   silently passed as `Analysis.project`; legacy callers still receive the
   eleven-field graph. A bounded caller using public `project.unchanged` would
   bypass its owner, so no bounded caller is admissible until all its paths use
   the handle. The current PR does not introduce that handle or claim it works.
5. Normal-source extraction is a conventional source diff, not exec/compile,
   import replacement or text rewriting at runtime. Review the actual diff,
   preserving one domain-algorithm definition. #621's pinned recipe is a test
   oracle and temporary migration reference only, not a second shipped loader.
6. Preserve monkeypatch observability deliberately: tests/downstream code may
   patch module-level parser/tokenize or helper names. Moving imports into an ops
   module changes those hooks even if outputs match. Inventory supported hooks,
   test them or explicitly document a breaking internal change before promotion.

This design chooses compatibility over prematurely exposing `ops=` publicly.
An internal custom-ops invocation returning only a public graph would lose its
owner after return; that is specifically not a bounded-loader API.

## Evidence and remaining promotion gates

Seventeen new controls cover source inventory drift/alias detection, legacy function
signatures, eleven-field object shape, explicit experimental ABI counterexamples,
copy/replace/pickle behavior, Package class identity, report aliasing, lock-file
revalidation limits, supplied-project frontend equivalence, import
fallback overlays, locked-overlay semantics, diagnostic boundary placement,
revalidation exception propagation and no production imports of experiments.
Scoped test-only loader injection also compares the actual analyze_project path
for six success/error/lock/overlay scenarios and a post-analysis source race.
The existing #621 differential oracle adds 26 controls (including all 80 example
files, with 68 successful graph loads and 12 matching missing-input failures).
The previous API/context suite adds 55. The focused gate therefore requires 98
unique controls and zero skips/expected failures, on exact PR HEAD.

This audit does not execute every CLI, workspace, native publisher or protocol
end-to-end path. The consumer map is source-review evidence; the 17 tests are a
small executable compatibility contract. No new native ABI/full-project pass.

Before production changes: implement and independently review the normal-source
diff; run existing module/package/protocol/workspace/CLI and native publication
suites against it; verify the supported Python >=3.11 and OS matrix; resolve
monkeypatch and serialization policy; compare full diagnostics/read order/races;
then separately review any session-bound internal handle. A new compiler hash
requires fresh qualified artifacts, not relabelled old receipts. No production
bounded default, hard time/heap ceiling, sandbox, merge or deployment is admitted.
